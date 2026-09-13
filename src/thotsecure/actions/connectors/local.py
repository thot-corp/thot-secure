"""Connecteurs locaux : les seuls du MVP qui produisent un effet **réel et vérifiable**.

Ils sont volontairement modestes et entièrement réversibles :

* ``nginx-local`` : maintient un fichier d'inclusions Nginx (deny / rate-limit) et
  déclenche un rechargement **uniquement** si la commande est explicitement configurée ;
* ``local-quarantine`` : met un fichier en quarantaine (déplacement + empreinte SHA-256 +
  manifeste) et sait le restaurer, en refusant tout chemin hors périmètre autorisé ;
* ``local-ticket`` : écrit un ticket Markdown dans un répertoire — utile pour un MSP qui
  n'a pas d'API de ticketing, et suffisant pour prouver la chaîne de traitement.

Aucun de ces connecteurs ne nécessite de credential, ce qui permet de valider le
fonctionnement de bout en bout avant de brancher un WAF réel.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

from ...core.logging_setup import get_logger
from ...core.util import iso_z, new_id, now_iso, parse_dt, slugify, utcnow
from .base import Connector, ConnectorNotConfiguredError, ConnectorResult

log = get_logger("actions.connector.local")


def _atomic_write(path: Path, content: str) -> None:
    """Écriture atomique : un fichier de configuration Nginx tronqué couperait le service."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


class NginxLocalConnector(Connector):
    """Blocage d'IP et limitation de débit par fichier d'inclusion Nginx."""

    driver = "nginx-local"

    DEFAULT_DENY_FILE = "./data/actions/nginx-deny.conf"
    DEFAULT_STATE_FILE = "./data/actions/nginx-state.json"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"block_ip", "unblock_ip", "rate_limit", "remove_rate_limit"})

    # -- chemins -----------------------------------------------------------------------

    @property
    def deny_file(self) -> Path:
        return Path(self.settings.get("deny_file") or self.DEFAULT_DENY_FILE).expanduser()

    @property
    def state_file(self) -> Path:
        return Path(self.settings.get("state_file") or self.DEFAULT_STATE_FILE).expanduser()

    @property
    def reload_command(self) -> list[str] | None:
        command = self.settings.get("reload_command")
        if not command:
            return None
        if isinstance(command, str):
            return command.split()
        return [str(part) for part in command]

    # -- état --------------------------------------------------------------------------

    def _load_state(self) -> dict[str, Any]:
        if not self.state_file.exists():
            return {"version": 1, "entries": []}
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.error("état Nginx illisible, réinitialisation", extra={"error": str(exc)})
            return {"version": 1, "entries": []}

    def _save_state(self, state: dict[str, Any]) -> None:
        _atomic_write(self.state_file, json.dumps(state, indent=2, ensure_ascii=False))

    def prune(self) -> int:
        """Retire les entrées expirées et réécrit le fichier d'inclusion."""
        state = self._load_state()
        now = utcnow()
        before = len(state["entries"])
        state["entries"] = [
            entry
            for entry in state["entries"]
            if not entry.get("expires_at") or (parse_dt(entry["expires_at"]) or now) > now
        ]
        removed = before - len(state["entries"])
        self._save_state(state)
        self._render(prune_only=True)
        return removed

    # -- rendu du fichier d'inclusion ---------------------------------------------------

    def _render(self, *, prune_only: bool = False) -> None:
        state = self._load_state()
        blocks = [
            "# Fichier généré par Thot Secure — NE PAS ÉDITER À LA MAIN.",
            "# Chaque entrée correspond à une action auditée et réversible depuis l'interface.",
            "# Incluez ce fichier dans votre bloc http{} ou server{} :",
            "#     include /etc/nginx/conf.d/thotsecure-deny.conf;",
            "",
        ]
        rate_entries = [entry for entry in state["entries"] if entry.get("operation") == "rate_limit"]
        deny_entries = [entry for entry in state["entries"] if entry.get("operation") == "block_ip"]

        if rate_entries:
            blocks.append("# --- Limitation de débit (zones) ---")
            for entry in sorted(rate_entries, key=lambda item: item["id"]):
                zone = f"thotsecure_{entry['id'][:8]}"
                blocks.append(
                    f"# {entry.get('note') or 'rate limit'} — expire {entry.get('expires_at') or 'jamais'}"
                )
                blocks.append(
                    f"limit_req_zone $binary_remote_addr zone={zone}:10m "
                    f"rate={entry.get('rate', '10r/s')};"
                )
            blocks.append("")

        if deny_entries:
            blocks.append("# --- Adresses bloquées ---")
            for entry in sorted(deny_entries, key=lambda item: item["ip"]):
                blocks.append(
                    f"# motif: {entry.get('note') or 'n/a'} — expire {entry.get('expires_at') or 'jamais'}"
                )
                blocks.append(f"deny {entry['ip']};")
            blocks.append("")

        if not rate_entries and not deny_entries:
            blocks.append("# (aucune entrée active)")

        _atomic_write(self.deny_file, "\n".join(blocks) + "\n")
        if not prune_only:
            log.info(
                "fichier d'inclusion Nginx régénéré",
                extra={"file": str(self.deny_file), "entries": len(state["entries"])},
            )

    def _reload(self) -> tuple[bool, str]:
        command = self.reload_command
        if not command:
            return False, (
                "aucun rechargement déclenché : configurez 'reload_command' "
                "(ex. ['nginx', '-s', 'reload']) pour l'activer"
            )
        try:
            completed = subprocess.run(  # noqa: S603 - commande issue de la configuration locale
                command, capture_output=True, timeout=15, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"échec du rechargement: {exc}"
        if completed.returncode != 0:
            return False, f"rechargement en erreur: {completed.stderr.decode('utf-8', 'replace')[:200]}"
        return True, "rechargement Nginx effectué"

    # -- opérations --------------------------------------------------------------------

    def op_block_ip(self, params: dict[str, Any]) -> ConnectorResult:
        ip = str(params.get("target") or params.get("ip") or "").strip()
        if not ip:
            return ConnectorResult(ok=False, error="paramètre 'target' (IP) manquant")
        duration = int(params.get("duration_seconds") or 3600)
        entry = {
            "id": new_id("nx_"),
            "operation": "block_ip",
            "ip": ip,
            "note": str(params.get("reason") or "Thot Secure auto-mitigation")[:200],
            "created_at": now_iso(),
            "expires_at": iso_z(utcnow() + timedelta(seconds=duration)),
        }
        state = self._load_state()
        state["entries"].append(entry)
        self._save_state(state)
        self._render()
        reloaded, reload_detail = self._reload()
        return ConnectorResult(
            ok=True,
            detail=f"IP {ip} ajoutée au fichier d'inclusion Nginx. {reload_detail}",
            data={"entry_id": entry["id"], "expires_at": entry["expires_at"], "reloaded": reloaded},
            rollback_token=entry["id"],
        )

    def op_unblock_ip(self, params: dict[str, Any]) -> ConnectorResult:
        ip = str(params.get("target") or params.get("ip") or "").strip()
        token = params.get("rollback_token")
        state = self._load_state()
        before = len(state["entries"])
        state["entries"] = [
            entry
            for entry in state["entries"]
            if not (
                (token and entry["id"] == token)
                or (ip and entry.get("ip") == ip and entry.get("operation") == "block_ip")
            )
        ]
        removed = before - len(state["entries"])
        self._save_state(state)
        self._render()
        reloaded, reload_detail = self._reload()
        return ConnectorResult(
            ok=removed > 0,
            detail=f"{removed} entrée(s) retirée(s). {reload_detail}",
            data={"removed": removed, "reloaded": reloaded},
            error=None if removed > 0 else "aucune entrée correspondante (déjà débloquée ?)",
        )

    def op_rate_limit(self, params: dict[str, Any]) -> ConnectorResult:
        ip = str(params.get("target") or params.get("ip") or "").strip()
        if not ip:
            return ConnectorResult(ok=False, error="paramètre 'target' (IP) manquant")
        duration = int(params.get("duration_seconds") or 3600)
        entry = {
            "id": new_id("nx_"),
            "operation": "rate_limit",
            "ip": ip,
            "rate": str(params.get("rate") or "10r/s"),
            "note": str(params.get("reason") or "Thot Secure rate limit")[:200],
            "created_at": now_iso(),
            "expires_at": iso_z(utcnow() + timedelta(seconds=duration)),
        }
        state = self._load_state()
        state["entries"].append(entry)
        self._save_state(state)
        self._render()
        reloaded, reload_detail = self._reload()
        return ConnectorResult(
            ok=True,
            detail=f"Zone de limitation déclarée pour {ip} ({entry['rate']}). {reload_detail}",
            data={"entry_id": entry["id"], "reloaded": reloaded},
            rollback_token=entry["id"],
        )

    def op_remove_rate_limit(self, params: dict[str, Any]) -> ConnectorResult:
        token = params.get("rollback_token")
        ip = str(params.get("target") or params.get("ip") or "").strip()
        state = self._load_state()
        before = len(state["entries"])
        state["entries"] = [
            entry
            for entry in state["entries"]
            if not (
                (token and entry["id"] == token)
                or (ip and entry.get("ip") == ip and entry.get("operation") == "rate_limit")
            )
        ]
        removed = before - len(state["entries"])
        self._save_state(state)
        self._render()
        reloaded, reload_detail = self._reload()
        return ConnectorResult(
            ok=removed > 0,
            detail=f"{removed} zone(s) retirée(s). {reload_detail}",
            data={"removed": removed, "reloaded": reloaded},
            error=None if removed > 0 else "aucune zone correspondante",
        )

    def describe_state(self) -> dict[str, Any]:
        state = self._load_state()
        return {
            "driver": self.driver,
            "deny_file": str(self.deny_file),
            "state_file": str(self.state_file),
            "entries": len(state.get("entries", [])),
            "reload_configured": bool(self.reload_command),
        }


class LocalQuarantineConnector(Connector):
    """Quarantaine de fichier : déplacement réversible avec vérification d'empreinte.

    Garde-fou essentiel : seuls les chemins situés sous ``allowed_roots`` peuvent être mis
    en quarantaine. Sans cette limite, un playbook mal écrit pourrait déplacer
    ``/etc/passwd`` — c'est-à-dire provoquer un déni de service sur sa propre
    infrastructure, exactement ce qu'un outil défensif ne doit jamais pouvoir faire.
    """

    driver = "local-quarantine"

    DEFAULT_DIR = "./data/quarantine"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"quarantine_file", "restore_file"})

    @property
    def quarantine_dir(self) -> Path:
        return Path(self.settings.get("quarantine_dir") or self.DEFAULT_DIR).expanduser()

    @property
    def allowed_roots(self) -> list[Path]:
        configured = self.settings.get("allowed_roots") or ["./data"]
        return [Path(item).expanduser().resolve() for item in configured]

    @property
    def manifest_file(self) -> Path:
        return self.quarantine_dir / "manifest.json"

    def _load_manifest(self) -> dict[str, Any]:
        if not self.manifest_file.exists():
            return {"version": 1, "entries": []}
        try:
            return json.loads(self.manifest_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"version": 1, "entries": []}

    def _save_manifest(self, manifest: dict[str, Any]) -> None:
        _atomic_write(self.manifest_file, json.dumps(manifest, indent=2, ensure_ascii=False))

    def _is_allowed(self, path: Path) -> bool:
        resolved = path.resolve()
        return any(resolved.is_relative_to(root) for root in self.allowed_roots)

    def op_quarantine_file(self, params: dict[str, Any]) -> ConnectorResult:
        raw = params.get("target") or params.get("path")
        if not raw:
            return ConnectorResult(ok=False, error="paramètre 'target' (chemin) manquant")
        source = Path(str(raw)).expanduser()
        if not source.exists():
            return ConnectorResult(ok=False, error=f"fichier introuvable: {source}")
        if source.is_dir():
            return ConnectorResult(ok=False, error="la quarantaine ne s'applique qu'aux fichiers")
        if not self._is_allowed(source):
            return ConnectorResult(
                ok=False,
                error=(
                    f"chemin hors périmètre autorisé: {source} "
                    f"(allowed_roots={[str(root) for root in self.allowed_roots]})"
                ),
            )
        digest = _sha256_file(source)
        entry_id = new_id("qz_")
        destination = self.quarantine_dir / f"{entry_id}_{source.name}.quarantined"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
        manifest = self._load_manifest()
        manifest["entries"].append(
            {
                "id": entry_id,
                "original_path": str(source.resolve()),
                "quarantined_path": str(destination.resolve()),
                "sha256": digest,
                "size": destination.stat().st_size,
                "reason": str(params.get("reason") or "")[:300],
                "quarantined_at": now_iso(),
                "restored_at": None,
            }
        )
        self._save_manifest(manifest)
        return ConnectorResult(
            ok=True,
            detail=f"fichier mis en quarantaine (sha256={digest[:12]}…)",
            data={"entry_id": entry_id, "sha256": digest, "quarantined_path": str(destination)},
            rollback_token=entry_id,
        )

    def op_restore_file(self, params: dict[str, Any]) -> ConnectorResult:
        token = params.get("rollback_token") or params.get("entry_id")
        raw = params.get("target") or params.get("path")
        manifest = self._load_manifest()
        entry = None
        for candidate in manifest["entries"]:
            if token and candidate["id"] == token:
                entry = candidate
                break
            if raw and candidate["original_path"] == str(Path(str(raw)).expanduser().resolve()):
                entry = candidate
                break
        if entry is None:
            return ConnectorResult(ok=False, error="aucune entrée de quarantaine correspondante")
        if entry.get("restored_at"):
            return ConnectorResult(ok=False, error="ce fichier a déjà été restauré")

        quarantined = Path(entry["quarantined_path"])
        if not quarantined.exists():
            return ConnectorResult(ok=False, error="fichier en quarantaine introuvable")
        current_digest = _sha256_file(quarantined)
        if current_digest != entry["sha256"]:
            return ConnectorResult(
                ok=False,
                error=(
                    "empreinte différente de celle enregistrée : le fichier a été modifié, "
                    "restauration refusée (investigation requise)"
                ),
            )
        original = Path(entry["original_path"])
        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(quarantined), str(original))
        entry["restored_at"] = now_iso()
        self._save_manifest(manifest)
        return ConnectorResult(
            ok=True,
            detail=f"fichier restauré vers {original}",
            data={"entry_id": entry["id"], "path": str(original)},
        )

    def describe_state(self) -> dict[str, Any]:
        manifest = self._load_manifest()
        active = [entry for entry in manifest["entries"] if not entry.get("restored_at")]
        return {
            "driver": self.driver,
            "quarantine_dir": str(self.quarantine_dir),
            "allowed_roots": [str(root) for root in self.allowed_roots],
            "quarantined": len(active),
        }


class LocalTicketConnector(Connector):
    """Ticketing local : un fichier Markdown par incident.

    Suffisant pour tracer la chaîne de traitement (et pour un audit), sans dépendre d'un
    outil tiers. Le connecteur webhook permet de brancher Jira/GLPI/GitHub si besoin.
    """

    driver = "local-ticket"

    DEFAULT_DIR = "./data/tickets"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"open_ticket", "close_ticket", "notify"})

    @property
    def directory(self) -> Path:
        return Path(self.settings.get("directory") or self.DEFAULT_DIR).expanduser()

    def op_open_ticket(self, params: dict[str, Any]) -> ConnectorResult:
        title = str(params.get("title") or "Incident Thot Secure")
        severity = str(params.get("severity") or "medium")
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        ticket_id = f"{stamp}-{slugify(title, max_length=40)}"
        path = self.directory / f"{ticket_id}.md"
        body = "\n".join(
            [
                "---",
                f"ticket_id: {ticket_id}",
                f"title: {title}",
                f"severity: {severity}",
                f"tenant_id: {params.get('tenant_id', '')}",
                f"finding_id: {params.get('finding_id', '')}",
                f"action_id: {params.get('action_id', '')}",
                f"created_at: {now_iso()}",
                "status: open",
                "---",
                "",
                f"# {title}",
                "",
                "## Contexte",
                "",
                str(params.get("description") or "Ticket ouvert automatiquement par Thot Secure."),
                "",
                "## Remédiation recommandée",
                "",
                str(params.get("remediation") or "Analyser, confirmer, appliquer, documenter."),
                "",
                "## Journal",
                "",
                f"- {now_iso()} — ticket ouvert par Thot Secure",
                "",
            ]
        )
        _atomic_write(path, body)
        return ConnectorResult(
            ok=True,
            detail=f"ticket créé: {path}",
            data={"ticket_id": ticket_id, "path": str(path)},
            rollback_token=ticket_id,
        )

    def op_close_ticket(self, params: dict[str, Any]) -> ConnectorResult:
        ticket_id = str(params.get("rollback_token") or params.get("ticket_id") or "")
        if not ticket_id:
            return ConnectorResult(ok=False, error="identifiant de ticket manquant")
        path = self.directory / f"{ticket_id}.md"
        if not path.exists():
            return ConnectorResult(ok=False, error=f"ticket introuvable: {path}")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                f"\n## Clôture\n\n- {now_iso()} — clôturé : "
                f"{params.get('resolution') or 'résolu'}\n"
                f"- commentaire : {params.get('comment') or 'n/a'}\n"
            )
        return ConnectorResult(ok=True, detail=f"ticket clôturé: {path}", data={"ticket_id": ticket_id})

    def op_notify(self, params: dict[str, Any]) -> ConnectorResult:
        """Une notification locale reste traceable : elle est écrite, pas seulement émise."""
        message = str(params.get("message") or "Notification Thot Secure")
        path = self.directory / "notifications.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{now_iso()}\t{message[:500]}\n")
        return ConnectorResult(ok=True, detail="notification journalisée localement")

    def describe_state(self) -> dict[str, Any]:
        count = len(list(self.directory.glob("*.md"))) if self.directory.exists() else 0
        return {"driver": self.driver, "directory": str(self.directory), "tickets": count}


def _sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "LocalQuarantineConnector",
    "LocalTicketConnector",
    "NginxLocalConnector",
]
