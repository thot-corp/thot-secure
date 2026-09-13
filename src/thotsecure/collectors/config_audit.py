"""Audit de configuration : détecte les réglages dangereux sur **vos** serveurs.

Ce collecteur lit des fichiers de configuration locaux explicitement déclarés et signale les
réglages qui ouvrent une porte : connexion root en SSH, protocol TLS obsolète, conteneur
privilégié, montage du socket Docker, absence de ``no-new-privileges``…

Chaque contrôle référence sa source normative (CIS Benchmark, ANSSI, OWASP) pour que le
rapport soit directement exploitable en audit. Le collecteur ne modifie **rien** : la
correction passe par un playbook, donc par une décision tracée.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.models import Severity
from .base import Collector, CollectorContext, CollectorResult


@dataclass(slots=True)
class ConfigCheck:
    """Contrôle de configuration."""

    check: str
    pattern: str
    severity: Severity
    message: str
    reference: str
    #: Si vrai, le motif déclenche l'alerte ; sinon son absence déclenche l'alerte.
    expect_absent: bool = True
    #: Contexte requis pour considérer le contrôle applicable (ex. bloc ``http {}``).
    requires: str | None = None


#: Contrôles SSH (CIS Benchmark, section 5.2).
SSH_CHECKS: tuple[ConfigCheck, ...] = (
    ConfigCheck(
        check="ssh_permit_root_login",
        pattern=r"(?im)^\s*PermitRootLogin\s+(yes|without-password|prohibit-password)",
        severity="high",
        message="La connexion directe de root en SSH est autorisée : un mot de passe root compromis suffit.",
        reference="CIS 5.2.8 — Ensure SSH root login is disabled",
    ),
    ConfigCheck(
        check="ssh_password_authentication",
        pattern=r"(?im)^\s*PasswordAuthentication\s+yes",
        severity="medium",
        message="L'authentification par mot de passe SSH est active : elle est vulnérable au bourrage d'identifiants.",
        reference="CIS 5.2.10 — Ensure SSH access is limited / keys only",
    ),
    ConfigCheck(
        check="ssh_empty_passwords",
        pattern=r"(?im)^\s*PermitEmptyPasswords\s+yes",
        severity="critical",
        message="Les mots de passe vides sont acceptés en SSH : accès direct sans authentification.",
        reference="CIS 5.2.9 — Ensure SSH PermitEmptyPasswords is disabled",
    ),
    ConfigCheck(
        check="ssh_max_auth_tries",
        pattern=r"(?im)^\s*MaxAuthTries\s+([0-9]+)",
        severity="low",
        message="Limiter MaxAuthTries réduit la fenêtre d'un bourrage d'identifiants.",
        reference="CIS 5.2.7 — Ensure SSH MaxAuthTries is set to 4 or less",
        expect_absent=False,
    ),
    ConfigCheck(
        check="ssh_protocol_v1",
        pattern=r"(?im)^\s*Protocol\s+1",
        severity="critical",
        message="Le protocole SSH v1 est obsolète et cassé (CVE-2001-0361).",
        reference="ANSSI — Recommandations SSH",
    ),
)

#: Contrôles Nginx / Apache.
WEB_CHECKS: tuple[ConfigCheck, ...] = (
    ConfigCheck(
        check="web_tls_legacy_protocol",
        pattern=r"(?im)^\s*ssl_protocols\s+[^;]*\b(TLSv1|TLSv1\.1|SSLv3)\b",
        severity="high",
        message="Des protocoles TLS obsolètes sont activés : le chiffrement est considéré comme cassé.",
        reference="CIS 2.4 — Nginx TLS configuration",
    ),
    ConfigCheck(
        check="web_server_tokens",
        pattern=r"(?im)^\s*server_tokens\s+on\s*;",
        severity="low",
        message="server_tokens on divulgue la version exacte du serveur.",
        reference="OWASP — Information exposure",
    ),
    ConfigCheck(
        check="web_directory_listing",
        pattern=r"(?im)^\s*autoindex\s+on\s*;",
        severity="medium",
        message="L'indexation automatique des répertoires est active : elle expose l'arborescence et les fichiers non liés.",
        reference="OWASP — Directory listing",
    ),
    ConfigCheck(
        check="web_missing_hsts",
        pattern=r"(?im)add_header\s+Strict-Transport-Security",
        severity="medium",
        message="Aucun en-tête HSTS trouvé : la rétrogradation d'une première requête en HTTP est possible.",
        reference="OWASP Secure Headers Project",
        expect_absent=False,
    ),
)

#: Contrôles de conteneurs (Docker / Compose).
CONTAINER_CHECKS: tuple[ConfigCheck, ...] = (
    ConfigCheck(
        check="container_privileged",
        pattern=r"(?im)privileged\s*:\s*true",
        severity="critical",
        message="Un conteneur est lancé en mode privilégié : il peut s'échapper vers l'hôte.",
        reference="CIS Docker 5.4 — Ensure privileged containers are not used",
    ),
    ConfigCheck(
        check="container_docker_socket",
        pattern=r"(?im)/var/run/docker\.sock",
        severity="critical",
        message="Le socket Docker est monté dans un conteneur : cela équivaut à un accès root sur l'hôte.",
        reference="CIS Docker 5.31 — Ensure the Docker socket is not mounted",
    ),
    ConfigCheck(
        check="container_host_network",
        pattern=r"(?im)network_mode\s*:\s*[\"']?host[\"']?",
        severity="high",
        message="Un conteneur partage la pile réseau de l'hôte : les protections réseau deviennent inopérantes.",
        reference="CIS Docker 5.9 — Ensure host network mode is not used",
    ),
    ConfigCheck(
        check="container_no_new_privileges",
        pattern=r"(?im)no-new-privileges",
        severity="medium",
        message="L'option no-new-privileges n'est pas définie : un binaire setuid peut élever les privilèges.",
        reference="CIS Docker 5.25 — Ensure no-new-privileges is set",
        expect_absent=False,
    ),
    ConfigCheck(
        check="container_readonly_rootfs",
        pattern=r"(?im)read_only\s*:\s*true",
        severity="low",
        message="Le système de fichiers du conteneur n'est pas monté en lecture seule.",
        reference="CIS Docker 5.12 — Ensure the container root filesystem is read-only",
        expect_absent=False,
    ),
)

CHECKS_BY_KIND: dict[str, tuple[ConfigCheck, ...]] = {
    "ssh": SSH_CHECKS,
    "sshd": SSH_CHECKS,
    "sshd_config": SSH_CHECKS,
    "nginx": WEB_CHECKS,
    "apache": WEB_CHECKS,
    "httpd": WEB_CHECKS,
    "docker": CONTAINER_CHECKS,
    "docker-compose": CONTAINER_CHECKS,
    "compose": CONTAINER_CHECKS,
}


class ConfigAuditCollector(Collector):
    """Audite les fichiers de configuration déclarés."""

    name = "config_audit"
    source_type = "config_audit"
    description = "Détecte les réglages dangereux dans les fichiers de configuration déclarés."
    default_interval_seconds = 1800
    requires_probe_optin = False

    def collect(self, context: CollectorContext) -> CollectorResult:
        result = CollectorResult(collector=self.name)
        scope = context.scope
        config_files = scope.config_files
        if not config_files:
            return self._skip(
                f"aucun fichier de configuration déclaré pour le tenant '{scope.tenant_id}' "
                "(renseignez 'config_files' dans config/targets.yaml)"
            )

        for entry in config_files:
            path = Path(entry.path).expanduser()
            if not path.is_absolute():
                path = context.settings.root_path / path
            if not path.exists():
                result.add_error(f"fichier de configuration introuvable: {path}")
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                result.add_error(f"{path}: {exc}")
                continue

            kind = _resolve_kind(entry.kind, path.name)
            checks = CHECKS_BY_KIND.get(kind)
            if checks is None:
                result.add_error(
                    f"type de configuration non reconnu pour {path.name} "
                    f"(kind={entry.kind!r}) : aucun contrôle appliqué"
                )
                continue

            findings = run_checks(text, checks)
            for finding in findings:
                result.events.append(
                    context.make_event(
                        kind="config.audit",
                        source_type=self.source_type,
                        source_name=self.name,
                        source_host=path.name,
                        labels={
                            "check": finding["check"],
                            "file": str(path),
                            "kind": kind,
                            "line": finding["line"],
                            "evidence": finding["evidence"][:300],
                        },
                        payload={
                            "message": finding["message"],
                            "reference": finding["reference"],
                            "explanation": finding["explanation"],
                        },
                        severity_hint=finding["severity"],  # type: ignore[arg-type]
                    )
                )
            result.detail.setdefault("per_file", {})[path.name] = {
                "kind": kind,
                "checks_applied": len(checks),
                "findings": len(findings),
            }

        result.finished_at = _now()
        return result


# --------------------------------------------------------------------------------------


def run_checks(text: str, checks: tuple[ConfigCheck, ...]) -> list[dict[str, Any]]:
    """Applique une série de contrôles à un contenu de configuration."""
    findings: list[dict[str, Any]] = []
    lines = text.splitlines()
    for check in checks:
        pattern = re.compile(check.pattern)
        match = pattern.search(text)
        triggered = False
        evidence = ""
        line_number = 0

        if check.expect_absent:
            if match:
                triggered = True
                evidence = match.group(0).strip()
                line_number = text[: match.start()].count("\n") + 1
        elif not match:
            # Contrôle « présence attendue » : l'absence est le problème.
            triggered = True
            evidence = f"aucune occurrence de {check.pattern}"
            line_number = 1

        if not triggered:
            continue
        findings.append(
            {
                "check": check.check,
                "severity": check.severity,
                "message": check.message,
                "reference": check.reference,
                "explanation": _explain(check, evidence, lines, line_number),
                "evidence": evidence,
                "line": line_number,
            }
        )
    return findings


def _explain(check: ConfigCheck, evidence: str, lines: list[str], line: int) -> str:
    context_line = lines[line - 1].strip() if 0 < line <= len(lines) else evidence
    return f"{check.message} Référence : {check.reference}. Extrait : « {context_line[:200]} »"


def _resolve_kind(kind: str, filename: str) -> str:
    if kind and kind != "auto":
        return kind.lower()
    lower = filename.lower()
    if "ssh" in lower:
        return "ssh"
    if "nginx" in lower:
        return "nginx"
    if "apache" in lower or "httpd" in lower:
        return "apache"
    if "docker" in lower or "compose" in lower:
        return "docker"
    return "inconnu"


def available_checks() -> dict[str, list[str]]:
    """Liste des contrôles disponibles par type (documentation et API)."""
    return {
        kind: [check.check for check in checks]
        for kind, checks in (
            ("ssh", SSH_CHECKS),
            ("nginx", WEB_CHECKS),
            ("docker", CONTAINER_CHECKS),
        )
    }


def _now() -> Any:
    from ..core.util import utcnow

    return utcnow()


__all__ = [
    "CHECKS_BY_KIND",
    "CONTAINER_CHECKS",
    "SSH_CHECKS",
    "WEB_CHECKS",
    "ConfigAuditCollector",
    "ConfigCheck",
    "available_checks",
    "run_checks",
]
