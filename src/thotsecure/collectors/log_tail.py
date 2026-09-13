"""Surveillance des journaux locaux (``tail`` avec reprise et détection de rotation).

Le collecteur lit incrémentalement les fichiers déclarés, normalise chaque ligne en événement
``http.request`` / ``log.line`` et conserve sa position dans un fichier d'état. Il survit donc
à un redémarrage sans relire (et donc sans rejouer) tout l'historique — un piège classique
qui produit des milliers de faux positifs au redémarrage.

Formats pris en charge : journal combiné Nginx/Apache, journal JSON structuré, et repli
« ligne brute » (qui reste utile : une règle peut chercher un motif dans ``labels.message``).

Aucun secret n'est persisté : les cookies, jetons et en-têtes d'autorisation sont masqués
avant émission (voir ``collectors.base._sanitize``).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .base import Collector, CollectorContext, CollectorResult

#: Taille maximale lue par passe et par fichier : on ne bloque pas un cycle de collecte sur un
#: fichier de plusieurs gigaoctets (le reste sera lu au cycle suivant).
MAX_BYTES_PER_RUN = 4 * 1024 * 1024

#: Nombre maximal d'événements émis par fichier et par passe.
MAX_EVENTS_PER_FILE = 5000

#: Journal combiné Nginx/Apache.
COMBINED_LOG = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^"]*?)\s*(?P<protocol>HTTP/[0-9.]+)?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s*'
    r'(?:"(?P<referer>[^"]*)"\s*"(?P<user_agent>[^"]*)")?'
)

SYSLOG_TS_FORMATS = ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S")


@dataclass(slots=True)
class ParsedLine:
    """Ligne de journal normalisée."""

    kind: str
    labels: dict[str, Any]
    payload: dict[str, Any]
    ts: Any = None
    severity_hint: str | None = None


@dataclass(slots=True)
class TailState:
    """Position de lecture d'un fichier."""

    offset: int = 0
    size: int = 0
    modified: float = 0.0
    lines: int = 0
    rotated: int = 0


class LogTailCollector(Collector):
    """Lit incrémentalement les journaux déclarés et les normalise."""

    name = "log_tail"
    source_type = "log_tail"
    description = "Suit les journaux déclarés (Nginx/Apache/JSON) et les normalise en événements."
    default_interval_seconds = 60
    requires_probe_optin = False

    # ----------------------------------------------------------------------------------

    def collect(self, context: CollectorContext) -> CollectorResult:
        result = CollectorResult(collector=self.name)
        scope = context.scope
        sources = scope.log_sources
        if not sources:
            return self._skip(
                f"aucun journal déclaré pour le tenant '{scope.tenant_id}' "
                "(renseignez 'log_sources' dans config/targets.yaml)"
            )

        state = self._load_state(context)
        for source in sources:
            path = Path(source.path).expanduser()
            if not path.is_absolute():
                path = context.settings.root_path / path
            if not path.exists():
                result.add_error(f"journal introuvable: {path}")
                continue
            try:
                events = self._read_new_lines(path, source.format, state, context)
            except OSError as exc:
                result.add_error(f"{path}: {exc}")
                continue
            result.events.extend(events)
            result.detail.setdefault("per_file", {})[str(path)] = len(events)

        self._save_state(context, state)
        result.detail["sources"] = [source.path for source in sources]
        result.finished_at = _now()
        return result

    # ----------------------------------------------------------------------------------

    def _read_new_lines(
        self, path: Path, file_format: str, state: dict[str, TailState], context: CollectorContext
    ) -> list:
        key = str(path.resolve())
        stat = path.stat()
        entry = state.get(key, TailState())

        # Rotation détectée : le fichier a rétréci, ou son inode a changé (taille + date).
        if stat.st_size < entry.offset or (entry.size and stat.st_size < entry.size):
            entry.rotated += 1
            entry.offset = 0
        entry.size = stat.st_size
        entry.modified = stat.st_mtime

        events: list = []
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(entry.offset)
            consumed = 0
            for line in handle:
                consumed += len(line.encode("utf-8", "replace"))
                if consumed > MAX_BYTES_PER_RUN or len(events) >= MAX_EVENTS_PER_FILE:
                    break
                stripped = line.rstrip("\n")
                if not stripped.strip():
                    continue
                parsed = parse_log_line(stripped, file_format)
                if parsed is None:
                    continue
                events.append(
                    context.make_event(
                        kind=parsed.kind,  # type: ignore[arg-type]
                        source_type=self.source_type,
                        source_name=self.name,
                        source_host=path.name,
                        labels={**parsed.labels, "log_file": str(path)},
                        payload=parsed.payload,
                        severity_hint=parsed.severity_hint,  # type: ignore[arg-type]
                        ts=parsed.ts,
                    )
                )
                entry.lines += 1
            entry.offset = handle.tell()
        state[key] = entry
        return events

    # ----------------------------------------------------------------------------------

    def _load_state(self, context: CollectorContext) -> dict[str, TailState]:
        path = context.state_dir / "log_tail-state.json"
        if not path.exists():
            return {}
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        state: dict[str, TailState] = {}
        for key, value in (document.get("files") or {}).items():
            try:
                state[key] = TailState(**value)
            except TypeError:
                continue
        return state

    def _save_state(self, context: CollectorContext, state: dict[str, TailState]) -> None:
        path = context.state_dir / "log_tail-state.json"
        payload = {
            "version": 1,
            "updated_at": _now().isoformat(),
            # ``asdict`` (et non ``vars``) : ``TailState`` utilise ``slots=True`` et n'a donc
            # pas de ``__dict__``.
            "files": {key: asdict(value) for key, value in state.items()},
        }
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        temporary.replace(path)


# --------------------------------------------------------------------------------------
# Analyse des lignes
# --------------------------------------------------------------------------------------


def parse_log_line(line: str, file_format: str = "auto") -> ParsedLine | None:
    """Normalise une ligne de journal. Retourne ``None`` si la ligne est illisible."""
    if file_format == "json" or (file_format == "auto" and line.lstrip().startswith("{")):
        return parse_json_log(line)
    match = COMBINED_LOG.match(line)
    if match:
        return parse_combined_log(match)
    if file_format in {"nginx", "apache", "combined"}:
        return None
    return ParsedLine(
        kind="log.line",
        labels={"message": line[:1024]},
        payload={"raw_length": len(line)},
    )


def parse_combined_log(match: re.Match[str]) -> ParsedLine:
    """Convertit une ligne de journal combiné en événement normalisé."""
    from ..core.util import parse_dt

    status = int(match.group("status"))
    raw_bytes = match.group("bytes")
    labels: dict[str, Any] = {
        "src_ip": match.group("src_ip"),
        "method": match.group("method"),
        "path": match.group("path"),
        "status": status,
        "user": None if match.group("user") in {"-", None} else match.group("user"),
        "user_agent": (match.group("user_agent") or "")[:512],
        "referer": (match.group("referer") or "")[:512],
        "log_format": "combined",
    }
    payload: dict[str, Any] = {
        "status": status,
        "bytes": int(raw_bytes) if raw_bytes and raw_bytes != "-" else 0,
    }
    ts = _parse_combined_ts(match.group("ts"))
    severity: str | None = None
    if status >= 500:
        severity = "medium"
    elif status in {401, 403}:
        severity = "low"
    return ParsedLine(
        kind="http.request",
        labels={key: value for key, value in labels.items() if value is not None},
        payload=payload,
        ts=ts or parse_dt(None),
        severity_hint=severity,
    )


def parse_json_log(line: str) -> ParsedLine | None:
    """Normalise une ligne JSON (log applicatif structuré)."""
    try:
        document = json.loads(line)
    except ValueError:
        return None
    if not isinstance(document, dict):
        return None

    # On remonte les champs les plus courants au niveau des labels (espace de nommage des
    # règles) et on conserve le reste dans la charge utile.
    label_keys = {
        "src_ip": ("src_ip", "remote_addr", "client_ip", "source_ip", "ip"),
        "method": ("method", "request_method", "http_method"),
        "path": ("path", "uri", "request_uri", "url", "request"),
        "status": ("status", "status_code", "response_status"),
        "host": ("host", "server_name", "vhost"),
        "user_agent": ("user_agent", "http_user_agent", "agent"),
        "user": ("user", "username", "remote_user", "actor"),
        "level": ("level", "severity", "log_level"),
        "message": ("message", "msg", "event", "error"),
    }
    labels: dict[str, Any] = {}
    for label, candidates in label_keys.items():
        for candidate in candidates:
            if candidate in document and document[candidate] is not None:
                value = document[candidate]
                labels[label] = value if isinstance(value, (int, float, bool)) else str(value)[:1024]
                break

    severity = None
    level = str(labels.get("level", "")).lower()
    if level in {"critical", "fatal", "panic"}:
        severity = "high"
    elif level in {"error", "err"}:
        severity = "medium"
    elif level == "warning":
        severity = "low"

    from ..core.util import parse_dt

    return ParsedLine(
        kind="log.line",
        labels=labels,
        payload={key: value for key, value in document.items() if key not in labels},
        ts=parse_dt(document.get("ts") or document.get("timestamp") or document.get("time")),
        severity_hint=severity,
    )


def _parse_combined_ts(value: str) -> Any:
    from datetime import datetime

    from ..core.util import UTC

    for fmt in SYSLOG_TS_FORMATS:
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _now() -> Any:
    from ..core.util import utcnow

    return utcnow()


__all__ = [
    "COMBINED_LOG",
    "MAX_BYTES_PER_RUN",
    "MAX_EVENTS_PER_FILE",
    "LogTailCollector",
    "ParsedLine",
    "TailState",
    "parse_combined_log",
    "parse_json_log",
    "parse_log_line",
]
