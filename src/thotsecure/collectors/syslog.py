"""Réception syslog (RFC 3164 / RFC 5424) sur UDP.

Collecteur particulier : il ne « passe » pas à intervalle régulier, il **écoute**. Il expose
donc ``serve()`` en plus de ``collect()`` (qui renvoie simplement une passe ignorée).

L'écoute est désactivée par défaut (``THOT_SYSLOG_ENABLED=false``) : ouvrir un port UDP
est une décision d'exploitation, pas un effet de bord d'installation. Le parseur, lui, est une
fonction pure — donc testable sans ouvrir le moindre socket.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from typing import Any

from ..core.logging_setup import get_logger
from ..core.util import UTC, utcnow
from .base import Collector, CollectorContext, CollectorResult

log = get_logger("collectors.syslog")

#: RFC 5424 : <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s+"
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<rest>.*)$",
    re.DOTALL,
)

#: RFC 3164 : <PRI>Mmm dd hh:mm:ss HOST TAG: MSG
#: Le motif du tag exclut le crochet ouvrant, sinon ``sshd[1234]`` serait capturé en entier
#: comme nom d'application (et le PID perdu).
RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\s\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$",
    re.DOTALL,
)

#: Sans en-tête PRI : on accepte quand même (beaucoup d'équipements en omettent).
BARE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$", re.DOTALL)

#: Composantes d'un horodatage RFC 3164 : « Mon dd hh:mm:ss », **sans année** (c'est le
#: format). Analysé par composantes plutôt qu'avec ``strptime`` : depuis Python 3.13,
#: demander à ``strptime`` une date sans année émet un ``DeprecationWarning``, que le projet
#: transforme en erreur pour ses propres modules.
_RFC3164_TS = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
)

#: Numéro de mois par abréviation anglaise, seule forme normalisée par la RFC 3164.
_MONTHS: dict[str, int] = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

SEVERITY_BY_CODE: dict[int, str] = {
    0: "critical",  # Emergency
    1: "critical",  # Alert
    2: "critical",  # Critical
    3: "high",  # Error
    4: "medium",  # Warning
    5: "low",  # Notice
    6: "info",  # Informational
    7: "info",  # Debug
}

FACILITIES: dict[int, str] = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}


def parse_syslog_line(line: str) -> dict[str, Any] | None:
    """Analyse une ligne syslog et retourne un dictionnaire normalisé."""
    text = line.strip()
    if not text:
        return None

    pri = None
    matched = RFC5424.match(text)
    if matched:
        pri = int(matched.group("pri"))
        structured = matched.group("rest")
        # La partie structurée est optionnelle : on ne tente pas de l'analyser finement,
        # on la conserve brute pour qu'une règle puisse y chercher un motif.
        message = structured
        ts = _parse_rfc5424_ts(matched.group("ts"))
        return {
            "facility": FACILITIES.get(pri // 8, str(pri // 8)),
            "severity": SEVERITY_BY_CODE.get(pri % 8, "info"),
            "host": matched.group("host"),
            "app": matched.group("app"),
            "procid": matched.group("procid"),
            "msgid": matched.group("msgid"),
            "message": message.strip()[:4096],
            "ts": ts,
        }

    matched = RFC3164.match(text)
    if matched:
        pri = int(matched.group("pri"))
        return {
            "facility": FACILITIES.get(pri // 8, str(pri // 8)),
            "severity": SEVERITY_BY_CODE.get(pri % 8, "info"),
            "host": matched.group("host"),
            "app": matched.group("tag"),
            "procid": matched.group("pid") or "",
            "msgid": "",
            "message": (matched.group("msg") or "").strip()[:4096],
            "ts": _parse_rfc3164_ts(matched.group("ts")),
        }

    matched = BARE.match(text)
    if matched:
        return {
            "facility": "unknown",
            "severity": "info",
            "host": "",
            "app": "",
            "procid": "",
            "msgid": "",
            "message": matched.group("rest").strip()[:4096],
            "ts": _parse_rfc3164_ts(matched.group("ts")),
        }

    # Dernier recours : ligne brute. On ne jette jamais un journal.
    return {
        "facility": "unknown",
        "severity": "info",
        "host": "",
        "app": "",
        "procid": "",
        "msgid": "",
        "message": text[:4096],
        "ts": utcnow(),
    }


def _parse_rfc5424_ts(value: str) -> datetime:
    if value in {"-", ""}:
        return utcnow()
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return utcnow()


def _parse_rfc3164_ts(value: str) -> datetime:
    """Analyse un horodatage RFC 3164, qui ne comporte **pas** d'année.

    L'année ne peut donc pas être demandée à ``strptime`` : Python 3.13 déprécie l'analyse
    d'une date sans année (« Parsing dates involving a day of month without a year specified
    is ambiguous »), et le projet transforme les ``DeprecationWarning`` venant de ses propres
    modules en erreurs — le test de conformité pytest échouait donc sur Python 3.13.

    On analyse explicitement les composantes avec une expression régulière, puis on rattache
    l'année courante en corrigeant le passage d'année : un message de décembre reçu en janvier
    appartient à l'année précédente. C'est le comportement que le code appliquait déjà, mais
    cette fois sans dépendre d'une analyse ambiguë.
    """
    match = _RFC3164_TS.match(" ".join(value.split()))
    if match is None:
        return utcnow()
    month = _MONTHS.get(match.group("month").lower())
    if month is None:
        return utcnow()

    now = utcnow()
    try:
        candidate = datetime(
            now.year,
            month,
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=UTC,
        )
    except ValueError:  # 31 février ou heure hors bornes : message non exploitable
        return utcnow()

    # Passage d'année : un message de décembre reçu en janvier appartient à l'année précédente.
    if candidate > now.replace(microsecond=0) and (candidate - now).days > 1:
        try:
            candidate = candidate.replace(year=now.year - 1)
        except ValueError:  # 29 février d'une année bissextile
            return utcnow()
    return candidate


class _SyslogProtocol(asyncio.DatagramProtocol):
    """Protocole UDP qui normalise chaque datagramme et l'émet."""

    def __init__(self, context: CollectorContext, *, max_datagram: int = 65535) -> None:
        self.context = context
        self.max_datagram = max_datagram
        self.received = 0
        self.dropped = 0
        self.errors = 0
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # type: ignore[override]
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.received += 1
        if len(data) > self.max_datagram:
            self.dropped += 1
            return
        try:
            text = data.decode("utf-8", "replace").strip()
            if not text:
                self.dropped += 1
                return
            parsed = parse_syslog_line(text)
            if parsed is None:
                self.dropped += 1
                return
            self.context.emit(
                kind="syslog",
                source_type="syslog",
                source_name="syslog-udp",
                source_host=parsed.get("host") or addr[0],
                labels={
                    "src_ip": addr[0],
                    "src_port": addr[1],
                    "facility": parsed.get("facility", ""),
                    "syslog_severity": parsed.get("severity", "info"),
                    "app": parsed.get("app", ""),
                    "host": parsed.get("host", ""),
                    "message": parsed.get("message", ""),
                },
                payload={
                    "procid": parsed.get("procid", ""),
                    "msgid": parsed.get("msgid", ""),
                    "message_length": len(parsed.get("message", "")),
                },
                severity_hint=parsed.get("severity"),  # type: ignore[arg-type]
                ts=parsed.get("ts"),
            )
        except Exception as exc:  # noqa: BLE001 - un datagramme malformé ne tue pas l'écoute
            self.errors += 1
            log.warning("datagramme syslog ignoré", extra={"error": str(exc), "from": addr[0]})

    def error_received(self, exc: Exception) -> None:  # pragma: no cover - dépend du réseau
        self.errors += 1
        log.warning("erreur de socket syslog", extra={"error": str(exc)})

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()


class SyslogCollector(Collector):
    """Écoute syslog UDP et alimente le pipeline en continu."""

    name = "syslog"
    source_type = "syslog"
    description = "Écoute syslog (RFC 3164/5424) sur UDP et normalise les messages."
    default_interval_seconds = 0
    requires_probe_optin = False

    def __init__(self) -> None:
        self.received = 0
        self.emitted = 0
        self.errors = 0
        self.started = False

    def collect(self, context: CollectorContext) -> CollectorResult:
        """Un collecteur d'écoute n'a pas de passe périodique : on explique pourquoi."""
        return CollectorResult(
            collector=self.name,
            status="skipped",
            detail={
                "reason": (
                    "collecteur en mode écoute : démarrez le service avec "
                    "THOT_SYSLOG_ENABLED=true (il ne s'exécute pas à intervalle)"
                )
            },
        )

    def enabled(self, settings: Any, scope: Any) -> tuple[bool, str]:
        if not settings.syslog_enabled:
            return False, "THOT_SYSLOG_ENABLED=false"
        return True, "écoute syslog activée"

    async def serve(
        self, context: CollectorContext, stop_event: asyncio.Event | None = None
    ) -> None:
        """Démarre l'écoute UDP jusqu'à ``stop_event``."""
        settings = context.settings
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(context),
            local_addr=(settings.syslog_host, settings.syslog_port),
        )
        self.started = True
        log.info(
            "écoute syslog démarrée",
            extra={"host": settings.syslog_host, "port": settings.syslog_port},
        )
        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            raise
        finally:
            self.received = getattr(protocol, "received", 0)
            self.errors = getattr(protocol, "errors", 0)
            if isinstance(protocol, _SyslogProtocol):
                protocol.close()
            transport.close()
            self.started = False
            log.info(
                "écoute syslog arrêtée",
                extra={"received": self.received, "errors": self.errors},
            )

    def describe(self) -> dict[str, Any]:
        return {**super().describe(), "mode": "listener", "state": "started" if self.started else "stopped"}


__all__ = [
    "BARE",
    "FACILITIES",
    "RFC3164",
    "RFC5424",
    "SEVERITY_BY_CODE",
    "SyslogCollector",
    "parse_syslog_line",
]
