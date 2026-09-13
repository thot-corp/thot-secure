"""Journalisation structurée (JSON par défaut) — sans dépendance externe.

Chaque enregistrement peut porter un contexte de corrélation (``tenant_id``, ``actor``,
``request_id``, ``event_id``, ``finding_id``, ``action_id``). Les valeurs sensibles sont
masquées avant écriture : un log de sécurité ne doit jamais devenir une fuite.
"""

from __future__ import annotations

import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar
from typing import Any

from .util import redact_secrets

_CTX: ContextVar[dict[str, Any]] = ContextVar("thotsecure_log_context", default={})

#: Attributs standards de ``logging`` : tout le reste est traité comme contexte applicatif.
_RESERVED = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)

#: Préfixe appliqué aux clés réservées passées par erreur dans ``extra=``.
_ESCAPE_PREFIX = "ctx_"


class SafeLogger(logging.Logger):
    """Logger qui ne peut pas planter sur une clé ``extra`` réservée.

    ``logging`` lève ``KeyError: Attempt to overwrite 'name' in LogRecord`` lorsqu'une clé
    réservée est passée dans ``extra``. Un journal qui plante **au moment précis** où l'on
    journalise une erreur est inacceptable (c'est exactement ce qui s'est produit ici lors
    du rejet d'un playbook) : la clé fautive est donc renommée (``name`` → ``ctx_name``)
    plutôt que de faire échouer l'appel.
    """

    def makeRecord(  # type: ignore[override]
        self,
        name: str,
        level: int,
        fn: str,
        lno: int,
        msg: Any,
        args: Any,
        exc_info: Any,
        func: str | None = None,
        extra: Any = None,
        sinfo: str | None = None,
    ) -> logging.LogRecord:
        if extra:
            extra = {
                (f"{_ESCAPE_PREFIX}{key}" if key in _RESERVED else key): value
                for key, value in extra.items()
            }
        return super().makeRecord(name, level, fn, lno, msg, args, exc_info, func, extra, sinfo)


# Installé dès l'import du module : tous les loggers créés ensuite héritent du comportement,
# car les modules appellent ``get_logger`` après avoir importé ce module.
logging.setLoggerClass(SafeLogger)


def bind_context(**values: Any) -> None:
    """Enrichit le contexte de journalisation de la tâche courante."""
    current = dict(_CTX.get())
    current.update({k: v for k, v in values.items() if v is not None})
    _CTX.set(current)


def clear_context() -> None:
    _CTX.set({})


def current_context() -> dict[str, Any]:
    return dict(_CTX.get())


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value, max_length=2048)
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(v) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    """Format une ligne = un objet JSON, prêt pour Loki/ELK/Datadog."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": redact_secrets(record.getMessage(), max_length=8192),
        }
        payload.update(_CTX.get())
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = _redact_value(value)
        if record.exc_info:
            payload["exception"] = redact_secrets(
                self.formatException(record.exc_info), max_length=8192
            )
        return json.dumps(payload, ensure_ascii=False, default=str)


class ConsoleFormatter(logging.Formatter):
    """Format lisible pour le développement humain."""

    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[41m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        context = _CTX.get()
        suffix = ""
        if context:
            parts = [
                f"{k}={v}" for k, v in context.items() if k in {"tenant_id", "actor", "request_id"}
            ]
            if parts:
                suffix = " [" + " ".join(parts) + "]"
        message = redact_secrets(record.getMessage(), max_length=8192)
        line = f"{time.strftime('%H:%M:%S', time.localtime(record.created))} {color}{record.levelname:<8}{self.RESET} {record.name:<28} {message}{suffix}"
        if record.exc_info:
            line += "\n" + redact_secrets(self.formatException(record.exc_info), max_length=8192)
        return line


def configure_logging(
    level: str = "INFO",
    fmt: str = "json",
    *,
    stream: Any | None = None,
) -> None:
    """Configure le logger racine. Idempotent : appelable plusieurs fois sans doublon."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else ConsoleFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Uvicorn garde ses propres handlers : on les aligne pour éviter les lignes en double.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True

    # Le protocole NATS est très bavard en DEBUG : on le bride par défaut.
    logging.getLogger("thotsecure.bus.nats").setLevel(max(logging.INFO, root.level))


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name if name.startswith("thotsecure") else f"thotsecure.{name}")


__all__ = [
    "ConsoleFormatter",
    "JsonFormatter",
    "SafeLogger",
    "bind_context",
    "clear_context",
    "configure_logging",
    "current_context",
    "get_logger",
    "new_request_id",
]
