"""SDK Python officiel pour l'API Thot Secure v0.1.0.

Exemple minimal ::

    import os
    from thotsecure_sdk import ThotSecureClient, normalize_event

    with ThotSecureClient(os.environ["THOT_URL"], os.environ["THOT_API_KEY"]) as client:
        client.ingest_event(normalize_event('127.0.0.1 - - [14/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 403 12',
                                            tenant_id="acme", source_name="edge"))

**Zéro dépendance** : ``httpx`` est utilisé s'il est importable, sinon le SDK bascule
automatiquement sur ``urllib.request`` (stdlib). Aucune autre dépendance n'est requise.
"""

from __future__ import annotations

from .client import DEFAULT_BASE_URL, MAX_BATCH_SIZE, ThotSecureClient
from .errors import (
    ThotSecureError,
    AuthenticationError,
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
    ServerError,
    TransportError,
    ValidationError,
    WebSocketError,
)
from .helpers import (
    MAX_PAYLOAD_BYTES,
    chunked,
    env,
    from_syslog_line,
    iter_jsonl,
    new_event_id,
    normalize_event,
    now_iso,
    parse_http_log_line,
    parse_timestamp,
    pseudonymize_ip,
    pseudonymize_ip_fields,
    redact_secrets,
    truncate_payload,
)
from .models import (
    Action,
    ApiKey,
    AuditRecord,
    AuditVerification,
    CollectorStatus,
    Decision,
    Event,
    Finding,
    IngestOutcome,
    IngestResult,
    Page,
    Playbook,
    Rule,
    RuleValidation,
    StatsOverview,
    Tenant,
)
from .transport import (
    HttpRequest,
    HttpResponse,
    HttpxTransport,
    RetryingTransport,
    Transport,
    UrllibTransport,
    create_transport,
    httpx_available,
)
from .ws import FRAME_TYPES, Frame, WebSocketClient, WebSocketConnection, build_ws_url

__version__ = "0.1.0"

#: Version du contrat d'interface implémentée (docs/architecture/api-contract.md).
API_CONTRACT_VERSION = "0.1.0"

__all__ = [
    "__version__",
    "API_CONTRACT_VERSION",
    "ThotSecureClient",
    "DEFAULT_BASE_URL",
    "MAX_BATCH_SIZE",
    "MAX_PAYLOAD_BYTES",
    # erreurs
    "ThotSecureError",
    "AuthenticationError",
    "PermissionDeniedError",
    "NotFoundError",
    "ConflictError",
    "ValidationError",
    "RateLimitedError",
    "ServerError",
    "TransportError",
    "WebSocketError",
    # modèles
    "Action",
    "ApiKey",
    "AuditRecord",
    "AuditVerification",
    "CollectorStatus",
    "Decision",
    "Event",
    "Finding",
    "IngestOutcome",
    "IngestResult",
    "Page",
    "Playbook",
    "Rule",
    "RuleValidation",
    "StatsOverview",
    "Tenant",
    # transport
    "HttpRequest",
    "HttpResponse",
    "Transport",
    "UrllibTransport",
    "HttpxTransport",
    "RetryingTransport",
    "create_transport",
    "httpx_available",
    # WebSocket
    "Frame",
    "FRAME_TYPES",
    "WebSocketClient",
    "WebSocketConnection",
    "build_ws_url",
    # helpers
    "chunked",
    "env",
    "from_syslog_line",
    "iter_jsonl",
    "new_event_id",
    "normalize_event",
    "now_iso",
    "parse_http_log_line",
    "parse_timestamp",
    "pseudonymize_ip",
    "pseudonymize_ip_fields",
    "redact_secrets",
    "truncate_payload",
]
