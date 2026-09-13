"""Authentification : clés API hachées, sessions signées, amorçage.

Deux mécanismes, deux usages :

* **clé API** (``X-API-Key``) pour les machines : CLI, CI, collecteurs, SDK. Format
  ``thot_<identifiant>_<secret>``, stockée sous forme d'empreinte **scrypt** avec un poivre
  serveur. L'identifiant en clair permet une recherche en O(1) sans jamais stocker le secret.
* **session signée** (cookie) pour la console web : HMAC-SHA256 sur
  ``tenant|rôle|clé|expiration``, ``HttpOnly`` + ``SameSite=Strict``.

Performance : scrypt coûte ~20 ms. Authentifier chaque requête avec serait intenable à
600 req/min. Les authentifications réussies sont donc mises en cache 60 secondes (invalidé à
la révocation), et ``last_used_at`` est écrit au plus une fois par minute et par clé pour
éviter l'amplification d'écriture.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from ..audit.chain import AuditChain
from ..core.config import DEV_BOOTSTRAP_KEY, Settings
from ..core.errors import AuthenticationError, NotFoundError
from ..core.logging_setup import get_logger
from ..core.models import ApiKeyInfo, ApiKeyRecord, Principal, Role, Tenant
from ..core.util import iso_z, new_id, parse_dt, token, utcnow
from ..storage.store import Store
from .rbac import build_principal

log = get_logger("tenancy.auth")

KEY_PREFIX = "thot_"
SCRYPT_N = 2**13
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32

#: Durée de mise en cache d'une authentification réussie (secondes).
AUTH_CACHE_TTL = 60.0

#: Intervalle minimal d'écriture de ``last_used_at`` (secondes).
TOUCH_INTERVAL = 60.0


@dataclass(slots=True)
class _CacheEntry:
    principal: Principal
    expires_at: float


class ApiKeyService:
    """Gestion des clés API et des sessions."""

    def __init__(self, store: Store, settings: Settings, audit: AuditChain | None = None) -> None:
        self.store = store
        self.settings = settings
        self.audit = audit
        self._cache: dict[str, _CacheEntry] = {}
        self._touch_seen: dict[str, float] = {}
        self._lock = threading.Lock()
        self.authentications = 0
        self.failures = 0

    # ----------------------------------------------------------------------------------
    # Empreintes
    # ----------------------------------------------------------------------------------

    def _pepper(self) -> bytes:
        return self.settings.secret_key.encode("utf-8")

    def hash_key(self, api_key: str) -> str:
        """Empreinte scrypt salée par le poivre serveur."""
        digest = hashlib.scrypt(
            api_key.encode("utf-8"),
            salt=self._pepper(),
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
        )
        return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${digest.hex()}"

    @staticmethod
    def split_key(api_key: str) -> tuple[str, str] | None:
        """Découpe ``thot_<key_id>_<secret>``. Retourne ``None`` si le format est invalide."""
        parts = (api_key or "").split("_")
        if len(parts) != 3 or parts[0] != "thot":
            return None
        key_id, secret_part = parts[1], parts[2]
        if not key_id or len(secret_part) < 16:
            return None
        return key_id, secret_part

    # ----------------------------------------------------------------------------------
    # Création / révocation
    # ----------------------------------------------------------------------------------

    def create(
        self,
        *,
        tenant_id: str,
        role: Role = "viewer",
        label: str = "",
        actor: str = "cli",
        actor_role: str = "admin",
    ) -> tuple[ApiKeyInfo, str]:
        """Crée une clé API. Le secret n'est retourné **qu'une seule fois**."""
        tenant = self.store.get_tenant(tenant_id)
        if tenant is None:
            raise NotFoundError(f"tenant inconnu: {tenant_id}", details={"tenant_id": tenant_id})

        key_id = new_id("k").upper()[:12]
        secret_part = token(24).replace("-", "").replace("_", "")
        api_key = f"{KEY_PREFIX}{key_id}_{secret_part}"
        record = ApiKeyRecord(
            key_id=key_id,
            tenant_id=tenant.tenant_id,
            label=label[:80],
            role=role,
            key_hash=self.hash_key(api_key),
            key_prefix=api_key[: len(KEY_PREFIX) + 6],
            created_at=utcnow(),
        )
        self.store.insert_api_key(record)
        if self.audit is not None:
            self.audit.record(
                tenant_id=tenant.tenant_id,
                actor=actor,
                actor_role=actor_role,
                action="key.create",
                target={"type": "api_key", "id": key_id},
                after={"key_id": key_id, "role": role, "label": record.label},
                context={"note": "le secret n'est jamais journalisé ni relisible"},
            )
        log.info(
            "clé API créée",
            extra={"tenant_id": tenant.tenant_id, "key_id": key_id, "role": role},
        )
        return ApiKeyInfo(**record.model_dump(exclude={"key_hash"})), api_key

    def revoke(self, *, key_id: str, tenant_id: str | None = None, actor: str = "cli") -> bool:
        record = self.store.get_api_key(key_id)
        if record is None:
            raise NotFoundError(f"clé API inconnue: {key_id}", details={"key_id": key_id})
        if tenant_id and record.tenant_id != tenant_id:
            # Un tenant ne peut pas révoquer la clé d'un autre : on répond « introuvable »
            # pour ne pas révéler l'existence de la ressource.
            raise NotFoundError(f"clé API inconnue: {key_id}")
        revoked = self.store.revoke_api_key(key_id, tenant_id=tenant_id)
        with self._lock:
            self._cache.clear()
        if revoked and self.audit is not None:
            self.audit.record(
                tenant_id=record.tenant_id,
                actor=actor,
                actor_role="admin",
                action="key.revoke",
                target={"type": "api_key", "id": key_id},
                before={"revoked_at": None},
                after={"revoked_at": iso_z(utcnow())},
            )
        log.warning(
            "clé API révoquée",
            extra={"tenant_id": record.tenant_id, "key_id": key_id, "actor": actor},
        )
        return revoked

    def list_keys(self, tenant_id: str) -> list[ApiKeyInfo]:
        return [
            ApiKeyInfo(**record.model_dump(exclude={"key_hash"}))
            for record in self.store.list_api_keys(tenant_id)
        ]

    # ----------------------------------------------------------------------------------
    # Authentification
    # ----------------------------------------------------------------------------------

    def authenticate(self, api_key: str | None, *, request_id: str | None = None) -> Principal:
        """Authentifie une clé API. Lève ``AuthenticationError`` en cas d'échec."""
        self.authentications += 1
        if not api_key:
            self.failures += 1
            raise AuthenticationError("en-tête X-API-Key manquant")

        cache_key = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and cached.expires_at > now:
                return cached.principal
            if cached:
                self._cache.pop(cache_key, None)

        split = self.split_key(api_key)
        if split is None:
            self.failures += 1
            raise AuthenticationError(
                "format de clé API invalide (attendu: thot_<identifiant>_<secret>)"
            )
        key_id, _ = split
        record = self.store.get_api_key(key_id)
        if record is None or record.revoked_at is not None:
            self.failures += 1
            raise AuthenticationError("clé API inconnue ou révoquée")

        # Comparaison à temps constant sur l'empreinte : jamais de comparaison de secrets.
        candidate = self.hash_key(api_key)
        if not hmac.compare_digest(candidate, record.key_hash):
            self.failures += 1
            log.warning(
                "échec d'authentification",
                extra={"key_id": key_id, "request_id": request_id},
            )
            raise AuthenticationError("clé API invalide")

        principal = build_principal(
            tenant_id=record.tenant_id,
            role=record.role,
            key_id=record.key_id,
            label=record.label,
        )
        with self._lock:
            self._cache[cache_key] = _CacheEntry(principal=principal, expires_at=now + AUTH_CACHE_TTL)
            last_touch = self._touch_seen.get(key_id, 0.0)
            should_touch = now - last_touch > TOUCH_INTERVAL
            if should_touch:
                self._touch_seen[key_id] = now
        if should_touch:
            self.store.touch_api_key(key_id)
        return principal

    def invalidate(self, key_id: str | None = None) -> None:
        """Vide le cache d'authentification (après révocation ou création)."""
        with self._lock:
            if key_id is None:
                self._cache.clear()
            else:
                self._cache = {
                    digest: entry
                    for digest, entry in self._cache.items()
                    if entry.principal.key_id != key_id
                }

    # ----------------------------------------------------------------------------------
    # Sessions de la console
    # ----------------------------------------------------------------------------------

    def issue_session(self, principal: Principal, *, ttl_seconds: int | None = None) -> str:
        """Émet un jeton de session signé (HMAC-SHA256)."""
        ttl = ttl_seconds or self.settings.session_ttl_seconds
        payload = {
            "tenant_id": principal.tenant_id,
            "role": principal.role,
            "key_id": principal.key_id or "",
            "exp": int(time.time()) + ttl,
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")
        signature = hmac.new(self._pepper(), encoded.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{encoded}.{signature}"

    def verify_session(self, session_token: str | None) -> Principal | None:
        """Vérifie un jeton de session. Retourne ``None`` si invalide ou expiré."""
        if not session_token or "." not in session_token:
            return None
        encoded, _, signature = session_token.partition(".")
        expected = hmac.new(self._pepper(), encoded.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            log.warning("signature de session invalide")
            return None
        try:
            padded = encoded + "=" * (-len(encoded) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        key_id = payload.get("key_id") or None
        # Une session adossée à une clé révoquée devient immédiatement invalide.
        if key_id is not None:
            record = self.store.get_api_key(key_id)
            if record is None or record.revoked_at is not None:
                return None
        return build_principal(
            tenant_id=str(payload.get("tenant_id", "")),
            role=str(payload.get("role", "viewer")),
            key_id=key_id,
            label="console",
        )

    # ----------------------------------------------------------------------------------
    # Amorçage
    # ----------------------------------------------------------------------------------

    def bootstrap(self) -> Tenant | None:
        """Crée le tenant et la clé d'administration initiaux si la base est vide.

        La clé d'amorçage est publique (documentée) : elle est refusée en production
        (``THOT_ENV=prod``) et signalée à chaque démarrage en développement.
        """
        tenants = self.store.list_tenants()
        if tenants:
            return None
        tenant = Tenant(
            tenant_id=self.settings.demo_tenant if self.settings.env == "dev" else "admin",
            name="Tenant d'amorçage",
            mode="supervised",
            dry_run=True,
        )
        self.store.upsert_tenant(tenant)
        bootstrap_key = self.settings.bootstrap_api_key or DEV_BOOTSTRAP_KEY
        record = ApiKeyRecord(
            key_id="BOOTSTRAP",
            tenant_id=tenant.tenant_id,
            label="clé d'amorçage (à révoquer)",
            role="admin",
            key_hash=self.hash_key(bootstrap_key),
            key_prefix=bootstrap_key[:12],
            created_at=utcnow(),
        )
        self.store.insert_api_key(record)
        if self.audit is not None:
            self.audit.record(
                tenant_id=tenant.tenant_id,
                actor="system:bootstrap",
                actor_role="system",
                action="tenant.create",
                target={"type": "tenant", "id": tenant.tenant_id},
                after={"tenant_id": tenant.tenant_id, "mode": tenant.mode, "dry_run": tenant.dry_run},
                context={
                    "note": "tenant d'amorçage créé automatiquement",
                    "bootstrap_key_is_dev": self.settings.bootstrap_key_is_dev,
                },
            )
        log.warning(
            "tenant d'amorçage créé",
            extra={"tenant_id": tenant.tenant_id, "key_id": "BOOTSTRAP"},
        )
        return tenant

    def stats(self) -> dict[str, Any]:
        return {
            "authentications": self.authentications,
            "failures": self.failures,
            "cached": len(self._cache),
            "scrypt": {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
        }


def principal_from_token_payload(payload: dict[str, Any]) -> Principal:
    """Construit un principal depuis une charge de session (utilisé par les tests)."""
    return build_principal(
        tenant_id=str(payload.get("tenant_id", "")),
        role=str(payload.get("role", "viewer")),
        key_id=payload.get("key_id"),
        label=str(payload.get("label", "")),
    )


def mask_key(api_key: str) -> str:
    """Représentation masquée d'une clé, sûre à journaliser."""
    split = ApiKeyService.split_key(api_key)
    if split is None:
        return "<clé invalide>"
    key_id, _ = split
    return f"{KEY_PREFIX}{key_id}_<secret masqué>"


def generate_secret_key() -> str:
    """Génère une clé de signature utilisable dans ``THOT_SECRET_KEY``."""
    return secrets.token_urlsafe(48)


__all__ = [
    "AUTH_CACHE_TTL",
    "KEY_PREFIX",
    "SCRYPT_N",
    "TOUCH_INTERVAL",
    "ApiKeyService",
    "generate_secret_key",
    "mask_key",
    "principal_from_token_payload",
]
