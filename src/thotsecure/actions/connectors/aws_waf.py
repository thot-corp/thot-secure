"""Connecteur natif AWS WAF (WAFv2) : blocage et déblocage par mise à jour d'un IPSet.

AWS WAF n'a pas d'API « bloque cette adresse » : une adresse se bloque en l'**ajoutant à un
IPSet**, qui est ensuite référencé par une règle WAF. Ce connecteur fait donc exactement cela,
en deux appels :

1. ``GetIPSet`` — lecture des adresses courantes **et du ``LockToken``** ;
2. ``UpdateIPSet`` — écriture de la nouvelle liste, avec ce ``LockToken``.

Le ``LockToken`` est le point délicat : AWS refuse une écriture si l'IPSet a changé depuis la
lecture (``WAFOptimisticLockException``). C'est une protection utile — elle empêche d'écraser
la modification d'un collègue — mais elle rend le code naïf fragile. On relit donc l'IPSet et
on **retente une fois** ; au-delà, l'échec est remonté tel quel plutôt que masqué par une
boucle de réessai qui pourrait masquer un conflit réel.

**Signature AWS SigV4 implémentée en stdlib** (``hmac``/``hashlib``), sans ``boto3`` : le
projet n'a aucune dépendance SDK, et une signature fausse est une erreur silencieuse et
coûteuse. La justesse est donc verrouillée par les vecteurs de test officiels d'AWS dans
``tests/test_connectors_native.py`` (exemples ``AKIDEXAMPLE`` de la documentation AWS).

Ce connecteur n'implémente **pas** ``rate_limit`` : limiter un débit sur AWS WAF v2 ne se fait
pas dans un IPSet mais dans une ``RateBasedStatement`` d'une **WebACL**. Or modifier une WebACL
revient à réécrire l'objet qui décide de tout le filtrage du client : une erreur y coupe le
service, et la réversibilité (reconstruire l'état exact de la WebACL) n'est pas garantissable
par un connecteur de contre-mesure. Une riposte graduée sur AWS passe donc par un autre
levier (Cloudflare, reverse-proxy local, ou une WebACL dédiée gérée par le client).

Sécurité : la clé secrète et le jeton de session ne sont jamais journalisés, jamais inclus
dans un résultat ou une erreur, et restent masqués par ``redact_params``.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import urllib.parse
from datetime import UTC, datetime
from typing import Any

from ...core.logging_setup import get_logger
from .base import Connector, ConnectorNotConfiguredError, ConnectorResult
from .http_client import DEFAULT_TIMEOUT, HttpClient, HttpResult

log = get_logger("actions.connector.aws_waf")

ALGORITHM = "AWS4-HMAC-SHA256"

#: Nom de service utilisé dans la portée de signature (et dans l'endpoint).
SERVICE = "wafv2"

#: Cibles de l'API WAFv2 (protocole AWS JSON 1.1).
TARGET_GET_IPSET = "AWSWAF_20191119.GetIPSet"
TARGET_UPDATE_IPSET = "AWSWAF_20191119.UpdateIPSet"

CONTENT_TYPE = "application/x-amz-json-1.1"

#: Erreur de concurrence optimiste : la seule pour laquelle une nouvelle tentative est sûre.
OPTIMISTIC_LOCK_ERROR = "WAFOptimisticLockException"

#: Portée CloudFront : AWS impose la région ``us-east-1`` pour ces IPSet globaux.
CLOUDFRONT_REGION = "us-east-1"

ALLOWED_SCOPES = ("REGIONAL", "CLOUDFRONT")

#: Préfixe du jeton de rollback (:data:`rollback_token`), pour rester lisible et vérifiable.
TOKEN_PREFIX = "wafv2"


# --------------------------------------------------------------------------------------
# Signature AWS SigV4 (stdlib uniquement)
# --------------------------------------------------------------------------------------


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def hmac_sha256(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def normalize_header_value(value: Any) -> str:
    """AWS exige une valeur d'en-tête « trimée » et sans espaces multiples."""
    return " ".join(str(value).split())


def uri_encode(value: str, *, encode_slash: bool = True) -> str:
    """Encodage d'URI conforme AWS (RFC 3986, ``~`` non échappé)."""
    safe = "-_.~" if encode_slash else "-_.~/"
    return urllib.parse.quote(str(value), safe=safe, encoding="utf-8")


def canonical_query_string(query: str) -> str:
    """Query string canonique : paramètres triés par nom puis valeur, encodés."""
    if not query:
        return ""
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    encoded = sorted((uri_encode(key), uri_encode(value)) for key, value in pairs)
    return "&".join(f"{key}={value}" for key, value in encoded)


def canonical_uri(path: str) -> str:
    """URI canonique : le chemin encodé, ``/`` conservé (service non-S3)."""
    if not path:
        return "/"
    normalized = path if path.startswith("/") else f"/{path}"
    return uri_encode(normalized, encode_slash=False)


def build_canonical_request(
    *,
    method: str,
    canonical_uri_value: str,
    canonical_query: str,
    headers: dict[str, str],
    signed_headers: list[str],
    payload_hash: str,
) -> str:
    """Construit la requête canonique telle que définie par la spécification SigV4.

    ``headers`` doit être indexé par nom **en minuscules** ; seuls les en-têtes listés dans
    ``signed_headers`` sont inclus, et ils doivent exister.
    """
    canonical_headers = "".join(
        f"{name}:{normalize_header_value(headers[name])}\n" for name in signed_headers
    )
    return "\n".join(
        [
            method.upper(),
            canonical_uri_value,
            canonical_query,
            canonical_headers,
            ";".join(signed_headers),
            payload_hash,
        ]
    )


def build_string_to_sign(amz_date: str, scope: str, canonical_request: str) -> str:
    return "\n".join([ALGORITHM, amz_date, scope, sha256_hex(canonical_request.encode("utf-8"))])


def derive_signing_key(secret_access_key: str, date_stamp: str, region: str, service: str) -> bytes:
    """Clé de signature dérivée (chaîne de HMAC-SHA256 du jour, de la région, du service)."""
    key = hmac_sha256(f"AWS4{secret_access_key}".encode(), date_stamp)
    key = hmac_sha256(key, region)
    key = hmac_sha256(key, service)
    return hmac_sha256(key, "aws4_request")


def compute_signature(signing_key: bytes, string_to_sign: str) -> str:
    return hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_request(
    *,
    method: str,
    url: str,
    region: str,
    service: str,
    access_key_id: str,
    secret_access_key: str,
    payload: bytes | str = b"",
    extra_headers: dict[str, str] | None = None,
    session_token: str | None = None,
    amz_date: str | None = None,
    sign_content_sha256: bool = True,
) -> dict[str, str]:
    """Retourne les en-têtes signés à envoyer (dont ``Authorization``).

    ``amz_date`` permet de fixer l'horodatage : les tests s'en servent pour reproduire les
    vecteurs officiels AWS, la production laisse la fonction lire l'heure courante.
    """
    body = payload.encode("utf-8") if isinstance(payload, str) else payload
    parts = urllib.parse.urlsplit(url)
    host = parts.netloc
    if not host:
        raise ValueError("URL AWS invalide : hôte manquant")

    stamp = amz_date or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    date_stamp = stamp[:8]

    headers: dict[str, str] = {"host": host, "x-amz-date": stamp}
    if sign_content_sha256:
        headers["x-amz-content-sha256"] = sha256_hex(body)
    if session_token:
        headers["x-amz-security-token"] = session_token
    for name, value in (extra_headers or {}).items():
        headers[name.lower()] = normalize_header_value(value)

    signed_headers = sorted(headers)
    canonical = build_canonical_request(
        method=method,
        canonical_uri_value=canonical_uri(parts.path),
        canonical_query=canonical_query_string(parts.query),
        headers=headers,
        signed_headers=signed_headers,
        payload_hash=sha256_hex(body),
    )
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = build_string_to_sign(stamp, scope, canonical)
    signing_key = derive_signing_key(secret_access_key, date_stamp, region, service)
    signature = compute_signature(signing_key, string_to_sign)

    # Les en-têtes supplémentaires conservent leur casse d'origine : un en-tête renommé
    # (``content-type`` → ``Content-Type``) ferait diverger le corps signé du corps transmis.
    result: dict[str, str] = {
        "Host": headers["host"],
        "X-Amz-Date": headers["x-amz-date"],
    }
    if sign_content_sha256:
        result["X-Amz-Content-Sha256"] = headers["x-amz-content-sha256"]
    if session_token:
        result["X-Amz-Security-Token"] = headers["x-amz-security-token"]
    for name, value in (extra_headers or {}).items():
        result[str(name)] = str(value)
    result["Authorization"] = (
        f"{ALGORITHM} Credential={access_key_id}/{scope}, "
        f"SignedHeaders={';'.join(signed_headers)}, Signature={signature}"
    )
    return result


# --------------------------------------------------------------------------------------
# Connecteur
# --------------------------------------------------------------------------------------


class AwsWafConnector(Connector):
    """Blocage / déblocage d'adresses par mise à jour d'un IPSet WAFv2."""

    driver = "aws-waf"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"block_ip", "unblock_ip"})

    @property
    def description(self) -> str:
        return "aws-waf (WAFv2 GetIPSet/UpdateIPSet, SigV4 stdlib)"

    # -- configuration -----------------------------------------------------------------

    @property
    def ip_set_id(self) -> str:
        value = str(self.settings.get("ip_set_id") or "").strip()
        if not value:
            raise ConnectorNotConfiguredError(
                "paramètre 'ip_set_id' absent (identifiant de l'IPSet WAFv2 à maintenir)"
            )
        return value

    @property
    def ip_set_name(self) -> str:
        value = str(self.settings.get("ip_set_name") or "").strip()
        if not value:
            raise ConnectorNotConfiguredError(
                "paramètre 'ip_set_name' absent (nom de l'IPSet, exigé par GetIPSet/UpdateIPSet)"
            )
        return value

    @property
    def scope(self) -> str:
        value = str(self.settings.get("scope") or "REGIONAL").strip().upper()
        if value not in ALLOWED_SCOPES:
            raise ConnectorNotConfiguredError(
                f"paramètre 'scope' invalide: '{value}' (attendu {' ou '.join(ALLOWED_SCOPES)})"
            )
        return value

    @property
    def region(self) -> str:
        configured = str(self.settings.get("region") or CLOUDFRONT_REGION).strip()
        if self.scope == "CLOUDFRONT" and configured != CLOUDFRONT_REGION:
            log.warning(
                "portée CLOUDFRONT : la région est forcée à us-east-1 (contrainte AWS)",
                extra={"region_configuree": configured},
            )
            return CLOUDFRONT_REGION
        return configured

    @property
    def access_key_id(self) -> str:
        value = str(self.settings.get("access_key_id") or "").strip()
        if not value:
            raise ConnectorNotConfiguredError(
                "paramètre 'access_key_id' absent : préférez un rôle à privilèges minimaux "
                "(wafv2:GetIPSet et wafv2:UpdateIPSet sur l'IPSet exact)"
            )
        return value

    @property
    def secret_access_key(self) -> str:
        value = str(self.settings.get("secret_access_key") or "").strip()
        if not value:
            raise ConnectorNotConfiguredError("paramètre 'secret_access_key' absent")
        return value

    @property
    def endpoint_url(self) -> str:
        """Endpoint WAFv2. Surchargeable pour un test local ou un point de terminaison privé."""
        configured = str(self.settings.get("endpoint_url") or "").strip()
        if configured:
            return configured
        return f"https://{SERVICE}.{self.region}.amazonaws.com/"

    def _client(self) -> HttpClient:
        return HttpClient(
            driver=self.driver,
            timeout=float(self.settings.get("timeout_seconds") or DEFAULT_TIMEOUT),
            verify_tls=bool(self.settings.get("verify_tls", True)),
            allow_insecure_http=bool(self.settings.get("allow_insecure_http", False)),
        )

    # -- appels signés -----------------------------------------------------------------

    def _call_api(self, target: str, payload: dict[str, Any]) -> HttpResult:
        """Appelle l'API WAFv2 avec une requête signée SigV4."""
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = sign_request(
            method="POST",
            url=self.endpoint_url,
            region=self.region,
            service=SERVICE,
            access_key_id=self.access_key_id,
            secret_access_key=self.secret_access_key,
            payload=body,
            extra_headers={"Content-Type": CONTENT_TYPE, "X-Amz-Target": target},
            session_token=str(self.settings.get("session_token") or "") or None,
        )
        return self._client().request("POST", self.endpoint_url, headers=headers, body=body)

    @staticmethod
    def error_type(result: HttpResult) -> str:
        """Type d'erreur AWS : ``__type`` (JSON 1.1) ou ``x-amzn-errortype`` (en-tête)."""
        raw = str(result.payload.get("__type") or result.headers.get("x-amzn-errortype") or "")
        if not raw:
            return ""
        return raw.split("#")[-1].split(":")[-1].strip()

    @staticmethod
    def error_message(result: HttpResult) -> str:
        return str(
            result.payload.get("message")
            or result.payload.get("Message")
            or result.headers.get("x-amzn-errormessage")
            or ""
        ).strip()

    def _diagnose(self, result: HttpResult, target: str) -> str | None:
        """``None`` si l'appel a réussi, sinon un diagnostic **sans aucun secret**."""
        if result.transport_error:
            return f"AWS WAF injoignable: {result.error}"
        if result.ok:
            return None
        kind = self.error_type(result)
        message = self.error_message(result)
        detail = message or (result.text or "").strip().replace("\n", " ")[:200]
        label = target.rsplit(".", 1)[-1]
        if kind or detail:
            return (
                f"AWS WAF a refusé {label} (HTTP {result.status})"
                + (f" — {kind}" if kind else "")
                + (f": {detail}" if detail else "")
            )
        return f"AWS WAF: HTTP {result.status} sans corps exploitable ({label})"

    # -- lecture / écriture de l'IPSet -------------------------------------------------

    def _read_ipset(self) -> tuple[dict[str, Any] | None, str | None]:
        result = self._call_api(
            TARGET_GET_IPSET,
            {"Id": self.ip_set_id, "Name": self.ip_set_name, "Scope": self.scope},
        )
        failure = self._diagnose(result, TARGET_GET_IPSET)
        if failure:
            return None, failure
        body = result.payload.get("IPSet") or {}
        lock_token = str(result.payload.get("LockToken") or "")
        if not lock_token:
            return None, (
                "GetIPSet n'a pas rendu de LockToken : sans lui, AWS refusera toute "
                "modification — aucune écriture tentée"
            )
        addresses = [str(item) for item in (body.get("Addresses") or [])]
        return {
            "addresses": addresses,
            "lock_token": lock_token,
            "arn": str(body.get("ARN") or ""),
            "ip_address_version": str(body.get("IPAddressVersion") or "IPV4"),
        }, None

    def _write_ipset(self, addresses: list[str], lock_token: str) -> HttpResult:
        return self._call_api(
            TARGET_UPDATE_IPSET,
            {
                "Id": self.ip_set_id,
                "Name": self.ip_set_name,
                "Scope": self.scope,
                "Addresses": addresses,
                "LockToken": lock_token,
            },
        )

    # -- adresses ----------------------------------------------------------------------

    @staticmethod
    def normalize_address(raw: Any) -> tuple[str | None, str | None]:
        """Normalise une adresse au format IPSet (CIDR : ``1.2.3.4`` → ``1.2.3.4/32``)."""
        text = str(raw or "").strip()
        if not text:
            return None, "paramètre 'target' (IP ou CIDR) manquant"
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return None, f"cible invalide '{text}': adresse IP ou plage CIDR attendue"
        return str(network), None

    @staticmethod
    def build_rollback_token(scope: str, ip_set_id: str, address: str) -> str:
        return f"{TOKEN_PREFIX}:{scope}:{ip_set_id}:{address}"

    @staticmethod
    def parse_rollback_token(token: str) -> dict[str, str]:
        """Analyse ``wafv2:<scope>:<ip_set_id>:<address>`` ; ``{}`` si non reconnu."""
        parts = str(token or "").split(":", 3)
        if len(parts) != 4 or parts[0] != TOKEN_PREFIX:
            return {}
        return {"scope": parts[1], "ip_set_id": parts[2], "address": parts[3]}

    # -- opérations --------------------------------------------------------------------

    def _mutate(self, *, address: str, add: bool, operation: str) -> ConnectorResult:
        """Ajoute ou retire une adresse, avec une seule nouvelle tentative sur conflit."""
        for attempt in (1, 2):
            state, failure = self._read_ipset()
            if state is None:
                return ConnectorResult(
                    ok=False, error=failure, data={"address": address, "ip_set_id": self.ip_set_id}
                )

            current: list[str] = state["addresses"]
            if add and address in current:
                return ConnectorResult(
                    ok=True,
                    detail=(
                        f"{address} est déjà présente dans l'IPSet {self.ip_set_id} "
                        "(aucune modification envoyée)"
                    ),
                    data={
                        "address": address,
                        "ip_set_id": self.ip_set_id,
                        "scope": self.scope,
                        "addresses_count": len(current),
                        "already_present": True,
                    },
                    rollback_token=self.build_rollback_token(self.scope, self.ip_set_id, address),
                )
            if not add and address not in current:
                return ConnectorResult(
                    ok=False,
                    error=(
                        f"{address} est absente de l'IPSet {self.ip_set_id} "
                        "(déjà retirée ? ou posée dans un autre IPSet)"
                    ),
                    data={"address": address, "ip_set_id": self.ip_set_id},
                )

            target_addresses = (
                sorted({*current, address})
                if add
                else [item for item in current if item != address]
            )
            result = self._write_ipset(target_addresses, state["lock_token"])
            failure = self._diagnose(result, TARGET_UPDATE_IPSET)
            if failure is None:
                verb = "ajoutée à" if add else "retirée de"
                log.info(
                    "IPSet AWS WAF mis à jour",
                    extra={
                        "action": "add" if add else "remove",
                        "ip_set_id": self.ip_set_id,
                        "scope": self.scope,
                        "address": address,
                        "addresses_count": len(target_addresses),
                    },
                )
                return ConnectorResult(
                    ok=True,
                    detail=(
                        f"{address} {verb} l'IPSet WAFv2 {self.ip_set_id} "
                        f"({len(target_addresses)} adresse(s) déclarée(s), portée {self.scope})"
                    ),
                    data={
                        "address": address,
                        "ip_set_id": self.ip_set_id,
                        "ip_set_name": self.ip_set_name,
                        "scope": self.scope,
                        "region": self.region,
                        "addresses_count": len(target_addresses),
                        "rollback_operation": "unblock_ip" if add else "block_ip",
                    },
                    rollback_token=(
                        self.build_rollback_token(self.scope, self.ip_set_id, address)
                        if add
                        else None
                    ),
                )

            if self.error_type(result) == OPTIMISTIC_LOCK_ERROR:
                if attempt == 1:
                    log.warning(
                        "IPSet WAF modifié concurremment : relecture et nouvelle tentative unique",
                        extra={
                            "ip_set_id": self.ip_set_id,
                            "operation": operation,
                            "attempt": attempt,
                        },
                    )
                    continue
                return ConnectorResult(
                    ok=False,
                    error=(
                        "IPSet WAF modifié concurremment lors des deux tentatives "
                        "(WAFOptimisticLockException) : vérifiez qui écrit dans cet IPSet "
                        f"avant de réessayer — détail AWS: {failure}"
                    ),
                    data={"address": address, "ip_set_id": self.ip_set_id, "attempts": attempt},
                )
            return ConnectorResult(
                ok=False,
                error=failure,
                data={"address": address, "ip_set_id": self.ip_set_id, "attempts": attempt},
            )

    def op_block_ip(self, params: dict[str, Any]) -> ConnectorResult:
        address, error = self.normalize_address(params.get("target") or params.get("ip"))
        if error:
            return ConnectorResult(ok=False, error=error)
        return self._mutate(address=address, add=True, operation="block_ip")

    def op_unblock_ip(self, params: dict[str, Any]) -> ConnectorResult:
        token = str(params.get("rollback_token") or "").strip()
        parsed = self.parse_rollback_token(token)
        raw_target = params.get("target") or params.get("ip") or parsed.get("address")
        address, error = self.normalize_address(raw_target)
        if error:
            return ConnectorResult(
                ok=False,
                error=(
                    f"{error} — précisez 'target' (adresse) ou le 'rollback_token' rendu "
                    "par block_ip (wafv2:<scope>:<ip_set_id>:<adresse>)"
                ),
            )
        return self._mutate(address=address, add=False, operation="unblock_ip")

    # -- état --------------------------------------------------------------------------

    def describe_state(self) -> dict[str, Any]:
        """État du connecteur : identifiants de ressource, jamais de secret."""
        default_endpoint = f"https://{SERVICE}.{self.region}.amazonaws.com/"
        return {
            "driver": self.driver,
            "endpoint_url": str(self.settings.get("endpoint_url") or default_endpoint),
            "scope": str(self.settings.get("scope") or "REGIONAL"),
            "region_configured": bool(self.settings.get("region")),
            "ip_set_id_configured": bool(self.settings.get("ip_set_id")),
            "ip_set_name_configured": bool(self.settings.get("ip_set_name")),
            "access_key_configured": bool(self.settings.get("access_key_id")),
            "session_token_used": bool(self.settings.get("session_token")),
            "verify_tls": bool(self.settings.get("verify_tls", True)),
            "operations": sorted(self.capabilities),
        }


__all__ = [
    "ALGORITHM",
    "ALLOWED_SCOPES",
    "CLOUDFRONT_REGION",
    "CONTENT_TYPE",
    "OPTIMISTIC_LOCK_ERROR",
    "SERVICE",
    "TARGET_GET_IPSET",
    "TARGET_UPDATE_IPSET",
    "AwsWafConnector",
    "build_canonical_request",
    "build_string_to_sign",
    "canonical_query_string",
    "canonical_uri",
    "compute_signature",
    "derive_signing_key",
    "normalize_header_value",
    "sha256_hex",
    "sign_request",
    "uri_encode",
]
