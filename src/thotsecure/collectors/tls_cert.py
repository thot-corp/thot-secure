"""Surveillance des certificats TLS des actifs déclarés.

Un certificat expiré est l'une des causes les plus banales — et les plus coûteuses — de panne
de service et de perte de confiance. Le contrôle est ici purement défensif : on ouvre une
connexion TLS vers **notre** service déclaré et on lit ce que le serveur présente.

Contrôles effectués :

* expiration (déjà expiré, ou expire dans moins de 30 / 14 / 7 jours) ;
* protocole négocié obsolète (TLS 1.0 / 1.1, SSLv3) ;
* certificat auto-signé ou émis par une autorité inconnue (détecté via la vérification
  stricte, effectuée en parallèle) ;
* absence de nom d'hôte correspondant (mismatch) ;
* faiblesse de la taille de clé / de l'algorithme de signature, quand l'information est
  disponible.
"""

from __future__ import annotations

import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from ..core.models import Severity
from .base import Collector, CollectorContext, CollectorResult
from .net import inspect_certificate

#: Seuils d'alerte d'expiration (jours) et sévérité associée.
EXPIRY_THRESHOLDS: tuple[tuple[int, Severity, str], ...] = (
    (7, "critical", "expire dans moins de 7 jours"),
    (14, "high", "expire dans moins de 14 jours"),
    (30, "medium", "expire dans moins de 30 jours"),
)

#: Protocoles considérés comme obsolètes.
LEGACY_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"})

#: Taille minimale de clé considérée comme acceptable pour RSA.
MIN_RSA_BITS = 2048


class TlsCertCollector(Collector):
    """Vérifie l'état des certificats TLS des actifs déclarés."""

    name = "tls_cert"
    source_type = "tls_cert"
    description = "Surveille l'expiration et la robustesse des certificats TLS déclarés."
    default_interval_seconds = 21600  # 6 heures : inutile de vérifier plus souvent
    requires_probe_optin = True

    def collect(self, context: CollectorContext) -> CollectorResult:
        result = CollectorResult(collector=self.name)
        scope = context.scope

        targets: list[tuple[str, int]] = []
        for asset in scope.assets:
            for url in asset.urls:
                parsed = urlparse(url)
                if parsed.scheme != "https":
                    continue
                host = parsed.hostname or asset.normalized_host
                targets.append((host, parsed.port or 443))
        # Dédoublonnage en préservant l'ordre : un certificat par couple hôte/port.
        unique = list(dict.fromkeys(targets))
        if not unique:
            return self._skip(f"aucun actif HTTPS déclaré pour le tenant '{scope.tenant_id}'")

        result.detail["targets"] = [f"{host}:{port}" for host, port in unique]

        for host, port in unique:
            try:
                result.events.extend(self._check(host, port, context))
            except Exception as exc:
                result.add_error(f"{host}:{port}: {exc}")

        result.finished_at = result.finished_at or _now()
        return result

    # ----------------------------------------------------------------------------------

    def _check(self, host: str, port: int, context: CollectorContext) -> list:
        timeout = context.settings.http_probe_timeout_seconds
        info = inspect_certificate(host, port, timeout=timeout)
        events = []

        if not info.ok:
            events.append(
                context.make_event(
                    kind="tls.cert",
                    source_type=self.source_type,
                    source_name=self.name,
                    source_host=host,
                    labels={"check": "tls_handshake_failed", "host": host, "port": port},
                    payload={"error": info.error, **info.to_dict()},
                    severity_hint="high",
                )
            )
            return events

        events.append(
            context.make_event(
                kind="tls.cert",
                source_type=self.source_type,
                source_name=self.name,
                source_host=host,
                labels={
                    "check": "certificate",
                    "host": host,
                    "port": port,
                    "days_to_expiry": info.days_to_expiry
                    if info.days_to_expiry is not None
                    else -1,
                    "protocol": info.protocol,
                },
                payload=info.to_dict(),
            )
        )

        if info.days_to_expiry is not None:
            if info.days_to_expiry < 0:
                events.append(
                    context.make_event(
                        kind="tls.cert",
                        source_type=self.source_type,
                        source_name=self.name,
                        source_host=host,
                        labels={
                            "check": "cert_expired",
                            "host": host,
                            "port": port,
                            "days_to_expiry": info.days_to_expiry,
                        },
                        payload=info.to_dict(),
                        severity_hint="critical",
                    )
                )
            else:
                for threshold, severity, explanation in EXPIRY_THRESHOLDS:
                    if info.days_to_expiry <= threshold:
                        events.append(
                            context.make_event(
                                kind="tls.cert",
                                source_type=self.source_type,
                                source_name=self.name,
                                source_host=host,
                                labels={
                                    "check": "cert_expiring_soon",
                                    "host": host,
                                    "port": port,
                                    "days_to_expiry": info.days_to_expiry,
                                    "threshold": threshold,
                                },
                                payload={"explanation": explanation, **info.to_dict()},
                                severity_hint=severity,
                            )
                        )
                        break

        if info.protocol in LEGACY_PROTOCOLS:
            events.append(
                context.make_event(
                    kind="tls.cert",
                    source_type=self.source_type,
                    source_name=self.name,
                    source_host=host,
                    labels={
                        "check": "tls_legacy_protocol",
                        "host": host,
                        "port": port,
                        "protocol": info.protocol,
                    },
                    payload={
                        "explanation": (
                            "Protocole TLS obsolète négocié : chiffrement considéré comme cassé."
                        ),
                        **info.to_dict(),
                    },
                    severity_hint="high",
                )
            )

        verification = self._verify_chain(host, port, timeout)
        if verification is not None:
            events.append(
                context.make_event(
                    kind="tls.cert",
                    source_type=self.source_type,
                    source_name=self.name,
                    source_host=host,
                    labels={"check": "cert_untrusted", "host": host, "port": port},
                    payload={
                        "explanation": (
                            "La chaîne de certification n'est pas validable par le magasin système "
                            "(certificat auto-signé, expiré, ou autorité inconnue)."
                        ),
                        "detail": verification,
                        **info.to_dict(),
                    },
                    severity_hint="high",
                )
            )

        key_info = self._key_strength(host, port, timeout)
        if key_info is not None:
            events.append(
                context.make_event(
                    kind="tls.cert",
                    source_type=self.source_type,
                    source_name=self.name,
                    source_host=host,
                    labels={"check": "cert_weak_key", "host": host, "port": port},
                    payload={
                        "explanation": (
                            f"Clé de {key_info} bits : inférieure au minimum recommandé "
                            f"de {MIN_RSA_BITS}."
                        ),
                        **info.to_dict(),
                    },
                    severity_hint="medium",
                )
            )
        return events

    @staticmethod
    def _verify_chain(host: str, port: int, timeout: float) -> str | None:
        """Vérification stricte en parallèle : retourne la raison de l'échec, ou ``None``."""
        context = ssl.create_default_context()
        if hasattr(context, "minimum_version") and hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as raw,
                context.wrap_socket(raw, server_hostname=host),
            ):
                return None
        except ssl.SSLCertVerificationError as exc:
            return f"{exc.verify_message} (code {exc.verify_code})"
        except (ssl.SSLError, OSError):
            # Erreur réseau déjà signalée par le contrôle principal : on n'ajoute pas de bruit.
            return None

    @staticmethod
    def _key_strength(host: str, port: int, timeout: float) -> int | None:
        """Taille de clé du certificat feuille, si le serveur la communique."""
        try:
            from cryptography import x509  # type: ignore[import-not-found]
        except ImportError:
            return None
        try:
            pem = ssl.get_server_certificate((host, port))
            certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
            public_key = certificate.public_key()
            size = getattr(public_key, "key_size", None)
            if size and size < MIN_RSA_BITS:
                return int(size)
        except Exception:
            return None
        return None


def _now() -> Any:
    from ..core.util import utcnow

    return utcnow()


__all__ = ["EXPIRY_THRESHOLDS", "LEGACY_PROTOCOLS", "MIN_RSA_BITS", "TlsCertCollector"]
