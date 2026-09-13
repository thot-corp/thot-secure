"""Audit défensif de la surface d'exposition **de ses propres actifs**.

Ce collecteur vérifie, sur les URLs explicitement déclarées par le tenant :

* les en-têtes de sécurité attendus (HSTS, CSP, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, X-Frame-Options) ;
* les attributs des cookies (``Secure``, ``HttpOnly``, ``SameSite``) ;
* la divulgation de version dans les en-têtes ``Server`` / ``X-Powered-By`` ;
* la redirection HTTP → HTTPS ;
* la présence de fichiers de configuration exposés (``/.git/config``, ``/.env``,
  ``/server-status``…) ;
* l'absence de ``/.well-known/security.txt`` (canal de divulgation responsable).

Ce n'est **pas** un scanner de vulnérabilités et ce n'est **pas** un outil offensif : une
requête par contrôle, aucune charge utile d'attaque, aucune énumération, aucun test
d'intrusion. Les chemins testés sont des fichiers de configuration oubliés, ce qui est un
contrôle de durcissement standard.

L'accès est doublement verrouillé : l'actif doit être déclaré, et le tenant doit avoir activé
``allow_probe: true``.
"""

from __future__ import annotations

import time
from typing import Any

from ..core.models import Severity
from .base import Collector, CollectorContext, CollectorResult
from .net import fetch, host_of, scheme_of

#: En-têtes de sécurité vérifiés, avec la sévérité associée et l'explication à destination
#: de l'analyste (un rapport doit dire *pourquoi*, pas seulement *quoi*).
SECURITY_HEADERS: dict[str, tuple[str, Severity, str]] = {
    "strict-transport-security": (
        "missing_hsts",
        "medium",
        "Sans HSTS, la première requête peut être interceptée et rétrogradée en HTTP.",
    ),
    "content-security-policy": (
        "missing_csp",
        "medium",
        "Sans CSP, une injection de contenu s'exécute directement dans le navigateur.",
    ),
    "x-content-type-options": (
        "missing_xcto",
        "low",
        "Sans nosniff, le navigateur peut interpréter un fichier comme un script.",
    ),
    "referrer-policy": (
        "missing_referrer_policy",
        "low",
        "Sans Referrer-Policy, les URL internes fuient vers les sites tiers.",
    ),
    "permissions-policy": (
        "missing_permissions_policy",
        "info",
        "Sans Permissions-Policy, les API navigateur restent accessibles sans restriction.",
    ),
    "x-frame-options": (
        "missing_frame_options",
        "low",
        "Sans protection anti-cadrage, le site est exposé au clickjacking.",
    ),
}

#: Chemins de configuration fréquemment exposés par erreur. Ce sont des fichiers **statiques**
#: attendus ; on ne sonde aucun point d'entrée applicatif et on n'envoie aucune charge utile.
EXPOSED_PATHS: tuple[tuple[str, Severity, str], ...] = (
    (
        "/.git/config",
        "high",
        "Dépôt Git exposé : le code source et l'historique sont téléchargeables.",
    ),
    (
        "/.env",
        "critical",
        "Fichier d'environnement exposé : secrets et identifiants de base de données.",
    ),
    ("/.svn/entries", "medium", "Métadonnées Subversion exposées."),
    ("/server-status", "medium", "Page d'état du serveur web exposée publiquement."),
    ("/phpinfo.php", "high", "Page phpinfo exposée : configuration, chemins et versions révélés."),
    (
        "/actuator/env",
        "high",
        "Point d'entrée Spring Boot Actuator exposé : variables d'environnement.",
    ),
    ("/server-info", "medium", "Page d'information serveur Apache exposée."),
    ("/web.config", "medium", "Fichier de configuration IIS exposé."),
    ("/.DS_Store", "low", "Fichier macOS exposé : révèle l'arborescence du site."),
)


class WebProbeCollector(Collector):
    """Contrôle de durcissement de la surface web déclarée."""

    name = "web_probe"
    source_type = "web_probe"
    description = "Audit de durcissement des actifs web déclarés (en-têtes, cookies, exposition)."
    default_interval_seconds = 3600
    requires_probe_optin = True

    def collect(self, context: CollectorContext) -> CollectorResult:
        result = CollectorResult(collector=self.name)
        settings = context.settings
        scope = context.scope

        urls: list[str] = []
        for asset in scope.assets:
            urls.extend(asset.urls or [])
        if not urls:
            return self._skip(f"aucune URL déclarée pour le tenant '{scope.tenant_id}'")

        max_targets = settings.http_probe_max_targets
        if len(urls) > max_targets:
            result.add_error(
                f"{len(urls)} URLs déclarées, limité à {max_targets} (THOT_HTTP_PROBE_MAX_TARGETS)"
            )
            urls = urls[:max_targets]

        result.detail["targets"] = urls
        delay = max(0.0, settings.http_probe_delay_seconds)

        for url in urls:
            try:
                result.events.extend(self._probe_url(url, context))
            except Exception as exc:
                result.add_error(f"{url}: {exc}")
            if delay:
                # Espacement volontaire : on n'inflige pas de charge à la cible.
                time.sleep(delay)

        result.detail["checked"] = len(urls)
        result.finished_at = result.finished_at or _now()
        return result

    # ----------------------------------------------------------------------------------

    def _probe_url(self, url: str, context: CollectorContext) -> list:
        host = host_of(url)
        events = []

        response = fetch(url, timeout=context.settings.http_probe_timeout_seconds)
        if not response.ok and response.error:
            events.append(
                context.make_event(
                    kind="http.response",
                    source_type=self.source_type,
                    source_name=self.name,
                    source_host=host,
                    labels={"check": "target_unreachable", "url": url, "host": host},
                    payload={"error": response.error},
                    severity_hint="info",
                )
            )
            return events

        events.append(
            context.make_event(
                kind="http.response",
                source_type=self.source_type,
                source_name=self.name,
                source_host=host,
                labels={
                    "check": "reachable",
                    "url": url,
                    "host": host,
                    "status": response.status,
                    "scheme": scheme_of(url),
                },
                payload=response.to_dict(),
            )
        )

        for header, (check, severity, explanation) in SECURITY_HEADERS.items():
            value = response.header(header)
            if value:
                continue
            # X-Frame-Options est redondant si CSP définit frame-ancestors.
            if header == "x-frame-options":
                csp = response.header("content-security-policy") or ""
                if "frame-ancestors" in csp:
                    continue
            events.append(
                context.make_event(
                    kind="http.response",
                    source_type=self.source_type,
                    source_name=self.name,
                    source_host=host,
                    labels={"check": check, "url": url, "host": host, "header": header},
                    payload={"explanation": explanation, "status": response.status},
                    severity_hint=severity,
                )
            )

        events.extend(self._check_cookies(url, host, response, context))
        events.extend(self._check_banner(url, host, response, context))

        if scheme_of(url) == "http":
            events.append(
                context.make_event(
                    kind="http.response",
                    source_type=self.source_type,
                    source_name=self.name,
                    source_host=host,
                    labels={"check": "no_https", "url": url, "host": host},
                    payload={
                        "explanation": "L'actif est déclaré en HTTP : le trafic n'est pas chiffré."
                    },
                    severity_hint="high",
                )
            )

        events.extend(self._check_exposed_paths(url, host, context))

        if not response.header("content-security-policy") and not _has_security_txt(url, context):
            events.append(
                context.make_event(
                    kind="http.response",
                    source_type=self.source_type,
                    source_name=self.name,
                    source_host=host,
                    labels={"check": "missing_security_txt", "url": url, "host": host},
                    payload={
                        "explanation": (
                            "Aucun /.well-known/security.txt : les chercheurs n'ont pas de canal "
                            "de divulgation identifié."
                        )
                    },
                    severity_hint="info",
                )
            )
        return events

    # ----------------------------------------------------------------------------------

    def _check_cookies(self, url: str, host: str, response: Any, context: CollectorContext) -> list:
        events = []
        raw_cookies = response.headers.get("set-cookie")
        if not raw_cookies:
            return events
        lowered = raw_cookies.lower()
        if "secure" not in lowered:
            events.append(
                context.make_event(
                    kind="http.response",
                    source_type=self.source_type,
                    source_name=self.name,
                    source_host=host,
                    labels={"check": "cookie_without_secure", "url": url, "host": host},
                    payload={
                        "explanation": (
                            "Un cookie de session sans attribut Secure peut fuiter en HTTP."
                        )
                    },
                    severity_hint="medium",
                )
            )
        if "httponly" not in lowered:
            events.append(
                context.make_event(
                    kind="http.response",
                    source_type=self.source_type,
                    source_name=self.name,
                    source_host=host,
                    labels={"check": "cookie_without_httponly", "url": url, "host": host},
                    payload={
                        "explanation": (
                            "Sans HttpOnly, un script injecté peut lire le cookie de session."
                        )
                    },
                    severity_hint="medium",
                )
            )
        if "samesite" not in lowered:
            events.append(
                context.make_event(
                    kind="http.response",
                    source_type=self.source_type,
                    source_name=self.name,
                    source_host=host,
                    labels={"check": "cookie_without_samesite", "url": url, "host": host},
                    payload={
                        "explanation": (
                            "Sans SameSite, le site est exposé aux requêtes forgées (CSRF)."
                        )
                    },
                    severity_hint="low",
                )
            )
        return events

    def _check_banner(self, url: str, host: str, response: Any, context: CollectorContext) -> list:
        import re

        events = []
        for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            value = response.header(header)
            if not value:
                continue
            if re.search(r"\d+\.\d+", value):
                events.append(
                    context.make_event(
                        kind="http.response",
                        source_type=self.source_type,
                        source_name=self.name,
                        source_host=host,
                        labels={
                            "check": "version_disclosure",
                            "url": url,
                            "host": host,
                            "header": header,
                        },
                        payload={
                            "value": value,
                            "explanation": (
                                "Une version précise est annoncée publiquement : elle permet de "
                                "cibler une vulnérabilité connue sans effort."
                            ),
                        },
                        severity_hint="low",
                    )
                )
        return events

    def _check_exposed_paths(self, url: str, host: str, context: CollectorContext) -> list:
        from urllib.parse import urljoin

        events = []
        base = url if url.endswith("/") else f"{url}/"
        delay = max(0.0, context.settings.http_probe_delay_seconds)
        for path, severity, explanation in EXPOSED_PATHS:
            target = urljoin(base, path.lstrip("/"))
            response = fetch(
                target, timeout=context.settings.http_probe_timeout_seconds, method="GET"
            )
            if delay:
                time.sleep(delay)
            if response.status in {200, 301, 302, 401, 403} and response.status != 404:
                # 200 = exposé ; 401/403 = présent mais protégé (à signaler comme mineur).
                exposed = response.status == 200
                signals = _match_signature(path, response.body_snippet)
                if not exposed and not signals:
                    continue
                events.append(
                    context.make_event(
                        kind="http.response",
                        source_type=self.source_type,
                        source_name=self.name,
                        source_host=host,
                        labels={
                            "check": "exposed_path" if exposed else "restricted_path",
                            "url": target,
                            "host": host,
                            "path": path,
                            "status": response.status,
                        },
                        payload={
                            "explanation": explanation,
                            "signature_match": signals,
                            "size": len(response.body_snippet),
                        },
                        severity_hint=severity if exposed else "info",
                    )
                )
        return events


def _match_signature(path: str, body: str) -> list[str]:
    """Confirme l'exposition par une signature de contenu (et non seulement par le code HTTP).

    Une page 200 personnalisée renvoyée pour toutes les URL produirait sinon une avalanche de
    faux positifs — l'erreur classique d'un scanner naïf.
    """
    signatures = {
        "/.git/config": ["[core]", "repositoryformatversion"],
        "/.env": ["APP_KEY", "DB_PASSWORD", "SECRET_KEY", "="],
        "/svn/entries": ["dir", "svn"],
        "/server-status": ["Apache Server Status", "Server Version"],
        "/phpinfo.php": ["phpinfo()", "PHP Version"],
        "/actuator/env": ["propertySources", "activeProfiles"],
        "/server-info": ["Server Settings", "Apache Server Information"],
        "/web.config": ["<configuration", "system.web"],
        "/.DS_Store": ["Bud1"],
    }
    for key, markers in signatures.items():
        if key in path:
            return [marker for marker in markers if marker.lower() in body.lower()]
    return []


def _has_security_txt(url: str, context: CollectorContext) -> bool:
    from urllib.parse import urljoin

    base = url if url.endswith("/") else f"{url}/"
    response = fetch(
        urljoin(base, ".well-known/security.txt"),
        timeout=context.settings.http_probe_timeout_seconds,
    )
    return response.status == 200 and "contact" in response.body_snippet.lower()


def _now():
    from ..core.util import utcnow

    return utcnow()


__all__ = ["EXPOSED_PATHS", "SECURITY_HEADERS", "WebProbeCollector"]
