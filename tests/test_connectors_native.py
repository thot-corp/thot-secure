"""Tests des connecteurs natifs — **exécutables hors ligne, sans réseau externe**.

Trois familles de vérifications, qui répondent chacune à un risque précis :

1. **Signature AWS SigV4** : c'est le point où une erreur est silencieuse et coûteuse. Les
   vecteurs **officiels** de la documentation AWS (``AKIDEXAMPLE``, ``20150830T123600Z``,
   ``us-east-1``, ``wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY``) sont rejoués à l'identique,
   et la signature produite pour un ``POST`` avec corps et ``X-Amz-Target`` est comparée à une
   **réimplémentation indépendante** écrite dans ce fichier. Une erreur de transcription ne
   peut donc pas passer : soit elle casse le vecteur officiel, soit elle fait diverger les
   deux implémentations.
2. **Protocole des API** (Cloudflare, AWS WAF, Slack, GitHub) : un serveur HTTP local
   (``http.server`` dans un fil d'exécution) enregistre chaque requête. On vérifie l'URL
   appelée, la méthode, les en-têtes, le corps envoyé, l'extraction du ``rollback_token``,
   le diagnostic d'erreur — et l'absence de tout secret dans les résultats.
3. **Sûreté** : en ``dry_run``, **aucun** connecteur natif n'émet la moindre requête (vérifié
   par compteur d'appels sur le faux serveur), et la configuration par défaut du produit reste
   entièrement simulée.

Aucun test ne contacte Cloudflare, AWS, Slack ou GitHub : les endpoints sont remplacés par
``api_base``, ``endpoint_url`` et ``api_url``, paramètres prévus pour cela.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
import re
import socket
import socketserver
import threading
import unittest
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from thotsecure.actions.connectors.aws_waf import (
    ALGORITHM,
    CONTENT_TYPE,
    TARGET_GET_IPSET,
    TARGET_UPDATE_IPSET,
    AwsWafConnector,
    build_canonical_request,
    build_string_to_sign,
    compute_signature,
    derive_signing_key,
    sha256_hex,
    sign_request,
)
from thotsecure.actions.connectors.base import ConnectorNotConfiguredError, redact_params
from thotsecure.actions.connectors.cloudflare import CloudflareConnector
from thotsecure.actions.connectors.http_webhook import HttpWebhookConnector
from thotsecure.actions.connectors.notifications import (
    GithubIssueConnector,
    SlackConnector,
)
from thotsecure.actions.connectors.simulation import SimulationConnector
from thotsecure.actions.executor import PlaybookExecutor
from thotsecure.actions.playbook_loader import load_playbooks_from_dir, parse_playbook
from thotsecure.actions.registry import DEFAULT_CONNECTORS, DRIVERS, ConnectorRegistry

#: Racine du dépôt : les playbooks livrés sont chargés tels quels par les tests d'intégration.
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------------------
# Vecteurs officiels AWS (§ « Examples of the complete Version 4 signing process »)
# --------------------------------------------------------------------------------------

AWS_ACCESS_KEY = "AKIDEXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
AWS_AMZ_DATE = "20150830T123600Z"

#: Exemple ``get-vanilla`` (service générique ``service``). AWS publie la requête canonique,
#: son empreinte ``bb579772…`` et la clé de signature dérivée ``938127b5…`` ; la signature
#: ci-dessous en **découle** et sert de verrou de non-régression — elle n'est pas présentée
#: comme une chaîne publiée telle quelle (c'est le vecteur IAM ci-dessous qui joue ce rôle,
#: avec la signature ``5d672d79…`` de la documentation AWS).
VECTOR_GET_VANILLA = {
    "method": "GET",
    "uri": "/",
    "query": "",
    "host": "example.amazonaws.com",
    "region": "us-east-1",
    "service": "service",
    "headers": {"host": "example.amazonaws.com", "x-amz-date": AWS_AMZ_DATE},
    "payload": b"",
    "canonical_request_hash": "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
    "signing_key": "938127b5336810ddb6a5d6af445fcac9e371f9ed418ed386b022aed82901be75",
    "signature": "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
    "authorization": (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    ),
}

#: Exemple AWS IAM ``ListUsers`` : c'est **ce vecteur** qui porte la signature
#: ``5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7`` publiée par AWS
#: (chaîne canonique ``f536975d…``, clé de signature ``c4afb1cc…``), avec un corps de requête
#: vide, un en-tête ``content-type`` signé et une query string.
VECTOR_IAM_LIST_USERS = {
    "method": "GET",
    "uri": "/",
    "query": "Action=ListUsers&Version=2010-05-08",
    "host": "iam.amazonaws.com",
    "region": "us-east-1",
    "service": "iam",
    "headers": {
        "content-type": "application/x-www-form-urlencoded; charset=utf-8",
        "host": "iam.amazonaws.com",
        "x-amz-date": AWS_AMZ_DATE,
    },
    "payload": b"",
    "canonical_request_hash": "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59",
    "signing_key": "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
    "signature": "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
    "authorization": (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, "
        "SignedHeaders=content-type;host;x-amz-date, "
        "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    ),
}

AUTHORIZATION_RE = re.compile(
    r"^AWS4-HMAC-SHA256 Credential=(?P<access_key>[^/]+)/(?P<date>\d{8})/"
    r"(?P<region>[^/]+)/(?P<service>[^/]+)/aws4_request, "
    r"SignedHeaders=(?P<signed>[a-z0-9;-]+), Signature=(?P<signature>[0-9a-f]{64})$"
)


# --------------------------------------------------------------------------------------
# Réimplémentation indépendante de SigV4 (sert de contre-vérification)
# --------------------------------------------------------------------------------------


def _ref_hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def reference_sigv4(
    *,
    method: str,
    host: str,
    path: str,
    query: str,
    region: str,
    service: str,
    access_key_id: str,
    secret_access_key: str,
    body: bytes,
    amz_date: str,
    extra_signed_headers: dict[str, str] | None = None,
    session_token: str | None = None,
) -> dict[str, str]:
    """SigV4 réécrit depuis la spécification, pour vérifier l'implémentation du connecteur.

    Ce code n'importe **rien** du connecteur : il ne partage que la spécification publique.
    """
    payload_hash = hashlib.sha256(body).hexdigest()
    headers: dict[str, str] = {
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token
    for name, value in (extra_signed_headers or {}).items():
        headers[name.lower()] = " ".join(value.split())

    names = sorted(headers)
    canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in names)
    canonical_request = "\n".join(
        [
            method.upper(),
            path or "/",
            query,
            canonical_headers,
            ";".join(names),
            payload_hash,
        ]
    )
    scope = f"{amz_date[:8]}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            ALGORITHM,
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    key = _ref_hmac(f"AWS4{secret_access_key}".encode(), amz_date[:8])
    for element in (region, service, "aws4_request"):
        key = _ref_hmac(key, element)
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "canonical_request": canonical_request,
        "string_to_sign": string_to_sign,
        "signature": signature,
        "authorization": (
            f"{ALGORITHM} Credential={access_key_id}/{scope}, "
            f"SignedHeaders={';'.join(names)}, Signature={signature}"
        ),
    }


def verify_received_signature(
    request: RecordedRequest,
    *,
    secret_access_key: str,
    expected_region: str | None = None,
    expected_service: str = "wafv2",
) -> str | None:
    """Recalcule la signature de la requête **reçue** ; retourne un message d'erreur sinon.

    Vérifier ce qui a été envoyé (et pas seulement ce que l'on croit avoir signé) est le seul
    moyen d'attraper une divergence entre le corps signé et le corps transmis.
    """
    authorization = request.headers.get("authorization", "")
    match = AUTHORIZATION_RE.match(authorization)
    if not match:
        return f"en-tête Authorization illisible: {authorization[:120]}"
    if expected_region and match.group("region") != expected_region:
        return f"région signée inattendue: {match.group('region')} ≠ {expected_region}"
    if match.group("service") != expected_service:
        return f"service signé inattendu: {match.group('service')}"

    signed_names = match.group("signed").split(";")
    missing = [name for name in signed_names if name not in request.headers]
    if missing:
        return f"en-têtes signés absents de la requête: {missing}"

    parts = urlsplit(request.path)
    reference = reference_sigv4(
        method=request.method,
        host=request.headers.get("host", ""),
        path=parts.path,
        query="&".join(
            sorted(
                f"{key}={value}" for key, value in parse_qsl(parts.query, keep_blank_values=True)
            )
        ),
        region=match.group("region"),
        service=match.group("service"),
        access_key_id=match.group("access_key"),
        secret_access_key=secret_access_key,
        body=request.body,
        amz_date=request.headers.get("x-amz-date", ""),
        extra_signed_headers={
            name: request.headers[name]
            for name in signed_names
            if name not in {"host", "x-amz-date", "x-amz-content-sha256", "x-amz-security-token"}
        },
    )
    if reference["signature"] != match.group("signature"):
        return (
            "signature reçue ≠ signature recalculée "
            f"({match.group('signature')[:16]}… ≠ {reference['signature'][:16]}…)"
        )
    return None


# --------------------------------------------------------------------------------------
# Faux serveur HTTP local
# --------------------------------------------------------------------------------------


class RecordedRequest:
    """Requête reçue par le faux serveur, conservée pour les assertions."""

    def __init__(self, method: str, target: str, headers: dict[str, str], body: bytes) -> None:
        self.method = method
        self.path = target
        self.headers = headers
        self.body = body

    @property
    def json_body(self) -> dict[str, Any]:
        if not self.body:
            return {}
        try:
            parsed = json.loads(self.body.decode("utf-8"))
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    @property
    def query(self) -> dict[str, str]:
        return dict(parse_qsl(urlsplit(self.path).query, keep_blank_values=True))

    def __repr__(self) -> str:  # pragma: no cover - confort de débogage
        return f"<{self.method} {self.path} body={len(self.body)}o>"


#: Une réponse scriptée : ``(statut, corps)``, le corps étant un dict JSON ou des octets bruts.
Responder = Callable[[RecordedRequest], Any]


def _unused_local_port() -> int:
    """Port local fermé : garantit un « service injoignable » immédiat et déterministe."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class FakeApiServer:
    """Serveur HTTP local qui enregistre les requêtes et rend des réponses scriptées."""

    def __init__(self, responder: Responder) -> None:
        self.responder = responder
        self.requests: list[RecordedRequest] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                recorded = RecordedRequest(
                    self.command,
                    self.path,
                    {key.lower(): value for key, value in self.headers.items()},
                    raw,
                )
                with outer._lock:
                    outer.requests.append(recorded)
                status, payload, extra = outer._respond(recorded)
                body = (
                    payload
                    if isinstance(payload, bytes)
                    else json.dumps(payload, ensure_ascii=False).encode("utf-8")
                )
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for key, value in (extra or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            # Noms imposés par `http.server.BaseHTTPRequestHandler`, qui répartit les méthodes
            # HTTP par attribut `do_<VERBE>` : les renommer casserait le faux serveur de test.
            do_GET = _handle  # noqa: N815
            do_POST = _handle  # noqa: N815
            do_PUT = _handle  # noqa: N815
            do_PATCH = _handle  # noqa: N815
            do_DELETE = _handle  # noqa: N815

            def log_message(self, *args: object) -> None:  # silence le serveur de test
                return

        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _respond(self, request: RecordedRequest) -> tuple[int, Any, dict[str, str] | None]:
        response = self.responder(request)
        if isinstance(response, tuple) and len(response) == 2 and isinstance(response[0], int):
            return response[0], response[1], None
        if isinstance(response, tuple) and len(response) == 3:
            return response[0], response[1], response[2]
        return 200, response, None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    @property
    def calls(self) -> int:
        with self._lock:
            return len(self.requests)

    def path_of(self, index: int) -> str:
        return urlsplit(self.requests[index].path).path

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


class NativeConnectorTestCase(unittest.TestCase):
    """Socle : ouvre un faux serveur par test et le ferme proprement."""

    def fake_server(self, responder: Responder) -> FakeApiServer:
        server = FakeApiServer(responder)
        self.addCleanup(server.close)
        return server

    # Nom aligné sur l'API d'assertion de `unittest` (`assertEqual`, `assertIn`…) : conservé
    # tel quel, il est appelé par de nombreux tests.
    def assertNoSecret(self, secret: str, payload: Any, message: str = "") -> None:  # noqa: N802
        """Aucune trace d'un secret dans un résultat, sérialisé en JSON."""
        rendered = json.dumps(payload, ensure_ascii=False, default=str)
        self.assertNotIn(secret, rendered, message or "un secret a fuité dans le résultat")


# --------------------------------------------------------------------------------------
# 1. Signature AWS SigV4
# --------------------------------------------------------------------------------------


class SigV4OfficialVectorsTest(unittest.TestCase):
    """Vecteurs officiels AWS : la référence absolue, rejouée à l'identique."""

    def _check_vector(self, vector: dict[str, Any], expected_prefix: str) -> None:
        canonical = build_canonical_request(
            method=vector["method"],
            canonical_uri_value=vector["uri"],
            canonical_query=vector["query"],
            headers=vector["headers"],
            signed_headers=sorted(vector["headers"]),
            payload_hash=sha256_hex(vector["payload"]),
        )
        self.assertEqual(
            vector["canonical_request_hash"],
            sha256_hex(canonical.encode("utf-8")),
            "la requête canonique ne correspond pas au vecteur publié par AWS",
        )

        scope = f"{AWS_AMZ_DATE[:8]}/{vector['region']}/{vector['service']}/aws4_request"
        string_to_sign = build_string_to_sign(AWS_AMZ_DATE, scope, canonical)
        self.assertTrue(string_to_sign.startswith(f"{ALGORITHM}\n{AWS_AMZ_DATE}\n{scope}\n"))

        signing_key = derive_signing_key(
            AWS_SECRET_KEY, AWS_AMZ_DATE[:8], vector["region"], vector["service"]
        )
        self.assertEqual(vector["signing_key"], signing_key.hex())
        self.assertEqual(vector["signature"], compute_signature(signing_key, string_to_sign))
        self.assertTrue(vector["authorization"].startswith(expected_prefix))

    def test_official_vector_get_vanilla(self) -> None:
        self._check_vector(
            VECTOR_GET_VANILLA, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service"
        )

    def test_official_vector_iam_list_users(self) -> None:
        """Le vecteur qui porte la signature ``5d672d79…`` de la documentation AWS."""
        self._check_vector(
            VECTOR_IAM_LIST_USERS, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam"
        )

    def test_high_level_signer_reproduces_the_official_iam_authorization(self) -> None:
        """``sign_request`` doit produire exactement l'en-tête ``Authorization`` publié.

        On désactive ``x-amz-content-sha256`` : l'exemple AWS IAM n'en comporte pas, et signer
        un en-tête que l'exemple ne liste pas changerait la signature.
        """
        headers = sign_request(
            method=VECTOR_IAM_LIST_USERS["method"],
            url=f"https://{VECTOR_IAM_LIST_USERS['host']}/?{VECTOR_IAM_LIST_USERS['query']}",
            region=VECTOR_IAM_LIST_USERS["region"],
            service=VECTOR_IAM_LIST_USERS["service"],
            access_key_id=AWS_ACCESS_KEY,
            secret_access_key=AWS_SECRET_KEY,
            payload=VECTOR_IAM_LIST_USERS["payload"],
            extra_headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
            amz_date=AWS_AMZ_DATE,
            sign_content_sha256=False,
        )
        self.assertEqual(VECTOR_IAM_LIST_USERS["authorization"], headers["Authorization"])
        self.assertEqual(AWS_AMZ_DATE, headers["X-Amz-Date"])


class SigV4AgainstIndependentImplementationTest(unittest.TestCase):
    """Vérification croisée : deux implémentations indépendantes doivent signer pareil."""

    def _compare(self, **kwargs: Any) -> dict[str, str]:
        body = kwargs.pop("body", b"")
        url = kwargs.pop("url")
        amz_date = kwargs.pop("amz_date")
        parts = urlsplit(url)
        headers = sign_request(
            url=url,
            payload=body,
            amz_date=amz_date,
            access_key_id=AWS_ACCESS_KEY,
            secret_access_key=AWS_SECRET_KEY,
            **kwargs,
        )
        reference = reference_sigv4(
            method=kwargs["method"],
            host=parts.netloc,
            path=parts.path or "/",
            query=parts.query,
            region=kwargs["region"],
            service=kwargs["service"],
            access_key_id=AWS_ACCESS_KEY,
            secret_access_key=AWS_SECRET_KEY,
            body=body,
            amz_date=amz_date,
            extra_signed_headers=kwargs.get("extra_headers"),
            session_token=kwargs.get("session_token"),
        )
        self.assertEqual(reference["authorization"], headers["Authorization"])
        return headers

    def test_post_with_body_and_target_header(self) -> None:
        """Cas réel du connecteur : POST WAFv2 avec corps JSON et ``X-Amz-Target``."""
        body = json.dumps(
            {
                "Id": "a1b2c3d4-0000-0000-0000-000000000000",
                "Name": "thotsecure-blocklist",
                "Scope": "REGIONAL",
            },
            separators=(",", ":"),
        ).encode("utf-8")
        headers = self._compare(
            method="POST",
            url="https://wafv2.eu-west-3.amazonaws.com/",
            region="eu-west-3",
            service="wafv2",
            body=body,
            extra_headers={"Content-Type": CONTENT_TYPE, "X-Amz-Target": TARGET_GET_IPSET},
            amz_date="20260214T101500Z",
        )
        self.assertIn("x-amz-target", headers["Authorization"].split("SignedHeaders=")[1])
        self.assertEqual(sha256_hex(body), headers["X-Amz-Content-Sha256"])

    def test_body_is_actually_signed(self) -> None:
        """Un corps différent doit donner une signature différente, sinon le corps n'est pas signé."""
        first = self._compare(
            method="POST",
            url="https://wafv2.us-east-1.amazonaws.com/",
            region="us-east-1",
            service="wafv2",
            body=b'{"Addresses":["203.0.113.9/32"]}',
            extra_headers={"Content-Type": CONTENT_TYPE, "X-Amz-Target": TARGET_UPDATE_IPSET},
            amz_date=AWS_AMZ_DATE,
        )
        second = self._compare(
            method="POST",
            url="https://wafv2.us-east-1.amazonaws.com/",
            region="us-east-1",
            service="wafv2",
            body=b'{"Addresses":["203.0.113.10/32"]}',
            extra_headers={"Content-Type": CONTENT_TYPE, "X-Amz-Target": TARGET_UPDATE_IPSET},
            amz_date=AWS_AMZ_DATE,
        )
        self.assertNotEqual(first["Authorization"], second["Authorization"])

    def test_session_token_is_signed_but_secret_never_appears(self) -> None:
        headers = self._compare(
            method="POST",
            url="https://wafv2.us-east-1.amazonaws.com/",
            region="us-east-1",
            service="wafv2",
            body=b"{}",
            extra_headers={"Content-Type": CONTENT_TYPE, "X-Amz-Target": TARGET_GET_IPSET},
            session_token="FQoGZXIvYXdzEBYaDExampleSessionToken",
            amz_date=AWS_AMZ_DATE,
        )
        self.assertIn("x-amz-security-token", headers["Authorization"].split("SignedHeaders=")[1])
        self.assertEqual("FQoGZXIvYXdzEBYaDExampleSessionToken", headers["X-Amz-Security-Token"])
        self.assertNotIn(AWS_SECRET_KEY, json.dumps(headers))


# --------------------------------------------------------------------------------------
# 2. Cloudflare
# --------------------------------------------------------------------------------------

CLOUDFLARE_TOKEN = "jeton-cloudflare-de-test-000000000000"
CLOUDFLARE_RULE_ID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
CLOUDFLARE_RULESET_ID = "11112222333344445555666677778888"
CLOUDFLARE_RULE_LIMIT_ID = "99998888777766665555444433332222"


def cloudflare_created(request: RecordedRequest) -> Any:
    return {
        "success": True,
        "errors": [],
        "messages": [],
        "result": {
            "id": CLOUDFLARE_RULE_ID,
            "mode": request.json_body.get("mode"),
            "notes": request.json_body.get("notes"),
            "configuration": request.json_body.get("configuration"),
        },
    }


class CloudflareBlockTest(NativeConnectorTestCase):
    """Blocage et déblocage via les IP Access Rules."""

    def connector(self, server: FakeApiServer, **overrides: Any) -> CloudflareConnector:
        settings = {
            "api_base": f"{server.url}/client/v4",
            "api_token": CLOUDFLARE_TOKEN,
            "account_id": "acct-42",
            "zone_id": "zone-7",
            **overrides,
        }
        return CloudflareConnector(settings, dry_run=False)

    def test_block_ip_posts_an_ip_access_rule(self) -> None:
        server = self.fake_server(cloudflare_created)
        connector = self.connector(server)

        result = connector.call(
            "block_ip",
            {
                "ip": "203.0.113.9",
                "ttl": 3600,
                "note": "attaque web confirmée",
                "action_id": "act-777",
            },
        )

        self.assertTrue(result.ok, result.error)
        self.assertEqual(1, server.calls)
        request = server.requests[0]
        self.assertEqual("POST", request.method)
        self.assertEqual("/client/v4/accounts/acct-42/firewall/access_rules/rules", request.path)
        self.assertEqual(f"Bearer {CLOUDFLARE_TOKEN}", request.headers["authorization"])
        self.assertTrue(request.headers["user-agent"].startswith("ThotSecure/"))
        self.assertEqual("block", request.json_body["mode"])
        self.assertEqual(
            {"target": "ip", "value": "203.0.113.9"}, request.json_body["configuration"]
        )
        self.assertIn("act-777", request.json_body["notes"])
        self.assertIn("3600s", request.json_body["notes"])

        self.assertEqual(CLOUDFLARE_RULE_ID, result.rollback_token)
        self.assertEqual(CLOUDFLARE_RULE_ID, result.data["rule_id"])
        self.assertIn("unblock_ip", str(result.data["rollback_operation"]))
        self.assertNoSecret(CLOUDFLARE_TOKEN, result.to_dict())

    def test_block_ip_normalizes_address_and_rejects_nonsense(self) -> None:
        server = self.fake_server(cloudflare_created)
        connector = self.connector(server)

        network = connector.call("block_ip", {"ip": "198.51.100.7/24"})
        self.assertTrue(network.ok, network.error)
        self.assertEqual("198.51.100.0/24", server.requests[0].json_body["configuration"]["value"])

        invalid = connector.call("block_ip", {"ip": "pas-une-ip"})
        self.assertFalse(invalid.ok)
        self.assertIn("invalide", invalid.error)
        self.assertEqual(1, server.calls, "une cible invalide ne doit produire aucun appel")

    def test_unblock_ip_deletes_by_rule_id_without_listing(self) -> None:
        """La suppression par identifiant est la seule annulation non ambiguë."""
        server = self.fake_server(
            lambda request: {"success": True, "errors": [], "result": {"id": CLOUDFLARE_RULE_ID}}
        )
        connector = self.connector(server)

        result = connector.call(
            "unblock_ip", {"rollback_token": CLOUDFLARE_RULE_ID, "ip": "203.0.113.9"}
        )

        self.assertTrue(result.ok, result.error)
        self.assertEqual(1, server.calls, "aucune recherche par valeur ne doit être émise")
        self.assertEqual("DELETE", server.requests[0].method)
        self.assertEqual(
            f"/client/v4/accounts/acct-42/firewall/access_rules/rules/{CLOUDFLARE_RULE_ID}",
            server.requests[0].path,
        )
        self.assertEqual("rule_id", result.data["match"])

    def test_unblock_ip_falls_back_to_value_lookup(self) -> None:
        """Sans jeton (perdu), le repli existe — et il est signalé comme moins fiable."""

        def responder(request: RecordedRequest) -> Any:
            if request.method == "GET":
                return {
                    "success": True,
                    "errors": [],
                    "result": [
                        {
                            "id": CLOUDFLARE_RULE_ID,
                            "mode": "block",
                            "configuration": {"target": "ip", "value": "203.0.113.9"},
                        }
                    ],
                }
            return {"success": True, "errors": [], "result": {"id": CLOUDFLARE_RULE_ID}}

        server = self.fake_server(responder)
        connector = self.connector(server)

        result = connector.call("unblock_ip", {"ip": "203.0.113.9"})

        self.assertTrue(result.ok, result.error)
        self.assertEqual(2, server.calls)
        self.assertEqual("GET", server.requests[0].method)
        self.assertEqual("203.0.113.9", server.requests[0].query["configuration.value"])
        self.assertEqual("ip", server.requests[0].query["configuration.target"])
        self.assertEqual("DELETE", server.requests[1].method)
        self.assertEqual("configuration.value", result.data["match"])
        self.assertIn("avertissement", result.data)

    def test_unblock_ip_reports_a_missing_rule(self) -> None:
        server = self.fake_server(
            lambda request: (
                404,
                {
                    "success": False,
                    "errors": [{"code": 1002, "message": "rule not found"}],
                    "result": None,
                },
            )
        )
        connector = self.connector(server)

        result = connector.call("unblock_ip", {"rollback_token": CLOUDFLARE_RULE_ID})

        self.assertFalse(result.ok)
        self.assertIn("introuvable", result.error)
        self.assertIn(CLOUDFLARE_RULE_ID, result.error)
        self.assertNoSecret(CLOUDFLARE_TOKEN, result.to_dict())

    def test_cloudflare_error_codes_are_extracted(self) -> None:
        """Un 403 doit dire *quoi* : ``errors[].code`` et ``errors[].message``."""
        server = self.fake_server(
            lambda request: (
                403,
                {
                    "success": False,
                    "errors": [
                        {"code": 10000, "message": "Authentication error"},
                        {"code": 9109, "message": "Unauthorized to access requested resource"},
                    ],
                },
            )
        )
        connector = self.connector(server)

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("code 10000", result.error)
        self.assertIn("Authentication error", result.error)
        self.assertIn("code 9109", result.error)
        self.assertNoSecret(CLOUDFLARE_TOKEN, result.to_dict())

    def test_error_codes_helper_is_used_for_all_shapes(self) -> None:
        self.assertEqual(
            "code 1: un; code 2: deux",
            CloudflareConnector.format_errors(
                [{"code": 1, "message": "un"}, {"code": 2, "message": "deux"}]
            ),
        )
        self.assertEqual("brut", CloudflareConnector.format_errors(["brut"]))
        self.assertEqual("", CloudflareConnector.format_errors(None))

    def test_unreachable_api_never_raises(self) -> None:
        connector = CloudflareConnector(
            {
                "api_base": f"http://127.0.0.1:{_unused_local_port()}/client/v4",
                "api_token": CLOUDFLARE_TOKEN,
                "account_id": "acct-42",
                "timeout_seconds": 2,
            },
            dry_run=False,
        )

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("injoignable", result.error)
        self.assertNoSecret(CLOUDFLARE_TOKEN, result.to_dict())

    def test_missing_token_is_reported_as_not_configured(self) -> None:
        connector = CloudflareConnector({"account_id": "acct-42"}, dry_run=False)

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("non configuré", result.error)
        self.assertIn("api_token", result.error)

    def test_plain_http_to_a_remote_host_is_refused(self) -> None:
        connector = CloudflareConnector(
            {
                "api_base": "http://api.cloudflare.com/client/v4",
                "api_token": CLOUDFLARE_TOKEN,
                "account_id": "acct-42",
            },
            dry_run=False,
        )

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("refusé", result.error)

    def test_foreign_rollback_token_falls_back_to_the_value_lookup(self) -> None:
        """Le moteur injecte le jeton de la dernière étape appliquée, pas forcément le nôtre.

        Sans ce garde-fou, ``unblock_ip`` enverrait ``DELETE …/rules/simulation%3Aopen_ticket`` :
        une requête absurde, et un blocage jamais levé. On préfère annuler réellement par la
        valeur connue.
        """

        def responder(request: RecordedRequest) -> Any:
            if request.method == "GET":
                return {
                    "success": True,
                    "errors": [],
                    "result": [
                        {
                            "id": CLOUDFLARE_RULE_ID,
                            "configuration": {"target": "ip", "value": "203.0.113.9"},
                        }
                    ],
                }
            return {"success": True, "errors": [], "result": {"id": CLOUDFLARE_RULE_ID}}

        server = self.fake_server(responder)
        connector = self.connector(server)

        result = connector.call(
            "unblock_ip", {"rollback_token": "simulation:open_ticket", "ip": "203.0.113.9"}
        )

        self.assertTrue(result.ok, result.error)
        self.assertEqual(2, server.calls)
        self.assertEqual("GET", server.requests[0].method)
        self.assertEqual("DELETE", server.requests[1].method)
        self.assertIn(CLOUDFLARE_RULE_ID, server.path_of(1))
        self.assertNotIn("simulation", "".join(server.path_of(i) for i in range(server.calls)))
        self.assertEqual("configuration.value", result.data["match"])

    def test_foreign_rollback_token_without_target_is_refused(self) -> None:
        server = self.fake_server(cloudflare_created)
        connector = self.connector(server)

        result = connector.call("unblock_ip", {"rollback_token": "simulation:open_ticket"})

        self.assertFalse(result.ok)
        self.assertIn("target", result.error)
        self.assertEqual(0, server.calls, "aucune requête absurde ne doit être émise")


class CloudflareRateLimitTest(NativeConnectorTestCase):
    """Limitation de débit : ruleset de phase ``http_ratelimit``."""

    def connector(self, server: FakeApiServer, **overrides: Any) -> CloudflareConnector:
        return CloudflareConnector(
            {
                "api_base": f"{server.url}/client/v4",
                "api_token": CLOUDFLARE_TOKEN,
                "account_id": "acct-42",
                "zone_id": "zone-7",
                **overrides,
            },
            dry_run=False,
        )

    def _entrypoint_responder(self) -> Responder:
        def responder(request: RecordedRequest) -> Any:
            if request.method == "GET":
                return (
                    404,
                    {
                        "success": False,
                        "errors": [{"code": 10000, "message": "no ruleset found"}],
                        "result": None,
                    },
                )
            if request.method == "PUT":
                rules = request.json_body.get("rules") or []
                created = [
                    {**rule, "id": CLOUDFLARE_RULE_LIMIT_ID, "version": "1"} for rule in rules
                ]
                return {
                    "success": True,
                    "errors": [],
                    "result": {
                        "id": CLOUDFLARE_RULESET_ID,
                        "phase": "http_ratelimit",
                        "rules": created,
                    },
                }
            return {"success": True, "errors": [], "result": {"id": CLOUDFLARE_RULE_LIMIT_ID}}

        return responder

    def test_rate_limit_creates_the_entrypoint_and_returns_a_token(self) -> None:
        server = self.fake_server(self._entrypoint_responder())
        connector = self.connector(server)

        result = connector.call(
            "rate_limit",
            {"ip": "203.0.113.9", "rate": "30r/m", "ttl": 1800, "action_id": "act-9"},
        )

        self.assertTrue(result.ok, result.error)
        self.assertEqual(2, server.calls, "GET (ruleset absent) puis PUT")
        self.assertEqual(
            "/client/v4/zones/zone-7/rulesets/phases/http_ratelimit/entrypoint",
            server.path_of(0),
        )
        self.assertEqual("PUT", server.requests[1].method)
        rule = server.requests[1].json_body["rules"][0]
        self.assertEqual("(ip.src eq 203.0.113.9)", rule["expression"])
        self.assertEqual("block", rule["action"])
        self.assertTrue(rule["enabled"])
        self.assertIn("act-9", rule["description"])
        self.assertEqual(
            {
                "characteristics": ["ip.src"],
                "period": 60,
                "requests_per_period": 30,
                "mitigation_timeout": 1800,
            },
            rule["ratelimit"],
        )
        self.assertEqual(
            f"{CLOUDFLARE_RULESET_ID}/{CLOUDFLARE_RULE_LIMIT_ID}", result.rollback_token
        )

    def test_rate_units_are_converted_faithfully(self) -> None:
        cases = [
            ("10r/s", 10, 100),
            ("30r/m", 60, 30),
            ("600r/h", 3600, 600),
            ("2/10s", 10, 2),
        ]
        for rate, expected_period, expected_requests in cases:
            with self.subTest(rate=rate):
                server = self.fake_server(self._entrypoint_responder())
                connector = self.connector(server)
                result = connector.call("rate_limit", {"ip": "203.0.113.9", "rate": rate})
                self.assertTrue(result.ok, result.error)
                payload = server.requests[1].json_body["rules"][0]["ratelimit"]
                self.assertEqual(expected_period, payload["period"])
                self.assertEqual(expected_requests, payload["requests_per_period"])

    def test_rate_limit_rejects_an_unparsable_rate_without_calling_the_api(self) -> None:
        server = self.fake_server(self._entrypoint_responder())
        connector = self.connector(server)

        result = connector.call("rate_limit", {"ip": "203.0.113.9", "rate": "beaucoup"})

        self.assertFalse(result.ok)
        self.assertIn("incompris", result.error)
        self.assertEqual(0, server.calls)

    def test_rate_limit_rejects_a_duration_out_of_cloudflare_bounds(self) -> None:
        server = self.fake_server(self._entrypoint_responder())
        connector = self.connector(server)

        result = connector.call("rate_limit", {"ip": "203.0.113.9", "ttl": 5})

        self.assertFalse(result.ok)
        self.assertIn("hors bornes", result.error)
        self.assertEqual(0, server.calls)

    def test_rate_limit_replaces_a_rule_for_the_same_source(self) -> None:
        """Deux limitations concurrentes sur la même source : on remplace, on n'empile pas."""

        def responder(request: RecordedRequest) -> Any:
            if request.method == "GET":
                return {
                    "success": True,
                    "errors": [],
                    "result": {
                        "id": CLOUDFLARE_RULESET_ID,
                        "rules": [
                            {
                                "id": "aaaa1111bbbb2222cccc3333dddd4444",
                                "expression": "(ip.src eq 203.0.113.9)",
                                "action": "block",
                            },
                            {
                                "id": "bbbb2222cccc3333dddd4444eeee5555",
                                "expression": "(ip.src eq 198.51.100.4)",
                                "action": "block",
                            },
                        ],
                    },
                }
            rules = request.json_body["rules"]
            return {
                "success": True,
                "errors": [],
                "result": {
                    "id": CLOUDFLARE_RULESET_ID,
                    "rules": [
                        {**rule, "id": rule.get("id") or CLOUDFLARE_RULE_LIMIT_ID} for rule in rules
                    ],
                },
            }

        server = self.fake_server(responder)
        connector = self.connector(server)

        result = connector.call(
            "rate_limit", {"ip": "203.0.113.9", "rate": "10r/m", "action_id": "act-2"}
        )

        self.assertTrue(result.ok, result.error)
        written = server.requests[1].json_body["rules"]
        self.assertEqual(2, len(written), "l'ancienne règle de la même source doit être remplacée")
        self.assertEqual("(ip.src eq 198.51.100.4)", written[0]["expression"])
        self.assertIn("act-2", written[1]["description"])

    def test_remove_rate_limit_deletes_by_identifier(self) -> None:
        server = self.fake_server(
            lambda request: {"success": True, "errors": [], "result": {"id": "ok"}}
        )
        connector = self.connector(server)

        result = connector.call(
            "remove_rate_limit",
            {"rollback_token": f"{CLOUDFLARE_RULESET_ID}/{CLOUDFLARE_RULE_LIMIT_ID}"},
        )

        self.assertTrue(result.ok, result.error)
        self.assertEqual(1, server.calls)
        self.assertEqual("DELETE", server.requests[0].method)
        self.assertEqual(
            f"/client/v4/zones/zone-7/rulesets/{CLOUDFLARE_RULESET_ID}"
            f"/rules/{CLOUDFLARE_RULE_LIMIT_ID}",
            server.requests[0].path,
        )
        self.assertEqual("rule_id", result.data["match"])

    def test_remove_rate_limit_falls_back_to_expression_match(self) -> None:
        def responder(request: RecordedRequest) -> Any:
            if request.method == "GET":
                return {
                    "success": True,
                    "errors": [],
                    "result": {
                        "id": CLOUDFLARE_RULESET_ID,
                        "rules": [
                            {"id": "aaaa", "expression": "(ip.src eq 203.0.113.9)"},
                            {"id": "bbbb", "expression": "(ip.src eq 198.51.100.4)"},
                        ],
                    },
                }
            return {"success": True, "errors": [], "result": {"id": CLOUDFLARE_RULESET_ID}}

        server = self.fake_server(responder)
        connector = self.connector(server)

        result = connector.call("remove_rate_limit", {"ip": "203.0.113.9"})

        self.assertTrue(result.ok, result.error)
        self.assertEqual(1, result.data["removed"])
        kept = server.requests[1].json_body["rules"]
        self.assertEqual(["bbbb"], [rule["id"] for rule in kept])

    def test_remove_rate_limit_without_match_is_an_honest_failure(self) -> None:
        server = self.fake_server(
            lambda request: {
                "success": True,
                "errors": [],
                "result": {"id": CLOUDFLARE_RULESET_ID, "rules": []},
            }
        )
        connector = self.connector(server)

        result = connector.call("remove_rate_limit", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("aucune limitation", result.error)

    def test_remove_rate_limit_ignores_a_foreign_token(self) -> None:
        server = self.fake_server(self._entrypoint_responder())
        connector = self.connector(server)

        result = connector.call("remove_rate_limit", {"rollback_token": "simulation:rate_limit"})

        self.assertFalse(result.ok)
        self.assertEqual(0, server.calls, "un jeton d'une autre forme ne doit rien déclencher")


# --------------------------------------------------------------------------------------
# 3. AWS WAF
# --------------------------------------------------------------------------------------

AWS_SETTINGS = {
    "ip_set_id": "a1b2c3d4-1111-2222-3333-444455556666",
    "ip_set_name": "thotsecure-blocklist",
    "scope": "REGIONAL",
    "region": "eu-west-3",
    "access_key_id": AWS_ACCESS_KEY,
    "secret_access_key": AWS_SECRET_KEY,
}
AWS_ADDRESS = "203.0.113.9/32"
AWS_EXISTING = "198.51.100.7/32"


def aws_ipset_body(addresses: list[str]) -> dict[str, Any]:
    return {
        "IPSet": {
            "Id": AWS_SETTINGS["ip_set_id"],
            "Name": AWS_SETTINGS["ip_set_name"],
            "ARN": "arn:aws:wafv2:eu-west-3:111122223333:regional/ipset/thotsecure-blocklist/abc",
            "Addresses": addresses,
            "IPAddressVersion": "IPV4",
        },
        "LockToken": "lock-token-1",
    }


class AwsWafTest(NativeConnectorTestCase):
    """Mise à jour d'IPSet WAFv2 : signature, ``LockToken``, erreurs."""

    def connector(self, server: FakeApiServer, **overrides: Any) -> AwsWafConnector:
        return AwsWafConnector(
            {**AWS_SETTINGS, "endpoint_url": f"{server.url}/", **overrides}, dry_run=False
        )

    def test_block_ip_reads_then_updates_the_ipset(self) -> None:
        def responder(request: RecordedRequest) -> Any:
            if request.headers.get("x-amz-target") == TARGET_GET_IPSET:
                return aws_ipset_body([AWS_EXISTING])
            return {"NextLockToken": "lock-token-2"}

        server = self.fake_server(responder)
        connector = self.connector(server)

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertTrue(result.ok, result.error)
        self.assertEqual(2, server.calls)
        self.assertEqual("POST", server.requests[0].method)
        self.assertEqual(CONTENT_TYPE, server.requests[0].headers["content-type"])
        self.assertEqual(
            {
                "Id": AWS_SETTINGS["ip_set_id"],
                "Name": AWS_SETTINGS["ip_set_name"],
                "Scope": "REGIONAL",
            },
            server.requests[0].json_body,
        )
        self.assertEqual(TARGET_UPDATE_IPSET, server.requests[1].headers["x-amz-target"])
        update = server.requests[1].json_body
        self.assertEqual(sorted([AWS_EXISTING, AWS_ADDRESS]), update["Addresses"])
        self.assertEqual("lock-token-1", update["LockToken"])

        # La signature reçue doit correspondre au recalcul indépendant, pour les deux appels.
        for request in server.requests:
            self.assertIsNone(
                verify_received_signature(
                    request, secret_access_key=AWS_SECRET_KEY, expected_region="eu-west-3"
                )
            )

        self.assertEqual(
            f"wafv2:REGIONAL:{AWS_SETTINGS['ip_set_id']}:{AWS_ADDRESS}", result.rollback_token
        )
        self.assertEqual(2, result.data["addresses_count"])
        self.assertNoSecret(AWS_SECRET_KEY, result.to_dict())

    def test_block_ip_is_idempotent_for_an_address_already_present(self) -> None:
        server = self.fake_server(lambda request: aws_ipset_body([AWS_ADDRESS]))
        connector = self.connector(server)

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertTrue(result.ok, result.error)
        self.assertEqual(1, server.calls, "aucune écriture inutile ne doit être envoyée")
        self.assertTrue(result.data["already_present"])
        self.assertEqual(
            f"wafv2:REGIONAL:{AWS_SETTINGS['ip_set_id']}:{AWS_ADDRESS}", result.rollback_token
        )

    def test_optimistic_lock_is_retried_once_with_a_fresh_token(self) -> None:
        """``WAFOptimisticLockException`` : relire, puis retenter **une** fois."""
        state = {"gets": 0, "updates": 0}
        seen_locks: list[str] = []

        def responder(request: RecordedRequest) -> Any:
            if request.headers.get("x-amz-target") == TARGET_GET_IPSET:
                state["gets"] += 1
                body = aws_ipset_body([AWS_EXISTING])
                body["LockToken"] = f"lock-token-{state['gets']}"
                return body
            state["updates"] += 1
            seen_locks.append(str(request.json_body.get("LockToken")))
            if state["updates"] == 1:
                return (
                    400,
                    {
                        "__type": "WAFOptimisticLockException",
                        "message": "AWS WAF couldn't perform the operation because your resource "
                        "was modified by another process.",
                    },
                )
            return {"NextLockToken": "lock-token-3"}

        server = self.fake_server(responder)
        connector = self.connector(server)

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertTrue(result.ok, result.error)
        self.assertEqual(4, server.calls, "GET, PUT, GET (relecture), PUT (nouvelle tentative)")
        self.assertEqual(["lock-token-1", "lock-token-2"], seen_locks)

    def test_optimistic_lock_twice_is_reported_not_looped(self) -> None:
        def responder(request: RecordedRequest) -> Any:
            if request.headers.get("x-amz-target") == TARGET_GET_IPSET:
                return aws_ipset_body([AWS_EXISTING])
            return (400, {"__type": "WAFOptimisticLockException", "message": "modified"})

        server = self.fake_server(responder)
        connector = self.connector(server)

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("concurremment", result.error)
        self.assertEqual(4, server.calls, "une seule nouvelle tentative, jamais une boucle")

    def test_missing_lock_token_prevents_any_write(self) -> None:
        server = self.fake_server(
            lambda request: {"IPSet": aws_ipset_body([AWS_EXISTING])["IPSet"]}
        )
        connector = self.connector(server)

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("LockToken", result.error)
        self.assertEqual(1, server.calls, "aucune écriture sans LockToken")

    def test_unblock_ip_removes_the_address_from_the_rollback_token(self) -> None:
        server = self.fake_server(
            lambda request: (
                aws_ipset_body([AWS_ADDRESS])
                if request.headers.get("x-amz-target") == TARGET_GET_IPSET
                else {"NextLockToken": "lock-token-4"}
            )
        )
        connector = self.connector(server)

        result = connector.call(
            "unblock_ip",
            {"rollback_token": f"wafv2:REGIONAL:{AWS_SETTINGS['ip_set_id']}:{AWS_ADDRESS}"},
        )

        self.assertTrue(result.ok, result.error)
        self.assertEqual([], server.requests[1].json_body["Addresses"])

    def test_unblock_ip_on_an_absent_address_fails_clearly(self) -> None:
        server = self.fake_server(lambda request: aws_ipset_body([AWS_EXISTING]))
        connector = self.connector(server)

        result = connector.call("unblock_ip", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("absente", result.error)
        self.assertEqual(1, server.calls)

    def test_aws_error_type_and_message_are_surfaced(self) -> None:
        server = self.fake_server(
            lambda request: (
                400,
                {
                    "__type": "com.amazonaws.wafv2#WAFNonexistentItemException",
                    "message": "AWS WAF couldn't perform the operation because your resource "
                    "doesn't exist.",
                },
            )
        )
        connector = self.connector(server)

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("WAFNonexistentItemException", result.error)
        self.assertIn("doesn't exist", result.error)
        self.assertIn("GetIPSet", result.error)
        self.assertNoSecret(AWS_SECRET_KEY, result.to_dict())

    def test_cloudfront_scope_forces_the_us_east_1_region(self) -> None:
        server = self.fake_server(lambda request: aws_ipset_body([AWS_EXISTING]))
        connector = self.connector(server, scope="CLOUDFRONT", region="eu-west-3")

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertTrue(result.ok, result.error)
        authorization = server.requests[0].headers["authorization"]
        self.assertIn("/us-east-1/wafv2/aws4_request", authorization)
        self.assertIsNone(
            verify_received_signature(
                server.requests[0],
                secret_access_key=AWS_SECRET_KEY,
                expected_region="us-east-1",
            )
        )

    def test_unreachable_endpoint_never_raises(self) -> None:
        connector = AwsWafConnector(
            {**AWS_SETTINGS, "endpoint_url": f"http://127.0.0.1:{_unused_local_port()}/"},
            dry_run=False,
        )

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("injoignable", result.error)

    def test_missing_configuration_is_reported_without_network_call(self) -> None:
        server = self.fake_server(lambda request: aws_ipset_body([AWS_EXISTING]))
        connector = AwsWafConnector(
            {"access_key_id": AWS_ACCESS_KEY, "secret_access_key": AWS_SECRET_KEY}, dry_run=False
        )

        result = connector.call("block_ip", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("non configuré", result.error)
        self.assertIn("ip_set_id", result.error)
        self.assertEqual(0, server.calls)

    def test_unsupported_operation_is_refused(self) -> None:
        """Un connecteur natif ne prétend pas savoir tout faire."""
        connector = AwsWafConnector(AWS_SETTINGS, dry_run=False)

        result = connector.call("rate_limit", {"ip": "203.0.113.9"})

        self.assertFalse(result.ok)
        self.assertIn("non supportée", result.error)


# --------------------------------------------------------------------------------------
# 4. Slack
# --------------------------------------------------------------------------------------

SLACK_WEBHOOK_SECRET = "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
SLACK_WEBHOOK_PATH = f"/services/{SLACK_WEBHOOK_SECRET}"


class SlackTest(NativeConnectorTestCase):
    """Notification Slack : message structuré, correction, erreurs."""

    def connector(self, server: FakeApiServer, **overrides: Any) -> SlackConnector:
        return SlackConnector(
            {"webhook_url": f"{server.url}{SLACK_WEBHOOK_PATH}", **overrides}, dry_run=False
        )

    def test_notify_sends_a_structured_message(self) -> None:
        server = self.fake_server(lambda request: (200, b"ok"))
        connector = self.connector(server)

        result = connector.call(
            "notify",
            {
                "message": "Blocage de 203.0.113.9",
                "severity": "critical",
                "finding_id": "f1c2",
                "action_id": "a91b",
                "target": "203.0.113.9",
                "tenant_id": "acme",
            },
        )

        self.assertTrue(result.ok, result.error)
        self.assertEqual(1, server.calls)
        request = server.requests[0]
        self.assertEqual("POST", request.method)
        self.assertEqual(SLACK_WEBHOOK_PATH, urlsplit(request.path).path)
        payload = request.json_body
        self.assertIn("[CRITICAL]", payload["text"])
        self.assertIn("Blocage de 203.0.113.9", payload["text"])
        rendered = json.dumps(payload, ensure_ascii=False)
        for expected in ("Gravité", "Finding", "Action", "Cible", "f1c2", "a91b", "203.0.113.9"):
            self.assertIn(expected, rendered)
        self.assertTrue(result.rollback_token.startswith("slack:"))
        self.assertNoSecret("B00000000", result.to_dict(), "l'URL du webhook ne doit pas fuiter")
        self.assertNoSecret(SLACK_WEBHOOK_SECRET, result.to_dict())

    def test_notify_rollback_is_a_correction_message(self) -> None:
        """Le rollback d'une notification est un démenti explicite, jamais un silence."""
        server = self.fake_server(lambda request: (200, b"ok"))
        connector = self.connector(server)
        first = connector.call("notify", {"message": "Alerte", "severity": "high"})

        correction = connector.call(
            "notify",
            {
                "message": "Correction : alerte annulée",
                "severity": "info",
                "correction_of": first.rollback_token,
            },
        )

        self.assertTrue(correction.ok, correction.error)
        payload = server.requests[1].json_body
        self.assertIn("CORRECTION", payload["text"])
        self.assertIn(first.rollback_token, json.dumps(payload, ensure_ascii=False))

    def test_slack_404_and_500_are_reported_without_leaking_the_webhook(self) -> None:
        cases = [(404, b"no_service"), (500, b"<html>internal error</html>")]
        for status, body in cases:
            with self.subTest(status=status):
                server = self.fake_server(lambda request, s=status, b=body: (s, b))
                connector = self.connector(server)

                result = connector.call("notify", {"message": "test", "severity": "low"})

                self.assertFalse(result.ok)
                self.assertIn(f"HTTP {status}", result.error)
                self.assertNoSecret(SLACK_WEBHOOK_SECRET, result.to_dict())
                self.assertNotIn("hooks.slack.com", json.dumps(result.to_dict()))

    def test_unreachable_webhook_is_reported(self) -> None:
        connector = SlackConnector(
            {"webhook_url": f"http://127.0.0.1:{_unused_local_port()}/services/x/y/z"},
            dry_run=False,
        )

        result = connector.call("notify", {"message": "test"})

        self.assertFalse(result.ok)
        self.assertIn("injoignable", result.error)

    def test_missing_webhook_is_reported_as_not_configured(self) -> None:
        connector = SlackConnector({}, dry_run=False)

        result = connector.call("notify", {"message": "test"})

        self.assertFalse(result.ok)
        self.assertIn("non configuré", result.error)
        self.assertIn("webhook_url", result.error)

    def test_invalid_webhook_scheme_is_refused(self) -> None:
        connector = SlackConnector({"webhook_url": "ftp://exemple.invalid/hook"}, dry_run=False)

        result = connector.call("notify", {"message": "test"})

        self.assertFalse(result.ok)
        self.assertIn("invalide", result.error)


# --------------------------------------------------------------------------------------
# 5. GitHub Issues
# --------------------------------------------------------------------------------------


#: Jeton GitHub factice : sa valeur sert d'aiguille pour vérifier qu'il ne fuit nulle part.
GH_TOKEN = "ghp_jetonDeTest000000000000000000000000"


class GithubIssueTest(NativeConnectorTestCase):
    """Ticketing GitHub : ouverture, fermeture, erreurs."""

    GITHUB_TOKEN = GH_TOKEN

    def connector(self, server: FakeApiServer, **overrides: Any) -> GithubIssueConnector:
        return GithubIssueConnector(
            {
                "api_url": server.url,
                "token": self.GITHUB_TOKEN,
                "repository": "acme/api",
                "labels": ["securite", "thotsecure"],
                **overrides,
            },
            dry_run=False,
        )

    def test_open_ticket_posts_an_issue(self) -> None:
        server = self.fake_server(
            lambda request: (
                201,
                {
                    "number": 42,
                    "html_url": "https://github.com/acme/api/issues/42",
                    "state": "open",
                },
            )
        )
        connector = self.connector(server)

        result = connector.call(
            "open_ticket",
            {
                "title": "Mise à jour de dépendance : jinja2 → 3.1.5",
                "severity": "high",
                "description": "CVE-2024-22195 dans jinja2.",
                "remediation": "Mettre à jour puis relancer les tests.",
                "finding_id": "f1c2",
                "action_id": "a91b",
                "package": "jinja2",
                "version": "3.1.5",
            },
        )

        self.assertTrue(result.ok, result.error)
        self.assertEqual(1, server.calls)
        request = server.requests[0]
        self.assertEqual("POST", request.method)
        self.assertEqual("/repos/acme/api/issues", urlsplit(request.path).path)
        self.assertEqual(f"Bearer {self.GITHUB_TOKEN}", request.headers["authorization"])
        self.assertEqual("2022-11-28", request.headers["x-github-api-version"])
        body = request.json_body
        self.assertIn("jinja2", body["title"])
        self.assertEqual(["securite", "thotsecure"], body["labels"])
        self.assertIn("**Gravité** : high", body["body"])
        self.assertIn("Mettre à jour puis relancer les tests.", body["body"])

        self.assertEqual("42", result.rollback_token)
        self.assertEqual("42", result.data["ticket_id"])
        self.assertNoSecret(self.GITHUB_TOKEN, result.to_dict())

    def test_close_ticket_comments_then_closes(self) -> None:
        server = self.fake_server(lambda request: (200, {"number": 42, "state": "closed"}))
        connector = self.connector(server)

        result = connector.call(
            "close_ticket",
            {"rollback_token": "42", "comment": "annulé : faux positif confirmé"},
        )

        self.assertTrue(result.ok, result.error)
        self.assertEqual(2, server.calls)
        self.assertEqual(
            "/repos/acme/api/issues/42/comments", urlsplit(server.requests[0].path).path
        )
        self.assertEqual({"body": "annulé : faux positif confirmé"}, server.requests[0].json_body)
        self.assertEqual("PATCH", server.requests[1].method)
        self.assertEqual("/repos/acme/api/issues/42", urlsplit(server.requests[1].path).path)
        self.assertEqual(
            {"state": "closed", "state_reason": "completed"}, server.requests[1].json_body
        )
        self.assertNoSecret(self.GITHUB_TOKEN, result.to_dict())

    def test_close_ticket_without_comment_makes_a_single_call(self) -> None:
        server = self.fake_server(lambda request: (200, {"number": 42, "state": "closed"}))
        connector = self.connector(server)

        result = connector.call("close_ticket", {"ticket_id": "42"})

        self.assertTrue(result.ok, result.error)
        self.assertEqual(1, server.calls)
        self.assertEqual("PATCH", server.requests[0].method)

    def test_404_is_actionable(self) -> None:
        server = self.fake_server(lambda request: (404, {"message": "Not Found"}))
        connector = self.connector(server)

        result = connector.call("open_ticket", {"title": "test"})

        self.assertFalse(result.ok)
        self.assertIn("HTTP 404", result.error)
        self.assertIn("introuvable", result.error)
        self.assertIn("jeton sans accès", result.error)
        self.assertNoSecret(self.GITHUB_TOKEN, result.to_dict())

    def test_500_is_reported(self) -> None:
        server = self.fake_server(lambda request: (500, {"message": "Server Error"}))
        connector = self.connector(server)

        result = connector.call("open_ticket", {"title": "test"})

        self.assertFalse(result.ok)
        self.assertIn("HTTP 500", result.error)
        self.assertNoSecret(self.GITHUB_TOKEN, result.to_dict())

    def test_validation_errors_are_surfaced(self) -> None:
        server = self.fake_server(
            lambda request: (
                422,
                {
                    "message": "Validation Failed",
                    "errors": [{"message": "label 'securite' does not exist"}],
                },
            )
        )
        connector = self.connector(server)

        result = connector.call("open_ticket", {"title": "test"})

        self.assertFalse(result.ok)
        self.assertIn("HTTP 422", result.error)
        self.assertIn("label 'securite' does not exist", result.error)

    def test_missing_repository_is_reported_as_not_configured(self) -> None:
        connector = GithubIssueConnector({"token": self.GITHUB_TOKEN}, dry_run=False)

        result = connector.call("open_ticket", {"title": "test"})

        self.assertFalse(result.ok)
        self.assertIn("non configuré", result.error)
        self.assertIn("repository", result.error)

    def test_invalid_repository_format_is_refused(self) -> None:
        connector = GithubIssueConnector(
            {"token": self.GITHUB_TOKEN, "repository": "pas-un-depot"}, dry_run=False
        )

        result = connector.call("open_ticket", {"title": "test"})

        self.assertFalse(result.ok)
        self.assertIn("invalide", result.error)

    def test_close_ticket_requires_a_numeric_issue(self) -> None:
        connector = GithubIssueConnector(
            {"token": self.GITHUB_TOKEN, "repository": "acme/api"}, dry_run=False
        )

        result = connector.call("close_ticket", {"rollback_token": "JIRA-42"})

        self.assertFalse(result.ok)
        self.assertIn("invalide", result.error)

    def test_unreachable_api_is_reported(self) -> None:
        connector = GithubIssueConnector(
            {
                "api_url": f"http://127.0.0.1:{_unused_local_port()}",
                "token": self.GITHUB_TOKEN,
                "repository": "acme/api",
            },
            dry_run=False,
        )

        result = connector.call("open_ticket", {"title": "test"})

        self.assertFalse(result.ok)
        self.assertIn("injoignable", result.error)


# --------------------------------------------------------------------------------------
# 6. Intégration : le moteur de playbooks pilote un connecteur natif
# --------------------------------------------------------------------------------------

#: Playbook minimal (chargé par le vrai chargeur) : seules les étapes WAF, de sorte que le
#: ``rollback_token`` du connecteur soit bien celui injecté au rollback.
MINIMAL_PLAYBOOK = {
    "name": "block-source-ip-minimal",
    "description": "Blocage d'une IP par le connecteur WAF configuré (variante de test).",
    "reversible": True,
    "dry_run_capable": True,
    "connectors": ["waf"],
    "params": {
        "target": {"type": "ip", "required": True, "description": "IP à bloquer."},
        "duration_seconds": {
            "type": "duration",
            "default": 3600,
            "min": 60,
            "max": 604800,
            "description": "Durée du blocage.",
        },
        "reason": {"type": "string", "default": "test", "description": "Motif."},
    },
    "execute": [
        {
            "connector": "waf",
            "call": "block_ip",
            "with": {
                "ip": "${params.target}",
                "ttl": "${params.duration_seconds}",
                "note": "${params.reason}",
            },
        }
    ],
    "rollback": [
        {
            "connector": "waf",
            "call": "unblock_ip",
            # Le jeton rendu par ``block_ip`` est indispensable pour supprimer la règle par son
            # identifiant : un playbook qui l'omet retombe sur la recherche par valeur.
            "with": {"rollback_token": "${params.rollback_token}"},
        }
    ],
    "audit": {"severity": "high"},
}


class PlaybookIntegrationTest(NativeConnectorTestCase):
    """Le connecteur natif vu depuis le moteur : substitution, exécution, rollback.

    Ces tests vérifient la couture, pas le connecteur : les paramètres arrivent avec les noms
    du playbook (`ip`, `ttl`, `note`), et le rollback doit fonctionner avec ce que l'exécuteur
    lui transmet réellement.

    Deux points de vigilance, constatés pendant l'écriture de ces tests (ils appartiennent au
    moteur/aux playbooks livrés, hors périmètre de ce fichier de connecteurs) :

    * ``ActionEngine._execution_context`` ne fournit pas ``finding.remediation``, alors que
      ``playbooks/block-source-ip.yaml`` le référence dans son étape optionnelle de ticket :
      l'exécution du playbook livré échoue avec ``paramètre non résolu: ${finding.remediation}``.
      Le test ci-dessous fournit donc explicitement ce champ, pour vérifier ce qui relève du
      connecteur (l'appel HTTP réel) et non ce qui relève du contexte de rendu ;
    * ``PlaybookExecutor._build_context`` fait primer ``context['params']`` sur
      ``base_params['rollback_token']`` (le jeton injecté au rollback) : dans le chemin du
      moteur, ``${params.rollback_token}`` n'est donc jamais résolu. C'est pourquoi le test de
      suppression par identifiant appelle ``rollback`` sans contexte porteur de ``params`` :
      il vérifie la **capacité** du connecteur (supprimer une règle par son identifiant), pas
      le chemin actuel du moteur.
    """

    def cloudflare_responder(self) -> Responder:
        def responder(request: RecordedRequest) -> Any:
            if request.method == "POST":
                return (
                    200,
                    {
                        "success": True,
                        "errors": [],
                        "result": {
                            "id": CLOUDFLARE_RULE_ID,
                            "configuration": request.json_body.get("configuration"),
                        },
                    },
                )
            if request.method == "GET":
                return {
                    "success": True,
                    "errors": [],
                    "result": [
                        {
                            "id": CLOUDFLARE_RULE_ID,
                            "configuration": {"target": "ip", "value": "203.0.113.9"},
                        }
                    ],
                }
            return {"success": True, "errors": [], "result": {"id": CLOUDFLARE_RULE_ID}}

        return responder

    def registry(self, server: FakeApiServer) -> ConnectorRegistry:
        return ConnectorRegistry(
            {
                "waf": {
                    "driver": "cloudflare",
                    "settings": {
                        "api_base": f"{server.url}/client/v4",
                        "api_token": CLOUDFLARE_TOKEN,
                        "account_id": "acct-42",
                    },
                },
                # Le ticketing reste simulé : le test ne doit écrire aucun fichier sur disque.
                "ticketing": {"driver": "simulation", "settings": {}},
            },
            dry_run=False,
        )

    def context(self) -> dict[str, Any]:
        return {
            "tenant": {"id": "acme"},
            "finding": {
                "id": "f1c2",
                "title": "Tentative d'injection SQL",
                "severity": "high",
                "remediation": "Bloquer la source puis vérifier les journaux.",
            },
            "action": {"id": "a91b"},
        }

    def test_the_shipped_block_source_ip_playbook_reaches_cloudflare(self) -> None:
        """Le playbook **livré** déclenche bien un appel Cloudflare réel."""
        playbooks, diagnostics = load_playbooks_from_dir(REPO_ROOT / "playbooks")
        self.assertEqual([], [(item.path, item.error) for item in diagnostics])
        playbook = playbooks["block-source-ip"]

        server = self.fake_server(self.cloudflare_responder())
        executor = PlaybookExecutor(self.registry(server), dry_run=False)

        outcome = executor.execute(
            playbook,
            {
                "target": "203.0.113.9",
                "duration_seconds": 3600,
                "reason": "contre-mesure de test",
            },
            self.context(),
        )

        self.assertTrue(outcome.ok, outcome.error)
        # L'étape WAF est réelle : seule l'étape de ticketing reste simulée dans ce montage.
        self.assertFalse(outcome.steps[0].simulated)
        self.assertEqual("POST", server.requests[0].method)
        self.assertEqual(
            "/client/v4/accounts/acct-42/firewall/access_rules/rules", server.path_of(0)
        )
        body = server.requests[0].json_body
        self.assertEqual({"target": "ip", "value": "203.0.113.9"}, body["configuration"])
        self.assertIn("3600s", body["notes"])
        self.assertIn("contre-mesure de test", body["notes"])
        # La pile de rollback contient le jeton rendu par le connecteur.
        self.assertIn(CLOUDFLARE_RULE_ID, outcome.rollback_token or "")

    def test_the_shipped_unblock_playbook_levies_the_block(self) -> None:
        """Le playbook de rollback **livré** (`unblock-source-ip`) lève réellement le blocage.

        C'est le chemin réellement emprunté en production : une politique déclare
        ``rollback.playbook: unblock-source-ip``, qui transmet l'adresse. Le connecteur retrouve
        alors la règle par sa valeur — d'où l'avertissement qu'il inscrit dans son résultat.
        """
        playbooks, diagnostics = load_playbooks_from_dir(REPO_ROOT / "playbooks")
        self.assertEqual([], [(item.path, item.error) for item in diagnostics])
        unblock = playbooks["unblock-source-ip"]

        server = self.fake_server(self.cloudflare_responder())
        executor = PlaybookExecutor(self.registry(server), dry_run=False)

        outcome = executor.execute(
            unblock,
            {"target": "203.0.113.9", "reason": "levée du blocage (test)"},
            self.context(),
        )

        self.assertTrue(outcome.ok, outcome.error)
        self.assertEqual(["GET", "DELETE"], [request.method for request in server.requests])
        self.assertEqual("203.0.113.9", server.requests[0].query["configuration.value"])
        self.assertIn(CLOUDFLARE_RULE_ID, server.path_of(1))
        self.assertIn("supprimée", outcome.steps[0].detail)

    def test_the_rule_id_rendered_by_the_connector_can_delete_the_rule(self) -> None:
        """Capacité du connecteur : un jeton de règle supprime la règle **par identifiant**."""
        playbook = parse_playbook(MINIMAL_PLAYBOOK)
        server = self.fake_server(self.cloudflare_responder())
        executor = PlaybookExecutor(self.registry(server), dry_run=False)
        params = {"target": "203.0.113.9", "duration_seconds": 600, "reason": "test"}

        outcome = executor.execute(playbook, params)
        self.assertTrue(outcome.ok, outcome.error)

        # Contexte omis volontairement : voir la note de classe sur ``_build_context``.
        rolled = executor.rollback(playbook, outcome.rollback_token or "")

        self.assertTrue(rolled.ok, rolled.error)
        self.assertEqual(["POST", "DELETE"], [request.method for request in server.requests])
        self.assertEqual(
            f"/client/v4/accounts/acct-42/firewall/access_rules/rules/{CLOUDFLARE_RULE_ID}",
            server.path_of(1),
        )

    def test_no_playbook_step_reaches_the_network_in_dry_run(self) -> None:
        playbook = parse_playbook(MINIMAL_PLAYBOOK)
        server = self.fake_server(self.cloudflare_responder())
        executor = PlaybookExecutor(self.registry(server), dry_run=True)

        outcome = executor.execute(
            playbook, {"target": "203.0.113.9", "duration_seconds": 600, "reason": "test"}
        )

        self.assertTrue(outcome.ok, outcome.error)
        self.assertTrue(outcome.simulated)
        self.assertEqual(0, server.calls)


# --------------------------------------------------------------------------------------
# 7. Mode simulation : aucun connecteur natif ne doit émettre de requête
# --------------------------------------------------------------------------------------


class NativeDryRunTest(NativeConnectorTestCase):
    """``dry_run=True`` : l'intention est journalisée, rien n'est émis — jamais."""

    def test_no_native_connector_emits_any_request_in_dry_run(self) -> None:
        server = self.fake_server(lambda request: (200, {"success": True, "result": {}}))
        connectors = [
            CloudflareConnector(
                {
                    "api_base": f"{server.url}/client/v4",
                    "api_token": CLOUDFLARE_TOKEN,
                    "account_id": "acct-42",
                    "zone_id": "zone-7",
                },
                dry_run=True,
            ),
            AwsWafConnector({**AWS_SETTINGS, "endpoint_url": f"{server.url}/"}, dry_run=True),
            SlackConnector({"webhook_url": f"{server.url}{SLACK_WEBHOOK_PATH}"}, dry_run=True),
            GithubIssueConnector(
                {"api_url": server.url, "token": GH_TOKEN, "repository": "a/b"},
                dry_run=True,
            ),
        ]
        params = {"ip": "203.0.113.9", "target": "203.0.113.9", "message": "test"}

        for connector in connectors:
            for operation in sorted(connector.capabilities):
                with self.subTest(connector=connector.driver, operation=operation):
                    result = connector.call(operation, dict(params))
                    self.assertTrue(result.ok, result.error)
                    self.assertTrue(result.simulated)
                    self.assertIn("simulation", result.detail)
        self.assertEqual(0, server.calls, "aucun effet de bord ne doit être émis en dry-run")
        self.assertEqual(0, server.calls)

    def test_dry_run_masks_secrets_in_the_echoed_parameters(self) -> None:
        connector = CloudflareConnector(
            {"api_token": CLOUDFLARE_TOKEN, "account_id": "acct-42"}, dry_run=True
        )

        result = connector.call("block_ip", {"ip": "203.0.113.9", "api_token": CLOUDFLARE_TOKEN})

        self.assertNoSecret(CLOUDFLARE_TOKEN, result.to_dict())
        self.assertEqual("<redacted>", result.data["params_echo"]["api_token"])
        self.assertEqual("<redacted>", redact_params({"api_token": CLOUDFLARE_TOKEN})["api_token"])

    def test_dry_run_does_not_require_credentials(self) -> None:
        """En simulation, un connecteur non configuré doit rester utilisable sans secret."""
        for connector in (
            CloudflareConnector({}, dry_run=True),
            AwsWafConnector({}, dry_run=True),
            SlackConnector({}, dry_run=True),
            GithubIssueConnector({}, dry_run=True),
        ):
            with self.subTest(connector=connector.driver):
                results = [
                    connector.call(op, {"ip": "203.0.113.9"}) for op in connector.capabilities
                ]
                self.assertTrue(all(item.ok for item in results))
                self.assertTrue(all(item.simulated for item in results))


# --------------------------------------------------------------------------------------
# 8. Registre : les pilotes natifs existent, mais ne sont jamais actifs par défaut
# --------------------------------------------------------------------------------------


class NativeRegistryTest(unittest.TestCase):
    """Le registre doit exposer les pilotes natifs sans changer la sûreté par défaut."""

    def test_native_drivers_are_registered(self) -> None:
        self.assertIs(CloudflareConnector, DRIVERS["cloudflare"])
        self.assertIs(AwsWafConnector, DRIVERS["aws-waf"])
        self.assertIs(SlackConnector, DRIVERS["slack"])
        self.assertIs(GithubIssueConnector, DRIVERS["github-issues"])

    def test_default_configuration_stays_simulated(self) -> None:
        """Garantie de sûreté du produit : aucun pilote natif actif à l'installation."""
        native = {"cloudflare", "aws-waf", "slack", "github-issues"}
        for name, body in DEFAULT_CONNECTORS.items():
            self.assertNotIn(
                body["driver"], native, f"le connecteur '{name}' active un pilote natif par défaut"
            )
        self.assertIsInstance(ConnectorRegistry().get("waf"), SimulationConnector)

    def test_a_logical_name_can_be_switched_to_a_native_driver(self) -> None:
        registry = ConnectorRegistry(
            {"waf": {"driver": "cloudflare", "settings": {"api_token": "jeton-de-test"}}},
            dry_run=True,
        )
        self.assertIsInstance(registry.get("waf"), CloudflareConnector)
        self.assertEqual("cloudflare", registry.get("waf").driver)
        self.assertIn("cloudflare", registry.describe()["connectors"]["waf"])

    def test_unknown_driver_falls_back_to_simulation(self) -> None:
        registry = ConnectorRegistry({"waf": {"driver": "pilote-inexistant", "settings": {}}})
        self.assertIsInstance(registry.get("waf"), SimulationConnector)

    def test_every_driver_exposes_the_connector_contract(self) -> None:
        for name, driver in DRIVERS.items():
            with self.subTest(driver=name):
                instance = driver({}, dry_run=True)
                self.assertTrue(instance.capabilities)
                self.assertTrue(instance.description)
                stats = instance.stats()
                self.assertEqual(name, stats["driver"])
                self.assertEqual(sorted(instance.capabilities), stats["capabilities"])

    def test_native_drivers_do_not_claim_operations_they_cannot_perform(self) -> None:
        """Un pilote natif limité le dit : la passerelle webhook reste disponible pour le reste."""
        self.assertEqual(
            frozenset({"block_ip", "unblock_ip", "rate_limit", "remove_rate_limit"}),
            CloudflareConnector({}).capabilities,
        )
        self.assertEqual(frozenset({"block_ip", "unblock_ip"}), AwsWafConnector({}).capabilities)
        self.assertEqual(frozenset({"notify"}), SlackConnector({}).capabilities)
        self.assertEqual(
            frozenset({"open_ticket", "close_ticket"}), GithubIssueConnector({}).capabilities
        )


class WebhookSchemeValidationTest(unittest.TestCase):
    """Une URL de connecteur ne doit jamais ouvrir autre chose que du HTTP.

    Défaut corrigé, et il méritait un test : ``rollback_url`` était renvoyée telle quelle à
    ``urlopen``. ``urllib`` ouvre aussi ``file://``, ``ftp://`` et ``data:`` — une ligne de
    configuration mal remplie transformait donc le connecteur en lecteur de disque, et le
    contenu du fichier se retrouvait dans le résultat de l'action, donc dans le journal,
    l'audit et l'API.
    """

    def _connector(self, **settings: object) -> HttpWebhookConnector:
        base: dict[str, object] = {"url": "https://passerelle.interne/thotsecure"}
        base.update(settings)
        return HttpWebhookConnector(base, dry_run=True)

    def test_http_and_https_are_accepted(self) -> None:
        for value in (
            "https://passerelle.interne/hook",
            "http://127.0.0.1:9000/hook",
            # La casse ne doit pas décider : `startswith` refusait `HTTPS://` à tort.
            "HTTPS://PASSERELLE.INTERNE/hook",
        ):
            with self.subTest(url=value):
                self.assertEqual(value, self._connector(rollback_url=value, url=value).rollback_url)

    def test_every_other_scheme_is_refused(self) -> None:
        for value in (
            "file:///etc/passwd",
            "file://C:/Windows/win.ini",
            "ftp://exemple.interne/fichier",
            "data:text/plain;base64,QQ==",
            "gopher://exemple.interne/",
            "sans-schema",
        ):
            with self.subTest(url=value):
                connector = self._connector(rollback_url=value)
                with self.assertRaises(ConnectorNotConfiguredError):
                    _ = connector.rollback_url

    def test_an_absent_rollback_url_stays_absent(self) -> None:
        self.assertIsNone(self._connector().rollback_url)

    def test_a_bad_scheme_becomes_a_recorded_failure_not_a_crash(self) -> None:
        """Le contrat de connecteur : jamais d'exception qui remonte, toujours un résultat."""
        connector = self._connector(rollback_url="file:///etc/passwd")
        connector.dry_run = False  # chemin réel : l'URL est refusée avant toute ouverture
        # `unblock_ip` est l'opération de rollback : c'est elle qui lit `rollback_url`.
        result = connector.call("unblock_ip", {"target": "203.0.113.9"})
        self.assertFalse(result.ok)
        self.assertIn("rollback_url", result.error or "")
        self.assertIn("refusé", result.error or "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
