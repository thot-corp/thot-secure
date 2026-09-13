"""Client WebSocket Thot Secure — **stdlib pur**.

Aucune dépendance ``websockets`` / ``websocket-client`` : le handshake HTTP (RFC 6455) et les
trames sont implémentés avec ``socket``, ``base64``, ``hashlib`` et ``struct``.

Cible : ``GET /api/v1/ws/stream?api_key=…&tenant_id=…`` (contrat §4.8). Les navigateurs ne
pouvant pas poser d'en-tête sur ``ws://``, la clé passe en paramètre de requête — c'est pourquoi
**aucune erreur ni aucun log de ce module ne contient l'URL brute** (elle est nettoyée par
:func:`thotsecure_sdk.errors.redact_url`).

Frames attendues : ``{"type":"event|finding|action|audit|heartbeat","data":{…}}``.

Fonctionnalités : reconnexion avec backoff exponentiel, ping/pong applicatif (heartbeat), détection
de connexion morte, assemblage des trames fragmentées, filtrage par type.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import random
import socket
import ssl
import struct
import time
import warnings
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Self
from urllib.parse import urlencode, urlsplit, urlunsplit

from .errors import AuthenticationError, PermissionDeniedError, WebSocketError, redact_url

logger = logging.getLogger("thotsecure_sdk.ws")

__all__ = [
    "FRAME_TYPES",
    "WS_PATH",
    "Frame",
    "WebSocketClient",
    "WebSocketConnection",
    "accept_key",
    "build_ws_url",
    "encode_frame",
    "read_frame",
]

#: Chemin du flux temps réel (contrat §4.8).
WS_PATH = "/api/v1/ws/stream"

#: Types de frames documentés par le contrat.
FRAME_TYPES = ("event", "finding", "action", "audit", "heartbeat")

#: Constante magique du handshake RFC 6455.
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OPCODE_CONTINUATION = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA

_OPCODE_NAMES = {
    OPCODE_TEXT: "text",
    OPCODE_BINARY: "binary",
    OPCODE_CLOSE: "close",
    OPCODE_PING: "ping",
    OPCODE_PONG: "pong",
    OPCODE_CONTINUATION: "continuation",
}

MAX_FRAME_BYTES = 16 * 1024 * 1024


@dataclass
class Frame:
    """Frame applicative décodée : ``{"type": …, "data": …}``."""

    type: str
    data: Any = None
    raw: dict[str, Any] = field(default_factory=dict)
    received_at: float = field(default_factory=time.time)

    def __getitem__(self, key: str) -> Any:
        if key == "type":
            return self.type
        if key == "data":
            return self.data
        return self.raw[key]

    def get(self, key: str, default: Any = None) -> Any:
        if key in ("type", "data"):
            return getattr(self, key)
        return self.raw.get(key, default)

    def __repr__(self) -> str:  # pragma: no cover - confort de débogage
        return (
            f"Frame(type={self.type!r}, data={json.dumps(self.data, ensure_ascii=False, default=str)[:120]})"
        )


# --------------------------------------------------------------------------------------
# Fonctions pures (testables sans réseau)
# --------------------------------------------------------------------------------------


def accept_key(sec_websocket_key: str) -> str:
    """Calcule ``Sec-WebSocket-Accept`` = base64(sha1(key + GUID))."""
    digest = hashlib.sha1((sec_websocket_key + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def build_ws_url(
    base_url: str,
    api_key: str | None = None,
    tenant_id: str | None = None,
    *,
    path: str = WS_PATH,
) -> str:
    """Construit l'URL ``ws://`` / ``wss://`` du flux, avec ``api_key`` et ``tenant_id``.

    ``http://`` → ``ws://``, ``https://`` → ``wss://``. Un éventuel préfixe de chemin du
    ``base_url`` (déploiement derrière un reverse-proxy) est conservé.

    ⚠️ L'URL retournée **contient la clé API** : ne la journalisez jamais telle quelle,
    utilisez :func:`thotsecure_sdk.errors.redact_url`.
    """
    if not base_url:
        raise ValueError("build_ws_url : base_url requis")
    parts = urlsplit(base_url if "://" in base_url else "http://" + base_url)
    if parts.scheme in ("http", "ws"):
        scheme = "ws"
    elif parts.scheme in ("https", "wss"):
        scheme = "wss"
    else:
        raise ValueError(f"build_ws_url : schéma non supporté {parts.scheme!r}")

    prefix = parts.path.rstrip("/")
    full_path = prefix + path
    query: dict[str, str] = {}
    if api_key:
        query["api_key"] = api_key
    if tenant_id:
        query["tenant_id"] = tenant_id
    return urlunsplit((scheme, parts.netloc, full_path, urlencode(query), ""))


def encode_frame(
    opcode: int,
    payload: bytes = b"",
    *,
    fin: bool = True,
    mask: bool = True,
    mask_key: bytes | None = None,
) -> bytes:
    """Encode une trame RFC 6455. Un client **doit** masquer ses trames (``mask=True``)."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    length = len(payload)
    first = (0x80 if fin else 0x00) | (opcode & 0x0F)
    mask_bit = 0x80 if mask else 0x00

    if length < 126:
        header = struct.pack("!BB", first, mask_bit | length)
    elif length < 65536:
        header = struct.pack("!BBH", first, mask_bit | 126, length)
    else:
        header = struct.pack("!BBQ", first, mask_bit | 127, length)

    if not mask:
        return header + payload
    key = mask_key if mask_key is not None else os.urandom(4)
    if len(key) != 4:
        raise ValueError("mask_key doit faire exactement 4 octets")
    masked = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return header + key + masked


def read_frame(
    recv: Callable[[int], bytes],
    *,
    max_payload: int = MAX_FRAME_BYTES,
) -> tuple:
    """Lit une trame depuis *recv* (fonction de lecture de type ``socket.recv``).

    Retourne ``(fin, opcode, payload)``. Lève :class:`WebSocketError` si la trame est invalide
    ou trop volumineuse (protection anti-DoS sur un flux non fiable).
    """
    header = _read_exact(recv, 2)
    first, second = header[0], header[1]
    fin = bool(first & 0x80)
    if first & 0x70:
        raise WebSocketError("trame invalide : bits RSV non nuls (extensions non négociées)")
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F

    if length == 126:
        length = struct.unpack("!H", _read_exact(recv, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", _read_exact(recv, 8))[0]
    if length > max_payload:
        raise WebSocketError("trame trop volumineuse : %d octets (max %d)" % (length, max_payload))

    key = _read_exact(recv, 4) if masked else b""
    payload = _read_exact(recv, length) if length else b""
    if masked:
        payload = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return fin, opcode, payload


def _read_exact(recv: Callable[[int], bytes], count: int) -> bytes:
    """Lit exactement *count* octets, ou lève si la connexion se ferme avant."""
    chunks = bytearray()
    while len(chunks) < count:
        chunk = recv(count - len(chunks))
        if not chunk:
            raise WebSocketError("connexion fermée par le serveur (%d/%d octets lus)" % (len(chunks), count))
        chunks.extend(chunk)
    return bytes(chunks)


# --------------------------------------------------------------------------------------
# Connexion
# --------------------------------------------------------------------------------------


class _SocketReader:
    """Lecteur tamponné au-dessus d'un socket (ou de toute fonction ``recv``)."""

    def __init__(self, recv: Callable[[int], bytes]) -> None:
        self._recv = recv
        self._buffer = bytearray()

    def read_exact(self, count: int) -> bytes:
        while len(self._buffer) < count:
            chunk = self._recv(65536)
            if not chunk:
                raise WebSocketError("connexion fermée")
            self._buffer.extend(chunk)
        data = bytes(self._buffer[:count])
        del self._buffer[:count]
        return data

    def read_until(self, delimiter: bytes, limit: int = 65536) -> bytes:
        while delimiter not in self._buffer:
            if len(self._buffer) > limit:
                raise WebSocketError("en-têtes de handshake trop volumineux")
            chunk = self._recv(4096)
            if not chunk:
                raise WebSocketError("connexion fermée pendant le handshake")
            self._buffer.extend(chunk)
        index = self._buffer.index(delimiter) + len(delimiter)
        data = bytes(self._buffer[:index])
        del self._buffer[:index]
        return data


class WebSocketConnection:
    """Connexion WebSocket bas niveau (handshake + trames), sans logique de reconnexion."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 30.0,
        verify_tls: bool = True,
        extra_headers: Mapping[str, str] | None = None,
        socket_factory: Callable[..., Any] | None = None,
        max_payload: int = MAX_FRAME_BYTES,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.extra_headers = dict(extra_headers or {})
        self.max_payload = max_payload
        self._socket_factory = socket_factory or socket.create_connection
        self._sock: Any | None = None
        self._reader: _SocketReader | None = None

    # ------------------------------------------------------------------ connexion

    def connect(self) -> None:
        """Ouvre le socket, effectue le handshake et valide ``Sec-WebSocket-Accept``."""
        parts = urlsplit(self.url)
        host = parts.hostname
        if not host:
            raise WebSocketError("URL WebSocket invalide", url=self.url)
        secure = parts.scheme == "wss"
        port = parts.port or (443 if secure else 80)

        try:
            sock = self._socket_factory((host, port), self.timeout)
        except OSError as exc:
            raise WebSocketError(
                f"connexion WebSocket impossible vers {host}:{port} : {exc}", url=self.url
            ) from exc

        if secure:
            context = ssl.create_default_context()
            if not self.verify_tls:
                warnings.warn(
                    "WebSocket: verify_tls=False — le certificat TLS n'est PAS vérifié.",
                    RuntimeWarning,
                    stacklevel=2,
                )
                context = ssl._create_unverified_context()
            try:
                sock = context.wrap_socket(sock, server_hostname=host)
            except (ssl.SSLError, OSError) as exc:
                sock.close()
                raise WebSocketError(f"échec TLS : {exc}", url=self.url) from exc

        sock.settimeout(self.timeout)
        self._sock = sock
        self._reader = _SocketReader(sock.recv)
        self._handshake(parts, host, port)

    def _handshake(self, parts: Any, host: str, port: int) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        default_port = 443 if parts.scheme == "wss" else 80
        host_header = host if port == default_port else "%s:%d" % (host, port)

        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host_header}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            "User-Agent: thotsecure-sdk-python/0.1.0",
        ]
        for name, value in self.extra_headers.items():
            lines.append(f"{name}: {value}")
        request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")

        try:
            self._sock.sendall(request)
            raw_response = self._reader.read_until(b"\r\n\r\n")
        except OSError as exc:
            raise WebSocketError(f"handshake WebSocket interrompu : {exc}", url=self.url) from exc

        status, headers = self._parse_handshake(raw_response)
        if status != 101:
            message = f"handshake WebSocket refusé (HTTP {status})"
            if status == 401:
                raise AuthenticationError(message, url=self.url)
            if status == 403:
                raise PermissionDeniedError(message, url=self.url)
            raise WebSocketError(message, status_code=status, url=self.url)

        expected = accept_key(key)
        received = headers.get("sec-websocket-accept", "")
        if received.strip() != expected:
            raise WebSocketError(
                "Sec-WebSocket-Accept invalide : le serveur distant n'est pas un WebSocket "
                "conforme RFC 6455 (proxy mal configuré ?)",
                url=self.url,
            )
        if "websocket" not in headers.get("upgrade", "").lower():
            raise WebSocketError("en-tête Upgrade absent du handshake", url=self.url)
        logger.debug("WebSocket connecté (%s)", redact_url(self.url).split("?")[0])

    @staticmethod
    def _parse_handshake(raw: bytes) -> tuple:
        text = raw.decode("iso-8859-1", errors="replace")
        lines = text.split("\r\n")
        status_line = lines[0] if lines else ""
        pieces = status_line.split(" ", 2)
        try:
            status = int(pieces[1])
        except (IndexError, ValueError) as exc:
            raise WebSocketError("réponse de handshake illisible") from exc
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return status, headers

    # ------------------------------------------------------------------ trames

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def send_text(self, text: str) -> None:
        self._send(OPCODE_TEXT, text.encode("utf-8"))

    def send_binary(self, payload: bytes) -> None:
        self._send(OPCODE_BINARY, payload)

    def send_json(self, obj: Any) -> None:
        self.send_text(json.dumps(obj, ensure_ascii=False))

    def send_ping(self, payload: bytes = b"thotsecure") -> None:
        self._send(OPCODE_PING, payload)

    def send_pong(self, payload: bytes = b"") -> None:
        self._send(OPCODE_PONG, payload)

    def send_close(self, code: int = 1000, reason: str = "") -> None:
        body = struct.pack("!H", code) + reason.encode("utf-8")[:123]
        try:
            self._send(OPCODE_CLOSE, body)
        except WebSocketError:  # connexion déjà morte : rien à faire
            logger.debug("envoi de Close impossible : connexion déjà fermée")

    def _send(self, opcode: int, payload: bytes) -> None:
        if self._sock is None:
            raise WebSocketError("WebSocket non connecté", url=self.url)
        try:
            self._sock.sendall(encode_frame(opcode, payload, mask=True))
        except OSError as exc:
            raise WebSocketError(f"envoi de trame impossible : {exc}", url=self.url) from exc

    def read_message(self, *, timeout: float | None = None) -> tuple:
        """Lit un message complet (assemblage des fragments).

        Les ``ping`` reçus sont acquittés automatiquement (``pong``), les ``pong`` sont ignorés.
        Retourne ``("text"|"binary"|"close", payload_bytes)``.
        Lève ``socket.timeout`` si ``timeout`` expire (utilisé pour l'heartbeat applicatif).
        """
        if self._sock is None or self._reader is None:
            raise WebSocketError("WebSocket non connecté", url=self.url)
        if timeout is not None:
            self._sock.settimeout(timeout)

        buffer = bytearray()
        message_opcode: int | None = None
        while True:
            fin, opcode, payload = read_frame(self._reader.read_exact, max_payload=self.max_payload)

            if opcode == OPCODE_PING:
                self.send_pong(payload)
                continue
            if opcode == OPCODE_PONG:
                continue
            if opcode == OPCODE_CLOSE:
                self.send_close(int.from_bytes(payload[:2], "big") if len(payload) >= 2 else 1000)
                return "close", payload
            if opcode == OPCODE_CONTINUATION:
                if message_opcode is None:
                    raise WebSocketError("fragment de continuation sans message initial")
                buffer.extend(payload)
            else:
                if message_opcode is not None:
                    raise WebSocketError("nouveau message avant la fin du précédent")
                message_opcode = opcode
                buffer.extend(payload)
            if not fin:
                continue
            return _OPCODE_NAMES.get(message_opcode, "binary"), bytes(buffer)

    def close(self) -> None:
        """Ferme proprement la connexion (Close frame puis ``shutdown``)."""
        if self._sock is None:
            return
        try:
            self.send_close()
        except Exception:  # pragma: no cover - fermeture best effort
            pass
        try:
            self._sock.close()
        except Exception:  # pragma: no cover
            pass
        finally:
            self._sock = None
            self._reader = None

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


# --------------------------------------------------------------------------------------
# Client haut niveau (reconnexion + filtrage)
# --------------------------------------------------------------------------------------


class WebSocketClient:
    """Client du flux temps réel avec reconnexion, heartbeat et filtrage par type.

    Utilisation ::

        with WebSocketClient("http://127.0.0.1:8080", api_key=key, tenant_id="acme") as ws:
            for frame in ws.stream(types=["finding"]):
                print(frame.type, frame.data)
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        tenant_id: str | None = None,
        *,
        url: str | None = None,
        timeout: float = 30.0,
        connect_timeout: float = 10.0,
        verify_tls: bool = True,
        reconnect: bool = True,
        max_reconnect_attempts: int = 10,
        backoff_base: float = 0.5,
        backoff_max: float = 30.0,
        heartbeat_seconds: float = 30.0,
        dead_connection_factor: float = 3.0,
        socket_factory: Callable[..., Any] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        rand: Callable[[], float] = random.random,
    ) -> None:
        resolved_url = url or build_ws_url(
            base_url or os.environ.get("THOT_URL") or "http://127.0.0.1:8080",
            api_key if api_key is not None else os.environ.get("THOT_API_KEY"),
            tenant_id if tenant_id is not None else os.environ.get("THOT_TENANT_ID"),
        )
        if not resolved_url.startswith(("ws://", "wss://")):
            raise ValueError("url WebSocket doit commencer par ws:// ou wss://")
        if not verify_tls:
            warnings.warn(
                "WebSocketClient(verify_tls=False) : le certificat TLS ne sera PAS vérifié.",
                RuntimeWarning,
                stacklevel=2,
            )

        self.url = resolved_url
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self.verify_tls = verify_tls
        self.reconnect = reconnect
        self.max_reconnect_attempts = max(0, int(max_reconnect_attempts))
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.heartbeat_seconds = heartbeat_seconds
        self.dead_connection_factor = dead_connection_factor
        self._socket_factory = socket_factory
        self._sleep = sleep
        self._rand = rand
        self._connection: WebSocketConnection | None = None
        #: Nombre de reconnexions effectuées depuis la création du client.
        self.reconnect_count = 0

    # ------------------------------------------------------------------ cycle de vie

    def connect(self) -> WebSocketConnection:
        """Ouvre (ou rouvre) la connexion."""
        self.close()
        connection = WebSocketConnection(
            self.url,
            timeout=self.connect_timeout,
            verify_tls=self.verify_tls,
            socket_factory=self._socket_factory,
        )
        connection.connect()
        self._connection = connection
        return connection

    def close(self) -> None:
        """Ferme la connexion courante."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __repr__(self) -> str:  # pragma: no cover - jamais de clé dans le repr
        return f"WebSocketClient(url={redact_url(self.url)!r}, reconnect={self.reconnect})"

    # ------------------------------------------------------------------ flux

    def _delay(self, attempt: int) -> float:
        raw = min(self.backoff_max, self.backoff_base * (2**attempt))
        return raw * (0.5 + 0.5 * self._rand())

    def stream(
        self,
        *,
        types: Sequence[str] | None = None,
        include_heartbeat: bool = False,
        max_messages: int | None = None,
    ) -> Iterator[Frame]:
        """Itère sur les frames du flux, en se reconnectant si nécessaire.

        ``types`` filtre les types applicatifs (``event``, ``finding``, ``action``, ``audit``).
        ``include_heartbeat`` conserve les frames de battement de cœur (ignorées par défaut).
        La reconnexion applique un backoff exponentiel avec jitter ; au-delà de
        ``max_reconnect_attempts``, l'exception de transport est propagée.
        """
        wanted = set(types) if types else None
        attempts = 0
        delivered = 0

        while True:
            try:
                if self._connection is None or not self._connection.connected:
                    self.connect()
                attempts = 0
                frame = self._next_frame()
                if frame is None:
                    continue
            except WebSocketError as exc:
                if not self.reconnect or attempts >= self.max_reconnect_attempts:
                    raise
                delay = self._delay(attempts)
                attempts += 1
                self.reconnect_count += 1
                logger.warning(
                    "WebSocket déconnecté (%s) — reconnexion %d/%d dans %.2fs",
                    exc.message,
                    attempts,
                    self.max_reconnect_attempts,
                    delay,
                )
                self.close()
                if delay > 0:
                    self._sleep(delay)
                continue
            except OSError as exc:
                if not self.reconnect or attempts >= self.max_reconnect_attempts:
                    raise WebSocketError(f"flux WebSocket interrompu : {exc}", url=self.url) from exc
                delay = self._delay(attempts)
                attempts += 1
                self.reconnect_count += 1
                logger.warning("Erreur réseau WebSocket (%s) — reconnexion dans %.2fs", exc, delay)
                self.close()
                if delay > 0:
                    self._sleep(delay)
                continue

            if frame.type == "heartbeat" and not include_heartbeat:
                continue
            if wanted is not None and frame.type not in wanted:
                continue
            yield frame
            delivered += 1
            if max_messages is not None and delivered >= max_messages:
                return

    def _next_frame(self) -> Frame | None:
        """Lit le prochain message en gérant le heartbeat (retourne ``None`` après un ping)."""
        connection = self._connection
        if connection is None:
            raise WebSocketError("WebSocket non connecté", url=self.url)
        try:
            kind, payload = connection.read_message(timeout=self.heartbeat_seconds)
        except TimeoutError:
            # Aucun trafic pendant l'intervalle : on vérifie que la connexion vit toujours.
            connection.send_ping()
            return None
        except ssl.SSLError as exc:
            raise WebSocketError(f"erreur TLS sur le flux : {exc}", url=self.url) from exc

        if kind == "close":
            raise WebSocketError("flux fermé par le serveur", url=self.url)

        text = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload)
        try:
            decoded = json.loads(text)
        except (ValueError, binascii.Error):
            return Frame(type="raw", data=text, raw={})
        if isinstance(decoded, Mapping):
            frame_type = str(decoded.get("type", "unknown"))
            return Frame(type=frame_type, data=decoded.get("data"), raw=dict(decoded))
        return Frame(type="raw", data=decoded, raw={})

    def __iter__(self) -> Iterator[Frame]:
        return self.stream()
