"""Tests de la couche WebSocket — **hors ligne**, sans aucune connexion réseau.

Les fonctions pures (handshake, encodage/décodage de trames) sont testées directement.
L'assemblage des messages est testé sur une paire de sockets locales (``socket.socketpair``),
et la logique de reconnexion/filtrage avec un lecteur de trames simulé.

Exécution ::

    python -m unittest discover -s sdks/python/tests -t sdks/python -v
"""

from __future__ import annotations

import io
import json
import pathlib
import socket
import struct
import sys
import unittest
from typing import Any

_SDK_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))

from thotsecure_sdk.errors import WebSocketError, redact_url
from thotsecure_sdk.ws import (
    OPCODE_BINARY,
    OPCODE_CLOSE,
    OPCODE_CONTINUATION,
    OPCODE_PING,
    OPCODE_PONG,
    OPCODE_TEXT,
    Frame,
    WebSocketClient,
    WebSocketConnection,
    _SocketReader,
    accept_key,
    build_ws_url,
    encode_frame,
    read_frame,
)


class TestHandshakeHelpers(unittest.TestCase):
    def test_accept_key_rfc6455_vector(self) -> None:
        # Vecteur officiel de la RFC 6455 §1.3.
        self.assertEqual(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_build_ws_url_http_to_ws(self) -> None:
        url = build_ws_url("http://127.0.0.1:8080", "ao_key", "acme")
        self.assertTrue(url.startswith("ws://127.0.0.1:8080/api/v1/ws/stream?"))
        self.assertIn("api_key=ao_key", url)
        self.assertIn("tenant_id=acme", url)

    def test_build_ws_url_https_to_wss_and_path_prefix(self) -> None:
        url = build_ws_url("https://aegis.example/thotsecure/", "ao_key", "acme")
        self.assertTrue(url.startswith("wss://aegis.example/thotsecure/api/v1/ws/stream?"))

    def test_build_ws_url_without_credentials(self) -> None:
        url = build_ws_url("http://127.0.0.1:8080")
        self.assertEqual(url, "ws://127.0.0.1:8080/api/v1/ws/stream")

    def test_build_ws_url_rejects_unknown_scheme(self) -> None:
        with self.assertRaises(ValueError):
            build_ws_url("ftp://exemple", "k", "t")

    def test_redact_url_hides_key_in_ws_url(self) -> None:
        url = build_ws_url("http://127.0.0.1:8080", "ao_tres_secret", "acme")
        self.assertIn("ao_tres_secret", url)  # l'URL brute contient bien la clé…
        self.assertNotIn("ao_tres_secret", redact_url(url))  # …mais jamais dans les logs/erreurs


class TestFrameCodec(unittest.TestCase):
    @staticmethod
    def reader(data: bytes):
        stream = io.BytesIO(data)
        return stream.read

    def test_encode_small_masked_frame_layout(self) -> None:
        frame = encode_frame(OPCODE_TEXT, b"hello", mask=True, mask_key=b"\x01\x02\x03\x04")

        self.assertEqual(frame[0], 0x81)  # FIN + opcode texte
        self.assertEqual(frame[1], 0x85)  # masque + longueur 5
        self.assertEqual(frame[2:6], b"\x01\x02\x03\x04")
        self.assertEqual(len(frame), 6 + 5)

    def test_unmasked_frame_round_trip(self) -> None:
        payload = b'{"type":"heartbeat","data":{}}'
        raw = encode_frame(OPCODE_TEXT, payload, mask=False)

        fin, opcode, decoded = read_frame(self.reader(raw))

        self.assertTrue(fin)
        self.assertEqual(opcode, OPCODE_TEXT)
        self.assertEqual(decoded, payload)

    def test_masked_frame_round_trip(self) -> None:
        payload = b"charge utile de test"
        raw = encode_frame(OPCODE_BINARY, payload, mask=True, mask_key=b"\xaa\xbb\xcc\xdd")

        fin, opcode, decoded = read_frame(self.reader(raw))

        self.assertTrue(fin)
        self.assertEqual(opcode, OPCODE_BINARY)
        self.assertEqual(decoded, payload)
        self.assertNotIn(payload, raw)  # la charge utile est bien masquée sur le fil

    def test_medium_payload_uses_16_bit_length(self) -> None:
        payload = b"x" * 200
        raw = encode_frame(OPCODE_TEXT, payload, mask=False)

        self.assertEqual(raw[1], 126)
        self.assertEqual(struct.unpack("!H", raw[2:4])[0], 200)
        self.assertEqual(read_frame(self.reader(raw))[2], payload)

    def test_large_payload_uses_64_bit_length(self) -> None:
        payload = b"y" * 70000
        raw = encode_frame(OPCODE_TEXT, payload, mask=False)

        self.assertEqual(raw[1], 127)
        self.assertEqual(struct.unpack("!Q", raw[2:10])[0], 70000)
        self.assertEqual(read_frame(self.reader(raw))[2], payload)

    def test_fragmented_header_flag(self) -> None:
        raw = encode_frame(OPCODE_TEXT, b"part", fin=False, mask=False)
        fin, opcode, payload = read_frame(self.reader(raw))
        self.assertFalse(fin)
        self.assertEqual(opcode, OPCODE_TEXT)
        self.assertEqual(payload, b"part")

    def test_rsv_bits_are_rejected(self) -> None:
        raw = bytes([0x91, 0x00])  # RSV1 positionné : extensions non négociées
        with self.assertRaises(WebSocketError):
            read_frame(self.reader(raw))

    def test_oversized_frame_is_rejected(self) -> None:
        raw = struct.pack("!BBQ", 0x82, 127, 10_000_000)
        with self.assertRaises(WebSocketError) as ctx:
            read_frame(self.reader(raw), max_payload=1024)
        self.assertIn("trop volumineuse", str(ctx.exception))

    def test_truncated_stream_raises(self) -> None:
        with self.assertRaises(WebSocketError):
            read_frame(self.reader(b""))


class TestMessageAssembly(unittest.TestCase):
    """Assemblage des messages via une paire de sockets locale (aucun réseau externe)."""

    def setUp(self) -> None:
        self.client_end, self.server_end = socket.socketpair()
        self.client_end.settimeout(1.0)
        self.server_end.settimeout(1.0)
        self.addCleanup(self.client_end.close)
        self.addCleanup(self.server_end.close)

        self.connection = WebSocketConnection("ws://127.0.0.1:1/api/v1/ws/stream", timeout=1.0)
        # Injection directe : on teste le décodage sans refaire le handshake.
        self.connection._sock = self.client_end
        self.connection._reader = _SocketReader(self.client_end.recv)

    def test_text_message(self) -> None:
        payload = json.dumps({"type": "finding", "data": {"finding_id": "f1"}}).encode("utf-8")
        self.server_end.sendall(encode_frame(OPCODE_TEXT, payload, mask=False))

        kind, decoded = self.connection.read_message(timeout=1.0)

        self.assertEqual(kind, "text")
        self.assertEqual(json.loads(decoded), {"type": "finding", "data": {"finding_id": "f1"}})

    def test_fragmented_message_is_reassembled(self) -> None:
        self.server_end.sendall(encode_frame(OPCODE_TEXT, b'{"type":"eve', fin=False, mask=False))
        self.server_end.sendall(encode_frame(OPCODE_CONTINUATION, b'nt","data":{}}', fin=True, mask=False))

        kind, decoded = self.connection.read_message(timeout=1.0)

        self.assertEqual(kind, "text")
        self.assertEqual(json.loads(decoded), {"type": "event", "data": {}})

    def test_ping_is_answered_with_pong(self) -> None:
        self.server_end.sendall(encode_frame(OPCODE_PING, b"ping-data", mask=False))
        self.server_end.sendall(encode_frame(OPCODE_TEXT, b'{"type":"heartbeat"}', mask=False))

        kind, _ = self.connection.read_message(timeout=1.0)
        self.assertEqual(kind, "text")

        _fin, opcode, payload = read_frame(self.server_end.recv)
        self.assertEqual(opcode, OPCODE_PONG)
        self.assertEqual(payload, b"ping-data")

    def test_close_frame_is_reported(self) -> None:
        self.server_end.sendall(encode_frame(OPCODE_CLOSE, struct.pack("!H", 1000), mask=False))

        kind, payload = self.connection.read_message(timeout=1.0)

        self.assertEqual(kind, "close")
        self.assertEqual(struct.unpack("!H", payload[:2])[0], 1000)

    def test_connection_lost_during_read_raises(self) -> None:
        self.server_end.close()
        with self.assertRaises(WebSocketError):
            self.connection.read_message(timeout=1.0)


class _StubConnection:
    """Connexion factice : suffit à l'API publique utilisée par ``WebSocketClient``."""

    connected = True

    def close(self) -> None:
        self.connected = False


class TestWebSocketClient(unittest.TestCase):
    def _client(self, **kwargs: Any) -> WebSocketClient:
        self.sleeps: list[float] = []
        params: dict[str, Any] = {
            "url": "ws://127.0.0.1:9/api/v1/ws/stream?api_key=ao_x&tenant_id=acme",
            "reconnect": False,
            "sleep": self.sleeps.append,
            "rand": lambda: 0.0,
        }
        params.update(kwargs)
        return WebSocketClient(**params)

    def _with_frames(self, client: WebSocketClient, frames: list[Frame]) -> None:
        client._connection = _StubConnection()  # type: ignore[assignment]
        iterator = iter(frames)

        def next_frame() -> Frame:
            # Le flux de test est fini : on renvoie un heartbeat neutre plutôt que de laisser
            # `StopIteration` remonter dans le générateur (les tests bornent via max_messages).
            return next(iterator, Frame("heartbeat", {}))

        client._next_frame = next_frame  # type: ignore[assignment]

    def test_stream_filters_frames_by_type(self) -> None:
        client = self._client()
        self._with_frames(
            client,
            [
                Frame("heartbeat", {}),
                Frame("event", {"event_id": "e1"}),
                Frame("finding", {"finding_id": "f1"}),
                Frame("audit", {"seq": 1}),
            ],
        )

        received = list(client.stream(types=["finding"], max_messages=1))

        self.assertEqual([frame.type for frame in received], ["finding"])
        self.assertEqual(received[0].data, {"finding_id": "f1"})
        self.assertEqual(received[0]["type"], "finding")

    def test_stream_skips_heartbeats_by_default(self) -> None:
        client = self._client()
        self._with_frames(client, [Frame("heartbeat", {}), Frame("finding", {"finding_id": "f1"})])

        received = list(client.stream(max_messages=1))

        self.assertEqual([frame.type for frame in received], ["finding"])

    def test_stream_can_include_heartbeats(self) -> None:
        client = self._client()
        self._with_frames(client, [Frame("heartbeat", {"ts": "..."})])

        received = list(client.stream(include_heartbeat=True, max_messages=1))

        self.assertEqual([frame.type for frame in received], ["heartbeat"])

    def test_stream_stops_after_max_messages(self) -> None:
        client = self._client()
        self._with_frames(
            client,
            [Frame("finding", {"finding_id": "f1"}), Frame("finding", {"finding_id": "f2"})],
        )

        received = list(client.stream(max_messages=1))

        self.assertEqual(len(received), 1)

    def test_stream_raises_when_reconnect_disabled(self) -> None:
        def failing_factory(address: Any, timeout: float) -> Any:
            raise OSError("connexion refusée")

        client = self._client(socket_factory=failing_factory)

        with self.assertRaises(WebSocketError):
            list(client.stream())

    def test_stream_reconnects_with_backoff_then_gives_up(self) -> None:
        attempts = {"count": 0}

        def failing_factory(address: Any, timeout: float) -> Any:
            attempts["count"] += 1
            raise OSError("connexion refusée")

        client = self._client(
            socket_factory=failing_factory,
            reconnect=True,
            max_reconnect_attempts=2,
            backoff_base=1.0,
        )

        with self.assertRaises(WebSocketError):
            list(client.stream())

        self.assertEqual(attempts["count"], 3)  # tentative initiale + 2 reconnexions
        self.assertEqual(client.reconnect_count, 2)
        # backoff : 1.0*2**0 et 1.0*2**1, jitter 0.5 → 0.5 puis 1.0
        self.assertEqual(self.sleeps, [0.5, 1.0])

    def test_repr_never_exposes_api_key(self) -> None:
        client = self._client()
        self.assertNotIn("ao_x", repr(client))


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
