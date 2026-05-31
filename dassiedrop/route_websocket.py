import struct
from http import HTTPStatus

from . import auth, config, storage, websocket

class WebSocketRoutesMixin:
    def handle_websocket(self) -> None:
        workspace_id = self.require_workspace_context()
        if workspace_id is None:
            return
        session_id, _ = auth.get_session(self)

        upgrade = self.headers.get("Upgrade", "")
        connection = self.headers.get("Connection", "")
        websocket_key = self.headers.get("Sec-WebSocket-Key", "")
        websocket_version = self.headers.get("Sec-WebSocket-Version", "")

        if upgrade.lower() != "websocket" or "upgrade" not in connection.lower():
            self.send_error(HTTPStatus.BAD_REQUEST, "Expected WebSocket upgrade")
            return
        if not websocket_key or websocket_version != "13":
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid WebSocket headers")
            return

        accept_value = websocket.websocket_accept_value(websocket_key)
        self.send_response(HTTPStatus.SWITCHING_PROTOCOLS)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_value)
        self.end_headers()

        client = websocket.WebSocketClient(self.connection, workspace_id, session_id=session_id)
        websocket.register_websocket_client(client)
        client.send_json(storage.get_snapshot(workspace_id))

        try:
            while True:
                opcode, payload = self.read_websocket_frame()
                if opcode is None:
                    break
                if opcode == 0x8:
                    client.send_frame(0x8, payload[:2] if payload else b"")
                    break
                if opcode == 0x9:
                    client.send_frame(0xA, payload)
        finally:
            websocket.unregister_websocket_client(client)

    def read_exact(self, length: int) -> bytes | None:
        remaining = length
        chunks = []
        while remaining > 0:
            try:
                chunk = self.rfile.read(remaining)
            except OSError:
                return None
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def read_websocket_frame(self) -> tuple[int | None, bytes]:
        header = self.read_exact(2)
        if not header:
            return (None, b"")

        first_byte, second_byte = header
        if not (first_byte & 0x80):
            return (0x8, struct.pack("!H", self.websocket_close_protocol_error))
        opcode = first_byte & 0x0F
        masked = bool(second_byte & 0x80)
        if not masked:
            return (0x8, struct.pack("!H", self.websocket_close_protocol_error))
        payload_length = second_byte & 0x7F

        if payload_length == 126:
            extended = self.read_exact(2)
            if extended is None:
                return (None, b"")
            payload_length = int.from_bytes(extended, "big")
        elif payload_length == 127:
            extended = self.read_exact(8)
            if extended is None:
                return (None, b"")
            payload_length = int.from_bytes(extended, "big")

        if payload_length > config.MAX_WEBSOCKET_FRAME_SIZE:
            return (0x8, struct.pack("!H", self.websocket_close_message_too_big))

        masking_key = self.read_exact(4) if masked else b""
        if masked and masking_key is None:
            return (None, b"")

        payload = self.read_exact(payload_length) if payload_length else b""
        if payload is None:
            return (None, b"")

        if masked:
            payload = bytes(
                byte ^ masking_key[index % 4] for index, byte in enumerate(payload)
            )
        return (opcode, payload)
