import shutil
from http import HTTPStatus
from pathlib import Path

from . import auth, config, state, storage, websocket
from .http_support import base_url_from_request, share_payload

class UploadRoutesMixin:
    def handle_file_upload(self) -> None:
        workspace_id = self.require_workspace_context()
        if workspace_id is None:
            return
        allowed, retry_after = auth.consume_rate_limit_token(
            self,
            "file-upload",
            config.UPLOAD_RATE_LIMIT_MAX_REQUESTS,
            config.UPLOAD_RATE_LIMIT_WINDOW_SECONDS,
        )
        if not allowed:
            self.send_throttled("Too many uploads", retry_after)
            return
        parsed = self.parse_file_upload_request()
        if parsed is None:
            return

        created = self.store_file_upload(parsed, workspace_id)
        if created is None:
            return
        snapshot = storage.get_snapshot(workspace_id)
        self.send_json(snapshot)
        websocket.broadcast_snapshot(workspace_id, snapshot)

    def handle_file_share(self) -> None:
        workspace_id = self.require_workspace_context()
        if workspace_id is None:
            return
        allowed, retry_after = auth.consume_rate_limit_token(
            self,
            "file-upload",
            config.UPLOAD_RATE_LIMIT_MAX_REQUESTS,
            config.UPLOAD_RATE_LIMIT_WINDOW_SECONDS,
        )
        if not allowed:
            self.send_throttled("Too many uploads", retry_after)
            return
        parsed = self.parse_file_upload_request()
        if parsed is None:
            return

        created = self.store_file_upload(parsed, workspace_id)
        if created is None:
            return
        snapshot = storage.get_snapshot(workspace_id)
        self.send_json(share_payload("file", created, base_url_from_request(self)))
        websocket.broadcast_snapshot(workspace_id, snapshot)

    def parse_file_upload_request(self) -> dict | None:
        content_type = self.headers.get("Content-Type", "")
        boundary = None
        for item in content_type.split(";"):
            item = item.strip()
            if item.startswith("boundary="):
                boundary = item.split("=", 1)[1].encode("utf-8")
                break

        if not boundary:
            self.send_error(HTTPStatus.BAD_REQUEST, "Missing multipart boundary")
            return None

        length = self.parse_content_length()
        if length is None:
            return None
        if length <= 0:
            self.send_error(HTTPStatus.BAD_REQUEST, "Empty upload")
            return None
        if length > config.MAX_FILE_SIZE:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "File too large")
            return None

        filename, temp_path, file_size, fields = self.parse_multipart_file_stream(length, boundary)
        if filename is None or temp_path is None:
            self.send_error(HTTPStatus.BAD_REQUEST, "Could not read uploaded file")
            return None
        hidden = fields.get("hidden", "false").lower() == "true"
        password = fields.get("password", "").strip()
        sharer_name = fields.get("name", "").strip()
        if hidden and not password:
            Path(temp_path).unlink(missing_ok=True)
            self.send_error(HTTPStatus.BAD_REQUEST, "Hidden files require a password")
            return None

        return {
            "filename": filename,
            "temp_path": temp_path,
            "file_size": file_size,
            "hidden": hidden,
            "password": password,
            "name": sharer_name,
        }

    def store_file_upload(self, parsed: dict, workspace_id: str) -> dict | None:
        storage.ensure_upload_dir()
        file_size = int(parsed["file_size"])
        with state.state_lock:
            if not storage.reserve_upload_capacity_locked(file_size):
                Path(parsed["temp_path"]).unlink(missing_ok=True)
                self.send_error(HTTPStatus.INSUFFICIENT_STORAGE, "Storage quota exceeded")
                return None
            stored_name = storage.reserve_upload_target_name_locked(parsed["filename"])
            target = storage.upload_path(stored_name)
            if target is None:
                storage.release_reserved_upload_bytes_locked(file_size)
                storage.release_upload_target_name_locked(stored_name)
                Path(parsed["temp_path"]).unlink(missing_ok=True)
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Could not store uploaded file")
                return None
        _failed = False
        try:
            shutil.move(parsed["temp_path"], target)
            created = storage.add_file(
                parsed["filename"],
                stored_name,
                file_size,
                hidden=parsed["hidden"],
                password=parsed["password"],
                sharer_name=parsed["name"],
                sharer_ip=self.client_address[0],
                workspace_id=workspace_id,
            )
            created["workspace_id"] = workspace_id
            return created
        except Exception:
            _failed = True
            if target.exists():
                target.unlink(missing_ok=True)
            return None
        finally:
            with state.state_lock:
                storage.release_reserved_upload_bytes_locked(file_size)
                storage.release_upload_target_name_locked(stored_name)
            if _failed:
                self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Could not store uploaded file")

    def parse_multipart_file_stream(self, length: int, boundary: bytes):
        marker = b"--" + boundary
        fields: dict[str, str] = {}
        temp_path = None
        file_size = 0
        upload_name = None
        remaining = length

        def read_line() -> bytes | None:
            nonlocal remaining
            if remaining <= 0:
                return b""
            try:
                line = self.rfile.readline(remaining)
            except OSError:
                return None
            if not line:
                return None
            remaining -= len(line)
            return line

        line = read_line()
        if line is None or line.rstrip(b"\r\n") != marker:
            return (None, None, 0, {})

        while True:
            header_lines = []
            while True:
                line = read_line()
                if line is None:
                    if temp_path:
                        Path(temp_path).unlink(missing_ok=True)
                    return (None, None, 0, {})
                if line in (b"\r\n", b"\n", b""):
                    break
                header_lines.append(line.decode("utf-8", errors="ignore").strip())

            field_name = None
            filename = None
            for line in header_lines:
                if line.lower().startswith("content-disposition:"):
                    for piece in line.split(";"):
                        piece = piece.strip()
                        if piece.startswith("name="):
                            field_name = piece.split("=", 1)[1].strip("\"")
                        elif piece.startswith("filename="):
                            filename = piece.split("=", 1)[1].strip("\"")

            if not field_name:
                if temp_path:
                    Path(temp_path).unlink(missing_ok=True)
                return (None, None, 0, {})

            payload_file = None
            payload_chunks = []
            if field_name == "file":
                spool = storage.make_upload_spool()
                temp_path = spool.name
                payload_file = spool
                upload_name = storage.sanitize_filename(filename or "upload.bin")

            previous_line = None
            boundary_line = None
            while True:
                line = read_line()
                if line is None:
                    if payload_file is not None:
                        payload_file.close()
                    if temp_path:
                        Path(temp_path).unlink(missing_ok=True)
                    return (None, None, 0, {})
                stripped = line.rstrip(b"\r\n")
                if stripped == marker or stripped == marker + b"--":
                    boundary_line = stripped
                    if previous_line is not None:
                        final_chunk = previous_line[:-2] if previous_line.endswith(b"\r\n") else previous_line
                        if payload_file is not None:
                            payload_file.write(final_chunk)
                            file_size += len(final_chunk)
                        else:
                            payload_chunks.append(final_chunk)
                    break
                if previous_line is not None:
                    if payload_file is not None:
                        payload_file.write(previous_line)
                        file_size += len(previous_line)
                    else:
                        payload_chunks.append(previous_line)
                previous_line = line

            if payload_file is not None:
                payload_file.close()
            else:
                fields[field_name] = b"".join(payload_chunks).decode("utf-8", errors="ignore")

            if boundary_line == marker + b"--":
                break

        return (upload_name, temp_path, file_size, fields)
