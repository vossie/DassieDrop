from http import HTTPStatus

from . import auth, config, storage, websocket
from .http_support import base_url_from_request, share_payload

class ContentRoutesMixin:
    def handle_text_update(self) -> None:
        workspace_id = self.require_workspace_context()
        if workspace_id is None:
            return
        entry = self.parse_text_request()
        if entry is None:
            return

        storage.add_text_entry(
            entry["text"],
            hidden=entry["hidden"],
            password=entry["password"],
            sharer_name=entry["name"],
            sharer_ip=self.client_address[0],
            workspace_id=workspace_id,
        )
        snapshot = storage.get_snapshot(workspace_id)
        self.send_json(snapshot)
        websocket.broadcast_snapshot(workspace_id, snapshot)

    def handle_text_share(self) -> None:
        workspace_id = self.require_workspace_context()
        if workspace_id is None:
            return
        entry = self.parse_text_request()
        if entry is None:
            return

        storage.add_text_entry(
            entry["text"],
            hidden=entry["hidden"],
            password=entry["password"],
            sharer_name=entry["name"],
            sharer_ip=self.client_address[0],
            workspace_id=workspace_id,
        )
        created = storage.find_text_entry(storage.get_snapshot(workspace_id)["texts"][0]["id"], workspace_id=workspace_id)
        if created is None:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Could not create text entry")
            return
        snapshot = storage.get_snapshot(workspace_id)
        self.send_json(share_payload("text", created, base_url_from_request(self)))
        websocket.broadcast_snapshot(workspace_id, snapshot)

    def parse_text_request(self) -> dict | None:
        payload = self.parse_json_body()
        if payload is None:
            return None

        text = payload.get("text", "")
        if not isinstance(text, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Text must be a string")
            return None
        normalized_text = text.strip()
        if not normalized_text:
            self.send_error(HTTPStatus.BAD_REQUEST, "Text cannot be empty")
            return None
        hidden = payload.get("hidden", False)
        if not isinstance(hidden, bool):
            self.send_error(HTTPStatus.BAD_REQUEST, "Hidden must be a boolean")
            return None
        password = payload.get("password", "")
        if not isinstance(password, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Password must be a string")
            return None
        sharer_name = payload.get("name", "")
        if not isinstance(sharer_name, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Name must be a string")
            return None

        return {
            "text": normalized_text,
            "hidden": hidden,
            "password": password.strip() if hidden else "",
            "name": sharer_name.strip(),
        }

    def handle_text_reveal(self, entry_id: str) -> None:
        entry = storage.find_text_entry(entry_id)
        if entry is None:
            self.send_error(HTTPStatus.NOT_FOUND, "Text entry not found")
            return

        payload = self.parse_json_body()
        if payload is None:
            return
        password = payload.get("password", "")
        if not isinstance(password, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Password must be a string")
            return
        allowed, retry_after = auth.throttle_status(self, "text-reveal", entry_id)
        if not allowed:
            self.send_throttled("Too many password attempts", retry_after)
            return
        if not storage.entry_password_is_valid(entry, password):
            auth.record_throttle_failure(self, "text-reveal", entry_id)
            self.send_error(HTTPStatus.FORBIDDEN, "Wrong password")
            return

        auth.clear_throttle_failures(self, "text-reveal", entry_id)
        self.send_json({"content": entry["content"]})

    def handle_latest_text(self) -> None:
        workspace_id = self.require_workspace_context()
        if workspace_id is None:
            return
        entry = storage.get_latest_text_entry(workspace_id)
        if entry is None:
            self.send_error(HTTPStatus.NOT_FOUND, "No text entries found")
            return
        self.send_json(entry)

    def handle_latest_file(self) -> None:
        workspace_id = self.require_workspace_context()
        if workspace_id is None:
            return
        entry = storage.get_latest_file_entry(workspace_id)
        if entry is None:
            self.send_error(HTTPStatus.NOT_FOUND, "No file entries found")
            return
        self.send_json(entry)

    def handle_latest_file_content(self) -> None:
        workspace_id = self.require_workspace_context()
        if workspace_id is None:
            return
        latest_entry = storage.get_latest_file_entry(workspace_id)
        if latest_entry is None:
            self.send_error(HTTPStatus.NOT_FOUND, "No file entries found")
            return
        entry = storage.find_file_entry(latest_entry["id"], workspace_id=workspace_id)
        if entry is None:
            self.send_error(HTTPStatus.NOT_FOUND, "No file entries found")
            return
        self.serve_file_entry(entry, as_attachment=True)

    def handle_short_link(self, short_code: str, password: str = "") -> None:
        normalized_code = short_code.strip()
        if not normalized_code:
            self.send_access_denied()
            return
        entry = storage.find_entry_by_short_code(short_code)
        workspace = None
        requires_password = False
        if entry is not None:
            _, payload = entry
            workspace = storage.get_workspace(payload["workspace_id"])
            requires_password = bool(payload.get("password_hash")) or bool(
                workspace and workspace.get("password_hash")
            )
        browser_request = self.is_browser_request()
        if (
            browser_request
            and self.command == "GET"
            and not password
            and entry is not None
            and workspace is not None
            and requires_password
        ):
            self.send_share_access_page(normalized_code)
            return

        allowed, _ = auth.throttle_status(self, "short-link", normalized_code)
        if not allowed:
            self.send_access_denied(browser_request=browser_request and requires_password, short_code=normalized_code)
            return
        if entry is None:
            auth.record_throttle_failure(self, "short-link", normalized_code)
            self.send_access_denied()
            return

        entry_type, payload = entry
        if workspace is None:
            auth.record_throttle_failure(self, "short-link", normalized_code)
            self.send_access_denied()
            return
        if not storage.workspace_user_can_access(workspace, self.current_user_id()):
            auth.record_throttle_failure(self, "short-link", normalized_code)
            self.send_access_denied(browser_request=browser_request, short_code=normalized_code)
            return
        if payload.get("password_hash"):
            if not storage.entry_password_is_valid(payload, password):
                auth.record_throttle_failure(self, "short-link", normalized_code)
                self.send_access_denied(browser_request=browser_request, short_code=normalized_code)
                return
        elif workspace.get("password_hash"):
            if not storage.workspace_password_is_valid(workspace, password):
                auth.record_throttle_failure(self, "short-link", normalized_code)
                self.send_access_denied(browser_request=browser_request, short_code=normalized_code)
                return
        if entry_type == "text":
            auth.clear_throttle_failures(self, "short-link", normalized_code)
            self.send_text(payload["content"])
            return

        auth.clear_throttle_failures(self, "short-link", normalized_code)
        self.serve_file_entry(payload, as_attachment=True)

    def handle_text_delete(self, entry_id: str) -> None:
        workspace_id = self.require_workspace_context()
        if workspace_id is None:
            return
        if not storage.delete_text_entry(entry_id, workspace_id=workspace_id):
            self.send_error(HTTPStatus.NOT_FOUND, "Text entry not found")
            return
        snapshot = storage.get_snapshot(workspace_id)
        self.send_json(snapshot)
        websocket.broadcast_snapshot(workspace_id, snapshot)

    def handle_file_delete(self, file_id: str) -> None:
        workspace_id = self.require_workspace_context()
        if workspace_id is None:
            return
        if not storage.delete_file_entry(file_id, workspace_id=workspace_id):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return
        snapshot = storage.get_snapshot(workspace_id)
        self.send_json(snapshot)
        websocket.broadcast_snapshot(workspace_id, snapshot)
