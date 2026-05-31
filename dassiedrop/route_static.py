import shutil
import urllib.parse
from http import HTTPStatus

from . import auth, config, storage

class StaticRoutesMixin:
    def serve_download(self, file_id: str, password: str = "") -> None:
        entry = storage.find_file_entry(file_id)
        if entry is None:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return
        workspace = storage.get_workspace(entry.get("workspace_id", config.DEFAULT_WORKSPACE_ID))
        if workspace is None:
            self.send_error(HTTPStatus.NOT_FOUND, "Workspace not found")
            return
        if not storage.workspace_user_can_access(workspace, self.current_user_id()):
            self.send_error(HTTPStatus.FORBIDDEN, "Workspace access denied")
            return
        allowed, retry_after = auth.throttle_status(self, "file-download", file_id)
        if not allowed:
            self.send_throttled("Too many password attempts", retry_after)
            return
        current_workspace_id = self.current_session_workspace_id()
        workspace_password = auth.requested_workspace_password(self)
        if (
            workspace.get("password_hash")
            and current_workspace_id != workspace["id"]
            and not storage.workspace_password_is_valid(
                workspace,
                workspace_password.strip(),
            )
        ):
            auth.record_throttle_failure(self, "file-download", file_id)
            self.send_error(HTTPStatus.FORBIDDEN, "Wrong workspace password")
            return
        if entry.get("password_hash") and not storage.entry_password_is_valid(entry, password):
            auth.record_throttle_failure(self, "file-download", file_id)
            self.send_error(HTTPStatus.FORBIDDEN, "Wrong password")
            return
        auth.clear_throttle_failures(self, "file-download", file_id)
        self.serve_file_entry(entry, as_attachment=True)

    def serve_preview(self, file_id: str, password: str = "") -> None:
        entry = storage.find_file_entry(file_id)
        if entry is None:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return
        workspace = storage.get_workspace(entry.get("workspace_id", config.DEFAULT_WORKSPACE_ID))
        if workspace is None:
            self.send_error(HTTPStatus.NOT_FOUND, "Workspace not found")
            return
        if not storage.workspace_user_can_access(workspace, self.current_user_id()):
            self.send_error(HTTPStatus.FORBIDDEN, "Workspace access denied")
            return
        allowed, retry_after = auth.throttle_status(self, "file-preview", file_id)
        if not allowed:
            self.send_throttled("Too many password attempts", retry_after)
            return
        current_workspace_id = self.current_session_workspace_id()
        workspace_password = auth.requested_workspace_password(self)
        if (
            workspace.get("password_hash")
            and current_workspace_id != workspace["id"]
            and not storage.workspace_password_is_valid(
                workspace,
                workspace_password.strip(),
            )
        ):
            auth.record_throttle_failure(self, "file-preview", file_id)
            self.send_error(HTTPStatus.FORBIDDEN, "Wrong workspace password")
            return
        if entry.get("password_hash") and not storage.entry_password_is_valid(entry, password):
            auth.record_throttle_failure(self, "file-preview", file_id)
            self.send_error(HTTPStatus.FORBIDDEN, "Wrong password")
            return
        auth.clear_throttle_failures(self, "file-preview", file_id)
        self.serve_file_entry(entry, as_attachment=False)

    def serve_file_entry(self, entry: dict, as_attachment: bool) -> None:
        target = storage.upload_path(entry["stored_name"])
        if target is None or not target.exists() or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        content_type = storage.guess_content_type(entry["name"])
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_common_security_headers()
        disposition = "attachment" if as_attachment else "inline"
        self.send_header(
            "Content-Disposition",
            f"{disposition}; filename*=UTF-8''{urllib.parse.quote(entry['name'])}",
        )
        self.send_header("Content-Length", str(target.stat().st_size))
        self.end_headers()
        with target.open("rb") as handle:
            shutil.copyfileobj(handle, self.wfile)

    def serve_asset(self, asset_name: str) -> None:
        safe_name = urllib.parse.unquote(asset_name)
        safe_name = safe_name.split("/")[-1]
        target = config.ASSETS_DIR / safe_name
        if (
            not storage.path_within_root(config.ASSETS_DIR, target)
            or not target.exists()
            or not target.is_file()
        ):
            self.send_error(HTTPStatus.NOT_FOUND, "Asset not found")
            return

        content_type = storage.guess_content_type(target.name)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_common_security_headers()
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Length", str(target.stat().st_size))
        self.end_headers()
        with target.open("rb") as handle:
            shutil.copyfileobj(handle, self.wfile)

    def serve_openapi_schema(self) -> None:
        package_root = (config.BASE_DIR / "dassiedrop").resolve()
        target = (package_root / "openapi.yaml").resolve()
        if not storage.path_within_root(package_root, target) or not target.exists() or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "Schema not found")
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/yaml; charset=utf-8")
        self.send_common_security_headers()
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Disposition", 'attachment; filename="openapi.yaml"')
        self.send_header("Content-Length", str(target.stat().st_size))
        self.end_headers()
        with target.open("rb") as handle:
            shutil.copyfileobj(handle, self.wfile)
