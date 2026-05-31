import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

from . import auth, storage
from .http_support import render_template
from .route_base import RouteBaseMixin
from .route_content import ContentRoutesMixin
from .route_management import ManagementRoutesMixin
from .route_pages import PageRoutesMixin
from .route_static import StaticRoutesMixin
from .route_uploads import UploadRoutesMixin
from .route_websocket import WebSocketRoutesMixin


class AppHandler(
    RouteBaseMixin,
    PageRoutesMixin,
    ManagementRoutesMixin,
    ContentRoutesMixin,
    UploadRoutesMixin,
    WebSocketRoutesMixin,
    StaticRoutesMixin,
    BaseHTTPRequestHandler,
):
    server_version = "DassieDrop/1.2"
    protocol_version = "HTTP/1.1"
    websocket_close_protocol_error = 1002
    websocket_close_message_too_big = 1009
    content_security_policy = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "connect-src 'self' ws: wss:; "
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    )

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/favicon.ico":
            self.serve_asset("DassieDrop-dassie-icon.png")
            return

        if parsed.path.startswith("/assets/"):
            asset_name = parsed.path.removeprefix("/assets/")
            self.serve_asset(asset_name)
            return

        if parsed.path == "/":
            self.handle_root()
            return

        if parsed.path == "/login":
            if auth.access_code_is_configured() and auth.is_authorized(self):
                self.redirect("/")
                return
            self.send_html(render_template("login.html"))
            return

        if parsed.path == "/logout":
            self.redirect("/login", cookie=auth.logout(self))
            return

        if parsed.path == "/workspaces":
            self.handle_workspaces_page()
            return

        if parsed.path == "/workspaces/access":
            self.handle_workspace_access_page()
            return

        if parsed.path == "/settings":
            self.redirect("/users")
            return

        if parsed.path == "/users":
            self.handle_users_page()
            return

        if parsed.path == "/users/new":
            self.handle_new_user_page()
            return

        if parsed.path == "/users/edit":
            self.handle_edit_user_page()
            return

        if parsed.path == "/help":
            self.handle_help_page()
            return

        if parsed.path == "/openapi.yaml":
            self.serve_openapi_schema()
            return

        if parsed.path.startswith("/w/"):
            workspace_slug_value = urllib.parse.unquote(parsed.path.removeprefix("/w/"))
            self.handle_workspace_shortcut(workspace_slug_value)
            return

        if parsed.path == "/api/workspaces":
            if auth.access_code_is_configured() and not auth.is_authorized(self):
                self.send_error(HTTPStatus.UNAUTHORIZED, "Login required")
                return
            self.send_json(self.workspace_list_payload())
            return

        if parsed.path == "/api/workspaces/access":
            if auth.access_code_is_configured() and not auth.is_authorized(self):
                self.send_error(HTTPStatus.UNAUTHORIZED, "Login required")
                return
            self.handle_workspace_access_payload()
            return

        if parsed.path == "/api/settings":
            self.send_error(HTTPStatus.GONE, "User accounts manage security now")
            return

        if parsed.path == "/api/users":
            if auth.access_code_is_configured() and not auth.is_authorized(self):
                self.send_error(HTTPStatus.UNAUTHORIZED, "Login required")
                return
            self.send_json(self.users_payload())
            return

        if parsed.path.startswith("/s/"):
            short_code = urllib.parse.unquote(parsed.path.removeprefix("/s/"))
            self.handle_short_link(short_code, auth.requested_access_password(self))
            return

        if auth.access_code_is_configured() and not auth.is_authorized(self):
            self.send_error(HTTPStatus.UNAUTHORIZED, "Login required")
            return

        if parsed.path == "/ws":
            self.handle_websocket()
            return

        if parsed.path == "/api/state":
            workspace_id = self.require_workspace_context()
            if workspace_id is None:
                return
            self.send_json(storage.get_snapshot(workspace_id))
            return

        if parsed.path == "/api/latest-text":
            self.handle_latest_text()
            return

        if parsed.path == "/api/latest-file":
            self.handle_latest_file()
            return

        if parsed.path == "/api/latest-file/content":
            self.handle_latest_file_content()
            return

        if parsed.path.startswith("/download/"):
            file_id = urllib.parse.unquote(parsed.path.removeprefix("/download/"))
            self.serve_download(file_id, auth.requested_entry_password(self))
            return

        if parsed.path.startswith("/preview/"):
            file_id = urllib.parse.unquote(parsed.path.removeprefix("/preview/"))
            self.serve_preview(file_id, auth.requested_entry_password(self))
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")
    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/login":
            self.handle_login()
            return
        if parsed.path.startswith("/s/"):
            short_code = urllib.parse.unquote(parsed.path.removeprefix("/s/"))
            password = auth.requested_access_password(self)
            if not password:
                payload = self.read_form_body()
                if payload is None:
                    return
                password = str(payload.get("access_password", "")).strip()
            self.handle_short_link(short_code, password)
            return
        if not auth.validate_csrf(self):
            self.send_error(HTTPStatus.FORBIDDEN, "CSRF token required")
            return

        if auth.access_code_is_configured() and not auth.is_authorized(self):
            self.send_error(HTTPStatus.UNAUTHORIZED, "Login required")
            return

        if parsed.path == "/api/workspaces":
            self.handle_workspace_create()
            return

        if parsed.path.startswith("/api/workspaces/") and parsed.path.endswith("/users"):
            workspace_id = urllib.parse.unquote(
                parsed.path.removeprefix("/api/workspaces/").removesuffix("/users")
            )
            self.handle_workspace_users_update(workspace_id)
            return

        if parsed.path.startswith("/api/workspaces/") and parsed.path.endswith("/password"):
            workspace_id = urllib.parse.unquote(
                parsed.path.removeprefix("/api/workspaces/").removesuffix("/password")
            )
            self.handle_workspace_password_update(workspace_id)
            return

        if parsed.path == "/api/settings":
            self.handle_settings_update()
            return

        if parsed.path == "/api/users":
            if not self.require_root_user():
                return
            self.handle_user_save()
            return

        if parsed.path.startswith("/api/users/"):
            user_id = urllib.parse.unquote(parsed.path.removeprefix("/api/users/"))
            self.handle_user_update(user_id)
            return

        if parsed.path.startswith("/api/workspaces/") and parsed.path.endswith("/enter"):
            workspace_selector = urllib.parse.unquote(
                parsed.path.removeprefix("/api/workspaces/").removesuffix("/enter")
            )
            self.handle_workspace_enter(workspace_selector)
            return

        if parsed.path == "/api/text":
            self.handle_text_update()
            return

        if parsed.path == "/api/share-text":
            self.handle_text_share()
            return

        if parsed.path.startswith("/api/text/") and parsed.path.endswith("/reveal"):
            entry_id = urllib.parse.unquote(
                parsed.path.removeprefix("/api/text/").removesuffix("/reveal")
            )
            self.handle_text_reveal(entry_id)
            return

        if parsed.path == "/api/upload":
            self.handle_file_upload()
            return

        if parsed.path == "/api/share-file":
            self.handle_file_share()
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if not auth.validate_csrf(self):
            self.send_error(HTTPStatus.FORBIDDEN, "CSRF token required")
            return
        if auth.access_code_is_configured() and not auth.is_authorized(self):
            self.send_error(HTTPStatus.UNAUTHORIZED, "Login required")
            return

        if parsed.path.startswith("/api/workspaces/"):
            workspace_id = urllib.parse.unquote(parsed.path.removeprefix("/api/workspaces/"))
            self.handle_workspace_delete(workspace_id)
            return

        if parsed.path.startswith("/api/users/"):
            if not self.require_root_user():
                return
            user_id = urllib.parse.unquote(parsed.path.removeprefix("/api/users/"))
            self.handle_user_delete(user_id)
            return

        if parsed.path.startswith("/api/text/"):
            entry_id = urllib.parse.unquote(parsed.path.removeprefix("/api/text/"))
            self.handle_text_delete(entry_id)
            return

        if parsed.path.startswith("/api/file/"):
            file_id = urllib.parse.unquote(parsed.path.removeprefix("/api/file/"))
            self.handle_file_delete(file_id)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")
