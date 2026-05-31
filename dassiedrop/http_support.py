import html
import ssl
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config, state, storage


def get_share_base_url() -> str:
    return config.SHARE_BASE_URL.rstrip("/")


def get_app_version() -> str:
    return config.load_app_version()


def build_server(host: str, port: int, use_https: bool = False) -> tuple[ThreadingHTTPServer, str]:
    from .routes import AppHandler

    server = ThreadingHTTPServer((host, port), AppHandler)
    scheme = "http"
    server.is_https = use_https
    if use_https:
        cert_path, key_path = config.ensure_https_certificate()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    return server, scheme


def base_url_from_request(handler: BaseHTTPRequestHandler) -> str:
    configured = get_share_base_url()
    if configured:
        return configured

    forwarded_proto = handler.headers.get("X-Forwarded-Proto", "").strip()
    proto = forwarded_proto or (
        "https" if getattr(handler.server, "server_port", 0) == 443 else "http"
    )
    host = handler.headers.get("Host", "").strip()
    if host:
        return f"{proto}://{host}".rstrip("/")

    server_host, server_port = handler.server.server_address[:2]
    return f"http://{server_host}:{server_port}"


def share_payload(entry_type: str, entry: dict, base_url: str) -> dict:
    path = f"/s/{urllib.parse.quote(entry['short_code'])}"
    workspace_id = entry.get("workspace_id", config.DEFAULT_WORKSPACE_ID)
    workspace_display_name = config.DEFAULT_WORKSPACE_NAME
    workspace_slug_value = storage.workspace_slug(config.DEFAULT_WORKSPACE_NAME)
    with state.state_lock:
        workspace = storage.get_workspace_locked(workspace_id)
        if workspace is not None:
            workspace_display_name = workspace["name"]
            workspace_slug_value = storage.workspace_slug_value(workspace)
    payload = {
        "type": entry_type,
        "id": entry["id"],
        "short_code": entry["short_code"],
        "share_path": path,
        "share_url": f"{base_url.rstrip('/')}{path}",
        "hidden": bool(entry.get("hidden", False)),
        "password_required": bool(entry.get("password_hash")),
        "created_at": entry["created_at"],
        "expires_at": entry["expires_at"],
        "workspace_id": workspace_id,
        "workspace_display_name": workspace_display_name,
        "workspace_slug": workspace_slug_value,
        "workspace_path": f"/w/{urllib.parse.quote(workspace_slug_value)}",
        "workspace_url": f"{base_url.rstrip('/')}/w/{urllib.parse.quote(workspace_slug_value)}",
    }
    if entry_type == "text":
        payload["content"] = entry["content"]
    else:
        payload["name"] = entry["name"]
        payload["size"] = entry["size"]
        payload["download_path"] = f"/download/{urllib.parse.quote(entry['id'])}"
        payload["download_url"] = f"{base_url.rstrip('/')}{payload['download_path']}"
    return payload


def render_template(name: str, replacements: dict[str, str] | None = None) -> str:
    template_path = config.TEMPLATES_DIR / name
    body = template_path.read_text(encoding="utf-8")
    merged_replacements = {
        "__ASSET_VERSION__": urllib.parse.quote(get_app_version(), safe=""),
        "__UPDATE_NOTICE__": "",
    }
    merged_replacements.update(replacements or {})
    for needle, value in merged_replacements.items():
        body = body.replace(needle, value)
    return body


def update_notice_html() -> str:
    with state.state_lock:
        update_state = state.shared_state.get("update_check", {})
        if not update_state.get("update_available"):
            return ""
        latest_version = str(update_state.get("latest_version", "")).strip()
    if latest_version:
        message = f"Update available: v{latest_version}"
    else:
        message = "Update available"
    return f'<p class="footer-line update-available">{html.escape(message)}</p>'
