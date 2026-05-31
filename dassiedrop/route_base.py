import html
import json
import logging
import urllib.parse
from http import HTTPStatus

from . import config, storage
from .http_support import render_template


logger = logging.getLogger("dassiedrop.http")

class RouteBaseMixin:
    def send_common_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        if getattr(self.server, "is_https", False):
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    def send_throttled(self, message: str, retry_after: int) -> None:
        data = message.encode("utf-8")
        self.send_response(HTTPStatus.TOO_MANY_REQUESTS)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_common_security_headers()
        self.send_header("Retry-After", str(retry_after))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_json_body(self) -> dict | None:
        length = self.parse_content_length()
        if length is None:
            return None
        if length > config.MAX_JSON_BODY_SIZE:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "JSON body too large")
            return None
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid JSON")
            return None
        if not isinstance(payload, dict):
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid JSON")
            return None
        return payload

    def read_form_body(self) -> dict[str, str] | None:
        length = self.parse_content_length()
        if length is None:
            return None
        if length > config.MAX_JSON_BODY_SIZE:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Form body too large")
            return None
        body = self.rfile.read(length) if length > 0 else b""
        try:
            parsed = urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True)
        except UnicodeDecodeError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid form body")
            return None
        return {key: values[0] if values else "" for key, values in parsed.items()}

    def is_browser_request(self) -> bool:
        accept = self.headers.get("Accept", "")
        return "text/html" in accept.lower()

    def parse_json_body(self) -> dict | None:
        return self.read_json_body()

    def parse_content_length(self) -> int | None:
        raw_value = self.headers.get("Content-Length", "0").strip()
        try:
            length = int(raw_value or "0")
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
            return None
        if length < 0:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
            return None
        return length

    def send_html(self, body: str, cookie: str | None = None, status: HTTPStatus = HTTPStatus.OK) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_common_security_headers()
        self.send_header("Content-Security-Policy", self.content_security_policy)
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, payload: dict, cookie: str | None = None) -> None:
        data = storage.json_bytes(payload)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_common_security_headers()
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_common_security_headers()
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_access_denied(
        self,
        browser_request: bool = False,
        short_code: str = "",
    ) -> None:
        if browser_request and short_code:
            self.send_share_access_page(short_code, error_message="Access denied", status=HTTPStatus.UNAUTHORIZED)
            return
        data = storage.json_bytes({"message": "Access denied"})
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_common_security_headers()
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_share_access_page(
        self,
        short_code: str,
        error_message: str = "",
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        self.send_html(
            render_template(
                "share-access.html",
                {
                    "__SHORT_CODE__": html.escape(short_code),
                    "__ERROR_TEXT__": html.escape(error_message),
                },
            ),
            status=status,
        )

    def redirect(self, location: str, cookie: str | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_common_security_headers()
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_error(self, code, message=None, explain=None) -> None:
        short, long = self.responses.get(code, ("Unknown", "Unknown"))
        message = message or short
        explain = explain or long
        body = f"{int(code)} {message}\n{explain}\n"
        data = body.encode("utf-8", errors="replace")
        self.send_response(code, message)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_common_security_headers()
        self.send_header("Content-Security-Policy", self.content_security_policy)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        message = fmt % args
        logger.info("%s %s", self.log_date_time_string(), html.escape(message))
