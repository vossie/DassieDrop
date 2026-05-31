import html
import urllib.parse
from http import HTTPStatus

from . import auth, config, state, storage
from .http_support import get_app_version, get_share_base_url, render_template, update_notice_html

class PageRoutesMixin:
    def handle_root(self) -> None:
        if auth.access_code_is_configured() and not auth.is_authorized(self):
            self.send_html(render_template("login.html"))
            return

        session_id, session, cookie = auth.ensure_browser_session(self)
        if session is None or session_id is None:
            self.send_html(render_template("login.html"))
            return

        workspace_id = session.get("workspace_id")
        with state.state_lock:
            workspace = storage.get_workspace_locked(workspace_id) if workspace_id else None
        if workspace is None:
            self.redirect("/workspaces", cookie=cookie)
            return

        can_manage_access = storage.workspace_access_mode(workspace) in {
            "explicit",
            "password",
        } and self.user_can_manage_workspace(workspace)
        self.send_html(
            render_template(
                "index.html",
                {
                    "__SHARE_BASE_URL__": html.escape(get_share_base_url()),
                    "__APP_VERSION__": html.escape(get_app_version()),
                    "__UPDATE_NOTICE__": update_notice_html(),
                    "__WORKSPACE_NAME__": html.escape(storage.compact_workspace_name(workspace["name"])),
                    "__CSRF_TOKEN__": html.escape(auth.csrf_token(session)),
                    "__MANAGE_ACCESS_HEADER_LINK__": (
                        '<a class="header-access-link" href="/workspaces/access" '
                        'aria-label="Manage workspace access" title="Manage Access">'
                        '<img class="header-lock-icon" src="/assets/access-lock.svg" alt="">'
                        "</a>"
                        if can_manage_access
                        else ""
                    ),
                    "__MANAGE_ACCESS_LINK__": (
                        '<a class="tabs-access-link" href="/workspaces/access">Manage Access</a>'
                        if can_manage_access
                        else ""
                    ),
                },
            ),
            cookie=cookie,
        )

    def handle_workspaces_page(self) -> None:
        if auth.access_code_is_configured() and not auth.is_authorized(self):
            self.send_html(render_template("login.html"))
            return

        _, session, cookie = auth.ensure_browser_session(self)
        self.send_html(
            render_template(
                "workspaces.html",
                {
                    "__APP_VERSION__": html.escape(get_app_version()),
                    "__UPDATE_NOTICE__": update_notice_html(),
                    "__CSRF_TOKEN__": html.escape(auth.csrf_token(session)),
                },
            ),
            cookie=cookie,
        )

    def handle_workspace_access_page(self) -> None:
        if auth.access_code_is_configured() and not auth.is_authorized(self):
            self.send_html(render_template("login.html"))
            return

        session_id, session, cookie = auth.ensure_browser_session(self)
        if session is None or session_id is None:
            self.send_html(render_template("login.html"))
            return
        parsed = urllib.parse.urlparse(self.path)
        requested_workspace = urllib.parse.parse_qs(parsed.query).get("workspace", [""])[0]
        if requested_workspace:
            workspace = storage.get_workspace_by_selector(requested_workspace)
            if workspace is None:
                self.send_error(HTTPStatus.NOT_FOUND, "Workspace not found")
                return
        else:
            workspace_id = session.get("workspace_id")
            workspace = storage.get_workspace(str(workspace_id or ""))
        if workspace is None:
            self.redirect("/workspaces", cookie=cookie)
            return
        if storage.workspace_access_mode(workspace) not in {"explicit", "password"}:
            self.redirect("/", cookie=cookie)
            return
        if not self.user_can_manage_workspace(workspace):
            self.send_error(HTTPStatus.FORBIDDEN, "Workspace admin required")
            return
        with state.session_lock:
            active_session = state.authorized_sessions.get(session_id)
            if active_session is not None:
                active_session["access_workspace_id"] = workspace["id"]

        access_mode = storage.workspace_access_mode(workspace)
        self.send_html(
            render_template(
                "workspace_access.html",
                {
                    "__APP_VERSION__": html.escape(get_app_version()),
                    "__UPDATE_NOTICE__": update_notice_html(),
                    "__CSRF_TOKEN__": html.escape(auth.csrf_token(session)),
                    "__WORKSPACE_NAME__": html.escape(storage.compact_workspace_name(workspace["name"])),
                    "__PASSWORD_PANEL_HIDDEN__": "" if access_mode == "password" else "hidden",
                    "__ACCESS_MANAGER_HIDDEN__": "" if access_mode == "explicit" else "hidden",
                },
            ),
            cookie=cookie,
        )

    def handle_help_page(self) -> None:
        if auth.access_code_is_configured() and not auth.is_authorized(self):
            self.send_html(render_template("login.html"))
            return

        _, session, cookie = auth.ensure_browser_session(self)
        self.send_html(
            render_template(
                "help.html",
                {
                    "__APP_VERSION__": html.escape(get_app_version()),
                    "__UPDATE_NOTICE__": update_notice_html(),
                    "__CSRF_TOKEN__": html.escape(auth.csrf_token(session)),
                },
            ),
            cookie=cookie,
        )

    def handle_settings_page(self) -> None:
        self.redirect("/users")

    def handle_users_page(self) -> None:
        if auth.access_code_is_configured() and not auth.is_authorized(self):
            self.send_html(render_template("login.html"))
            return

        _, session, cookie = auth.ensure_browser_session(self)
        self.send_html(
            render_template(
                "users.html",
                {
                    "__APP_VERSION__": html.escape(get_app_version()),
                    "__UPDATE_NOTICE__": update_notice_html(),
                    "__CSRF_TOKEN__": html.escape(auth.csrf_token(session)),
                },
            ),
            cookie=cookie,
        )

    def handle_new_user_page(self) -> None:
        if auth.access_code_is_configured() and not auth.is_authorized(self):
            self.send_html(render_template("login.html"))
            return
        if not self.require_root_user(html_response=True):
            return

        _, session, cookie = auth.ensure_browser_session(self)
        self.send_html(
            render_template(
                "user_new.html",
                {
                    "__APP_VERSION__": html.escape(get_app_version()),
                    "__UPDATE_NOTICE__": update_notice_html(),
                    "__CSRF_TOKEN__": html.escape(auth.csrf_token(session)),
                },
            ),
            cookie=cookie,
        )

    def handle_edit_user_page(self) -> None:
        if auth.access_code_is_configured() and not auth.is_authorized(self):
            self.send_html(render_template("login.html"))
            return
        if not self.user_can_access_edit_user_page():
            return

        _, session, cookie = auth.ensure_browser_session(self)
        self.send_html(
            render_template(
                "user_edit.html",
                {
                    "__APP_VERSION__": html.escape(get_app_version()),
                    "__UPDATE_NOTICE__": update_notice_html(),
                    "__CSRF_TOKEN__": html.escape(auth.csrf_token(session)),
                },
            ),
            cookie=cookie,
        )

    def handle_workspace_shortcut(self, workspace_slug_value: str) -> None:
        if auth.access_code_is_configured() and not auth.is_authorized(self):
            self.send_html(render_template("login.html"))
            return

        session_id, session, cookie = auth.ensure_browser_session(self)
        if session is None or session_id is None:
            self.send_html(render_template("login.html"))
            return

        workspace = storage.get_workspace_by_selector(workspace_slug_value)
        if workspace is None:
            self.send_error(HTTPStatus.NOT_FOUND, "Workspace not found")
            return
        if workspace.get("password_hash"):
            current_workspace_id = session.get("workspace_id")
            password = auth.requested_workspace_password(self)
            allowed, retry_after = auth.throttle_status(self, "workspace-shortcut", workspace["id"])
            if not allowed:
                self.send_throttled("Too many password attempts", retry_after)
                return
            if current_workspace_id != workspace["id"] and not storage.workspace_password_is_valid(
                workspace,
                password.strip(),
            ):
                auth.record_throttle_failure(self, "workspace-shortcut", workspace["id"])
                self.redirect(
                    f"/workspaces?workspace={urllib.parse.quote(workspace_slug_value)}",
                    cookie=cookie,
                )
                return
            auth.clear_throttle_failures(self, "workspace-shortcut", workspace["id"])
        if not storage.workspace_user_can_access(workspace, self.current_user_id()):
            self.redirect(
                f"/workspaces?workspace={urllib.parse.quote(workspace_slug_value)}",
                cookie=cookie,
            )
            return
        with state.state_lock:
            locked_workspace = storage.get_workspace_locked(workspace["id"])
            if locked_workspace is None:
                self.send_error(HTTPStatus.NOT_FOUND, "Workspace not found")
                return
            storage.touch_workspace_locked(locked_workspace, persist_interval=0.0)
            storage.persist_workspaces_locked()

        auth.set_session_workspace(session_id, workspace["id"])
        self.redirect("/", cookie=cookie)
