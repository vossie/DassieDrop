import logging
import urllib.parse
from http import HTTPStatus

from . import auth, config, state, storage


logger = logging.getLogger("dassiedrop.http")


class ManagementRoutesMixin:
    def current_session_workspace_id(self) -> str | None:
        _, session = auth.get_session(self)
        if session is None:
            return None
        workspace_id = session.get("workspace_id")
        if not workspace_id:
            return None
        with state.state_lock:
            if storage.get_workspace_locked(workspace_id) is None:
                return None
        return workspace_id

    def workspace_list_payload(self) -> dict:
        workspaces = [
            workspace
            for workspace in storage.list_workspaces()
            if storage.workspace_user_can_access(workspace, self.current_user_id())
        ]
        return {
            "workspaces": [
                {**workspace, "can_delete": self.user_can_delete_workspace(workspace)}
                for workspace in workspaces
            ],
            "current_workspace_id": self.current_session_workspace_id(),
        }

    def current_user_id(self) -> str:
        current_user = auth.current_user(self)
        return str((current_user or {}).get("id") or "")

    def user_can_manage_workspace(self, workspace: dict) -> bool:
        current_user_id = self.current_user_id()
        if auth.user_has_role(self, {"root", "admin"}):
            return True
        return bool(current_user_id) and str(workspace.get("owner_user_id") or "") == current_user_id

    def user_can_delete_workspace(self, workspace: dict) -> bool:
        if workspace.get("id") == config.DEFAULT_WORKSPACE_ID:
            return auth.user_has_role(self, {"root"})
        if not auth.access_code_is_configured():
            return True
        return self.user_can_manage_workspace(workspace)

    def users_payload(self) -> dict:
        current_user = auth.current_user(self)
        current_user_id = str((current_user or {}).get("id") or "")
        can_manage_users = auth.user_has_role(self, {"root"})
        users = storage.list_users() if can_manage_users else []
        if not can_manage_users and current_user_id:
            user = storage.get_user(current_user_id)
            users = [user] if user is not None else []
        return {
            "users": users,
            "roles": list(storage.USER_ROLES),
            "current_user_id": current_user_id,
            "can_manage_users": can_manage_users,
        }

    def require_root_user(self, html_response: bool = False) -> bool:
        if not auth.user_has_role(self, {"root"}):
            if html_response:
                self.send_error(HTTPStatus.FORBIDDEN, "Root user required")
            else:
                self.send_error(HTTPStatus.FORBIDDEN, "Root user required")
            return False
        return True

    def user_can_access_edit_user_page(self) -> bool:
        if auth.user_has_role(self, {"root"}):
            return True
        parsed = urllib.parse.urlparse(self.path)
        requested_user_id = urllib.parse.parse_qs(parsed.query).get("id", [""])[0]
        current_user = auth.current_user(self)
        if current_user is not None and requested_user_id == current_user.get("id"):
            return True
        self.send_error(HTTPStatus.FORBIDDEN, "User account required")
        return False

    def handle_login(self) -> None:
        allowed, retry_after = auth.throttle_status(self, "login")
        if not allowed:
            self.send_throttled("Too many login attempts", retry_after)
            return
        allowed, retry_after = auth.consume_rate_limit_token(
            self,
            "login-request",
            config.LOGIN_RATE_LIMIT_MAX_REQUESTS,
            config.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        )
        if not allowed:
            self.send_throttled("Too many login requests", retry_after)
            return

        payload = self.read_json_body()
        if payload is None:
            return

        username = payload.get("username", "")
        password = payload.get("password", "")
        totp_code = payload.get("totp_code", "")
        if not isinstance(username, str) or not isinstance(password, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Username and password must be strings")
            return
        if not isinstance(totp_code, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Authenticator code must be a string")
            return
        user = auth.login_user(username, password)
        if user is None:
            auth.record_throttle_failure(self, "login")
            self.send_error(HTTPStatus.UNAUTHORIZED, "Wrong username or password")
            return
        if user.get("totp_enabled") and not storage.user_totp_code_is_valid(user["id"], totp_code):
            auth.record_throttle_failure(self, "login")
            self.send_error(HTTPStatus.UNAUTHORIZED, "Authenticator code required")
            return

        auth.clear_throttle_failures(self, "login")
        session_id = auth.create_authorized_session(
            config.DEFAULT_WORKSPACE_ID,
            user_id=user["id"],
            username=user["username"],
            role=user["role"],
        )
        self.send_json(
            {"ok": True},
            cookie=auth.session_cookie(session_id, secure=bool(getattr(self.server, "is_https", False))),
        )

    def handle_workspace_create(self) -> None:
        payload = self.parse_json_body()
        if payload is None:
            return

        name = payload.get("name", "")
        if not isinstance(name, str) or not name.strip():
            self.send_error(HTTPStatus.BAD_REQUEST, "Workspace name is required")
            return
        password = payload.get("password", "")
        if not isinstance(password, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Password must be a string")
            return
        expiry_seconds = payload.get("expiry_seconds", config.EXPIRY_SECONDS)
        if type(expiry_seconds) is not int or expiry_seconds < 0:
            self.send_error(HTTPStatus.BAD_REQUEST, "Expiry seconds must be a non-negative integer")
            return
        message_expiry_seconds = payload.get("message_expiry_seconds", expiry_seconds)
        if type(message_expiry_seconds) is not int or message_expiry_seconds < 0:
            self.send_error(HTTPStatus.BAD_REQUEST, "Message expiry seconds must be a non-negative integer")
            return
        access_mode = payload.get("access_mode", "password" if password.strip() else "public")
        if not isinstance(access_mode, str) or access_mode not in {"public", "password", "explicit"}:
            self.send_error(HTTPStatus.BAD_REQUEST, "Access mode must be public, password, or explicit")
            return
        explicit_user_ids = payload.get("explicit_user_ids", [])
        if not isinstance(explicit_user_ids, list) or not all(
            isinstance(user_id, str) for user_id in explicit_user_ids
        ):
            self.send_error(HTTPStatus.BAD_REQUEST, "Explicit user IDs must be a list of strings")
            return

        allowed, retry_after = auth.consume_rate_limit_token(
            self,
            "workspace-create",
            config.WORKSPACE_CREATE_RATE_LIMIT_MAX_REQUESTS,
            config.WORKSPACE_CREATE_RATE_LIMIT_WINDOW_SECONDS,
        )
        if not allowed:
            self.send_throttled("Too many workspaces created", retry_after)
            return

        try:
            workspace = storage.create_workspace(
                name,
                password=password.strip(),
                expiry_seconds=expiry_seconds,
                message_expiry_seconds=message_expiry_seconds,
                owner_user_id=self.current_user_id(),
                access_mode=access_mode,
                explicit_user_ids=explicit_user_ids,
            )
        except ValueError as exc:
            self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self.send_json(
            {
                "workspace": workspace,
                **self.workspace_list_payload(),
            }
        )

    def handle_settings_update(self) -> None:
        self.send_error(HTTPStatus.GONE, "User accounts manage security now")

    def handle_user_save(self) -> None:
        payload = self.parse_json_body()
        if payload is None:
            return
        username = payload.get("username", "")
        password = payload.get("password", None)
        api_key = payload.get("api_key", None)
        role = payload.get("role", "user")
        if not isinstance(username, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Username must be a string")
            return
        if password is not None and not isinstance(password, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Password must be a string")
            return
        if api_key is not None and not isinstance(api_key, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "API key must be a string")
            return
        if not isinstance(role, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Role must be a string")
            return
        try:
            user = storage.set_user(username, password=password, api_key=api_key, role=role)
        except ValueError as exc:
            self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self.send_json({"user": user, **self.users_payload()})

    def handle_user_update(self, user_id: str) -> None:
        payload = self.parse_json_body()
        if payload is None:
            return
        if not auth.user_has_role(self, {"root"}):
            current_user = auth.current_user(self)
            if current_user is None or user_id != current_user.get("id"):
                self.send_error(HTTPStatus.FORBIDDEN, "User account required")
                return
            password = payload.get("password", None)
            api_key = payload.get("api_key", None)
            if password is not None and not isinstance(password, str):
                self.send_error(HTTPStatus.BAD_REQUEST, "Password must be a string")
                return
            if api_key is not None and not isinstance(api_key, str):
                self.send_error(HTTPStatus.BAD_REQUEST, "API key must be a string")
                return
            try:
                user = storage.update_user_secrets(user_id, password=password, api_key=api_key)
            except KeyError:
                self.send_error(HTTPStatus.NOT_FOUND, "User not found")
                return
            except ValueError as exc:
                self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
                return
            self.send_json({"user": user, **self.users_payload()})
            return
        username = payload.get("username", "")
        password = payload.get("password", None)
        api_key = payload.get("api_key", None)
        role = payload.get("role", "user")
        if not isinstance(username, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Username must be a string")
            return
        if password is not None and not isinstance(password, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Password must be a string")
            return
        if api_key is not None and not isinstance(api_key, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "API key must be a string")
            return
        if not isinstance(role, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Role must be a string")
            return
        try:
            user = storage.update_user(user_id, username, password=password, api_key=api_key, role=role)
        except KeyError:
            self.send_error(HTTPStatus.NOT_FOUND, "User not found")
            return
        except ValueError as exc:
            self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self.send_json({"user": user, **self.users_payload()})

    def handle_user_delete(self, user_id: str) -> None:
        try:
            deleted = storage.delete_user(user_id)
        except ValueError as exc:
            self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        if not deleted:
            self.send_error(HTTPStatus.NOT_FOUND, "User not found")
            return
        self.send_json({"ok": True, **self.users_payload()})

    def user_can_manage_totp(self, user_id: str, allow_root: bool = True) -> bool:
        current_user = auth.current_user(self)
        if current_user is None:
            return False
        if user_id == current_user.get("id"):
            return True
        return allow_root and auth.user_has_role(self, {"root"})

    def handle_user_totp_setup(self, user_id: str) -> None:
        if not self.user_can_manage_totp(user_id, allow_root=False):
            self.send_error(HTTPStatus.FORBIDDEN, "User account required")
            return
        try:
            payload = storage.begin_user_totp_setup(user_id)
        except KeyError:
            self.send_error(HTTPStatus.NOT_FOUND, "User not found")
            return
        except ValueError as exc:
            self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self.send_json(payload)

    def handle_user_totp_confirm(self, user_id: str) -> None:
        if not self.user_can_manage_totp(user_id, allow_root=False):
            self.send_error(HTTPStatus.FORBIDDEN, "User account required")
            return
        payload = self.parse_json_body()
        if payload is None:
            return
        code = payload.get("code", "")
        if not isinstance(code, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Authenticator code must be a string")
            return
        try:
            user = storage.confirm_user_totp_setup(user_id, code)
        except KeyError:
            self.send_error(HTTPStatus.NOT_FOUND, "User not found")
            return
        except ValueError as exc:
            self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self.send_json({"user": user, **self.users_payload()})

    def handle_user_totp_disable(self, user_id: str) -> None:
        if not self.user_can_manage_totp(user_id, allow_root=True):
            self.send_error(HTTPStatus.FORBIDDEN, "User account required")
            return
        try:
            user = storage.disable_user_totp(user_id)
        except KeyError:
            self.send_error(HTTPStatus.NOT_FOUND, "User not found")
            return
        except ValueError as exc:
            self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        self.send_json({"user": user, **self.users_payload()})

    def handle_workspace_enter(self, workspace_selector: str) -> None:
        session_id, session = auth.get_session(self)
        if session_id is None or session is None:
            self.send_error(HTTPStatus.UNAUTHORIZED, "Session required")
            return
        payload = self.parse_json_body()
        if payload is None:
            return
        password = payload.get("password", "")
        if not isinstance(password, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Password must be a string")
            return
        allowed, retry_after = auth.throttle_status(self, "workspace-enter", workspace_selector)
        if not allowed:
            self.send_throttled("Too many workspace password attempts", retry_after)
            return
        ok, message = storage.enter_workspace(
            session_id,
            workspace_selector,
            password=password,
            user_id=self.current_user_id(),
        )
        if not ok:
            status = HTTPStatus.NOT_FOUND if message == "Workspace not found" else HTTPStatus.FORBIDDEN
            if status == HTTPStatus.FORBIDDEN:
                auth.record_throttle_failure(self, "workspace-enter", workspace_selector)
            self.send_error(status, message)
            return
        auth.clear_throttle_failures(self, "workspace-enter", workspace_selector)
        resolved_workspace = storage.get_workspace(self.current_session_workspace_id() or "")
        self.send_json(
            {
                "ok": True,
                "workspace": storage.serialize_workspace_summary(resolved_workspace)
                if resolved_workspace is not None
                else None,
            }
        )

    def handle_workspace_users_update(self, workspace_id: str) -> None:
        payload = self.parse_json_body()
        if payload is None:
            return
        workspace = storage.get_workspace(workspace_id)
        if workspace is None:
            self.send_error(HTTPStatus.NOT_FOUND, "Workspace not found")
            return
        if not self.user_can_manage_workspace(workspace):
            self.send_error(HTTPStatus.FORBIDDEN, "Workspace admin required")
            return
        user_ids = payload.get("user_ids", [])
        if not isinstance(user_ids, list):
            self.send_error(HTTPStatus.BAD_REQUEST, "User IDs must be a list")
            return
        try:
            workspace = storage.set_workspace_explicit_users(workspace_id, user_ids)
        except KeyError:
            self.send_error(HTTPStatus.NOT_FOUND, "Workspace not found")
            return
        self.send_json({"workspace": workspace, **self.workspace_list_payload()})

    def handle_workspace_password_update(self, workspace_id: str) -> None:
        payload = self.parse_json_body()
        if payload is None:
            return
        workspace = storage.get_workspace(workspace_id)
        if workspace is None:
            self.send_error(HTTPStatus.NOT_FOUND, "Workspace not found")
            return
        if storage.workspace_access_mode(workspace) != "password":
            self.send_error(HTTPStatus.BAD_REQUEST, "Workspace is not password protected")
            return
        if not self.user_can_manage_workspace(workspace):
            self.send_error(HTTPStatus.FORBIDDEN, "Workspace admin required")
            return
        password = payload.get("password", "")
        if not isinstance(password, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Password must be a string")
            return
        try:
            workspace = storage.set_workspace_password(workspace_id, password)
        except ValueError as exc:
            self.send_error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        except KeyError:
            self.send_error(HTTPStatus.NOT_FOUND, "Workspace not found")
            return
        self.send_json({"workspace": workspace, **self.workspace_list_payload()})

    def handle_workspace_access_payload(self) -> None:
        workspace_id = self.current_session_workspace_id()
        workspace = storage.get_workspace(str(workspace_id or ""))
        if workspace is None:
            self.send_error(HTTPStatus.CONFLICT, "Workspace not selected")
            return
        if storage.workspace_access_mode(workspace) not in {"explicit", "password"}:
            self.send_error(HTTPStatus.BAD_REQUEST, "Workspace access cannot be managed")
            return
        if not self.user_can_manage_workspace(workspace):
            self.send_error(HTTPStatus.FORBIDDEN, "Workspace admin required")
            return
        users = [
            {
                "id": str(user.get("id") or ""),
                "username": str(user.get("username") or ""),
                "role": str(user.get("role") or ""),
            }
            for user in storage.list_users()
        ]
        self.send_json(
            {
                "workspace": storage.serialize_workspace_summary(workspace),
                "users": users,
                "current_user_id": self.current_user_id(),
            }
        )

    def handle_workspace_delete(self, workspace_id: str) -> None:
        payload = self.parse_json_body()
        if payload is None:
            return
        password = payload.get("password", "")
        if not isinstance(password, str):
            self.send_error(HTTPStatus.BAD_REQUEST, "Password must be a string")
            return
        allowed, retry_after = auth.throttle_status(self, "workspace-delete", workspace_id)
        if not allowed:
            self.send_throttled("Too many workspace password attempts", retry_after)
            return
        workspace = storage.get_workspace(workspace_id)
        if workspace is not None and not self.user_can_delete_workspace(workspace):
            self.send_error(HTTPStatus.FORBIDDEN, "Workspace admin required")
            return
        if (
            workspace is not None
            and storage.workspace_access_mode(workspace) == "explicit"
            and not self.user_can_manage_workspace(workspace)
        ):
            self.send_error(HTTPStatus.FORBIDDEN, "Workspace admin required")
            return
        current_user_id = self.current_user_id()
        ok, message = storage.delete_workspace(workspace_id, password=password, user_id=current_user_id)
        if not ok:
            status = HTTPStatus.NOT_FOUND if message == "Workspace not found" else HTTPStatus.FORBIDDEN
            if status == HTTPStatus.FORBIDDEN:
                auth.record_throttle_failure(self, "workspace-delete", workspace_id)
            self.send_error(status, message)
            return
        if workspace is not None and storage.workspace_delete_uses_super_password(password, current_user_id):
            logger.warning(
                "Workspace deleted with privileged user password: workspace_id=%s workspace_name=%s client_ip=%s",
                workspace_id,
                workspace.get("name", ""),
                self.client_address[0],
            )
        auth.clear_throttle_failures(self, "workspace-delete", workspace_id)
        self.send_json(self.workspace_list_payload())

    def require_workspace_context(self) -> str | None:
        explicit_workspace_selector = auth.requested_workspace_selector(self)
        if explicit_workspace_selector:
            workspace = storage.get_workspace_by_selector(explicit_workspace_selector)
            if workspace is None:
                self.send_error(HTTPStatus.NOT_FOUND, "Workspace not found")
                return None
            if not storage.workspace_user_can_access(workspace, self.current_user_id()):
                self.send_error(HTTPStatus.FORBIDDEN, "Workspace access denied")
                return None
            allowed, retry_after = auth.throttle_status(self, "workspace-context", workspace["id"])
            if not allowed:
                self.send_throttled("Too many workspace password attempts", retry_after)
                return None
            if workspace.get("password_hash") and not storage.workspace_password_or_user_override_is_valid(
                workspace,
                auth.requested_workspace_password(self),
                user_id=self.current_user_id(),
            ):
                auth.record_throttle_failure(self, "workspace-context", workspace["id"])
                self.send_error(HTTPStatus.FORBIDDEN, "Wrong workspace password")
                return None
            auth.clear_throttle_failures(self, "workspace-context", workspace["id"])
            return workspace["id"]

        session_id, session = auth.get_session(self)
        if session_id is not None and session is not None:
            workspace_id = session.get("workspace_id")
            if not workspace_id:
                self.send_error(HTTPStatus.CONFLICT, "Workspace not selected")
                return None
            with state.state_lock:
                workspace = storage.get_workspace_locked(workspace_id)
            if workspace is None:
                auth.set_session_workspace(session_id, None)
                self.send_error(HTTPStatus.CONFLICT, "Workspace not selected")
                return None
            if not storage.workspace_user_can_access(workspace, self.current_user_id()):
                auth.set_session_workspace(session_id, None)
                self.send_error(HTTPStatus.FORBIDDEN, "Workspace access denied")
                return None
            return workspace_id

        if auth.access_code_is_configured():
            if auth.api_key_is_valid(self):
                return config.DEFAULT_WORKSPACE_ID
            self.send_error(HTTPStatus.UNAUTHORIZED, "Login required")
            return None

        return config.DEFAULT_WORKSPACE_ID
