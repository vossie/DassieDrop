import hashlib
import hmac
import json
import math
import mimetypes
import re
import secrets
import shelve
import tempfile
from pathlib import Path

from . import config, state


def ensure_upload_dir() -> None:
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def uploads_index_path() -> Path:
    return config.UPLOAD_DIR / ".dassiedrop-workspaces"


def legacy_uploads_index_path() -> Path:
    return config.UPLOAD_DIR / ".dassiedrop-workspaces.json"


def sanitize_filename(name: str) -> str:
    normalized = name.replace("\\", "/")
    raw_name = Path(normalized).name.strip().replace("\x00", "")
    safe_name = raw_name or "upload.bin"
    return safe_name


def sanitize_workspace_name(name: str) -> str:
    normalized = name.strip().lower()
    normalized = re.sub(r"[^a-z0-9._-]+", "-", normalized)
    normalized = re.sub(r"-{2,}", "-", normalized)
    normalized = re.sub(r"([_.-]){2,}", r"\1", normalized)
    normalized = normalized.strip("._-")
    return normalized[:80] or "workspace"


def compact_workspace_name(name: str) -> str:
    return sanitize_workspace_name(name)[:16]


def workspace_slug(name: str) -> str:
    return sanitize_workspace_name(name)


def workspace_slug_value(workspace: dict) -> str:
    value = workspace.get("slug")
    if isinstance(value, str) and value.strip():
        return value.strip().lower()
    return workspace_slug(str(workspace.get("name") or ""))


def make_unique_workspace_slug_locked(
    name: str,
    exclude_workspace_id: str | None = None,
    workspaces: dict[str, dict] | None = None,
    reserved_slugs: set[str] | None = None,
) -> str:
    base_slug = workspace_slug(name)
    workspace_map = state.shared_state["workspaces"] if workspaces is None else workspaces
    used = {
        workspace_slug_value(workspace)
        for workspace in workspace_map.values()
        if workspace.get("id") != exclude_workspace_id
    }
    used.update(slug for slug in (reserved_slugs or set()) if slug)
    if base_slug not in used:
        return base_slug
    suffix = 2
    while True:
        candidate = f"{base_slug}-{suffix}"
        if candidate not in used:
            return candidate
        suffix += 1


def workspace_name_exists_locked(name: str) -> bool:
    clean_name = sanitize_workspace_name(name)
    return any(
        sanitize_workspace_name(str(workspace.get("name") or "")) == clean_name
        for workspace in state.shared_state["workspaces"].values()
    )


def unique_filename(name: str) -> str:
    candidate = sanitize_filename(name)
    path = config.UPLOAD_DIR / candidate
    if not path.exists():
        return candidate

    stem = Path(candidate).stem
    suffix = Path(candidate).suffix
    return f"{stem}-{secrets.token_hex(4)}{suffix}"


def make_id() -> str:
    return secrets.token_hex(8)


def make_short_code() -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(10))


def make_workspace_id() -> str:
    return secrets.token_hex(6)


PASSWORD_HASH_SCHEME = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 600_000


def hash_password(password: str, iterations: int = PASSWORD_HASH_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{PASSWORD_HASH_SCHEME}${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, password_hash: str | None) -> bool:
    if password_hash is None:
        return True
    if password_hash.startswith(f"{PASSWORD_HASH_SCHEME}$"):
        parts = password_hash.split("$", 3)
        if len(parts) != 4:
            return False
        _, iterations_value, salt_hex, digest_hex = parts
        try:
            iterations = int(iterations_value)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
        except ValueError:
            return False
        if iterations <= 0:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    if ":" not in password_hash:
        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(legacy, password_hash)
    salt_hex, digest_hex = password_hash.split(":", 1)
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return hmac.compare_digest(actual, expected)


def path_within_root(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def upload_path(stored_name: str) -> Path | None:
    target = config.UPLOAD_DIR / stored_name
    if not path_within_root(config.UPLOAD_DIR, target):
        return None
    return target


def make_upload_spool() -> tempfile.NamedTemporaryFile:
    return tempfile.NamedTemporaryFile(prefix="dassiedrop-upload-", suffix=".part", delete=False)


def total_storage_bytes() -> int:
    total = 0
    if not config.UPLOAD_DIR.exists():
        return 0
    for path in config.UPLOAD_DIR.iterdir():
        if path.name.startswith("."):
            continue
        try:
            if path.is_file():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def reset_shared_state_locked(workspaces: dict | None = None) -> None:
    state.shared_state["workspaces"] = {} if workspaces is None else workspaces
    state.shared_state["default_workspace_deleted"] = False
    state.shared_state["reserved_upload_bytes"] = 0
    state.shared_state["reserved_upload_names"] = set()
    state.shared_state["app_settings"] = default_app_settings()
    state.shared_state["users"] = default_users()


def reserve_upload_capacity_locked(size: int) -> bool:
    requested = max(0, int(size))
    reserved = int(state.shared_state.get("reserved_upload_bytes", 0) or 0)
    if (
        config.MAX_TOTAL_STORAGE_BYTES > 0
        and total_storage_bytes() + reserved + requested > config.MAX_TOTAL_STORAGE_BYTES
    ):
        return False
    state.shared_state["reserved_upload_bytes"] = reserved + requested
    return True


def release_reserved_upload_bytes_locked(size: int) -> None:
    reserved = int(state.shared_state.get("reserved_upload_bytes", 0) or 0)
    state.shared_state["reserved_upload_bytes"] = max(0, reserved - max(0, int(size)))


def reserve_upload_target_name_locked(name: str) -> str:
    reserved_names = state.shared_state.setdefault("reserved_upload_names", set())
    candidate = sanitize_filename(name)
    path = config.UPLOAD_DIR / candidate
    if not path.exists() and candidate not in reserved_names:
        reserved_names.add(candidate)
        return candidate

    stem = Path(candidate).stem
    suffix = Path(candidate).suffix
    while True:
        candidate = f"{stem}-{secrets.token_hex(4)}{suffix}"
        path = config.UPLOAD_DIR / candidate
        if not path.exists() and candidate not in reserved_names:
            reserved_names.add(candidate)
            return candidate


def release_upload_target_name_locked(name: str) -> None:
    reserved_names = state.shared_state.get("reserved_upload_names")
    if isinstance(reserved_names, set):
        reserved_names.discard(name)


def build_workspace(
    name: str,
    password_hash: str | None = None,
    expiry_seconds: int | None = None,
    message_expiry_seconds: int | None = None,
    workspace_id: str | None = None,
    slug: str | None = None,
    created_at: float | None = None,
    last_used_at: float | None = None,
    owner_user_id: str | None = None,
    access_mode: str = "public",
    explicit_user_ids: list[str] | None = None,
) -> dict:
    timestamp = config.now_ts() if created_at is None else created_at
    normalized_access_mode = normalize_workspace_access_mode(access_mode, password_hash)
    normalized_expiry_seconds = normalize_expiry_seconds(expiry_seconds)
    return {
        "id": workspace_id or make_workspace_id(),
        "name": sanitize_workspace_name(name),
        "slug": (slug or workspace_slug(name)).strip().lower() or "workspace",
        "password_hash": password_hash,
        "owner_user_id": str(owner_user_id or "").strip(),
        "access_mode": normalized_access_mode,
        "explicit_user_ids": normalize_workspace_user_ids(explicit_user_ids),
        "expiry_seconds": normalized_expiry_seconds,
        "message_expiry_seconds": normalize_message_expiry_seconds(
            message_expiry_seconds,
            normalized_expiry_seconds,
        ),
        "created_at": timestamp,
        "updated_at": 0.0,
        "last_used_at": timestamp if last_used_at is None else last_used_at,
        "texts": [],
        "files": [],
    }


def normalize_workspace_access_mode(mode: object, password_hash: str | None = None) -> str:
    value = str(mode or "").strip().lower()
    if value in {"public", "password", "explicit"}:
        return value
    return "password" if password_hash else "public"


def normalize_workspace_user_ids(user_ids: object) -> list[str]:
    if not isinstance(user_ids, list):
        return []
    normalized = []
    seen = set()
    for user_id in user_ids:
        clean_user_id = str(user_id or "").strip()
        if not clean_user_id or clean_user_id in seen:
            continue
        normalized.append(clean_user_id)
        seen.add(clean_user_id)
    return normalized


def normalize_expiry_seconds(value: object) -> int:
    if value is None or value == "":
        return config.EXPIRY_SECONDS
    try:
        expiry_seconds = int(value)
    except (TypeError, ValueError):
        return config.EXPIRY_SECONDS
    return max(0, expiry_seconds)


def workspace_expiry_seconds(workspace: dict) -> int:
    return normalize_expiry_seconds(workspace.get("expiry_seconds"))


def normalize_message_expiry_seconds(value: object, workspace_expiry_seconds: int) -> int:
    workspace_seconds = normalize_expiry_seconds(workspace_expiry_seconds)
    if value is None or value == "":
        return workspace_seconds
    try:
        message_seconds = int(value)
    except (TypeError, ValueError):
        return workspace_seconds
    message_seconds = max(0, message_seconds)
    if workspace_seconds > 0 and (message_seconds <= 0 or message_seconds > workspace_seconds):
        return workspace_seconds
    return message_seconds


def workspace_message_expiry_seconds(workspace: dict) -> int:
    return normalize_message_expiry_seconds(
        workspace.get("message_expiry_seconds"),
        workspace_expiry_seconds(workspace),
    )


def entry_expires_at(created_at: float, expiry_seconds: int) -> float | None:
    if expiry_seconds <= 0:
        return None
    return created_at + expiry_seconds


def ensure_default_workspace_locked() -> dict:
    workspace = state.shared_state["workspaces"].get(config.DEFAULT_WORKSPACE_ID)
    if workspace is None:
        workspace = build_workspace(
            config.DEFAULT_WORKSPACE_NAME,
            workspace_id=config.DEFAULT_WORKSPACE_ID,
            created_at=0.0,
        )
        state.shared_state["workspaces"][config.DEFAULT_WORKSPACE_ID] = workspace
    state.shared_state["default_workspace_deleted"] = False
    return workspace


def workspace_sort_key(item: dict) -> tuple[int, str]:
    return (0 if item["id"] == config.DEFAULT_WORKSPACE_ID else 1, item["name"].lower())


def list_workspace_objects_locked() -> list[dict]:
    if not state.shared_state.get("default_workspace_deleted"):
        ensure_default_workspace_locked()
    return sorted(state.shared_state["workspaces"].values(), key=workspace_sort_key)


def get_workspace_locked(workspace_id: str) -> dict | None:
    return state.shared_state["workspaces"].get(workspace_id)


def get_workspace_by_slug_locked(slug: str) -> dict | None:
    target = slug.strip().lower()
    if not target:
        return None
    for workspace in list_workspace_objects_locked():
        if workspace_slug_value(workspace) == target:
            return workspace
    return None


def get_workspace(workspace_id: str) -> dict | None:
    with state.state_lock:
        workspace = get_workspace_locked(workspace_id)
        return dict(workspace) if workspace is not None else None


def get_workspace_by_selector(selector: str) -> dict | None:
    with state.state_lock:
        workspace = resolve_workspace_selector_locked(selector)
        return dict(workspace) if workspace is not None else None


def resolve_workspace_selector_locked(selector: str) -> dict | None:
    normalized = selector.strip()
    if not normalized:
        return None
    workspace = get_workspace_locked(normalized)
    if workspace is not None:
        return workspace
    return get_workspace_by_slug_locked(normalized)


def recompute_workspace_updated_at_locked(workspace: dict) -> None:
    timestamps = [item["created_at"] for item in workspace["texts"]]
    timestamps.extend(item["created_at"] for item in workspace["files"])
    workspace["updated_at"] = max(timestamps, default=workspace["created_at"])


def touch_workspace_locked(workspace: dict, persist_interval: float = 60.0) -> bool:
    previous = float(workspace.get("last_used_at") or workspace["created_at"])
    current = config.now_ts()
    workspace["last_used_at"] = current
    return current - previous >= persist_interval


def delete_file_artifacts(entries: list[dict]) -> None:
    for item in entries:
        target = upload_path(item["stored_name"])
        if target is not None and target.exists():
            target.unlink(missing_ok=True)


def trim_workspace_history_locked(workspace: dict, delete_files: bool = True) -> list[dict]:
    overflow_files = []
    if len(workspace["texts"]) > config.MAX_TEXT_HISTORY:
        workspace["texts"] = workspace["texts"][: config.MAX_TEXT_HISTORY]

    if len(workspace["files"]) > config.MAX_FILE_HISTORY:
        overflow_files = workspace["files"][config.MAX_FILE_HISTORY :]
        workspace["files"] = workspace["files"][: config.MAX_FILE_HISTORY]

    if delete_files:
        delete_file_artifacts(overflow_files)

    recompute_workspace_updated_at_locked(workspace)
    return overflow_files


def prune_workspace_locked(workspace: dict) -> bool:
    now = config.now_ts()
    expired_files = [
        item for item in workspace["files"] if item.get("expires_at") is not None and item["expires_at"] < now
    ]
    before_texts = len(workspace["texts"])
    before_files = len(workspace["files"])
    workspace["texts"] = [
        item for item in workspace["texts"] if item.get("expires_at") is None or item["expires_at"] >= now
    ]
    workspace["files"] = [
        item for item in workspace["files"] if item.get("expires_at") is None or item["expires_at"] >= now
    ]
    for item in expired_files:
        target = upload_path(item["stored_name"])
        if target is not None and target.exists():
            target.unlink(missing_ok=True)
    recompute_workspace_updated_at_locked(workspace)
    return before_texts != len(workspace["texts"]) or before_files != len(workspace["files"])


def workspace_is_inactive_locked(workspace: dict) -> bool:
    if workspace["id"] == config.DEFAULT_WORKSPACE_ID:
        return False
    expiry_seconds = workspace_expiry_seconds(workspace)
    if expiry_seconds <= 0:
        return False
    last_used_at = float(
        workspace.get("last_used_at") or workspace["updated_at"] or workspace["created_at"]
    )
    return last_used_at < (config.now_ts() - expiry_seconds)


def workspace_password_is_valid(workspace: dict, password: str) -> bool:
    return verify_password(password, workspace.get("password_hash"))


def privileged_user_password_is_valid_for_user(user_id: str | None, password: str) -> bool:
    clean_user_id = str(user_id or "").strip()
    candidate = password.strip()
    if not clean_user_id or not candidate:
        return False
    with state.state_lock:
        user = get_users_locked().get(clean_user_id)
        if user is None or normalize_user_role(user.get("role")) not in {"root", "admin"}:
            return False
        return secret_matches_hash(candidate, user.get("password_hash"))


def workspace_password_or_user_override_is_valid(
    workspace: dict,
    password: str,
    user_id: str | None = None,
) -> bool:
    candidate = password.strip()
    if not candidate:
        return False
    if workspace_password_is_valid(workspace, candidate):
        return True
    return privileged_user_password_is_valid_for_user(user_id, candidate)


def workspace_access_mode(workspace: dict) -> str:
    return normalize_workspace_access_mode(workspace.get("access_mode"), workspace.get("password_hash"))


def user_is_privileged_locked(user_id: str) -> bool:
    user = get_users_locked().get(str(user_id or "").strip())
    return user is not None and normalize_user_role(user.get("role")) in {"root", "admin"}


def workspace_user_can_access(workspace: dict, user_id: str | None) -> bool:
    if workspace_access_mode(workspace) != "explicit":
        return True
    clean_user_id = str(user_id or "").strip()
    if not clean_user_id:
        return False
    with state.state_lock:
        locked_workspace = get_workspace_locked(workspace["id"]) or workspace
        if user_is_privileged_locked(clean_user_id):
            return True
        if str(locked_workspace.get("owner_user_id") or "").strip() == clean_user_id:
            return True
        return clean_user_id in normalize_workspace_user_ids(locked_workspace.get("explicit_user_ids"))


def workspace_delete_password_is_valid(
    workspace: dict,
    password: str,
    user_id: str | None = None,
) -> bool:
    if workspace.get("password_hash") is None:
        return True
    return workspace_password_or_user_override_is_valid(workspace, password, user_id=user_id)


def workspace_delete_uses_super_password(password: str, user_id: str | None = None) -> bool:
    return privileged_user_password_is_valid_for_user(user_id, password)


def serialize_workspace_summary(workspace: dict) -> dict:
    slug = workspace_slug_value(workspace)
    return {
        "id": workspace["id"],
        "name": workspace["name"],
        "slug": slug,
        "path": f"/w/{slug}",
        "password_required": bool(workspace.get("password_hash")),
        "access_mode": workspace_access_mode(workspace),
        "owner_user_id": str(workspace.get("owner_user_id") or ""),
        "explicit_user_ids": normalize_workspace_user_ids(workspace.get("explicit_user_ids")),
        "expiry_seconds": workspace_expiry_seconds(workspace),
        "message_expiry_seconds": workspace_message_expiry_seconds(workspace),
        "created_at": workspace["created_at"],
        "updated_at": workspace["updated_at"],
        "text_count": len(workspace["texts"]),
        "file_count": len(workspace["files"]),
    }


def serialize_persisted_workspace(workspace: dict) -> dict:
    return {
        "id": workspace["id"],
        "name": workspace["name"],
        "slug": workspace_slug_value(workspace),
        "password_hash": workspace.get("password_hash"),
        "owner_user_id": str(workspace.get("owner_user_id") or ""),
        "access_mode": workspace_access_mode(workspace),
        "explicit_user_ids": normalize_workspace_user_ids(workspace.get("explicit_user_ids")),
        "expiry_seconds": workspace_expiry_seconds(workspace),
        "message_expiry_seconds": workspace_message_expiry_seconds(workspace),
        "created_at": workspace["created_at"],
        "updated_at": workspace["updated_at"],
        "last_used_at": workspace.get("last_used_at", workspace["created_at"]),
        "texts": workspace["texts"],
        "files": workspace["files"],
    }


PERSISTED_PAYLOAD_KEY = "payload"
PERSISTED_SETTINGS_KEY = "settings"
PERSISTED_USERS_KEY = "users"
USER_ROLES = ("root", "admin", "user")


def default_app_settings() -> dict:
    return {
        "access_code_hash": None,
        "api_key_hash": None,
        "workspace_super_password_hash": None,
    }


def normalize_app_settings(settings: object) -> dict:
    normalized = default_app_settings()
    if not isinstance(settings, dict):
        return normalized
    for key in normalized:
        value = settings.get(key)
        normalized[key] = value if isinstance(value, str) and value else None
    return normalized


def get_app_settings_locked() -> dict:
    settings = state.shared_state.get("app_settings")
    if not isinstance(settings, dict):
        settings = default_app_settings()
        state.shared_state["app_settings"] = settings
    return settings


def secret_matches_hash(candidate: str, password_hash: str | None) -> bool:
    return bool(candidate) and bool(password_hash) and verify_password(candidate, password_hash)


def normalize_user_role(role: object) -> str:
    value = str(role or "").strip().lower()
    return value if value in USER_ROLES else "user"


def normalize_username(username: object) -> str:
    value = str(username or "").strip()
    value = re.sub(r"\s+", " ", value)
    return value[:80]


def make_user_id() -> str:
    return secrets.token_hex(8)


def default_users() -> dict:
    return {}


def normalize_users(users: object) -> dict:
    if not isinstance(users, dict):
        return default_users()
    normalized = {}
    seen_usernames = set()

    def restore_ts(value: object) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return config.now_ts()

    for user_id, user in users.items():
        if not isinstance(user, dict):
            continue
        username = normalize_username(user.get("username"))
        username_key = username.lower()
        if not username or username_key in seen_usernames:
            continue
        seen_usernames.add(username_key)
        normalized_id = str(user_id or "").strip() or make_user_id()
        normalized[normalized_id] = {
            "id": normalized_id,
            "username": username,
            "role": normalize_user_role(user.get("role")),
            "password_hash": user.get("password_hash")
            if isinstance(user.get("password_hash"), str)
            else None,
            "api_key_hash": user.get("api_key_hash")
            if isinstance(user.get("api_key_hash"), str)
            else None,
            "created_at": restore_ts(user.get("created_at")),
            "updated_at": restore_ts(user.get("updated_at") or user.get("created_at")),
        }
    return normalized


def get_users_locked() -> dict:
    users = state.shared_state.get("users")
    if not isinstance(users, dict):
        users = default_users()
        state.shared_state["users"] = users
    return users


def serialize_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "username": user["username"],
        "role": normalize_user_role(user.get("role")),
        "password_configured": bool(user.get("password_hash")),
        "api_key_configured": bool(user.get("api_key_hash")),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
    }


def list_users() -> list[dict]:
    with state.state_lock:
        users = list(get_users_locked().values())
        users.sort(key=lambda user: user.get("username", "").lower())
        return [serialize_user(user) for user in users]


def root_user_exists_locked() -> bool:
    return any(normalize_user_role(user.get("role")) == "root" for user in get_users_locked().values())


def root_user_count_locked() -> int:
    return sum(1 for user in get_users_locked().values() if normalize_user_role(user.get("role")) == "root")


def is_last_root_user_locked(user_id: str) -> bool:
    user = get_users_locked().get(user_id)
    return (
        user is not None
        and normalize_user_role(user.get("role")) == "root"
        and root_user_count_locked() <= 1
    )


def ensure_bootstrap_root_user_locked() -> bool:
    if root_user_exists_locked():
        return False
    now = config.now_ts()
    user_id = make_user_id()
    password_hash = hash_password("password")
    get_users_locked()[user_id] = {
        "id": user_id,
        "username": "admin",
        "role": "root",
        "password_hash": password_hash,
        "api_key_hash": password_hash,
        "created_at": now,
        "updated_at": now,
    }
    return True


def find_user_by_username_locked(username: str) -> dict | None:
    username_key = normalize_username(username).lower()
    if not username_key:
        return None
    for user in get_users_locked().values():
        if user.get("username", "").lower() == username_key:
            return user
    return None


def get_user(user_id: str) -> dict | None:
    clean_user_id = str(user_id or "").strip()
    if not clean_user_id:
        return None
    with state.state_lock:
        user = get_users_locked().get(clean_user_id)
        return serialize_user(user) if user is not None else None


def authenticate_user(username: str, password: str) -> dict | None:
    clean_username = normalize_username(username)
    candidate = password.strip()
    if not clean_username or not candidate:
        return None
    with state.state_lock:
        user = find_user_by_username_locked(clean_username)
        if user is None or not secret_matches_hash(candidate, user.get("password_hash")):
            return None
        return serialize_user(user)


def api_key_user(api_key: str) -> dict | None:
    candidate = api_key.strip()
    if not candidate:
        return None
    with state.state_lock:
        for user in get_users_locked().values():
            if secret_matches_hash(candidate, user.get("api_key_hash")):
                return serialize_user(user)
    return None


def set_user(
    username: str,
    password: str | None = None,
    api_key: str | None = None,
    role: str = "user",
) -> dict:
    clean_username = normalize_username(username)
    if not clean_username:
        raise ValueError("Username required")
    clean_role = normalize_user_role(role)
    with state.state_lock:
        users = get_users_locked()
        user = find_user_by_username_locked(clean_username)
        if user is not None:
            raise ValueError("Username already exists")
        now = config.now_ts()
        user_id = make_user_id()
        user = {
            "id": user_id,
            "username": clean_username,
            "role": clean_role,
            "password_hash": None,
            "api_key_hash": None,
            "created_at": now,
            "updated_at": now,
        }
        users[user_id] = user
        user["username"] = clean_username
        user["role"] = clean_role
        if password is not None:
            user["password_hash"] = hash_password(password.strip()) if password.strip() else None
        if api_key is not None:
            user["api_key_hash"] = hash_password(api_key.strip()) if api_key.strip() else None
        user["updated_at"] = now
        persist_state_locked()
        return serialize_user(user)


def update_user(
    user_id: str,
    username: str,
    password: str | None = None,
    api_key: str | None = None,
    role: str = "user",
) -> dict:
    clean_user_id = str(user_id or "").strip()
    clean_username = normalize_username(username)
    if not clean_user_id:
        raise ValueError("User ID required")
    if not clean_username:
        raise ValueError("Username required")
    clean_role = normalize_user_role(role)
    with state.state_lock:
        users = get_users_locked()
        user = users.get(clean_user_id)
        if user is None:
            raise KeyError("User not found")
        duplicate = find_user_by_username_locked(clean_username)
        if duplicate is not None and duplicate.get("id") != clean_user_id:
            raise ValueError("Username already exists")
        if is_last_root_user_locked(clean_user_id) and clean_role != "root":
            raise ValueError("At least one root user is required")
        user["username"] = clean_username
        user["role"] = clean_role
        if password is not None:
            user["password_hash"] = hash_password(password.strip()) if password.strip() else None
        if api_key is not None:
            user["api_key_hash"] = hash_password(api_key.strip()) if api_key.strip() else None
        user["updated_at"] = config.now_ts()
        persist_state_locked()
        return serialize_user(user)


def update_user_secrets(
    user_id: str,
    password: str | None = None,
    api_key: str | None = None,
) -> dict:
    clean_user_id = str(user_id or "").strip()
    if not clean_user_id:
        raise ValueError("User ID required")
    with state.state_lock:
        users = get_users_locked()
        user = users.get(clean_user_id)
        if user is None:
            raise KeyError("User not found")
        if password is not None:
            user["password_hash"] = hash_password(password.strip()) if password.strip() else None
        if api_key is not None:
            user["api_key_hash"] = hash_password(api_key.strip()) if api_key.strip() else None
        user["updated_at"] = config.now_ts()
        persist_state_locked()
        return serialize_user(user)


def delete_user(user_id: str) -> bool:
    clean_user_id = str(user_id or "").strip()
    if not clean_user_id:
        return False
    with state.state_lock:
        users = get_users_locked()
        if clean_user_id not in users:
            return False
        if is_last_root_user_locked(clean_user_id):
            raise ValueError("At least one root user is required")
        users.pop(clean_user_id)
        persist_state_locked()
        return True


def persisted_payload() -> dict:
    return {
        "default_workspace_deleted": bool(state.shared_state.get("default_workspace_deleted")),
        "workspaces": [
            serialize_persisted_workspace(workspace)
            for workspace in list_workspace_objects_locked()
        ]
    }


def shelve_index_exists() -> bool:
    index_path = uploads_index_path()
    candidates = [
        index_path,
        index_path.with_suffix(index_path.suffix + ".db"),
        index_path.with_suffix(index_path.suffix + ".dat"),
        index_path.with_suffix(index_path.suffix + ".dir"),
        index_path.with_suffix(index_path.suffix + ".bak"),
    ]
    return any(path.exists() for path in candidates)


def read_shelved_payload() -> dict:
    if not shelve_index_exists():
        return {}
    try:
        with shelve.open(str(uploads_index_path()), flag="r") as index:
            payload = index.get(PERSISTED_PAYLOAD_KEY, {})
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def read_shelved_settings() -> dict:
    if not shelve_index_exists():
        return default_app_settings()
    try:
        with shelve.open(str(uploads_index_path()), flag="r") as index:
            settings = index.get(PERSISTED_SETTINGS_KEY, {})
    except Exception:
        return default_app_settings()
    return normalize_app_settings(settings)


def read_shelved_users() -> dict:
    if not shelve_index_exists():
        return default_users()
    try:
        with shelve.open(str(uploads_index_path()), flag="r") as index:
            users = index.get(PERSISTED_USERS_KEY, {})
    except Exception:
        return default_users()
    return normalize_users(users)


def read_legacy_json_payload() -> dict:
    index_path = legacy_uploads_index_path()
    if not index_path.exists():
        return {}
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def persist_state_locked() -> None:
    ensure_upload_dir()
    with shelve.open(str(uploads_index_path()), flag="n") as index:
        index[PERSISTED_PAYLOAD_KEY] = persisted_payload()
        index[PERSISTED_SETTINGS_KEY] = normalize_app_settings(get_app_settings_locked())
        index[PERSISTED_USERS_KEY] = normalize_users(get_users_locked())
        index.sync()


def persist_workspaces_locked() -> None:
    persist_state_locked()


def load_persisted_workspaces() -> None:
    ensure_upload_dir()
    loaded_workspaces = {}
    restored_short_codes = set()

    def restore_float(value: object, default: float) -> float:
        try:
            restored = float(value)
        except (TypeError, ValueError):
            return default
        if not math.isfinite(restored):
            return default
        return restored

    def restore_int(value: object, default: int) -> int:
        try:
            restored = int(value)
        except (TypeError, ValueError):
            return default
        if restored < 0:
            return default
        return restored

    def restore_expires_at(value: object, created_at: float, expiry_seconds: int) -> float | None:
        if expiry_seconds <= 0:
            return None
        default_expires_at = created_at + expiry_seconds
        if value is None:
            return default_expires_at
        return min(restore_float(value, default_expires_at), default_expires_at)

    def restore_text_entry(text_item: dict, expiry_seconds: int) -> dict | None:
        content = text_item.get("content")
        if not isinstance(content, str):
            return None
        now = config.now_ts()
        created_at = restore_float(text_item.get("created_at"), now)
        short_code = str(text_item.get("short_code") or "").strip()
        if not short_code or short_code in restored_short_codes:
            while True:
                short_code = make_short_code()
                if short_code not in restored_short_codes:
                    break
        restored_short_codes.add(short_code)
        return {
            "id": str(text_item.get("id") or make_id()),
            "content": content,
            "hidden": bool(text_item.get("hidden", False)),
            "password_hash": text_item.get("password_hash")
            if isinstance(text_item.get("password_hash"), str)
            else None,
            "sharer_name": str(text_item.get("sharer_name") or "").strip(),
            "sharer_ip": str(text_item.get("sharer_ip") or "").strip(),
            "short_code": short_code,
            "created_at": created_at,
            "expires_at": restore_expires_at(text_item.get("expires_at"), created_at, expiry_seconds),
        }

    def restore_file_entry(file_item: dict, expiry_seconds: int) -> dict | None:
        stored_name = file_item.get("stored_name")
        if not isinstance(stored_name, str):
            return None
        target = upload_path(stored_name)
        if target is None or not target.exists() or not target.is_file():
            return None
        now = config.now_ts()
        short_code = str(file_item.get("short_code") or "").strip()
        if not short_code or short_code in restored_short_codes:
            while True:
                short_code = make_short_code()
                if short_code not in restored_short_codes:
                    break
        restored_short_codes.add(short_code)
        created_at = restore_float(file_item.get("created_at"), now)
        return {
            "id": str(file_item.get("id") or make_id()),
            "name": sanitize_filename(str(file_item.get("name") or stored_name)),
            "stored_name": stored_name,
            "size": restore_int(file_item.get("size"), target.stat().st_size),
            "hidden": bool(file_item.get("hidden", False)),
            "password_hash": file_item.get("password_hash")
            if isinstance(file_item.get("password_hash"), str)
            else None,
            "sharer_name": str(file_item.get("sharer_name") or "").strip(),
            "sharer_ip": str(file_item.get("sharer_ip") or "").strip(),
            "short_code": short_code,
            "created_at": created_at,
            "expires_at": restore_expires_at(file_item.get("expires_at"), created_at, expiry_seconds),
        }

    settings = read_shelved_settings()
    users = read_shelved_users()
    payload = read_shelved_payload() or read_legacy_json_payload()
    if payload:
        raw_workspaces = payload.get("workspaces")
        if isinstance(raw_workspaces, list):
            for item in raw_workspaces:
                if not isinstance(item, dict):
                    continue
                workspace_id = str(item.get("id") or make_workspace_id()).strip() or make_workspace_id()
                workspace = build_workspace(
                    str(item.get("name") or config.DEFAULT_WORKSPACE_NAME),
                    password_hash=item.get("password_hash")
                    if isinstance(item.get("password_hash"), str)
                    else None,
                    expiry_seconds=normalize_expiry_seconds(item.get("expiry_seconds")),
                    message_expiry_seconds=item.get("message_expiry_seconds"),
                    workspace_id=workspace_id,
                    slug=str(item.get("slug") or workspace_slug(str(item.get("name") or config.DEFAULT_WORKSPACE_NAME))),
                    created_at=restore_float(item.get("created_at"), config.now_ts()),
                    last_used_at=restore_float(
                        item.get("last_used_at") or item.get("updated_at") or item.get("created_at"),
                        config.now_ts(),
                    ),
                    owner_user_id=str(item.get("owner_user_id") or "").strip(),
                    access_mode=normalize_workspace_access_mode(item.get("access_mode"), item.get("password_hash")),
                    explicit_user_ids=normalize_workspace_user_ids(item.get("explicit_user_ids")),
                )
                raw_texts = item.get("texts", [])
                if not isinstance(raw_texts, list):
                    raw_texts = []
                restored_texts = []
                expiry_seconds = workspace_message_expiry_seconds(workspace)
                for text_item in raw_texts:
                    if not isinstance(text_item, dict):
                        continue
                    restored = restore_text_entry(text_item, expiry_seconds)
                    if restored is not None:
                        restored_texts.append(restored)
                restored_texts.sort(key=lambda entry: entry["created_at"], reverse=True)
                workspace["texts"] = restored_texts
                raw_files = item.get("files", [])
                if not isinstance(raw_files, list):
                    raw_files = []
                restored_files = []
                for file_item in raw_files:
                    if not isinstance(file_item, dict):
                        continue
                    restored = restore_file_entry(file_item, expiry_seconds)
                    if restored is not None:
                        restored_files.append(restored)
                restored_files.sort(key=lambda entry: entry["created_at"], reverse=True)
                workspace["files"] = restored_files
                trim_workspace_history_locked(workspace)
                prune_workspace_locked(workspace)
                workspace["slug"] = make_unique_workspace_slug_locked(
                    workspace["name"],
                    exclude_workspace_id=workspace["id"],
                    workspaces=loaded_workspaces,
                    reserved_slugs=(
                        {workspace_slug(config.DEFAULT_WORKSPACE_NAME)}
                        if workspace["id"] != config.DEFAULT_WORKSPACE_ID
                        else None
                    ),
                )
                loaded_workspaces[workspace["id"]] = workspace
        else:
            raw_files = payload.get("files", [])
            if isinstance(raw_files, list):
                workspace = build_workspace(
                    config.DEFAULT_WORKSPACE_NAME,
                    workspace_id=config.DEFAULT_WORKSPACE_ID,
                    created_at=0.0,
                )
                restored_files = []
                for file_item in raw_files:
                    if not isinstance(file_item, dict):
                        continue
                    restored = restore_file_entry(file_item, workspace_message_expiry_seconds(workspace))
                    if restored is not None:
                        restored_files.append(restored)
                restored_files.sort(key=lambda entry: entry["created_at"], reverse=True)
                workspace["files"] = restored_files
                trim_workspace_history_locked(workspace)
                prune_workspace_locked(workspace)
                loaded_workspaces[workspace["id"]] = workspace

    with state.state_lock:
        reset_shared_state_locked(loaded_workspaces)
        state.shared_state["default_workspace_deleted"] = bool(payload.get("default_workspace_deleted"))
        state.shared_state["app_settings"] = settings
        state.shared_state["users"] = users
        ensure_bootstrap_root_user_locked()
        if not state.shared_state["default_workspace_deleted"]:
            ensure_default_workspace_locked()
        persist_workspaces_locked()


def load_persisted_files() -> None:
    load_persisted_workspaces()


def delete_workspace_artifacts(workspace: dict) -> None:
    from .auth import clear_workspace_selection_for_deleted_workspace
    from .websocket import close_workspace_clients

    for item in workspace["files"]:
        target = upload_path(item["stored_name"])
        if target is not None and target.exists():
            target.unlink(missing_ok=True)
    clear_workspace_selection_for_deleted_workspace(workspace["id"])
    close_workspace_clients(workspace["id"])


def prune_expired_entries() -> list[str]:
    changed_workspace_ids = []
    removed_workspaces = []
    with state.state_lock:
        for workspace in list(state.shared_state["workspaces"].values()):
            pruned = prune_workspace_locked(workspace)
            inactive = workspace_is_inactive_locked(workspace)
            if inactive:
                removed_workspaces.append(state.shared_state["workspaces"].pop(workspace["id"]))
            elif pruned:
                changed_workspace_ids.append(workspace["id"])
        if changed_workspace_ids or removed_workspaces:
            persist_workspaces_locked()
    for workspace in removed_workspaces:
        delete_workspace_artifacts(workspace)
    return changed_workspace_ids


def mask_text_value(value: str) -> str:
    return "*****" if value else ""


def guess_content_type(filename: str) -> str:
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


def serialize_text_entry(entry: dict) -> dict:
    return {
        "id": entry["id"],
        "hidden": entry["hidden"],
        "password_required": bool(entry.get("password_hash")),
        "sharer_name": entry.get("sharer_name", ""),
        "sharer_ip": entry.get("sharer_ip", ""),
        "short_code": entry["short_code"],
        "created_at": entry["created_at"],
        "expires_at": entry["expires_at"],
        "masked_content": mask_text_value(entry["content"]),
        "content": None
        if entry["hidden"] and entry.get("password_hash")
        else entry["content"],
    }


def serialize_file_entry(entry: dict) -> dict:
    return {
        "id": entry["id"],
        "name": entry["name"],
        "content_type": guess_content_type(entry["name"]),
        "size": entry["size"],
        "hidden": entry.get("hidden", False),
        "password_required": bool(entry.get("password_hash")),
        "sharer_name": entry.get("sharer_name", ""),
        "sharer_ip": entry.get("sharer_ip", ""),
        "short_code": entry["short_code"],
        "created_at": entry["created_at"],
        "expires_at": entry["expires_at"],
    }


def serialize_workspace_payload(workspace: dict) -> dict:
    return {
        "workspace": serialize_workspace_summary(workspace),
        "updated_at": workspace["updated_at"],
        "expires_after_seconds": workspace_message_expiry_seconds(workspace),
        "latest_text": ""
        if not workspace["texts"]
        else (
            ""
            if workspace["texts"][0]["hidden"] and workspace["texts"][0].get("password_hash")
            else workspace["texts"][0]["content"]
        ),
        "texts": [serialize_text_entry(item) for item in workspace["texts"]],
        "files": [serialize_file_entry(item) for item in workspace["files"]],
    }


def get_snapshot(workspace_id: str = config.DEFAULT_WORKSPACE_ID) -> dict:
    with state.state_lock:
        workspace = get_workspace_locked(workspace_id)
        if workspace is None:
            workspace = ensure_default_workspace_locked()
        prune_workspace_locked(workspace)
        if touch_workspace_locked(workspace):
            persist_workspaces_locked()
        return serialize_workspace_payload(workspace)


def get_latest_text_entry(workspace_id: str = config.DEFAULT_WORKSPACE_ID) -> dict | None:
    with state.state_lock:
        workspace = get_workspace_locked(workspace_id)
        if workspace is None:
            return None
        prune_workspace_locked(workspace)
        if touch_workspace_locked(workspace):
            persist_workspaces_locked()
        if not workspace["texts"]:
            return None
        return serialize_text_entry(workspace["texts"][0])


def get_latest_file_entry(workspace_id: str = config.DEFAULT_WORKSPACE_ID) -> dict | None:
    with state.state_lock:
        workspace = get_workspace_locked(workspace_id)
        if workspace is None:
            return None
        prune_workspace_locked(workspace)
        if touch_workspace_locked(workspace):
            persist_workspaces_locked()
        if not workspace["files"]:
            return None
        return serialize_file_entry(workspace["files"][0])


def make_unique_short_code_locked() -> str:
    existing = set()
    for workspace in state.shared_state["workspaces"].values():
        existing.update(item["short_code"] for item in workspace["texts"])
        existing.update(item["short_code"] for item in workspace["files"])
    while True:
        candidate = make_short_code()
        if candidate not in existing:
            return candidate


def create_workspace(
    name: str,
    password: str = "",
    expiry_seconds: int | None = None,
    message_expiry_seconds: int | None = None,
    owner_user_id: str | None = None,
    access_mode: str | None = None,
    explicit_user_ids: list[str] | None = None,
) -> dict:
    workspace_name = sanitize_workspace_name(name)
    selected_access_mode = access_mode or ("password" if password.strip() else "public")
    clean_access_mode = normalize_workspace_access_mode(selected_access_mode)
    clean_expiry_seconds = normalize_expiry_seconds(expiry_seconds)
    clean_message_expiry_seconds = normalize_message_expiry_seconds(
        message_expiry_seconds,
        clean_expiry_seconds,
    )
    password_hash = hash_password(password.strip()) if clean_access_mode == "password" and password.strip() else None
    if clean_access_mode == "password" and password_hash is None:
        clean_access_mode = "public"
    with state.state_lock:
        if not state.shared_state.get("default_workspace_deleted"):
            ensure_default_workspace_locked()
        if workspace_name_exists_locked(workspace_name):
            raise ValueError("Workspace name already exists")
        workspace = build_workspace(
            workspace_name,
            slug=make_unique_workspace_slug_locked(workspace_name),
            password_hash=password_hash,
            expiry_seconds=clean_expiry_seconds,
            message_expiry_seconds=clean_message_expiry_seconds,
            owner_user_id=owner_user_id,
            access_mode=clean_access_mode,
            explicit_user_ids=explicit_user_ids,
        )
        state.shared_state["workspaces"][workspace["id"]] = workspace
        persist_workspaces_locked()
        return serialize_workspace_summary(workspace)


def set_workspace_explicit_users(workspace_id: str, user_ids: list[str]) -> dict:
    clean_workspace_id = str(workspace_id or "").strip()
    with state.state_lock:
        workspace = get_workspace_locked(clean_workspace_id)
        if workspace is None:
            raise KeyError("Workspace not found")
        users = get_users_locked()
        clean_user_ids = [
            user_id
            for user_id in normalize_workspace_user_ids(user_ids)
            if user_id in users
        ]
        workspace["explicit_user_ids"] = clean_user_ids
        persist_workspaces_locked()
        return serialize_workspace_summary(workspace)


def set_workspace_password(workspace_id: str, password: str) -> dict:
    clean_workspace_id = str(workspace_id or "").strip()
    clean_password = str(password or "").strip()
    if not clean_password:
        raise ValueError("Workspace password is required")
    with state.state_lock:
        workspace = get_workspace_locked(clean_workspace_id)
        if workspace is None:
            raise KeyError("Workspace not found")
        workspace["password_hash"] = hash_password(clean_password)
        workspace["access_mode"] = "password"
        persist_workspaces_locked()
        return serialize_workspace_summary(workspace)


def list_workspaces() -> list[dict]:
    with state.state_lock:
        removed_workspaces = []
        changed = False
        for workspace in list(state.shared_state["workspaces"].values()):
            if prune_workspace_locked(workspace):
                changed = True
            if workspace_is_inactive_locked(workspace):
                removed_workspaces.append(state.shared_state["workspaces"].pop(workspace["id"]))
                changed = True
        if changed:
            persist_workspaces_locked()
        summaries = [
            serialize_workspace_summary(workspace) for workspace in list_workspace_objects_locked()
        ]
    for workspace in removed_workspaces:
        delete_workspace_artifacts(workspace)
    return summaries


def enter_workspace(
    session_id: str,
    workspace_selector: str,
    password: str = "",
    user_id: str | None = None,
) -> tuple[bool, str]:
    from .auth import set_session_workspace

    workspace = get_workspace_by_selector(workspace_selector)
    if workspace is None:
        return (False, "Workspace not found")
    if not workspace_user_can_access(workspace, user_id):
        return (False, "Workspace access denied")
    if workspace.get("password_hash") and not workspace_delete_password_is_valid(
        workspace,
        password,
        user_id=user_id,
    ):
        return (False, "Wrong workspace password")

    with state.state_lock:
        locked_workspace = get_workspace_locked(workspace["id"])
        if locked_workspace is None:
            return (False, "Workspace not found")
        touch_workspace_locked(locked_workspace, persist_interval=0.0)
        persist_workspaces_locked()
    set_session_workspace(session_id, workspace["id"])
    return (True, "")


def delete_workspace(
    workspace_id: str,
    password: str = "",
    user_id: str | None = None,
) -> tuple[bool, str]:
    workspace = get_workspace(workspace_id)
    if workspace is None:
        return (False, "Workspace not found")
    if not workspace_delete_password_is_valid(workspace, password, user_id=user_id):
        return (False, "Wrong workspace password")

    removed_workspace = None
    with state.state_lock:
        locked_workspace = get_workspace_locked(workspace_id)
        if locked_workspace is None:
            return (False, "Workspace not found")
        removed_workspace = state.shared_state["workspaces"].pop(workspace_id)
        if workspace_id == config.DEFAULT_WORKSPACE_ID:
            state.shared_state["default_workspace_deleted"] = True
        persist_workspaces_locked()

    delete_workspace_artifacts(removed_workspace)
    return (True, "")


def add_text_entry(
    value: str,
    hidden: bool = False,
    password: str = "",
    sharer_name: str = "",
    sharer_ip: str = "",
    workspace_id: str = config.DEFAULT_WORKSPACE_ID,
) -> None:
    password_hash = hash_password(password) if password else None
    with state.state_lock:
        workspace = get_workspace_locked(workspace_id)
        if workspace is None:
            workspace = ensure_default_workspace_locked()
        prune_workspace_locked(workspace)
        expiry_seconds = workspace_message_expiry_seconds(workspace)
        created_at = config.now_ts()
        workspace["texts"].insert(
            0,
            {
                "id": make_id(),
                "content": value,
                "hidden": hidden,
                "password_hash": password_hash,
                "sharer_name": sharer_name.strip(),
                "sharer_ip": sharer_ip.strip(),
                "short_code": make_unique_short_code_locked(),
                "created_at": created_at,
                "expires_at": entry_expires_at(created_at, expiry_seconds),
            },
        )
        trim_workspace_history_locked(workspace)
        touch_workspace_locked(workspace, persist_interval=0.0)
        persist_workspaces_locked()


def delete_text_entry(entry_id: str, workspace_id: str = config.DEFAULT_WORKSPACE_ID) -> bool:
    with state.state_lock:
        workspace = get_workspace_locked(workspace_id)
        if workspace is None:
            return False
        prune_workspace_locked(workspace)
        original_len = len(workspace["texts"])
        workspace["texts"] = [item for item in workspace["texts"] if item["id"] != entry_id]
        recompute_workspace_updated_at_locked(workspace)
        changed = len(workspace["texts"]) != original_len
        if changed:
            touch_workspace_locked(workspace, persist_interval=0.0)
            persist_workspaces_locked()
        return changed


def add_file(
    original_name: str,
    stored_name: str,
    size: int,
    hidden: bool = False,
    password: str = "",
    sharer_name: str = "",
    sharer_ip: str = "",
    workspace_id: str = config.DEFAULT_WORKSPACE_ID,
) -> dict:
    password_hash = hash_password(password) if password else None
    with state.state_lock:
        workspace = get_workspace_locked(workspace_id)
        if workspace is None:
            workspace = ensure_default_workspace_locked()
        prune_workspace_locked(workspace)
        expiry_seconds = workspace_message_expiry_seconds(workspace)
        previous_files = list(workspace["files"])
        previous_updated_at = workspace.get("updated_at", 0.0)
        previous_last_used_at = workspace.get("last_used_at", workspace["created_at"])
        created_at = config.now_ts()
        entry = {
            "id": make_id(),
            "name": original_name,
            "stored_name": stored_name,
            "size": size,
            "hidden": hidden,
            "password_hash": password_hash,
            "sharer_name": sharer_name.strip(),
            "sharer_ip": sharer_ip.strip(),
            "short_code": make_unique_short_code_locked(),
            "created_at": created_at,
            "expires_at": entry_expires_at(created_at, expiry_seconds),
        }
        workspace["files"].insert(0, entry)
        overflow_files = trim_workspace_history_locked(workspace, delete_files=False)
        touch_workspace_locked(workspace, persist_interval=0.0)
        try:
            persist_workspaces_locked()
        except Exception:
            workspace["files"] = previous_files
            workspace["updated_at"] = previous_updated_at
            workspace["last_used_at"] = previous_last_used_at
            raise
        try:
            delete_file_artifacts(overflow_files)
        except OSError:
            # Keep the newly persisted file entry authoritative even if trimming old
            # file artifacts hits a transient filesystem problem.
            pass
        return dict(entry)


def delete_file_entry(file_id: str, workspace_id: str = config.DEFAULT_WORKSPACE_ID) -> bool:
    with state.state_lock:
        workspace = get_workspace_locked(workspace_id)
        if workspace is None:
            return False
        prune_workspace_locked(workspace)
        removed = None
        kept = []
        for item in workspace["files"]:
            if item["id"] == file_id and removed is None:
                removed = item
            else:
                kept.append(item)
        workspace["files"] = kept
        recompute_workspace_updated_at_locked(workspace)
        if removed is not None:
            touch_workspace_locked(workspace, persist_interval=0.0)
            persist_workspaces_locked()

    if removed is None:
        return False

    target = upload_path(removed["stored_name"])
    if target is not None and target.exists():
        target.unlink(missing_ok=True)
    return True


def find_file_entry(file_id: str, workspace_id: str | None = None) -> dict | None:
    with state.state_lock:
        workspaces = (
            [get_workspace_locked(workspace_id)] if workspace_id is not None else list_workspace_objects_locked()
        )
        for workspace in workspaces:
            if workspace is None:
                continue
            prune_workspace_locked(workspace)
            for item in workspace["files"]:
                if item["id"] == file_id:
                    payload = dict(item)
                    payload["workspace_id"] = workspace["id"]
                    return payload
    return None


def find_text_entry(text_id: str, workspace_id: str | None = None) -> dict | None:
    with state.state_lock:
        workspaces = (
            [get_workspace_locked(workspace_id)] if workspace_id is not None else list_workspace_objects_locked()
        )
        for workspace in workspaces:
            if workspace is None:
                continue
            prune_workspace_locked(workspace)
            for item in workspace["texts"]:
                if item["id"] == text_id:
                    payload = dict(item)
                    payload["workspace_id"] = workspace["id"]
                    return payload
    return None


def find_entry_by_short_code(short_code: str) -> tuple[str, dict] | None:
    normalized = short_code.strip()
    with state.state_lock:
        for workspace in list_workspace_objects_locked():
            prune_workspace_locked(workspace)
            for item in workspace["texts"]:
                if item["short_code"] == normalized:
                    payload = dict(item)
                    payload["workspace_id"] = workspace["id"]
                    return ("text", payload)
            for item in workspace["files"]:
                if item["short_code"] == normalized:
                    payload = dict(item)
                    payload["workspace_id"] = workspace["id"]
                    return ("file", payload)
    return None


def entry_password_is_valid(entry: dict, password: str) -> bool:
    return verify_password(password, entry.get("password_hash"))


def json_bytes(payload: dict) -> bytes:
    return json.dumps(payload).encode("utf-8")
