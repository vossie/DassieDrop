import base64
import http.client
import json
import logging
import os
import socket
import struct
import subprocess
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import app
from dassiedrop import config, state, storage
from dassiedrop.http_support import render_template

REPO_ROOT = Path(__file__).resolve().parents[1]


def reset_app_state() -> None:
    with state.state_lock:
        state.shared_state["workspaces"] = {}
        state.shared_state["default_workspace_deleted"] = False
        state.shared_state["reserved_upload_bytes"] = 0
        state.shared_state["reserved_upload_names"] = set()
        state.shared_state["app_settings"] = {
            "access_code_hash": None,
            "api_key_hash": None,
            "workspace_super_password_hash": None,
        }
        state.shared_state["users"] = {}
        state.shared_state["update_check"] = {
            "checking": False,
            "last_checked_at": 0.0,
            "latest_version": "",
            "update_available": False,
        }
    with state.session_lock:
        state.authorized_sessions.clear()
    with state.auth_attempt_lock:
        state.auth_attempts.clear()
        state.rate_limit_events.clear()
    app.stop_background_tasks()


class AppStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.original_upload_dir = config.UPLOAD_DIR
        self.original_share_base_url = config.SHARE_BASE_URL
        self.original_now_ts = config.now_ts
        self.original_version_file = config.VERSION_FILE
        self.original_update_check_enabled = config.UPDATE_CHECK_ENABLED
        self.original_update_check_url = config.UPDATE_CHECK_URL
        self.original_update_check_interval_seconds = config.UPDATE_CHECK_INTERVAL_SECONDS
        config.UPLOAD_DIR = Path(self.temp_dir.name) / "uploads"
        config.SHARE_BASE_URL = ""
        config.UPDATE_CHECK_ENABLED = False
        config.UPDATE_CHECK_URL = "https://example.invalid/VERSION"
        config.UPDATE_CHECK_INTERVAL_SECONDS = 24 * 60 * 60
        config.now_ts = self.fake_now
        config.VERSION_FILE = Path(self.temp_dir.name) / "VERSION"
        config.VERSION_FILE.write_text("9.9.9", encoding="utf-8")
        self.current_time = 1_700_000_000.0
        app.ensure_upload_dir()
        reset_app_state()

    def tearDown(self) -> None:
        reset_app_state()
        config.UPLOAD_DIR = self.original_upload_dir
        config.SHARE_BASE_URL = self.original_share_base_url
        config.UPDATE_CHECK_ENABLED = self.original_update_check_enabled
        config.UPDATE_CHECK_URL = self.original_update_check_url
        config.UPDATE_CHECK_INTERVAL_SECONDS = self.original_update_check_interval_seconds
        config.now_ts = self.original_now_ts
        config.VERSION_FILE = self.original_version_file
        self.temp_dir.cleanup()

    def fake_now(self) -> float:
        return self.current_time

    def test_snapshot_contains_latest_text_and_file_history(self) -> None:
        app.add_text_entry("first", sharer_name="Alice", sharer_ip="192.168.1.10")
        self.current_time += 5
        app.add_text_entry("second", sharer_name="Bob", sharer_ip="192.168.1.11")
        app.add_file(
            "hello.txt",
            "stored-hello.txt",
            12,
            sharer_name="Bob",
            sharer_ip="192.168.1.11",
        )

        snapshot = app.get_snapshot()

        self.assertEqual(snapshot["latest_text"], "second")
        self.assertEqual(len(snapshot["texts"]), 2)
        self.assertEqual(snapshot["texts"][0]["content"], "second")
        self.assertEqual(snapshot["texts"][0]["sharer_name"], "Bob")
        self.assertEqual(snapshot["texts"][0]["sharer_ip"], "192.168.1.11")
        self.assertEqual(len(snapshot["texts"][0]["short_code"]), 10)
        self.assertEqual(len(snapshot["files"]), 1)
        self.assertEqual(snapshot["files"][0]["name"], "hello.txt")
        self.assertEqual(snapshot["files"][0]["content_type"], "text/plain")
        self.assertEqual(snapshot["files"][0]["sharer_name"], "Bob")
        self.assertEqual(snapshot["files"][0]["sharer_ip"], "192.168.1.11")
        self.assertEqual(len(snapshot["files"][0]["short_code"]), 10)
        self.assertEqual(snapshot["expires_after_seconds"], app.EXPIRY_SECONDS)

    def test_app_version_comes_from_version_file_or_env(self) -> None:
        self.assertEqual(app.get_app_version(), "9.9.9")
        original_value = os.environ.get("APP_VERSION")
        os.environ["APP_VERSION"] = "2.3.4"
        try:
            self.assertEqual(app.get_app_version(), "2.3.4")
        finally:
            if original_value is None:
                os.environ.pop("APP_VERSION", None)
            else:
                os.environ["APP_VERSION"] = original_value

    def test_rendered_templates_cache_bust_static_assets_with_app_version(self) -> None:
        rendered = render_template("login.html")

        self.assertIn('/assets/login.css?v=9.9.9', rendered)
        self.assertIn('/assets/password-toggle.js?v=9.9.9', rendered)
        self.assertIn('/assets/login.js?v=9.9.9', rendered)
        self.assertNotIn("__ASSET_VERSION__", rendered)

    def test_update_check_marks_newer_remote_version_available(self) -> None:
        config.UPDATE_CHECK_ENABLED = True
        original_fetch = config.fetch_remote_app_version
        try:
            config.fetch_remote_app_version = lambda *args, **kwargs: "9.9.10"
            self.assertTrue(app.check_for_updates(force=True))
        finally:
            config.fetch_remote_app_version = original_fetch

        update_state = app.get_update_check_state()
        self.assertTrue(update_state["update_available"])
        self.assertEqual(update_state["latest_version"], "9.9.10")
        self.assertEqual(update_state["last_checked_at"], self.current_time)

    def test_compact_workspace_name_limits_header_label_to_16_characters(self) -> None:
        self.assertEqual(app.compact_workspace_name("1234567890abcdefXYZ"), "1234567890abcdef")
        self.assertEqual(app.compact_workspace_name("  Demo Workspace  "), "demo-workspace")

    def test_workspace_slug_normalizes_name_for_direct_urls(self) -> None:
        self.assertEqual(app.workspace_slug("Carel Workspace"), "carel-workspace")
        self.assertEqual(app.workspace_slug("  Prod / EU West  "), "prod-eu-west")

    def test_filename_sanitisation_strips_paths_and_nulls(self) -> None:
        self.assertEqual(app.sanitize_filename("../unsafe.txt"), "unsafe.txt")
        self.assertEqual(app.sanitize_filename("..\\unsafe.txt"), "unsafe.txt")
        self.assertEqual(app.sanitize_filename("bad\x00name.txt"), "badname.txt")
        self.assertEqual(app.sanitize_filename(""), "upload.bin")

    def test_workspace_selector_can_resolve_workspace_slug(self) -> None:
        workspace = app.create_workspace("Ops Desk")

        with state.state_lock:
            resolved = app.resolve_workspace_selector_locked("ops-desk")

        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["id"], workspace["id"])

    def test_workspace_creation_rejects_duplicate_normalized_names(self) -> None:
        first = app.create_workspace("Ops Desk")

        with self.assertRaisesRegex(ValueError, "Workspace name already exists"):
            app.create_workspace("Ops-Desk")

        with state.state_lock:
            resolved_first = app.resolve_workspace_selector_locked("ops-desk")
        self.assertEqual(resolved_first["id"], first["id"])

    def test_text_entries_can_be_marked_hidden(self) -> None:
        app.add_text_entry("secret", hidden=True)

        snapshot = app.get_snapshot()

        self.assertTrue(snapshot["texts"][0]["hidden"])
        self.assertEqual(snapshot["latest_text"], "secret")

    def test_password_protected_text_is_masked_in_snapshot(self) -> None:
        app.add_text_entry("secret value", hidden=True, password="open-sesame")

        snapshot = app.get_snapshot()

        self.assertEqual(snapshot["latest_text"], "")
        self.assertTrue(snapshot["texts"][0]["hidden"])
        self.assertTrue(snapshot["texts"][0]["password_required"])
        self.assertIsNone(snapshot["texts"][0]["content"])
        self.assertEqual(snapshot["texts"][0]["masked_content"], "*****")

    def test_text_snapshot_contains_plain_text_only(self) -> None:
        app.add_text_entry("Hello world", sharer_name="Alice")

        snapshot = app.get_snapshot()

        self.assertEqual(snapshot["texts"][0]["content"], "Hello world")
        self.assertEqual(snapshot["texts"][0]["sharer_name"], "Alice")
        self.assertNotIn("rich", snapshot["texts"][0])
        self.assertNotIn("content_html", snapshot["texts"][0])

    def test_delete_file_entry_removes_file_from_disk(self) -> None:
        target = config.UPLOAD_DIR / "stored.txt"
        target.write_text("payload", encoding="utf-8")
        app.add_file("original.txt", "stored.txt", target.stat().st_size)
        file_id = app.get_snapshot()["files"][0]["id"]

        deleted = app.delete_file_entry(file_id)

        self.assertTrue(deleted)
        self.assertFalse(target.exists())
        self.assertEqual(app.get_snapshot()["files"], [])

    def test_expired_entries_are_removed_and_expired_files_deleted(self) -> None:
        expired_file = config.UPLOAD_DIR / "old.txt"
        expired_file.write_text("old", encoding="utf-8")
        app.add_text_entry("old text")
        app.add_file("old.txt", "old.txt", expired_file.stat().st_size)
        self.current_time += app.EXPIRY_SECONDS + 1

        snapshot = app.get_snapshot()

        self.assertEqual(snapshot["texts"], [])
        self.assertEqual(snapshot["files"], [])
        self.assertFalse(expired_file.exists())

    def test_expiry_cleanup_reports_changed_workspace_ids(self) -> None:
        target = config.UPLOAD_DIR / "cleanup.txt"
        target.write_text("payload", encoding="utf-8")
        app.add_text_entry("drop")
        app.add_file("cleanup.txt", "cleanup.txt", target.stat().st_size)

        self.current_time += app.EXPIRY_SECONDS + 1
        changed_workspace_ids = app.prune_expired_entries()

        self.assertIn(app.DEFAULT_WORKSPACE_ID, changed_workspace_ids)
        snapshot = app.get_snapshot()
        self.assertEqual(snapshot["texts"], [])
        self.assertEqual(snapshot["files"], [])
        self.assertFalse(target.exists())

    def test_workspace_creation_sets_password_requirement(self) -> None:
        workspace = app.create_workspace("Private Ops", password="vault")
        listed = app.list_workspaces()

        created = next(item for item in listed if item["id"] == workspace["id"])
        self.assertEqual(created["slug"], "private-ops")
        self.assertTrue(created["password_required"])
        self.assertEqual(created["expiry_seconds"], app.EXPIRY_SECONDS)

    def test_explicit_workspace_access_allows_owner_privileged_and_selected_users(self) -> None:
        owner = storage.set_user("Owner", password="owner-pass", api_key="owner-api", role="user")
        allowed_user = storage.set_user("Allowed", password="allowed-pass", api_key="allowed-api", role="user")
        blocked_user = storage.set_user("Blocked", password="blocked-pass", api_key="blocked-api", role="user")
        admin = storage.set_user("Admin", password="admin-pass", api_key="admin-api", role="admin")
        workspace = app.create_workspace(
            "Invite Only",
            owner_user_id=owner["id"],
            access_mode="explicit",
        )

        self.assertEqual(workspace["access_mode"], "explicit")
        self.assertEqual(workspace["owner_user_id"], owner["id"])
        self.assertFalse(workspace["password_required"])

        owner_session = app.create_authorized_session()
        ok, message = app.enter_workspace(owner_session, workspace["id"], user_id=owner["id"])
        self.assertTrue(ok)
        self.assertEqual(message, "")

        blocked_session = app.create_authorized_session()
        ok, message = app.enter_workspace(blocked_session, workspace["id"], user_id=blocked_user["id"])
        self.assertFalse(ok)
        self.assertEqual(message, "Workspace access denied")

        storage.set_workspace_explicit_users(workspace["id"], [allowed_user["id"]])
        allowed_session = app.create_authorized_session()
        ok, message = app.enter_workspace(allowed_session, workspace["id"], user_id=allowed_user["id"])
        self.assertTrue(ok)
        self.assertEqual(message, "")

        admin_session = app.create_authorized_session()
        ok, message = app.enter_workspace(admin_session, workspace["id"], user_id=admin["id"])
        self.assertTrue(ok)
        self.assertEqual(message, "")

    def test_workspace_custom_expiry_controls_entry_expiry(self) -> None:
        workspace = app.create_workspace("Short Lived", expiry_seconds=60)

        app.add_text_entry("brief", workspace_id=workspace["id"])

        snapshot = app.get_snapshot(workspace["id"])
        self.assertEqual(snapshot["expires_after_seconds"], 60)
        self.assertEqual(snapshot["texts"][0]["expires_at"], self.current_time + 60)

        self.current_time += 61
        self.assertEqual(app.get_snapshot(workspace["id"])["texts"], [])

    def test_workspace_message_expiry_can_be_shorter_than_workspace_expiry(self) -> None:
        workspace = app.create_workspace(
            "Long Room Short Messages",
            expiry_seconds=3600,
            message_expiry_seconds=60,
        )

        app.add_text_entry("brief text", workspace_id=workspace["id"])
        target = config.UPLOAD_DIR / "brief.txt"
        target.write_text("brief file", encoding="utf-8")
        app.add_file("brief.txt", "brief.txt", target.stat().st_size, workspace_id=workspace["id"])

        snapshot = app.get_snapshot(workspace["id"])
        self.assertEqual(snapshot["workspace"]["expiry_seconds"], 3600)
        self.assertEqual(snapshot["workspace"]["message_expiry_seconds"], 60)
        self.assertEqual(snapshot["expires_after_seconds"], 60)
        self.assertEqual(snapshot["texts"][0]["expires_at"], self.current_time + 60)
        self.assertEqual(snapshot["files"][0]["expires_at"], self.current_time + 60)

        self.current_time += 61
        listed = app.list_workspaces()
        snapshot = app.get_snapshot(workspace["id"])
        self.assertIn(workspace["id"], {item["id"] for item in listed})
        self.assertEqual(snapshot["texts"], [])
        self.assertEqual(snapshot["files"], [])

    def test_workspace_message_expiry_is_capped_to_workspace_expiry(self) -> None:
        longer = app.create_workspace(
            "Too Long",
            expiry_seconds=60,
            message_expiry_seconds=3600,
        )
        infinite = app.create_workspace(
            "Never Too Long",
            expiry_seconds=60,
            message_expiry_seconds=0,
        )

        self.assertEqual(longer["message_expiry_seconds"], 60)
        self.assertEqual(infinite["message_expiry_seconds"], 60)

    def test_workspace_infinite_expiry_keeps_entries_and_workspace(self) -> None:
        workspace = app.create_workspace("Permanent", expiry_seconds=0)

        app.add_text_entry("kept", workspace_id=workspace["id"])
        self.current_time += app.EXPIRY_SECONDS * 10

        listed = app.list_workspaces()
        snapshot = app.get_snapshot(workspace["id"])
        self.assertIn(workspace["id"], {item["id"] for item in listed})
        self.assertEqual(snapshot["expires_after_seconds"], 0)
        self.assertIsNone(snapshot["texts"][0]["expires_at"])

    def test_inactive_non_default_workspace_is_deleted_after_24_hours(self) -> None:
        workspace = app.create_workspace("Old Workspace")

        self.current_time += app.EXPIRY_SECONDS + 1

        listed = app.list_workspaces()

        self.assertNotIn(workspace["id"], {item["id"] for item in listed})

    def test_workspace_snapshot_access_keeps_workspace_active(self) -> None:
        workspace = app.create_workspace("Active Workspace")

        self.current_time += app.EXPIRY_SECONDS - 10
        app.get_snapshot(workspace["id"])
        self.current_time += 20

        listed = app.list_workspaces()

        self.assertIn(workspace["id"], {item["id"] for item in listed})

    def test_default_workspace_is_listed_first_and_others_follow_alphabetically(self) -> None:
        zebra = app.create_workspace("Zebra")
        alpha = app.create_workspace("Alpha")
        middle = app.create_workspace("Middle")

        listed = app.list_workspaces()

        self.assertEqual(listed[0]["id"], app.DEFAULT_WORKSPACE_ID)
        self.assertEqual(
            [item["id"] for item in listed[1:]],
            [alpha["id"], middle["id"], zebra["id"]],
        )

    def test_text_history_is_capped_at_200_newest_entries(self) -> None:
        for index in range(app.MAX_TEXT_HISTORY + 5):
            app.add_text_entry(f"text-{index}")
            self.current_time += 1

        snapshot = app.get_snapshot()

        self.assertEqual(len(snapshot["texts"]), app.MAX_TEXT_HISTORY)
        self.assertEqual(snapshot["texts"][0]["content"], "text-204")
        self.assertEqual(snapshot["texts"][-1]["content"], "text-5")

    def test_file_history_is_capped_at_100_and_oldest_files_are_deleted(self) -> None:
        oldest_target = None
        newest_target = None

        for index in range(app.MAX_FILE_HISTORY + 3):
            stored_name = f"stored-{index}.txt"
            target = config.UPLOAD_DIR / stored_name
            target.write_text(f"payload-{index}", encoding="utf-8")
            app.add_file(f"original-{index}.txt", stored_name, target.stat().st_size)
            if index == 0:
                oldest_target = target
            if index == app.MAX_FILE_HISTORY + 2:
                newest_target = target
            self.current_time += 1

        snapshot = app.get_snapshot()

        self.assertEqual(len(snapshot["files"]), app.MAX_FILE_HISTORY)
        self.assertEqual(snapshot["files"][0]["name"], "original-102.txt")
        self.assertEqual(snapshot["files"][-1]["name"], "original-3.txt")
        self.assertIsNotNone(oldest_target)
        self.assertFalse(oldest_target.exists())
        self.assertIsNotNone(newest_target)
        self.assertTrue(newest_target.exists())

    def test_file_metadata_is_persisted_and_reloaded_after_restart(self) -> None:
        target = config.UPLOAD_DIR / "persisted.txt"
        target.write_text("payload", encoding="utf-8")

        app.add_file(
            "persisted.txt",
            "persisted.txt",
            target.stat().st_size,
            hidden=True,
            password="vault",
            sharer_name="Laptop",
            sharer_ip="192.168.1.9",
        )
        original_snapshot = app.get_snapshot()
        original_entry = original_snapshot["files"][0]

        with state.state_lock:
            state.shared_state["workspaces"] = {}
            state.shared_state["reserved_upload_bytes"] = 0
            state.shared_state["reserved_upload_names"] = set()

        app.load_persisted_files()

        reloaded_snapshot = app.get_snapshot()
        reloaded_entry = reloaded_snapshot["files"][0]
        self.assertEqual(len(reloaded_snapshot["files"]), 1)
        self.assertEqual(reloaded_entry["id"], original_entry["id"])
        self.assertEqual(reloaded_entry["name"], "persisted.txt")
        self.assertTrue(reloaded_entry["hidden"])
        self.assertTrue(reloaded_entry["password_required"])
        self.assertEqual(reloaded_entry["sharer_name"], "Laptop")
        self.assertEqual(reloaded_entry["sharer_ip"], "192.168.1.9")
        self.assertEqual(reloaded_entry["short_code"], original_entry["short_code"])

    def test_reload_skips_missing_files_and_cleans_index(self) -> None:
        target = config.UPLOAD_DIR / "gone.txt"
        target.write_text("payload", encoding="utf-8")
        app.add_file("gone.txt", "gone.txt", target.stat().st_size)
        target.unlink()

        with state.state_lock:
            state.shared_state["workspaces"] = {}
            state.shared_state["reserved_upload_bytes"] = 0
            state.shared_state["reserved_upload_names"] = set()

        app.load_persisted_files()

        self.assertEqual(app.get_snapshot()["files"], [])
        index_payload = app.read_shelved_payload()
        self.assertEqual(index_payload["workspaces"][0]["files"], [])

    def test_can_create_enter_and_delete_workspace_with_super_password(self) -> None:
        workspace = app.create_workspace("Secure", password="vault")
        session_id = app.create_authorized_session()

        ok, message = app.enter_workspace(session_id, workspace["id"], password="wrong")
        self.assertFalse(ok)
        self.assertEqual(message, "Wrong workspace password")

        ok, message = app.enter_workspace(session_id, workspace["id"], password="vault")
        self.assertTrue(ok)
        self.assertEqual(message, "")

        admin = storage.set_user("Admin", password="override", api_key="override-api", role="admin")
        deleted, delete_message = app.delete_workspace(
            workspace["id"],
            password="override",
            user_id=admin["id"],
        )
        self.assertTrue(deleted)
        self.assertEqual(delete_message, "")
        self.assertNotIn(workspace["id"], {item["id"] for item in app.list_workspaces()})

    def test_can_enter_workspace_with_admin_user_password(self) -> None:
        workspace = app.create_workspace("Secure", password="vault")
        session_id = app.create_authorized_session()
        admin = storage.set_user("Admin", password="override", api_key="override-api", role="admin")

        ok, message = app.enter_workspace(
            session_id,
            workspace["id"],
            password="override",
            user_id=admin["id"],
        )

        self.assertTrue(ok)
        self.assertEqual(message, "")

    def test_can_enter_workspace_with_root_user_password(self) -> None:
        workspace = app.create_workspace("Secure", password="vault")
        session_id = app.create_authorized_session()
        root = storage.set_user("Root", password="stored-override", api_key="root-api", role="root")

        ok, message = app.enter_workspace(
            session_id,
            workspace["id"],
            password="stored-override",
            user_id=root["id"],
        )

        self.assertTrue(ok)
        self.assertEqual(message, "")

    def test_can_delete_workspace_with_root_user_password(self) -> None:
        workspace = app.create_workspace("Secure", password="vault")
        root = storage.set_user("Root", password="stored-override", api_key="root-api", role="root")

        deleted, delete_message = app.delete_workspace(
            workspace["id"],
            password="stored-override",
            user_id=root["id"],
        )

        self.assertTrue(deleted)
        self.assertEqual(delete_message, "")
        self.assertNotIn(workspace["id"], {item["id"] for item in app.list_workspaces()})

    def test_privileged_workspace_override_requires_matching_user(self) -> None:
        workspace = app.create_workspace("Secure", password="vault")
        session_id = app.create_authorized_session()
        root = storage.set_user("Root", password="stored-override", api_key="root-api", role="root")
        user = storage.set_user("Alice", password="alice-pass", api_key="alice-api", role="user")

        ok, message = app.enter_workspace(
            session_id,
            workspace["id"],
            password="stored-override",
            user_id=user["id"],
        )
        self.assertFalse(ok)
        self.assertEqual(message, "Wrong workspace password")

        deleted, delete_message = app.delete_workspace(
            workspace["id"],
            password="stored-override",
            user_id=user["id"],
        )
        self.assertFalse(deleted)
        self.assertEqual(delete_message, "Wrong workspace password")

        deleted, delete_message = app.delete_workspace(
            workspace["id"],
            password="stored-override",
            user_id=root["id"],
        )
        self.assertTrue(deleted)
        self.assertEqual(delete_message, "")

    def test_default_workspace_can_be_deleted_and_is_not_recreated_by_listing(self) -> None:
        self.assertIn(app.DEFAULT_WORKSPACE_ID, {item["id"] for item in app.list_workspaces()})

        deleted, delete_message = app.delete_workspace(app.DEFAULT_WORKSPACE_ID)

        self.assertTrue(deleted)
        self.assertEqual(delete_message, "")
        self.assertNotIn(app.DEFAULT_WORKSPACE_ID, {item["id"] for item in app.list_workspaces()})
        self.assertTrue(app.read_shelved_payload()["default_workspace_deleted"])

    def test_user_records_are_hashed_and_persisted(self) -> None:
        user = storage.set_user("Alice", password="secret-pass", api_key="secret-api", role="admin")

        self.assertEqual(user["username"], "Alice")
        self.assertEqual(user["role"], "admin")
        self.assertTrue(user["password_configured"])
        self.assertTrue(user["api_key_configured"])
        users = storage.read_shelved_users()
        stored = users[user["id"]]
        self.assertTrue(app.verify_password("secret-pass", stored["password_hash"]))
        self.assertTrue(app.verify_password("secret-api", stored["api_key_hash"]))
        self.assertNotIn("secret-pass", str(stored))
        self.assertNotIn("secret-api", str(stored))

    def test_user_totp_setup_confirms_and_disables(self) -> None:
        user = storage.set_user("Alice", password="secret-pass", api_key="secret-api", role="admin")

        setup = storage.begin_user_totp_setup(user["id"])
        self.assertIn("secret", setup)
        self.assertIn("otpauth://totp/DassieDrop%3AAlice", setup["otpauth_uri"])
        self.assertIn("<svg", setup["qr_svg"])
        self.assertIn("server_time", setup)
        self.assertNotIn("server_code", setup)
        self.assertIn('fill="#000"', setup["qr_svg"])
        self.assertIn('aria-label="Authenticator QR code"', setup["qr_svg"])
        repeated_setup = storage.begin_user_totp_setup(user["id"])
        self.assertEqual(repeated_setup["secret"], setup["secret"])
        code = storage.totp_code(setup["secret"], self.fake_now())
        confirmed = storage.confirm_user_totp_setup(user["id"], code)

        self.assertTrue(confirmed["totp_enabled"])
        self.assertTrue(storage.user_totp_code_is_valid(user["id"], code))
        users = storage.read_shelved_users()
        stored = users[user["id"]]
        self.assertEqual(stored["totp_secret"], setup["secret"])
        self.assertNotIn("totp_secret", confirmed)
        repeated_confirmed = storage.confirm_user_totp_setup(user["id"], code)
        self.assertTrue(repeated_confirmed["totp_enabled"])

        disabled = storage.disable_user_totp(user["id"])
        self.assertFalse(disabled["totp_enabled"])
        self.assertFalse(storage.user_totp_code_is_valid(user["id"], code))

    def test_user_totp_setup_accepts_setup_timestamp_code(self) -> None:
        user = storage.set_user("Alice", password="secret-pass", api_key="secret-api", role="admin")
        setup = storage.begin_user_totp_setup(user["id"])
        code = storage.totp_code(setup["secret"], setup["server_time"])

        config.now_ts = lambda: self.fake_now() + 300
        confirmed = storage.confirm_user_totp_setup(user["id"], code)

        self.assertTrue(confirmed["totp_enabled"])

    def test_user_secret_reset_can_clear_totp_lockout(self) -> None:
        user = storage.set_user("Alice", password="secret-pass", api_key="secret-api", role="admin")
        setup = storage.begin_user_totp_setup(user["id"])
        storage.confirm_user_totp_setup(user["id"], storage.totp_code(setup["secret"], setup["server_time"]))

        reset_user = storage.update_user_secrets(user["id"], password="replacement", clear_totp=True)

        self.assertFalse(reset_user["totp_enabled"])
        self.assertIsNotNone(storage.authenticate_user("Alice", "replacement"))
        users = storage.read_shelved_users()
        stored = users[user["id"]]
        self.assertIsNone(stored["totp_secret"])
        self.assertIsNone(stored["totp_pending_secret"])
        self.assertIsNone(stored["totp_pending_at"])

    def test_user_creation_rejects_duplicate_usernames(self) -> None:
        storage.set_user("Alice", password="secret-pass", api_key="secret-api", role="admin")

        with self.assertRaisesRegex(ValueError, "Username already exists"):
            storage.set_user("alice", password="other-pass", api_key="other-api", role="user")

    def test_user_roles_default_to_user(self) -> None:
        user = storage.set_user("Alice", password="secret-pass", api_key="secret-api", role="owner")

        self.assertEqual(user["role"], "user")

    def test_startup_bootstraps_default_root_user(self) -> None:
        app.load_persisted_workspaces()

        users = storage.read_shelved_users()
        self.assertEqual(len(users), 1)
        user = next(iter(users.values()))
        self.assertEqual(user["username"], "admin")
        self.assertEqual(user["role"], "root")
        self.assertTrue(app.verify_password("password", user["password_hash"]))
        self.assertTrue(app.verify_password("password", user["api_key_hash"]))

    def test_startup_bootstraps_root_user_from_legacy_app_settings(self) -> None:
        legacy_access_hash = storage.hash_password("old-access-code")
        legacy_api_hash = storage.hash_password("old-api-key")
        with state.state_lock:
            state.shared_state["app_settings"] = {
                "access_code_hash": legacy_access_hash,
                "api_key_hash": legacy_api_hash,
                "workspace_super_password_hash": None,
            }
            app.persist_workspaces_locked()
        reset_app_state()

        app.load_persisted_workspaces()

        users = storage.read_shelved_users()
        self.assertEqual(len(users), 1)
        user = next(iter(users.values()))
        self.assertEqual(user["username"], "admin")
        self.assertEqual(user["role"], "root")
        self.assertTrue(app.verify_password("old-access-code", user["password_hash"]))
        self.assertTrue(app.verify_password("old-api-key", user["api_key_hash"]))
        self.assertFalse(app.verify_password("password", user["password_hash"]))

    def test_startup_repairs_default_root_user_from_legacy_app_settings(self) -> None:
        legacy_access_hash = storage.hash_password("old-access-code")
        legacy_api_hash = storage.hash_password("old-api-key")
        now = self.fake_now()
        with state.state_lock:
            state.shared_state["app_settings"] = {
                "access_code_hash": legacy_access_hash,
                "api_key_hash": legacy_api_hash,
                "workspace_super_password_hash": None,
            }
            state.shared_state["users"] = {
                "legacy-admin": {
                    "id": "legacy-admin",
                    "username": "admin",
                    "role": "root",
                    "password_hash": storage.hash_password("password"),
                    "api_key_hash": storage.hash_password("password"),
                    "created_at": now,
                    "updated_at": now,
                }
            }
            app.persist_workspaces_locked()
        reset_app_state()

        app.load_persisted_workspaces()

        users = storage.read_shelved_users()
        user = users["legacy-admin"]
        self.assertTrue(app.verify_password("old-access-code", user["password_hash"]))
        self.assertTrue(app.verify_password("old-api-key", user["api_key_hash"]))
        self.assertFalse(app.verify_password("password", user["password_hash"]))

    def test_startup_does_not_bootstrap_when_root_user_exists(self) -> None:
        existing = storage.set_user("Rooty", password="root-pass", api_key="root-api", role="root")

        app.load_persisted_workspaces()

        users = storage.read_shelved_users()
        self.assertEqual(len(users), 1)
        self.assertIn(existing["id"], users)
        self.assertEqual(users[existing["id"]]["username"], "Rooty")

    def test_cannot_demote_or_delete_last_root_user(self) -> None:
        root = storage.set_user("Rooty", password="root-pass", api_key="root-api", role="root")

        with self.assertRaises(ValueError):
            storage.update_user(root["id"], "Rooty", role="admin")
        with self.assertRaises(ValueError):
            storage.delete_user(root["id"])

        users = storage.read_shelved_users()
        self.assertEqual(len(users), 1)
        self.assertEqual(users[root["id"]]["role"], "root")

    def test_can_demote_or_delete_root_when_another_root_exists(self) -> None:
        first = storage.set_user("Rooty", password="root-pass", api_key="root-api", role="root")
        second = storage.set_user("Backup", password="backup-pass", api_key="backup-api", role="root")

        updated = storage.update_user(first["id"], "Rooty", role="admin")

        self.assertEqual(updated["role"], "admin")
        storage.update_user(first["id"], "Rooty", role="root")
        deleted = storage.delete_user(first["id"])
        self.assertTrue(deleted)

    def test_share_payload_includes_workspace_metadata(self) -> None:
        workspace = app.create_workspace("Ops Desk")
        app.add_text_entry("hello", workspace_id=workspace["id"])
        entry = app.find_text_entry(app.get_snapshot(workspace["id"])["texts"][0]["id"], workspace_id=workspace["id"])

        payload = app.share_payload("text", entry, "http://127.0.0.1:8000")

        self.assertEqual(payload["workspace_id"], workspace["id"])
        self.assertEqual(payload["workspace_display_name"], "ops-desk")
        self.assertEqual(payload["workspace_slug"], "ops-desk")
        self.assertEqual(payload["workspace_path"], "/w/ops-desk")
        self.assertEqual(payload["workspace_url"], "http://127.0.0.1:8000/w/ops-desk")



class HttpServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.original_upload_dir = config.UPLOAD_DIR
        self.original_share_base_url = config.SHARE_BASE_URL
        self.original_now_ts = config.now_ts
        self.original_version_file = config.VERSION_FILE
        self.original_update_check_enabled = config.UPDATE_CHECK_ENABLED
        self.original_update_check_url = config.UPDATE_CHECK_URL
        self.original_update_check_interval_seconds = config.UPDATE_CHECK_INTERVAL_SECONDS
        self.original_upload_rate_limit_window_seconds = config.UPLOAD_RATE_LIMIT_WINDOW_SECONDS
        self.original_upload_rate_limit_max_requests = config.UPLOAD_RATE_LIMIT_MAX_REQUESTS
        self.original_workspace_create_rate_limit_window_seconds = (
            config.WORKSPACE_CREATE_RATE_LIMIT_WINDOW_SECONDS
        )
        self.original_workspace_create_rate_limit_max_requests = (
            config.WORKSPACE_CREATE_RATE_LIMIT_MAX_REQUESTS
        )
        self.current_time = 1_700_100_000.0
        config.UPLOAD_DIR = Path(self.temp_dir.name) / "uploads"
        config.SHARE_BASE_URL = ""
        config.UPDATE_CHECK_ENABLED = False
        config.UPDATE_CHECK_URL = "https://example.invalid/VERSION"
        config.UPDATE_CHECK_INTERVAL_SECONDS = 24 * 60 * 60
        config.UPLOAD_RATE_LIMIT_WINDOW_SECONDS = 60
        config.UPLOAD_RATE_LIMIT_MAX_REQUESTS = 10
        config.WORKSPACE_CREATE_RATE_LIMIT_WINDOW_SECONDS = 60
        config.WORKSPACE_CREATE_RATE_LIMIT_MAX_REQUESTS = 10
        config.now_ts = self.fake_now
        config.VERSION_FILE = Path(self.temp_dir.name) / "VERSION"
        config.VERSION_FILE.write_text("9.9.9", encoding="utf-8")
        app.ensure_upload_dir()
        reset_app_state()
        self.server = None
        self.thread = None

    def tearDown(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)
        reset_app_state()
        config.UPLOAD_DIR = self.original_upload_dir
        config.SHARE_BASE_URL = self.original_share_base_url
        config.UPDATE_CHECK_ENABLED = self.original_update_check_enabled
        config.UPDATE_CHECK_URL = self.original_update_check_url
        config.UPDATE_CHECK_INTERVAL_SECONDS = self.original_update_check_interval_seconds
        config.UPLOAD_RATE_LIMIT_WINDOW_SECONDS = self.original_upload_rate_limit_window_seconds
        config.UPLOAD_RATE_LIMIT_MAX_REQUESTS = self.original_upload_rate_limit_max_requests
        config.WORKSPACE_CREATE_RATE_LIMIT_WINDOW_SECONDS = (
            self.original_workspace_create_rate_limit_window_seconds
        )
        config.WORKSPACE_CREATE_RATE_LIMIT_MAX_REQUESTS = (
            self.original_workspace_create_rate_limit_max_requests
        )
        config.now_ts = self.original_now_ts
        config.VERSION_FILE = self.original_version_file
        self.temp_dir.cleanup()

    def fake_now(self) -> float:
        return self.current_time

    def start_server(self, access_code: str = "", api_key: str = "") -> None:
        reset_app_state()
        if access_code:
            storage.set_user(
                "admin",
                password=access_code,
                api_key=api_key or access_code,
                role="root",
            )
        app.start_background_tasks()
        self.server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.AppHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        result = {
            "status": response.status,
            "headers": dict(response.getheaders()),
            "body": payload,
            "text": payload.decode("utf-8", errors="replace"),
        }
        connection.close()
        return result

    def root_cookie(self, username: str = "admin", password: str = "password") -> str:
        storage.set_user(username, password=password, api_key="root-api", role="root")
        login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": username, "password": password}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(login["status"], 200)
        return login["headers"]["Set-Cookie"].split(";", 1)[0]

    def user_cookie(self, username: str = "alice", password: str = "password") -> str:
        storage.set_user(username, password=password, api_key=f"{username}-api", role="user")
        login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": username, "password": password}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(login["status"], 200)
        return login["headers"]["Set-Cookie"].split(";", 1)[0]

    def select_workspace(self, cookie: str, workspace: str = app.DEFAULT_WORKSPACE_ID, password: str = ""):
        page = self.request("GET", "/workspaces", headers={"Cookie": cookie})
        token = page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]
        return self.request(
            "POST",
            f"/api/workspaces/{workspace}/enter",
            body=json.dumps({"password": password}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )

    def csrf_token(self, cookie: str) -> str:
        page = self.request("GET", "/workspaces", headers={"Cookie": cookie})
        self.assertEqual(page["status"], 200)
        return page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]

    def upload_with_cookie_session(self, filename: str, content: bytes, cookie: str):
        page = self.request("GET", "/workspaces", headers={"Cookie": cookie})
        token = page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]
        boundary = "----DassieDropBoundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8") + content
        body += (
            f"\r\n--{boundary}\r\n"
            'Content-Disposition: form-data; name="hidden"\r\n\r\n'
            "false"
        ).encode("utf-8")
        body += (
            f"\r\n--{boundary}\r\n"
            'Content-Disposition: form-data; name="password"\r\n\r\n'
        ).encode("utf-8")
        body += (
            f"\r\n--{boundary}\r\n"
            'Content-Disposition: form-data; name="name"\r\n\r\n'
        ).encode("utf-8")
        body += f"\r\n--{boundary}--\r\n".encode("utf-8")
        return self.request(
            "POST",
            "/api/upload",
            body=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(body)),
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )

    def open_websocket(self, cookie: str | None = None):
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        websocket_key = base64.b64encode(os.urandom(16)).decode("ascii")
        headers = [
            "GET /ws HTTP/1.1",
            f"Host: 127.0.0.1:{self.port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {websocket_key}",
            "Sec-WebSocket-Version: 13",
        ]
        if cookie:
            headers.append(f"Cookie: {cookie}")
        request = "\r\n".join(headers) + "\r\n\r\n"
        connection.sendall(request.encode("utf-8"))
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response += chunk
        header_blob, _, remainder = response.partition(b"\r\n\r\n")
        return connection, header_blob.decode("utf-8", errors="replace"), websocket_key, remainder

    def read_websocket_frame(self, connection: socket.socket, buffered: bytes = b"") -> tuple[bytes, bytes]:
        pending = bytearray(buffered)

        def read_exact(length: int) -> bytes:
            while len(pending) < length:
                chunk = connection.recv(4096)
                if not chunk:
                    raise AssertionError("WebSocket connection closed early")
                pending.extend(chunk)
            data = bytes(pending[:length])
            del pending[:length]
            return data

        header = read_exact(2)
        first_byte, second_byte = header
        self.assertEqual(first_byte & 0x0F, 0x1)
        payload_length = second_byte & 0x7F
        if payload_length == 126:
            payload_length = struct.unpack("!H", read_exact(2))[0]
        elif payload_length == 127:
            payload_length = struct.unpack("!Q", read_exact(8))[0]
        return read_exact(payload_length), bytes(pending)

    def read_websocket_close_code(self, connection: socket.socket, buffered: bytes = b"") -> tuple[int, bytes]:
        pending = bytearray(buffered)

        def read_exact(length: int) -> bytes:
            while len(pending) < length:
                chunk = connection.recv(4096)
                if not chunk:
                    raise AssertionError("WebSocket connection closed early")
                pending.extend(chunk)
            data = bytes(pending[:length])
            del pending[:length]
            return data

        header = read_exact(2)
        first_byte, second_byte = header
        self.assertEqual(first_byte & 0x0F, 0x8)
        payload_length = second_byte & 0x7F
        if payload_length == 126:
            payload_length = struct.unpack("!H", read_exact(2))[0]
        elif payload_length == 127:
            payload_length = struct.unpack("!Q", read_exact(8))[0]
        payload = read_exact(payload_length)
        self.assertGreaterEqual(len(payload), 2)
        return struct.unpack("!H", payload[:2])[0], bytes(pending)

    def wait_for_websocket_client_count(self, expected_count: int, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with state.websocket_lock:
                current_count = len(state.websocket_clients)
            if current_count == expected_count:
                return
            time.sleep(0.01)
        self.fail(f"Expected {expected_count} websocket clients, found {current_count}")

    def upload_request(
        self,
        filename: str,
        content: bytes,
        cookie: str | None = None,
        hidden: bool = False,
        password: str = "",
        name: str = "",
        workspace_slug: str = "",
        workspace_name: str = "",
        workspace_password: str = "",
    ):
        boundary = "----DassieDropBoundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8") + content
        body += (
            f"\r\n--{boundary}\r\n"
            'Content-Disposition: form-data; name="hidden"\r\n\r\n'
            f"{'true' if hidden else 'false'}"
        ).encode("utf-8")
        body += (
            f"\r\n--{boundary}\r\n"
            'Content-Disposition: form-data; name="password"\r\n\r\n'
            f"{password}"
        ).encode("utf-8")
        body += (
            f"\r\n--{boundary}\r\n"
            'Content-Disposition: form-data; name="name"\r\n\r\n'
            f"{name}"
        ).encode("utf-8")
        body += f"\r\n--{boundary}--\r\n".encode("utf-8")
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        }
        if cookie:
            headers["Cookie"] = cookie
        if workspace_slug:
            headers["X-Workspace"] = workspace_slug
        elif workspace_name:
            headers["X-Workspace-Name"] = workspace_name
        if workspace_password:
            headers["X-Workspace-Password"] = workspace_password
        return self.request("POST", "/api/upload", body=body, headers=headers)

    def test_text_file_and_delete_flow_without_auth(self) -> None:
        self.start_server()

        home = self.request("GET", "/")
        self.assertEqual(home["status"], 303)
        self.assertEqual(home["headers"]["Location"], "/workspaces")

        text_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "shared text", "name": "Laptop"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(text_response["status"], 200)
        text_snapshot = json.loads(text_response["body"])
        text_id = text_snapshot["texts"][0]["id"]
        self.assertEqual(text_snapshot["latest_text"], "shared text")

        latest_text_response = self.request("GET", "/api/latest-text")
        self.assertEqual(latest_text_response["status"], 200)
        latest_text_entry = json.loads(latest_text_response["body"])
        self.assertEqual(latest_text_entry["id"], text_id)
        self.assertEqual(latest_text_entry["content"], "shared text")
        self.assertFalse(latest_text_entry["hidden"])
        self.assertEqual(latest_text_entry["sharer_name"], "Laptop")
        self.assertEqual(latest_text_entry["sharer_ip"], "127.0.0.1")
        text_short_code = latest_text_entry["short_code"]

        hidden_text_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "top secret", "hidden": True, "name": "Carel"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(hidden_text_response["status"], 200)
        hidden_snapshot = json.loads(hidden_text_response["body"])
        self.assertTrue(hidden_snapshot["texts"][0]["hidden"])
        self.assertEqual(hidden_snapshot["texts"][0]["sharer_name"], "Carel")

        upload_response = self.upload_request("note.txt", b"network payload", name="Phone")
        self.assertEqual(upload_response["status"], 200)
        upload_snapshot = json.loads(upload_response["body"])
        file_entry = upload_snapshot["files"][0]
        file_id = file_entry["id"]

        saved_file = config.UPLOAD_DIR / app.find_file_entry(file_id)["stored_name"]
        self.assertTrue(saved_file.exists())

        latest_file_response = self.request("GET", "/api/latest-file")
        self.assertEqual(latest_file_response["status"], 200)
        latest_file_entry = json.loads(latest_file_response["body"])
        self.assertEqual(latest_file_entry["id"], file_id)
        self.assertEqual(latest_file_entry["name"], "note.txt")
        self.assertEqual(latest_file_entry["sharer_name"], "Phone")
        self.assertEqual(latest_file_entry["sharer_ip"], "127.0.0.1")
        file_short_code = latest_file_entry["short_code"]

        latest_file_content_response = self.request("GET", "/api/latest-file/content")
        self.assertEqual(latest_file_content_response["status"], 200)
        self.assertEqual(latest_file_content_response["body"], b"network payload")
        self.assertEqual(
            latest_file_content_response["headers"]["Content-Type"],
            "text/plain",
        )

        shared_text_response = self.request("GET", f"/s/{text_short_code}")
        self.assertEqual(shared_text_response["status"], 200)
        self.assertEqual(shared_text_response["body"], b"shared text")
        self.assertEqual(
            shared_text_response["headers"]["Content-Type"],
            "text/plain; charset=utf-8",
        )

        shared_file_response = self.request("GET", f"/s/{file_short_code}")
        self.assertEqual(shared_file_response["status"], 200)
        self.assertEqual(shared_file_response["body"], b"network payload")
        self.assertEqual(shared_file_response["headers"]["Content-Type"], "text/plain")

        download_response = self.request("GET", f"/download/{file_id}")
        self.assertEqual(download_response["status"], 200)
        self.assertEqual(download_response["body"], b"network payload")
        self.assertEqual(download_response["headers"]["Content-Type"], "text/plain")
        self.assertEqual(
            download_response["headers"]["Content-Disposition"],
            "attachment; filename*=UTF-8''note.txt",
        )

        preview_response = self.request("GET", f"/preview/{file_id}")
        self.assertEqual(preview_response["status"], 200)
        self.assertEqual(preview_response["body"], b"network payload")
        self.assertEqual(preview_response["headers"]["Content-Type"], "text/plain")
        self.assertEqual(
            preview_response["headers"]["Content-Disposition"],
            "inline; filename*=UTF-8''note.txt",
        )

        delete_text_response = self.request("DELETE", f"/api/text/{text_id}")
        self.assertEqual(delete_text_response["status"], 200)
        remaining_texts = json.loads(delete_text_response["body"])["texts"]
        self.assertEqual(len(remaining_texts), 1)
        self.assertEqual(remaining_texts[0]["content"], "top secret")

        delete_file_response = self.request("DELETE", f"/api/file/{file_id}")
        self.assertEqual(delete_file_response["status"], 200)
        self.assertEqual(json.loads(delete_file_response["body"])["files"], [])
        self.assertFalse(saved_file.exists())

    def test_workspace_creation_endpoint_returns_workspace_summary(self) -> None:
        self.start_server()

        response = self.request(
            "POST",
            "/api/workspaces",
            body=json.dumps({"name": "QA Room", "password": "vault"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response["status"], 200)
        payload = json.loads(response["body"])
        self.assertEqual(payload["workspace"]["name"], "qa-room")
        self.assertEqual(payload["workspace"]["slug"], "qa-room")
        self.assertTrue(payload["workspace"]["password_required"])
        self.assertEqual(payload["workspace"]["expiry_seconds"], app.EXPIRY_SECONDS)
        self.assertEqual(payload["workspace"]["message_expiry_seconds"], app.EXPIRY_SECONDS)

    def test_workspace_creation_endpoint_records_creator_and_explicit_users(self) -> None:
        self.start_server()
        creator_cookie = self.user_cookie("creator", "creator-pass")
        creator_id = next(user["id"] for user in storage.list_users() if user["username"] == "creator")
        creator_token = self.csrf_token(creator_cookie)

        response = self.request(
            "POST",
            "/api/workspaces",
            body=json.dumps(
                {"name": "Team Room", "password": "", "expiry_seconds": 86400, "access_mode": "explicit"}
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": creator_cookie,
                "X-CSRF-Token": creator_token,
            },
        )

        self.assertEqual(response["status"], 200)
        payload = json.loads(response["body"])
        workspace = payload["workspace"]
        self.assertEqual(workspace["access_mode"], "explicit")
        self.assertEqual(workspace["owner_user_id"], creator_id)
        self.assertEqual(workspace["explicit_user_ids"], [])
        self.assertNotIn("users", payload)

        blocked_cookie = self.user_cookie("blocked", "blocked-pass")
        blocked_id = next(user["id"] for user in storage.list_users() if user["username"] == "blocked")
        blocked_token = self.csrf_token(blocked_cookie)
        blocked_enter = self.request(
            "POST",
            f"/api/workspaces/{workspace['id']}/enter",
            body=json.dumps({"password": ""}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": blocked_cookie,
                "X-CSRF-Token": blocked_token,
            },
        )
        self.assertEqual(blocked_enter["status"], 403)

        update_response = self.request(
            "POST",
            f"/api/workspaces/{workspace['id']}/users",
            body=json.dumps({"user_ids": [blocked_id]}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": creator_cookie,
                "X-CSRF-Token": creator_token,
            },
        )
        self.assertEqual(update_response["status"], 200)
        updated = json.loads(update_response["body"])["workspace"]
        self.assertEqual(updated["explicit_user_ids"], [blocked_id])

        allowed_enter = self.request(
            "POST",
            f"/api/workspaces/{workspace['id']}/enter",
            body=json.dumps({"password": ""}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": blocked_cookie,
                "X-CSRF-Token": blocked_token,
            },
        )
        self.assertEqual(allowed_enter["status"], 200)

        delete_response = self.request(
            "DELETE",
            f"/api/workspaces/{workspace['id']}",
            body=json.dumps({"password": ""}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": blocked_cookie,
                "X-CSRF-Token": blocked_token,
            },
        )
        self.assertEqual(delete_response["status"], 403)

    def test_explicit_workspace_api_key_access_and_management(self) -> None:
        self.start_server()
        owner = storage.set_user("Owner", password="owner-pass", api_key="owner-api", role="user")
        allowed = storage.set_user("Allowed", password="allowed-pass", api_key="allowed-api", role="user")
        blocked = storage.set_user("Blocked", password="blocked-pass", api_key="blocked-api", role="user")

        create_response = self.request(
            "POST",
            "/api/workspaces",
            body=json.dumps(
                {
                    "name": "API Team",
                    "access_mode": "explicit",
                    "explicit_user_ids": [allowed["id"]],
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-API-Key": "owner-api"},
        )
        self.assertEqual(create_response["status"], 200)
        workspace = json.loads(create_response["body"])["workspace"]
        self.assertEqual(workspace["access_mode"], "explicit")
        self.assertEqual(workspace["owner_user_id"], owner["id"])
        self.assertEqual(workspace["explicit_user_ids"], [allowed["id"]])

        allowed_state = self.request(
            "GET",
            "/api/state",
            headers={"X-API-Key": "allowed-api", "X-Workspace": workspace["slug"]},
        )
        self.assertEqual(allowed_state["status"], 200)

        blocked_state = self.request(
            "GET",
            "/api/state",
            headers={"X-API-Key": "blocked-api", "X-Workspace": workspace["slug"]},
        )
        self.assertEqual(blocked_state["status"], 403)

        share_response = self.request(
            "POST",
            "/api/share-text",
            body=json.dumps({"text": "from automation"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "allowed-api",
                "X-Workspace": workspace["slug"],
            },
        )
        self.assertEqual(share_response["status"], 200)

        update_response = self.request(
            "POST",
            f"/api/workspaces/{workspace['id']}/users",
            body=json.dumps({"user_ids": [blocked["id"]]}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-API-Key": "owner-api"},
        )
        self.assertEqual(update_response["status"], 200)
        self.assertEqual(json.loads(update_response["body"])["workspace"]["explicit_user_ids"], [blocked["id"]])

        blocked_state = self.request(
            "GET",
            "/api/state",
            headers={"X-API-Key": "blocked-api", "X-Workspace": workspace["slug"]},
        )
        self.assertEqual(blocked_state["status"], 200)

    def test_explicit_workspace_access_page_manages_selected_users(self) -> None:
        self.start_server()
        creator_cookie = self.user_cookie("creator", "creator-pass")
        creator = next(user for user in storage.list_users() if user["username"] == "creator")
        allowed = storage.set_user("Allowed", password="allowed-pass", api_key="allowed-api", role="user")
        blocked = storage.set_user("Blocked", password="blocked-pass", api_key="blocked-api", role="user")
        admin = storage.set_user("Admin", password="admin-pass", api_key="admin-api", role="admin")
        workspace = app.create_workspace(
            "Team Room",
            owner_user_id=creator["id"],
            access_mode="explicit",
            explicit_user_ids=[allowed["id"]],
        )
        enter = self.select_workspace(creator_cookie, workspace["id"])
        self.assertEqual(enter["status"], 200)

        page = self.request("GET", "/", headers={"Cookie": creator_cookie})
        self.assertEqual(page["status"], 200)
        self.assertIn('href="/workspaces/access"', page["text"])

        access_page = self.request("GET", "/workspaces/access", headers={"Cookie": creator_cookie})
        self.assertEqual(access_page["status"], 200)
        self.assertIn('id="hasAccessUsers"', access_page["text"])
        token = access_page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]

        access_payload_response = self.request(
            "GET",
            "/api/workspaces/access",
            headers={"Cookie": creator_cookie},
        )
        self.assertEqual(access_payload_response["status"], 200)
        access_payload = json.loads(access_payload_response["body"])
        self.assertEqual(access_payload["workspace"]["id"], workspace["id"])
        self.assertIn(allowed["id"], access_payload["workspace"]["explicit_user_ids"])
        self.assertIn(blocked["id"], {user["id"] for user in access_payload["users"]})
        self.assertIn(admin["id"], {user["id"] for user in access_payload["users"]})

        update_response = self.request(
            "POST",
            f"/api/workspaces/{workspace['id']}/users",
            body=json.dumps({"user_ids": [blocked["id"]]}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": creator_cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(update_response["status"], 200)
        updated = json.loads(update_response["body"])["workspace"]
        self.assertEqual(updated["explicit_user_ids"], [blocked["id"]])

    def test_workspace_access_page_requires_explicit_workspace_manager(self) -> None:
        self.start_server()
        owner_cookie = self.user_cookie("owner", "owner-pass")
        outsider_cookie = self.user_cookie("outsider", "outsider-pass")
        owner = next(user for user in storage.list_users() if user["username"] == "owner")
        outsider = next(user for user in storage.list_users() if user["username"] == "outsider")
        explicit_workspace = app.create_workspace(
            "Team Room",
            owner_user_id=owner["id"],
            access_mode="explicit",
            explicit_user_ids=[outsider["id"]],
        )
        public_workspace = app.create_workspace("Public Room", owner_user_id=owner["id"])

        self.assertEqual(self.select_workspace(outsider_cookie, explicit_workspace["id"])["status"], 200)
        forbidden = self.request("GET", "/workspaces/access", headers={"Cookie": outsider_cookie})
        self.assertEqual(forbidden["status"], 403)

        self.assertEqual(self.select_workspace(owner_cookie, public_workspace["id"])["status"], 200)
        redirected = self.request("GET", "/workspaces/access", headers={"Cookie": owner_cookie})
        self.assertEqual(redirected["status"], 303)
        self.assertEqual(redirected["headers"]["Location"], "/")

    def test_password_workspace_owner_can_change_password_from_access_page(self) -> None:
        self.start_server()
        owner_cookie = self.user_cookie("owner", "owner-pass")
        outsider_cookie = self.user_cookie("outsider", "outsider-pass")
        owner = next(user for user in storage.list_users() if user["username"] == "owner")
        workspace = app.create_workspace(
            "Password Room",
            password="old-vault",
            owner_user_id=owner["id"],
            access_mode="password",
        )

        self.assertEqual(self.select_workspace(owner_cookie, workspace["id"], password="old-vault")["status"], 200)
        page = self.request("GET", "/", headers={"Cookie": owner_cookie})
        self.assertEqual(page["status"], 200)
        self.assertIn('href="/workspaces/access"', page["text"])

        access_page = self.request("GET", "/workspaces/access", headers={"Cookie": owner_cookie})
        self.assertEqual(access_page["status"], 200)
        self.assertIn('id="workspacePasswordPanel"', access_page["text"])
        self.assertIn('id="workspacePasswordPanel" class="workspace-password-panel" >', access_page["text"])
        self.assertIn('<div class="access-manager" hidden>', access_page["text"])
        self.assertIn('<button id="saveAccessBtn" type="button" hidden>Save Access</button>', access_page["text"])
        token = access_page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]

        access_payload_response = self.request(
            "GET",
            "/api/workspaces/access",
            headers={"Cookie": owner_cookie},
        )
        self.assertEqual(access_payload_response["status"], 200)
        access_payload = json.loads(access_payload_response["body"])
        self.assertEqual(access_payload["workspace"]["access_mode"], "password")

        update_response = self.request(
            "POST",
            f"/api/workspaces/{workspace['id']}/password",
            body=json.dumps({"password": "new-vault"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": owner_cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(update_response["status"], 200)
        updated = json.loads(update_response["body"])["workspace"]
        self.assertTrue(updated["password_required"])
        self.assertTrue(app.workspace_password_is_valid(app.get_workspace(workspace["id"]), "new-vault"))

        self.assertEqual(self.select_workspace(outsider_cookie, workspace["id"], password="old-vault")["status"], 403)
        self.assertEqual(self.select_workspace(outsider_cookie, workspace["id"], password="new-vault")["status"], 200)

    def test_workspace_creation_endpoint_accepts_custom_expiry(self) -> None:
        self.start_server()

        response = self.request(
            "POST",
            "/api/workspaces",
            body=json.dumps(
                {
                    "name": "QA Room",
                    "password": "",
                    "expiry_seconds": 3600,
                    "message_expiry_seconds": 60,
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response["status"], 200)
        payload = json.loads(response["body"])
        self.assertEqual(payload["workspace"]["expiry_seconds"], 3600)
        self.assertEqual(payload["workspace"]["message_expiry_seconds"], 60)

    def test_workspace_creation_endpoint_caps_message_expiry_to_workspace_expiry(self) -> None:
        self.start_server()

        response = self.request(
            "POST",
            "/api/workspaces",
            body=json.dumps(
                {
                    "name": "QA Room",
                    "password": "",
                    "expiry_seconds": 60,
                    "message_expiry_seconds": 3600,
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response["status"], 200)
        payload = json.loads(response["body"])
        self.assertEqual(payload["workspace"]["expiry_seconds"], 60)
        self.assertEqual(payload["workspace"]["message_expiry_seconds"], 60)

    def test_workspace_creation_endpoint_rejects_invalid_expiry(self) -> None:
        self.start_server()

        response = self.request(
            "POST",
            "/api/workspaces",
            body=json.dumps({"name": "QA Room", "password": "", "expiry_seconds": -1}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response["status"], 400)

        response = self.request(
            "POST",
            "/api/workspaces",
            body=json.dumps(
                {"name": "QA Room", "password": "", "expiry_seconds": 60, "message_expiry_seconds": -1}
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response["status"], 400)

    def test_settings_redirects_to_users(self) -> None:
        self.start_server()
        cookie = self.root_cookie()

        page = self.request("GET", "/settings", headers={"Cookie": cookie})
        self.assertEqual(page["status"], 303)
        self.assertEqual(page["headers"]["Location"], "/users")
        users_page = self.request("GET", "/users", headers={"Cookie": cookie})
        token = users_page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]

        response = self.request(
            "POST",
            "/api/settings",
            body=json.dumps({"access_code": "stored-code"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )

        self.assertEqual(response["status"], 410)

    def test_user_password_is_used_for_login(self) -> None:
        self.start_server()
        storage.set_user("admin", password="stored-pass", api_key="stored-api", role="root")

        blocked = self.request("GET", "/api/state")
        self.assertEqual(blocked["status"], 401)

        login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "admin", "password": "stored-pass"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(login["status"], 200)

    def test_user_login_requires_authenticator_code_when_enabled(self) -> None:
        self.start_server()
        user = storage.set_user("admin", password="stored-pass", api_key="stored-api", role="root")
        setup = storage.begin_user_totp_setup(user["id"])
        code = storage.totp_code(setup["secret"], self.fake_now())
        storage.confirm_user_totp_setup(user["id"], code)

        missing_code = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "admin", "password": "stored-pass"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(missing_code["status"], 401)
        self.assertIn("Authenticator code required", missing_code["text"])
        bad_code = "000000" if code != "000000" else "111111"

        wrong_code = self.request(
            "POST",
            "/login",
            body=json.dumps(
                {"username": "admin", "password": "stored-pass", "totp_code": bad_code}
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(wrong_code["status"], 401)

        login = self.request(
            "POST",
            "/login",
            body=json.dumps(
                {"username": "admin", "password": "stored-pass", "totp_code": code}
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(login["status"], 200)
        self.assertIn("Set-Cookie", login["headers"])

    def test_user_can_manage_own_authenticator_and_root_can_disable(self) -> None:
        self.start_server()
        cookie = self.root_cookie()
        user_id = next(user["id"] for user in storage.list_users() if user["username"] == "admin")
        token = self.csrf_token(cookie)

        setup_response = self.request(
            "POST",
            f"/api/users/{user_id}/totp/setup",
            body=b"{}",
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(setup_response["status"], 200)
        setup_payload = json.loads(setup_response["body"])
        self.assertIn("otpauth_uri", setup_payload)
        self.assertIn("server_time", setup_payload)
        self.assertNotIn("server_code", setup_payload)
        self.assertIn("<svg", setup_payload["qr_svg"])
        setup_code = storage.totp_code(setup_payload["secret"], setup_payload["server_time"])

        confirm_response = self.request(
            "POST",
            f"/api/users/{user_id}/totp/confirm",
            body=json.dumps({"code": setup_code}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(confirm_response["status"], 200)
        self.assertTrue(json.loads(confirm_response["body"])["user"]["totp_enabled"])

        duplicate_confirm_response = self.request(
            "POST",
            f"/api/users/{user_id}/totp/confirm",
            body=json.dumps({"code": setup_code}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(duplicate_confirm_response["status"], 200)
        self.assertTrue(json.loads(duplicate_confirm_response["body"])["user"]["totp_enabled"])

        disable_response = self.request(
            "DELETE",
            f"/api/users/{user_id}/totp",
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(disable_response["status"], 200)
        self.assertFalse(json.loads(disable_response["body"])["user"]["totp_enabled"])

    def test_user_totp_setup_drains_body_before_confirm_on_same_connection(self) -> None:
        self.start_server()
        cookie = self.root_cookie()
        user_id = next(user["id"] for user in storage.list_users() if user["username"] == "admin")
        token = self.csrf_token(cookie)
        headers = {
            "Content-Type": "application/json",
            "Cookie": cookie,
            "X-CSRF-Token": token,
        }
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(
                "POST",
                f"/api/users/{user_id}/totp/setup",
                body=b"{}",
                headers=headers,
            )
            setup_response = connection.getresponse()
            setup_payload = setup_response.read()
            self.assertEqual(setup_response.status, 200)
            setup = json.loads(setup_payload)

            connection.request(
                "POST",
                f"/api/users/{user_id}/totp/confirm",
                body=json.dumps({"code": storage.totp_code(setup["secret"], setup["server_time"])}).encode("utf-8"),
                headers=headers,
            )
            confirm_response = connection.getresponse()
            confirm_payload = confirm_response.read()
        finally:
            connection.close()

        self.assertEqual(confirm_response.status, 200, confirm_payload.decode("utf-8", errors="replace"))
        self.assertTrue(json.loads(confirm_payload)["user"]["totp_enabled"])

    def test_users_pages_and_api_store_hashed_user_secrets(self) -> None:
        self.start_server()
        cookie = self.root_cookie()

        users_page = self.request("GET", "/users", headers={"Cookie": cookie})
        self.assertEqual(users_page["status"], 200)
        self.assertIn("DassieDrop Users", users_page["text"])
        self.assertIn('href="/users/new"', users_page["text"])
        self.assertNotIn("cancelEditUserBtn", users_page["text"])

        new_user_page = self.request("GET", "/users/new", headers={"Cookie": cookie})
        self.assertEqual(new_user_page["status"], 200)
        self.assertIn("DassieDrop Add User", new_user_page["text"])
        token = new_user_page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]

        initial_root_id = next(iter(storage.read_shelved_users()))
        blocked_update = self.request(
            "POST",
            f"/api/users/{initial_root_id}",
            body=json.dumps({"username": "admin", "role": "admin"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(blocked_update["status"], 400)
        blocked_delete = self.request(
            "DELETE",
            f"/api/users/{initial_root_id}",
            headers={
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(blocked_delete["status"], 400)

        response = self.request(
            "POST",
            "/api/users",
            body=json.dumps(
                {
                    "username": "alice",
                    "password": "secret-pass",
                    "api_key": "secret-api",
                    "role": "root",
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )

        self.assertEqual(response["status"], 200)
        payload = json.loads(response["body"])
        self.assertEqual(payload["user"]["username"], "alice")
        self.assertEqual(payload["user"]["role"], "root")
        self.assertTrue(payload["user"]["password_configured"])
        self.assertTrue(payload["user"]["api_key_configured"])
        self.assertNotIn("secret-pass", response["text"])
        self.assertNotIn("secret-api", response["text"])
        users = storage.read_shelved_users()
        stored = users[payload["user"]["id"]]
        self.assertTrue(app.verify_password("secret-pass", stored["password_hash"]))
        self.assertTrue(app.verify_password("secret-api", stored["api_key_hash"]))

        duplicate_user = self.request(
            "POST",
            "/api/users",
            body=json.dumps(
                {
                    "username": "ALICE",
                    "password": "duplicate-pass",
                    "api_key": "duplicate-api",
                    "role": "user",
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(duplicate_user["status"], 400)
        self.assertIn("Username already exists", duplicate_user["text"])

        second_root = self.request(
            "POST",
            "/api/users",
            body=json.dumps(
                {
                    "username": "backup",
                    "password": "backup-pass",
                    "api_key": "backup-api",
                    "role": "root",
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(second_root["status"], 200)

        duplicate_update = self.request(
            "POST",
            f"/api/users/{payload['user']['id']}",
            body=json.dumps({"username": "backup", "role": "admin"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(duplicate_update["status"], 400)
        self.assertIn("Username already exists", duplicate_update["text"])

        updated = self.request(
            "POST",
            f"/api/users/{payload['user']['id']}",
            body=json.dumps({"username": "alice2", "role": "admin"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(updated["status"], 200)
        updated_payload = json.loads(updated["body"])
        self.assertEqual(updated_payload["user"]["username"], "alice2")
        self.assertEqual(updated_payload["user"]["role"], "admin")
        updated_users = storage.read_shelved_users()
        updated_stored = updated_users[payload["user"]["id"]]
        self.assertTrue(app.verify_password("secret-pass", updated_stored["password_hash"]))
        self.assertTrue(app.verify_password("secret-api", updated_stored["api_key_hash"]))

        users_script = self.request("GET", "/assets/users.js", headers={"Cookie": cookie})
        self.assertEqual(users_script["status"], 200)
        self.assertIn("/users/edit?id=", users_script["text"])
        edit_page = self.request(
            "GET",
            f"/users/edit?id={payload['user']['id']}",
            headers={"Cookie": cookie},
        )
        self.assertEqual(edit_page["status"], 200)
        self.assertIn("DassieDrop Edit User", edit_page["text"])
        self.assertIn('href="/users">Cancel</a>', edit_page["text"])

        delete_response = self.request(
            "DELETE",
            f"/api/users/{payload['user']['id']}",
            headers={
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )

        self.assertEqual(delete_response["status"], 200)
        remaining_users = json.loads(delete_response["body"])["users"]
        self.assertEqual(len(remaining_users), 2)
        remaining_by_username = {user["username"]: user for user in remaining_users}
        self.assertEqual(remaining_by_username["admin"]["role"], "root")
        self.assertEqual(remaining_by_username["backup"]["role"], "root")

    def test_non_root_user_only_manages_own_secrets(self) -> None:
        self.start_server()
        root = storage.set_user("root", password="root-pass", api_key="root-api", role="root")
        user = storage.set_user("alice", password="alice-pass", api_key="alice-api", role="user")
        login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "alice", "password": "alice-pass"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(login["status"], 200)
        cookie = login["headers"]["Set-Cookie"].split(";", 1)[0]

        users_page = self.request("GET", "/users", headers={"Cookie": cookie})
        self.assertEqual(users_page["status"], 200)
        self.assertIn("DassieDrop Users", users_page["text"])
        token = users_page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]

        users_response = self.request("GET", "/api/users", headers={"Cookie": cookie})
        self.assertEqual(users_response["status"], 200)
        users_payload = json.loads(users_response["body"])
        self.assertFalse(users_payload["can_manage_users"])
        self.assertEqual([item["id"] for item in users_payload["users"]], [user["id"]])

        new_user_page = self.request("GET", "/users/new", headers={"Cookie": cookie})
        self.assertEqual(new_user_page["status"], 403)
        create_response = self.request(
            "POST",
            "/api/users",
            body=json.dumps({"username": "bob", "password": "bob-pass", "role": "root"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(create_response["status"], 403)

        other_edit_page = self.request(
            "GET",
            f"/users/edit?id={root['id']}",
            headers={"Cookie": cookie},
        )
        self.assertEqual(other_edit_page["status"], 403)
        own_edit_page = self.request(
            "GET",
            f"/users/edit?id={user['id']}",
            headers={"Cookie": cookie},
        )
        self.assertEqual(own_edit_page["status"], 200)

        forbidden_update = self.request(
            "POST",
            f"/api/users/{root['id']}",
            body=json.dumps({"password": "new-root-pass"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(forbidden_update["status"], 403)

        self_update = self.request(
            "POST",
            f"/api/users/{user['id']}",
            body=json.dumps(
                {
                    "username": "alice-root",
                    "role": "root",
                    "password": "new-alice-pass",
                    "api_key": "new-alice-api",
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(self_update["status"], 200)
        updated_users = storage.read_shelved_users()
        updated = updated_users[user["id"]]
        self.assertEqual(updated["username"], "alice")
        self.assertEqual(updated["role"], "user")
        self.assertTrue(app.verify_password("new-alice-pass", updated["password_hash"]))
        self.assertTrue(app.verify_password("new-alice-api", updated["api_key_hash"]))

    def test_root_user_can_change_own_username_and_role_when_another_root_remains(self) -> None:
        self.start_server()
        root = storage.set_user("root", password="root-pass", api_key="root-api", role="root")
        storage.set_user("backup", password="backup-pass", api_key="backup-api", role="root")
        login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "root", "password": "root-pass"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(login["status"], 200)
        cookie = login["headers"]["Set-Cookie"].split(";", 1)[0]
        users_page = self.request("GET", "/users", headers={"Cookie": cookie})
        token = users_page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]

        response = self.request(
            "POST",
            f"/api/users/{root['id']}",
            body=json.dumps({"username": "renamed-root", "role": "admin"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": token,
            },
        )

        self.assertEqual(response["status"], 200)
        users = storage.read_shelved_users()
        self.assertEqual(users[root["id"]]["username"], "renamed-root")
        self.assertEqual(users[root["id"]]["role"], "admin")

    def test_logout_clears_browser_session_and_login_page_is_direct(self) -> None:
        self.start_server()
        cookie = self.root_cookie()
        session_id = cookie.split("=", 1)[1]
        self.assertIn(session_id, state.authorized_sessions)

        login_page = self.request("GET", "/login")
        self.assertEqual(login_page["status"], 200)
        self.assertIn("Sign In", login_page["text"])

        logout = self.request("GET", "/logout", headers={"Cookie": cookie})

        self.assertEqual(logout["status"], 303)
        self.assertEqual(logout["headers"]["Location"], "/login")
        self.assertIn("Max-Age=0", logout["headers"]["Set-Cookie"])
        self.assertNotIn(session_id, state.authorized_sessions)

    def test_workspace_creation_is_rate_limited(self) -> None:
        self.start_server()
        config.WORKSPACE_CREATE_RATE_LIMIT_MAX_REQUESTS = 2
        config.WORKSPACE_CREATE_RATE_LIMIT_WINDOW_SECONDS = 60

        for name in ("one", "two"):
            response = self.request(
                "POST",
                "/api/workspaces",
                body=json.dumps({"name": name, "password": ""}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            self.assertEqual(response["status"], 200)

        blocked = self.request(
            "POST",
            "/api/workspaces",
            body=json.dumps({"name": "three", "password": ""}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(blocked["status"], 429)

    def test_workspace_list_hides_inaccessible_explicit_and_marks_deletable(self) -> None:
        self.start_server()
        owner_cookie = self.user_cookie("owner", "owner-pass")
        outsider_cookie = self.user_cookie("outsider", "outsider-pass")
        root_cookie = self.root_cookie("root", "root-pass")
        owner = next(user for user in storage.list_users() if user["username"] == "owner")
        allowed = next(user for user in storage.list_users() if user["username"] == "outsider")
        owned = app.create_workspace("Owned Room", owner_user_id=owner["id"])
        explicit = app.create_workspace(
            "Invite Only",
            owner_user_id=owner["id"],
            access_mode="explicit",
            explicit_user_ids=[allowed["id"]],
        )
        hidden = app.create_workspace("Hidden Room", owner_user_id=owner["id"], access_mode="explicit")

        owner_response = self.request("GET", "/api/workspaces", headers={"Cookie": owner_cookie})
        owner_payload = json.loads(owner_response["body"])
        owner_workspaces = {workspace["id"]: workspace for workspace in owner_payload["workspaces"]}
        self.assertTrue(owner_workspaces[owned["id"]]["can_delete"])
        self.assertTrue(owner_workspaces[explicit["id"]]["can_delete"])
        self.assertFalse(owner_workspaces[app.DEFAULT_WORKSPACE_ID]["can_delete"])

        outsider_response = self.request("GET", "/api/workspaces", headers={"Cookie": outsider_cookie})
        outsider_payload = json.loads(outsider_response["body"])
        outsider_ids = {workspace["id"] for workspace in outsider_payload["workspaces"]}
        self.assertIn(explicit["id"], outsider_ids)
        self.assertNotIn(hidden["id"], outsider_ids)
        outsider_workspaces = {workspace["id"]: workspace for workspace in outsider_payload["workspaces"]}
        self.assertFalse(outsider_workspaces[explicit["id"]]["can_delete"])

        root_response = self.request("GET", "/api/workspaces", headers={"Cookie": root_cookie})
        root_payload = json.loads(root_response["body"])
        root_workspaces = {workspace["id"]: workspace for workspace in root_payload["workspaces"]}
        self.assertTrue(root_workspaces[app.DEFAULT_WORKSPACE_ID]["can_delete"])
        self.assertIn(hidden["id"], root_workspaces)

    def test_root_can_delete_default_workspace_and_home_redirects_to_workspaces(self) -> None:
        self.start_server()
        root_cookie = self.root_cookie("root", "root-pass")
        workspaces_page = self.request("GET", "/workspaces", headers={"Cookie": root_cookie})
        token = workspaces_page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]
        self.assertEqual(self.select_workspace(root_cookie, app.DEFAULT_WORKSPACE_ID)["status"], 200)

        delete_response = self.request(
            "DELETE",
            f"/api/workspaces/{app.DEFAULT_WORKSPACE_ID}",
            body=json.dumps({"password": ""}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": root_cookie,
                "X-CSRF-Token": token,
            },
        )

        self.assertEqual(delete_response["status"], 200)
        payload = json.loads(delete_response["body"])
        self.assertNotIn(app.DEFAULT_WORKSPACE_ID, {workspace["id"] for workspace in payload["workspaces"]})
        home = self.request("GET", "/", headers={"Cookie": root_cookie})
        self.assertEqual(home["status"], 303)
        self.assertEqual(home["headers"]["Location"], "/workspaces")

    def test_non_root_cannot_delete_default_workspace(self) -> None:
        self.start_server()
        user_cookie = self.user_cookie("alice", "alice-pass")
        workspaces_page = self.request("GET", "/workspaces", headers={"Cookie": user_cookie})
        token = workspaces_page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]

        delete_response = self.request(
            "DELETE",
            f"/api/workspaces/{app.DEFAULT_WORKSPACE_ID}",
            body=json.dumps({"password": ""}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": user_cookie,
                "X-CSRF-Token": token,
            },
        )

        self.assertEqual(delete_response["status"], 403)
        self.assertIn(app.DEFAULT_WORKSPACE_ID, {workspace["id"] for workspace in app.list_workspaces()})

    def test_non_manager_cannot_delete_another_users_workspace(self) -> None:
        self.start_server()
        owner_cookie = self.user_cookie("owner", "owner-pass")
        outsider_cookie = self.user_cookie("outsider", "outsider-pass")
        owner = next(user for user in storage.list_users() if user["username"] == "owner")
        workspace = app.create_workspace("Owned Room", owner_user_id=owner["id"])
        workspaces_page = self.request("GET", "/workspaces", headers={"Cookie": outsider_cookie})
        token = workspaces_page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]

        delete_response = self.request(
            "DELETE",
            f"/api/workspaces/{workspace['id']}",
            body=json.dumps({"password": ""}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": outsider_cookie,
                "X-CSRF-Token": token,
            },
        )

        self.assertEqual(delete_response["status"], 403)
        self.assertIn(workspace["id"], {item["id"] for item in app.list_workspaces()})
        self.assertEqual(self.select_workspace(owner_cookie, workspace["id"])["status"], 200)

    def test_text_drop_endpoint_adds_text_to_history(self) -> None:
        self.start_server()

        response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "dropped text", "name": "Phone"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response["status"], 200)
        payload = json.loads(response["body"])
        self.assertEqual(payload["latest_text"], "dropped text")
        self.assertEqual(payload["texts"][0]["content"], "dropped text")
        self.assertEqual(payload["texts"][0]["sharer_name"], "Phone")

    def test_file_upload_rejects_payloads_over_size_limit(self) -> None:
        self.start_server()

        response = self.request(
            "POST",
            "/api/upload",
            body=b"",
            headers={
                "Content-Type": "multipart/form-data; boundary=----TooBig",
                "Content-Length": str(config.MAX_FILE_SIZE + 1),
            },
        )

        self.assertEqual(response["status"], 413)

    def test_file_upload_is_rate_limited_per_client_ip(self) -> None:
        config.UPLOAD_RATE_LIMIT_MAX_REQUESTS = 2
        config.UPLOAD_RATE_LIMIT_WINDOW_SECONDS = 60
        self.start_server()

        first = self.upload_request("one.txt", b"payload-1")
        second = self.upload_request("two.txt", b"payload-2")
        third = self.upload_request("three.txt", b"payload-3")

        self.assertEqual(first["status"], 200)
        self.assertEqual(second["status"], 200)
        self.assertEqual(third["status"], 429)
        self.assertEqual(third["headers"]["Retry-After"], "60")

    def test_workspace_delete_logs_privileged_user_password_usage(self) -> None:
        self.start_server()
        cookie = self.root_cookie(password="override")
        workspace = app.create_workspace("Secure", password="vault")

        workspace_page = self.request("GET", "/workspaces", headers={"Cookie": cookie})
        self.assertEqual(workspace_page["status"], 200)
        token = workspace_page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]

        with self.assertLogs("dassiedrop.http", level="WARNING") as captured:
            response = self.request(
                "DELETE",
                f"/api/workspaces/{workspace['id']}",
                body=json.dumps({"password": "override"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "X-CSRF-Token": token,
                },
            )

        self.assertEqual(response["status"], 200)
        self.assertTrue(
            any(
                "Workspace deleted with privileged user password" in message and workspace["id"] in message
                for message in captured.output
            )
        )

    def test_delete_flow_removes_entry_from_follow_up_requests(self) -> None:
        self.start_server()

        upload_response = self.upload_request("delete-me.txt", b"payload")
        self.assertEqual(upload_response["status"], 200)
        file_id = json.loads(upload_response["body"])["files"][0]["id"]

        delete_response = self.request("DELETE", f"/api/file/{file_id}")
        self.assertEqual(delete_response["status"], 200)

        download_response = self.request("GET", f"/download/{file_id}")
        self.assertEqual(download_response["status"], 404)

    def test_configured_share_base_url_is_rendered_into_page(self) -> None:
        config.SHARE_BASE_URL = "http://192.168.1.24:8000/"
        self.start_server()

        home = self.request("GET", "/")

        self.assertEqual(home["status"], 303)
        workspace_page = self.request("GET", "/workspaces", headers={"Cookie": home["headers"]["Set-Cookie"].split(";", 1)[0]})
        self.assertEqual(workspace_page["status"], 200)
        self.assertIn("Create Workspace", workspace_page["text"])

    def test_html_pages_are_not_cacheable(self) -> None:
        self.start_server()

        workspace_page = self.request("GET", "/workspaces")

        self.assertEqual(workspace_page["status"], 200)
        self.assertEqual(
            workspace_page["headers"]["Cache-Control"],
            "no-store, no-cache, must-revalidate",
        )
        self.assertEqual(workspace_page["headers"]["Pragma"], "no-cache")
        self.assertEqual(workspace_page["headers"]["Expires"], "0")

    def test_public_workspace_can_be_opened_directly_by_slug_url(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Carel Space")

        response = self.request("GET", "/w/carel-space")

        self.assertEqual(response["status"], 303)
        self.assertEqual(response["headers"]["Location"], "/")
        cookie = response["headers"]["Set-Cookie"].split(";", 1)[0]
        state = self.request("GET", "/api/state", headers={"Cookie": cookie})
        self.assertEqual(state["status"], 200)
        self.assertEqual(json.loads(state["body"])["workspace"]["id"], workspace["id"])

    def test_openapi_schema_is_publicly_downloadable(self) -> None:
        self.start_server()

        response = self.request("GET", "/openapi.yaml")

        self.assertEqual(response["status"], 200)
        self.assertEqual(response["headers"]["Content-Type"], "application/yaml; charset=utf-8")
        self.assertIn('attachment; filename="openapi.yaml"', response["headers"]["Content-Disposition"])
        self.assertIn("openapi: 3.1.0", response["text"])

    def test_openapi_schema_is_publicly_downloadable_when_access_code_is_enabled(self) -> None:
        self.start_server(access_code="secret-code")

        response = self.request("GET", "/openapi.yaml")

        self.assertEqual(response["status"], 200)
        self.assertIn("openapi: 3.1.0", response["text"])

    def test_duplicate_workspace_names_are_rejected_by_http_api(self) -> None:
        self.start_server()
        page = self.request("GET", "/workspaces")
        token = page["text"].split('<meta name="dassiedrop-csrf-token" content="', 1)[1].split('"', 1)[0]

        first = self.request(
            "POST",
            "/api/workspaces",
            body=json.dumps({"name": "Carel Space", "password": ""}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-CSRF-Token": token},
        )
        duplicate = self.request(
            "POST",
            "/api/workspaces",
            body=json.dumps({"name": "Carel-Space", "password": ""}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-CSRF-Token": token},
        )

        self.assertEqual(first["status"], 200)
        self.assertEqual(duplicate["status"], 400)
        self.assertIn("Workspace name already exists", duplicate["text"])

    def test_protected_workspace_slug_redirects_to_workspace_picker_without_password(self) -> None:
        self.start_server()
        app.create_workspace("Secure Space", password="vault")

        response = self.request("GET", "/w/secure-space")

        self.assertEqual(response["status"], 303)
        self.assertEqual(response["headers"]["Location"], "/workspaces?workspace=secure-space")

    def test_protected_workspace_can_be_selected_by_header_password(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Secure Space", password="vault")

        state = self.request(
            "GET",
            "/api/state?workspace=secure-space",
            headers={"X-Workspace-Password": "vault"},
        )

        self.assertEqual(state["status"], 200)
        self.assertEqual(json.loads(state["body"])["workspace"]["id"], workspace["id"])

    def test_text_share_returns_plain_text(self) -> None:
        self.start_server()

        create_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "Hello world"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(create_response["status"], 200)
        created_entry = json.loads(create_response["body"])["texts"][0]
        self.assertEqual(created_entry["content"], "Hello world")

        latest_text_response = self.request("GET", "/api/latest-text")
        self.assertEqual(latest_text_response["status"], 200)
        latest_text_entry = json.loads(latest_text_response["body"])
        self.assertEqual(latest_text_entry["content"], "Hello world")

        shared_text_response = self.request("GET", f"/s/{created_entry['short_code']}")
        self.assertEqual(shared_text_response["status"], 200)
        self.assertEqual(
            shared_text_response["headers"]["Content-Type"],
            "text/plain; charset=utf-8",
        )
        self.assertEqual(shared_text_response["body"], b"Hello world")

    def test_short_link_requires_workspace_password_when_workspace_is_protected(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Secure Space", password="vault")

        create_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "Hello world"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Workspace-Name": workspace["slug"],
                "X-Workspace-Password": "vault",
            },
        )
        self.assertEqual(create_response["status"], 200)
        created_entry = json.loads(create_response["body"])["texts"][0]

        blocked_share = self.request("GET", f"/s/{created_entry['short_code']}")
        self.assertEqual(blocked_share["status"], 401)
        self.assertEqual(json.loads(blocked_share["body"]), {"message": "Access denied"})

        allowed_share = self.request(
            "GET",
            f"/s/{created_entry['short_code']}",
            headers={"X-Access-Password": "vault"},
        )
        self.assertEqual(allowed_share["status"], 200)
        self.assertEqual(allowed_share["body"], b"Hello world")

    def test_browser_get_to_protected_short_link_shows_password_page(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Secure Space", password="vault")

        create_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "Hello world"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Workspace-Name": workspace["slug"],
                "X-Workspace-Password": "vault",
            },
        )
        self.assertEqual(create_response["status"], 200)
        created_entry = json.loads(create_response["body"])["texts"][0]

        response = self.request(
            "GET",
            f"/s/{created_entry['short_code']}",
            headers={"Accept": "text/html"},
        )

        self.assertEqual(response["status"], 200)
        self.assertIn("Access Password", response["text"])
        self.assertIn(f'action="/s/{created_entry["short_code"]}"', response["text"])

    def test_browser_post_to_protected_short_link_opens_content_with_correct_password(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Secure Space", password="vault")

        create_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "Hello world"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Workspace-Name": workspace["slug"],
                "X-Workspace-Password": "vault",
            },
        )
        self.assertEqual(create_response["status"], 200)
        created_entry = json.loads(create_response["body"])["texts"][0]

        response = self.request(
            "POST",
            f"/s/{created_entry['short_code']}",
            body=b"access_password=vault",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(b"access_password=vault")),
                "Accept": "text/html",
            },
        )

        self.assertEqual(response["status"], 200)
        self.assertEqual(response["body"], b"Hello world")

    def test_browser_post_to_protected_short_link_rerenders_page_on_wrong_password(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Secure Space", password="vault")

        create_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "Hello world"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Workspace-Name": workspace["slug"],
                "X-Workspace-Password": "vault",
            },
        )
        self.assertEqual(create_response["status"], 200)
        created_entry = json.loads(create_response["body"])["texts"][0]

        response = self.request(
            "POST",
            f"/s/{created_entry['short_code']}",
            body=b"access_password=wrong",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(b"access_password=wrong")),
                "Accept": "text/html",
            },
        )

        self.assertEqual(response["status"], 401)
        self.assertIn("Access Password", response["text"])
        self.assertIn("Access denied", response["text"])

    def test_short_link_with_object_password_overrides_workspace_password(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Secure Space", password="vault")

        create_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "Hello world", "hidden": True, "password": "swordfish"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Workspace-Name": workspace["slug"],
                "X-Workspace-Password": "vault",
            },
        )
        self.assertEqual(create_response["status"], 200)
        created_entry = json.loads(create_response["body"])["texts"][0]

        workspace_password_response = self.request(
            "GET",
            f"/s/{created_entry['short_code']}",
            headers={"X-Access-Password": "vault"},
        )
        self.assertEqual(workspace_password_response["status"], 401)
        self.assertEqual(json.loads(workspace_password_response["body"]), {"message": "Access denied"})

        object_password_response = self.request(
            "GET",
            f"/s/{created_entry['short_code']}",
            headers={"X-Access-Password": "swordfish"},
        )
        self.assertEqual(object_password_response["status"], 200)
        self.assertEqual(object_password_response["body"], b"Hello world")

    def test_share_text_endpoint_returns_compact_share_payload(self) -> None:
        self.start_server()

        response = self.request(
            "POST",
            "/api/share-text",
            body=json.dumps({"text": "shell text", "name": "CLI"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response["status"], 200)
        payload = json.loads(response["body"])
        self.assertEqual(payload["type"], "text")
        self.assertEqual(payload["content"], "shell text")
        self.assertEqual(payload["share_path"], f"/s/{payload['short_code']}")
        self.assertEqual(
            payload["share_url"],
            f"http://127.0.0.1:{self.port}{payload['share_path']}",
        )
        self.assertEqual(payload["workspace_id"], app.DEFAULT_WORKSPACE_ID)
        self.assertEqual(payload["workspace_display_name"], app.DEFAULT_WORKSPACE_NAME)
        self.assertEqual(payload["workspace_slug"], app.workspace_slug(app.DEFAULT_WORKSPACE_NAME))
        self.assertEqual(payload["workspace_path"], f"/w/{payload['workspace_slug']}")
        self.assertEqual(payload["workspace_url"], f"http://127.0.0.1:{self.port}{payload['workspace_path']}")

    def test_share_file_endpoint_returns_compact_share_payload(self) -> None:
        self.start_server()

        boundary = "----DassieDropShareBoundary"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="cli.txt"\r\n'
            "Content-Type: text/plain\r\n\r\n"
            "hello from bash"
            f"\r\n--{boundary}\r\n"
            'Content-Disposition: form-data; name="name"\r\n\r\n'
            "CLI"
            f"\r\n--{boundary}--\r\n"
        ).encode("utf-8")
        response = self.request(
            "POST",
            "/api/share-file",
            body=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(body)),
            },
        )

        self.assertEqual(response["status"], 200)
        payload = json.loads(response["body"])
        self.assertEqual(payload["type"], "file")
        self.assertEqual(payload["name"], "cli.txt")
        self.assertEqual(payload["share_path"], f"/s/{payload['short_code']}")
        self.assertEqual(
            payload["share_url"],
            f"http://127.0.0.1:{self.port}{payload['share_path']}",
        )
        self.assertEqual(
            payload["download_url"],
            f"http://127.0.0.1:{self.port}/download/{payload['id']}",
        )
        self.assertEqual(payload["workspace_id"], app.DEFAULT_WORKSPACE_ID)
        self.assertEqual(payload["workspace_display_name"], app.DEFAULT_WORKSPACE_NAME)
        self.assertEqual(payload["workspace_slug"], app.workspace_slug(app.DEFAULT_WORKSPACE_NAME))

    def test_share_endpoints_accept_x_api_key_when_access_code_is_enabled(self) -> None:
        self.start_server(access_code="secret-code")

        text_response = self.request(
            "POST",
            "/api/share-text",
            body=json.dumps({"text": "shell text"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "secret-code",
            },
        )
        self.assertEqual(text_response["status"], 200)
        text_payload = json.loads(text_response["body"])
        self.assertEqual(text_payload["type"], "text")
        self.assertEqual(text_payload["content"], "shell text")

        boundary = "----DassieDropApiKeyBoundary"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="cli.txt"\r\n'
            "Content-Type: text/plain\r\n\r\n"
            "hello from bash"
            f"\r\n--{boundary}--\r\n"
        ).encode("utf-8")
        file_response = self.request(
            "POST",
            "/api/share-file",
            body=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(body)),
                "X-API-Key": "secret-code",
            },
        )
        self.assertEqual(file_response["status"], 200)
        file_payload = json.loads(file_response["body"])
        self.assertEqual(file_payload["type"], "file")
        self.assertEqual(file_payload["name"], "cli.txt")

    def test_api_can_target_workspace_by_slug_header(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Ops Desk")

        create_response = self.request(
            "POST",
            "/api/share-text",
            body=json.dumps({"text": "workspace text"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Workspace-Name": "ops-desk",
            },
        )

        self.assertEqual(create_response["status"], 200)
        payload = json.loads(create_response["body"])
        self.assertEqual(payload["workspace_id"], workspace["id"])
        self.assertEqual(payload["workspace_slug"], "ops-desk")

        state_response = self.request("GET", "/api/state?workspace=ops-desk")
        self.assertEqual(state_response["status"], 200)
        snapshot = json.loads(state_response["body"])
        self.assertEqual(snapshot["workspace"]["id"], workspace["id"])
        self.assertEqual(snapshot["texts"][0]["content"], "workspace text")

    def test_text_update_rejects_non_boolean_hidden_flag(self) -> None:
        self.start_server()

        response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "shared text", "hidden": "yes"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response["status"], 400)

    def test_non_hidden_text_ignores_stray_password(self) -> None:
        self.start_server()

        response = self.request(
            "POST",
            "/api/text",
            body=json.dumps(
                {"text": "shared text", "hidden": False, "password": "vault", "name": "Laptop"}
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        self.assertEqual(response["status"], 200)
        snapshot = json.loads(response["body"])
        entry = snapshot["texts"][0]
        self.assertFalse(entry["hidden"])
        self.assertFalse(entry["password_required"])

        latest_text = app.find_text_entry(entry["id"])
        self.assertIsNotNone(latest_text)
        self.assertIsNone(latest_text.get("password_hash"))

        short_link_response = self.request("GET", f"/s/{entry['short_code']}")
        self.assertEqual(short_link_response["status"], 200)
        self.assertEqual(short_link_response["body"], b"shared text")

    def test_password_protected_text_requires_reveal_password(self) -> None:
        self.start_server()

        create_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps(
                {"text": "classified", "hidden": True, "password": "swordfish"}
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(create_response["status"], 200)
        created_entry = json.loads(create_response["body"])["texts"][0]
        self.assertTrue(created_entry["password_required"])
        self.assertIsNone(created_entry["content"])

        latest_text_response = self.request("GET", "/api/latest-text")
        self.assertEqual(latest_text_response["status"], 200)
        latest_text_entry = json.loads(latest_text_response["body"])
        self.assertIsNone(latest_text_entry["content"])
        self.assertTrue(latest_text_entry["password_required"])

        wrong_reveal = self.request(
            "POST",
            f"/api/text/{created_entry['id']}/reveal",
            body=json.dumps({"password": "wrong"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(wrong_reveal["status"], 403)

        reveal = self.request(
            "POST",
            f"/api/text/{created_entry['id']}/reveal",
            body=json.dumps({"password": "swordfish"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(reveal["status"], 200)
        self.assertEqual(json.loads(reveal["body"])["content"], "classified")

        blocked_share = self.request("GET", f"/s/{created_entry['short_code']}")
        self.assertEqual(blocked_share["status"], 401)

        allowed_share = self.request(
            "GET",
            f"/s/{created_entry['short_code']}",
            headers={"X-Access-Password": "swordfish"},
        )
        self.assertEqual(allowed_share["status"], 200)
        self.assertEqual(allowed_share["body"], b"classified")

    def test_hidden_share_in_protected_workspace_requires_workspace_and_entry_passwords(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Secure Space", password="vault")

        text_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps(
                {"text": "classified", "hidden": True, "password": "swordfish"}
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Workspace-Name": workspace["slug"],
                "X-Workspace-Password": "vault",
            },
        )
        self.assertEqual(text_response["status"], 200)
        text_entry = json.loads(text_response["body"])["texts"][0]

        object_password_only = self.request(
            "GET",
            f"/s/{text_entry['short_code']}",
            headers={"X-Access-Password": "swordfish"},
        )
        self.assertEqual(object_password_only["status"], 200)
        self.assertEqual(object_password_only["body"], b"classified")

        blocked_without_entry = self.request(
            "GET",
            f"/s/{text_entry['short_code']}",
            headers={"X-Access-Password": "vault"},
        )
        self.assertEqual(blocked_without_entry["status"], 401)

    def test_hidden_file_requires_password_for_upload_and_download(self) -> None:
        self.start_server()

        missing_password_upload = self.upload_request("locked.txt", b"secret", hidden=True)
        self.assertEqual(missing_password_upload["status"], 400)

        upload_response = self.upload_request(
            "locked.txt", b"secret", hidden=True, password="vault"
        )
        self.assertEqual(upload_response["status"], 200)
        file_entry = json.loads(upload_response["body"])["files"][0]
        self.assertTrue(file_entry["password_required"])
        self.assertTrue(file_entry["hidden"])

        blocked_download = self.request("GET", f"/download/{file_entry['id']}")
        self.assertEqual(blocked_download["status"], 403)

        allowed_download = self.request(
            "GET",
            f"/download/{file_entry['id']}",
            headers={"X-Entry-Password": "vault"},
        )
        self.assertEqual(allowed_download["status"], 200)
        self.assertEqual(allowed_download["body"], b"secret")

        blocked_share = self.request("GET", f"/s/{file_entry['short_code']}")
        self.assertEqual(blocked_share["status"], 401)

        allowed_share = self.request(
            "GET",
            f"/s/{file_entry['short_code']}",
            headers={"X-Access-Password": "vault"},
        )
        self.assertEqual(allowed_share["status"], 200)
        self.assertEqual(allowed_share["body"], b"secret")

        blocked_preview = self.request("GET", f"/preview/{file_entry['id']}")
        self.assertEqual(blocked_preview["status"], 403)

        allowed_preview = self.request(
            "GET",
            f"/preview/{file_entry['id']}",
            headers={"X-Entry-Password": "vault"},
        )
        self.assertEqual(allowed_preview["status"], 200)
        self.assertEqual(allowed_preview["body"], b"secret")

    def test_workspace_password_is_required_for_direct_file_download_and_preview(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Secure Space", password="vault")

        upload_response = self.upload_request(
            "locked.txt",
            b"secret",
            workspace_slug=workspace["slug"],
            workspace_password="vault",
        )
        self.assertEqual(upload_response["status"], 200)
        file_entry = json.loads(upload_response["body"])["files"][0]

        blocked_download = self.request("GET", f"/download/{file_entry['id']}")
        self.assertEqual(blocked_download["status"], 403)
        self.assertIn("Wrong workspace password", blocked_download["text"])

        allowed_download = self.request(
            "GET",
            f"/download/{file_entry['id']}",
            headers={"X-Workspace-Password": "vault"},
        )
        self.assertEqual(allowed_download["status"], 200)
        self.assertEqual(allowed_download["body"], b"secret")

        blocked_preview = self.request("GET", f"/preview/{file_entry['id']}")
        self.assertEqual(blocked_preview["status"], 403)
        self.assertIn("Wrong workspace password", blocked_preview["text"])

        allowed_preview = self.request(
            "GET",
            f"/preview/{file_entry['id']}",
            headers={"X-Workspace-Password": "vault"},
        )
        self.assertEqual(allowed_preview["status"], 200)
        self.assertEqual(allowed_preview["body"], b"secret")

    def test_workspace_password_override_requires_logged_in_privileged_user(self) -> None:
        self.start_server()
        root = storage.set_user("Root", password="root-pass", api_key="root-api", role="root")
        user_cookie = self.user_cookie("alice", "alice-pass")
        workspace = app.create_workspace("Secure Space", password="vault")
        token = self.csrf_token(user_cookie)

        blocked_enter = self.request(
            "POST",
            f"/api/workspaces/{workspace['id']}/enter",
            body=json.dumps({"password": "root-pass"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": user_cookie,
                "X-CSRF-Token": token,
            },
        )
        self.assertEqual(blocked_enter["status"], 403)
        self.assertIn("Wrong workspace password", blocked_enter["text"])

        root_login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "Root", "password": "root-pass"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(root_login["status"], 200)
        root_cookie = root_login["headers"]["Set-Cookie"].split(";", 1)[0]
        root_token = self.csrf_token(root_cookie)
        allowed_enter = self.request(
            "POST",
            f"/api/workspaces/{workspace['id']}/enter",
            body=json.dumps({"password": "root-pass"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Cookie": root_cookie,
                "X-CSRF-Token": root_token,
            },
        )
        self.assertEqual(allowed_enter["status"], 200)
        self.assertEqual(root["role"], "root")

    def test_direct_file_workspace_override_requires_matching_privileged_user(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Secure Space", password="vault")
        upload_response = self.upload_request(
            "locked.txt",
            b"secret",
            workspace_slug=workspace["slug"],
            workspace_password="vault",
        )
        self.assertEqual(upload_response["status"], 200)
        file_entry = json.loads(upload_response["body"])["files"][0]
        storage.set_user("Root", password="root-pass", api_key="root-api", role="root")
        user_cookie = self.user_cookie("alice", "alice-pass")

        blocked_download = self.request(
            "GET",
            f"/download/{file_entry['id']}",
            headers={"Cookie": user_cookie, "X-Workspace-Password": "root-pass"},
        )
        self.assertEqual(blocked_download["status"], 403)
        self.assertIn("Wrong workspace password", blocked_download["text"])

        admin_cookie = self.root_cookie("Admin", "admin-pass")
        allowed_download = self.request(
            "GET",
            f"/download/{file_entry['id']}",
            headers={"Cookie": admin_cookie, "X-Workspace-Password": "admin-pass"},
        )
        self.assertEqual(allowed_download["status"], 200)
        self.assertEqual(allowed_download["body"], b"secret")

    def test_hidden_file_share_in_protected_workspace_requires_workspace_and_entry_passwords(self) -> None:
        self.start_server()
        workspace = app.create_workspace("Secure Space", password="vault")

        upload_response = self.upload_request(
            "locked.txt",
            b"secret",
            hidden=True,
            password="item-secret",
            workspace_name=workspace["slug"],
            workspace_password="vault",
        )
        self.assertEqual(upload_response["status"], 200)
        file_entry = json.loads(upload_response["body"])["files"][0]

        object_password_only = self.request(
            "GET",
            f"/s/{file_entry['short_code']}",
            headers={"X-Access-Password": "item-secret"},
        )
        self.assertEqual(object_password_only["status"], 200)
        self.assertEqual(object_password_only["body"], b"secret")

        blocked_without_entry = self.request(
            "GET",
            f"/s/{file_entry['short_code']}",
            headers={"X-Access-Password": "vault"},
        )
        self.assertEqual(blocked_without_entry["status"], 401)

    def test_user_login_is_enforced_and_unlocks_api(self) -> None:
        self.start_server(access_code="secret-code")

        home = self.request("GET", "/")
        self.assertEqual(home["status"], 200)
        self.assertIn("Username", home["text"])

        unauthorized = self.request("GET", "/api/state")
        self.assertEqual(unauthorized["status"], 401)

        wrong_login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "admin", "password": "wrong"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(wrong_login["status"], 401)

        login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "admin", "password": "secret-code"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(login["status"], 200)
        cookie = login["headers"]["Set-Cookie"].split(";", 1)[0]

        workspace_list = self.request("GET", "/api/workspaces", headers={"Cookie": cookie})
        self.assertEqual(workspace_list["status"], 200)

        authorized_state = self.request("GET", "/api/state", headers={"Cookie": cookie})
        self.assertEqual(authorized_state["status"], 200)

        protected_latest_text_missing = self.request(
            "GET",
            "/api/latest-text",
            headers={"Cookie": cookie},
        )
        self.assertEqual(protected_latest_text_missing["status"], 404)

        protected_upload = self.upload_with_cookie_session("secure.txt", b"secure-data", cookie)
        self.assertEqual(protected_upload["status"], 200)
        file_id = json.loads(protected_upload["body"])["files"][0]["id"]

        protected_latest_file = self.request(
            "GET",
            "/api/latest-file",
            headers={"Cookie": cookie},
        )
        self.assertEqual(protected_latest_file["status"], 200)
        self.assertEqual(json.loads(protected_latest_file["body"])["id"], file_id)

        protected_latest_file_content = self.request(
            "GET",
            "/api/latest-file/content",
            headers={"Cookie": cookie},
        )
        self.assertEqual(protected_latest_file_content["status"], 200)
        self.assertEqual(protected_latest_file_content["body"], b"secure-data")

        protected_download = self.request(
            "GET",
            f"/download/{file_id}",
            headers={"Cookie": cookie},
        )
        self.assertEqual(protected_download["status"], 200)
        self.assertEqual(protected_download["body"], b"secure-data")

    def test_access_code_auth_accepts_x_api_key_for_state(self) -> None:
        self.start_server(access_code="secret-code")

        unauthorized = self.request("GET", "/api/state")
        self.assertEqual(unauthorized["status"], 401)

        authorized = self.request("GET", "/api/state", headers={"X-API-Key": "secret-code"})
        self.assertEqual(authorized["status"], 200)

    def test_separate_api_key_is_used_for_stateless_api_access(self) -> None:
        self.start_server(access_code="secret-code", api_key="api-secret")

        unauthorized = self.request("GET", "/api/state")
        self.assertEqual(unauthorized["status"], 401)

        old_access_code = self.request("GET", "/api/state", headers={"X-API-Key": "secret-code"})
        self.assertEqual(old_access_code["status"], 401)

        authorized = self.request("GET", "/api/state", headers={"X-API-Key": "api-secret"})
        self.assertEqual(authorized["status"], 200)

    def test_browser_login_uses_user_password_when_api_key_is_configured(self) -> None:
        self.start_server(access_code="secret-code", api_key="api-secret")

        wrong_login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "admin", "password": "api-secret"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(wrong_login["status"], 401)

        login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "admin", "password": "secret-code"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(login["status"], 200)

    def test_websocket_receives_initial_snapshot_and_live_updates(self) -> None:
        self.start_server()

        websocket, handshake, websocket_key, buffered = self.open_websocket()
        self.addCleanup(websocket.close)

        self.assertIn("101 Switching Protocols", handshake)
        expected_accept = app.websocket_accept_value(websocket_key)
        self.assertIn(f"Sec-WebSocket-Accept: {expected_accept}", handshake)

        initial_frame, buffered = self.read_websocket_frame(websocket, buffered)
        initial_snapshot = json.loads(initial_frame.decode("utf-8"))
        self.assertEqual(initial_snapshot["texts"], [])
        self.assertEqual(initial_snapshot["files"], [])

        text_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "live update"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(text_response["status"], 200)

        pushed_frame, buffered = self.read_websocket_frame(websocket, buffered)
        pushed_snapshot = json.loads(pushed_frame.decode("utf-8"))
        self.assertEqual(pushed_snapshot["texts"][0]["content"], "live update")

    def test_websocket_requires_authorization_when_access_code_is_enabled(self) -> None:
        self.start_server(access_code="secret-code")

        unauthorized_socket, handshake, _, _ = self.open_websocket()
        self.addCleanup(unauthorized_socket.close)
        self.assertIn("401", handshake)

        login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "admin", "password": "secret-code"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(login["status"], 200)
        cookie = login["headers"]["Set-Cookie"].split(";", 1)[0]
        enter_response = self.select_workspace(cookie)
        self.assertEqual(enter_response["status"], 200)

        authorized_socket, authorized_handshake, websocket_key, _ = self.open_websocket(
            cookie=cookie
        )
        self.addCleanup(authorized_socket.close)
        self.assertIn("101 Switching Protocols", authorized_handshake)
        expected_accept = app.websocket_accept_value(websocket_key)
        self.assertIn(f"Sec-WebSocket-Accept: {expected_accept}", authorized_handshake)

    def test_websocket_accepts_x_api_key_when_access_code_is_enabled(self) -> None:
        self.start_server(access_code="secret-code")

        connection = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.addCleanup(connection.close)
        websocket_key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET /ws HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {websocket_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "X-API-Key: secret-code\r\n\r\n"
        )
        connection.sendall(request.encode("utf-8"))
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response += chunk
        handshake = response.partition(b"\r\n\r\n")[0].decode("utf-8", errors="replace")
        self.assertIn("101 Switching Protocols", handshake)

    def test_websocket_uses_separate_api_key_when_configured(self) -> None:
        self.start_server(access_code="secret-code", api_key="api-secret")

        connection = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.addCleanup(connection.close)
        websocket_key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET /ws HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {websocket_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "X-API-Key: secret-code\r\n\r\n"
        )
        connection.sendall(request.encode("utf-8"))
        denied = b""
        while b"\r\n\r\n" not in denied:
            chunk = connection.recv(4096)
            if not chunk:
                break
            denied += chunk
        self.assertIn("401", denied.decode("utf-8", errors="replace"))

        allowed = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.addCleanup(allowed.close)
        request = (
            f"GET /ws HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {websocket_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "X-API-Key: api-secret\r\n\r\n"
        )
        allowed.sendall(request.encode("utf-8"))
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = allowed.recv(4096)
            if not chunk:
                break
            response += chunk
        self.assertIn("101 Switching Protocols", response.decode("utf-8", errors="replace"))

    def test_websocket_rejects_unmasked_client_frames(self) -> None:
        self.start_server()
        websocket, handshake, _, buffered = self.open_websocket()
        self.addCleanup(websocket.close)
        self.assertIn("101 Switching Protocols", handshake)
        initial_frame, buffered = self.read_websocket_frame(websocket, buffered)
        self.assertTrue(initial_frame)

        websocket.sendall(b"\x81\x00")
        close_frame = websocket.recv(4)
        self.wait_for_websocket_client_count(0)

        self.assertTrue(close_frame)

    def test_websocket_rejects_oversized_client_frames(self) -> None:
        self.start_server()
        websocket, handshake, _, buffered = self.open_websocket()
        self.addCleanup(websocket.close)
        self.assertIn("101 Switching Protocols", handshake)
        initial_frame, buffered = self.read_websocket_frame(websocket, buffered)
        self.assertTrue(initial_frame)

        oversized_length = config.MAX_WEBSOCKET_FRAME_SIZE + 1
        websocket.sendall(b"\x81\xff" + struct.pack("!Q", oversized_length))
        close_frame = websocket.recv(4)
        self.wait_for_websocket_client_count(0)

        self.assertTrue(close_frame)

    def test_websocket_closes_when_cookie_session_expires(self) -> None:
        self.start_server(access_code="secret-code")

        login = self.request(
            "POST",
            "/login",
            body=json.dumps({"username": "admin", "password": "secret-code"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(login["status"], 200)
        cookie = login["headers"]["Set-Cookie"].split(";", 1)[0]

        websocket, handshake, _, buffered = self.open_websocket(cookie=cookie)
        self.addCleanup(websocket.close)
        self.assertIn("101 Switching Protocols", handshake)
        initial_frame, buffered = self.read_websocket_frame(websocket, buffered)
        self.assertTrue(initial_frame)

        self.current_time += config.SESSION_TTL_SECONDS + 1
        text_response = self.request(
            "POST",
            "/api/text",
            body=json.dumps({"text": "server-side update"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "secret-code",
            },
        )
        self.assertEqual(text_response["status"], 200)

        close_code, buffered = self.read_websocket_close_code(websocket, buffered)
        self.wait_for_websocket_client_count(0)
        self.assertEqual(close_code, 1008)

    def test_latest_endpoints_return_not_found_when_history_is_empty(self) -> None:
        self.start_server()

        latest_text = self.request("GET", "/api/latest-text")
        self.assertEqual(latest_text["status"], 404)

        latest_file = self.request("GET", "/api/latest-file")
        self.assertEqual(latest_file["status"], 404)

        latest_file_content = self.request("GET", "/api/latest-file/content")
        self.assertEqual(latest_file_content["status"], 404)

    def test_short_link_returns_not_found_when_code_is_missing(self) -> None:
        self.start_server()

        response = self.request("GET", "/s/ABCD")

        self.assertEqual(response["status"], 401)
        self.assertEqual(response["headers"]["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(json.loads(response["body"]), {"message": "Access denied"})

    def test_lan_link_does_not_require_api_key_even_when_access_code_is_enabled(self) -> None:
        self.start_server(access_code="secret-code", api_key="api-secret")

        create = self.request(
            "POST",
            "/api/share-text",
            body=json.dumps({"text": "share me"}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "api-secret",
            },
        )
        self.assertEqual(create["status"], 200)
        short_code = json.loads(create["body"])["short_code"]

        response = self.request("GET", f"/s/{short_code}")
        self.assertEqual(response["status"], 200)
        self.assertEqual(response["body"], b"share me")

    def test_help_page_renders_terminal_examples_and_general_usage(self) -> None:
        self.start_server()

        response = self.request("GET", "/help")

        self.assertEqual(response["status"], 200)
        self.assertIn("LAN Link Examples", response["text"])
        self.assertIn("curl -ksSL", response["text"])
        self.assertIn("X-Access-Password", response["text"])
        self.assertIn("bash -c", response["text"])
        self.assertIn("General Use", response["text"])
        self.assertIn("openapi.yaml", response["text"])

    def test_help_footer_shows_update_notice_when_available(self) -> None:
        config.UPDATE_CHECK_ENABLED = True
        self.start_server()
        original_fetch = config.fetch_remote_app_version
        try:
            config.fetch_remote_app_version = lambda *args, **kwargs: "9.9.10"
            app.check_for_updates(force=True)
        finally:
            config.fetch_remote_app_version = original_fetch

        response = self.request("GET", "/help")

        self.assertEqual(response["status"], 200)
        self.assertIn("Update available: v9.9.10", response["text"])
        self.assertIn("update-available", response["text"])

    def test_expired_file_is_removed_from_disk_when_state_is_read(self) -> None:
        self.start_server()

        upload_response = self.upload_request("old.txt", b"old-data")
        self.assertEqual(upload_response["status"], 200)
        file_entry = json.loads(upload_response["body"])["files"][0]
        saved_file = config.UPLOAD_DIR / app.find_file_entry(file_entry["id"])["stored_name"]
        self.assertTrue(saved_file.exists())

        self.current_time += app.EXPIRY_SECONDS + 1
        state_response = self.request("GET", "/api/state")

        self.assertEqual(state_response["status"], 200)
        snapshot = json.loads(state_response["body"])
        self.assertEqual(snapshot["files"], [])
        self.assertFalse(saved_file.exists())


class ScriptTests(unittest.TestCase):
    def test_bash_api_help_doc_mentions_share_endpoints(self) -> None:
        doc = (REPO_ROOT / "docs" / "bash-api.md").read_text(encoding="utf-8")
        self.assertIn("/api/share-text", doc)
        self.assertIn("/api/share-file", doc)
        self.assertIn("openapi.yaml", doc)
        self.assertIn("curl", doc)

    def test_openapi_schema_documents_core_http_api(self) -> None:
        doc = (REPO_ROOT / "docs" / "openapi.yaml").read_text(encoding="utf-8")
        self.assertIn("openapi: 3.1.0", doc)
        self.assertIn("/login:", doc)
        self.assertIn("/api/state:", doc)
        self.assertIn("/api/share-text:", doc)
        self.assertIn("/api/share-file:", doc)
        self.assertIn("/api/workspaces:", doc)
        self.assertIn("X-Workspace", doc)
        self.assertIn("X-API-Key", doc)

    def test_developer_guide_mentions_versioning_and_main_rule(self) -> None:
        doc = (REPO_ROOT / "docs" / "developer-guide.md").read_text(encoding="utf-8")
        self.assertIn("VERSION", doc)
        self.assertIn("Versions roll up when committing to `main`.", doc)

    def test_readme_and_license_cover_local_control_and_isc_license(self) -> None:
        root = REPO_ROOT
        readme = (root / "README.md").read_text(encoding="utf-8")
        license_text = (root / "LICENSE").read_text(encoding="utf-8")
        index_template = (root / "templates" / "index.html").read_text(encoding="utf-8")
        version = (root / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(version, app.get_app_version())
        self.assertIn("No cloud. No syncing. No external account.", readme)
        self.assertIn("docs/api-usage.md", readme)
        self.assertIn("local-first drop zone", readme)
        self.assertIn("Python standard library", readme)
        self.assertIn("ISC License", license_text)
        self.assertIn("Copyright (c) 2026 Carel Vosloo", license_text)
        self.assertIn("ISC licensed.", index_template)
        self.assertIn("If you are not an intended recipient or authorized user", index_template)
        self.assertIn("docs/installation.md", readme)

    def test_security_doc_covers_lan_only_deployment(self) -> None:
        security = (REPO_ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("trusted local networks", security)
        self.assertIn("Do not expose", security)
        self.assertIn("reverse proxy", security)
        self.assertIn("TLS", security)
        self.assertIn("24 hours", security)

    def test_github_ubuntu_install_upgrade_script_uses_github_archive_and_env_file(self) -> None:
        script = (REPO_ROOT / "scripts" / "github-ubuntu-install-upgrade.sh").read_text(encoding="utf-8")
        self.assertIn("--port", script)
        self.assertIn("--https-port", script)
        self.assertIn('PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3.11}"', script)
        self.assertIn('require_command apt-get', script)
        self.assertIn('require_command systemctl', script)
        self.assertIn('ensure_package python3.11 python3.11', script)
        self.assertIn("https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${ref}.tar.gz", script)
        self.assertIn('bash "${SOURCE_DIR}/scripts/install-ubuntu-service.sh"', script)
        self.assertIn('if [[ ! -f "${ENV_FILE}" ]]; then', script)
        self.assertIn('done < "${ENV_FILE}"', script)
        self.assertIn('export "${key}=${value}"', script)
        self.assertIn('export HTTPS_PORT="${HTTPS_PORT_OVERRIDE}"', script)
        self.assertIn('SHARE_BASE_URL=${SHARE_BASE_URL_VALUE}', (REPO_ROOT / "scripts" / "install-ubuntu-service.sh").read_text(encoding="utf-8"))

    def test_github_ubuntu_install_upgrade_script_has_valid_bash_syntax(self) -> None:
        result = subprocess.run(
            ["bash", "-n", "scripts/github-ubuntu-install-upgrade.sh"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_root_compatibility_wrappers_forward_to_scripts_paths(self) -> None:
        ubuntu = (REPO_ROOT / "github-ubuntu-install-upgrade.sh").read_text(encoding="utf-8")
        centos = (REPO_ROOT / "github-centos-stream-install-upgrade.sh").read_text(encoding="utf-8")
        self.assertIn("/scripts/github-ubuntu-install-upgrade.sh", ubuntu)
        self.assertIn('exec bash "${TMP_SCRIPT}" "$@"', ubuntu)
        self.assertIn("/scripts/github-centos-stream-install-upgrade.sh", centos)
        self.assertIn('exec bash "${TMP_SCRIPT}" "$@"', centos)

    def test_root_compatibility_wrappers_have_valid_bash_syntax(self) -> None:
        for path in (
            "github-ubuntu-install-upgrade.sh",
            "github-centos-stream-install-upgrade.sh",
        ):
            result = subprocess.run(
                ["bash", "-n", path],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_github_centos_stream_install_upgrade_script_mentions_dnf_and_env_file(self) -> None:
        script = (REPO_ROOT / "scripts" / "github-centos-stream-install-upgrade.sh").read_text(encoding="utf-8")
        self.assertIn("--port", script)
        self.assertIn("--https-port", script)
        self.assertIn("--silent", script)
        self.assertIn('require_command dnf', script)
        self.assertIn('PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3.11}"', script)
        self.assertIn('dnf -y install "${package_name}"', script)
        self.assertIn('dnf -y install openssl', script)
        self.assertIn('ensure_package python3.11 python3.11', script)
        self.assertIn('HTTPS_VALUE="${HTTPS:-1}"', script)
        self.assertIn('HTTPS_PORT_VALUE="${HTTPS_PORT:-8443}"', script)
        self.assertNotIn("ACCESS_CODE", script)
        self.assertNotIn("API_KEY", script)
        self.assertIn('UPDATE_CHECK_ENABLED_VALUE="${UPDATE_CHECK_ENABLED:-}"', script)
        self.assertIn('resolve_update_check_enabled "${UPDATE_CHECK_ENABLED_VALUE}"', script)
        self.assertIn('read -r -p "Enable daily update checks? [y/N]: " answer </dev/tty', script)
        self.assertIn('UPDATE_CHECK_ENABLED=${UPDATE_CHECK_ENABLED_VALUE}', script)
        self.assertIn('HTTPS_CERT_FILE=${HTTPS_CERT_FILE_VALUE}', script)
        self.assertIn('done < "${ENV_FILE}"', script)
        self.assertIn('SOURCE_DIR}/dassiedrop', script)
        self.assertIn('APP_DIR}/dassiedrop', script)
        self.assertIn('ExecStart=${PYTHON_BIN} ${APP_DIR}/app.py', script)
        self.assertIn('systemctl restart "${SERVICE_NAME}.service"', script)

    def test_github_centos_stream_install_upgrade_script_has_valid_bash_syntax(self) -> None:
        result = subprocess.run(
            ["bash", "-n", "scripts/github-centos-stream-install-upgrade.sh"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_install_script_deploys_assets_and_templates(self) -> None:
        script = (REPO_ROOT / "scripts" / "install-ubuntu-service.sh").read_text(encoding="utf-8")
        self.assertIn("--port", script)
        self.assertIn("--https-port", script)
        self.assertIn("--silent", script)
        self.assertIn('PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3.11}"', script)
        self.assertIn('REPO_DIR}/VERSION', script)
        self.assertIn('APP_DIR}/VERSION', script)
        self.assertIn('REPO_DIR}/dassiedrop', script)
        self.assertIn('APP_DIR}/dassiedrop', script)
        self.assertIn('REPO_DIR}/assets', script)
        self.assertIn('APP_DIR}/assets', script)
        self.assertIn('REPO_DIR}/templates', script)
        self.assertIn('APP_DIR}/templates', script)
        self.assertIn('apt-get install -y python3.11', script)
        self.assertIn('apt-get install -y openssl', script)
        self.assertNotIn("ACCESS_CODE", script)
        self.assertNotIn("API_KEY", script)
        self.assertIn('UPDATE_CHECK_ENABLED_VALUE="${UPDATE_CHECK_ENABLED:-}"', script)
        self.assertIn('resolve_update_check_enabled "${UPDATE_CHECK_ENABLED_VALUE}"', script)
        self.assertIn('read -r -p "Enable daily update checks? [y/N]: " answer </dev/tty', script)
        self.assertIn('UPDATE_CHECK_ENABLED=${UPDATE_CHECK_ENABLED_VALUE}', script)
        self.assertIn('HTTPS_VALUE="${HTTPS:-1}"', script)
        self.assertIn('HTTPS_PORT=${HTTPS_PORT_VALUE}', script)
        self.assertIn('HTTPS_CERT_FILE=${HTTPS_CERT_FILE_VALUE}', script)
        self.assertIn('install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0750 "${CERT_DIR}"', script)
        self.assertIn('ExecStart=${PYTHON_BIN} ${APP_DIR}/app.py', script)
        self.assertIn('systemctl restart "${SERVICE_NAME}.service"', script)

    def test_install_script_has_valid_bash_syntax(self) -> None:
        result = subprocess.run(
            ["bash", "-n", "scripts/install-ubuntu-service.sh"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_uninstall_script_has_valid_bash_syntax(self) -> None:
        result = subprocess.run(
            ["bash", "-n", "scripts/uninstall-ubuntu-service.sh"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_uninstall_centos_stream_script_has_valid_bash_syntax(self) -> None:
        result = subprocess.run(
            ["bash", "-n", "scripts/uninstall-centos-stream-service.sh"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dockerfile_sets_runtime_defaults(self) -> None:
        dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("FROM python:3.12-slim", dockerfile)
        self.assertIn("apt-get install -y --no-install-recommends openssl", dockerfile)
        self.assertIn("UPLOAD_DIR=/data/uploads", dockerfile)
        self.assertIn("COPY dassiedrop ./dassiedrop", dockerfile)
        self.assertIn('VOLUME ["/data"]', dockerfile)
        self.assertIn("EXPOSE 8000 8443", dockerfile)
        self.assertIn("HEALTHCHECK --interval=30s --timeout=5s CMD python3 -c", dockerfile)
        self.assertIn('CMD ["python3", "app.py"]', dockerfile)

    def test_docker_compose_persists_uploads_and_configures_env(self) -> None:
        compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("build: .", compose)
        self.assertIn('${HTTPS_PORT:-8443}:8443', compose)
        self.assertIn("dassiedrop-data:/data", compose)
        self.assertNotIn("ACCESS_CODE:", compose)
        self.assertNotIn("API_KEY:", compose)
        self.assertIn("SHARE_BASE_URL:", compose)
        self.assertIn("HTTPS:", compose)
        self.assertIn("HTTPS_CERT_FILE:", compose)
        self.assertIn("HTTPS_KEY_FILE:", compose)
        self.assertIn("UPLOAD_DIR: /data/uploads", compose)

    def test_docker_proxy_compose_and_caddyfile_are_present(self) -> None:
        proxy_compose = (REPO_ROOT / "docker-compose.proxy.yml").read_text(encoding="utf-8")
        caddyfile = (REPO_ROOT / "docker" / "Caddyfile").read_text(encoding="utf-8")
        self.assertIn("caddy:", proxy_compose)
        self.assertIn("443:443", proxy_compose)
        self.assertIn("tls internal", caddyfile)
        self.assertIn("reverse_proxy dassiedrop:8000", caddyfile)

    def test_installation_doc_mentions_docker_and_https_usage(self) -> None:
        install_doc = (REPO_ROOT / "docs" / "installation.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("## Run With Docker", install_doc)
        self.assertIn("docker build -t dassiedrop .", install_doc)
        self.assertIn("docker compose up -d", install_doc)
        self.assertIn("### Docker With Native HTTPS", install_doc)
        self.assertIn("### Docker With Reverse-Proxy TLS", install_doc)
        self.assertIn("docker-compose.proxy.yml", install_doc)
        self.assertIn("docker/Caddyfile", install_doc)
        self.assertIn("## Run With HTTPS", install_doc)
        self.assertIn("admin` with password `password", install_doc)
        self.assertIn("http://localhost:8000", install_doc)
        self.assertIn("https://localhost:8443", install_doc)
        self.assertIn("## Use Your Own SSL Certificate", install_doc)
        self.assertIn("HTTPS_CERT_FILE=/etc/ssl/certs/dassiedrop.crt", install_doc)
        self.assertIn("HTTPS_KEY_FILE=/etc/ssl/private/dassiedrop.key", install_doc)
        self.assertIn("### Reset The Installed Admin Password", install_doc)
        self.assertIn("cd /opt/dassiedrop", install_doc)
        self.assertIn("PYTHONPATH=/opt/dassiedrop UPLOAD_DIR=/var/lib/dassiedrop/uploads", install_doc)
        self.assertIn("scripts/reset_admin_password.py password", install_doc)
        self.assertIn("disables authenticator app protection", install_doc)
        self.assertIn("By default, the service install enables:", install_doc)
        self.assertIn("sudo HTTPS=0 bash ./scripts/install-ubuntu-service.sh", install_doc)
        self.assertIn("sudo bash ./scripts/uninstall-centos-stream-service.sh", install_doc)
        self.assertIn("sudo HTTPS=0 bash", install_doc)
        self.assertIn("master/scripts/github-ubuntu-install-upgrade.sh", install_doc)
        self.assertIn("master/scripts/github-centos-stream-install-upgrade.sh", install_doc)
        self.assertNotIn("ACCESS_CODE=", install_doc)
        self.assertNotIn("API_KEY=", install_doc)
        self.assertIn("--silent", install_doc)
        self.assertIn("UPDATE_CHECK_ENABLED", install_doc)

    def test_app_can_enable_https_with_self_signed_cert_support(self) -> None:
        config_source = (REPO_ROOT / "dassiedrop" / "config.py").read_text(encoding="utf-8")
        http_support_source = (REPO_ROOT / "dassiedrop" / "http_support.py").read_text(encoding="utf-8")
        self.assertIn('HTTPS_ENABLED = os.environ.get("HTTPS", "").strip().lower() in {"1", "true", "yes", "on"}', config_source)
        self.assertIn('HTTP_PORT = int(os.environ.get("HTTP_PORT", os.environ.get("PORT", "8000")))', config_source)
        self.assertIn('HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "8443"))', config_source)
        self.assertIn("def ensure_https_certificate()", config_source)
        self.assertIn('"openssl"', config_source)
        self.assertIn("context.wrap_socket(server.socket, server_side=True)", http_support_source)

    def test_text_history_reveal_ui_is_inline(self) -> None:
        script = (REPO_ROOT / "assets" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('label.textContent = isMasked ? "Click to reveal" : "Click to copy"', script)
        self.assertIn('toggleVisibilityBtn.textContent = isRevealed ? "👁" : "🙈"', script)
        self.assertNotIn('revealHead.textContent = "Reveal"', script)

    def test_help_template_and_footer_links_exist(self) -> None:
        index_template = (REPO_ROOT / "templates" / "index.html").read_text(encoding="utf-8")
        workspaces_template = (REPO_ROOT / "templates" / "workspaces.html").read_text(encoding="utf-8")
        help_template = (REPO_ROOT / "templates" / "help.html").read_text(encoding="utf-8")
        lan_link_doc = (REPO_ROOT / "docs" / "lan-link-access.md").read_text(encoding="utf-8")
        self.assertIn('href="/help"', index_template)
        self.assertIn('href="/help"', workspaces_template)
        self.assertIn('href="/openapi.yaml"', index_template)
        self.assertIn('href="/openapi.yaml"', workspaces_template)
        self.assertIn('href="/openapi.yaml"', help_template)
        self.assertIn("LAN Link Examples", help_template)
        self.assertIn("General Use", help_template)
        self.assertIn("Workspace password", help_template)
        self.assertIn("Object password", help_template)
        self.assertIn("No password required", help_template)
        self.assertIn("Workspace password via <code>X-Access-Password</code>", help_template)
        self.assertIn("Object password via <code>X-Access-Password</code>", help_template)
        self.assertIn("most specific applicable protection rule", help_template)
        self.assertIn("| Workspace password | Object password | Required access |", lan_link_doc)
        self.assertIn("| Yes | Yes | Object password via `X-Access-Password` |", lan_link_doc)
        self.assertIn("most specific applicable protection rule", lan_link_doc)

    def test_file_history_preview_ui_is_limited_to_known_image_mime_types(self) -> None:
        script = (REPO_ROOT / "assets" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('function isKnownImageMimeType(contentType)', script)
        self.assertIn('contentType.startsWith("image/")', script)
        self.assertIn('previewLink.textContent = "Preview"', script)
        self.assertIn('previewLink.href = `/preview/${encodeURIComponent(file.id)}`', script)

    def test_collapsed_details_summary_includes_saved_time(self) -> None:
        script = (REPO_ROOT / "assets" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("function formatTime(ts)", script)
        self.assertIn("function collapsedDetailsMeta(ts, sharerName)", script)
        self.assertIn("Shared at ${time} by ${source}", script)

    def test_live_snapshot_updates_do_not_clear_unsaved_text(self) -> None:
        script = (REPO_ROOT / "assets" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("renderSnapshot(snapshot)", script)
        self.assertNotIn("if (!pendingTextPush && !isTextFormActive()) {\n    clearEditor();\n  }", script)

    def test_workspace_selection_ui_exists(self) -> None:
        template = (REPO_ROOT / "templates" / "workspaces.html").read_text(
            encoding="utf-8"
        )
        access_template = (REPO_ROOT / "templates" / "workspace_access.html").read_text(
            encoding="utf-8"
        )
        script = (REPO_ROOT / "assets" / "workspaces.js").read_text(
            encoding="utf-8"
        )
        access_script = (REPO_ROOT / "assets" / "workspace-access.js").read_text(
            encoding="utf-8"
        )
        index = (REPO_ROOT / "templates" / "index.html").read_text(
            encoding="utf-8"
        )
        help_template = (REPO_ROOT / "templates" / "help.html").read_text(
            encoding="utf-8"
        )
        users_template = (REPO_ROOT / "templates" / "users.html").read_text(
            encoding="utf-8"
        )
        stylesheet = (REPO_ROOT / "assets" / "app.css").read_text(encoding="utf-8")
        self.assertIn("Create Workspace", template)
        self.assertIn('id="workspaceAccessMode"', template)
        self.assertLess(template.index('id="workspaceAccessMode"'), template.index('id="createWorkspaceBtn"'))
        self.assertIn('class="workspace-create-submit-row"', template)
        self.assertIn(".workspace-create-submit", stylesheet)
        self.assertIn(".access-manager[hidden]", stylesheet)
        self.assertIn("#saveAccessBtn[hidden]", stylesheet)
        self.assertIn('id="workspaceMessageExpiry"', template)
        self.assertIn('value="explicit"', template)
        self.assertIn('fetch("/api/workspaces")', script)
        self.assertNotIn("saveExplicitWorkspaceUsers", script)
        self.assertNotIn("workspace-explicit-editor", script)
        self.assertIn("syncMessageExpiryOptions", script)
        self.assertIn("message_expiry_seconds: messageExpirySeconds", script)
        self.assertIn("__MANAGE_ACCESS_LINK__", index)
        self.assertIn("__MANAGE_ACCESS_HEADER_LINK__", index)
        self.assertIn(".tabs-access-link", stylesheet)
        self.assertIn(".header-access-link", stylesheet)
        self.assertIn(".header-lock-icon", stylesheet)
        self.assertIn("/assets/access-lock.svg", (REPO_ROOT / "dassiedrop" / "route_pages.py").read_text(encoding="utf-8"))
        self.assertIn("@media (max-width: 900px)", stylesheet)
        self.assertIn(".tabs-access-link {\n    display: none;", stylesheet)
        self.assertIn('id="hasAccessUsers"', access_template)
        self.assertIn('id="noAccessUsers"', access_template)
        self.assertIn('id="workspacePasswordPanel"', access_template)
        self.assertIn("__PASSWORD_PANEL_HIDDEN__", access_template)
        self.assertIn("__ACCESS_MANAGER_HIDDEN__", access_template)
        self.assertIn('id="workspaceAccessPassword"', access_template)
        self.assertIn('/assets/password-toggle.js', access_template)
        self.assertIn('fetch("/api/workspaces/access")', access_script)
        self.assertIn('/password`, {', access_script)
        self.assertIn('workspace.access_mode === "password"', access_script)
        self.assertIn("moveSelected", access_script)
        self.assertIn("Save Access", access_template)
        self.assertIn('href="/workspaces"', index)
        self.assertIn('class="hero-brand-link"', index)
        self.assertIn('/assets/DassieDrop-dassie-icon.png', index)
        self.assertIn("DassieDrop</span>", index)
        self.assertIn('class="workspace-pill"', index)
        self.assertIn('id="workspaceSelector"', index)
        self.assertIn('class="workspace-selector-wrap"', index)
        self.assertIn('class="workspace-pill-label"', index)
        self.assertIn('aria-label="Current workspace: __WORKSPACE_NAME__"', index)
        self.assertIn('title="Current workspace: __WORKSPACE_NAME__"', index)
        self.assertNotIn("Share text and files across your network", index)
        self.assertIn("DassieDrop v__APP_VERSION__", index)
        self.assertIn('class="hero-title-row hero-title-row-workspace"', template)
        self.assertIn('class="hero-brand-link"', template)
        for page in (index, template, help_template, users_template):
            self.assertIn('<a class="hero-brand-link" href="/workspaces">', page)
            self.assertIn('href="https://github.com/vossie/DassieDrop"', page)
            self.assertIn('href="/logout"', page)
        self.assertNotIn("Choose a workspace or create a new one", template)
        self.assertNotIn("window.prompt", script)
        self.assertIn("function confirmWorkspaceDelete(workspace)", script)
        self.assertIn("Are you sure you want to delete ${workspace.name}? All data will be lost.", script)
        self.assertIn('className = "workspace-auth-row"', script)
        self.assertIn("if (workspace.can_delete) {", script)
        self.assertIn('li.addEventListener("click"', script)
        self.assertIn('if (event.target.closest("button, input, label, select, a")) {', script)
        self.assertIn('const requestedWorkspaceSlug = new URLSearchParams(window.location.search).get("workspace") || ""', script)
        self.assertIn('window.addEventListener("pageshow"', script)
        self.assertIn('window.addEventListener("pageshow"', (REPO_ROOT / "assets" / "app.js").read_text(encoding="utf-8"))
        self.assertLess(template.index("<h2>Create Workspace</h2>"), template.index("<h2>Workspaces</h2>"))

    def test_login_form_uses_stacked_full_width_controls(self) -> None:
        template = (REPO_ROOT / "templates" / "login.html").read_text(
            encoding="utf-8"
        )
        stylesheet = (REPO_ROOT / "assets" / "login.css").read_text(
            encoding="utf-8"
        )
        script = (REPO_ROOT / "assets" / "login.js").read_text(
            encoding="utf-8"
        )

        self.assertIn('class="login-form"', template)
        self.assertIn('id="rememberUsername"', template)
        self.assertIn('id="loginTotpCode"', template)
        self.assertLess(template.index('id="loginUsername"'), template.index('id="loginPassword"'))
        self.assertIn(".login-form {\n  display: grid;\n  gap: 12px;\n}", stylesheet)
        self.assertIn(".remember-row {", stylesheet)
        self.assertIn("input {\n  width: 100%;\n  min-width: 0;", stylesheet)
        self.assertIn('const rememberedUsernameKey = "dassiedrop.rememberedUsername"', script)
        self.assertIn("totp_code", script)
        self.assertIn("Authenticator code required", script)
        self.assertIn("window.localStorage.setItem(rememberedUsernameKey, username)", script)
        self.assertNotIn("localStorage.setItem(rememberedUsernameKey, loginPassword", script)

    def test_user_edit_page_exposes_authenticator_setup(self) -> None:
        template = (REPO_ROOT / "templates" / "user_edit.html").read_text(
            encoding="utf-8"
        )
        script = (REPO_ROOT / "assets" / "user-edit.js").read_text(
            encoding="utf-8"
        )
        stylesheet = (REPO_ROOT / "assets" / "app.css").read_text(
            encoding="utf-8"
        )

        self.assertIn("Authenticator app", template)
        self.assertIn('id="setupTotpBtn"', template)
        self.assertIn('id="totpQrCode"', template)
        self.assertIn('id="totpServerTime"', template)
        self.assertNotIn('id="totpServerCode"', template)
        self.assertIn('id="totpSecret"', template)
        self.assertIn("totpQrCode.innerHTML", script)
        self.assertIn("totpServerTime.textContent", script)
        self.assertNotIn("totpServerCode.textContent", script)
        self.assertIn("/totp/setup", script)
        self.assertIn("/totp/confirm", script)
        self.assertIn(".totp-qr-code", stylesheet)
        self.assertIn(".totp-setup-panel", stylesheet)

    def test_text_panel_exposes_paste_and_send_control(self) -> None:
        index = (REPO_ROOT / "templates" / "index.html").read_text(
            encoding="utf-8"
        )
        script = (REPO_ROOT / "assets" / "app.js").read_text(
            encoding="utf-8"
        )
        css = (REPO_ROOT / "assets" / "app.css").read_text(
            encoding="utf-8"
        )
        self.assertIn('id="pasteSendBtn"', index)
        self.assertIn('/assets/cloud_1434863.png', index)
        self.assertIn('const pasteSendBtn = document.getElementById("pasteSendBtn");', script)
        self.assertIn("async function pasteAndSendText()", script)
        self.assertIn("const clipboardReadAvailable = !!(window.isSecureContext && navigator.clipboard && navigator.clipboard.readText);", script)
        self.assertIn('textEditorWrap.classList.add("clipboard-read-unavailable");', script)
        self.assertIn("window.isSecureContext", script)
        self.assertIn('const pasted = document.execCommand("paste");', script)
        self.assertIn("navigator.clipboard.readText()", script)
        self.assertIn("Clipboard read requires HTTPS or localhost.", script)
        self.assertIn('if (clipboardReadAvailable && pasteSendBtn) {', script)
        self.assertIn('pasteSendBtn.addEventListener("click", pasteAndSendText);', script)
        self.assertIn(".hero-brand-link", css)
        self.assertIn(".hero-title-text", css)
        self.assertIn(".workspace-selector-wrap", css)
        self.assertIn(".workspace-selector-hint", css)
        self.assertIn(".workspace-pill-label", css)
        self.assertIn(".paste-send-btn", css)
        self.assertIn(".workspace-pill", css)
        self.assertIn(".text-editor-wrap.clipboard-read-unavailable .paste-send-btn", css)
        login_script = (REPO_ROOT / "assets" / "login.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('window.location.href = "/?workspace_hint=1";', login_script)
        self.assertIn("Click here to change workspace", script)
        self.assertIn('params.get("workspace_hint") !== "1"', script)

    def test_legacy_uninstall_script_has_valid_bash_syntax(self) -> None:
        result = subprocess.run(
            ["bash", "-n", "scripts/uninstall-legacy-landrop-service.sh"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
