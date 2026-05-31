import json

from dassiedrop import auth, config, state, storage

import app
from tests.support import CoreStateTestCase, make_app_handler


class AuthTests(CoreStateTestCase):
    def test_user_auth_blocks_unauthorised_access_and_allows_valid_api_key(self) -> None:
        storage.set_user("admin", password="secret-pass", api_key="api-secret", role="root")

        unauthorized_handler = make_app_handler(headers={})
        self.assertFalse(auth.is_authorized(unauthorized_handler))

        authorized_handler = make_app_handler(headers={"X-API-Key": "api-secret"})
        self.assertTrue(auth.is_authorized(authorized_handler))

        password_handler = make_app_handler(headers={"X-API-Key": "secret-pass"})
        self.assertFalse(auth.is_authorized(password_handler))
        self.assertIsNotNone(auth.login_user("admin", "secret-pass"))
        self.assertIsNone(auth.login_user("admin", "wrong"))

    def test_x_api_key_does_not_fallback_to_user_password(self) -> None:
        storage.set_user("admin", password="secret-pass", api_key="", role="root")

        authorized_handler = make_app_handler(headers={"X-API-Key": "secret-pass"})
        self.assertFalse(auth.is_authorized(authorized_handler))

    def test_user_api_key_authorizes_requests(self) -> None:
        storage.set_user("admin", password="stored-pass", api_key="stored-api", role="root")
        api_handler = make_app_handler(headers={"X-API-Key": "stored-api"})

        self.assertTrue(auth.is_authorized(api_handler))
        self.assertFalse(auth.access_code_is_valid("stored-pass"))

    def test_password_protected_items_require_correct_password(self) -> None:
        app.add_text_entry("classified", hidden=True, password="vault")
        entry = app.find_text_entry(app.get_snapshot()["texts"][0]["id"])

        self.assertIsNotNone(entry)
        self.assertFalse(app.entry_password_is_valid(entry, "wrong"))
        self.assertTrue(app.entry_password_is_valid(entry, "vault"))

    def test_hidden_items_are_not_visible_without_proper_access(self) -> None:
        app.add_text_entry("classified", hidden=True, password="vault")

        latest = app.get_latest_text_entry()
        self.assertIsNotNone(latest)
        self.assertIsNone(latest["content"])
        self.assertTrue(latest["password_required"])

    def test_sessions_expire_after_ttl(self) -> None:
        session_id = auth.create_authorized_session()
        handler = make_app_handler(headers={"Cookie": f"session={session_id}"})

        session_key, session = auth.get_session(handler)
        self.assertEqual(session_key, session_id)
        self.assertIsNotNone(session)

        self.current_time += config.SESSION_TTL_SECONDS + 1
        session_key, session = auth.get_session(handler)

        self.assertIsNone(session_key)
        self.assertIsNone(session)

    def test_cleanup_authorized_sessions_removes_expired_sessions(self) -> None:
        session_id = auth.create_authorized_session()

        self.current_time += config.SESSION_TTL_SECONDS + 1
        auth.cleanup_authorized_sessions()

        self.assertNotIn(session_id, state.authorized_sessions)
