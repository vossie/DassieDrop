import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import app
from dassiedrop import config
from dassiedrop import storage


REPO_ROOT = Path(__file__).resolve().parents[1]


class ScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory()
        self.original_upload_dir = config.UPLOAD_DIR
        config.UPLOAD_DIR = Path(self.temp_dir.name) / "uploads"
        app.ensure_upload_dir()

    def tearDown(self) -> None:
        config.UPLOAD_DIR = self.original_upload_dir
        self.temp_dir.cleanup()

    def run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["UPLOAD_DIR"] = str(config.UPLOAD_DIR)
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "reset_access_code.py"), *args],
            cwd=str(REPO_ROOT),
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_reset_access_code_script_updates_shelved_hash(self) -> None:
        result = self.run_script("new-code")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Stored access code reset", result.stdout)
        settings = storage.read_shelved_settings()
        self.assertTrue(app.verify_password("new-code", settings["access_code_hash"]))
        self.assertFalse(app.verify_password("old-code", settings["access_code_hash"]))

    def test_reset_access_code_script_can_clear_stored_hash(self) -> None:
        self.assertEqual(self.run_script("new-code").returncode, 0)

        result = self.run_script("--clear")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Stored access code cleared", result.stdout)
        settings = storage.read_shelved_settings()
        self.assertIsNone(settings["access_code_hash"])


if __name__ == "__main__":
    unittest.main()
