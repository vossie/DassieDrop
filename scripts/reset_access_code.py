#!/usr/bin/env python3
import argparse
import os
import shelve
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reset the stored DassieDrop web access code."
    )
    parser.add_argument(
        "access_code",
        help="New web access code to store. Use --clear instead to remove the stored access code.",
        nargs="?",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Remove the stored access code hash.",
    )
    parser.add_argument(
        "--upload-dir",
        help="Upload directory containing the DassieDrop shelve index. Defaults to UPLOAD_DIR or ./uploads.",
    )
    return parser.parse_args()


def configure_import_path(upload_dir: str | None) -> None:
    if upload_dir:
        os.environ["UPLOAD_DIR"] = upload_dir
    sys.path.insert(0, str(REPO_ROOT))


def main() -> int:
    args = parse_args()
    if args.clear and args.access_code:
        print("Pass either a new access code or --clear, not both.", file=sys.stderr)
        return 2
    if not args.clear and not args.access_code:
        print("Pass a new access code, or use --clear.", file=sys.stderr)
        return 2

    configure_import_path(args.upload_dir)

    from dassiedrop import storage

    storage.ensure_upload_dir()
    settings = storage.read_shelved_settings()
    if args.clear:
        settings["access_code_hash"] = None
        action = "cleared"
    else:
        access_code = args.access_code.strip()
        if not access_code:
            print("Access code cannot be blank. Use --clear to remove it.", file=sys.stderr)
            return 2
        settings["access_code_hash"] = storage.hash_password(access_code)
        action = "reset"

    settings = storage.normalize_app_settings(settings)
    try:
        with shelve.open(str(storage.uploads_index_path()), flag="c") as index:
            index[storage.PERSISTED_SETTINGS_KEY] = settings
            index.sync()
    except Exception as exc:
        print(f"Could not update settings store: {exc}", file=sys.stderr)
        return 1

    print(f"Stored access code {action}. Restart DassieDrop for the change to take effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
