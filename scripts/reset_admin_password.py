#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from dassiedrop import storage


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reset a DassieDrop user's password and clear authenticator protection."
    )
    parser.add_argument("password", help="Replacement password")
    parser.add_argument(
        "--username",
        default="admin",
        help="Username to reset. Defaults to admin.",
    )
    args = parser.parse_args()

    username_key = args.username.strip().lower()
    if not username_key:
        print("username is required", file=sys.stderr)
        return 2
    if not args.password:
        print("password is required", file=sys.stderr)
        return 2

    storage.load_persisted_files()
    user = next(
        (candidate for candidate in storage.list_users() if candidate["username"].lower() == username_key),
        None,
    )
    if user is None:
        print(f"user not found: {args.username}", file=sys.stderr)
        return 1

    storage.update_user_secrets(user["id"], password=args.password, clear_totp=True)
    print(f"{user['username']} password reset; authenticator disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
