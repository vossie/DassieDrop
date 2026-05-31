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
    parser.add_argument(
        "--role",
        choices=storage.USER_ROLES + ("root",),
        default=None,
        help="Optional role to set: super-admin, admin, or user. Legacy root is accepted as super-admin.",
    )
    args = parser.parse_args()

    username_key = args.username.strip().lower()
    if not username_key:
        print("username is required", file=sys.stderr)
        return 2
    if not args.password:
        print("password is required", file=sys.stderr)
        return 2

    migrated_roles = storage.migrate_legacy_root_roles()
    storage.load_persisted_files()
    user = next(
        (candidate for candidate in storage.list_users() if candidate["username"].lower() == username_key),
        None,
    )
    if user is None:
        print(f"user not found: {args.username}", file=sys.stderr)
        return 1

    if args.role is not None:
        user = storage.update_user(
            user["id"],
            user["username"],
            password=args.password,
            role=args.role,
        )
        storage.update_user_secrets(user["id"], clear_totp=True)
    else:
        user = storage.update_user_secrets(user["id"], password=args.password, clear_totp=True)
    suffix = f"; migrated {migrated_roles} legacy root role(s)" if migrated_roles else ""
    print(f"{user['username']} password reset; role {user['role']}; authenticator disabled{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
