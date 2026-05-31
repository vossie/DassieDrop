# Changelog

## 1.1.2 - 2026-05-31

- Fixed authenticator setup over browser keep-alive connections by draining the setup request body before confirmation.
- Removed the temporary server check code from the authenticator setup UI.
- Added an installed-service admin password reset script that also clears authenticator protection.
- Restricted authenticator setup to the logged-in user's own account; super-admin users can disable another user's authenticator but cannot enroll one for them.

## 1.1.1 - 2026-05-31

- Added local user management with super-admin, admin, and user roles, per-user API keys, browser login, remember-username support, and logout links.
- Replaced the old global app access code, global API key, and workspace super password with the user system. New installs create a super-admin user named `admin` with password `password`.
- Enforced that at least one super-admin user always remains; super-admin users can manage every account, while non-super-admin users can only update their own password and API key.
- Added workspace access modes: public, password-protected, and explicit user access. Workspace owners, admins, and super-admin users can manage access.
- Associated custom workspaces with the user that created them.
- Added workspace-level expiry and message/file expiry controls. Message and file expiry is capped so entries cannot outlive their workspace, and startup migration repairs older workspace expiry records.
- Allowed super-admin users to delete the default workspace. If no workspace named Default exists, the app now lands on the workspace selector.
- Hid inaccessible explicit workspaces and unavailable delete actions from users without permission.
- Added password-protected workspace access management so owners, admins, and super-admin users can change the workspace password.
- Prevented duplicate workspace names after normalisation and duplicate usernames after normalisation.
- Added login request rate limiting on top of wrong-password lockout to reduce brute-force and request-flood pressure on the login endpoint.
- Restricted workspace password override to the logged-in admin/super-admin user's own password; normal users can no longer unlock a workspace with someone else's privileged password.
- Added versioned CSS and JavaScript asset URLs so upgraded deployments do not keep using stale login/workspace styling from the browser cache.
- Migrated legacy app access-code and API-key hashes into the first `admin` super-admin user during 1.0.x upgrades, including repair for installs that already bootstrapped `admin/password`.
- Added optional per-user authenticator app login codes with dependency-free TOTP and QR-code setup, including shorter Google Authenticator-compatible QR payloads, stable pending setup secrets, setup-code verification, duplicate-submit protection, request-body draining for browser keep-alive requests, visible server time, and wider clock-skew tolerance.
- Updated the footer, workspace selector layout, mobile access controls, and password visibility controls.
- Split the HTTP route handler into focused route mixins to make routing, pages, management actions, uploads, static serving, and WebSockets easier to maintain.

## 1.0.40 - 2026-05-08

- Enforced workspace protection on direct `/download/{fileId}` and `/preview/{fileId}` access. Protected workspaces now require an authorized workspace session or `X-Workspace-Password` even for direct file URLs.
- Moved workspace password hashing and verification out of the main shared state lock in the creation and selection paths to reduce PBKDF2 lock contention.
- Added rate limiting for workspace creation requests.
- Exposed the OpenAPI schema from the running app at `/openapi.yaml`.
- Bundled the OpenAPI schema into the app package so installed deployments can serve it without relying on the repo `docs/` directory.
- Added clickable OpenAPI links in the Help API section and in the main footer beside `Help`.

## 1.0.39 - 2026-05-07

- Tightened workspace identifiers to the canonical `a-z`, `0-9`, `-`, `_`, and `.` character set.
- Changed workspace entry to resolve `POST /api/workspaces/{workspace}/enter` by selector string instead of a raw workspace id.

## 1.0.38 - 2026-05-07

- Simplified the public workspace selector contract to one opaque, case-sensitive string via `X-Workspace` or `workspace`.
- The OpenAPI schema and Markdown docs now treat `X-Workspace-ID`, `X-Workspace-Slug`, `X-Workspace-Name`, `workspace_slug`, and `workspace_name` as compatibility aliases instead of first-class API inputs.

## 1.0.37 - 2026-05-07

- Breaking API change: share payloads now use `workspace_display_name` instead of `workspace_name` to make the display-name field explicit.
- API selector terminology now prefers `X-Workspace-Slug` and `workspace_slug`, while the older `X-Workspace-Name` and `workspace_name` request aliases remain supported for compatibility.
- OpenAPI and Markdown docs were updated to reflect the current API behavior and authenticated upload examples.
