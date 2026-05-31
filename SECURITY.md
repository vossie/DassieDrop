# Security

DassieDrop is designed for trusted local networks.

- Designed for trusted LANs.
- Do not expose DassieDrop directly to the internet.
- If you need remote access, put it behind a reverse proxy with TLS and require user login.
- New installs create a local super-admin user named `admin` with password `password`; change it after first login.
- Authenticator app codes can be enabled per user for an extra login factor.
- API automation uses per-user `X-API-Key` values. Browser login passwords are not API keys.
- Workspace passwords are separate from user passwords. Admin and super-admin passwords do not unlock password-protected workspaces.
- Files and messages expire after 24 hours by default unless the workspace policy says otherwise.
- Passwords and API keys are stored as salted hashes, not plaintext.
