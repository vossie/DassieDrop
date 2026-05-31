# Security

DassieDrop is designed for trusted local networks.

- Designed for trusted LANs.
- Do not expose DassieDrop directly to the internet.
- If you need remote access, put it behind a reverse proxy with TLS and require user login.
- New installs create a local root user named `admin` with password `password`; change it after first login.
- Authenticator app codes can be enabled per user for an extra login factor.
- Files and messages expire after 24 hours by default unless the workspace policy says otherwise.
- Passwords and API keys are stored as salted hashes, not plaintext.
