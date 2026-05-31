# Bash API Help

OpenAPI schema: [openapi.yaml](openapi.yaml)

DassieDrop exposes bash-friendly endpoints for automation, including workspace-aware sharing:

- `POST /api/share-text`
- `POST /api/share-file`
- `GET /api/workspaces`
- `POST /api/workspaces`

Share endpoints return a compact JSON payload with the generated short code, LAN share URL, and workspace metadata.

LAN link behavior is documented separately in [lan-link-access.md](lan-link-access.md).

## Workspace Selection

Workspace-aware requests can target a workspace with any of these:

- `X-Workspace: <workspace-selector>`
- `?workspace=<workspace-selector>`

Treat the workspace selector as an opaque string. Pass back the value the API gives you, exactly as-is.

The older `X-Workspace-ID`, `X-Workspace-Slug`, `X-Workspace-Name`, `workspace_slug`, and `workspace_name` aliases still work for compatibility, but they are no longer the public contract.

Protected workspaces can also use:

- `X-Workspace-Password: <workspace-password>`

User login passwords do not work as workspace passwords. Admin and super-admin users can manage restricted workspaces, but entering a password-protected workspace still requires the workspace password. For explicit-access workspaces, admins and super-admins can add themselves through access management before entering.

List workspaces:

```bash
curl -sS http://127.0.0.1:8000/api/workspaces
```

Create a workspace:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -X POST \
  -d '{"name":"ops-desk","password":"vault","expiry_seconds":86400}' \
  http://127.0.0.1:8000/api/workspaces
```

Set `expiry_seconds` to `0` for a workspace whose workspace record never expires automatically. Use `message_expiry_seconds` to control message and file expiry; messages and files cannot outlive the workspace. Workspace names must be unique after normalisation, so `Ops Desk` and `Ops-Desk` conflict.

Create an explicit-access workspace from automation:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: owner-user-api-key' \
  -X POST \
  -d '{"name":"ops-private","access_mode":"explicit","explicit_usernames":["alice","bob"]}' \
  http://127.0.0.1:8000/api/workspaces
```

Replace the explicit access list later:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: owner-user-api-key' \
  -X POST \
  -d '{"usernames":["bob"]}' \
  http://127.0.0.1:8000/api/workspaces/WORKSPACE_ID/users
```

Read state for a workspace by slug:

```bash
curl -sS \
  -H 'X-Workspace: ops-desk' \
  http://127.0.0.1:8000/api/state
```

## Share Text

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -X POST \
  -d '{
    "text": "hello from bash",
    "name": "CLI"
  }' \
  http://127.0.0.1:8000/api/share-text
```

Example response:

```json
{
  "type": "text",
  "id": "4b6a6d7c8e9f0123",
  "short_code": "AbC123XyZ9",
  "share_path": "/s/AbC123XyZ9",
  "share_url": "http://127.0.0.1:8000/s/AbC123XyZ9",
  "hidden": false,
  "password_required": false,
  "created_at": 1714672800.0,
  "expires_at": 1714759200.0,
  "workspace_id": "default",
  "workspace_display_name": "Default",
  "workspace_slug": "default",
  "workspace_path": "/w/default",
  "workspace_url": "http://127.0.0.1:8000/w/default",
  "content": "hello from bash"
}
```

Hidden text example:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -X POST \
  -d '{
    "text": "secret note",
    "name": "CLI",
    "hidden": true,
    "password": "vault"
  }' \
  http://127.0.0.1:8000/api/share-text
```

Send text to a specific workspace:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -H 'X-Workspace: ops-desk' \
  -X POST \
  -d '{
    "text": "hello from ops",
    "name": "CLI"
  }' \
  http://127.0.0.1:8000/api/share-text
```

## Share File

```bash
curl -sS \
  -X POST \
  -F 'file=@./example.txt' \
  -F 'name=CLI' \
  http://127.0.0.1:8000/api/share-file
```

Example response:

```json
{
  "type": "file",
  "id": "18f7d6c5b4a39281",
  "short_code": "Qw7N4LmP2x",
  "share_path": "/s/Qw7N4LmP2x",
  "share_url": "http://127.0.0.1:8000/s/Qw7N4LmP2x",
  "hidden": false,
  "password_required": false,
  "created_at": 1714672800.0,
  "expires_at": 1714759200.0,
  "workspace_id": "default",
  "workspace_display_name": "Default",
  "workspace_slug": "default",
  "workspace_path": "/w/default",
  "workspace_url": "http://127.0.0.1:8000/w/default",
  "name": "example.txt",
  "size": 42,
  "download_path": "/download/18f7d6c5b4a39281",
  "download_url": "http://127.0.0.1:8000/download/18f7d6c5b4a39281"
}
```

Hidden file example:

```bash
curl -sS \
  -X POST \
  -F 'file=@./secret.pdf' \
  -F 'name=CLI' \
  -F 'hidden=true' \
  -F 'password=vault' \
  http://127.0.0.1:8000/api/share-file
```

Upload a file into a specific workspace:

```bash
curl -sS \
  -H 'X-Workspace: ops-desk' \
  -X POST \
  -F 'file=@./example.txt' \
  -F 'name=CLI' \
  http://127.0.0.1:8000/api/share-file
```

## API Key

If DassieDrop is protected, send a user's automation key as `X-API-Key`:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-user-api-key' \
  -X POST \
  -d '{"text":"hello again"}' \
  http://127.0.0.1:8000/api/share-text
```

You can do the same for file uploads:

```bash
curl -sS \
  -H 'X-API-Key: your-user-api-key' \
  -X POST \
  -F 'file=@./example.txt' \
  http://127.0.0.1:8000/api/share-file
```

And combine API key plus workspace targeting:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-user-api-key' \
  -H 'X-Workspace: ops-desk' \
  -X POST \
  -d '{"text":"hello again"}' \
  http://127.0.0.1:8000/api/share-text
```

If you still want browser-style session auth from bash, you can log in first, fetch a page to read the CSRF token, and reuse both the session cookie and `X-CSRF-Token`:

```bash
curl -sS -c cookies.txt \
  -H 'Content-Type: application/json' \
  -X POST \
  -d '{"username":"admin","password":"password"}' \
  http://127.0.0.1:8000/login

CSRF_TOKEN="$(
  curl -sS -b cookies.txt http://127.0.0.1:8000/ \
    | sed -n 's/.*name="dassiedrop-csrf-token" content="\([^"]*\)".*/\1/p'
)"
```

Then pass both values on later cookie-authenticated mutation requests:

```bash
curl -sS -b cookies.txt \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -X POST \
  -d '{"text":"hello again"}' \
  http://127.0.0.1:8000/api/share-text
```

For automation, prefer `X-API-Key`; it does not need CSRF. User passwords are only for browser login, not API authentication. LAN links under `/s/{SHORT-CODE}` do not use `X-API-Key`; use `X-Access-Password` there only when a password is required.
