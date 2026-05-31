# DassieDrop Installation

Use this guide for local startup, Docker, and server installs.

## Quick Start

```bash
./.venv/bin/python app.py
```

Then open:

```text
http://127.0.0.1:8000
```

From other devices on the same network:

```text
http://<this-machine-ip>:8000
```

## Windows Portable Build

Download the zip file from the [GitHub Releases](https://github.com/vossie/DassieDrop/releases) page. It contains:

- `dassiedrop.exe` — the application
- `dassiedrop.env.example` — a configuration template

Extract both files to the same folder.

Double-click `dassiedrop.exe`, or run it from Command Prompt or PowerShell:

```text
dassiedrop.exe
```

Then open:

```text
http://127.0.0.1:8000
```

From other devices on the same network:

```text
http://<this-machine-ip>:8000
```

### Windows Security Warning

When you first run `dassiedrop.exe`, Windows Defender SmartScreen may show a warning:
"Microsoft Defender SmartScreen prevented an unrecognised app from starting."

This appears because the binary is not signed with a code signing certificate. It is safe to run. To proceed:

1. Click **More info**
2. Click **Run anyway**

The warning will appear each time until the app accumulates sufficient download reputation with Microsoft, or until the binary is signed with a trusted code signing certificate.

### Configuration

Copy `dassiedrop.env.example` to `dassiedrop.env` in the same folder as `dassiedrop.exe`, then uncomment and edit the settings you want to change:

```ini
HTTP_PORT=8000
UPLOAD_DIR=C:\DassieDrop\uploads
```

Settings are applied in this priority order:

1. Environment variables set before launching `dassiedrop.exe` (highest priority)
2. Values in `dassiedrop.env`
3. Built-in defaults

### Storage

By default, uploaded files go into an `uploads` folder next to `dassiedrop.exe`. To use a different location, set `UPLOAD_DIR` in `dassiedrop.env`.

### HTTPS

Set `HTTPS=1` in `dassiedrop.env` to enable HTTPS. A self-signed certificate is generated automatically in a `certs` folder next to `dassiedrop.exe` on first start. Set `HTTPS_SELF_SIGNED_HOST` to your machine's hostname or LAN IP so the certificate matches the address you open in the browser.

```ini
HTTPS=1
HTTPS_SELF_SIGNED_HOST=192.168.1.24
```

## Default User

On a new installation DassieDrop creates a super-admin user named `admin` with password `password`.
Change that password from the Users page after first login.

Super-admin users can manage all local user accounts. Admin and super-admin users can manage restricted workspace access and passwords, but they still need the workspace password to enter a password-protected workspace and must grant themselves access before entering an explicit-access workspace. Regular users can access public workspaces, password-protected workspaces with the workspace password, and explicit-access workspaces they have been granted.

Users can enable an optional authenticator app from their own edit-user page. DassieDrop uses standard TOTP codes, so apps such as Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden, and Aegis can scan the displayed QR code or add the displayed secret manually. Super-admin users can disable authenticator protection for any user if someone loses access to their authenticator device.

### Reset The Installed Admin Password

If you lock yourself out of a native Linux service install, reset the shelve-backed `admin` user password from the server. This also disables authenticator app protection for that user. The Ubuntu and CentOS Stream installers use the same default layout:

- app code: `/opt/dassiedrop`
- upload and shelve data: `/var/lib/dassiedrop/uploads`
- service user: `dassiedrop`

Run:

```bash
sudo systemctl stop dassiedrop

cd /opt/dassiedrop
sudo -u dassiedrop env PYTHONPATH=/opt/dassiedrop UPLOAD_DIR=/var/lib/dassiedrop/uploads /usr/bin/python3.11 scripts/reset_admin_password.py password

sudo systemctl start dassiedrop
```

Replace the final `password` argument if you want a different replacement password. To reset a different user, add `--username <name>` before the password.

## Run With HTTPS

DassieDrop can generate a local self-signed certificate automatically when you enable HTTPS.
With HTTPS enabled, DassieDrop keeps plain HTTP on port `8000` and adds HTTPS on port `8443` by default.

```bash
HTTPS=1 ./.venv/bin/python app.py
```

The first start creates:

- `certs/dassiedrop-selfsigned.crt`
- `certs/dassiedrop-selfsigned.key`

Then open:

```text
http://localhost:8000
https://localhost:8443
```

Notes:

- Browser clipboard read works much more reliably over `https://` than plain LAN `http://`.
- Browsers will warn that the certificate is self-signed until you explicitly trust it.
- `localhost` is the easiest hostname for clipboard support. A raw LAN IP may still work for HTTPS, but certificate trust and browser behavior are stricter there.
- Override ports with `HTTP_PORT` and `HTTPS_PORT` if you do not want `8000` and `8443`.

Optional overrides:

```bash
HTTPS=1 \
HTTP_PORT=8000 \
HTTPS_PORT=8443 \
HTTPS_CERT_FILE=/path/to/dassiedrop.crt \
HTTPS_KEY_FILE=/path/to/dassiedrop.key \
HTTPS_SELF_SIGNED_HOST=localhost \
HTTPS_SELF_SIGNED_SANS=DNS:localhost,IP:127.0.0.1 \
./.venv/bin/python app.py
```

## Use Your Own SSL Certificate

If you already have a certificate and private key, point DassieDrop at those files instead of using the generated self-signed pair:

```bash
HTTPS=1 \
HTTP_PORT=8000 \
HTTPS_PORT=8443 \
HTTPS_CERT_FILE=/etc/ssl/certs/dassiedrop.crt \
HTTPS_KEY_FILE=/etc/ssl/private/dassiedrop.key \
./.venv/bin/python app.py
```

Use a certificate whose hostname or IP matches the address you open in the browser. For example, if you browse to `https://files.example.lan:8443`, that hostname must be covered by the certificate.

## Run With Docker

DassieDrop ships with:

- a `Dockerfile` for local image builds
- a `docker-compose.yml` for a persistent container setup
- a `docker-compose.proxy.yml` overlay for reverse-proxy TLS with Caddy
- a writable `/data/uploads` path for uploaded files

```bash
docker build -t dassiedrop .
```

```bash
docker run -d \
  --name dassiedrop \
  -p 8000:8000 \
  -e SHARE_BASE_URL=http://192.168.1.24:8000 \
  -v dassiedrop-data:/data \
  dassiedrop
```

Open `http://127.0.0.1:8000`.

The container stores uploads in `/data/uploads`.

Run with Compose:

```bash
SHARE_BASE_URL=http://192.168.1.24:8000 docker compose up -d
```

The included [docker-compose.yml](/home/carel/IdeaProjects/bronzegate/DassieDrop/docker-compose.yml) maps ports `8000` and `8443`, keeps uploads in a named volume, and restarts automatically.

### Docker With Native HTTPS

The container can run DassieDrop's built-in HTTPS support directly.

```bash
HTTPS=1 \
HTTPS_SELF_SIGNED_HOST=localhost \
HTTPS_SELF_SIGNED_SANS=DNS:localhost,IP:127.0.0.1 \
docker compose up -d
```

Then open:

```text
http://localhost:8000
https://localhost:8443
```

Notes:

- The container image includes `openssl`, so it can generate the self-signed certificate on first start.
- Generated certificates are stored under `/data/certs` in the same persistent Docker volume.
- For your own certificate, mount the cert and key into the container and set `HTTPS_CERT_FILE` and `HTTPS_KEY_FILE`.

Example with your own certificate:

```bash
docker run -d \
  --name dassiedrop \
  -p 8000:8000 \
  -p 8443:8443 \
  -e HTTPS=1 \
  -e HTTPS_CERT_FILE=/certs/dassiedrop.crt \
  -e HTTPS_KEY_FILE=/certs/dassiedrop.key \
  -v $PWD/certs:/certs:ro \
  -v dassiedrop-data:/data \
  dassiedrop
```

### Docker With Reverse-Proxy TLS

For a cleaner remote setup, keep DassieDrop on plain HTTP inside Docker and terminate TLS at a reverse proxy.

This repo includes:

- [docker-compose.proxy.yml](/home/carel/IdeaProjects/bronzegate/DassieDrop/docker-compose.proxy.yml)
- [docker/Caddyfile](/home/carel/IdeaProjects/bronzegate/DassieDrop/docker/Caddyfile)

Start the proxy stack:

```bash
SHARE_BASE_URL=https://localhost \
docker compose -f docker-compose.yml -f docker-compose.proxy.yml up -d
```

Then open:

```text
https://localhost
```

Notes:

- The Caddy config uses `tls internal`, which is convenient for LAN or lab use but still requires trusting Caddy's local CA in your browser.
- In this mode, DassieDrop stays on container port `8000` and Caddy handles HTTPS on `443`.
- For a real LAN hostname such as `files.example.lan`, update `docker/Caddyfile` and `SHARE_BASE_URL` to match.

## Configure The LAN Link Address

By default, DassieDrop uses the browser's current origin for share links. To force a fixed LAN address, set `SHARE_BASE_URL`.

```bash
SHARE_BASE_URL=http://192.168.1.24:8000 ./.venv/bin/python app.py
```

Use this when:

- all devices should see the same LAN address
- DassieDrop is behind a reverse proxy
- you do not want links generated from `127.0.0.1`

## Test

```bash
./.venv/bin/python -m unittest discover -s tests -v
```

## Install As An Ubuntu Service

Run on the target Ubuntu server as `root`:

```bash
sudo bash ./scripts/install-ubuntu-service.sh
```

By default, the service install enables:

- HTTP on port `8000`
- HTTPS on port `8443`

Disable HTTPS explicitly if you only want HTTP:

```bash
sudo HTTPS=0 bash ./scripts/install-ubuntu-service.sh
```

Quick install:

```bash
curl -fsSLo github-ubuntu-install-upgrade.sh https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/github-ubuntu-install-upgrade.sh
chmod +x github-ubuntu-install-upgrade.sh
sudo ./github-ubuntu-install-upgrade.sh
```

Or install or upgrade directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/github-ubuntu-install-upgrade.sh | sudo bash
```

It will:

- upgrade the runtime to `python3.11`
- create a system user and group named `dassiedrop`
- install the app into `/opt/dassiedrop`
- store uploads in `/var/lib/dassiedrop/uploads`
- write config to `/etc/dassiedrop/dassiedrop.env`
- create and enable a `systemd` service

Override defaults:

```bash
sudo PORT=8080 bash ./scripts/install-ubuntu-service.sh
```

Or use `--port`:

```bash
sudo bash ./scripts/install-ubuntu-service.sh --port 8080
```

Set the share link base address during install:

```bash
sudo SHARE_BASE_URL=http://192.168.1.24:8000 bash ./scripts/install-ubuntu-service.sh
```

The GitHub helper also supports overrides. On upgrade it reuses values from `/etc/dassiedrop/dassiedrop.env` unless you override them:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/github-ubuntu-install-upgrade.sh | sudo PORT=8080 bash
```

To explicitly enable daily update checks during install:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/github-ubuntu-install-upgrade.sh | sudo UPDATE_CHECK_ENABLED=1 bash
```

To run non-interactively, use `--silent`:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/github-ubuntu-install-upgrade.sh | sudo bash -s -- --silent
```

In `--silent` mode, the installer keeps optional prompts disabled and uses default values.

Uninstall the Ubuntu service from a checked-out repo:

```bash
sudo bash ./scripts/uninstall-ubuntu-service.sh
```

Or uninstall directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/uninstall-ubuntu-service.sh | sudo bash
```

Remove the uploaded data and service user too:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/uninstall-ubuntu-service.sh | sudo REMOVE_DATA=1 REMOVE_USER=1 bash
```

Use the Ubuntu service install for a native `systemd` deployment. Use Docker for a portable container runtime.

## Install On CentOS Stream From GitHub

Install or upgrade on a CentOS Stream host:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/github-centos-stream-install-upgrade.sh | sudo bash
```

By default, the service install enables:

- HTTP on port `8000`
- HTTPS on port `8443`

Disable HTTPS explicitly if you only want HTTP:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/github-centos-stream-install-upgrade.sh | sudo HTTPS=0 bash
```

The CentOS Stream helper installs required packages with `dnf`, upgrades to `python3.11`, creates the same `dassiedrop` system user and `systemd` service, and reuses values from `/etc/dassiedrop/dassiedrop.env` on upgrade unless you override them.

Override defaults:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/github-centos-stream-install-upgrade.sh | sudo PORT=8080 bash
```

To explicitly enable daily update checks during install:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/github-centos-stream-install-upgrade.sh | sudo UPDATE_CHECK_ENABLED=1 bash
```

To run non-interactively, use `--silent`:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/github-centos-stream-install-upgrade.sh | sudo bash -s -- --silent
```

In `--silent` mode, the installer keeps optional prompts disabled and uses default values.

Uninstall the CentOS Stream service:

```bash
sudo bash ./scripts/uninstall-centos-stream-service.sh
```

Or uninstall directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/uninstall-centos-stream-service.sh | sudo bash
```

Remove the uploaded data and service user too:

```bash
sudo REMOVE_DATA=1 REMOVE_USER=1 bash ./scripts/uninstall-centos-stream-service.sh
```

Directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/vossie/DassieDrop/master/scripts/uninstall-centos-stream-service.sh | sudo REMOVE_DATA=1 REMOVE_USER=1 bash
```
