<p align="center">
  <img src="static/images/logo_purple.png" alt="PhishHook Logo" width="128">
</p>

<h1 align="center">PhishHook</h1>

<p align="center">
  A hardened GoPhish fork for red team phishing operations — scanner-resistant landing pages,
  native Evilginx (AiTM) integration, and a phishlet generator, managed from one console.
</p>

---

## What is PhishHook?

Microsoft Safe Links and similar email security products crawl phishing links before users click them, poisoning your campaign metrics with bot "clicks" and tipping off the target. PhishHook fixes this — and goes further — in three layers:

1. **A scanner-resistant phishing server.** Cloudflare Turnstile challenges, behavioral telemetry (time-on-page, mouse movement, interaction events), Microsoft/Safe Links IP-range blocking, rate limiting, and header de-fingerprinting (`X-Server: gophish` is gone). Only real humans reach your landing pages, and only real human clicks show up in your metrics.
2. **Native Evilginx integration (AiTM).** Evilginx-mode campaigns serve targets the *real* login page through a proxy — the strongest possible fidelity for M365 and any OIDC/SSO target — while captured credentials and session tokens flow back into the same campaign timeline you already use. Lure URLs are encrypted per recipient, so link-level scanners learn nothing.
3. **A phishlet generator.** Point it at a target's login page and it analyzes the flow with a headless browser, generates a validated phishlet YAML, optionally refines it with AI, and manages a phishlet library — all from the PhishHook console.

Everything is GoPhish underneath: groups, templates, sending profiles, the API, IMAP email reporting, and webhooks all work exactly as upstream.

## Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Quick start (classic landing pages)](#quick-start)
- [Configuration reference](#configuration-reference)
- [Deploying the full stack](#deploying-the-full-stack)
- [Using PhishHook](#using-phishhook)
  - [Evilginx-mode campaigns](#evilginx-mode-campaigns)
  - [Evilginx console](#evilginx-console)
  - [Phishlet workflow](#phishlet-workflow)
  - [Monitoring and closeout](#monitoring-and-closeout)
- [API](#api)
- [CLI reference](#cli-reference)
- [Troubleshooting](#troubleshooting)
- [Design notes](#design-notes)
- [License and disclaimer](#license-and-disclaimer)

## Features

**Scanner filtering** (classic, self-hosted landing pages)

- Cloudflare Turnstile challenge — automated scanners never reach the page
- Behavioral detection — Microsoft 365 / Exchange Online Protection IP-range blocking, per-IP rate limiting, JS telemetry (time-on-page, mouse movement, scroll/click/touch)
- Header evasion — strips `X-Server: gophish` and friends
- Automatic Let's Encrypt certificates via `--domain`

**Evilginx AiTM** (recommended for M365 / SSO targets)

- Evilginx-mode campaigns with encrypted, personalized per-recipient lure URLs
- Result callbacks (`opened` → `clicked` → `submitted`) land in the normal campaign timeline
- Management console: phishlets, lures, captured sessions — no evilginx terminal required for daily operation
- Session correlation: every captured session is matched back to its recipient, with a merged event timeline and exportable cookies/credentials
- DNS pre-launch checks: verify every phishlet hostname resolves correctly *before* the campaign fires

**Phishlet generator**

- Headless-browser (Playwright) analysis of the target login flow
- Phishlet YAML generation with validation, warnings, and suggestions
- Optional AI refinement, live progress via WebSocket, and a phishlet library

**Everything else**

- Full upstream GoPhish compatibility — the API, campaigns, templates, groups, landing pages, IMAP reporting, and webhooks behave exactly as upstream.

## How it works

### The stack

```
                        +-------------------------------------+
                        |           Operator browser          |
                        +------------------|------------------+
                                           | HTTPS (login + API)
                                           v
+------------------------------------------+-----------------------------+
| PhishHook host                                                          |
|                                                                         |
|  +---------------------+      +----------------------+                  |
|  | PhishHook admin     |----->| evilginx REST API    |                  |
|  | 127.0.0.1:3333      |      | (fork) 127.0.0.1:8455|                  |
|  +----------+----------+      +----------+-----------+                  |
|             |                            |  ^                          |
|             | API key                    |  | opened/clicked/          |
|             v                            v  | submitted events         |
|  +---------------------+      +----------------------+                  |
|  | Phishlet generator  |      | evilginx phish server|                  |
|  | 127.0.0.1:8000      |      | :443 (its domains)   |                  |
|  +---------------------+      +----------+-----------+                  |
|                                            |                            |
+--------------------------------------------|----------------------------+
                                             |
              targets click the lure URL ----+  evilginx proxies the real
                                                login site, captures creds +
                                                session tokens
```

- **PhishHook admin** (`127.0.0.1:3333`) — the console and API. Reach it via SSH tunnel or VPN; only this surface ever needs to be exposed to you.
- **evilginx phish server** (`:443`) — public. Serves the proxied target site on the phishlet's hostnames and captures the goods.
- **evilginx REST API** (fork addition, `127.0.0.1:8455`) — the bridge both consoles use. PhishHook polls it (phishlets/lures/sessions) and evilginx pushes campaign events through it (bearer-authenticated).
- **Phishlet generator** (`127.0.0.1:8000`) — sidecar, reached only through PhishHook's authenticated `/api/phishletgen/*` proxy.

All service-to-service traffic stays on loopback. Nothing but the phishing endpoint and (optionally) your tunneled admin UI is ever exposed.

### Scanner filtering

For classic (self-hosted) landing pages, every request walks this gauntlet:

```
User clicks phishing link
         |
         v
  +-------------------+
  | Behavioral Check  |
  | - MS IP blocking  |
  | - Rate limiting   |
  +-------------------+
         |
    Blocked? Pass
         |
   +-----+-----+
   |           |
   v           v
 404 Page   +----------------+
            | Turnstile      |
            | Challenge Page |
            | + JS Telemetry |
            +----------------+
                   |
              Bot? |  Human?
                    |
              +-----+-----+
              |           |
              v           v
           Blocked    Solve Challenge
           (no click     |
            recorded)    v
                    +-----------------+
                    | Telemetry Check |
                    | - Time on page  |
                    | - Mouse moves   |
                    | - Interactions  |
                    +-----------------+
                           |
                      Pass | Fail
                           |
                     +-----+-----+
                     |           |
                     v           v
                +----------+  404 Page
                | Landing  |
                | Page     |
                | (click   |
                | recorded)|
                +----------+
```

The behavioral layer sources Microsoft 365 / Exchange Online Protection IP ranges from the official [Microsoft 365 endpoints API](https://endpoints.office.com/endpoints/worldwide), rate-limits per IP, and the challenge page collects time-on-page, mouse movement, click/scroll/touch events, screen dimensions and WebGL support. Safe Links crawlers typically hit within seconds of delivery with zero interaction events — trivially distinguishable from a real user.

In evilginx-mode campaigns this machinery is intentionally bypassed: evilginx serves the *real* site, and scanner-vs-human filtering happens at the lure-parameter layer instead (scanners receive an encrypted blob they can neither decode nor correlate; a real click decrypts cleanly).

## Quick start

Build from source (Go 1.24+; Node.js is only needed if you modify JS/CSS assets — minified bundles are committed):

```bash
git clone https://github.com/wcrooker/PhishHook.git
cd PhishHook
go build
```

Development (self-signed):

```bash
./gophish
```

Production (Let's Encrypt — binds :80 for ACME and :443 for HTTPS):

```bash
sudo setcap 'cap_net_bind_service=+ep' ./gophish
./gophish --domain phish.example.com
```

Certificates are cached in `certs/` and renewed automatically.

First run creates the `admin` account with a temporary password printed to the log (`password_change_required` is set — log in and change it), and the API key is available under **Account Settings**.

## Configuration reference

`config.json` — this is the complete surface. The `evilginx` and `phishlet_generator` sections are optional; everything else matches upstream GoPhish semantics.

```json
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",
    "use_tls": true,
    "cert_path": "gophish_admin.crt",
    "key_path": "gophish_admin.key",
    "csrf_key": "random-64-hex-chars",
    "trusted_origins": []
  },
  "phish_server": {
    "listen_url": "0.0.0.0:443",
    "use_tls": true,
    "cert_path": "phish.crt",
    "key_path": "phish.key"
  },
  "db_name": "sqlite3",
  "db_path": "gophish.db",
  "migrations_prefix": "db/db_",
  "contact_address": "",
  "logging": {
    "filename": "",
    "level": "info"
  },
  "turnstile": {
    "enabled": false,
    "site_key": "YOUR_CLOUDFLARE_SITE_KEY",
    "secret_key": "YOUR_CLOUDFLARE_SECRET_KEY",
    "cookie_secret": "random-32-char-secret"
  },
  "evasion": {
    "enabled": true,
    "strip_server_header": false,
    "custom_server_name": "IGNORE"
  },
  "behavioral": {
    "enabled": true,
    "min_time_on_page_ms": 2000,
    "require_mouse_movement": false,
    "require_interaction": false,
    "block_microsoft_ips": true,
    "custom_blocked_cidrs": [],
    "max_requests_per_minute": 30,
    "windows_only": true
  },
  "evilginx": {
    "api_url": "http://127.0.0.1:8455",
    "api_key": "the-evilginx-restapi-token"
  },
  "phishlet_generator": {
    "url": "http://127.0.0.1:8000"
  }
}
```

| Option | Description |
|--------|-------------|
| `admin_server.listen_url` | Admin UI/API bind address. Keep on loopback and reach it via SSH tunnel or VPN. |
| `admin_server.use_tls` / `cert_path` / `key_path` | TLS for the admin UI. |
| `admin_server.csrf_key` | CSRF signing key — set a unique random value per install. |
| `phish_server.listen_url` | Phishing server bind address. On an evilginx-shared host use `0.0.0.0:8443` (or run `--mode admin`, see [deployment](#deploying-the-full-stack)). |
| `turnstile.enabled` / `site_key` / `secret_key` / `cookie_secret` | Cloudflare Turnstile challenge on landing pages. |
| `evasion.enabled` / `strip_server_header` / `custom_server_name` | Header de-fingerprinting. `strip_server_header` removes `X-Server` entirely; otherwise it is rewritten (default value `IGNORE` produces no meaningful fingerprint). |
| `behavioral.enabled` | Master switch for behavioral bot detection. |
| `behavioral.min_time_on_page_ms` | Minimum ms on page before a form submission is accepted (default 2000). |
| `behavioral.require_mouse_movement` | Require mouse/touch movement before validating. |
| `behavioral.require_interaction` | Require scroll/click/keypress events. |
| `behavioral.block_microsoft_ips` | Block Microsoft 365 / EOP IP ranges (Safe Links crawlers). |
| `behavioral.custom_blocked_cidrs` | Extra CIDRs to block, e.g. `["10.0.0.0/8"]`. |
| `behavioral.max_requests_per_minute` | Per-IP rate limit (default 30). |
| `behavioral.windows_only` | Only serve pages to Windows user agents (default true). |
| `evilginx.api_url` | evilginx REST API base URL (evilginx3-phishhook fork, `-restapi` flag). |
| `evilginx.api_key` | Bearer token for the REST API (the `-restapi-token` value). |
| `phishlet_generator.url` | PhishletGenerator sidecar backend URL. |

### Turnstile setup

1. [Cloudflare Dashboard](https://dash.cloudflare.com/) → Turnstile → **Add Widget**
2. Enter your phishing domain, choose **Managed** mode (recommended)
3. Copy the site key and secret key into `config.json`
4. Generate a random `cookie_secret` (32+ characters)

## Deploying the full stack

### Automated (recommended): the setup wizard

The wizard packages the entire deployment as a Docker Compose stack and wires the services together — no hand-editing of configs, no terminal commands in evilginx, no secret juggling.

```bash
git clone https://github.com/wcrooker/PhishHook.git
cd PhishHook
go build -o phishhook-setup ./setup
sudo ./phishhook-setup            # interactive; asks everything below
```

It asks for:

- **Base phishing domain** (evilginx phishlets live under it) and the classic-phishing-server port if you want both
- **Admin UI exposure** — loopback + SSH tunnel (recommended) or public
- **Evilginx Let's Encrypt autocert** — off by default (self-signed/developer mode until DNS is live)
- **Phishlet generator sidecar** on/off
- **SMTP sending profile** — host:port, credentials, from address — and an optional post-launch **test email**
- A **GitHub token** if your repos are private

It then: pre-flights Docker/Compose, port availability, and DNS (resolves the base domain against the server's external IP); generates all secrets (admin password, API key, evilginx REST token, lure encryption key, CSRF key); clones the private repos; renders `docker-compose.yml` + `phishhook/config.json` + the evilginx config store **with the gophish pairing and enc_key already set**; builds and starts the stack; sets the admin password via the API; creates the sending profile; and runs smoke tests (admin API, evilginx REST + bridge + push pairing, generator through its authenticated proxy).

Useful flags (also usable with `--batch` for unattended installs): `--base-domain`, `--admin-listen loopback|public`, `--autocert`, `--smtp-host user:pass@host:port`, `--test-email`, `--no-start` (generate only), `--force` (overwrite configs; data dirs preserved).

The deployment lives in `/opt/phishhook` (configurable): secrets in `.env` (chmod 600), data under `phishhook/` (sqlite) and `evilginx/data/` (config store + phishlets). Update the stack with `cd /opt/phishhook && git -C ... pull && docker compose up -d --build`.

> Runs the services with host networking on Linux — the loopback URLs match the architecture above exactly (admin 3333, evilginx REST 8455, generator 8000).

### Manual deployment

This walks through deploying PhishHook, the evilginx fork, and the phishlet generator on one box by hand, wired together. Fresh Ubuntu/Debian box assumed; read top to bottom.

### Ports and who owns them

| Port | Service | Exposure |
|------|---------|----------|
| 443 | evilginx phish server (its domains) | public — the phished site |
| 80 | ACME challenge (only when evilginx autocert is on) | public |
| 3333 | PhishHook admin UI + API | loopback / SSH tunnel / VPN |
| 8455 | evilginx REST API (fork) | loopback only, bearer token |
| 8443 | PhishHook phish server, *if* you also serve classic landing pages on the same host | public |
| 8000 | PhishletGenerator backend | loopback only |

**The 443 question:** evilginx and PhishHook's own phishing server both want 443. Pick one:

- **Same host, evilginx-centric (recommended).** evilginx owns 443. If you only run evilginx-mode campaigns, start PhishHook with `--mode admin` and the phish server never binds at all. If you still want classic landing pages, bind them to `0.0.0.0:8443` in `phish_server`.
- **Separate hosts.** evilginx on its own redirector VPS — better OPSEC, since the team server never touches target traffic. Keep the evilginx REST API on loopback and tunnel it: `ssh -fN -L 8455:127.0.0.1:8455 evilginx-box`, then point `evilginx.api_url` at `http://127.0.0.1:8455`. The bearer token protects the tunnel.

### Step 1 — DNS

1. One A record per phishlet hostname (the console's **Phishlets → Verify** view lists them, e.g. `login.phish.example.com`, `aadcdn.phish.example.com`) → evilginx host IP.
2. An A record for the admin host (e.g. `team.example.com`) only if you expose the admin UI beyond loopback/VPN.

### Step 2 — Build PhishHook

```bash
git clone https://github.com/wcrooker/PhishHook.git
cd PhishHook && go build
sudo setcap 'cap_net_bind_service=+ep' ./gophish   # only if binding <1024
```

### Step 3 — Build the evilginx fork

```bash
git clone https://github.com/wcrooker/evilginx3-phishhook.git
cd evilginx3-phishhook && go build -o evilginx .
```

Phishlet YAML files live in `phishlets/` — the console and the generator both work against this directory.

### Step 4 — (Optional) Phishlet generator

```bash
git clone https://github.com/wcrooker/PhishletGenerator-Evilginx.git phishletgen
cd phishletgen/backend
pip install -r requirements.txt && playwright install chromium
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Or use `docker compose -f docker-compose.phishletgen.yml up -d --build` from the PhishHook repo (see [Phishlet generator](#phishlet-workflow)).

### Step 5 — evilginx: first-run config and pairing

Start evilginx with the REST API enabled:

```bash
./evilginx -p ./phishlets \
    -restapi 127.0.0.1:8455 \
    -restapi-token <generate-a-long-random-secret> \
    -developer        # omit once DNS is live and you want autocert
```

In the evilginx terminal:

```
config domain phish.example.com           # base domain for all phishlets
config ipv4 external <this-server-ip>
config enc_key <generate-a-32-char-secret>
config gophish admin_url http://127.0.0.1:3333
config gophish api_key <phishhook-api-key>
config gophish test                       # should report: connection successful
```

- The **API key** is shown under **Account Settings** in the PhishHook UI. This pairing is what lets evilginx report opened/clicked/submitted events into campaign timelines.
- The **enc_key** is shared with campaigns: put the *same value* in a campaign's **Lure Encryption Key** field. Setting it once here (rather than per-campaign) is the recommended pattern — every campaign you create will use this key.

### Step 6 — PhishHook: bridge config

Add the bridge sections to `config.json` (full reference [above](#configuration-reference)):

```json
"evilginx": {
    "api_url": "http://127.0.0.1:8455",
    "api_key": "<the -restapi-token value>"
},
"phishlet_generator": {
    "url": "http://127.0.0.1:8000"
}
```

Then start PhishHook (`./gophish`, or `--mode admin` if evilginx owns 443 and you don't serve classic pages).

### Step 7 — Keep it alive (systemd)

```ini
# /etc/systemd/system/phishhook.service
[Unit]
Description=PhishHook
After=network.target

[Service]
WorkingDirectory=/opt/phishhook
ExecStart=/opt/phishhook/gophish --mode admin --config /opt/phishhook/config.json
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/evilginx.service
[Unit]
Description=evilginx (phishhook fork)
After=network.target

[Service]
WorkingDirectory=/opt/evilginx
ExecStart=/opt/evilginx/evilginx -p /opt/evilginx/phishlets -restapi 127.0.0.1:8455 -restapi-token TOKEN
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

### Step 8 — Verify the wiring

Log into the PhishHook UI and open **Evilginx**:

- **Status** shows the evilginx version, base domain, external IP — and the gophish pairing state. "Not configured" means the bridge section is missing from `config.json`; a connection error means the API isn't running or the token is wrong.
- **Generator** shows the wizard instead of the setup hint.
- **Phishlets → Verify** should show green rows once DNS records exist.

## Using PhishHook

### Evilginx-mode campaigns

When **Evilginx Mode** is enabled on a campaign:

1. Instead of a PhishHook landing page, targets receive the evilginx lure URL.
2. PhishHook personalizes each URL per recipient (`fname`, `lname`, `email`, `rid`), wrapped in two layers of encryption so scanners (and anyone holding just the URL) can't decode them: parameters are RC4-encrypted with a random per-URL key, then the whole blob is AES-256-CBC-encrypted with the campaign's **Lure Encryption Key** — the same value as evilginx's `config enc_key`. Leave the field blank and a key is generated for you (pair it with evilginx as shown in [Step 5](#step-5--evilginx-first-run-config-and-pairing)).
3. evilginx decrypts the parameters when the target visits and reports `opened` → `clicked` → `submitted` back to the PhishHook API, so campaign results stay complete even though the landing page is evilginx's.

To run one: create a campaign, tick **Evilginx Mode**, paste the lure URL (from the console's Lures tab) into the **URL** field, and reference `{{.URL}}` in your template as usual.

The API creates evilginx-mode campaigns directly:

```bash
curl -k -X POST https://localhost:3333/api/campaigns/?api_key=YOUR_API_KEY \
  -d '{
    "name": "Evilginx Campaign",
    "template": {"name": "Template"},
    "smtp": {"name": "Profile"},
    "groups": [{"name": "Targets"}],
    "url": "https://lure.phish.example.com/report.pdf",
    "evilginx_mode": true,
    "encryption_key": "shared-with-evilginx"
  }'
```

### Evilginx console

The **Evilginx** page in the sidebar (admin-only) is the day-to-day control surface. The browser never talks to the evilginx API directly — every request flows through PhishHook's authenticated admin API (`/api/evilginx/*`, requires the Modify System permission), and PhishHook forwards to the loopback REST API.

- **Status** — evilginx version, base domain, autocert state, gophish pairing, session counts
- **Phishlets** — enable/disable, set hostnames (must be under the base domain), and run the **DNS pre-launch check**: every hostname the phishlet serves must resolve to the evilginx host before a campaign fires — a red row means the campaign is dead on arrival
- **Lures** — create lures, copy their URLs, delete them, or hit **Campaign** to jump straight into the campaign wizard pre-filled (evilginx mode on, lure URL set, encryption key generated)
- **Sessions** — captured sessions **correlated with campaigns**: each session is matched back to its recipient by decrypting the lure parameters, and the detail modal shows the merged timeline (opened → clicked → submitted → session captured) plus credentials, auth cookies, and exportable JSON for session replay

### Phishlet workflow

1. **Generate:** Evilginx → **Generator** → paste the target's real login URL → *Generate Phishlet* (live analysis progress; toggle AI refinement if keys are configured) → review warnings/suggestions → **Validate** → **Save to Library** and/or **Download** the YAML.
2. **Load:** copy the YAML into evilginx's `phishlets/` directory. evilginx loads phishlet files at startup, so restart the evilginx service after adding new ones.
3. **Configure:** Evilginx → **Phishlets** → set the **Hostname** (under the base domain) → **Enable**.
4. **Pre-flight:** click **Verify** — every row green, or fix DNS first.
5. **Lure:** Evilginx → **Lures** → **New Lure** (pick the phishlet, optionally set a post-phish redirect URL) → **Copy URL** for external use, or click **Campaign** to go straight to the pre-filled wizard.

### Monitoring and closeout

- **Campaigns** show the normal GoPhish metrics; evilginx feeds open/click/submit events into the same timeline.
- **Evilginx → Sessions** is the AiTM payoff: credentials, session cookies, and the full per-recipient story in one modal.
- **Teardown:** complete the campaign in PhishHook (stops scheduling), disable the phishlet in the console, and delete captured sessions when the engagement ends.

## API

PhishHook is fully compatible with the [GoPhish API](https://docs.getgophish.com/api-documentation/). Authenticate with the API key from **Account Settings**:

```bash
curl -k -H "Authorization: Bearer YOUR_API_KEY" https://localhost:3333/api/campaigns/
```

On top of upstream, PhishHook exposes:

| Endpoint | Description |
|----------|-------------|
| `/api/evilginx/status` | evilginx version, domain, pairing state |
| `/api/evilginx/phishlets` (+ `/{name}/enable\|disable\|hostname\|verify`) | phishlet management and DNS pre-flight |
| `/api/evilginx/lures` (+ `/{id}`) | lure CRUD |
| `/api/evilginx/sessions` (+ `/{sid}`, `/correlate`) | captured sessions and campaign correlation |
| `/api/phishletgen/*` | authenticated reverse proxy to the generator sidecar (WebSockets included) |
| `/api/results/{rid}/open\|click\|submit` | evilginx → PhishHook result callbacks (bearer auth; normally called by evilginx itself) |

## CLI reference

| Flag | Description |
|------|-------------|
| `--config` | Path to config.json (default `./config.json`) |
| `--domain` | Domain for Let's Encrypt SSL (phishing server) |
| `--disable-mailer` | Disable the built-in mailer (multi-system deployments) |
| `--mode` | `all` (default), `admin`, or `phish` — use `admin` when evilginx owns 443 |

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| Login "reloads" the page | Old builds only: session cookie was `SameSite=None` without `Secure` on plain HTTP — fixed in `d317480`; update. |
| Evilginx tab: "not configured" | `evilginx` section missing from `config.json`, or server not restarted after adding it. |
| Evilginx tab: connection error | REST API not running on `api_url`, or token mismatch. |
| 403 on admin form posts | Reverse proxy stripping Origin/Referer on HTTPS deployments — ensure `X-Forwarded-Proto` handling or run the admin server with `use_tls: true`. |
| Phishlet enable fails | Hostname not set, or hostname not a subdomain of the evilginx base domain. |
| Verify shows red rows | Missing/wrong DNS records, or records not propagated yet. |
| Targets get 404 on the lure | Phishlet disabled, lure deleted, or evilginx restarted and hostname unset. |
| No results in the campaign timeline | evilginx pairing missing or wrong API key — run `config gophish test` in evilginx. |
| Generator tab shows the setup hint | `phishlet_generator` section missing, or sidecar down. |
| Campaign launches but no emails arrive | Sending profile unreachable from the host, or SMTP credentials rejected — check the campaign's error events in the timeline. |

## Design notes

### Why there is no tenant-branding proxy

Older versions of PhishHook shipped a branding proxy (a `/branding` endpoint that fetched an organization's custom Microsoft 365 login branding via `GetCredentialType`). It was removed deliberately:

- **M365 phishing belongs in evilginx.** Evilginx proxies the *real* `login.microsoftonline.com`, so Microsoft applies the target tenant's branding natively during the proxied auth flow — better fidelity than any replica, plus session-token capture. A hand-built landing page plus a branding lookup cannot compete.
- **The runtime fetch was a fingerprint.** The victim's browser calling `GET /branding?email=<their own address>` on the phishing domain is an IOC visible in proxy/EDR logs; the real login page never does that. It contradicted the fork's whole thesis (stripping `X-Server: gophish`, filtering Safe Links, etc.).
- **Server-side lookups were OPSEC poison.** Querying `GetCredentialType` from phishing-infrastructure IPs with target emails is the classic tenant-enumeration detection pattern, and the endpoint doubled as an unauthenticated tenant-enumeration relay for anyone who found the domain.

If you ever need a convincing M365 pre-auth page without evilginx, reuse Microsoft's own assets rather than querying for tenant branding at runtime.

## License and disclaimer

MIT License — based on [GoPhish](https://github.com/gophish/gophish) by Jordan Wright. Evilginx integration is based on [evilginx2](https://github.com/kgretzky/evilginx2) by Kuba Gretzky.

This tool is intended for authorized security testing and red team operations only. Unauthorized use against systems you do not own or have explicit permission to test is illegal. Always obtain proper written authorization before conducting phishing assessments.
