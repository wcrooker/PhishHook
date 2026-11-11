<p align="center">
  <img src="static/images/logo_purple.png" alt="PhishHook Logo" width="128">
</p>

<h1 align="center">PhishHook</h1>

<p align="center">
  Enhanced GoPhish fork with evasion capabilities for professional red team operations.
</p>

## Features

- **Automatic Let's Encrypt SSL**: Use `--domain` flag for automatic certificate provisioning
- **Cloudflare Turnstile Integration**: Bot protection that blocks automated scanners (Safe Links, security crawlers) while allowing real users through
- **Behavioral Detection**: Filter automated scanners using timing analysis, Microsoft IP blocking, and JS telemetry (mouse movement, scroll events, time-on-page)
- **Microsoft Tenant Branding Proxy**: Automatically fetch target organization's custom Microsoft 365 login branding (background images, logos) via `{{.BrandingURL}}` template variable
- **Header Evasion**: Strips identifying headers (`X-Server: gophish`, etc.) that fingerprint the server
- **Evilginx AiTM Integration**: Evilginx-mode campaigns with encrypted per-recipient lures, result callbacks, and a full management console (phishlets, lures, DNS pre-launch checks, session correlation)
- **Phishlet Generator**: Sidecar-driven target analysis and phishlet YAML generation with validation, AI refinement, and a phishlet library
- **Full GoPhish Compatibility**: All upstream GoPhish features work as expected

## Why PhishHook?

Microsoft Safe Links and similar email security products crawl phishing links before users click them, generating false positive "clicks" in your campaign metrics. PhishHook solves this with multiple layers of defense:

1. **Behavioral Detection**: Blocks requests from known Microsoft 365/Safe Links IP ranges, enforces minimum time-on-page, and validates mouse/touch interaction telemetry
2. **Turnstile Challenge**: Automated scanners can't solve the Cloudflare challenge, so they never reach the landing page
3. **JS Telemetry**: Collects client-side behavioral signals (mouse movement, scroll, clicks) to distinguish humans from bots
4. **Clean Metrics**: Your campaign data reflects actual human interactions

## Installation

### From Source

```bash
git clone https://github.com/wcrooker/PhishHook.git
cd PhishHook
go build
```

### Requirements

- Go 1.21+
- Ports 80 and 443 (for Let's Encrypt)

## Quick Start

### Development (Self-Signed SSL)

```bash
./gophish
```

### Production (Let's Encrypt)

```bash
# Allow binding to privileged ports without root
sudo setcap 'cap_net_bind_service=+ep' ./gophish

# Start with automatic SSL
./gophish --domain phish.example.com
```

This will:
1. Start HTTP on port 80 for ACME challenges
2. Obtain a Let's Encrypt certificate automatically
3. Start HTTPS on port 443 with valid SSL
4. Cache certificates in `certs/` for renewal

## Configuration

Edit `config.json`:

```json
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",
    "use_tls": true,
    "cert_path": "gophish_admin.crt",
    "key_path": "gophish_admin.key"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:443",
    "use_tls": true,
    "cert_path": "phish.crt",
    "key_path": "phish.key"
  },
  "turnstile": {
    "enabled": true,
    "site_key": "YOUR_CLOUDFLARE_SITE_KEY",
    "secret_key": "YOUR_CLOUDFLARE_SECRET_KEY",
    "cookie_secret": "random-32-char-secret-here"
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
    "max_requests_per_minute": 30
  },
  "branding": {
    "enabled": true,
    "allowed_origins": ["*"]
  }
}
```

### Turnstile Setup

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/) > Turnstile
2. Click "Add Widget"
3. Enter your phishing domain
4. Choose "Managed" mode (recommended)
5. Copy Site Key and Secret Key to `config.json`
6. Generate a random `cookie_secret` (32+ characters)

### Configuration Options

| Option | Description |
|--------|-------------|
| `turnstile.enabled` | Enable Cloudflare Turnstile challenge |
| `turnstile.site_key` | Cloudflare Turnstile site key |
| `turnstile.secret_key` | Cloudflare Turnstile secret key |
| `turnstile.cookie_secret` | Secret for signing session cookies |
| `evasion.enabled` | Enable header stripping |
| `evasion.strip_server_header` | Remove X-Server header entirely |
| `evasion.custom_server_name` | Custom X-Server value (default: "IGNORE") |
| `behavioral.enabled` | Enable behavioral bot detection |
| `behavioral.min_time_on_page_ms` | Minimum milliseconds on page before form submission is valid (default: 2000) |
| `behavioral.require_mouse_movement` | Require mouse/touch movement to validate request |
| `behavioral.require_interaction` | Require scroll, click, or keypress events |
| `behavioral.block_microsoft_ips` | Block known Microsoft 365/Safe Links IP ranges |
| `behavioral.custom_blocked_cidrs` | Additional CIDR ranges to block (e.g., ["10.0.0.0/8"]) |
| `behavioral.max_requests_per_minute` | Rate limit per IP address (default: 30) |
| `branding.enabled` | Enable Microsoft tenant branding proxy |
| `branding.allowed_origins` | CORS allowed origins for branding endpoint (use ["*"] for all) |
| `evilginx.api_url` | Base URL of the evilginx REST API (evilginx3-phishhook fork) |
| `evilginx.api_key` | Bearer token for the evilginx REST API (`-restapi-token`) |
| `phishlet_generator.url` | Base URL of the PhishletGenerator sidecar backend |

## Full Deployment Workflow

This section walks through deploying the complete stack — PhishHook, the evilginx fork, and the phishlet generator — and wiring them together. Read it top to bottom on a fresh box.

### Architecture

```
                          +-------------------------------------+
                          |            Operator browser         |
                          +------------------|------------------+
                                             | HTTPS (login + API)
                                             v
+--------------------------------------------+--------------------------+
| PhishHook host                                             |
|  +---------------------+     +---------------------+     +---------+ |
|  | Admin server        |---->| evilginx REST API   |---->| evilginx| |
|  | 127.0.0.1:3333      |     | bridge (in-process) |     | :8443   | |
|  +---------------------+     +---------------------+     | :443    | |
|            |                                              +---------+ |
|  +---------------------+     +---------------------+                 |
|  | Phish server        |     | Generator sidecar   |                  |
|  | :443 or custom      |     | proxy /api/phishletgen/* -> :8000     |
|  +---------------------+     +---------------------+                 |
+----------------------------------------------------------------------+
         |                                       |
         v                                       v
  Targets receive email                  evilginx serves the phished
  with lure URLs (encrypted              site on its own domains,
  per-recipient)                         captures sessions, reports
                                         results back to PhishHook
```

All service-to-service traffic (evilginx API, generator API) stays on loopback or the compose network — only PhishHook's admin UI and the phishing endpoints are ever exposed.

### Ports & who owns them

| Port | Service | Exposure |
|------|---------|----------|
| 3333 | PhishHook admin UI + API (TLS) | loopback or VPN only |
| 443 | evilginx phish server (its domains) | public — the phished site |
| 443 | PhishHook phish server (landing pages) | public — **conflicts with evilginx, see below** |
| 80 | ACME challenge (autocert / Let's Encrypt) | public |
| 8443 | evilginx REST API | loopback only |
| 8000 | PhishletGenerator backend | loopback / compose network only |

**Port 443 conflict:** evilginx and PhishHook's phishing server both want 443. Pick one:

- **Separate hosts (recommended).** evilginx lives on its own redirector VPS — better OPSEC (the team server never touches target traffic) and no port fights. Keep the evilginx REST API on its loopback and reach it from PhishHook through an SSH tunnel: `ssh -fN -L 8443:127.0.0.1:8443 evilginx-box`, then point `evilginx.api_url` at `http://127.0.0.1:8443`. The bearer token protects the tunnel.
- **Same host.** Run PhHook's phish server on a different port (`"listen_url": "0.0.0.0:8443"` in `phish_server`) if you still serve classic landing pages; if you only run evilginx-mode campaigns, start PhishHook with `--mode admin` and don't bind the phish server at all.

### Step 1 — Provision DNS

Before anything starts, create DNS records so certificates can be issued:

1. A record for the **PhishHook admin host** (e.g. `team.example.com`) if you expose the admin UI beyond loopback/VPN.
2. For each evilginx phishlet: one record per host the phishlet needs (the console's **Phishlets → DNS** button lists them, e.g. `login.phish.example.com`, `aadcdn.phish.example.com`), all pointing at the **evilginx host's IP**.
3. Set the evilginx **base domain** (`config domain`, step 5) to the domain those subdomains live under.

### Step 2 — Build and install PhishHook

```bash
git clone https://github.com/wcrooker/PhishHook.git
cd PhishHook
go build
sudo setcap 'cap_net_bind_service=+ep' ./gophish   # only if binding <1024
```

### Step 3 — Install the evilginx fork

```bash
git clone https://github.com/wcrooker/evilginx3-phishhook.git
cd evilginx3-phishhook
go build -o evilginx .
```

Copy phishlets into `./phishlets/` as usual — the generator (step 4) and the console both write YAML here.

### Step 4 — (Optional) Start the phishlet generator

```bash
git clone https://github.com/wcrooker/PhishletGenerator-Evilginx.git phishletgen
cd phishletgen
pip install -r requirements.txt && playwright install chromium
cp ../PhishHook/.env.phishletgen.example ../PhishHook/.env   # optional AI keys
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Or use the compose file from the PhishHook repo, which brings up everything including FlareSolverr (see [Phishlet Generator](#phishlet-generator)).

### Step 5 — Configure and start evilginx

```bash
./evilginx -p ./phishlets \
    -restapi 127.0.0.1:8443 \
    -restapi-token <generate-a-long-random-secret> \
    -developer   # omit for autocert once DNS is live
```

In the evilginx terminal, do the first-run config:

```
config domain phish.example.com          # base domain for all phishlets
config ipv4 external <evilginx-host-ip>
config gophish admin_url https://127.0.0.1:3333
config gophish api_key <phishhook-api-key>
config gophish test                      # should say: connection successful
```

The PhishHook API key is shown under **Account Settings → API Key**. This pairing is what lets evilginx report opened/clicked/submitted events into campaign timelines.

### Step 6 — Configure and start PhishHook

Edit `config.json`, adding the bridge sections:

```json
{
  "admin_server": { "listen_url": "127.0.0.1:3333", "use_tls": true },
  "phish_server": { "listen_url": "0.0.0.0:8443", "use_tls": true },
  "evilginx": {
    "api_url": "http://127.0.0.1:8443",
    "api_key": "<the -restapi-token value>"
  },
  "phishlet_generator": {
    "url": "http://127.0.0.1:8000"
  }
}
```

Start it:

```bash
./gophish
```

First run prints a generated admin password to the log and flags `password_change_required` — log in, set your own password, and grab the API key from **Account Settings**.

**Keeping the stack alive** — systemd units for both processes:

```ini
# /etc/systemd/system/phishhook.service
[Unit]
Description=PhishHook
After=network.target

[Service]
WorkingDirectory=/opt/phishhook
ExecStart=/opt/phishhook/gophish
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
ExecStart=/opt/evilginx/evilginx -p /opt/evilginx/phishlets -restapi 127.0.0.1:8443 -restapi-token TOKEN
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

### Step 7 — Verify the wiring

Log into the PhishHook UI and open **Evilginx**:

- **Status** tab should show the evilginx version, base domain, and your external IP. If it errors "not configured", the bridge section isn't in `config.json`; if it's a connection error, the API isn't running or the token is wrong.
- **Generator** tab should show the wizard instead of the setup hint.

### Step 8 — Phishlet workflow

1. **Generate:** Evilginx → **Generator** → paste the target's real login URL → *Generate Phishlet* (watch live analysis progress; toggle AI refinement if keys are configured) → review warnings/suggestions → **Validate** → **Save to Library** and/or **Download** the YAML.
2. **Load:** copy the YAML into evilginx's `phishlets/` directory (evilginx loads phishlets at startup — restart the service after adding files).
3. **Configure:** Evilginx → **Phishlets** → set the **Hostname** for the phishlet (must be under the base domain) → **Enable**.
4. **Pre-launch check:** click **Verify** — every host in the list must be green. A red row means a missing DNS record; the campaign will be dead on arrival.

### Step 9 — Lure and campaign

1. Evilginx → **Lures** → **New Lure** (pick the phishlet, optionally set a redirect URL) → **Copy URL** for external use, or click **Campaign** to jump straight into the campaign wizard pre-filled (evilginx mode on, lure URL set, encryption key generated).
2. The **Lure Encryption Key** must match evilginx's `config enc_key <value>` — set one side to match the other.
3. Pick a template, sending profile, and group; launch. `{{.URL}}` in the template resolves to the per-recipient encrypted lure.

### Step 10 — Monitor and close out

- **Campaigns** show the normal metrics; evilginx reports opened/clicked/submitted into the same timeline.
- **Evilginx → Sessions** lists captures **correlated with campaigns** — each session is matched to its recipient, and the detail modal shows the merged timeline plus credentials and auth cookies (JSON-copyable for session replay).
- **Teardown:** complete the campaign in PhishHook (stops callbacks), disable the phishlet in the console, then delete captured sessions from the console when the engagement ends.

### Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| Login "reloads" the page | Old builds only: session cookie was `SameSite=None` without `Secure` on plain HTTP — fixed in `d317480`; update. |
| Evilginx tab: "not configured" | `evilginx` section missing from `config.json`, or server not restarted after adding it |
| Evilginx tab: connection error | REST API not running on `api_url`, or token mismatch |
| 403 on admin form posts | Reverse proxy stripping Origin/Referer on HTTPS deployments — ensure `X-Forwarded-Proto` handling or run admin server with `use_tls: true` |
| Phishlet enable fails | Hostname not set, or hostname not a subdomain of the evilginx base domain |
| Verify shows red rows | Missing/wrong DNS records, or records not propagated yet |
| Targets get 404 on lure | Phishlet disabled, lure deleted, or evilginx restarted and hostname unset |
| No results in campaign timeline | evilginx `config gophish` pairing missing or wrong API key — `config gophish test` in evilginx |
| Generator tab shows setup hint | `phishlet_generator` section missing, or sidecar down |

## CLI Options

| Flag | Description |
|------|-------------|
| `--config` | Path to config.json (default: ./config.json) |
| `--domain` | Domain for Let's Encrypt SSL |
| `--disable-mailer` | Disable built-in mailer |
| `--mode` | Run mode: all, admin, or phish |

## Endpoints

| Endpoint | Description |
|----------|-------------|
| https://localhost:3333 | Admin panel |
| https://your-domain:443 | Phishing server |
| https://your-domain:443/branding?email=user@company.com | Microsoft tenant branding proxy |
| http://127.0.0.1:8443/api/status | evilginx REST API (loopback, bearer token) |
| http://127.0.0.1:8000/api/v1/health | PhishletGenerator backend |

## API

PhishHook is fully compatible with the [GoPhish API](https://docs.getgophish.com/api-documentation/).

```bash
# Example: List campaigns
curl -k -H "Authorization: Bearer YOUR_API_KEY" https://localhost:3333/api/campaigns/
```

## How It Works

```
User clicks phishing link
         |
         v
  +-------------------+
  | Behavioral Check  |
  | - IP blocking     |
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

### Microsoft Tenant Branding

PhishHook can automatically fetch an organization's custom Microsoft 365 login branding, making phishing pages nearly indistinguishable from the real thing.

**How it works:**
1. Landing page includes `{{.BrandingURL}}` template variable
2. When page loads, JavaScript calls the branding endpoint with the target's email
3. PhishHook queries Microsoft's GetCredentialType API
4. Returns the organization's custom background image, logo, and boilerplate text
5. Landing page applies the branding dynamically

**Usage in landing pages:**
```javascript
fetch('{{.BrandingURL}}?email={{.Email}}')
  .then(r => r.json())
  .then(data => {
    if (data.userTenantBranding) {
      document.body.style.backgroundImage = 'url(' + data.backgroundImageUrl + ')';
    }
  });
```

**Response format:**
```json
{
  "success": true,
  "backgroundImageUrl": "https://aadcdn.msauthimages.net/...",
  "bannerLogoUrl": "https://aadcdn.msauthimages.net/...",
  "boilerPlateText": "<p>Custom login text...</p>",
  "userTenantBranding": true
}
```

### Behavioral Detection

The behavioral detection layer runs before Turnstile and blocks requests based on:

1. **IP Blocking**: Requests from Microsoft 365/Exchange Online Protection IP ranges are blocked immediately. These ranges are sourced from the official [Microsoft 365 endpoints API](https://endpoints.office.com/endpoints/worldwide).

2. **Rate Limiting**: IPs making more than `max_requests_per_minute` requests are temporarily blocked.

3. **JS Telemetry**: The challenge page collects behavioral signals:
   - Time spent on page before submission
   - Mouse movement count
   - Click and scroll events
   - Touch events (mobile)
   - Screen dimensions and WebGL support

Safe Links typically hits within seconds of email delivery with no interaction events, making it easy to distinguish from real users.

### Evilginx AiTM Integration

PhishHook ships with native integration for [Evilginx](https://github.com/kgretzky/evilginx2) (AiTM phishing with session-token capture), matching the official Evilginx Gophish integration.

When **Evilginx Mode** is enabled on a campaign:

1. Instead of a Gophish landing page, targets receive an **Evilginx lure URL**.
2. Gophish personalizes each lure URL per recipient (`fname`, `lname`, `email`, `rid`), encrypted so scanners can't decode it:
   - Parameters are RC4-encrypted with a random per-URL key, then wrapped in AES-256-CBC using the campaign's **Lure Encryption Key**.
   - If you leave the key field blank, one is generated for you.
3. Evilginx decrypts the parameters and reports `opened` → `clicked` → `submitted` events back to the PhishHook API, so your campaign results stay complete even though the landing page is served by Evilginx.

**Setup:**

1. On the Evilginx server, pair the encryption key and register the PhishHook API:

   ```
   config enc_key <the campaign's Lure Encryption Key>
   gophish <phishhook-admin-url> <api-key>
   ```

   The API key is shown under **Account Settings** in the PhishHook UI (it authenticates with `Authorization: Bearer`, which Evilginx uses automatically).

2. In PhishHook, create a campaign, tick **Evilginx Mode**, and paste the Evilginx lure URL (e.g. `https://lure.example.com/documents/report.pdf`) into the **URL** field. The landing page selector is hidden — Evilginx serves the target site instead.

3. Reference `{{.URL}}` in your email template as usual; PhishHook emits the encrypted, personalized lure URL for every recipient.

**Notes:**

- The **Lure Encryption Key** must match Evilginx's `enc_key`. If Evilginx runs without an `enc_key`, leave the campaign key blank too.
- Open tracking uses Evilginx's open-pixel callback, so no Gophish listener needs to be reachable from the lure domain.
- The API can create evilginx-mode campaigns directly:

  ```bash
  curl -k -X POST https://localhost:3333/api/campaigns/?api_key=YOUR_API_KEY \
    -d '{
      "name": "Evilginx Campaign",
      "template": {"name": "Template"},
      "smtp": {"name": "Profile"},
      "groups": [{"name": "Targets"}],
      "url": "https://lure.example.com/report.pdf",
      "evilginx_mode": true,
      "encryption_key": "shared-with-evilginx"
    }'
  ```

### Evilginx Management Console

PhishHook includes a full GUI for evilginx (admin-only, **Evilginx** in the sidebar) with tabs for status, phishlets, lures and captured sessions. The console talks to evilginx through a REST API added by the [evilginx3-phishhook](https://github.com/wcrooker/evilginx3-phishhook) fork — everything else in that fork works exactly like upstream evilginx.

**1. Run evilginx with the REST API enabled (same host as PhishHook):**

```bash
./evilginx -p ./phishlets -restapi 127.0.0.1:8443 -restapi-token <choose-a-secret>
```

**2. Configure the bridge in PhishHook's `config.json` and restart:**

```json
"evilginx": {
    "api_url": "http://127.0.0.1:8443",
    "api_key": "<the -restapi-token value>"
}
```

**3. Open the Evilginx page in PhishHook.** You can:

- **Status** — version, base domain, autocert, gophish pairing, session counts
- **Phishlets** — enable/disable, set hostnames, view the DNS records each phishlet needs, and run a **DNS pre-launch check** (resolves every phishlet hostname and confirms it points at the evilginx server — a red row means the phishlet will be dead)
- **Lures** — create, copy URLs, delete, and jump straight to a **pre-filled campaign** (evilginx mode on, lure URL set, encryption key generated)
- **Sessions** — browse captured sessions **correlated with PhishHook campaigns**: each session is matched back to its recipient by decrypting the lure parameters, and the detail modal shows the merged timeline (opened → clicked → submitted → session captured) plus credentials, auth cookies, and exportable JSON

The browser never talks to the evilginx API directly — every request goes through PhishHook's authenticated admin API (`/api/evilginx/*`, requires the Modify System permission), and PhishHook forwards to the loopback API.

### Phishlet Generator

The console's **Generator** tab drives the [PhishletGenerator](https://github.com/wcrooker/PhishletGenerator-Evilginx) sidecar (Playwright-based target analysis → phishlet YAML → validation), with an optional AI refinement toggle and live WebSocket progress during analysis. The sidecar runs on the compose network and is reached only through the authenticated `/api/phishletgen/*` proxy (WebSockets included).

**Standalone setup:** run the generator's backend (`uvicorn app.main:app --port 8000` inside the generator repo), then set in `config.json`:

```json
"phishlet_generator": {
    "url": "http://127.0.0.1:8000"
}
```

**Docker setup (everything together):**

```bash
git clone git@github.com:wcrooker/PhishletGenerator-Evilginx.git phishletgen
cp .env.phishletgen.example .env   # optional AI keys
docker compose -f docker-compose.phishletgen.yml up -d --build
```

## License

MIT License - Based on [GoPhish](https://github.com/gophish/gophish) by Jordan Wright

## Disclaimer

This tool is intended for authorized security testing and red team operations only. Unauthorized use against systems you do not own or have explicit permission to test is illegal. Always obtain proper written authorization before conducting phishing assessments.
