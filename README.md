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
- **Phishlets** — enable/disable, set hostnames, view the DNS records each phishlet needs
- **Lures** — create, copy URLs, delete
- **Sessions** — browse captured sessions, view captured credentials and auth cookies, copy session JSON, delete

The browser never talks to the evilginx API directly — every request goes through PhishHook's authenticated admin API (`/api/evilginx/*`, requires the Modify System permission), and PhishHook forwards to the loopback API.

### Phishlet Generator

The console's **Generator** tab drives the [PhishletGenerator](https://github.com/wcrooker/PhishletGenerator-Evilginx) sidecar (Playwright-based target analysis → phishlet YAML → validation), with an optional AI refinement toggle. The sidecar runs on the compose network and is reached only through the authenticated `/api/phishletgen/*` proxy.

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
