<p align="center">
  <img src="static/images/phishhook_logo.png" alt="PhishHook Logo" width="128">
</p>

<h1 align="center">PhishHook</h1>

<p align="center">
  Enhanced GoPhish fork with evasion capabilities for professional red team operations.
</p>

## Features

- **Automatic Let's Encrypt SSL**: Use `--domain` flag for automatic certificate provisioning
- **Cloudflare Turnstile Integration**: Bot protection that blocks automated scanners (Safe Links, security crawlers) while allowing real users through
- **Header Evasion**: Strips identifying headers (`X-Server: gophish`, etc.) that fingerprint the server
- **Full GoPhish Compatibility**: All upstream GoPhish features work as expected

## Why PhishHook?

Microsoft Safe Links and similar email security products crawl phishing links before users click them, generating false positive "clicks" in your campaign metrics. PhishHook solves this by:

1. **Turnstile Challenge**: Automated scanners can't solve the Cloudflare challenge, so they never reach the landing page
2. **Click Recording**: Only users who pass the challenge are recorded as clicks
3. **Clean Metrics**: Your campaign data reflects actual human interactions

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

## API

PhishHook is fully compatible with the [GoPhish API](https://docs.getgophish.com/api-documentation/).

```bash
# Example: List campaigns
curl -k -H "Authorization: Bearer YOUR_API_KEY" https://localhost:3333/api/campaigns/
```

## How Turnstile Works

```
User clicks phishing link
         |
         v
  +----------------+
  | Turnstile      |
  | Challenge Page |
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
          +----------------+
          | Landing Page   |
          | (click recorded)|
          +----------------+
```

## License

MIT License - Based on [GoPhish](https://github.com/gophish/gophish) by Jordan Wright

## Disclaimer

This tool is intended for authorized security testing and red team operations only. Unauthorized use against systems you do not own or have explicit permission to test is illegal. Always obtain proper written authorization before conducting phishing assessments.
