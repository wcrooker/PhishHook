# PhishHook

Enhanced GoPhish fork with evasion capabilities for professional red team operations.

## Features

PhishHook extends GoPhish with:

- **Automatic Let's Encrypt SSL**: Use `--domain` flag for automatic certificate provisioning
- **Cloudflare Turnstile Integration**: Presents a Cloudflare challenge page before serving phishing content, evading automated scanners and security tools
- **Header Evasion**: Strips identifying headers (`X-Server: gophish`, etc.) that fingerprint the server
- **All GoPhish Features**: Full compatibility with upstream GoPhish functionality

## Building

```bash
go build
```

## Configuration

Add to your `config.json`:

```json
{
  "admin_server": { ... },
  "phish_server": { ... },
  "turnstile": {
    "enabled": true,
    "site_key": "YOUR_CLOUDFLARE_SITE_KEY",
    "secret_key": "YOUR_CLOUDFLARE_SECRET_KEY",
    "cookie_secret": "random-32-char-secret"
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
2. Create a new widget for your phishing domain
3. Copy the Site Key and Secret Key to config.json
4. Generate a random cookie_secret (32+ characters)

### Evasion Options

| Option | Description |
|--------|-------------|
| `enabled` | Enable/disable evasion middleware |
| `strip_server_header` | Remove X-Server header entirely |
| `custom_server_name` | Custom value for X-Server header (default: "IGNORE") |

## Usage

### Basic (Self-Signed SSL)

```bash
./gophish
```

### With Let's Encrypt (Recommended for Production)

```bash
./gophish --domain phish.example.com
```

This will:
1. Start an HTTP server on port 80 for ACME challenges
2. Automatically obtain a Let's Encrypt certificate for your domain
3. Start the phishing server on port 443 with valid SSL
4. Store certificates in the `certs/` directory

**Requirements:**
- Ports 80 and 443 must be open and accessible from the internet
- DNS must be configured to point to your server
- Run as root or use `setcap` for binding to privileged ports

```bash
# Allow binding to ports 80/443 without root
sudo setcap 'cap_net_bind_service=+ep' ./gophish
```

### Endpoints

- Admin panel: https://localhost:3333
- Phishing server: https://your-domain:443 (with --domain) or https://localhost:443 (self-signed)

## License

MIT License - Based on [GoPhish](https://github.com/gophish/gophish) by Jordan Wright

## Disclaimer

This tool is intended for authorized security testing and red team operations only. Ensure you have proper authorization before use.
