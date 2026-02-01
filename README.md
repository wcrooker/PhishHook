# PhishHook

Enhanced GoPhish fork with evasion capabilities for professional red team operations.

## Features

PhishHook extends GoPhish with:

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

Same as GoPhish:

```bash
./gophish
```

Admin panel: https://localhost:3333
Phishing server: http://localhost:80

## License

MIT License - Based on [GoPhish](https://github.com/gophish/gophish) by Jordan Wright

## Disclaimer

This tool is intended for authorized security testing and red team operations only. Ensure you have proper authorization before use.
