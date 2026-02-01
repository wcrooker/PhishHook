package evasion

import (
	"net/http"
	"strings"
)

// EvasionConfig holds evasion middleware configuration
type EvasionConfig struct {
	Enabled           bool   `json:"enabled"`
	StripServerHeader bool   `json:"strip_server_header"`
	CustomServerName  string `json:"custom_server_name"`
}

// EvasionMiddleware removes identifying headers and fingerprints
type EvasionMiddleware struct {
	config *EvasionConfig
}

// NewEvasionMiddleware creates a new evasion middleware instance
func NewEvasionMiddleware(config *EvasionConfig) *EvasionMiddleware {
	return &EvasionMiddleware{config: config}
}

// IsEnabled returns whether evasion is enabled
func (em *EvasionMiddleware) IsEnabled() bool {
	return em.config.Enabled
}

// GetServerName returns the server name to use (or empty to strip)
func (em *EvasionMiddleware) GetServerName() string {
	if em.config.StripServerHeader {
		return ""
	}
	if em.config.CustomServerName != "" {
		return em.config.CustomServerName
	}
	return "IGNORE"
}

// Wrap wraps an http.Handler with evasion headers stripping
func (em *EvasionMiddleware) Wrap(next http.Handler) http.Handler {
	if !em.config.Enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap the ResponseWriter to intercept header writes
		ew := &evasionResponseWriter{
			ResponseWriter: w,
			middleware:     em,
		}
		next.ServeHTTP(ew, r)
	})
}

// evasionResponseWriter wraps http.ResponseWriter to strip headers
type evasionResponseWriter struct {
	http.ResponseWriter
	middleware *EvasionMiddleware
}

// WriteHeader intercepts the status code and strips identifying headers
func (ew *evasionResponseWriter) WriteHeader(code int) {
	// Remove identifying headers before writing
	ew.stripHeaders()
	ew.ResponseWriter.WriteHeader(code)
}

// Write ensures headers are stripped before writing body
func (ew *evasionResponseWriter) Write(b []byte) (int, error) {
	ew.stripHeaders()
	return ew.ResponseWriter.Write(b)
}

func (ew *evasionResponseWriter) stripHeaders() {
	h := ew.ResponseWriter.Header()

	// Strip X-Server header or replace with custom value
	serverName := ew.middleware.GetServerName()
	if serverName == "" {
		h.Del("X-Server")
	} else {
		h.Set("X-Server", serverName)
	}

	// Strip other identifying headers
	h.Del("X-Powered-By")
	h.Del("X-AspNet-Version")
	h.Del("X-AspNetMvc-Version")

	// Remove any headers starting with X-Gophish or X-Phish
	for key := range h {
		keyLower := strings.ToLower(key)
		if strings.HasPrefix(keyLower, "x-gophish") || strings.HasPrefix(keyLower, "x-phish") {
			h.Del(key)
		}
	}
}

// ResponseWriterFlusher allows access to the Flusher interface if available
func (ew *evasionResponseWriter) Flush() {
	if f, ok := ew.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
