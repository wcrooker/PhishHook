package evasion

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	TurnstileVerifyEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	TurnstileCookieName     = "_cf_clearance"
	TurnstileCookieMaxAge   = 24 * time.Hour
	TurnstileTokenField     = "cf-turnstile-response"
)

// TurnstileConfig holds Cloudflare Turnstile configuration
type TurnstileConfig struct {
	Enabled      bool   `json:"enabled"`
	SiteKey      string `json:"site_key"`
	SecretKey    string `json:"secret_key"`
	CookieSecret string `json:"cookie_secret"`
}

// TurnstileResponse is the response from Cloudflare's verification API
type TurnstileResponse struct {
	Success     bool     `json:"success"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
	ChallengeTS string   `json:"challenge_ts,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
}

// TurnstileMiddleware handles Cloudflare Turnstile challenges
type TurnstileMiddleware struct {
	config        *TurnstileConfig
	httpClient    *http.Client
	challengeHTML string
}

// NewTurnstileMiddleware creates a new Turnstile middleware instance
func NewTurnstileMiddleware(config *TurnstileConfig) *TurnstileMiddleware {
	tm := &TurnstileMiddleware{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	tm.challengeHTML = tm.buildChallengeHTML()
	return tm
}

// IsEnabled returns whether Turnstile protection is enabled
func (tm *TurnstileMiddleware) IsEnabled() bool {
	return tm.config.Enabled && tm.config.SiteKey != "" && tm.config.SecretKey != ""
}

// HasValidSession checks if the request has a valid Turnstile session cookie
func (tm *TurnstileMiddleware) HasValidSession(r *http.Request) bool {
	cookie, err := r.Cookie(TurnstileCookieName)
	if err != nil {
		return false
	}
	return tm.validateSessionToken(cookie.Value, getClientIP(r))
}

// ServeChallengePage serves the Turnstile challenge page
func (tm *TurnstileMiddleware) ServeChallengePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tm.challengeHTML))
}

// HandleVerification processes Turnstile token verification
// Returns true if verification succeeded and redirect was sent
func (tm *TurnstileMiddleware) HandleVerification(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}

	token := r.FormValue(TurnstileTokenField)
	if token == "" {
		return false
	}

	clientIP := getClientIP(r)
	if !tm.verifyToken(token, clientIP) {
		return false
	}

	// Set session cookie
	sessionToken := tm.generateSessionToken(clientIP)
	http.SetCookie(w, &http.Cookie{
		Name:     TurnstileCookieName,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   int(TurnstileCookieMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to original URL
	redirect := r.FormValue("redirect")
	if redirect == "" {
		redirect = r.URL.Path
		if r.URL.RawQuery != "" {
			redirect += "?" + r.URL.RawQuery
		}
	}
	http.Redirect(w, r, redirect, http.StatusFound)
	return true
}

// verifyToken validates a Turnstile token with Cloudflare
func (tm *TurnstileMiddleware) verifyToken(token, remoteIP string) bool {
	if token == "" {
		return false
	}

	data := url.Values{}
	data.Set("secret", tm.config.SecretKey)
	data.Set("response", token)
	if remoteIP != "" {
		data.Set("remoteip", remoteIP)
	}

	resp, err := tm.httpClient.PostForm(TurnstileVerifyEndpoint, data)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	var result TurnstileResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false
	}

	return result.Success
}

func (tm *TurnstileMiddleware) generateSessionToken(clientIP string) string {
	data := fmt.Sprintf("%s|%d", clientIP, time.Now().Add(TurnstileCookieMaxAge).Unix())
	mac := hmac.New(sha256.New, []byte(tm.config.CookieSecret))
	mac.Write([]byte(data))
	sig := mac.Sum(nil)
	return base64.URLEncoding.EncodeToString([]byte(data)) + "." + base64.URLEncoding.EncodeToString(sig)
}

func (tm *TurnstileMiddleware) validateSessionToken(token, clientIP string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}

	data, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	sig, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(tm.config.CookieSecret))
	mac.Write(data)
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(sig, expectedSig) {
		return false
	}

	dataParts := strings.SplitN(string(data), "|", 2)
	if len(dataParts) != 2 {
		return false
	}

	var expiry int64
	fmt.Sscanf(dataParts[1], "%d", &expiry)
	if time.Now().Unix() > expiry {
		return false
	}

	return true
}

func (tm *TurnstileMiddleware) buildChallengeHTML() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Just a moment...</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 16px;
            padding: 48px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            text-align: center;
            max-width: 420px;
            width: 90%%;
        }
        .logo {
            width: 120px;
            height: 40px;
            margin: 0 auto 24px;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIwIiBoZWlnaHQ9IjQwIiB2aWV3Qm94PSIwIDAgMTIwIDQwIiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPgo8cGF0aCBkPSJNMjAgMTBMMzAgMjBMMjAgMzBMMTAgMjBMMjAgMTBaIiBmaWxsPSIjRjQ4MTIwIi8+CjxwYXRoIGQ9Ik0yNSAxNUwzNSAyNUwyNSAzNUwxNSAyNUwyNSAxNVoiIGZpbGw9IiNGRkNBMjgiIG9wYWNpdHk9IjAuOCIvPgo8dGV4dCB4PSI0NSIgeT0iMjgiIGZvbnQtZmFtaWx5PSJBcmlhbCIgZm9udC1zaXplPSIxOCIgZm9udC13ZWlnaHQ9ImJvbGQiIGZpbGw9IiMzMzMiPmNsb3VkZmxhcmU8L3RleHQ+Cjwvc3ZnPg==') no-repeat center;
            background-size: contain;
        }
        h1 {
            font-size: 24px;
            font-weight: 600;
            color: #1a1a1a;
            margin-bottom: 8px;
        }
        .subtitle {
            color: #666;
            font-size: 14px;
            margin-bottom: 32px;
        }
        .spinner {
            width: 48px;
            height: 48px;
            border: 4px solid #e5e5e5;
            border-top-color: #f48120;
            border-radius: 50%%;
            animation: spin 1s linear infinite;
            margin: 0 auto 24px;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .turnstile-wrapper {
            display: flex;
            justify-content: center;
            margin: 24px 0;
            min-height: 65px;
        }
        .info {
            font-size: 12px;
            color: #999;
            margin-top: 24px;
        }
        .info a {
            color: #f48120;
            text-decoration: none;
        }
        .ray-id {
            font-family: monospace;
            font-size: 11px;
            color: #ccc;
            margin-top: 16px;
        }
    </style>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body>
    <div class="container">
        <div class="logo"></div>
        <div class="spinner" id="spinner"></div>
        <h1>Checking your connection</h1>
        <p class="subtitle">This process is automatic. Your browser will redirect shortly.</p>
        
        <form method="POST" action="" id="challenge-form">
            <div class="turnstile-wrapper">
                <div class="cf-turnstile" 
                     data-sitekey="%s" 
                     data-callback="onTurnstileSuccess"
                     data-theme="light"
                     data-size="normal"></div>
            </div>
            <input type="hidden" name="redirect" value="">
        </form>
        
        <p class="info">
            Protected by <a href="https://www.cloudflare.com" target="_blank">Cloudflare</a>
        </p>
        <p class="ray-id">Ray ID: <span id="ray-id"></span></p>
    </div>
    
    <script>
        document.getElementById('ray-id').textContent = Math.random().toString(36).substring(2, 18);
        document.querySelector('input[name="redirect"]').value = window.location.href;
        
        var t = {time_on_page_ms:0,mouse_moves:0,mouse_clicks:0,scroll_events:0,key_presses:0,touch_events:0,page_load_time:Date.now(),submit_time:0,screen_width:window.screen.width,screen_height:window.screen.height,has_webgl:false,has_touch:'ontouchstart' in window,device_pixel_ratio:window.devicePixelRatio||1};
        try{var c=document.createElement('canvas');t.has_webgl=!!(c.getContext('webgl')||c.getContext('experimental-webgl'));}catch(e){}
        var lm=0;document.addEventListener('mousemove',function(){var n=Date.now();if(n-lm>50){t.mouse_moves++;lm=n;}},{passive:true});
        document.addEventListener('click',function(){t.mouse_clicks++;},{passive:true});
        var ls=0;document.addEventListener('scroll',function(){var n=Date.now();if(n-ls>100){t.scroll_events++;ls=n;}},{passive:true});
        document.addEventListener('keydown',function(){t.key_presses++;},{passive:true});
        document.addEventListener('touchstart',function(){t.touch_events++;},{passive:true});
        
        function onTurnstileSuccess(token) {
            document.getElementById('spinner').style.display = 'none';
            t.submit_time = Date.now();
            t.time_on_page_ms = t.submit_time - t.page_load_time;
            var i = document.createElement('input');
            i.type = 'hidden';
            i.name = '_telemetry';
            i.value = JSON.stringify(t);
            document.getElementById('challenge-form').appendChild(i);
            document.getElementById('challenge-form').submit();
        }
    </script>
</body>
</html>`, tm.config.SiteKey)
}

func GetClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func getClientIP(r *http.Request) string {
	return GetClientIP(r)
}
