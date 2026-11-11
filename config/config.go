package config

import (
	"encoding/json"
	"io/ioutil"

	log "github.com/gophish/gophish/logger"
)

// AdminServer represents the Admin server configuration details
type AdminServer struct {
	ListenURL            string   `json:"listen_url"`
	UseTLS               bool     `json:"use_tls"`
	CertPath             string   `json:"cert_path"`
	KeyPath              string   `json:"key_path"`
	CSRFKey              string   `json:"csrf_key"`
	AllowedInternalHosts []string `json:"allowed_internal_hosts"`
	TrustedOrigins       []string `json:"trusted_origins"`
}

// PhishServer represents the Phish server configuration details
type PhishServer struct {
	ListenURL string `json:"listen_url"`
	UseTLS    bool   `json:"use_tls"`
	CertPath  string `json:"cert_path"`
	KeyPath   string `json:"key_path"`
	Domain    string `json:"-"` // Set via CLI flag, not config file
}

type TurnstileConfig struct {
	Enabled      bool   `json:"enabled"`
	SiteKey      string `json:"site_key"`
	SecretKey    string `json:"secret_key"`
	CookieSecret string `json:"cookie_secret"`
}

type EvasionConfig struct {
	Enabled           bool   `json:"enabled"`
	StripServerHeader bool   `json:"strip_server_header"`
	CustomServerName  string `json:"custom_server_name"`
}

type BehavioralConfig struct {
	Enabled              bool     `json:"enabled"`
	MinTimeOnPage        int      `json:"min_time_on_page_ms"`
	RequireMouseMovement bool     `json:"require_mouse_movement"`
	RequireInteraction   bool     `json:"require_interaction"`
	BlockMicrosoftIPs    bool     `json:"block_microsoft_ips"`
	CustomBlockedCIDRs   []string `json:"custom_blocked_cidrs"`
	MaxRequestsPerMinute int      `json:"max_requests_per_minute"`
	WindowsOnly          bool     `json:"windows_only"`
}

type BrandingConfig struct {
	Enabled        bool     `json:"enabled"`
	AllowedOrigins []string `json:"allowed_origins"`
}

// EvilginxConfig configures the bridge to a local evilginx instance
// running the PhishHook REST API fork (evilginx3-phishhook).
type EvilginxConfig struct {
	// APIURL is the base URL of the evilginx REST API. The API is
	// intended to be bound to loopback and reached from PhishHook on
	// the same host.
	APIURL string `json:"api_url"`
	// APIKey is the bearer token the evilginx REST API requires.
	APIKey string `json:"api_key"`
}

// PhishletGeneratorConfig configures the optional RTLPhishletGenerator
// sidecar service used to generate phishlets from target URLs.
type PhishletGeneratorConfig struct {
	// URL is the base URL of the generator's backend API, e.g.
	// http://127.0.0.1:8000. When set, the admin API proxies
	// /api/phishletgen/* to the generator's /api/v1/* endpoints.
	URL string `json:"url"`
}

type Config struct {
	AdminConf         AdminServer              `json:"admin_server"`
	PhishConf         PhishServer              `json:"phish_server"`
	DBName            string                   `json:"db_name"`
	DBPath            string                   `json:"db_path"`
	DBSSLCaPath       string                   `json:"db_sslca_path"`
	MigrationsPath    string                   `json:"migrations_prefix"`
	TestFlag          bool                     `json:"test_flag"`
	ContactAddress    string                   `json:"contact_address"`
	Logging           *log.Config              `json:"logging"`
	Turnstile         *TurnstileConfig         `json:"turnstile,omitempty"`
	Evasion           *EvasionConfig           `json:"evasion,omitempty"`
	Behavioral        *BehavioralConfig        `json:"behavioral,omitempty"`
	Branding          *BrandingConfig          `json:"branding,omitempty"`
	Evilginx          *EvilginxConfig          `json:"evilginx,omitempty"`
	PhishletGenerator *PhishletGeneratorConfig `json:"phishlet_generator,omitempty"`
}

// Version contains the current gophish version
var Version = ""

// ServerName is the server type that is returned in the transparency response.
const ServerName = "gophish"

// LoadConfig loads the configuration from the specified filepath
func LoadConfig(filepath string) (*Config, error) {
	// Get the config file
	configFile, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	config := &Config{}
	err = json.Unmarshal(configFile, config)
	if err != nil {
		return nil, err
	}
	if config.Logging == nil {
		config.Logging = &log.Config{}
	}
	// Choosing the migrations directory based on the database used.
	config.MigrationsPath = config.MigrationsPath + config.DBName
	// Explicitly set the TestFlag to false to prevent config.json overrides
	config.TestFlag = false
	return config, nil
}
