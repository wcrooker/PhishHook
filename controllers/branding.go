package controllers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gophish/gophish/config"
	log "github.com/gophish/gophish/logger"
)

type BrandingHandler struct {
	config *config.BrandingConfig
	client *http.Client
}

type getCredentialTypeRequest struct {
	Username                       string `json:"username"`
	IsOtherIdpSupported            bool   `json:"isOtherIdpSupported"`
	CheckPhones                    bool   `json:"checkPhones"`
	IsRemoteNGCSupported           bool   `json:"isRemoteNGCSupported"`
	IsCookieBannerShown            bool   `json:"isCookieBannerShown"`
	IsFidoSupported                bool   `json:"isFidoSupported"`
	Country                        string `json:"country,omitempty"`
	Forceotclogin                  bool   `json:"forceotclogin"`
	IsExternalFederationDisallowed bool   `json:"isExternalFederationDisallowed"`
	IsRemoteConnectSupported       bool   `json:"isRemoteConnectSupported"`
	FederationFlags                int    `json:"federationFlags"`
	IsSignup                       bool   `json:"isSignup"`
}

type BrandingResponse struct {
	Success            bool   `json:"success"`
	BackgroundImageURL string `json:"backgroundImageUrl,omitempty"`
	BannerLogoURL      string `json:"bannerLogoUrl,omitempty"`
	BoilerPlateText    string `json:"boilerPlateText,omitempty"`
	UserTenantBranding bool   `json:"userTenantBranding"`
	Error              string `json:"error,omitempty"`
}

func NewBrandingHandler(cfg *config.BrandingConfig) *BrandingHandler {
	return &BrandingHandler{
		config: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (bh *BrandingHandler) IsEnabled() bool {
	return bh.config != nil && bh.config.Enabled
}

func (bh *BrandingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if bh.isOriginAllowed(origin) {
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	var email string
	if r.Method == http.MethodGet {
		email = r.URL.Query().Get("email")
	} else if r.Method == http.MethodPost {
		var req struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			email = req.Email
		}
	}

	if email == "" {
		json.NewEncoder(w).Encode(BrandingResponse{
			Success: false,
			Error:   "email parameter required",
		})
		return
	}

	log.Infof("Fetching branding for: %s", email)

	branding, err := bh.fetchMicrosoftBranding(email)
	if err != nil {
		log.Errorf("Error fetching branding: %v", err)
		json.NewEncoder(w).Encode(BrandingResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	log.Infof("Branding fetched successfully (has background: %v)", branding.BackgroundImageURL != "")
	json.NewEncoder(w).Encode(branding)
}

func (bh *BrandingHandler) isOriginAllowed(origin string) bool {
	if bh.config == nil || len(bh.config.AllowedOrigins) == 0 {
		return true
	}
	for _, allowed := range bh.config.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

func (bh *BrandingHandler) fetchMicrosoftBranding(email string) (*BrandingResponse, error) {
	msReq := getCredentialTypeRequest{
		Username:                       email,
		IsOtherIdpSupported:            true,
		CheckPhones:                    false,
		IsRemoteNGCSupported:           true,
		IsCookieBannerShown:            false,
		IsFidoSupported:                true,
		Forceotclogin:                  false,
		IsExternalFederationDisallowed: false,
		IsRemoteConnectSupported:       true,
		FederationFlags:                0,
		IsSignup:                       false,
	}

	reqBody, err := json.Marshal(msReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/common/GetCredentialType", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", "https://login.microsoftonline.com")
	req.Header.Set("Referer", "https://login.microsoftonline.com/")

	resp, err := bh.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var msResp map[string]interface{}
	if err := json.Unmarshal(body, &msResp); err != nil {
		return nil, err
	}

	result := &BrandingResponse{
		Success: true,
	}

	if ests, ok := msResp["EstsProperties"].(map[string]interface{}); ok {
		// UserTenantBranding can be an array or object
		if brandingArray, ok := ests["UserTenantBranding"].([]interface{}); ok && len(brandingArray) > 0 {
			if branding, ok := brandingArray[0].(map[string]interface{}); ok {
				result.UserTenantBranding = true
				bh.extractBranding(branding, result)
			}
		} else if branding, ok := ests["UserTenantBranding"].(map[string]interface{}); ok {
			result.UserTenantBranding = true
			bh.extractBranding(branding, result)
		}
	}

	if branding, ok := msResp["Branding"].(map[string]interface{}); ok {
		result.UserTenantBranding = true
		bh.extractBranding(branding, result)
	}

	return result, nil
}

func (bh *BrandingHandler) extractBranding(branding map[string]interface{}, result *BrandingResponse) {
	// Try multiple field name variants (Microsoft API is inconsistent)
	if v, ok := branding["Illustration"].(string); ok && v != "" {
		result.BackgroundImageURL = v
	} else if v, ok := branding["BackgroundImageUrl"].(string); ok && v != "" {
		result.BackgroundImageURL = v
	}

	if v, ok := branding["BannerLogo"].(string); ok && v != "" {
		result.BannerLogoURL = v
	} else if v, ok := branding["BannerLogoUrl"].(string); ok && v != "" {
		result.BannerLogoURL = v
	}

	if v, ok := branding["BoilerPlateText"].(string); ok && v != "" {
		result.BoilerPlateText = v
	}
}

func WithBranding(cfg *config.BrandingConfig) PhishingServerOption {
	return func(ps *PhishingServer) {
		if cfg != nil && cfg.Enabled {
			ps.brandingHandler = NewBrandingHandler(cfg)
		}
	}
}

func GetBrandingURL(baseURL string, cfg *config.BrandingConfig) string {
	if cfg == nil || !cfg.Enabled {
		return ""
	}
	return strings.TrimSuffix(baseURL, "/") + "/branding"
}
