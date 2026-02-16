package api

import (
	"net/http"

	"github.com/gophish/gophish/models"
)

type BrandingStatusResponse struct {
	Enabled        bool     `json:"enabled"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
}

func (as *Server) BrandingStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	cfg := models.GetBrandingConfig()
	resp := BrandingStatusResponse{
		Enabled: false,
	}

	if cfg != nil {
		resp.Enabled = cfg.Enabled
		resp.AllowedOrigins = cfg.AllowedOrigins
	}

	JSONResponse(w, resp, http.StatusOK)
}
