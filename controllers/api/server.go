package api

import (
	"net/http"

	"github.com/gophish/gophish/evilginx"
	log "github.com/gophish/gophish/logger"
	mid "github.com/gophish/gophish/middleware"
	"github.com/gophish/gophish/middleware/ratelimit"
	"github.com/gophish/gophish/models"
	"github.com/gophish/gophish/worker"
	"github.com/gorilla/mux"
)

// ServerOption is an option to apply to the API server.
type ServerOption func(*Server)

// Server represents the routes and functionality of the Gophish API.
// It's not a server in the traditional sense, in that it isn't started and
// stopped. Rather, it's meant to be used as an http.Handler in the
// AdminServer.
type Server struct {
	handler          http.Handler
	worker           worker.Worker
	limiter          *ratelimit.PostLimiter
	evilginxClient   *evilginx.Client
	phishletGenProxy http.Handler
}

// NewServer returns a new instance of the API handler with the provided
// options applied.
func NewServer(options ...ServerOption) *Server {
	defaultWorker, _ := worker.New()
	defaultLimiter := ratelimit.NewPostLimiter()
	as := &Server{
		worker:  defaultWorker,
		limiter: defaultLimiter,
	}
	for _, opt := range options {
		opt(as)
	}
	as.registerRoutes()
	return as
}

// WithWorker is an option that sets the background worker.
func WithWorker(w worker.Worker) ServerOption {
	return func(as *Server) {
		as.worker = w
	}
}

func WithLimiter(limiter *ratelimit.PostLimiter) ServerOption {
	return func(as *Server) {
		as.limiter = limiter
	}
}

// WithEvilginxClient is an option that sets the evilginx REST API client.
func WithEvilginxClient(client *evilginx.Client) ServerOption {
	return func(as *Server) {
		as.evilginxClient = client
	}
}

// WithPhishletGenURL is an option that enables the phishlet generator
// sidecar reverse proxy for the given base URL.
func WithPhishletGenURL(generatorURL string) ServerOption {
	return func(as *Server) {
		if generatorURL == "" {
			return
		}
		proxy, err := newPhishletGenProxy(generatorURL)
		if err != nil {
			log.Errorf("phishlet generator proxy disabled: %v", err)
			return
		}
		as.phishletGenProxy = proxy
	}
}

func (as *Server) registerRoutes() {
	root := mux.NewRouter()
	root = root.StrictSlash(true)
	router := root.PathPrefix("/api/").Subrouter()
	router.Use(mid.RequireAPIKey)
	router.Use(mid.EnforceViewOnly)
	router.HandleFunc("/imap/", as.IMAPServer)
	router.HandleFunc("/imap/validate", as.IMAPServerValidate)
	router.HandleFunc("/reset", as.Reset)
	router.HandleFunc("/campaigns/", as.Campaigns)
	router.HandleFunc("/campaigns/summary", as.CampaignsSummary)
	router.HandleFunc("/campaigns/{id:[0-9]+}", as.Campaign)
	router.HandleFunc("/campaigns/{id:[0-9]+}/results", as.CampaignResults)
	router.HandleFunc("/campaigns/{id:[0-9]+}/summary", as.CampaignSummary)
	router.HandleFunc("/campaigns/{id:[0-9]+}/complete", as.CampaignComplete)
	router.HandleFunc("/groups/", as.Groups)
	router.HandleFunc("/groups/summary", as.GroupsSummary)
	router.HandleFunc("/groups/{id:[0-9]+}", as.Group)
	router.HandleFunc("/groups/{id:[0-9]+}/summary", as.GroupSummary)
	router.HandleFunc("/templates/", as.Templates)
	router.HandleFunc("/templates/{id:[0-9]+}", as.Template)
	router.HandleFunc("/pages/", as.Pages)
	router.HandleFunc("/pages/{id:[0-9]+}", as.Page)
	router.HandleFunc("/smtp/", as.SendingProfiles)
	router.HandleFunc("/smtp/{id:[0-9]+}", as.SendingProfile)
	router.HandleFunc("/users/", mid.Use(as.Users, mid.RequirePermission(models.PermissionModifySystem)))
	router.HandleFunc("/users/{id:[0-9]+}", mid.Use(as.User))
	router.HandleFunc("/util/send_test_email", as.SendTestEmail)
	router.HandleFunc("/import/group", as.ImportGroup)
	router.HandleFunc("/import/email", as.ImportEmail)
	router.HandleFunc("/import/site", as.ImportSite)
	router.HandleFunc("/webhooks/", mid.Use(as.Webhooks, mid.RequirePermission(models.PermissionModifySystem)))
	router.HandleFunc("/webhooks/{id:[0-9]+}/validate", mid.Use(as.ValidateWebhook, mid.RequirePermission(models.PermissionModifySystem)))
	router.HandleFunc("/webhooks/{id:[0-9]+}", mid.Use(as.Webhook, mid.RequirePermission(models.PermissionModifySystem)))
	router.HandleFunc("/config/branding", as.BrandingStatus)
	router.HandleFunc("/results/{id:[a-zA-Z0-9]+}/open", as.ResultOpen)
	router.HandleFunc("/results/{id:[a-zA-Z0-9]+}/click", as.ResultClick)
	router.HandleFunc("/results/{id:[a-zA-Z0-9]+}/submit", as.ResultSubmit)
	// Evilginx bridge. These proxy the evilginx REST API on loopback and
	// require the Modify System permission.
	evilginxPerm := mid.RequirePermission(models.PermissionModifySystem)
	router.Handle("/evilginx/status", mid.Use(as.EvilginxStatus, evilginxPerm))
	router.Handle("/evilginx/phishlets", mid.Use(as.EvilginxPhishlets, evilginxPerm))
	router.Handle("/evilginx/phishlets/{name}/hosts", mid.Use(as.EvilginxPhishletHosts, evilginxPerm))
	router.Handle("/evilginx/phishlets/{name}/{action}", mid.Use(as.EvilginxPhishletAction, evilginxPerm))
	router.Handle("/evilginx/lures", mid.Use(as.EvilginxLures, evilginxPerm))
	router.Handle("/evilginx/lures/{id:[0-9]+}", mid.Use(as.EvilginxLure, evilginxPerm))
	router.Handle("/evilginx/sessions", mid.Use(as.EvilginxSessions, evilginxPerm))
	router.Handle("/evilginx/sessions/{id:[a-zA-Z0-9]+}", mid.Use(as.EvilginxSession, evilginxPerm))
	// Phishlet generator sidecar reverse proxy. Registered last since it
	// matches a broad path prefix.
	if as.phishletGenProxy != nil {
		router.PathPrefix("/phishletgen/").Handler(as.phishletGenProxy)
	}
	as.handler = router
}

func (as *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	as.handler.ServeHTTP(w, r)
}
