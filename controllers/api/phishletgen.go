package api

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gophish/gophish/models"
)

// newPhishletGenProxy returns a reverse proxy that forwards
// /api/phishletgen/<rest> to <generator>/api/v1/<rest>. The proxy relies
// on the RequireAPIKey middleware in front of it, so the generator API is
// never exposed without PhishHook authentication.
func newPhishletGenProxy(generatorURL string) (http.Handler, error) {
	target, err := url.Parse(generatorURL)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// /api/phishletgen/foo -> /api/v1/foo
		rest := strings.TrimPrefix(req.URL.Path, "/api/phishletgen")
		req.URL.Path = "/api/v1" + rest
		req.Host = target.Host
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		JSONResponse(w, models.Response{
			Success: false,
			Message: "Phishlet generator is unreachable. Check the 'phishlet_generator' section in config.json.",
		}, http.StatusServiceUnavailable)
	}
	return proxy, nil
}
