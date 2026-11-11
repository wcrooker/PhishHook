package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gophish/gophish/evilginx"
	"github.com/gophish/gophish/models"
	"github.com/gorilla/mux"
)

// evilginxActionVars returns the route variables for evilginx actions.
func evilginxActionVars(r *http.Request) map[string]string {
	return mux.Vars(r)
}

// evilginx returns the evilginx REST API client for this server, or nil
// when evilginx is not configured.
func (as *Server) evilginx(r *http.Request) *evilginx.Client {
	return as.evilginxClient
}

// requireEvilginx writes an error response and returns false when the
// evilginx bridge is not configured.
func (as *Server) requireEvilginx(w http.ResponseWriter, r *http.Request) *evilginx.Client {
	client := as.evilginx(r)
	if client == nil || !client.Configured() {
		JSONResponse(w, models.Response{
			Success: false,
			Message: "Evilginx is not configured. Set the 'evilginx' section in config.json and restart.",
		}, http.StatusServiceUnavailable)
		return nil
	}
	return client
}

// decodeJSONBody decodes the request body into dst, writing a 400 on
// malformed input.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid JSON structure"}, http.StatusBadRequest)
		return false
	}
	return true
}

// writeEvilginxError converts an evilginx client error into a JSON API
// response.
func writeEvilginxError(w http.ResponseWriter, err error) {
	if apiErr, ok := err.(*evilginx.APIError); ok {
		status := http.StatusBadGateway
		switch apiErr.StatusCode {
		case http.StatusNotFound:
			status = http.StatusNotFound
		case http.StatusBadRequest:
			status = http.StatusBadRequest
		case http.StatusUnauthorized:
			status = http.StatusBadGateway
		}
		JSONResponse(w, models.Response{Success: false, Message: apiErr.Message}, status)
		return
	}
	JSONResponse(w, models.Response{Success: false, Message: err.Error()}, http.StatusBadGateway)
}

// EvilginxStatus returns the evilginx server status.
func (as *Server) EvilginxStatus(w http.ResponseWriter, r *http.Request) {
	client := as.requireEvilginx(w, r)
	if client == nil {
		return
	}
	status, err := client.GetStatus()
	if err != nil {
		writeEvilginxError(w, err)
		return
	}
	JSONResponse(w, status, http.StatusOK)
}

// EvilginxPhishlets lists, enables, disables or rehosts phishlets.
func (as *Server) EvilginxPhishlets(w http.ResponseWriter, r *http.Request) {
	client := as.requireEvilginx(w, r)
	if client == nil {
		return
	}
	if r.Method != http.MethodGet {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}
	phishlets, err := client.ListPhishlets()
	if err != nil {
		writeEvilginxError(w, err)
		return
	}
	JSONResponse(w, phishlets, http.StatusOK)
}

// EvilginxPhishletAction performs a runtime action on a phishlet:
// enable, disable, hostname, or hosts (DNS records).
func (as *Server) EvilginxPhishletAction(w http.ResponseWriter, r *http.Request) {
	client := as.requireEvilginx(w, r)
	if client == nil {
		return
	}
	if r.Method != http.MethodPost {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}
	vars := evilginxActionVars(r)
	name := vars["name"]
	action := vars["action"]
	if name == "" || action == "" {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid phishlet or action"}, http.StatusBadRequest)
		return
	}
	switch action {
	case "enable":
		if err := client.EnablePhishlet(name); err != nil {
			writeEvilginxError(w, err)
			return
		}
	case "disable":
		if err := client.DisablePhishlet(name); err != nil {
			writeEvilginxError(w, err)
			return
		}
	case "hostname":
		body := struct {
			Hostname string `json:"hostname"`
		}{}
		if !decodeJSONBody(w, r, &body) {
			return
		}
		if err := client.SetPhishletHostname(name, body.Hostname); err != nil {
			writeEvilginxError(w, err)
			return
		}
	default:
		JSONResponse(w, models.Response{Success: false, Message: "Unknown action"}, http.StatusBadRequest)
		return
	}
	JSONResponse(w, models.Response{Success: true, Message: "Action completed"}, http.StatusOK)
}

// EvilginxPhishletHosts returns the DNS records for a phishlet.
func (as *Server) EvilginxPhishletHosts(w http.ResponseWriter, r *http.Request) {
	client := as.requireEvilginx(w, r)
	if client == nil {
		return
	}
	if r.Method != http.MethodGet {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}
	vars := evilginxActionVars(r)
	name := vars["name"]
	if name == "" {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid phishlet"}, http.StatusBadRequest)
		return
	}
	records, err := client.GetPhishletHosts(name)
	if err != nil {
		writeEvilginxError(w, err)
		return
	}
	JSONResponse(w, map[string]interface{}{"phishlet": name, "records": records}, http.StatusOK)
}

// EvilginxLures lists and creates lures.
func (as *Server) EvilginxLures(w http.ResponseWriter, r *http.Request) {
	client := as.requireEvilginx(w, r)
	if client == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		lures, err := client.ListLures()
		if err != nil {
			writeEvilginxError(w, err)
			return
		}
		JSONResponse(w, lures, http.StatusOK)
	case http.MethodPost:
		var l evilginx.Lure
		if !decodeJSONBody(w, r, &l) {
			return
		}
		created, err := client.CreateLure(l)
		if err != nil {
			writeEvilginxError(w, err)
			return
		}
		JSONResponse(w, created, http.StatusCreated)
	default:
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
	}
}

// EvilginxLure gets, updates or deletes a single lure.
func (as *Server) EvilginxLure(w http.ResponseWriter, r *http.Request) {
	client := as.requireEvilginx(w, r)
	if client == nil {
		return
	}
	vars := evilginxActionVars(r)
	id := vars["id"]
	if id == "" {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid lure id"}, http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		lures, err := client.ListLures()
		if err != nil {
			writeEvilginxError(w, err)
			return
		}
		for _, l := range lures {
			if l.Id == id {
				JSONResponse(w, l, http.StatusOK)
				return
			}
		}
		JSONResponse(w, models.Response{Success: false, Message: "Lure not found"}, http.StatusNotFound)
	case http.MethodPut:
		var l evilginx.Lure
		if !decodeJSONBody(w, r, &l) {
			return
		}
		updated, err := client.UpdateLure(id, l)
		if err != nil {
			writeEvilginxError(w, err)
			return
		}
		JSONResponse(w, updated, http.StatusOK)
	case http.MethodDelete:
		if err := client.DeleteLure(id); err != nil {
			writeEvilginxError(w, err)
			return
		}
		JSONResponse(w, models.Response{Success: true, Message: "Lure deleted"}, http.StatusOK)
	default:
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
	}
}

// EvilginxSessions lists captured sessions.
func (as *Server) EvilginxSessions(w http.ResponseWriter, r *http.Request) {
	client := as.requireEvilginx(w, r)
	if client == nil {
		return
	}
	if r.Method != http.MethodGet {
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}
	sessions, err := client.ListSessions()
	if err != nil {
		writeEvilginxError(w, err)
		return
	}
	JSONResponse(w, sessions, http.StatusOK)
}

// EvilginxSession gets or deletes a captured session.
func (as *Server) EvilginxSession(w http.ResponseWriter, r *http.Request) {
	client := as.requireEvilginx(w, r)
	if client == nil {
		return
	}
	vars := evilginxActionVars(r)
	sid := vars["id"]
	if sid == "" || strings.Contains(sid, "/") {
		JSONResponse(w, models.Response{Success: false, Message: "Invalid session id"}, http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		detail, err := client.GetSession(sid)
		if err != nil {
			writeEvilginxError(w, err)
			return
		}
		JSONResponse(w, detail, http.StatusOK)
	case http.MethodDelete:
		if err := client.DeleteSession(sid); err != nil {
			writeEvilginxError(w, err)
			return
		}
		JSONResponse(w, models.Response{Success: true, Message: "Session deleted"}, http.StatusOK)
	default:
		JSONResponse(w, models.Response{Success: false, Message: "Method not allowed"}, http.StatusMethodNotAllowed)
	}
}
