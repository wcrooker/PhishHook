package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ensureRepo clones url into dest (if not already present) and returns the
// URL actually used. A token is embedded in the clone URL when provided.
func ensureRepo(url, dest, token string, batch bool) string {
	if _, err := os.Stat(filepath.Join(dest, ".git")); err == nil {
		fmt.Printf("  %s %s (already cloned)\n", ok("have"), filepath.Base(dest))
		return url
	}
	cloneURL := url
	if token != "" {
		cloneURL = strings.Replace(url, "https://", "https://"+token+"@", 1)
	}
	fmt.Printf("  %s cloning %s ...\n", "...", sanitize(url))
	cmd := exec.Command("git", "clone", "--depth", "1", cloneURL, dest)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := sanitize(stderr.String())
		if token == "" && strings.Contains(msg, "Authentication failed") {
			exitf("cloning %s failed (private repo?) — pass --github-token or set GITHUB_TOKEN\n%s", sanitize(url), msg)
		}
		exitf("cloning %s failed:\n%s", sanitize(url), msg)
	}
	fmt.Printf("  %s cloned %s\n", ok("OK"), sanitize(url))
	return url
}

func sanitize(s string) string {
	if lastDeployToken != "" {
		s = strings.ReplaceAll(s, lastDeployToken, "***")
	}
	return strings.TrimSpace(s)
}

var lastDeployToken string

func composeFile(c *Config) string {
	return filepath.Join(c.DeployDir, "docker-compose.yml")
}

func composeBuild(c *Config) {
	lastDeployDir = c.DeployDir
	lastDeployToken = c.EvilginxToken
	cmd := exec.Command("docker", "compose", "-f", composeFile(c), "build", "--progress", "plain")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		exitf("docker compose build failed")
	}
	fmt.Printf("  %s images built\n", ok("OK"))
}

func composeUp(c *Config) {
	cmd := exec.Command("docker", "compose", "-f", composeFile(c), "up", "-d")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		exitf("docker compose up failed")
	}
	fmt.Printf("  %s stack started\n", ok("OK"))
}

// --- post-start bootstrap ---------------------------------------------------

type apiResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func apiCall(method, url, token string, body interface{}) (int, *apiResponse, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var ar apiResponse
	_ = json.NewDecoder(resp.Body).Decode(&ar)
	return resp.StatusCode, &ar, nil
}

type smtpProfile struct {
	Name             string        `json:"name"`
	Interface        string        `json:"interface_type"`
	Host             string        `json:"host"`
	Username         string        `json:"username"`
	Password         string        `json:"password"`
	FromAddress      string        `json:"from_address"`
	IgnoreCertErrors bool          `json:"ignore_cert_errors"`
	Headers          []interface{} `json:"headers"`
}

func (c *Config) smtpJSON() smtpProfile {
	return smtpProfile{
		Name:             c.SMTPName,
		Interface:        "SMTP",
		Host:             fmt.Sprintf("%s:%d", c.SMTPHost, c.SMTPPort),
		Username:         c.SMTPUser,
		Password:         c.SMTPPass,
		FromAddress:      c.SMTPFrom,
		IgnoreCertErrors: c.SMTPIgnoreCert,
		Headers:          []interface{}{},
	}
}

// bootstrap waits for the admin server, sets the admin password, creates the
// sending profile, and optionally sends a test email.
func bootstrap(c *Config) {
	admin := "http://127.0.0.1:3333"
	fmt.Printf("  waiting for PhishHook admin server ...")
	if err := waitHTTP(admin+"/login", 180*time.Second); err != nil {
		exitf("%v", err)
	}
	fmt.Printf(" %s\n", ok("up"))

	// The first admin's API key was seeded via GOPHISH_INITIAL_ADMIN_API_TOKEN.
	body := map[string]interface{}{
		"username":                 "admin",
		"role":                     "admin",
		"password":                 c.AdminPassword,
		"password_change_required": false,
	}
	code, ar, err := apiCall("PUT", admin+"/api/users/1", c.AdminAPIKey, body)
	if err != nil || code != 200 {
		exitf("setting admin password failed (HTTP %d): %v — %s", code, err, arMsg(ar))
	}
	fmt.Printf("  %s admin password set (password_change_required cleared)\n", ok("OK"))

	if c.SMTPHost != "" {
		code, ar, err := apiCall("POST", admin+"/api/smtp/", c.AdminAPIKey, c.smtpJSON())
		if err != nil || code >= 300 {
			exitf("creating sending profile failed (HTTP %d): %v — %s", code, err, arMsg(ar))
		}
		fmt.Printf("  %s sending profile %q created (%s)\n", ok("OK"), c.SMTPName, fmt.Sprintf("%s:%d", c.SMTPHost, c.SMTPPort))
	}

	if c.TestEmail != "" {
		body := map[string]interface{}{
			"email": c.TestEmail,
			"smtp":  c.smtpJSON(),
		}
		code, ar, err := apiCall("POST", admin+"/api/util/send_test_email", c.AdminAPIKey, body)
		if err != nil || code >= 300 {
			fmt.Printf("  %s test email to %s failed (HTTP %d): %s — check the SMTP settings and try from the UI\n",
				warn("!"), c.TestEmail, code, arMsg(ar))
		} else {
			fmt.Printf("  %s test email sent to %s\n", ok("OK"), c.TestEmail)
		}
	}
}

func arMsg(ar *apiResponse) string {
	if ar == nil {
		return ""
	}
	return ar.Message
}

// --- smoke tests -------------------------------------------------------------

// smoke exercises the deployed stack from the host. Returns the list of
// failures (empty = all good); prints each result as it runs.
func smoke(c *Config) []string {
	var fails []string
	admin := "http://127.0.0.1:3333"

	check := func(name string, failMsg string, okFlag bool) {
		if okFlag {
			fmt.Printf("  %s %s\n", ok("OK"), name)
		} else {
			fails = append(fails, failMsg)
			fmt.Printf("  %s %s\n", red("FAIL"), name)
		}
	}

	// 1. admin UI
	err := waitHTTP(admin+"/login", 10*time.Second)
	check("admin UI reachable", "admin UI not reachable on 127.0.0.1:3333", err == nil)

	// 2. admin API auth
	code, _, err := apiCall("GET", admin+"/api/campaigns/", c.AdminAPIKey, nil)
	check("admin API accepts the seeded API key",
		"admin API rejected the seeded API key (was the database already populated before this deploy?)",
		err == nil && code == 200)

	// 3. evilginx REST (direct) — poll: the container may still be booting
	if c.EnableEvilginx {
		direct := pollAPI(fmt.Sprintf("http://%s/api/status", c.restAddr()), c.EvilginxToken, 60*time.Second)
		check("evilginx REST API reachable and token valid", "evilginx REST API not reachable/token rejected on "+c.restAddr(), direct)
		if direct {
			bridgeOK := false
			for i := 0; i < 15; i++ {
				code2, _, err2 := apiCall("GET", admin+"/api/evilginx/status", c.AdminAPIKey, nil)
				if err2 == nil && code2 == 200 {
					bridgeOK = true
					break
				}
				time.Sleep(2 * time.Second)
			}
			check("PhishHook <-> evilginx bridge works", "PhishHook evilginx bridge failed — is evilginx.api_url/api_key correct in phishhook/config.json?", bridgeOK)
			check("evilginx knows the PhishHook API key (push pairing)",
				"evilginx reports gophish_api_key_set=false — push callbacks will not work",
				gophishKeySet(c))
		}
	}

	// 4. generator — uvicorn's playwright imports make this boot slow
	if c.EnableGenerator {
		genOK := pollAPI(fmt.Sprintf("http://127.0.0.1:%d/api/v1/health", c.GeneratorPort), "", 90*time.Second)
		check("phishlet generator healthy", "generator health check failed on 127.0.0.1:"+fmt.Sprint(c.GeneratorPort), genOK)
		proxyOK := false
		for i := 0; i < 5 && !proxyOK; i++ {
			code, _, err := apiCall("GET", admin+"/api/phishletgen/health", c.AdminAPIKey, nil)
			proxyOK = err == nil && code == 200
			if !proxyOK {
				time.Sleep(2 * time.Second)
			}
		}
		check("generator reachable through the PhishHook proxy", "generator proxy /api/phishletgen/health failed", proxyOK)
	}

	return fails
}

// pollAPI polls a URL until it returns 200 or the timeout elapses.
func pollAPI(url, token string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		code, _, err := apiCall("GET", url, token, nil)
		if err == nil && code == 200 {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// gophishKeySet queries evilginx directly for the push-pairing flag.
func gophishKeySet(c *Config) bool {
	code, ar, err := apiCall("GET", fmt.Sprintf("http://%s/api/status", c.restAddr()), c.EvilginxToken, nil)
	if err != nil || code != 200 || ar == nil {
		return false
	}
	// apiCall decodes into apiResponse which drops unknown fields; re-fetch raw.
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/status", c.restAddr()), nil)
	req.Header.Set("Authorization", "Bearer "+c.EvilginxToken)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var status struct {
		GophishKeySet bool `json:"gophish_api_key_set"`
	}
	return json.NewDecoder(resp.Body).Decode(&status) == nil && status.GophishKeySet
}
