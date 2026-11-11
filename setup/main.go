package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config holds every decision the wizard makes.
type Config struct {
	// paths
	DeployDir string
	RepoDir   string

	// PhishHook admin
	AdminListen   string // host:port as it goes into config.json
	AdminPublic   bool
	AdminPassword string
	AdminAPIKey   string
	CSRFKey       string

	// evilginx
	EnableEvilginx   bool
	EvilginxRepo     string
	BaseDomain       string
	ExternalIP       string
	HTTPSPort        int
	HTTPPort         int
	DNSPort          int
	Autocert         bool
	LureKey          string
	EvilginxToken    string
	EvilginxRESTPort int

	// phish server (classic landing pages)
	EnablePhishServer bool
	PhishPort         int
	PhishDomain       string // --domain (Let's Encrypt); empty = no LE

	// generator
	EnableGenerator bool
	GeneratorRepo   string
	GeneratorPort   int

	// SMTP (created via the admin API after startup)
	SMTPName       string
	SMTPHost       string // host only, port in SMTPPort
	SMTPPort       int
	SMTPUser       string
	SMTPPass       string
	SMTPFrom       string
	SMTPIgnoreCert bool
	TestEmail      string

	GitHubToken string

	Batch   bool
	NoStart bool
	Force   bool
}

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\n"+red("x ")+format+"\n", args...)
	os.Exit(1)
}

// --- tiny ANSI helpers ------------------------------------------------------

func ok(s string) string   { return "\033[32m" + s + "\033[0m" }
func warn(s string) string { return "\033[33m" + s + "\033[0m" }
func bold(s string) string { return "\033[1m" + s + "\033[0m" }
func red(s string) string  { return "\033[31m" + s + "\033[0m" }

func banner() {
	fmt.Println(bold("PhishHook setup wizard"))
	fmt.Println("Generates a complete Docker Compose deployment: PhishHook, the evilginx")
	fmt.Println("fork (REST API), and the phishlet generator — configured and paired.")
	fmt.Println()
}

func main() {
	c := &Config{}
	var adminListen, repoFlag string
	var smtpHostPort string

	flag.BoolVar(&c.Batch, "batch", false, "non-interactive: take all answers from flags/defaults")
	flag.StringVar(&c.DeployDir, "deploy-dir", "/opt/phishhook", "deployment directory")
	flag.StringVar(&repoFlag, "repo", "", "PhishHook repository root (default: auto-detect from cwd)")
	flag.StringVar(&c.BaseDomain, "base-domain", "", "base domain for evilginx phishlets")
	flag.StringVar(&adminListen, "admin-listen", "loopback", "admin exposure: loopback (SSH tunnel) or public")
	flag.BoolVar(&c.EnableEvilginx, "evilginx", true, "deploy the evilginx fork")
	flag.StringVar(&c.EvilginxRepo, "evilginx-repo", "https://github.com/wcrooker/evilginx3-phishhook.git", "evilginx fork repository")
	flag.BoolVar(&c.EnableGenerator, "generator", true, "deploy the phishlet generator sidecar")
	flag.StringVar(&c.GeneratorRepo, "generator-repo", "https://github.com/wcrooker/PhishletGenerator-Evilginx.git", "generator repository")
	flag.BoolVar(&c.EnablePhishServer, "phish-server", false, "also run the classic phishing server (non-evilginx landing pages)")
	flag.IntVar(&c.PhishPort, "phish-port", 8443, "classic phishing server port")
	flag.StringVar(&c.PhishDomain, "phish-domain", "", "Let's Encrypt domain for the classic phishing server (empty = no LE)")
	flag.BoolVar(&c.Autocert, "autocert", false, "evilginx Let's Encrypt autocert (needs live DNS + port 80/443)")
	flag.IntVar(&c.HTTPSPort, "https-port", 443, "evilginx HTTPS port")
	flag.IntVar(&c.HTTPPort, "http-port", 80, "evilginx ACME port (autocert only)")
	flag.IntVar(&c.DNSPort, "dns-port", 53, "evilginx DNS port")
	flag.IntVar(&c.EvilginxRESTPort, "rest-port", 8455, "evilginx REST API loopback port")
	flag.IntVar(&c.GeneratorPort, "generator-port", 8000, "generator loopback port")
	flag.StringVar(&c.GitHubToken, "github-token", os.Getenv("GITHUB_TOKEN"), "GitHub token for private repo clones (or GITHUB_TOKEN env)")
	flag.StringVar(&c.SMTPName, "smtp-name", "SMTP Primary", "sending profile name")
	flag.StringVar(&smtpHostPort, "smtp-host", "", "SMTP host:port (e.g. smtp.example.com:587)")
	flag.StringVar(&c.SMTPUser, "smtp-user", "", "SMTP username")
	flag.StringVar(&c.SMTPPass, "smtp-pass", "", "SMTP password")
	flag.StringVar(&c.SMTPFrom, "smtp-from", "", "from address, e.g. 'PhishHook <no-reply@example.com>'")
	flag.BoolVar(&c.SMTPIgnoreCert, "smtp-ignore-cert", false, "ignore SMTP TLS certificate errors")
	flag.StringVar(&c.TestEmail, "test-email", "", "send a test email to this address after startup")
	flag.BoolVar(&c.NoStart, "no-start", false, "generate the deployment tree but do not build/start")
	flag.BoolVar(&c.Force, "force", false, "overwrite an existing deployment directory")
	flag.Parse()

	banner()

	// ---- repo root ---------------------------------------------------------
	if repoFlag != "" {
		c.RepoDir = repoFlag
	} else {
		dir, err := os.Getwd()
		if err != nil {
			exitf("cannot determine working directory: %v", err)
		}
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				exitf("cannot find the PhishHook repository (no go.mod upward from %s) — run from within the repo or pass --repo", dir)
			}
			dir = parent
		}
		c.RepoDir = dir
	}
	if _, err := os.Stat(filepath.Join(c.RepoDir, "deploy", "docker", "Dockerfile.phishhook")); err != nil {
		exitf("this repository checkout is too old: deploy/docker/Dockerfile.phishhook is missing — git pull and rebuild the wizard")
	}

	// ---- questions ---------------------------------------------------------
	if c.Batch {
		resolveBatch(c, adminListen)
	} else {
		askQuestions(c)
	}

	// SMTP host:port split
	if smtpHostPort != "" {
		host, port, ok := splitHostPort(smtpHostPort)
		if !ok {
			exitf("--smtp-host must be host:port, got %q", smtpHostPort)
		}
		c.SMTPHost, c.SMTPPort = host, port
	}
	if c.SMTPHost != "" && c.SMTPPort == 0 {
		c.SMTPPort = 587
	}
	if c.SMTPHost != "" && c.SMTPFrom == "" {
		exitf("--smtp-from is required when --smtp-host is set")
	}

	// ---- secrets ------------------------------------------------------------
	c.AdminPassword = genPassword()
	c.AdminAPIKey = genAPIKey()
	c.CSRFKey = genCSRFKey()
	if c.EnableEvilginx {
		c.EvilginxToken = genToken()
		c.LureKey = genLureKey()
	}

	// ---- preflight ----------------------------------------------------------
	fmt.Println(bold("\nPre-flight checks"))
	fmt.Println(strings.Repeat("-", 60))
	pf := runPreflight(c)
	c.ExternalIP = pf.ExternalIP

	// ---- deploy directory ---------------------------------------------------
	if _, err := os.Stat(filepath.Join(c.DeployDir, "docker-compose.yml")); err == nil && !c.Force {
		exitf("%s already contains a deployment (docker-compose.yml exists). Pass --force to overwrite configs (data dirs are preserved).", c.DeployDir)
	}
	if !c.Batch {
		c.DeployDir = askString("Deployment directory", c.DeployDir, true)
	}

	// ---- clones (before render: render drops the evilginx Dockerfile into the clone)
	if c.EnableEvilginx || c.EnableGenerator {
		fmt.Println(bold("\nFetching source repositories"))
		fmt.Println(strings.Repeat("-", 60))
	}
	if c.EnableEvilginx {
		c.EvilginxRepo = ensureRepo(c.EvilginxRepo, filepath.Join(c.DeployDir, "evilginx3"), c.GitHubToken, c.Batch)
	}
	if c.EnableGenerator {
		c.GeneratorRepo = ensureRepo(c.GeneratorRepo, filepath.Join(c.DeployDir, "phishletgen"), c.GitHubToken, c.Batch)
	}

	// ---- render --------------------------------------------------------------
	fmt.Println(bold("\nWriting deployment files"))
	fmt.Println(strings.Repeat("-", 60))
	if err := render(c); err != nil {
		exitf("writing deployment files: %v", err)
	}
	for _, f := range generatedFiles(c) {
		fmt.Printf("  %s %s\n", ok("wrote"), f)
	}

	// ---- build & start -------------------------------------------------------
	if c.NoStart {
		fmt.Printf("\n%s deployment tree generated in %s (--no-start). Finish with:\n", ok("done"), c.DeployDir)
		fmt.Printf("  cd %s && docker compose up -d --build\n", c.DeployDir)
		printSecrets(c)
		return
	}

	fmt.Println(bold("\nBuilding images (first build takes a few minutes)"))
	fmt.Println(strings.Repeat("-", 60))
	composeBuild(c)

	fmt.Println(bold("\nStarting stack"))
	fmt.Println(strings.Repeat("-", 60))
	composeUp(c)

	fmt.Println(bold("\nPost-start configuration"))
	fmt.Println(strings.Repeat("-", 60))
	bootstrap(c)

	fmt.Println(bold("\nSmoke tests"))
	fmt.Println(strings.Repeat("-", 60))
	fails := smoke(c)
	reportSmoke(fails)

	printSummary(c, pf)
}

// resolveBatch fills config from flags alone (batch mode).
func resolveBatch(c *Config, adminListen string) {
	if c.BaseDomain == "" && c.EnableEvilginx {
		exitf("--batch with evilginx requires --base-domain")
	}
	switch strings.ToLower(adminListen) {
	case "loopback":
		c.AdminListen, c.AdminPublic = "127.0.0.1:3333", false
	case "public":
		c.AdminListen, c.AdminPublic = "0.0.0.0:3333", true
	default:
		exitf("--admin-listen must be loopback or public")
	}
}

// askQuestions drives the interactive flow.
func askQuestions(c *Config) {
	if c.EnableEvilginx {
		c.BaseDomain = askString("Base domain for phishing phishlets (e.g. phish.acme-bank.com)", c.BaseDomain, true)
	}

	choice := askChoice("Admin UI exposure", []string{
		"Loopback + SSH tunnel (recommended: ssh -L 3333:127.0.0.1:3333 root@this-host)",
		"Public (0.0.0.0) — put it behind a reverse proxy with TLS",
	}, 1)
	c.AdminPublic = choice == 2
	c.AdminListen = "127.0.0.1:3333"
	if c.AdminPublic {
		c.AdminListen = "0.0.0.0:3333"
	}

	if c.EnableEvilginx {
		c.Autocert = askBool("Evilginx Let's Encrypt autocert (requires live DNS + free ports 80/443)?", false)
	}

	if c.EnableGenerator {
		c.EnableGenerator = askBool("Deploy the phishlet generator sidecar?", true)
	}

	if !c.EnableEvilginx {
		c.EnablePhishServer = true
	} else {
		c.EnablePhishServer = askBool("Also run the classic phishing server for non-evilginx landing pages?", false)
	}
	if c.EnablePhishServer {
		p := askString("Classic phishing server port", fmt.Sprintf("%d", c.PhishPort), true)
		c.PhishPort = atoiOr(p, c.PhishPort)
		if !c.EnableEvilginx {
			d := askString("Let's Encrypt domain for the phishing server (empty = skip LE)", c.PhishDomain, false)
			c.PhishDomain = d
		}
	}

	if askBool("Configure an SMTP sending profile now?", true) {
		hp := askString("SMTP host:port (e.g. smtp.example.com:587)", "", true)
		host, port, okp := splitHostPort(hp)
		if !okp {
			exitf("SMTP host must be host:port, got %q", hp)
		}
		c.SMTPHost, c.SMTPPort = host, port
		c.SMTPUser = askString("SMTP username", "", false)
		c.SMTPPass = askString("SMTP password", "", false)
		c.SMTPFrom = askString("From address (e.g. 'Acme HR <hr@acme-bank.com>')", "", true)
		c.SMTPName = askString("Sending profile name", "SMTP Primary", true)
		if askBool("Ignore SMTP TLS certificate errors?", false) {
			c.SMTPIgnoreCert = true
		}
		if askBool("Send a test email after startup?", false) {
			c.TestEmail = askString("Test email recipient", "", true)
		}
	}

	if !c.GitHubTokenIsSet() {
		fmt.Println("\n  Private repositories need a GitHub token (PAT with repo scope).")
		c.GitHubToken = askString("GitHub token (empty = try without auth)", "", false)
	}
}

func (c *Config) GitHubTokenIsSet() bool { return c.GitHubToken != "" }

func splitHostPort(s string) (string, int, bool) {
	idx := strings.LastIndex(s, ":")
	if idx <= 0 || idx == len(s)-1 {
		return "", 0, false
	}
	host := s[:idx]
	port := 0
	for _, r := range s[idx+1:] {
		if r < '0' || r > '9' {
			return "", 0, false
		}
		port = port*10 + int(r-'0')
	}
	if port == 0 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

func atoiOr(s string, def int) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return def
		}
		n = n*10 + int(r-'0')
	}
	if n == 0 {
		return def
	}
	return n
}

// generatedFiles lists what render() wrote, for the summary.
func generatedFiles(c *Config) []string {
	files := []string{
		filepath.Join("phishhook", "config.json"),
		"docker-compose.yml",
		".env",
	}
	if c.EnableEvilginx {
		files = append(files,
			filepath.Join("evilginx", "data", "cfg", "config.json"),
			"evilginx-entrypoint.sh",
		)
	}
	if c.EnableGenerator {
		files = append(files, "generator.env")
	}
	return files
}

func printSecrets(c *Config) {
	fmt.Println(bold("\nGenerated credentials (also in " + filepath.Join(c.DeployDir, ".env") + ")"))
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("  Admin username:    %s\n", "admin")
	fmt.Printf("  Admin password:    %s\n", bold(c.AdminPassword))
	fmt.Printf("  Admin API key:     %s\n", c.AdminAPIKey)
	if c.EnableEvilginx {
		fmt.Printf("  Lure encryption:   %s\n", c.LureKey)
		fmt.Printf("  evilginx token:    %s\n", c.EvilginxToken)
	}
}

func printSummary(c *Config, pf *preflightResult) {
	printSecrets(c)

	fmt.Println(bold("\nStack endpoints"))
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("  Admin UI:            http://127.0.0.1:3333  (SSH tunnel: ssh -L 3333:127.0.0.1:3333 root@%s)\n", pf.ExternalIP)
	if c.EnableEvilginx {
		fmt.Printf("  evilginx REST:       %s  (loopback, bearer token)\n", c.restAddr())
		fmt.Printf("  evilginx phishing:   https://<phishlet-host>:%d\n", c.HTTPSPort)
	}
	if c.EnableGenerator {
		fmt.Printf("  Generator API:       http://127.0.0.1:%d  (loopback)\n", c.GeneratorPort)
	}
	if c.EnablePhishServer {
		fmt.Printf("  Phishing server:     :%d\n", c.PhishPort)
	}

	fmt.Println(bold("\nNext steps"))
	fmt.Println(strings.Repeat("-", 60))
	if c.EnableEvilginx {
		fmt.Println("  1. Point DNS: A records for each phishlet hostname -> " + pf.ExternalIP)
		fmt.Println("  2. Add phishlet YAML to " + filepath.Join(c.DeployDir, "evilginx", "data", "phishlets"))
		fmt.Println("     (evilginx restart picks up new files: docker restart phishhook-evilginx)")
		fmt.Println("  3. Console -> Evilginx -> Phishlets: set hostname, enable, Verify")
		fmt.Println("  4. Console -> Evilginx -> Lures -> New Lure -> Campaign")
		fmt.Println("     Use the Lure Encryption Key from .env in every campaign.")
	} else {
		fmt.Println("  1. Log in, create a sending profile and landing page, launch a campaign.")
	}
	if c.AdminPublic {
		fmt.Println(warn("  ! Admin UI is on 0.0.0.0 without TLS — put it behind a reverse proxy."))
	}
	for _, w := range pf.Warnings {
		fmt.Println(warn("  ! " + w))
	}
	fmt.Println()
}

// reportSmoke prints smoke test results and exits non-zero on failures.
func reportSmoke(fails []string) {
	if len(fails) == 0 {
		fmt.Printf("\n%s all smoke tests passed\n", ok("OK"))
		return
	}
	fmt.Println()
	for _, f := range fails {
		fmt.Println(red("FAIL") + " " + f)
	}
	exitf("%d smoke test(s) failed — check 'docker compose logs' in %s", len(fails), cDeployDir())
}

var lastDeployDir string

func cDeployDir() string { return lastDeployDir }
