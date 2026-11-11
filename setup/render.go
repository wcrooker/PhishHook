package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// render writes the full deployment tree under c.DeployDir.
func render(c *Config) error {
	stamp = time.Now().UTC().Format("2006-01-02 15:04 UTC")
	dirs := []string{
		c.DeployDir,
		filepath.Join(c.DeployDir, "phishhook"), // PhishHook data (config.json + sqlite db)
		filepath.Join(c.DeployDir, "evilginx", "data", "cfg"),       // evilginx config store
		filepath.Join(c.DeployDir, "evilginx", "data", "phishlets"), // phishlet yaml files
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	// PhishHook config.json
	phishPort := c.PhishPort
	if !c.EnablePhishServer {
		phishPort = 8081 // unused in admin mode, kept for completeness
	}
	phishhookCfg := fmt.Sprintf(`{
	"admin_server": {
		"listen_url": "%s",
		"use_tls": false,
		"cert_path": "",
		"key_path": "",
		"csrf_key": "%s",
		"allowed_internal_hosts": [],
		"trusted_origins": []
	},
	"phish_server": {
		"listen_url": "0.0.0.0:%d",
		"use_tls": false,
		"cert_path": "",
		"key_path": ""
	},
	"db_name": "sqlite3",
	"db_path": "/data/gophish.db",
	"migrations_prefix": "db/db_",
	"contact_address": "",
	"logging": {
		"filename": "",
		"level": "info"
	},
	"turnstile": {
		"enabled": false,
		"site_key": "",
		"secret_key": "",
		"cookie_secret": ""
	},
	"evasion": {
		"enabled": true,
		"strip_server_header": false,
		"custom_server_name": "IGNORE"
	},
	"behavioral": {
		"enabled": true,
		"min_time_on_page_ms": 2000,
		"require_mouse_movement": false,
		"require_interaction": false,
		"block_microsoft_ips": true,
		"custom_blocked_cidrs": [],
		"max_requests_per_minute": 30,
		"windows_only": true
	}%s%s
}
`,
		c.AdminListen,
		c.CSRFKey,
		phishPort,
		renderEvilginxSection(c),
		renderGeneratorSection(c),
	)
	if err := writePrivate(filepath.Join(c.DeployDir, "phishhook", "config.json"), phishhookCfg); err != nil {
		return err
	}

	// evilginx config store (seeded; evilginx owns it from here on)
	if c.EnableEvilginx {
		egCfg := fmt.Sprintf(`{
	"general": {
		"domain": "%s",
		"external_ipv4": "%s",
		"bind_ipv4": "0.0.0.0",
		"https_port": %d,
		"dns_port": %d,
		"unauth_url": "",
		"autocert": %t,
		"enc_key": "%s"
	},
	"gophish": {
		"admin_url": "http://127.0.0.1:3333",
		"api_key": "%s",
		"insecure": false
	},
	"lures": [],
	"phishlets": {}
}
`,
			c.BaseDomain,
			c.ExternalIP,
			c.HTTPSPort,
			c.DNSPort,
			c.Autocert,
			c.LureKey,
			c.AdminAPIKey,
		)
		if err := writePrivate(filepath.Join(c.DeployDir, "evilginx", "data", "cfg", "config.json"), egCfg); err != nil {
			return err
		}

		// Entrypoint script (mounted into the container, keeps the
		// interactive terminal fed so the process stays alive).
		entrypoint := `#!/bin/bash
set -euo pipefail
cd /opt/evilginx
mkdir -p /data/cfg /data/phishlets
# Seed the default phishlet library on first boot
if [ ! -f /data/phishlets/.seeded ]; then
    cp -rn /opt/evilginx/phishlets/. /data/phishlets/ 2>/dev/null || true
    touch /data/phishlets/.seeded
fi
FLAGS=${EVILGINX_EXTRA_FLAGS:-}
exec_args=(./evilginx -p /data/phishlets -c /data/cfg
    -restapi "${EVILGINX_RESTAPI_ADDR:-127.0.0.1:8455}"
    -restapi-token "${EVILGINX_RESTAPI_TOKEN:?EVILGINX_RESTAPI_TOKEN is required}")
# Keep stdin open: evilginx's interactive terminal exits on EOF.
tail -f /dev/null | "${exec_args[@]}" $FLAGS
`
		if err := writeExec(filepath.Join(c.DeployDir, "evilginx-entrypoint.sh"), entrypoint); err != nil {
			return err
		}

		// evilginx Dockerfile (written into the build context)
		egDockerfile := `FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -o /out/evilginx .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl bash && \
	rm -rf /var/lib/apt/lists/*
WORKDIR /opt/evilginx
COPY --from=build /out/evilginx ./evilginx
COPY phishlets ./phishlets
EXPOSE 443 80 53/udp
`
		if err := os.WriteFile(filepath.Join(c.DeployDir, "evilginx3", "Dockerfile.phishhook"), []byte(egDockerfile), 0o644); err != nil {
			return err
		}
	}

	// docker-compose.yml
	compose := renderCompose(c)
	if err := writePrivate(filepath.Join(c.DeployDir, "docker-compose.yml"), compose); err != nil {
		return err
	}

	// .env — every secret in one 600 file for easy reference
	env := fmt.Sprintf(`# PhishHook deployment secrets (generated %s)
# Keep this file private (chmod 600).

ADMIN_URL=http://127.0.0.1:3333
ADMIN_USERNAME=admin
ADMIN_PASSWORD=%s
ADMIN_API_KEY=%s
LURE_ENCRYPTION_KEY=%s
`, stamp, c.AdminPassword, c.AdminAPIKey, c.LureKey)
	if c.EnableEvilginx {
		env += fmt.Sprintf(`EVILGINX_RESTAPI_TOKEN=%s
EVILGINX_BASE_DOMAIN=%s
`, c.EvilginxToken, c.BaseDomain)
	}
	if err := writePrivate(filepath.Join(c.DeployDir, ".env"), env); err != nil {
		return err
	}

	// generator env (AI keys optional; user fills in)
	if c.EnableGenerator {
		genEnv := `# Optional: API keys for AI phishlet refinement (leave empty to disable AI)
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
`
		if err := writePrivate(filepath.Join(c.DeployDir, "generator.env"), genEnv); err != nil {
			return err
		}
	}
	return nil
}

func renderEvilginxSection(c *Config) string {
	if !c.EnableEvilginx {
		return ""
	}
	return fmt.Sprintf(`,
	"evilginx": {
		"api_url": "http://127.0.0.1:%d",
		"api_key": "%s"
	}`, c.EvilginxRESTPort, c.EvilginxToken)
}

// restAddr is the loopback address evilginx binds its REST API on.
func (c *Config) restAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", c.EvilginxRESTPort)
}

func renderGeneratorSection(c *Config) string {
	if !c.EnableGenerator {
		return ""
	}
	return fmt.Sprintf(`,
	"phishlet_generator": {
		"url": "http://127.0.0.1:%d"
	}`, c.GeneratorPort)
}

func renderCompose(c *Config) string {
	var b strings.Builder
	b.WriteString("# Generated by phishhook-setup — all services use host networking so the\n")
	b.WriteString("# loopback URLs match the documented architecture (admin 3333, evilginx\n")
	b.WriteString("# REST 8455, generator 8000). Secrets live in .env (chmod 600).\n")
	b.WriteString("name: phishhook\n\nservices:\n")

	if c.EnableEvilginx {
		flags := ""
		if !c.Autocert {
			flags = "-developer"
		}
		b.WriteString("  evilginx:\n")
		b.WriteString("    build:\n")
		b.WriteString(fmt.Sprintf("      context: %s\n", filepath.Join(c.DeployDir, "evilginx3")))
		b.WriteString("      dockerfile: Dockerfile.phishhook\n")
		b.WriteString("    container_name: phishhook-evilginx\n")
		b.WriteString("    network_mode: host\n")
		b.WriteString("    stdin_open: true\n")
		b.WriteString("    restart: unless-stopped\n")
		b.WriteString("    entrypoint: [\"/bin/bash\", \"/entrypoint.sh\"]\n")
		b.WriteString("    environment:\n")
		b.WriteString(fmt.Sprintf("      EVILGINX_RESTAPI_ADDR: \"%s\"\n", c.restAddr()))
		b.WriteString(fmt.Sprintf("      EVILGINX_RESTAPI_TOKEN: \"%s\"\n", c.EvilginxToken))
		b.WriteString(fmt.Sprintf("      EVILGINX_EXTRA_FLAGS: \"%s\"\n", flags))
		b.WriteString("    volumes:\n")
		b.WriteString("      - ./evilginx-entrypoint.sh:/entrypoint.sh:ro\n")
		b.WriteString("      - ./evilginx/data:/data\n\n")
	}

	b.WriteString("  phishhook:\n")
	b.WriteString("    build:\n")
	b.WriteString(fmt.Sprintf("      context: %s\n", c.RepoDir))
	b.WriteString("      dockerfile: deploy/docker/Dockerfile.phishhook\n")
	b.WriteString("    container_name: phishhook-admin\n")
	b.WriteString("    network_mode: host\n")
	b.WriteString("    restart: unless-stopped\n")
	mode := "all"
	if c.EnableEvilginx && !c.EnablePhishServer {
		mode = "admin"
	}
	cmd := fmt.Sprintf("    command: [\"--config\", \"/data/config.json\", \"--mode\", \"%s\"", mode)
	if c.EnablePhishServer && c.PhishDomain != "" {
		cmd += fmt.Sprintf(", \"--domain\", \"%s\"", c.PhishDomain)
	}
	cmd += "]\n"
	b.WriteString(cmd)
	b.WriteString("    environment:\n")
	// Seeds the first admin's API key on an empty database so the wizard
	// can bootstrap the password right after startup.
	b.WriteString(fmt.Sprintf("      GOPHISH_INITIAL_ADMIN_API_TOKEN: \"%s\"\n", c.AdminAPIKey))
	b.WriteString("    volumes:\n")
	b.WriteString("      - ./phishhook:/data\n")

	if c.EnableGenerator {
		b.WriteString("\n  phishletgen:\n")
		b.WriteString("    build:\n")
		b.WriteString(fmt.Sprintf("      context: %s\n", filepath.Join(c.DeployDir, "phishletgen", "backend")))
		b.WriteString("      dockerfile: Dockerfile\n")
		b.WriteString("    container_name: phishhook-generator\n")
		b.WriteString("    network_mode: host\n")
		b.WriteString("    restart: unless-stopped\n")
		b.WriteString(fmt.Sprintf("    command: [\"uvicorn\", \"app.main:app\", \"--host\", \"127.0.0.1\", \"--port\", \"%d\"]\n", c.GeneratorPort))
		b.WriteString("    env_file:\n")
		b.WriteString("      - ./generator.env\n")
	}
	return b.String()
}

var stamp = ""

func writePrivate(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return err
	}
	return nil
}

func writeExec(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		return err
	}
	return nil
}
