package main

import (
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type preflightResult struct {
	ExternalIP    string
	DomainMatches bool
	Warnings      []string
}

// runPreflight validates the host before any files are written.
func runPreflight(c *Config) *preflightResult {
	p := &preflightResult{}

	// 1. docker + compose plugin
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		exitf("docker is required but not installed. Install it first:\n  curl -fsSL https://get.docker.com | sh")
	}
	_ = dockerPath
	out, err := exec.Command("docker", "compose", "version").CombinedOutput()
	if err != nil {
		exitf("docker compose plugin is required (got: %s)", strings.TrimSpace(string(out)))
	}
	fields := strings.Fields(string(out))
	if len(fields) > 0 {
		fmt.Printf("%s docker compose (%s)\n", ok("OK"), fields[len(fields)-1])
	}

	// 2. external IP
	p.ExternalIP = detectExternalIP()
	if p.ExternalIP == "" {
		p.Warnings = append(p.Warnings, "could not determine this server's external IP (no internet?)")
	} else {
		fmt.Printf("%s external IP: %s\n", ok("OK"), p.ExternalIP)
	}

	// 3. DNS for the base domain
	if c.EnableEvilginx && c.BaseDomain != "" {
		ips, err := net.LookupHost(c.BaseDomain)
		if err != nil {
			p.Warnings = append(p.Warnings, fmt.Sprintf("base domain %q does not resolve yet — add an A record for it (and any lure hostnames) pointing at %s before launching campaigns", c.BaseDomain, p.ExternalIP))
		} else if p.ExternalIP != "" {
			p.DomainMatches = false
			for _, ip := range ips {
				if ip == p.ExternalIP {
					p.DomainMatches = true
				}
			}
			if !p.DomainMatches {
				p.Warnings = append(p.Warnings, fmt.Sprintf("%s resolves to [%s] but this server is %s — fix the A record before going live", c.BaseDomain, strings.Join(ips, ", "), p.ExternalIP))
			} else {
				fmt.Printf("%s %s resolves to this server\n", ok("OK"), c.BaseDomain)
			}
		}
	}

	// 4. port availability
	ports := map[int]string{}
	if c.EnableEvilginx {
		ports[c.HTTPSPort] = "tcp (evilginx phishing)"
		ports[c.DNSPort] = "udp (evilginx dns)"
		if c.Autocert {
			ports[c.HTTPPort] = "tcp (letsencrypt acme)"
		}
	}
	ports[3333] = "tcp (phishhook admin)"
	if c.EnablePhishServer {
		ports[c.PhishPort] = "tcp (phishhook phish server)"
	}
	if c.EnableGenerator {
		ports[c.GeneratorPort] = "tcp (phishlet generator)"
	}
	for port, what := range ports {
		if port == 0 {
			continue
		}
		if err := checkPort(port, what); err != nil {
			exitf("%v", err)
		}
	}
	fmt.Printf("%s required ports are free\n", ok("OK"))

	return p
}

func checkPort(port int, what string) error {
	if isTCPOpen("0.0.0.0", port) {
		return fmt.Errorf("tcp port %d already in use (needed for %s) — free it or choose another port", port, what)
	}
	if strings.Contains(what, "udp") {
		if isUDPOpen(port) {
			return fmt.Errorf("udp port %d already in use (needed for %s)", port, what)
		}
	}
	return nil
}

func isTCPOpen(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func isUDPOpen(port int) bool {
	// Parse ss -uln rather than binding: binding low ports needs privileges
	// and would false-positive for non-root users.
	out, err := exec.Command("ss", "-uln").CombinedOutput()
	if err != nil {
		return false // cannot inspect; assume free (evilginx will fail loudly if not)
	}
	want := fmt.Sprintf(":%d", port)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		local := fields[len(fields)-2] // ss -uln: State Recv-Q Send-Q Local:Port Peer:Port
		if local == want || strings.HasSuffix(local, want) {
			// matches 0.0.0.0:53, *:53 — but NOT 127.0.0.53:53 unless exact
			if local == want || strings.HasPrefix(local, "0.0.0.0"+want) || strings.HasPrefix(local, "*"+want) || strings.HasPrefix(local, "[::]"+want) {
				return true
			}
		}
	}
	return false
}

func detectExternalIP() string {
	client := &http.Client{Timeout: 6 * time.Second}
	for _, url := range []string{"https://api.ipify.org", "https://ifconfig.me/ip"} {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		ip := strings.TrimSpace(string(buf[:n]))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// waitHTTP polls a URL until it returns any HTTP response or times out.
func waitHTTP(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 5 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timed out waiting for %s", url)
}
