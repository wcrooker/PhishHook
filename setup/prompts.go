package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
)

var stdin *bufio.Scanner

func init() {
	stdin = bufio.NewScanner(os.Stdin)
	stdin.Buffer(make([]byte, 1024*1024), 1024*1024)
}

// askString prompts for a string value with a default. In batch mode the
// default is used unless a flag overrode it before the call.
func askString(label, def string, required bool) string {
	for {
		if def != "" {
			fmt.Printf("? %-52s [%s]: ", label, def)
		} else {
			fmt.Printf("? %-52s: ", label)
		}
		if !stdin.Scan() {
			fmt.Println()
			exitf("input closed")
		}
		v := strings.TrimSpace(stdin.Text())
		if v == "" {
			v = def
		}
		if v == "" && required {
			fmt.Println("  a value is required")
			continue
		}
		return v
	}
}

// askBool prompts for a yes/no answer.
func askBool(label string, def bool) bool {
	defStr := "y/N"
	if def {
		defStr = "Y/n"
	}
	for {
		fmt.Printf("? %-52s [%s]: ", label, defStr)
		if !stdin.Scan() {
			fmt.Println()
			exitf("input closed")
		}
		v := strings.ToLower(strings.TrimSpace(stdin.Text()))
		if v == "" {
			return def
		}
		switch v {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
		fmt.Println("  please answer y or n")
	}
}

// askChoice prompts for a numbered choice.
func askChoice(label string, options []string, def int) int {
	fmt.Printf("? %s\n", label)
	for i, o := range options {
		marker := " "
		if i+1 == def {
			marker = ">"
		}
		fmt.Printf("    %s %d) %s\n", marker, i+1, o)
	}
	for {
		fmt.Printf("  choice [%d]: ", def)
		if !stdin.Scan() {
			fmt.Println()
			exitf("input closed")
		}
		v := strings.TrimSpace(stdin.Text())
		if v == "" {
			return def
		}
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n >= 1 && n <= len(options) {
			return n
		}
		fmt.Println("  enter a number between 1 and", len(options))
	}
}

// confirmSecret shows a generated value once and asks the user to store it.
func confirmSecret(label, value string) {
	fmt.Printf("\n  %s (also written to .env):\n", label)
	fmt.Printf("    %s\n\n", bold(value))
}

const (
	lower    = "abcdefghijklmnopqrstuvwxyz"
	upper    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits   = "0123456789"
	letters  = lower + upper
	alphanum = letters + digits
)

// randFrom returns n random characters from the given alphabet.
func randFrom(alphabet string, n int) string {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		c, err := rand.Int(rand.Reader, max)
		if err != nil {
			exitf("generating random value: %v", err)
		}
		out[i] = alphabet[c.Int64()]
	}
	return string(out)
}

// genAPIKey returns a gophish-style API key (40 hex chars).
func genAPIKey() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		exitf("generating api key: %v", err)
	}
	return hex.EncodeToString(b)
}

// genPassword returns a strong, memorable-enough admin password that
// passes the default password policy (length, mixed case, digits).
func genPassword() string {
	for {
		p := randFrom(letters, 4) + randFrom(digits, 2) + randFrom(letters, 4) + randFrom(digits, 2) + randFrom(letters+"!@#$%^&*-_=+", 6)
		var hasUpper, hasLower, hasDigit bool
		for _, c := range p {
			switch {
			case strings.ContainsRune(upper, c):
				hasUpper = true
			case strings.ContainsRune(lower, c):
				hasLower = true
			case strings.ContainsRune(digits, c):
				hasDigit = true
			}
		}
		if hasUpper && hasLower && hasDigit && len(p) >= 12 {
			return p
		}
	}
}

// genToken returns an opaque bearer token for the evilginx REST API.
func genToken() string {
	return randFrom(alphanum, 40)
}

// genLureKey returns a default lure encryption key (32 alphanum chars,
// matching what the campaign wizard generates).
func genLureKey() string {
	return randFrom(alphanum, 32)
}

// genCSRFKey returns a CSRF signing key (32 bytes, hex).
func genCSRFKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		exitf("generating csrf key: %v", err)
	}
	return hex.EncodeToString(b)
}
