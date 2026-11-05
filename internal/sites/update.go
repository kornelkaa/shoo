package sites

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Block lists that update-lists can download.
const (
	// StevenBlack: ads and malware, hosts format, MIT licensed.
	StevenBlackURL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
	// HaGeZi Pro: ads, trackers, analytics, telemetry; built to rarely break sites.
	HaGeZiProURL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt"
	// HaGeZi Pro++: stricter; more blocked, more chance a site breaks.
	HaGeZiProPlusURL = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus-onlydomains.txt"
)

// Levels are the list combinations users pick with `update-lists -level`.
var Levels = map[string][]string{
	"balanced": {StevenBlackURL},
	"strict":   {StevenBlackURL, HaGeZiProURL},
	"max":      {StevenBlackURL, HaGeZiProPlusURL},
}

// DefaultLevel is used when no level is given.
const DefaultLevel = "strict"

const (
	maxListBytes = 32 << 20
	minDomains   = 1000 // a smaller list means the download went wrong
)

// Update downloads every list in urls, merges them without duplicates, and
// saves the result in dir. If any download fails, the old list is kept.
// It returns the number of domains saved.
func Update(ctx context.Context, dir string, urls []string) (int, error) {
	seen := map[string]bool{}
	var domains []string
	for _, u := range urls {
		got, err := download(ctx, u)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", u, err)
		}
		for _, d := range got {
			if !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
	}

	var out strings.Builder
	for _, u := range urls {
		fmt.Fprintf(&out, "# Source: %s\n", u)
	}
	fmt.Fprintf(&out, "# Downloaded: %s\n", time.Now().UTC().Format(time.RFC3339))
	for _, d := range domains {
		out.WriteString(d)
		out.WriteByte('\n')
	}
	if err := writeFileAtomic(filepath.Join(dir, BlocklistFile), []byte(out.String())); err != nil {
		return 0, err
	}
	return len(domains), nil
}

func download(ctx context.Context, url string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxListBytes {
		return nil, fmt.Errorf("list is larger than %d MB", maxListBytes>>20)
	}
	domains, err := ParseHosts(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(domains) < minDomains {
		return nil, fmt.Errorf("list has only %d domains; keeping the old list", len(domains))
	}
	return domains, nil
}

// AddDomain appends a domain to the user's block or allow file, if it isn't
// already there.
func AddDomain(dir, file, domain string) error {
	path := filepath.Join(dir, file)
	existing, err := readDomainsFile(path)
	if err != nil {
		return err
	}
	for _, d := range existing {
		if d == domain {
			return nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, domain); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
