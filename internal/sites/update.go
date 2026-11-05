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

// DefaultListURL is StevenBlack's hosts list: ads and malware, MIT licensed.
const DefaultListURL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

const (
	maxListBytes = 32 << 20
	minDomains   = 1000 // a smaller list means the download went wrong
)

// Update downloads the block list from url and saves it in dir.
// It returns the number of domains saved.
func Update(ctx context.Context, dir, url string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download failed: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return 0, err
	}
	if len(body) > maxListBytes {
		return 0, fmt.Errorf("list is larger than %d MB", maxListBytes>>20)
	}
	domains, err := ParseHosts(bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	if len(domains) < minDomains {
		return 0, fmt.Errorf("list has only %d domains; keeping the old one", len(domains))
	}

	var out strings.Builder
	fmt.Fprintf(&out, "# Source: %s\n# Downloaded: %s\n", url, time.Now().UTC().Format(time.RFC3339))
	for _, d := range domains {
		out.WriteString(d)
		out.WriteByte('\n')
	}
	if err := writeFileAtomic(filepath.Join(dir, BlocklistFile), []byte(out.String())); err != nil {
		return 0, err
	}
	return len(domains), nil
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
