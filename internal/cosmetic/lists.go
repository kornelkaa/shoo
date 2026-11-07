package cosmetic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ListFile holds the downloaded filter lists, inside shoo's data folder.
// Their element-hiding rules are used here, their network rules by
// internal/netfilter.
const ListFile = "cosmetic.txt"

// Lists are the filter lists shoo downloads. They are fetched on this Mac,
// not shipped with shoo.
var Lists = []string{
	// EasyList: the main ad list (GPLv3 / CC BY-SA 3.0).
	"https://easylist.to/easylist/easylist.txt",
	// EasyPrivacy: trackers and analytics (GPLv3 / CC BY-SA 3.0).
	"https://easylist.to/easylist/easyprivacy.txt",
	// uBlock Origin's own lists: fixes for ads the others miss, and
	// privacy (GPLv3). Rules that need uBlock Origin's scripts are skipped.
	"https://ublockorigin.github.io/uAssets/filters/filters.txt",
	"https://ublockorigin.github.io/uAssets/filters/privacy.txt",
	// Hufilter: Hungarian sites.
	"https://raw.githubusercontent.com/hufilter/hufilter/gh-pages/hufilter.txt",
}

const maxListBytes = 16 << 20

// Load reads the saved lists from dir. A missing file means no rules.
func Load(dir string) (*Rules, error) {
	f, err := os.Open(filepath.Join(dir, ListFile))
	if errors.Is(err, os.ErrNotExist) {
		return &Rules{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Update downloads the lists and saves them in dir. If any download fails,
// the old file is kept. It returns the number of hiding rules.
func Update(ctx context.Context, dir string) (int, error) {
	var all strings.Builder
	for _, u := range Lists {
		body, err := download(ctx, u)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", u, err)
		}
		fmt.Fprintf(&all, "! Source: %s\n%s\n", u, body)
	}
	r, err := Parse(strings.NewReader(all.String()))
	if err != nil {
		return 0, err
	}
	if r.Len() < 1000 {
		return 0, fmt.Errorf("only %d hiding rules; the download looks wrong", r.Len())
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	tmp := filepath.Join(dir, ListFile+".tmp")
	if err := os.WriteFile(tmp, []byte(all.String()), 0o644); err != nil {
		return 0, err
	}
	return r.Len(), os.Rename(tmp, filepath.Join(dir, ListFile))
}

// Current reports whether the saved file in dir has every list in Lists
// (an update may add lists; then they're downloaded right away instead of
// at the next weekly refresh).
func Current(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, ListFile))
	if err != nil {
		return false
	}
	have := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		if u, ok := strings.CutPrefix(l, "! Source: "); ok {
			have[strings.TrimSpace(u)] = true
		}
	}
	for _, u := range Lists {
		if !have[u] {
			return false
		}
	}
	return true
}

func download(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxListBytes {
		return "", errors.New("list too big")
	}
	return string(b), nil
}

// AutoUpdate refreshes the lists when they are older than maxAge, checking
// once a day, and calls loaded with the new rules.
func AutoUpdate(ctx context.Context, dir string, maxAge time.Duration, logger *log.Logger, loaded func(*Rules)) {
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		next := 24 * time.Hour
		fi, err := os.Stat(filepath.Join(dir, ListFile))
		if err != nil || time.Since(fi.ModTime()) > maxAge || !Current(dir) {
			if n, err := Update(ctx, dir); err != nil {
				logger.Printf("refreshing element-hiding lists failed (keeping the old ones): %v", err)
				next = time.Hour // offline at login, say: don't wait a whole day
			} else if r, err := Load(dir); err == nil {
				loaded(r)
				logger.Printf("refreshed element-hiding lists: %d rules", n)
			}
		}
		timer.Reset(next)
	}
}
