package sites

import (
	"bufio"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Sources returns the list URLs the current block list was downloaded from,
// so refreshes keep the level the user picked.
func Sources(dir string) []string {
	f, err := os.Open(filepath.Join(dir, BlocklistFile))
	if err != nil {
		return nil
	}
	defer f.Close()
	var urls []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "#") {
			break // the header is only at the top
		}
		if u, ok := strings.CutPrefix(line, "# Source: "); ok {
			urls = append(urls, strings.TrimSpace(u))
		}
	}
	return urls
}

// AutoUpdate refreshes the block list when it is older than maxAge, checking
// once a day. A failed download keeps the old list. Handler.Watch picks up
// the new file.
func AutoUpdate(ctx context.Context, dir string, maxAge time.Duration, logger *log.Logger) {
	timer := time.NewTimer(time.Minute) // let the proxy start first
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if needsUpdate(dir, maxAge) {
			urls := Sources(dir)
			if len(urls) == 0 {
				urls = Levels[DefaultLevel]
			}
			if n, err := Update(ctx, dir, urls); err != nil {
				logger.Printf("refreshing ad-domain lists failed (keeping the old ones): %v", err)
			} else {
				logger.Printf("refreshed ad-domain lists: %d domains", n)
			}
		}
		timer.Reset(24 * time.Hour)
	}
}

func needsUpdate(dir string, maxAge time.Duration) bool {
	fi, err := os.Stat(filepath.Join(dir, BlocklistFile))
	return err != nil || time.Since(fi.ModTime()) > maxAge
}
