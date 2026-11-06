package sites

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Handler sits in front of the proxy. It serves the PAC file and stats and
// passes every other request to the proxy, which asks Blocked and Decrypt
// what to do with each site.
type Handler struct {
	Proxy http.Handler
	Addr  string
	Log   *log.Logger

	list    atomic.Pointer[List]
	pac     atomic.Pointer[string]
	blocked atomic.Int64
}

// NewHandler wraps the YouTube proxy with ad-domain blocking.
func NewHandler(proxy http.Handler, addr string, list *List, logger *log.Logger) *Handler {
	h := &Handler{Proxy: proxy, Addr: addr, Log: logger}
	h.SetList(list)
	return h
}

// SetList swaps in a new block list.
func (h *Handler) SetList(l *List) {
	pac := PAC(h.Addr, l)
	h.list.Store(l)
	h.pac.Store(&pac)
}

// Stats is what GET /stats returns.
type Stats struct {
	Blocked int64 `json:"blocked"`
	Domains int   `json:"domains"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() && r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/proxy.pac":
			w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
			w.Header().Set("Cache-Control", "no-store")
			io.WriteString(w, *h.pac.Load())
			return
		case "/stats":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(Stats{Blocked: h.blocked.Load(), Domains: h.list.Load().Len()})
			return
		}
	}

	h.Proxy.ServeHTTP(w, r)
}

// Blocked reports whether host is an ad domain, and counts and logs it.
// The proxy answers such requests itself (inside the decrypted connection,
// so macOS has nothing to retry directly).
func (h *Handler) Blocked(host string) bool {
	if !h.list.Load().Blocked(host) {
		return false
	}
	h.blocked.Add(1)
	h.Log.Printf("blocked %s", host)
	return true
}

// Decrypt reports whether the proxy may decrypt host.
func (h *Handler) Decrypt(host string) bool { return h.list.Load().Decrypt(host) }

// Watch reloads the list when any list file in dir changes.
func (h *Handler) Watch(dir string, every time.Duration) {
	last := listFilesState(dir)
	for range time.Tick(every) {
		cur := listFilesState(dir)
		if cur == last {
			continue
		}
		last = cur
		l, err := Load(dir)
		if err != nil {
			h.Log.Printf("reloading block list: %v", err)
			continue
		}
		h.SetList(l)
		h.Log.Printf("block list reloaded: %d domains", l.Len())
	}
}

func listFilesState(dir string) string {
	var b strings.Builder
	for _, f := range []string{BlocklistFile, BlockFile, AllowFile, SkipFile} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err == nil {
			fmt.Fprintf(&b, "%d/%d;", fi.ModTime().UnixNano(), fi.Size())
		} else {
			b.WriteString("-;")
		}
	}
	return b.String()
}

// WatchFiles calls changed whenever a list file in dir changes.
func WatchFiles(dir string, every time.Duration, changed func()) {
	last := listFilesState(dir)
	for range time.Tick(every) {
		if cur := listFilesState(dir); cur != last {
			last = cur
			changed()
		}
	}
}
