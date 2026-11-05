package sites

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Handler sits in front of the YouTube proxy. It serves the combined PAC
// file, refuses blocked ad domains, and passes every other request to the
// YouTube proxy unchanged.
type Handler struct {
	YouTube http.Handler // the existing YouTube proxy
	Addr    string
	Log     *log.Logger

	list    atomic.Pointer[List]
	pac     atomic.Pointer[string]
	blocked atomic.Int64
}

// NewHandler wraps the YouTube proxy with ad-domain blocking.
func NewHandler(youtube http.Handler, addr string, list *List, logger *log.Logger) *Handler {
	h := &Handler{YouTube: youtube, Addr: addr, Log: logger}
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

	if host := targetHost(r); host != "" && h.list.Load().Blocked(host) {
		h.blocked.Add(1)
		h.Log.Printf("blocked %s", host)
		http.Error(w, "blocked by ytblock", http.StatusForbidden)
		return
	}
	h.YouTube.ServeHTTP(w, r)
}

// targetHost is the site a proxy request is for (without the port).
func targetHost(r *http.Request) string {
	hostport := r.Host
	if r.Method != http.MethodConnect {
		if !r.URL.IsAbs() {
			return ""
		}
		hostport = r.URL.Host
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

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
	for _, f := range []string{BlocklistFile, BlockFile, AllowFile} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err == nil {
			fmt.Fprintf(&b, "%d/%d;", fi.ModTime().UnixNano(), fi.Size())
		} else {
			b.WriteString("-;")
		}
	}
	return b.String()
}
