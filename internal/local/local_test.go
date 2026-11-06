package local

import (
	"net/http/httptest"
	"testing"
)

func TestRequireLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:8899": true,
		"[::1]:8899":     true,
		"0.0.0.0:8899":   false,
		":8899":          false,
		"localhost:8899": false,
		"192.168.1.5:80": false,
	} {
		if err := RequireLoopback(addr); (err == nil) != ok {
			t.Errorf("RequireLoopback(%q) = %v", addr, err)
		}
	}
}

func TestRequest(t *testing.T) {
	for host, ok := range map[string]bool{
		"127.0.0.1:8899":    true,
		"127.0.0.1":         true,
		"[::1]:8899":        true,
		"evil.example:8899": false,
		"localhost:8899":    false,
		"":                  false,
	} {
		r := httptest.NewRequest("GET", "/proxy.pac", nil)
		r.Host = host
		if got := Request(r); got != ok {
			t.Errorf("Request(Host %q) = %v, want %v", host, got, ok)
		}
	}
}
