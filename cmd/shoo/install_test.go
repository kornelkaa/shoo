package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shoo/internal/sites"
)

func TestStableBinary(t *testing.T) {
	cases := map[string]string{
		"/opt/homebrew/Cellar/shoo/0.1.0/bin/shoo": "/opt/homebrew/opt/shoo/bin/shoo",
		"/usr/local/Cellar/shoo/1.2.3_1/bin/shoo":  "/usr/local/opt/shoo/bin/shoo",
		"/opt/homebrew/bin/shoo":                   "/opt/homebrew/bin/shoo",
		"/Users/me/blockr/shoo":                    "/Users/me/blockr/shoo",
	}
	for in, want := range cases {
		if got := stableBinary(in); got != want {
			t.Errorf("stableBinary(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSettings(t *testing.T) {
	dir := t.TempDir()
	if s := loadSettings(dir); s.Sites != "strict" || !s.StartAtLogin {
		t.Errorf("defaults = %+v", s)
	}
	// An existing install keeps the level its list came from.
	os.WriteFile(filepath.Join(dir, "blocklist.txt"), []byte("# Source: "+strings.Join(sitesLevel("balanced"), "\n# Source: ")+"\nads.example.com\n"), 0o644)
	if s := loadSettings(dir); s.Sites != "balanced" {
		t.Errorf("level from list = %q", s.Sites)
	}
	if err := saveSettings(dir, Settings{Sites: sitesOff, StartAtLogin: false}); err != nil {
		t.Fatal(err)
	}
	if s := loadSettings(dir); s.Sites != sitesOff || s.StartAtLogin {
		t.Errorf("saved = %+v", s)
	}
	if (Settings{Sites: "bogus"}).valid() == nil {
		t.Error("bogus level accepted")
	}
}

func sitesLevel(name string) []string { return sites.Levels[name] }

func TestIsShooPAC(t *testing.T) {
	cur := "http://127.0.0.1:8899/proxy.pac?v=2"
	for url, want := range map[string]bool{
		"http://127.0.0.1:8899/proxy.pac":     true, // older shoo
		"http://127.0.0.1:8899/proxy.pac?v=1": true,
		cur:                                   true,
		"http://127.0.0.1:8899/proxy.pacx":    false,
		"http://127.0.0.1:9999/proxy.pac":     false,
		"http://corp.example/wpad.dat":        false,
	} {
		if got := isShooPAC(url, cur); got != want {
			t.Errorf("isShooPAC(%q) = %v, want %v", url, got, want)
		}
	}
}
