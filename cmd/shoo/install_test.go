package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ytblock/internal/sites"
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

func TestAgentPlist(t *testing.T) {
	p := agentPlist("/Users/me/my <apps>/shoo", "127.0.0.1:8899", "/Users/me/Library/Logs/shoo.log", Settings{Sites: "strict", StartAtLogin: true})
	for _, want := range []string{
		"<string>com.kornelkaa.shoo</string>",
		"<string>/Users/me/my &lt;apps&gt;/shoo</string>",
		"<string>run</string>",
		"<string>127.0.0.1:8899</string>",
		"<key>KeepAlive</key>\n\t<true/>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<string>/Users/me/Library/Logs/shoo.log</string>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist missing %q", want)
		}
	}
	// Check it with macOS's own plist checker.
	if _, err := exec.LookPath("plutil"); err == nil {
		f := filepath.Join(t.TempDir(), "agent.plist")
		os.WriteFile(f, []byte(p), 0o644)
		if out, err := exec.Command("plutil", "-lint", f).CombinedOutput(); err != nil {
			t.Errorf("plutil: %s", out)
		}
	}
}

func TestAgentPlistChoices(t *testing.T) {
	p := agentPlist("/bin/shoo", "127.0.0.1:8899", "/tmp/y.log", Settings{Sites: sitesOff, StartAtLogin: false})
	for _, want := range []string{
		"<string>127.0.0.1:8899</string>\n\t\t<string>-sites=false</string>",
		"<key>KeepAlive</key>\n\t<false/>",
		"<key>RunAtLoad</key>\n\t<false/>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist missing %q\n%s", want, p)
		}
	}
	if _, err := exec.LookPath("plutil"); err == nil {
		f := filepath.Join(t.TempDir(), "agent.plist")
		os.WriteFile(f, []byte(p), 0o644)
		if out, err := exec.Command("plutil", "-lint", f).CombinedOutput(); err != nil {
			t.Errorf("plutil: %s", out)
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
