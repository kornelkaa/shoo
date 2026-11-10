//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestDNSPlist(t *testing.T) {
	p := dnsPlist("/Users/me/Library/Application Support/shoo")
	for _, want := range []string{
		"<string>com.kornelkaa.shoo.dns</string>",
		"<string>/Library/Application Support/shoo/shoo</string>\n\t\t<string>dns</string>",
		"<string>/Users/me/Library/Application Support/shoo</string>",
		"<key>KeepAlive</key>\n\t<true/>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("plist missing %q\n%s", want, p)
		}
	}
	if _, err := exec.LookPath("plutil"); err == nil {
		f := filepath.Join(t.TempDir(), "dns.plist")
		os.WriteFile(f, []byte(p), 0o644)
		if out, err := exec.Command("plutil", "-lint", f).CombinedOutput(); err != nil {
			t.Errorf("plutil: %s", out)
		}
	}
}
