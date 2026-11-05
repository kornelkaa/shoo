package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStableBinary(t *testing.T) {
	cases := map[string]string{
		"/opt/homebrew/Cellar/ytblock/0.1.0/bin/ytblock": "/opt/homebrew/opt/ytblock/bin/ytblock",
		"/usr/local/Cellar/ytblock/1.2.3_1/bin/ytblock":  "/usr/local/opt/ytblock/bin/ytblock",
		"/opt/homebrew/bin/ytblock":                      "/opt/homebrew/bin/ytblock",
		"/Users/me/blockr/ytblock":                       "/Users/me/blockr/ytblock",
	}
	for in, want := range cases {
		if got := stableBinary(in); got != want {
			t.Errorf("stableBinary(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAgentPlist(t *testing.T) {
	p := agentPlist("/Users/me/my <apps>/ytblock", "127.0.0.1:8899", "/Users/me/Library/Logs/ytblock.log")
	for _, want := range []string{
		"<string>com.kornelkaa.ytblock</string>",
		"<string>/Users/me/my &lt;apps&gt;/ytblock</string>",
		"<string>run</string>",
		"<string>127.0.0.1:8899</string>",
		"<key>KeepAlive</key>\n\t<true/>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<string>/Users/me/Library/Logs/ytblock.log</string>",
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
