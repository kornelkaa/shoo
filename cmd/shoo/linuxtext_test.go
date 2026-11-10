package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSdQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/local/bin/shoo":        `"/usr/local/bin/shoo"`,
		`/home/me/my "apps"/shoo`:    `"/home/me/my \"apps\"/shoo"`,
		`/home/me/100%/$HOME\x/shoo`: `"/home/me/100%%/$$HOME\\x/shoo"`,
		"/home/me/with space/shoo":   `"/home/me/with space/shoo"`,
		"127.0.0.1:8899":             `"127.0.0.1:8899"`,
	} {
		if got := sdQuote(in); got != want {
			t.Errorf("sdQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestAgentUnit(t *testing.T) {
	u := agentUnit("/home/me/bin/shoo", "127.0.0.1:8899", "/home/me/.local/state/shoo/shoo.log", Settings{Sites: "strict", StartAtLogin: true})
	for _, want := range []string{
		"ExecStart=\"/home/me/bin/shoo\" run -addr \"127.0.0.1:8899\"\n",
		"Restart=always\n",
		"StandardOutput=append:/home/me/.local/state/shoo/shoo.log\n",
		"WantedBy=default.target\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q\n%s", want, u)
		}
	}
	u = agentUnit("/bin/shoo", "127.0.0.1:8899", "/tmp/y.log", Settings{Sites: sitesOff, StartAtLogin: false})
	for _, want := range []string{"run -addr \"127.0.0.1:8899\" -sites=false\n", "Restart=no\n"} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q\n%s", want, u)
		}
	}
}

func TestDNSUnit(t *testing.T) {
	u := dnsUnit("/usr/local/libexec/shoo/shoo", "/home/me/.config/shoo", 1000, 1000, "/var/log/shoo-dns.log")
	for _, want := range []string{
		"ExecStart=\"/usr/local/libexec/shoo/shoo\" dns -data \"/home/me/.config/shoo\"\n",
		"User=1000\nGroup=1000\n",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE\n",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n",
		"NoNewPrivileges=yes\n",
		"WantedBy=multi-user.target\n",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q\n%s", want, u)
		}
	}
	if strings.Contains(u, "User=0") || strings.Contains(u, "User=root") {
		t.Error("DNS service must not run as root")
	}
}

func TestNMDNSConf(t *testing.T) {
	if !strings.Contains(nmDNSConf, "[global-dns-domain-*]\nservers=127.0.0.1\n") {
		t.Errorf("NetworkManager config:\n%s", nmDNSConf)
	}
}

func TestFirefoxProfiles(t *testing.T) {
	home := t.TempDir()
	mk := func(p string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(p, nil, 0o600)
	}
	mk(filepath.Join(home, ".mozilla/firefox/abc.default-release/cert9.db"))
	mk(filepath.Join(home, ".mozilla/firefox/empty.profile/prefs.js")) // never started: no db
	mk(filepath.Join(home, "snap/firefox/common/.mozilla/firefox/x.default/cert9.db"))
	mk(filepath.Join(home, ".var/app/org.mozilla.firefox/.mozilla/firefox/y.default/cert9.db"))
	mk(filepath.Join(home, ".config/mozilla/firefox/z.default/cert9.db"))
	got := firefoxProfiles(home)
	for i := range got {
		got[i], _ = filepath.Rel(home, got[i])
	}
	slices.Sort(got)
	want := []string{
		".config/mozilla/firefox/z.default",
		".mozilla/firefox/abc.default-release",
		".var/app/org.mozilla.firefox/.mozilla/firefox/y.default",
		"snap/firefox/common/.mozilla/firefox/x.default",
	}
	if !slices.Equal(got, want) {
		t.Errorf("firefoxProfiles = %q, want %q", got, want)
	}
}

func TestChromeDBs(t *testing.T) {
	home := t.TempDir()
	if got := chromeDBs(home); len(got) != 1 || got[0] != filepath.Join(home, ".pki/nssdb") {
		t.Errorf("chromeDBs = %q", got)
	}
	os.MkdirAll(filepath.Join(home, "snap/chromium/current/.pki/nssdb"), 0o700)
	if got := chromeDBs(home); len(got) != 2 {
		t.Errorf("with snap Chromium: %q", got)
	}
}

func TestGsettingsValue(t *testing.T) {
	for in, want := range map[string]string{
		"'auto'\n": "auto",
		"'http://127.0.0.1:8899/proxy.pac?v=2'\n": "http://127.0.0.1:8899/proxy.pac?v=2",
		"''\n": "",
		"none": "none",
	} {
		if got := gsettingsValue(in); got != want {
			t.Errorf("gsettingsValue(%q) = %q, want %q", in, got, want)
		}
	}
}
