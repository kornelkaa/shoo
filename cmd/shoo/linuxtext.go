package main

// Text and files for the Linux integration (linux*.go). Kept free of
// system calls and build tags so the tests run on every system.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	agentUnitName = "shoo.service"
	dnsUnitName   = "shoo-dns.service"
	// nssNick is the certificate's name in Chrome's and Firefox's
	// certificate databases.
	nssNick = "shoo local CA"
)

// nmDNSConf points every NetworkManager connection, including ones made
// later, at shoo's DNS server. Deleting the file puts DNS back.
const nmDNSConf = `# Written by shoo: all DNS lookups go to shoo's ad-blocking DNS server,
# which passes everything except ad domains on to the network's own DNS.
# ` + "`shoo uninstall`" + ` deletes this file.
[global-dns-domain-*]
servers=` + dnsServerIP + `
`

// sdQuote quotes one word of a systemd ExecStart= line.
func sdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$")
	return `"` + r.Replace(s) + `"`
}

// sdPath escapes a path used after "append:" in a unit file.
func sdPath(s string) string { return strings.ReplaceAll(s, "%", "%%") }

// agentUnit is the systemd user service that runs `shoo run`. With
// StartAtLogin it is enabled (starts with the login session) and restarted
// if it stops; without, it only runs when started (`shoo start`).
func agentUnit(bin, addr, logFile string, s Settings) string {
	args := []string{sdQuote(bin), "run", "-addr", sdQuote(addr)}
	if s.Sites == sitesOff {
		args = append(args, "-sites=false")
	}
	restart := "no"
	if s.StartAtLogin {
		restart = "always"
	}
	return `# Written by shoo setup. ` + "`shoo uninstall`" + ` deletes it.
[Unit]
Description=shoo ad blocker (proxy)

[Service]
ExecStart=` + strings.Join(args, " ") + `
Restart=` + restart + `
RestartSec=10
StandardOutput=append:` + sdPath(logFile) + `
StandardError=append:` + sdPath(logFile) + `

[Install]
WantedBy=default.target
`
}

// dnsUnit is the system service that runs `shoo dns` as the owner of the
// data folder. It never has root rights: only the right to open port 53.
func dnsUnit(bin, dir string, uid, gid int, logFile string) string {
	return `# Written by shoo setup. ` + "`shoo uninstall`" + ` deletes it.
[Unit]
Description=shoo ad-blocking DNS server
After=network.target
Before=nss-lookup.target
Wants=nss-lookup.target

[Service]
ExecStart=` + sdQuote(bin) + ` dns -data ` + sdQuote(dir) + `
User=` + strconv.Itoa(uid) + `
Group=` + strconv.Itoa(gid) + `
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
Restart=always
RestartSec=5
StandardOutput=append:` + sdPath(logFile) + `
StandardError=append:` + sdPath(logFile) + `

[Install]
WantedBy=multi-user.target
`
}

// firefoxRoots are the folders Firefox keeps its profiles in: the usual
// one, the newer XDG one, and the Snap and Flatpak packages'.
func firefoxRoots(home string) []string {
	return []string{
		filepath.Join(home, ".mozilla", "firefox"),
		filepath.Join(home, ".config", "mozilla", "firefox"),
		filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
		filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
	}
}

// firefoxProfiles lists Firefox profile folders that have a certificate
// database.
func firefoxProfiles(home string) []string {
	var out []string
	for _, root := range firefoxRoots(home) {
		m, _ := filepath.Glob(filepath.Join(root, "*", "cert9.db"))
		for _, db := range m {
			out = append(out, filepath.Dir(db))
		}
	}
	return out
}

// chromeDBs lists the certificate databases Chrome, Chromium and the
// browsers built on them read: ~/.pki/nssdb (created if missing) and the
// Snap Chromium's own.
func chromeDBs(home string) []string {
	out := []string{filepath.Join(home, ".pki", "nssdb")}
	snap := filepath.Join(home, "snap", "chromium", "current", ".pki", "nssdb")
	if fi, err := os.Stat(snap); err == nil && fi.IsDir() {
		out = append(out, snap)
	}
	return out
}

// gsettingsValue turns gsettings' output ('auto', 'http://…') into the plain
// string.
func gsettingsValue(out string) string {
	v := strings.TrimSpace(out)
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		v = v[1 : len(v)-1]
	}
	return v
}

// kdePAC is KDE's ProxyType value for "use proxy auto-config URL".
const kdePAC = "2"
