//go:build linux

package main

// The desktop's proxy setting on Linux. It belongs to the user, so changing
// it needs no password. GNOME's (gsettings) is read by GNOME apps, Chrome
// on GNOME and Firefox ("Use system proxy settings", its default); KDE's
// (kioslaverc) by KDE apps and Chrome on KDE. Both are set when both exist.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// proxyPlace is one desktop's proxy setting.
type proxyPlace struct {
	name string
	// get returns the current mode, and the PAC URL if the mode is "use a
	// PAC file".
	get func() (mode, url string, pac bool)
	// setPAC turns the PAC file at url on.
	setPAC func(url string) error
	// restore sets the mode (and URL) from before shoo.
	restore func(mode, url string) error
}

func gsettings(args ...string) (string, error) {
	out, err := exec.Command("gsettings", args...).Output()
	return gsettingsValue(string(out)), err
}

func gnomePlace() (proxyPlace, bool) {
	if _, err := gsettings("get", "org.gnome.system.proxy", "mode"); err != nil {
		return proxyPlace{}, false
	}
	return proxyPlace{
		name: "GNOME proxy setting",
		get: func() (string, string, bool) {
			mode, _ := gsettings("get", "org.gnome.system.proxy", "mode")
			url, _ := gsettings("get", "org.gnome.system.proxy", "autoconfig-url")
			return mode, url, mode == "auto"
		},
		setPAC: func(url string) error {
			if err := run("gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", url); err != nil {
				return err
			}
			return run("gsettings", "set", "org.gnome.system.proxy", "mode", "auto")
		},
		restore: func(mode, url string) error {
			if mode == "" {
				mode = "none"
			}
			if err := run("gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", url); err != nil {
				return err
			}
			return run("gsettings", "set", "org.gnome.system.proxy", "mode", mode)
		},
	}, true
}

func kdePlace() (proxyPlace, bool) {
	read, write := "kreadconfig6", "kwriteconfig6"
	if _, err := exec.LookPath(write); err != nil {
		read, write = "kreadconfig5", "kwriteconfig5"
		if _, err := exec.LookPath(write); err != nil {
			return proxyPlace{}, false
		}
	}
	get := func(key string) string {
		out, _ := exec.Command(read, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key).Output()
		return strings.TrimSpace(string(out))
	}
	set := func(key, val string) error {
		return run(write, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key, val)
	}
	// Tells running KDE apps to read the setting again.
	notify := func() {
		exec.Command("dbus-send", "--type=signal", "/KIO/Scheduler",
			"org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:").Run()
	}
	return proxyPlace{
		name: "KDE proxy setting",
		get: func() (string, string, bool) {
			mode := get("ProxyType")
			return mode, get("Proxy Config Script"), mode == kdePAC
		},
		setPAC: func(url string) error {
			if err := set("Proxy Config Script", url); err != nil {
				return err
			}
			if err := set("ProxyType", kdePAC); err != nil {
				return err
			}
			notify()
			return nil
		},
		restore: func(mode, url string) error {
			if mode == "" {
				mode = "0" // no proxy
			}
			if err := set("Proxy Config Script", url); err != nil {
				return err
			}
			if err := set("ProxyType", mode); err != nil {
				return err
			}
			notify()
			return nil
		},
	}, true
}

func proxyPlaces() []proxyPlace {
	var out []proxyPlace
	if p, ok := gnomePlace(); ok {
		out = append(out, p)
	}
	if p, ok := kdePlace(); ok {
		out = append(out, p)
	}
	return out
}

// proxyBefore is each place's setting from before shoo, kept to put back.
type proxyBefore map[string]struct{ Mode, URL string }

func proxyBeforePath() string {
	dir, _ := dataDir()
	return filepath.Join(dir, "proxy-before.json")
}

func readProxyBefore() proxyBefore {
	m := proxyBefore{}
	if b, err := os.ReadFile(proxyBeforePath()); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

func writeProxyBefore(m proxyBefore) error {
	if len(m) == 0 {
		err := os.Remove(proxyBeforePath())
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(proxyBeforePath(), b, 0o600)
}

// enabledEverywhere reports whether every proxy setting already uses pacURL.
func enabledEverywhere(pacURL string) bool {
	places := proxyPlaces()
	if len(places) == 0 {
		return false
	}
	for _, p := range places {
		if _, url, pac := p.get(); !pac || url != pacURL {
			return false
		}
	}
	return true
}

// enable points the desktop's proxy setting at our PAC file. It won't
// replace a different PAC file the user already has, unless force is set.
func enable(pacURL string, force bool) error {
	places := proxyPlaces()
	if len(places) == 0 {
		return errors.New("can't find GNOME's or KDE's proxy setting (gsettings, kwriteconfig6): " +
			"set your desktop's automatic proxy configuration URL to " + pacURL + " by hand")
	}
	before := readProxyBefore()
	for _, p := range places {
		mode, url, pac := p.get()
		if pac && !isShooPAC(url, pacURL) && !force {
			fmt.Printf("  %-24s skipped: already uses %s (use -force to replace)\n", p.name, url)
			continue
		}
		if !(pac && isShooPAC(url, pacURL)) {
			before[p.name] = struct{ Mode, URL string }{mode, url}
		}
		if err := p.setPAC(pacURL); err != nil {
			return fmt.Errorf("%s: %w", p.name, err)
		}
		fmt.Printf("  %-24s on\n", p.name)
	}
	return writeProxyBefore(before)
}

// disable puts the proxy setting back, only where it's ours.
func disable(pacURL string) error {
	before := readProxyBefore()
	for _, p := range proxyPlaces() {
		if _, url, pac := p.get(); !pac || !isShooPAC(url, pacURL) {
			continue
		}
		b := before[p.name]
		if err := p.restore(b.Mode, b.URL); err != nil {
			return fmt.Errorf("%s: %w", p.name, err)
		}
		delete(before, p.name)
		fmt.Printf("  %-24s off\n", p.name)
	}
	return writeProxyBefore(before)
}
