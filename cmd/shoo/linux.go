//go:build linux

package main

// Linux system integration: what setup, uninstall and status do here.
// The pieces are in linux_agent.go (background service), linux_trust.go
// (certificate), linux_net.go (proxy setting) and linux_dns.go (DNS).

import (
	"errors"
	"fmt"
	"os"
)

const (
	osName       = "Linux"
	computerName = "computer"
	reopenHint   = "Close your browser completely and open it again."
	reopenBrief  = "reopen your browser if it doesn't"
	trustPrompt  = "adding it to Chrome and Firefox; the system store asks for your password (sudo)"
	stopNote     = "shoo is stopped until `shoo start` (or your next login, if it starts at login).\nMeanwhile YouTube shows ads. Ad domains on other sites stay blocked (DNS keeps running)."
	certStore    = "trust stores"
	disableHint  = "shoo disable"
)

const usageSteps = `  shoo enable [-force] [-dns]
                            point your desktop's proxy setting (GNOME, KDE) at shoo
                               (-dns: also install the ad-blocking DNS service
                               and use it as DNS; asks for your password)
  shoo disable              turn shoo off in the proxy setting (also DNS)
  sudo shoo disable-dns     only remove the DNS service and restore DNS
`

// platformCommand runs the steps only Linux has; they run with sudo.
func platformCommand(cmd, dir string) (bool, error) {
	switch cmd {
	case "trust-system":
		return true, trustSystem(dir)
	case "untrust-system":
		return true, untrustSystem()
	}
	return false, nil
}

// cmdEnable is `shoo enable [-force] [-dns]`. The proxy setting is the
// user's own; with -dns it asks for the password and calls itself with
// sudo for the DNS service.
func cmdEnable(dir, pacURL string, force, dnsOn bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if !dnsOn {
			return errors.New("the proxy setting belongs to your user: run `shoo enable` without sudo")
		}
		return enableDNS(exe, dir)
	}
	if err := enable(pacURL, force); err != nil || !dnsOn {
		return err
	}
	return sudoRun(exe, "enable", "-dns", "-data", dir)
}

// cmdDisable is `shoo disable`: the proxy setting, then DNS (sudo).
func cmdDisable(_, pacURL string) error {
	if os.Geteuid() == 0 {
		return disableDNS()
	}
	err := disable(pacURL)
	if dnsInstalled() || fileExists(nmConfPath) {
		exe, exeErr := os.Executable()
		if exeErr == nil {
			exeErr = sudoRun(exe, "disable-dns")
		}
		if err == nil {
			err = exeErr
		}
	}
	return err
}

// applyNetwork is setup's last step: the proxy setting (no password) and,
// with wantDNS, the DNS service (sudo).
func applyNetwork(exe, dir, addr, pacURL string, wantDNS bool) error {
	changed := false
	if !enabledEverywhere(pacURL) {
		if err := enable(pacURL, false); err != nil {
			return err
		}
		changed = true
	}
	nm := networkManager()
	if wantDNS && !nm {
		fmt.Println("  DNS: skipped, it needs NetworkManager (ad domains are still blocked in the proxy)")
	}
	needDNSOn := wantDNS && nm && !(dnsInstalledFrom(exe) && dnsEverywhere() && dnsAnswers())
	needDNSOff := !wantDNS && (dnsInstalled() || fileExists(nmConfPath))
	if !needDNSOn && !needDNSOff {
		if !changed {
			fmt.Println("  already on")
		}
		return nil
	}
	fmt.Println("  the DNS service needs your password (sudo)")
	if !ownedByRoot(exe) {
		fmt.Printf("  note: %s can be changed without a password; installing with install.sh\n"+
			"  makes it admin-owned, so nothing can swap it before it runs with sudo\n", exe)
	}
	if needDNSOn {
		if err := sudoRun(exe, "enable", "-dns", "-data", dir); err != nil {
			return fmt.Errorf("turning on the DNS service: %w", err)
		}
		return nil
	}
	if err := sudoRun(exe, "disable-dns"); err != nil {
		return fmt.Errorf("removing the DNS service: %w", err)
	}
	return nil
}

// turnOffNetwork is uninstall's network step.
func turnOffNetwork(_, _, pacURL string) error { return cmdDisable("", pacURL) }

// networkStatus is the last part of `shoo status`: the proxy settings and DNS.
func networkStatus(pacURL string, showDNS bool) {
	fmt.Println("Network:")
	places := proxyPlaces()
	if len(places) == 0 {
		fmt.Println("  no GNOME or KDE proxy setting found (set the automatic proxy URL " + pacURL + " by hand)")
	}
	for _, p := range places {
		_, url, pac := p.get()
		var line string
		switch {
		case pac && url == pacURL:
			line = "on"
		case pac && isShooPAC(url, pacURL):
			line = "on, but an older PAC address (run `shoo setup`)"
		case pac:
			line = "not shoo (another PAC file is on: " + url + ")"
		default:
			line = "off"
		}
		fmt.Printf("  %-24s %s\n", p.name, line)
	}
	switch {
	case dnsEverywhere():
		fmt.Printf("  %-24s shoo\n", "DNS")
	case showDNS && !networkManager():
		fmt.Printf("  %-24s not shoo (needs NetworkManager)\n", "DNS")
	case showDNS:
		fmt.Printf("  %-24s not shoo\n", "DNS")
	}
}

// permissionsText is the password summary setup shows before it starts.
func permissionsText(trusted bool) string {
	certLine := "• Chrome and Firefox get shoo's certificate in your own profile (no\n" +
		"  password); the system's certificate store needs your password (sudo).\n" +
		"  With it shoo decrypts websites on this computer to remove ads and hide\n" +
		"  ad boxes. Banks, logins and payments are never decrypted, and the\n" +
		"  certificate can't be used for them. The key never leaves this computer."
	if trusted {
		certLine = "• The certificate is already trusted: no password needed for it\n" +
			"  (unless it's old or expires soon: then it's replaced, which asks once)."
	}
	return certLine + "\n" +
		"• If blocking other websites, sudo is also needed once to install the\n" +
		"  DNS service that answers ad domains with a dead address.\n" +
		"• The proxy setting (GNOME, KDE) and the background service need no password."
}
