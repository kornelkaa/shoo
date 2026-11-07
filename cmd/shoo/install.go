package main

// `shoo setup` and `shoo uninstall`: everything needed to turn shoo on or off
// with one command. The system-specific steps are in macos*.go and *_windows.go.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shoo/internal/certs"
	"shoo/internal/cosmetic"
	"shoo/internal/sites"
)

// caConstrained reports whether the saved CA only works for YouTube.
func caConstrained(dir string) bool {
	ca, err := certs.Load(dir)
	return err == nil && certs.Constrained(ca.Cert)
}

func proxyAnswers(pacURL string) bool {
	c := http.Client{Timeout: time.Second}
	resp, err := c.Get(pacURL)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// setup turns everything on. Unless yes is set (or there is no terminal to
// answer in), it first asks what to set up. Safe to run again: finished
// steps are skipped, and the background service is refreshed.
func setup(dir, addr string, addrGiven, yes bool) error {
	if isAdmin() {
		return errors.New("run `shoo setup` " + notAdminHint)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	s := loadSettings(dir)
	if !yes && interactive() {
		trusted, _ := isTrusted(dir)
		var ok bool
		if s, ok, err = askSettings(s, trusted); err != nil {
			return err
		} else if !ok {
			fmt.Println("Cancelled. Nothing was changed.")
			return nil
		}
	}
	if err := s.valid(); err != nil {
		return err
	}
	// The proxy address is chosen once and then kept; -addr replaces it.
	switch {
	case addrGiven:
		s.Addr = addr
	case s.Addr == "":
		if s.Addr, err = chooseAddr(); err != nil {
			return err
		}
	}
	addr = s.Addr
	pacURL := pacURLFor(addr)
	if err := saveSettings(dir, s); err != nil {
		return err
	}

	n := 0
	step := func(msg string) { n++; fmt.Printf("\n[%d/5] %s\n", n, msg) }

	step("shoo's certificate")
	_, statCA := os.Stat(filepath.Join(dir, certs.CertFile))
	replace := ""
	if ca, err := certs.Load(dir); statCA == nil && err == nil {
		// Old (YouTube-only, or able to sign for banks and logins) or
		// about to expire: make a new one.
		replace = certs.ReplaceReason(ca.Cert, sites.Exclusions(), s.Sites != sitesOff)
	}
	switch {
	case replace != "":
		fmt.Printf("  replacing the certificate: %s\n", replace)
		if err := untrust(dir); err != nil {
			return fmt.Errorf("removing the old certificate: %w", err)
		}
		if err := certs.Generate(dir, true, neverDecrypt(dir)); err != nil {
			return err
		}
		fmt.Println("  created")
	case statCA == nil:
		fmt.Println("  already created")
	default:
		if err := certs.Generate(dir, false, neverDecrypt(dir)); err != nil {
			return err
		}
		fmt.Println("  created")
	}

	step("Trust the certificate")
	if ok, _ := isTrusted(dir); ok {
		fmt.Println("  already trusted")
	} else {
		fmt.Println("  " + trustPrompt)
		if err := trust(dir); err != nil {
			return fmt.Errorf("trusting the certificate: %w", err)
		}
		fmt.Println("  trusted")
	}

	step("Ad-domain lists for other websites")
	_, statErr := os.Stat(filepath.Join(dir, sites.BlocklistFile))
	switch {
	case s.Sites == sitesOff:
		fmt.Println("  off (YouTube only)")
	case statErr == nil && currentLevel(dir) == s.Sites:
		fmt.Printf("  %s, already downloaded (refreshed automatically every week)\n", s.Sites)
	default:
		fmt.Printf("  downloading %s lists...\n", s.Sites)
		n, err := sites.Update(context.Background(), dir, sites.Levels[s.Sites])
		if err != nil {
			// Not fatal: YouTube blocking works without the lists, and the
			// background service retries.
			fmt.Printf("  could not download (%v); the background service will retry\n", err)
		} else {
			fmt.Printf("  %d ad domains\n", n)
		}
	}
	if s.Sites != sitesOff && !cosmetic.Current(dir) {
		fmt.Println("  downloading filter lists (EasyList, EasyPrivacy, uBlock Origin, Hufilter)...")
		if n, err := cosmetic.Update(context.Background(), dir); err != nil {
			fmt.Printf("  could not download (%v); the background service will retry\n", err)
		} else {
			fmt.Printf("  %d rules for hiding ad boxes\n", n)
		}
	}

	if s.StartAtLogin {
		step("Background service (starts at login)")
	} else {
		step("Background service (runs now; `shoo start` after you log in again)")
	}
	if err := installAgent(exe, addr, pacURL, s); err != nil {
		return err
	}

	wantDNS := s.Sites != sitesOff
	if wantDNS {
		step("Point " + osName + " at shoo (YouTube via the proxy, ad domains via DNS)")
	} else {
		step("Point " + osName + " at shoo (YouTube via the proxy)")
	}
	needPAC := !enabledEverywhere(pacURL)
	needDNSOn := wantDNS && !(dnsInstalledFrom(exe) && dnsServes(dir) && dnsEverywhere() && dnsAnswers())
	needDNSOff := !wantDNS && dnsServes(dir)
	if !needPAC && !needDNSOn && !needDNSOff {
		fmt.Println("  already on")
	} else {
		if err := applyNetwork(exe, dir, addr, pacURL, wantDNS, needDNSOn, needDNSOff); err != nil {
			return err
		}
	}

	fmt.Println("\nDone. " + reopenHint)
	fmt.Println()
	status(dir, addr, pacURL)
	return nil
}

// uninstall turns everything off. It keeps going when a step fails and
// reports what it couldn't undo.
func uninstall(dir, addr, pacURL string, purge bool) error {
	if isAdmin() {
		return errors.New("run `shoo uninstall` " + notAdminHint)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var failed []string

	fmt.Println("Stopping the background service...")
	if err := removeAgent(); err != nil {
		failed = append(failed, err.Error())
	}

	fmt.Println("Turning off the network settings and DNS service...")
	if err := turnOffNetwork(exe, dir, addr, pacURL); err != nil {
		failed = append(failed, "network setting: "+err.Error())
	}

	fmt.Println("Removing the certificate from the " + certStore + "...")
	if _, err := os.Stat(filepath.Join(dir, certs.CertFile)); err == nil {
		if err := untrust(dir); err != nil {
			failed = append(failed, "certificate: run `shoo untrust`")
		}
	}

	if purge {
		fmt.Println("Deleting shoo's files...")
		if err := os.RemoveAll(dir); err != nil {
			failed = append(failed, "delete "+dir)
		}
		if l, err := logPath(); err == nil {
			os.Remove(l)
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("could not undo: %s", strings.Join(failed, "; "))
	}
	fmt.Println("\nDone. shoo is off. " + reopenHint)
	if !purge {
		fmt.Printf("Your settings and lists are kept in %s (use -purge to delete them).\n", dir)
	}
	return nil
}

// waitForProxy waits for the background service to start answering.
func waitForProxy(pacURL, logFile string) error {
	for i := 0; i < 40; i++ {
		if proxyAnswers(pacURL) {
			fmt.Printf("  running (log: %s)\n", logFile)
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("the background service didn't start; see %s", logFile)
}
