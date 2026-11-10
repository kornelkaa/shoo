package main

// `shoo setup` and `shoo uninstall`: everything needed to turn shoo
// on or off with one command, including a background service that keeps
// the proxy running and starts it at login (macos_agent.go, linux_agent.go).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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

// stableBinary maps a versioned Homebrew path
// (/opt/homebrew/Cellar/shoo/0.1.0/bin/shoo) to the path that stays the
// same across `brew upgrade` (/opt/homebrew/opt/shoo/bin/shoo).
// Other paths are returned unchanged.
func stableBinary(exe string) string {
	const cellar = "/Cellar/shoo/"
	i := strings.Index(exe, cellar)
	if i < 0 {
		return exe
	}
	rest := exe[i+len(cellar):] // "0.1.0/bin/shoo"
	j := strings.IndexByte(rest, '/')
	if j < 0 {
		return exe
	}
	return exe[:i] + "/opt/shoo" + rest[j:]
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

// notRunningElsewhere fails if a proxy that isn't the background service
// (e.g. `shoo run` in a terminal) holds the address.
func notRunningElsewhere(pacURL string) error {
	for i := 0; i < 20 && !agentLoaded() && proxyAnswers(pacURL); i++ {
		time.Sleep(250 * time.Millisecond) // the old service is shutting down
	}
	if !agentLoaded() && proxyAnswers(pacURL) {
		return errors.New("shoo is already running in a Terminal window: stop it with Ctrl+C, then run `shoo setup` again")
	}
	return nil
}

// waitForProxy waits up to 10 seconds for the background service to answer.
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

// setup turns everything on. Unless yes is set (or there is no terminal to
// answer in), it first asks what to set up. Safe to run again: finished
// steps are skipped, and the background service is refreshed.
func setup(dir, addr, pacURL string, yes bool) error {
	if os.Geteuid() == 0 {
		return errors.New("run `shoo setup` without sudo; it asks for your password when needed")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	bin := stableBinary(exe)

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
	if err := installAgent(bin, addr, pacURL, s); err != nil {
		return err
	}

	wantDNS := s.Sites != sitesOff
	if wantDNS {
		step("Point " + osName + " at shoo (YouTube via the proxy, ad domains via DNS)")
	} else {
		step("Point " + osName + " at shoo (YouTube via the proxy)")
	}
	if err := applyNetwork(exe, dir, addr, pacURL, wantDNS); err != nil {
		return err
	}

	fmt.Println("\nDone. " + reopenHint)
	fmt.Println()
	status(dir, addr, pacURL)
	return nil
}

// uninstall turns everything off. It keeps going when a step fails and
// reports what it couldn't undo.
func uninstall(dir, addr, pacURL string, purge bool) error {
	if os.Geteuid() == 0 {
		return errors.New("run `shoo uninstall` without sudo; it asks for your password when needed")
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

	fmt.Println("Turning off the network settings and DNS service (may ask for your password)...")
	if err := turnOffNetwork(exe, addr, pacURL); err != nil {
		failed = append(failed, "network setting: run `"+disableHint+"`")
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

// ownedByRoot reports whether only an admin can change the file at path
// (and the folder it is in).
func ownedByRoot(path string) bool {
	for _, p := range []string{path, filepath.Dir(path)} {
		fi, err := os.Stat(p)
		if err != nil {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return false
		}
	}
	return true
}

func sudoRun(args ...string) error {
	sudo := exec.Command("sudo", args...)
	sudo.Stdin, sudo.Stdout, sudo.Stderr = os.Stdin, os.Stdout, os.Stderr
	return sudo.Run()
}
