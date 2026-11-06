package main

// `shoo setup` and `shoo uninstall`: everything needed to turn shoo
// on or off with one command, including a LaunchAgent that keeps the proxy
// running in the background and starts it at login.

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

const agentLabel = "com.kornelkaa.shoo"

// oldAgentLabel is the background service from when shoo was called ytblock.
const oldAgentLabel = "com.kornelkaa.ytblock"

// removeOldAgent stops and deletes the ytblock background service, if any.
func removeOldAgent() {
	exec.Command("launchctl", "bootout", guiDomain()+"/"+oldAgentLabel).Run()
	if home, err := os.UserHomeDir(); err == nil {
		os.Remove(filepath.Join(home, "Library", "LaunchAgents", oldAgentLabel+".plist"))
	}
}

// enabledEverywhere reports whether every network service already uses
// pacURL, so the sudo step can be skipped.
func enabledEverywhere(pacURL string) bool {
	svcs, err := networkServices()
	if err != nil || len(svcs) == 0 {
		return false
	}
	for _, svc := range svcs {
		if cur, on := autoProxy(svc); !on || cur != pacURL {
			return false
		}
	}
	return true
}

func agentPlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", agentLabel+".plist"), nil
}

func logPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Logs", "shoo.log"), nil
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

// agentPlist is the LaunchAgent that runs `shoo run`. With StartAtLogin
// it starts at login and is restarted if it stops; without, it only runs
// when started (`shoo start`) and stops at logout.
func agentPlist(bin, addr, logFile string, s Settings) string {
	e := html.EscapeString
	sitesArg := ""
	if s.Sites == sitesOff {
		sitesArg = "\n\t\t<string>-sites=false</string>"
	}
	atLogin := "<false/>"
	if s.StartAtLogin {
		atLogin = "<true/>"
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + agentLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + e(bin) + `</string>
		<string>run</string>
		<string>-addr</string>
		<string>` + e(addr) + `</string>` + sitesArg + `
	</array>
	<key>RunAtLoad</key>
	` + atLogin + `
	<key>KeepAlive</key>
	` + atLogin + `
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>` + e(logFile) + `</string>
	<key>StandardErrorPath</key>
	<string>` + e(logFile) + `</string>
</dict>
</plist>
`
}

func guiDomain() string { return "gui/" + strconv.Itoa(os.Getuid()) }

func agentLoaded() bool {
	return exec.Command("launchctl", "print", guiDomain()+"/"+agentLabel).Run() == nil
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
	switch {
	case statCA == nil && s.Sites != sitesOff && caConstrained(dir):
		// Made by an older shoo, for YouTube only: hiding ads on other
		// websites needs one that works for them too.
		fmt.Println("  replacing the YouTube-only certificate with one for all websites")
		if err := untrust(dir); err != nil {
			return fmt.Errorf("removing the old certificate: %w", err)
		}
		if err := certs.Generate(dir, true); err != nil {
			return err
		}
		fmt.Println("  created")
	case statCA == nil:
		fmt.Println("  already created")
	default:
		if err := certs.Generate(dir, false); err != nil {
			return err
		}
		fmt.Println("  created")
	}

	step("Trust the certificate")
	if ok, _ := isTrusted(dir); ok {
		fmt.Println("  already trusted")
	} else {
		fmt.Println("  macOS will ask for your password")
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
	if _, err := os.Stat(filepath.Join(dir, cosmetic.ListFile)); s.Sites != sitesOff && err != nil {
		fmt.Println("  downloading element-hiding lists (EasyList, Hufilter)...")
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
		step("Point macOS at shoo (YouTube via the proxy, ad domains via DNS)")
	} else {
		step("Point macOS at shoo (YouTube via the proxy)")
	}
	needPAC := !enabledEverywhere(pacURL)
	needDNSOn := wantDNS && !(dnsInstalledFrom(exe) && dnsEverywhere() && dnsAnswers())
	needDNSOff := !wantDNS && fileExists(dnsPlistPath)
	if !needPAC && !needDNSOn && !needDNSOff {
		fmt.Println("  already on")
	} else {
		fmt.Println("  changing network settings needs your password (sudo)")
		args := []string{exe, "enable", "-addr", addr}
		if wantDNS {
			args = append(args, "-dns", "-data", dir)
		}
		if err := sudoRun(args...); err != nil {
			return fmt.Errorf("turning on the network settings: %w", err)
		}
		if needDNSOff {
			if err := sudoRun(exe, "disable-dns"); err != nil {
				return fmt.Errorf("removing the DNS service: %w", err)
			}
		}
	}

	fmt.Println("\nDone. Quit Safari (⌘Q) and open it again.")
	fmt.Println()
	status(dir, addr, pacURL)
	return nil
}

func installAgent(bin, addr, pacURL string, s Settings) error {
	plistPath, err := agentPlistPath()
	if err != nil {
		return err
	}
	logFile, err := logPath()
	if err != nil {
		return err
	}
	removeOldAgent()
	for i := 0; i < 20 && !agentLoaded() && proxyAnswers(pacURL); i++ {
		time.Sleep(250 * time.Millisecond) // the old service is shutting down
	}
	if !agentLoaded() && proxyAnswers(pacURL) {
		return errors.New("shoo is already running in a Terminal window: stop it with Ctrl+C, then run `shoo setup` again")
	}
	for _, d := range []string{filepath.Dir(plistPath), filepath.Dir(logFile)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(plistPath, []byte(agentPlist(bin, addr, logFile, s)), 0o644); err != nil {
		return err
	}

	// Reload so a changed binary path or address takes effect.
	exec.Command("launchctl", "bootout", guiDomain()+"/"+agentLabel).Run()
	var out []byte
	for i := 0; i < 10; i++ { // bootout finishes in the background
		out, err = exec.Command("launchctl", "bootstrap", guiDomain(), plistPath).CombinedOutput()
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("starting the background service: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if !s.StartAtLogin {
		// Not started automatically when loaded: start it now.
		if err := startAgent(); err != nil {
			return err
		}
	}

	for i := 0; i < 40; i++ {
		if proxyAnswers(pacURL) {
			fmt.Printf("  running (log: %s)\n", logFile)
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("the background service didn't start; see %s", logFile)
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
	exec.Command("launchctl", "bootout", guiDomain()+"/"+agentLabel).Run()
	removeOldAgent()
	if p, err := agentPlistPath(); err == nil {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = append(failed, "remove "+p)
		}
	}

	fmt.Println("Turning off the network settings and DNS service (needs your password)...")
	sudo := exec.Command("sudo", exe, "disable", "-addr", addr)
	sudo.Stdin, sudo.Stdout, sudo.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := sudo.Run(); err != nil {
		failed = append(failed, "network setting: run `sudo shoo disable`")
	}

	fmt.Println("Removing the certificate from the keychain...")
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
	fmt.Println("\nDone. shoo is off. Quit Safari (⌘Q) and open it again.")
	if !purge {
		fmt.Printf("Your settings and lists are kept in %s (use -purge to delete them).\n", dir)
	}
	return nil
}

func sudoRun(args ...string) error {
	sudo := exec.Command("sudo", args...)
	sudo.Stdin, sudo.Stdout, sudo.Stderr = os.Stdin, os.Stdout, os.Stderr
	return sudo.Run()
}

// startAgent starts the background service now (it must be installed).
func startAgent() error {
	if out, err := exec.Command("launchctl", "kickstart", guiDomain()+"/"+agentLabel).CombinedOutput(); err != nil {
		return fmt.Errorf("starting the background service: %v: %s (run `shoo setup` first)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// loadAgent loads the installed background service after a login where it
// wasn't started automatically.
func loadAgent() error {
	if agentLoaded() {
		return nil
	}
	p, err := agentPlistPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err != nil {
		return errors.New("shoo isn't set up yet: run `shoo setup`")
	}
	if out, err := exec.Command("launchctl", "bootstrap", guiDomain(), p).CombinedOutput(); err != nil {
		return fmt.Errorf("loading the background service: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
