//go:build !windows

package main

// The LaunchAgent that keeps the proxy running in the background and starts
// it at login.

import (
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

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

func installAgent(exe, addr, pacURL string, s Settings) error {
	bin := stableBinary(exe)
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

	return waitForProxy(pacURL, logFile)
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

// stopAgent stops the background service.
func stopAgent() {
	exec.Command("launchctl", "bootout", guiDomain()+"/"+agentLabel).Run()
}

// agentInstalled reports whether the background service's file exists.
func agentInstalled() bool {
	p, err := agentPlistPath()
	return err == nil && fileExists(p)
}

// removeAgent stops the background service and deletes it.
func removeAgent() error {
	stopAgent()
	removeOldAgent()
	p, err := agentPlistPath()
	if err != nil {
		return nil
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s", p)
	}
	return nil
}

// notePID has nothing to do here: launchd knows what it started.
func notePID(string) {}
