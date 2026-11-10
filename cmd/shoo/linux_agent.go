//go:build linux

package main

// The systemd user service that keeps the proxy running in the background
// and starts it at login.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func agentUnitPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "systemd", "user", agentUnitName), nil
}

// logPath is ~/.local/state/shoo/shoo.log (or under $XDG_STATE_HOME).
func logPath() (string, error) {
	state := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(state) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		state = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(state, "shoo", "shoo.log"), nil
}

func systemctlUser(args ...string) error {
	out, err := exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl --user %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// agentLoaded reports whether the background service is running.
func agentLoaded() bool {
	return exec.Command("systemctl", "--user", "is-active", "--quiet", agentUnitName).Run() == nil
}

// agentInstalled reports whether the background service's file exists.
func agentInstalled() bool {
	p, err := agentUnitPath()
	return err == nil && fileExists(p)
}

func installAgent(bin, addr, pacURL string, s Settings) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("shoo needs systemd to run in the background; start it by hand with `shoo run`")
	}
	if err := exec.Command("systemctl", "--user", "show-environment").Run(); err != nil {
		return errors.New("can't reach your systemd user session (run `shoo setup` from a terminal in your desktop session, not over sudo or su)")
	}
	unitPath, err := agentUnitPath()
	if err != nil {
		return err
	}
	logFile, err := logPath()
	if err != nil {
		return err
	}
	if err := notRunningElsewhere(pacURL); err != nil {
		return err
	}
	for _, d := range []string{filepath.Dir(unitPath), filepath.Dir(logFile)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(unitPath, []byte(agentUnit(bin, addr, logFile, s)), 0o644); err != nil {
		return err
	}
	if err := systemctlUser("daemon-reload"); err != nil {
		return err
	}
	if s.StartAtLogin {
		err = systemctlUser("enable", agentUnitName)
	} else {
		err = systemctlUser("disable", agentUnitName)
	}
	if err != nil {
		return err
	}
	// Restart so a changed binary path or address takes effect.
	if err := systemctlUser("restart", agentUnitName); err != nil {
		return fmt.Errorf("starting the background service: %w", err)
	}
	return waitForProxy(pacURL, logFile)
}

// startAgent starts the background service now (it must be installed).
func startAgent() error {
	if err := systemctlUser("start", agentUnitName); err != nil {
		return fmt.Errorf("starting the background service: %w (run `shoo setup` first)", err)
	}
	return nil
}

// loadAgent checks the background service is installed (systemd loads it
// by itself).
func loadAgent() error {
	if !agentInstalled() {
		return errors.New("shoo isn't set up yet: run `shoo setup`")
	}
	return nil
}

// stopAgent stops the background service until `shoo start` or next login.
func stopAgent() {
	exec.Command("systemctl", "--user", "stop", agentUnitName).Run()
}

// removeAgent stops the background service and deletes it.
func removeAgent() error {
	exec.Command("systemctl", "--user", "disable", "--now", agentUnitName).Run()
	p, err := agentUnitPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s", p)
	}
	exec.Command("systemctl", "--user", "daemon-reload").Run()
	return nil
}
