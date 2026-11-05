package main

// `ytblock setup` and `ytblock uninstall`: everything needed to turn ytblock
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

	"ytblock/internal/certs"
	"ytblock/internal/sites"
)

const agentLabel = "com.kornelkaa.ytblock"

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
	return filepath.Join(home, "Library", "Logs", "ytblock.log"), nil
}

// stableBinary maps a versioned Homebrew path
// (/opt/homebrew/Cellar/ytblock/0.1.0/bin/ytblock) to the path that stays the
// same across `brew upgrade` (/opt/homebrew/opt/ytblock/bin/ytblock).
// Other paths are returned unchanged.
func stableBinary(exe string) string {
	const cellar = "/Cellar/ytblock/"
	i := strings.Index(exe, cellar)
	if i < 0 {
		return exe
	}
	rest := exe[i+len(cellar):] // "0.1.0/bin/ytblock"
	j := strings.IndexByte(rest, '/')
	if j < 0 {
		return exe
	}
	return exe[:i] + "/opt/ytblock" + rest[j:]
}

// agentPlist is the LaunchAgent that runs `ytblock run` at login and
// restarts it if it stops.
func agentPlist(bin, addr, logFile string) string {
	e := html.EscapeString
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
		<string>` + e(addr) + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
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

func step(n int, msg string) { fmt.Printf("\n[%d/5] %s\n", n, msg) }

// setup turns everything on. Safe to run again: finished steps are skipped,
// and the background service is refreshed.
func setup(dir, addr, pacURL string) error {
	if os.Geteuid() == 0 {
		return errors.New("run `ytblock setup` without sudo; it asks for your password when needed")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	bin := stableBinary(exe)

	step(1, "YouTube-only certificate")
	if _, err := os.Stat(filepath.Join(dir, certs.CertFile)); err == nil {
		fmt.Println("  already created")
	} else if err := certs.Generate(dir, false); err != nil {
		return err
	} else {
		fmt.Println("  created")
	}

	step(2, "Trust the certificate")
	if ok, _ := isTrusted(dir); ok {
		fmt.Println("  already trusted")
	} else {
		fmt.Println("  macOS will ask for your password")
		if err := trust(dir); err != nil {
			return fmt.Errorf("trusting the certificate: %w", err)
		}
		fmt.Println("  trusted")
	}

	step(3, "Ad-domain lists for other websites")
	if _, err := os.Stat(filepath.Join(dir, sites.BlocklistFile)); err == nil {
		fmt.Println("  already downloaded (refreshed automatically every week)")
	} else {
		fmt.Println("  downloading...")
		n, err := sites.Update(context.Background(), dir, sites.Levels[sites.DefaultLevel])
		if err != nil {
			// Not fatal: YouTube blocking works without the lists, and the
			// background service retries.
			fmt.Printf("  could not download (%v); the background service will retry\n", err)
		} else {
			fmt.Printf("  %d ad domains\n", n)
		}
	}

	step(4, "Background service (starts at login)")
	if err := installAgent(bin, addr, pacURL); err != nil {
		return err
	}

	step(5, "Send YouTube and ad domains through ytblock")
	fmt.Println("  changing network settings needs your password (sudo)")
	sudo := exec.Command("sudo", exe, "enable", "-addr", addr)
	sudo.Stdin, sudo.Stdout, sudo.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := sudo.Run(); err != nil {
		return fmt.Errorf("turning on the network setting: %w", err)
	}

	fmt.Println("\nDone. Quit Safari (⌘Q) and open it again.")
	fmt.Println()
	status(dir, addr, pacURL)
	return nil
}

func installAgent(bin, addr, pacURL string) error {
	plistPath, err := agentPlistPath()
	if err != nil {
		return err
	}
	logFile, err := logPath()
	if err != nil {
		return err
	}
	if !agentLoaded() && proxyAnswers(pacURL) {
		return errors.New("ytblock is already running in a Terminal window: stop it with Ctrl+C, then run `ytblock setup` again")
	}
	for _, d := range []string{filepath.Dir(plistPath), filepath.Dir(logFile)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(plistPath, []byte(agentPlist(bin, addr, logFile)), 0o644); err != nil {
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
		return errors.New("run `ytblock uninstall` without sudo; it asks for your password when needed")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var failed []string

	fmt.Println("Stopping the background service...")
	exec.Command("launchctl", "bootout", guiDomain()+"/"+agentLabel).Run()
	if p, err := agentPlistPath(); err == nil {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = append(failed, "remove "+p)
		}
	}

	fmt.Println("Turning off the network setting (needs your password)...")
	sudo := exec.Command("sudo", exe, "disable", "-addr", addr)
	sudo.Stdin, sudo.Stdout, sudo.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := sudo.Run(); err != nil {
		failed = append(failed, "network setting: run `sudo ytblock disable`")
	}

	fmt.Println("Removing the certificate from the keychain...")
	if _, err := os.Stat(filepath.Join(dir, certs.CertFile)); err == nil {
		if err := untrust(dir); err != nil {
			failed = append(failed, "certificate: run `ytblock untrust`")
		}
	}

	if purge {
		fmt.Println("Deleting ytblock's files...")
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
	fmt.Println("\nDone. ytblock is off. Quit Safari (⌘Q) and open it again.")
	if !purge {
		fmt.Printf("Your settings and lists are kept in %s (use -purge to delete them).\n", dir)
	}
	return nil
}
