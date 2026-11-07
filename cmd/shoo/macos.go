//go:build !windows

package main

// macOS system integration: Keychain trust and network proxy settings.

import (
	"crypto/sha1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"shoo/internal/certs"
)

func loginKeychain() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db"), nil
}

// trust adds the CA to the user's login keychain as a trusted root.
// macOS shows a password prompt. Safari and Chrome read this trust setting.
func trust(dir string) error {
	if os.Geteuid() == 0 {
		return errors.New("run `shoo trust` without sudo, so the certificate goes into your own keychain")
	}
	kc, err := loginKeychain()
	if err != nil {
		return err
	}
	return run("security", "add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", kc, filepath.Join(dir, certs.CertFile))
}

// untrust removes the trust setting and the certificate from the keychain.
func untrust(dir string) error {
	certPath := filepath.Join(dir, certs.CertFile)
	b, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return errors.New("certificate file is not valid PEM")
	}
	kc, err := loginKeychain()
	if err != nil {
		return err
	}
	// Ignore "not found" errors: the goal is just that it's gone.
	_ = run("security", "remove-trusted-cert", certPath)
	_ = run("security", "delete-certificate", "-Z", fmt.Sprintf("%X", sha1.Sum(block.Bytes)), kc)
	return nil
}

// isTrusted asks macOS (the same check Safari uses) whether a YouTube
// certificate signed by our CA would be accepted.
func isTrusted(dir string) (bool, error) {
	ca, err := certs.Load(dir)
	if err != nil {
		return false, err
	}
	leaf, err := ca.LeafFor("www.youtube.com")
	if err != nil {
		return false, err
	}
	f, err := os.CreateTemp("", "shoo-leaf-*.pem")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	f.Close()
	// The exit code is the answer; macOS prints Certificate Transparency
	// notes even on success, so the output can't be used.
	err = exec.Command("security", "verify-cert", "-c", f.Name(), "-p", "ssl", "-s", "www.youtube.com", "-q").Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return err == nil, err
}

// networkServices lists enabled network services (Wi-Fi, Ethernet, ...).
func networkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	var svcs []string
	for i, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		l = strings.TrimSpace(l)
		if i == 0 || l == "" || strings.HasPrefix(l, "*") { // header line; "*" = disabled
			continue
		}
		svcs = append(svcs, l)
	}
	return svcs, nil
}

func autoProxy(svc string) (url string, enabled bool) {
	out, _ := exec.Command("networksetup", "-getautoproxyurl", svc).Output()
	for _, l := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(l, "URL: "); ok {
			url = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(l, "Enabled: "); ok {
			enabled = strings.TrimSpace(v) == "Yes"
		}
	}
	return url, enabled
}

// enable points every network service at our PAC file. It won't replace a
// different PAC file the user already has, unless force is set.
func enable(pacURL string, force bool) error {
	if os.Geteuid() != 0 {
		return errors.New("changing network settings needs admin rights: run `sudo shoo enable`")
	}
	svcs, err := networkServices()
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		if cur, on := autoProxy(svc); on && !isShooPAC(cur) && !force {
			fmt.Printf("  %-24s skipped: already uses %s (use -force to replace)\n", svc, cur)
			continue
		}
		if err := run("networksetup", "-setautoproxyurl", svc, pacURL); err != nil {
			return fmt.Errorf("%s: %w", svc, err)
		}
		if err := run("networksetup", "-setautoproxystate", svc, "on"); err != nil {
			return fmt.Errorf("%s: %w", svc, err)
		}
		fmt.Printf("  %-24s on\n", svc)
	}
	return nil
}

// disable turns the PAC setting off, only where it's ours.
func disable(pacURL string) error {
	if os.Geteuid() != 0 {
		return errors.New("changing network settings needs admin rights: run `sudo shoo disable`")
	}
	svcs, err := networkServices()
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		if cur, on := autoProxy(svc); on && isShooPAC(cur) {
			if err := run("networksetup", "-setautoproxystate", svc, "off"); err != nil {
				return fmt.Errorf("%s: %w", svc, err)
			}
			fmt.Printf("  %-24s off\n", svc)
		}
	}
	return nil
}

// What the shared code says on this system.
const (
	osName       = "macOS"
	computerName = "Mac"
	reopenHint   = "Quit Safari (⌘Q) and open it again."
	reopenBrief  = "reopen Safari if it doesn't"
	notAdminHint = "without sudo; it asks for your password when needed"
	trustPrompt  = "macOS will ask for your password"
	stopNote     = "shoo is stopped until `shoo start` (or your next login, if it starts at login).\nMeanwhile YouTube shows ads. Ad domains on other sites stay blocked (DNS keeps running)."
	certStore    = "keychain"
)

// usageSteps is the part of the help that names system-specific commands.
const usageSteps = `  sudo shoo enable [-force] [-dns -data DIR]
                            turn shoo on in macOS network settings
                               (-dns: also install the ad-blocking DNS service
                               for the shoo folder DIR and use it as DNS)
  sudo shoo disable         turn shoo off in macOS network settings (also DNS)
  sudo shoo disable-dns     only remove the DNS service and restore DNS
`

// run runs a system tool, showing its output.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// isAdmin reports whether shoo is running with admin rights.
func isAdmin() bool { return os.Geteuid() == 0 }

// dataBase is the folder shoo's own folder goes in: ~/Library/Application Support.
func dataBase() (string, error) { return os.UserConfigDir() }

// attachConsole is only needed on Windows, where the admin step can't share
// the terminal by itself.
func attachConsole(int) {}

// cmdEnable is `shoo enable`, which needs sudo here.
func cmdEnable(dir, pacURL string, force, dnsOn bool) error {
	if err := enable(pacURL, force); err != nil || !dnsOn {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return enableDNS(exe, dir)
}

// cmdDisable is `shoo disable`, which needs sudo here.
func cmdDisable(dir, pacURL string) error {
	err := disable(pacURL)
	if dnsErr := disableDNS(dir); err == nil {
		err = dnsErr
	}
	return err
}

// applyNetwork makes the changes setup found were needed.
func applyNetwork(exe, dir, addr, pacURL string, wantDNS, dnsOn, dnsOff bool) error {
	fmt.Println("  changing network settings needs your password (sudo)")
	if !ownedByRoot(exe) {
		fmt.Printf("  note: %s can be changed without a password; installing with install.sh\n"+
			"  makes it admin-owned, so nothing can swap it before it runs with sudo\n", exe)
	}
	args := []string{exe, "enable", "-addr", addr}
	if wantDNS {
		args = append(args, "-dns", "-data", dir)
	}
	if err := sudoRun(args...); err != nil {
		return fmt.Errorf("turning on the network settings: %w", err)
	}
	if dnsOff {
		if err := sudoRun(exe, "disable-dns"); err != nil {
			return fmt.Errorf("removing the DNS service: %w", err)
		}
	}
	return nil
}

// turnOffNetwork is uninstall's network step.
func turnOffNetwork(exe, dir, addr, pacURL string) error {
	if err := sudoRun(exe, "disable", "-addr", addr); err != nil {
		return errors.New("run `sudo shoo disable`")
	}
	// sudo remembers the password for a few minutes: this doesn't ask again.
	if err := sudoRun(exe, "remove-program", "-data", dir); err != nil {
		return fmt.Errorf("removing %s: %w", exe, err)
	}
	return nil
}

// removeProgram (root) deletes the shoo command install.sh put in place,
// unless someone else on this Mac has shoo set up. A copy that isn't
// root-owned (built from source) or belongs to Homebrew is left alone.
func removeProgram(dir string, _ bool, _ int) error {
	if os.Geteuid() != 0 {
		return errors.New("needs admin rights: run `shoo uninstall`")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if filepath.Base(exe) != "shoo" || strings.Contains(exe, "/Cellar/") || !ownedByRoot(exe) {
		fmt.Printf("  %s wasn't installed by install.sh: left in place\n", exe)
		return nil
	}
	homes, _ := filepath.Glob("/Users/*/Library/Application Support/shoo/" + certs.CertFile)
	for _, ca := range homes {
		if filepath.Clean(filepath.Dir(ca)) != filepath.Clean(dir) {
			fmt.Println("  shoo stays installed: other people on this Mac use it")
			return nil
		}
	}
	if err := os.Remove(exe); err != nil {
		return err
	}
	fmt.Printf("  removed %s\n", exe)
	return nil
}

// networkStatus is the last part of `shoo status`.
func networkStatus(pacURL string, showDNS bool) {
	fmt.Println("Network services:")
	svcs, _ := networkServices()
	for _, svc := range svcs {
		cur, on := autoProxy(svc)
		line := pacLine(cur, on, pacURL)
		if usesShooDNS(svc) {
			line += ", DNS shoo"
		} else if showDNS {
			line += ", DNS not shoo"
		}
		fmt.Printf("  %-24s %s\n", svc, line)
	}
}

// permissionsText is what setup says it will ask for.
func permissionsText(trusted bool) string {
	certLine := "• macOS asks for your password once, to trust shoo's certificate.\n" +
		"  With it shoo decrypts websites on this Mac to remove ads and hide ad\n" +
		"  boxes. Banks, logins, payments and Apple services are never\n" +
		"  decrypted, and the certificate can't be used for them. The key\n" +
		"  never leaves your Mac."
	if trusted {
		certLine = "• The certificate is already trusted: no password needed for it\n" +
			"  (unless it's old or expires soon: then it's replaced, which asks once)."
	}
	return certLine + "\n" +
		"• Terminal asks for your password (sudo) once, to point macOS's network\n" +
		"  settings at shoo: websites go through its proxy, and (if blocking other\n" +
		"  websites) its DNS service answers ad domains with a dead address.\n" +
		"• Running in the background needs no password."
}

// chooseAddr is the proxy address setup saves. macOS's proxy setting is the
// same for everyone on the Mac, so there is one proxy, at the usual address.
func chooseAddr() (string, error) { return defaultAddr, nil }
