//go:build linux

package main

// Trusting shoo's certificate on Linux. There is no single trust store:
//
//   - the system store (curl, most apps, GNOME Web): root, one sudo prompt
//   - Chrome, Chromium and browsers built on them: ~/.pki/nssdb
//   - Firefox: each profile's own certificate database
//
// The browser databases belong to the user, so they need no password.

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"shoo/internal/certs"
)

// sysStore is a folder the distribution's update tool reads certificates
// from, and that tool.
type sysStore struct{ dir, update string }

var sysStores = []sysStore{
	{"/etc/pki/ca-trust/source/anchors", "update-ca-trust"},          // Fedora, RHEL
	{"/etc/ca-certificates/trust-source/anchors", "update-ca-trust"}, // Arch
	{"/etc/pki/trust/anchors", "update-ca-certificates"},             // openSUSE
	{"/usr/local/share/ca-certificates", "update-ca-certificates"},   // Debian, Ubuntu
}

const sysStoreFile = "shoo.crt"

// systemStore picks the store of this distribution: its folder's parent
// exists and its tool is installed.
func systemStore() (sysStore, bool) {
	for _, s := range sysStores {
		if _, err := exec.LookPath(s.update); err != nil {
			continue
		}
		if fi, err := os.Stat(filepath.Dir(s.dir)); err == nil && fi.IsDir() {
			return s, true
		}
	}
	return sysStore{}, false
}

// systemBundles are the files the update tools write, which programs read.
var systemBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Arch
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // Fedora, RHEL
	"/etc/ca-certificates/extracted/tls-ca-bundle.pem",  // Arch
	"/var/lib/ca-certificates/ca-bundle.pem",            // openSUSE
}

// systemTrusted reports whether a YouTube certificate signed by ca is
// accepted with the system's certificate bundle, the way curl and most
// apps check it. The bundle is read fresh (not cached like
// x509.SystemCertPool), so a change made a moment ago counts.
func systemTrusted(ca *certs.Authority) bool {
	leaf, err := ca.LeafFor("www.youtube.com")
	if err != nil {
		return false
	}
	c, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		return false
	}
	for _, f := range systemBundles {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(b)
		if _, err := c.Verify(x509.VerifyOptions{Roots: pool, DNSName: "www.youtube.com"}); err == nil {
			return true
		}
	}
	return false
}

// trustSystem (root) is `sudo shoo trust-system -data DIR`: it adds the
// certificate in DIR to the system store.
func trustSystem(dir string) error {
	if os.Geteuid() != 0 {
		return errors.New("needs admin rights: run `sudo shoo trust-system -data DIR`")
	}
	b, err := os.ReadFile(filepath.Join(dir, certs.CertFile))
	if err != nil {
		return err
	}
	// Only ever add a shoo CA: this file is in the user's folder, and the
	// system store is trusted by every account on this computer.
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("the certificate file is not a PEM certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if !c.IsCA || !slices.Equal(c.Subject.Organization, []string{"shoo"}) || c.CheckSignatureFrom(c) != nil {
		return errors.New("the certificate file is not shoo's certificate")
	}
	s, ok := systemStore()
	if !ok {
		return errors.New("can't find this system's certificate store (update-ca-certificates or update-ca-trust)")
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	if err := os.WriteFile(filepath.Join(s.dir, sysStoreFile), out, 0o644); err != nil {
		return err
	}
	return run(s.update)
}

// untrustSystem (root) is `sudo shoo untrust-system`.
func untrustSystem() error {
	if os.Geteuid() != 0 {
		return errors.New("needs admin rights: run `sudo shoo untrust-system`")
	}
	for _, s := range sysStores {
		p := filepath.Join(s.dir, sysStoreFile)
		if !fileExists(p) {
			continue
		}
		if err := os.Remove(p); err != nil {
			return err
		}
		if _, err := exec.LookPath(s.update); err == nil {
			if err := run(s.update); err != nil {
				return err
			}
		}
	}
	return nil
}

// systemStoreHasFile reports whether shoo's file is in a system store.
func systemStoreHasFile() bool {
	for _, s := range sysStores {
		if fileExists(filepath.Join(s.dir, sysStoreFile)) {
			return true
		}
	}
	return false
}

// nssDBs are the browser certificate databases to trust the certificate
// in: Chrome's and every Firefox profile's.
func nssDBs() (chrome, firefox []string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}
	return chromeDBs(home), firefoxProfiles(home)
}

func haveCertutil() bool {
	_, err := exec.LookPath("certutil")
	return err == nil
}

const certutilHint = "install certutil first: `sudo apt install libnss3-tools` (Debian, Ubuntu), " +
	"`sudo dnf install nss-tools` (Fedora), `sudo pacman -S nss` (Arch) or `sudo zypper install mozilla-nss-tools` (openSUSE)"

// nssHas reports whether db has exactly this certificate under nssNick.
func nssHas(db string, der []byte) bool {
	out, err := exec.Command("certutil", "-L", "-d", "sql:"+db, "-n", nssNick, "-a").Output()
	if err != nil {
		return false
	}
	block, _ := pem.Decode(out)
	return block != nil && bytes.Equal(block.Bytes, der)
}

// nssRemove deletes every certificate named nssNick from db.
func nssRemove(db string) {
	for i := 0; i < 10; i++ {
		if exec.Command("certutil", "-D", "-d", "sql:"+db, "-n", nssNick).Run() != nil {
			return
		}
	}
}

// nssAdd puts the certificate into db as trusted for websites, creating
// Chrome's database if it doesn't exist yet.
func nssAdd(db, certPath string) error {
	if !fileExists(filepath.Join(db, "cert9.db")) {
		if err := os.MkdirAll(db, 0o700); err != nil {
			return err
		}
		if out, err := exec.Command("certutil", "-N", "-d", "sql:"+db, "--empty-password").CombinedOutput(); err != nil {
			return fmt.Errorf("creating %s: %v: %s", db, err, strings.TrimSpace(string(out)))
		}
	}
	nssRemove(db)
	if out, err := exec.Command("certutil", "-A", "-d", "sql:"+db, "-n", nssNick, "-t", "C,,", "-i", certPath).CombinedOutput(); err != nil {
		return fmt.Errorf("adding to %s: %v: %s", db, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// trust adds the certificate to the browsers' databases (no password) and
// to the system store (sudo).
func trust(dir string) error {
	if os.Geteuid() == 0 {
		return errors.New("run `shoo trust` without sudo, so the certificate goes into your own browsers")
	}
	ca, err := certs.Load(dir)
	if err != nil {
		return err
	}
	certPath := filepath.Join(dir, certs.CertFile)
	if !haveCertutil() {
		return errors.New("Chrome and Firefox keep their own certificate lists; to add shoo's, " + certutilHint)
	}
	chrome, firefox := nssDBs()
	for _, db := range append(chrome, firefox...) {
		if nssHas(db, ca.Cert.Raw) {
			continue
		}
		if err := nssAdd(db, certPath); err != nil {
			return err
		}
	}
	if systemTrusted(ca) {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return sudoRun(exe, "trust-system", "-data", dir)
}

// untrust removes the certificate from the browsers and the system store.
func untrust(string) error {
	if haveCertutil() {
		chrome, firefox := nssDBs()
		for _, db := range append(chrome, firefox...) {
			if fileExists(filepath.Join(db, "cert9.db")) {
				nssRemove(db)
			}
		}
	}
	if !systemStoreHasFile() {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return sudoRun(exe, "untrust-system")
}

// isTrusted reports whether the system store and every browser database
// accept the certificate.
func isTrusted(dir string) (bool, error) {
	ca, err := certs.Load(dir)
	if err != nil {
		return false, err
	}
	if !systemTrusted(ca) || !haveCertutil() {
		return false, nil
	}
	chrome, firefox := nssDBs()
	for _, db := range append(chrome, firefox...) {
		if !nssHas(db, ca.Cert.Raw) {
			return false, nil
		}
	}
	return true, nil
}

// trustNotes are the details under "Certificate:" in `shoo status`.
func trustNotes(dir string) []string {
	ca, err := certs.Load(dir)
	if err != nil {
		return nil
	}
	yes := func(ok bool) string {
		if ok {
			return "trusted"
		}
		return "NOT trusted"
	}
	notes := []string{"system: " + yes(systemTrusted(ca))}
	if !haveCertutil() {
		return append(notes, "Chrome, Firefox: unknown; "+certutilHint)
	}
	home, _ := os.UserHomeDir()
	short := func(p string) string {
		if r, err := filepath.Rel(home, p); err == nil && !strings.HasPrefix(r, "..") {
			return "~/" + r
		}
		return p
	}
	chrome, firefox := nssDBs()
	for _, db := range chrome {
		notes = append(notes, "Chrome ("+short(db)+"): "+yes(nssHas(db, ca.Cert.Raw)))
	}
	for _, db := range firefox {
		notes = append(notes, "Firefox ("+short(db)+"): "+yes(nssHas(db, ca.Cert.Raw)))
	}
	if len(firefox) == 0 {
		notes = append(notes, "Firefox: no profile found (if you start Firefox for the first time later, run `shoo trust`)")
	}
	return notes
}
