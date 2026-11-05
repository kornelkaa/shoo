package certs

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func newTestCA(t *testing.T) *Authority {
	t.Helper()
	dir := t.TempDir()
	if err := Generate(dir, false); err != nil {
		t.Fatal(err)
	}
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func verify(a *Authority, host string, leaf *x509.Certificate) error {
	pool := x509.NewCertPool()
	pool.AddCert(a.Cert)
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool})
	return err
}

func TestLeafVerifiesForYouTube(t *testing.T) {
	a := newTestCA(t)
	for _, h := range []string{"www.youtube.com", "youtube.com", "m.youtube.com", "youtubei.googleapis.com"} {
		c, err := a.LeafFor(h)
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		if err := verify(a, h, c.Leaf); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
}

func TestRefusesOtherHosts(t *testing.T) {
	a := newTestCA(t)
	for _, h := range []string{"example.com", "notyoutube.com", "youtube.com.evil.net", "accounts.google.com", "googleapis.com"} {
		if _, err := a.LeafFor(h); err == nil {
			t.Errorf("LeafFor(%q) should fail", h)
		}
	}
}

// Even if the code check were bypassed (e.g. a stolen key), the name
// constraint must make other sites' certificates fail verification.
func TestNameConstraintBlocksOtherSites(t *testing.T) {
	a := newTestCA(t)
	for _, h := range []string{"www.bank.com", "accounts.google.com"} {
		c, err := a.sign(h)
		if err != nil {
			t.Fatal(err)
		}
		if err := verify(a, h, c.Leaf); err == nil {
			t.Errorf("certificate for %s verified; name constraint not enforced", h)
		}
	}
}

func TestKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	if err := Generate(dir, false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, want 0600", fi.Mode().Perm())
	}
	if err := Generate(dir, false); err == nil {
		t.Error("second Generate without force should fail")
	}
}
