package certs

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var testExcluded = []string{"bank.example", "PayPal.com.", "bad name"}

func newTestCA(t *testing.T) *Authority {
	t.Helper()
	dir := t.TempDir()
	if err := Generate(dir, false, testExcluded); err != nil {
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

func TestLeafForAnySite(t *testing.T) {
	a := newTestCA(t)
	if Constrained(a.Cert) {
		t.Error("new CA should not be limited to YouTube")
	}
	for _, h := range []string{"www.dictionary.com", "example.com", "a-b_c.example.org"} {
		c, err := a.LeafFor(h)
		if err != nil {
			t.Fatalf("%s: %v", h, err)
		}
		if err := verify(a, h, c.Leaf); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
}

func TestRefusesIPsAndBadNames(t *testing.T) {
	a := newTestCA(t)
	for _, h := range []string{"", "1.2.3.4", "::1", "a..b", "bad name.com", "x/y.com"} {
		if _, err := a.LeafFor(h); err == nil {
			t.Errorf("LeafFor(%q) should fail", h)
		}
	}
}

func TestKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	if err := Generate(dir, false, testExcluded); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, want 0600", fi.Mode().Perm())
	}
	if err := Generate(dir, false, testExcluded); err == nil {
		t.Error("second Generate without force should fail")
	}
}

func TestExcludedSites(t *testing.T) {
	a := newTestCA(t)
	if got := a.Cert.ExcludedDNSDomains; len(got) != 2 || got[0] != "bank.example" || got[1] != "paypal.com" {
		t.Fatalf("excluded = %v", got)
	}
	for _, h := range []string{"bank.example", "www.bank.example", "PAYPAL.com", "x.paypal.com."} {
		if a.CanSign(h) {
			t.Errorf("CanSign(%q) = true", h)
		}
		if _, err := a.LeafFor(h); err == nil {
			t.Errorf("LeafFor(%q) should fail", h)
		}
	}
	for _, h := range []string{"notbank.example", "paypal.com.evil.example", "example.com"} {
		if !a.CanSign(h) {
			t.Errorf("CanSign(%q) = false", h)
		}
	}
	// Even a certificate signed with the key directly (as a thief would)
	// is refused for an excluded site.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		DNSNames:     []string{"www.paypal.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	if err := verify(a, "www.paypal.com", leaf); err == nil {
		t.Error("forged certificate for an excluded site verified")
	}
}

func TestLifetime(t *testing.T) {
	a := newTestCA(t)
	if d := time.Until(a.Cert.NotAfter); d > Lifetime || d < Lifetime-2*time.Hour {
		t.Errorf("CA lasts %v", d)
	}
	c, err := a.LeafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.Leaf.NotAfter.After(a.Cert.NotAfter) {
		t.Error("leaf outlives the CA")
	}
	// Close to expiry the proxy stops decrypting rather than break sites.
	a.Cert.NotAfter = time.Now().Add(time.Hour)
	if a.CanSign("example.com") {
		t.Error("CanSign near CA expiry")
	}
}

func TestReplaceReason(t *testing.T) {
	a := newTestCA(t)
	if r := ReplaceReason(a.Cert, testExcluded, true); r != "" {
		t.Errorf("new CA: %q", r)
	}
	if r := ReplaceReason(a.Cert, append(testExcluded, "newbank.example"), true); r == "" {
		t.Error("CA missing a new exclusion should be replaced")
	}
	old := *a.Cert
	old.ExcludedDNSDomains = nil
	if ReplaceReason(&old, testExcluded, true) == "" {
		t.Error("CA without exclusions should be replaced")
	}
	yt := *a.Cert
	yt.ExcludedDNSDomains, yt.PermittedDNSDomains = nil, []string{"youtube.com"}
	if ReplaceReason(&yt, testExcluded, false) != "" || ReplaceReason(&yt, testExcluded, true) == "" {
		t.Error("YouTube-only CA: keep for YouTube-only use, replace otherwise")
	}
	soon := *a.Cert
	soon.NotAfter = time.Now().Add(10 * 24 * time.Hour)
	if ReplaceReason(&soon, testExcluded, true) == "" {
		t.Error("expiring CA should be replaced")
	}
}

func TestLeafCacheCapped(t *testing.T) {
	a := newTestCA(t)
	for i := 0; i < maxLeaves+5; i++ {
		if _, err := a.LeafFor(fmt.Sprintf("x%d.example.com", i)); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.cache) > maxLeaves {
		t.Errorf("cache holds %d", len(a.cache))
	}
}
