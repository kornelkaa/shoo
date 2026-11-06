// Package certs creates and uses the per-machine certificate authority.
//
// The proxy decrypts websites (to remove YouTube's ad data and hide ad boxes
// everywhere), so the CA signs certificates for most site names. Its private
// key never leaves this Mac and is readable only by the user. It can't sign
// for IP addresses or for the never-decrypt sites (banks, logins, Apple...):
// those are written into the certificate as excluded names, so even a stolen
// key can't impersonate them. It lasts two years; `shoo setup` replaces it
// before then.
//
// CAs made by older versions were limited to YouTube by a name constraint;
// Constrained detects those so setup can replace them.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// AllowedDomains are YouTube's page and API domains (and their subdomains),
// where YouTube's ad data is removed.
var AllowedDomains = []string{"youtube.com", "youtubei.googleapis.com"}

const (
	CertFile = "ca.pem"
	KeyFile  = "ca-key.pem"
)

const (
	// Lifetime is how long a new CA lasts.
	Lifetime = 2 * 365 * 24 * time.Hour
	// RenewBefore: setup replaces a CA that expires sooner than this.
	RenewBefore = 30 * 24 * time.Hour
	// stopBefore: the proxy stops decrypting this long before the CA
	// expires, so websites keep working (without ad hiding) instead of
	// showing certificate errors.
	stopBefore = 48 * time.Hour
	// maxLeaves caps the leaf certificate cache (a page can ask for any
	// number of made-up subdomains).
	maxLeaves = 4096
)

// Allowed reports whether host is YouTube or a subdomain of it.
func Allowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range AllowedDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Generate writes a new CA to dir. It can't sign for the excluded domains or
// their subdomains. The private key file is readable only by the current
// user. It refuses to overwrite an existing CA unless force is set.
func Generate(dir string, force bool, excluded []string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certPath, keyPath := filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)
	if !force {
		if _, err := os.Stat(certPath); err == nil {
			return fmt.Errorf("CA already exists at %s (use -force to replace it)", certPath)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: "shoo local CA (" + host + ")", Organization: []string{"shoo"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(Lifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
		ExcludedDNSDomains: cleanDomains(excluded),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}
	return writePEM(certPath, "CERTIFICATE", der, 0o644)
}

// cleanDomains lowercases, dedupes and sorts domains, dropping invalid ones.
func cleanDomains(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if ValidHost(d) && strings.Contains(d, ".") && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// excludedName reports whether cert's name constraints exclude host.
func excludedName(cert *x509.Certificate, host string) bool {
	for _, d := range cert.ExcludedDNSDomains {
		d = strings.ToLower(strings.TrimPrefix(d, "."))
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// ReplaceReason says why setup should replace cert with a new CA, or ""
// if it's fine. excluded are the never-decrypt sites a CA must exclude;
// allSites is whether shoo works on other websites (not just YouTube).
func ReplaceReason(cert *x509.Certificate, excluded []string, allSites bool) string {
	if time.Until(cert.NotAfter) < RenewBefore {
		return "it expires " + cert.NotAfter.Format("2006-01-02")
	}
	if Constrained(cert) {
		if allSites {
			return "it only works for YouTube"
		}
		return ""
	}
	for _, d := range cleanDomains(excluded) {
		if !excludedName(cert, d) {
			return "it can sign for never-decrypt sites like " + d
		}
	}
	return ""
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func randSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}

// Authority signs short-lived leaf certificates for the sites the proxy decrypts.
type Authority struct {
	Cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	leafKey *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// Load reads the CA from dir.
func Load(dir string) (*Authority, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		return nil, fmt.Errorf("reading CA (run `shoo init-ca` first): %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, KeyFile))
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("CA files are not valid PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("CA key is not ECDSA")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Authority{Cert: cert, key: key, leafKey: leafKey, cache: map[string]*tls.Certificate{}}, nil
}

// Constrained reports whether a CA is limited to YouTube (made by an older
// version of shoo).
func Constrained(cert *x509.Certificate) bool {
	return len(cert.PermittedDNSDomains) > 0
}

// ValidHost reports whether host is a site name the CA may sign for:
// not an IP address, and only letters, digits, '-', '_' and dots.
func ValidHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil || strings.HasPrefix(host, ".") || strings.Contains(host, "..") {
		return false
	}
	for _, c := range strings.ToLower(host) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// CanSign reports whether a certificate for host would be accepted: a valid
// site name the CA doesn't exclude, while the CA isn't about to expire.
func (a *Authority) CanSign(host string) bool {
	if !ValidHost(host) {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	now := time.Now()
	return !excludedName(a.Cert, host) && now.After(a.Cert.NotBefore) && a.Cert.NotAfter.Sub(now) > stopBefore
}

// LeafFor returns a certificate for host.
func (a *Authority) LeafFor(host string) (*tls.Certificate, error) {
	if !a.CanSign(host) {
		return nil, fmt.Errorf("refusing to sign for %q", host)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.cache[host]; ok && time.Until(c.Leaf.NotAfter) > 24*time.Hour {
		return c, nil
	}
	c, err := a.sign(host)
	if err != nil {
		return nil, err
	}
	if len(a.cache) >= maxLeaves {
		a.cache = map[string]*tls.Certificate{}
	}
	a.cache[host] = c
	return c, nil
}

// sign issues a leaf certificate for host.
func (a *Authority) sign(host string) (*tls.Certificate, error) {
	now := time.Now()
	notAfter := now.AddDate(0, 0, 30)
	if notAfter.After(a.Cert.NotAfter) {
		notAfter = a.Cert.NotAfter // never outlive the CA
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: a.leafKey, Leaf: leaf}, nil
}
