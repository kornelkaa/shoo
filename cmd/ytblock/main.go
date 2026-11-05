// Command ytblock removes YouTube ads in Safari (and other browsers that use
// the macOS proxy settings) by editing YouTube's responses in a local proxy.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"ytblock/internal/certs"
	"ytblock/internal/proxy"
	"ytblock/internal/prune"
)

const defaultAddr = "127.0.0.1:8899"

const usage = `ytblock - block YouTube ads in Safari on macOS

Usage:
  ytblock init-ca [-force]     create this Mac's YouTube-only certificate
  ytblock trust                trust the certificate (asks for your password)
  ytblock run                  start the proxy
  sudo ytblock enable [-force] send YouTube traffic through the proxy
  sudo ytblock disable         stop sending YouTube traffic through the proxy
  ytblock untrust              remove the certificate from the keychain
  ytblock status               show what's set up

All commands accept -addr (default ` + defaultAddr + `).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	addr := fs.String("addr", defaultAddr, "proxy listen address (loopback only)")
	force := fs.Bool("force", false, "init-ca: replace existing CA; enable: replace another PAC setting")
	fs.Parse(os.Args[2:])
	if err := requireLoopback(*addr); err != nil {
		log.Fatal(err)
	}
	pacURL := "http://" + *addr + "/proxy.pac"

	dir, err := dataDir()
	if err != nil {
		log.Fatal(err)
	}

	switch cmd {
	case "init-ca":
		err = certs.Generate(dir, *force)
		if err == nil {
			fmt.Printf("Created %s\nNext: ytblock trust\n", filepath.Join(dir, certs.CertFile))
		}
	case "trust":
		err = trust(dir)
		if err == nil {
			fmt.Println("Certificate trusted.")
		}
	case "untrust":
		err = untrust(dir)
		if err == nil {
			fmt.Println("Certificate removed from keychain.")
		}
	case "enable":
		err = enable(pacURL, *force)
	case "disable":
		err = disable(pacURL)
	case "status":
		status(dir, *addr, pacURL)
	case "run":
		err = runProxy(dir, *addr)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func runProxy(dir, addr string) error {
	ca, err := certs.Load(dir)
	if err != nil {
		return err
	}
	logger := log.New(os.Stderr, "ytblock: ", log.LstdFlags)
	p := proxy.New(ca, prune.Default, logger)
	p.Addr = addr
	srv := &http.Server{
		Addr:              addr,
		Handler:           p,
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          logger,
	}
	logger.Printf("listening on %s (PAC file: http://%s/proxy.pac)", addr, addr)
	return srv.ListenAndServe()
}

// dataDir is ~/Library/Application Support/ytblock. Under sudo it is only used
// by commands that don't need it (enable/disable).
func dataDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "ytblock"), nil
}

func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing to use %s: only loopback IP addresses like 127.0.0.1 are allowed", addr)
	}
	return nil
}
