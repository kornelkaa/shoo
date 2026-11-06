// Command ytblock removes ads in Safari on macOS. YouTube ads are removed by
// editing YouTube's responses in a local proxy (internal/proxy); ads on other
// sites are blocked by refusing known ad domains (internal/sites).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ytblock/internal/certs"
	"ytblock/internal/proxy"
	"ytblock/internal/prune"
	"ytblock/internal/sites"
	"ytblock/internal/ytskip"
)

const defaultAddr = "127.0.0.1:8899"

// version is set at build time: -ldflags "-X main.version=0.1.0".
var version = "dev"

const usage = `ytblock - block ads in Safari on macOS

Usage:
  ytblock setup                turn everything on (asks for your password twice)
  ytblock uninstall [-purge]   turn everything off (-purge: also delete settings and lists)
  ytblock status               show what's set up

  ytblock block DOMAIN         always block a domain on other websites
  ytblock allow DOMAIN         never block a domain (if a site breaks)
  ytblock update-lists [-level strict|balanced|max]
                               download ad-domain lists now (also refreshed weekly)
                               (strict = default; balanced if sites break; max = most blocking)
  ytblock version

Individual steps (setup does these for you):
  ytblock init-ca [-force]     create this Mac's YouTube-only certificate
  ytblock trust                trust the certificate (asks for your password)
  ytblock run [-sites=false]   start the proxy (-sites=false: YouTube only)
  sudo ytblock enable [-force] turn ytblock on in macOS network settings
  sudo ytblock disable         turn ytblock off in macOS network settings
  ytblock untrust              remove the certificate from the keychain

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
	sitesOn := fs.Bool("sites", true, "run: also block ad domains on other websites")
	level := fs.String("level", sites.DefaultLevel, "update-lists: strict, balanced or max")
	listURLs := fs.String("url", "", "update-lists: comma-separated list URLs (instead of -level)")
	purge := fs.Bool("purge", false, "uninstall: also delete settings, lists and the log")
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
	case "setup":
		err = setup(dir, *addr, pacURL)
	case "uninstall":
		err = uninstall(dir, *addr, pacURL, *purge)
	case "version", "-version", "--version":
		fmt.Println("ytblock", version)
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
	case "update-lists":
		urls, ok := sites.Levels[*level]
		if *listURLs != "" {
			urls, ok = strings.Split(*listURLs, ","), true
		}
		if !ok {
			log.Fatalf("unknown level %q: use strict, balanced or max", *level)
		}
		var n int
		n, err = sites.Update(context.Background(), dir, urls)
		if err == nil {
			fmt.Printf("Saved %d ad domains. A running proxy picks them up within a minute.\n", n)
		}
	case "block", "allow":
		err = addDomain(dir, cmd, fs.Arg(0))
	case "run":
		err = runProxy(dir, *addr, *sitesOn)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func addDomain(dir, cmd, arg string) error {
	d, err := sites.ValidateDomain(arg)
	if err != nil {
		return err
	}
	if sites.IsYouTube(d) {
		return fmt.Errorf("%s is part of YouTube, which is handled separately and never blocked", d)
	}
	file := sites.BlockFile
	if cmd == "allow" {
		file = sites.AllowFile
	}
	if err := sites.AddDomain(dir, file, d); err != nil {
		return err
	}
	fmt.Printf("Added %s to %s. A running proxy picks it up within a minute; reopen Safari if it doesn't.\n", d, file)
	return nil
}

func runProxy(dir, addr string, sitesOn bool) error {
	ca, err := certs.Load(dir)
	if err != nil {
		return err
	}
	logger := log.New(os.Stderr, "ytblock: ", log.LstdFlags)
	p := proxy.New(ca, prune.Default, logger)
	p.Addr = addr
	// Next to p: a backup script in YouTube pages that mutes and skips an ad
	// only if one still plays.
	p.Upstream = &ytskip.Transport{Next: p.Upstream, Log: logger}
	// YouTube is handled by p, unchanged. Ad-domain blocking for other sites
	// wraps it and only adds the combined PAC file and the refusals.
	var handler http.Handler = p
	if sitesOn {
		list, err := sites.Load(dir)
		if err != nil {
			return err
		}
		if list.Len() == 0 {
			logger.Printf("no ad-domain list yet: run `ytblock update-lists` (YouTube blocking works without it)")
		}
		h := sites.NewHandler(p, addr, list, logger)
		go h.Watch(dir, 30*time.Second)
		go sites.AutoUpdate(context.Background(), dir, 7*24*time.Hour, logger)
		handler = h
		logger.Printf("blocking %d ad domains on other websites", list.Len())
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          logger,
	}
	logger.Printf("ytblock %s listening on %s (PAC file: http://%s/proxy.pac)", version, addr, addr)
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
