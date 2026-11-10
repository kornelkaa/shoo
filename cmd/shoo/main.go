// Command shoo removes ads in Safari on macOS and in browsers on Linux. A
// local proxy (internal/proxy) decrypts websites, removes YouTube's ad data,
// answers requests to ad domains itself, and hides the boxes ads leave
// behind with EasyList's element-hiding rules (internal/cosmetic). A local
// DNS server (internal/dnsblock) also blocks ad domains for everything that
// doesn't go through the proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"shoo/internal/certs"
	"shoo/internal/cosmetic"
	"shoo/internal/local"
	"shoo/internal/netfilter"
	"shoo/internal/proxy"
	"shoo/internal/prune"
	"shoo/internal/sites"
	"shoo/internal/stats"
	"shoo/internal/ytskip"
)

const defaultAddr = "127.0.0.1:8899"

// pacVersion is part of the PAC file's address. macOS keeps using a PAC
// file it already downloaded until its address changes, so this goes up
// whenever the PAC file's routing changes (2: every site through the proxy).
const pacVersion = "2"

// version is set at build time: -ldflags "-X main.version=0.1.0".
var version = "dev"

var usage = `shoo - block ads on ` + osName + `

Usage:
  shoo setup [-yes]         set up shoo: asks a few questions, then your password
                               (-yes: no questions, use the saved or default choices)
  shoo uninstall [-purge]   turn everything off (-purge: also delete settings and lists)
  shoo status               show what's set up
  shoo stats                charts of what was blocked (today, 24 hours, 30 days)
  shoo start / stop         start or stop the background service

  shoo block DOMAIN         always block a domain on other websites
  shoo allow DOMAIN         never block a domain (if a site breaks)
  shoo skip DOMAIN          never decrypt a site: no ad hiding there, nothing
                               changed (if a site or app breaks)
  shoo update-lists [-level strict|balanced|max]
                               download ad-domain lists now (also refreshed weekly)
                               (strict = default; balanced if sites break; max = most blocking)
  shoo version

Individual steps (setup does these for you):
  shoo init-ca [-force]     create this ` + computerName + `'s certificate
  shoo trust                trust the certificate (asks for your password)
  shoo run [-sites=false]   start the proxy (-sites=false: YouTube only)
` + usageSteps + `  shoo untrust              remove the certificate from the ` + certStore + `

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
	yes := fs.Bool("yes", false, "setup: don't ask questions")
	dnsOn := fs.Bool("dns", false, "enable: also turn on the ad-blocking DNS service")
	dataFlag := fs.String("data", "", "enable -dns, dns: shoo's data folder")
	fs.Parse(os.Args[2:])
	if err := local.RequireLoopback(*addr); err != nil {
		log.Fatal(err)
	}
	pacURL := "http://" + *addr + "/proxy.pac?v=" + pacVersion

	// The DNS system service runs without $HOME, so -data comes first.
	dir := *dataFlag
	var err error
	if dir == "" {
		if dir, err = dataDir(); err != nil {
			log.Fatal(err)
		}
	}

	switch cmd {
	case "setup":
		err = setup(dir, *addr, pacURL, *yes)
	case "start":
		if err = loadAgent(); err == nil {
			if !proxyAnswers(pacURL) {
				err = startAgent()
			}
			if err == nil {
				fmt.Println("shoo is running.")
			}
		}
	case "stop":
		stopAgent()
		fmt.Println(stopNote)
	case "uninstall":
		err = uninstall(dir, *addr, pacURL, *purge)
	case "version", "-version", "--version":
		fmt.Println("shoo", version)
	case "init-ca":
		err = certs.Generate(dir, *force, neverDecrypt(dir))
		if err == nil {
			fmt.Printf("Created %s\nNext: shoo trust\n", filepath.Join(dir, certs.CertFile))
		}
	case "trust":
		err = trust(dir)
		if err == nil {
			fmt.Println("Certificate trusted.")
		}
	case "untrust":
		err = untrust(dir)
		if err == nil {
			fmt.Println("Certificate removed from the " + certStore + ".")
		}
	case "enable":
		err = cmdEnable(dir, pacURL, *force, *dnsOn)
	case "disable":
		err = cmdDisable(dir, pacURL)
	case "disable-dns":
		err = disableDNS()
	case "dns":
		err = runDNS(dir)
	case "status":
		status(dir, *addr, pacURL)
	case "stats":
		err = showStats(dir, *addr)
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
			fmt.Printf("Saved %d ad domains.\n", n)
			n, err = cosmetic.Update(context.Background(), dir)
		}
		if err == nil {
			nr, _ := netfilter.Load(dir, cosmetic.ListFile)
			fmt.Printf("Saved %d element-hiding rules and %d URL rules. A running proxy picks them up within a minute.\n", n, nr.Len())
		}
	case "block", "allow", "skip":
		err = addDomain(dir, cmd, fs.Arg(0))
	case "run":
		err = runProxy(dir, *addr, *sitesOn)
	default:
		var ok bool
		if ok, err = platformCommand(cmd, dir); !ok {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
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
	switch cmd {
	case "allow":
		file = sites.AllowFile
	case "skip":
		file = sites.SkipFile
	}
	if err := sites.AddDomain(dir, file, d); err != nil {
		return err
	}
	fmt.Printf("Added %s to %s. A running proxy picks it up within a minute; %s.\n", d, file, reopenBrief)
	return nil
}

func runProxy(dir, addr string, sitesOn bool) error {
	ca, err := certs.Load(dir)
	if err != nil {
		return err
	}
	logger := log.New(os.Stderr, "shoo: ", log.LstdFlags)
	p := proxy.New(ca, prune.Default, logger)
	p.Addr = addr
	// A backup script in YouTube pages that mutes and skips an ad only if
	// one still plays.
	p.Upstream = &ytskip.Transport{Next: p.Upstream, Log: logger}
	rec := stats.Open(filepath.Join(dir, stats.ProxyFile), logger)
	go rec.Run(30 * time.Second)
	saveOnExit(rec)
	p.Pruned = func() { rec.Add(stats.YouTube, "") }
	// Without -sites only YouTube is decrypted (and only YouTube goes
	// through the proxy, see proxy.PAC).
	var handler http.Handler = p
	if sitesOn {
		if certs.Constrained(ca.Cert) {
			logger.Printf("the certificate only works for YouTube: run `shoo setup` to block ads and hide ad boxes on other websites")
		} else if r := certs.ReplaceReason(ca.Cert, sites.Exclusions(), true); r != "" {
			logger.Printf("the certificate should be replaced (%s): run `shoo setup`", r)
		}
		list, err := sites.Load(dir)
		if err != nil {
			return err
		}
		if list.Len() == 0 {
			logger.Printf("no ad-domain list yet: run `shoo update-lists` (YouTube blocking works without it)")
		}
		rules, err := cosmetic.Load(dir)
		if err != nil {
			return err
		}
		netRules, err := netfilter.Load(dir, cosmetic.ListFile)
		if err != nil {
			return err
		}
		h := sites.NewHandler(p, addr, list, logger)
		h.Stats = rec
		urlRules := netfilter.NewEngine(netRules)
		if !certs.Constrained(ca.Cert) {
			p.Decrypt = h.Decrypt
			p.Cosmetic = cosmetic.NewEngine(rules)
			p.Filter = func(r *http.Request, scheme, host string) bool {
				if h.Exempt(hostOnly(host)) {
					return false
				}
				req := netfilter.FromHTTP(r, scheme, host)
				if urlRules.Match(req) == "" {
					return false
				}
				h.CountBlocked(urlKind(req.Type), req.Host)
				return true
			}
		}
		p.Blocked = h.Blocked
		go h.Watch(dir, 30*time.Second)
		go sites.AutoUpdate(context.Background(), dir, 7*24*time.Hour, logger)
		if p.Cosmetic != nil {
			// The filter lists file has both kinds of rules.
			reload := func(r *cosmetic.Rules) {
				p.Cosmetic.SetRules(r)
				if nr, err := netfilter.Load(dir, cosmetic.ListFile); err != nil {
					logger.Printf("loading URL rules: %v", err)
				} else {
					urlRules.SetRules(nr)
				}
				logger.Printf("filter lists loaded: %d element-hiding rules, %d URL rules", r.Len(), urlRules.Rules().Len())
			}
			go watchFile(filepath.Join(dir, cosmetic.ListFile), 30*time.Second, func() {
				if r, err := cosmetic.Load(dir); err == nil {
					reload(r)
				}
			})
			go cosmetic.AutoUpdate(context.Background(), dir, 7*24*time.Hour, logger, reload)
		}
		handler = h
		logger.Printf("blocking %d ad domains and %d URL rules, hiding ad boxes with %d rules", list.Len(), urlRules.Rules().Len(), rules.Len())
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          logger,
	}
	logger.Printf("shoo %s listening on %s (PAC file: http://%s/proxy.pac)", version, addr, addr)
	return srv.ListenAndServe()
}

// urlKind is the stats kind of a request blocked by URL.
func urlKind(typ string) string {
	switch typ {
	case "script":
		return stats.Script
	case "image", "ping":
		return stats.Image
	}
	return stats.Other
}

// saveOnExit saves the stats when the process is stopped (launchd and
// systemd send SIGTERM), then exits.
func saveOnExit(rec *stats.Recorder) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		rec.Save()
		os.Exit(0)
	}()
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// neverDecrypt is the built-in never-decrypt list plus the user's own
// (`shoo skip`). A new CA can't sign for any of them.
func neverDecrypt(dir string) []string {
	if l, err := sites.Load(dir); err == nil {
		return l.SkipDomains()
	}
	return sites.Exclusions()
}

// watchFile calls changed when the file at path changes.
func watchFile(path string, every time.Duration, changed func()) {
	state := func() string {
		fi, err := os.Stat(path)
		if err != nil {
			return "-"
		}
		return fmt.Sprint(fi.ModTime().UnixNano(), fi.Size())
	}
	last := state()
	for range time.Tick(every) {
		if cur := state(); cur != last {
			last = cur
			changed()
		}
	}
}

// dataDir is ~/Library/Application Support/shoo (macOS) or ~/.config/shoo (Linux). Under sudo it is only used
// by commands that don't need it (enable/disable).
func dataDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "shoo")
	// shoo used to be called ytblock: move its settings, lists and
	// certificate over, so the trusted certificate keeps working.
	old := filepath.Join(base, "ytblock")
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(old); err == nil {
			if err := os.Rename(old, dir); err != nil {
				return "", fmt.Errorf("moving %s to %s: %w", old, dir, err)
			}
		}
	}
	return dir, nil
}
