# shoo

Blocks ads in Safari on macOS, and hides the empty boxes they leave behind. A local proxy
decrypts the websites you visit, on your Mac, and cleans them up before Safari shows them.

- **Ad domains** ([StevenBlack](https://github.com/StevenBlack/hosts) +
  [HaGeZi Pro](https://github.com/hagezi/dns-blocklists), ~280k domains): the proxy answers
  their requests itself by closing the connection, so they never load and the page sees a
  network error, as with a browser ad blocker (ad-block testers count that as blocked).
- **Single ads and trackers** (URL rules from EasyList, EasyPrivacy, uBlock Origin's own
  lists and Hufilter, ~108k rules): one ad script, image or tracking pixel is blocked on a
  site that otherwise loads, e.g. `||example.com/ads/*$script,third-party` or
  `.facebook.com/tr/$image`. Rules can be limited to request types, third-party requests
  and pages (`$domain=`), with `@@` exceptions, `$important` and `$badfilter`. Pages
  themselves are never blocked, and neither is YouTube (it has its own code; only its
  ad host `ads.youtube.com` is blocked) or anything
  you `shoo allow`. Rules that need uBlock Origin's scripts or features (`$redirect`,
  `$removeparam`, `$csp`, ...) are skipped instead of half-applied.
- **Ad boxes:** every page gets two stylesheets (served by the proxy from
  `assets.shoo.internal`) built from the element-hiding rules of
  [EasyList](https://easylist.to), uBlock Origin's lists and
  [Hufilter](https://github.com/hufilter/hufilter) (~26k rules), e.g. `dictionary.com##[id^="dco"]`. The page's Content-Security-Policy is
  adjusted so the stylesheets are allowed.
- **YouTube:** the ad fields (`adPlacements`, `playerAds`, `adSlots`,
  `adBreakHeartbeatParams`) are removed from watch pages and API responses, and a backup
  script skips an ad that still plays.
- **DNS:** a small DNS server answers ad domains with 0.0.0.0, for apps that don't use the
  proxy and as a fallback if the proxy stops. Everything else goes to your network's DNS.

```
most websites          → proxy: decrypted, ad domains and ad URLs blocked, ad boxes hidden
YouTube                → proxy: same, plus ad fields removed
never-decrypted sites  → direct (banks, logins, payments, Apple services, video streams)
ad domains (any app)   → DNS answers 0.0.0.0
```

- **Never decrypted** (`internal/sites/exclusions.txt`): logins
  (Google, Apple, Microsoft), banks (worldwide) and payments, password managers,
  government sites, messaging, email and documents (Outlook, Google Docs/Drive), AWS sign-in,
  Apple services, YouTube's video stream. Add more with
  `shoo skip example.com`. If an app refuses shoo's certificate (some apps only trust their
  own), shoo stops decrypting that site automatically.
- **The certificate** is made on your Mac when you run setup, and its private key is
  readable only by your user. It works for most websites: anyone who stole that key
  file could impersonate them to this Mac. It can't sign for IP addresses or for the
  never-decrypted sites (they're written into the certificate as excluded names, which
  macOS enforces), so a stolen key can't fake your bank or password manager. It lasts two
  years; `shoo status` shows the date, and `shoo setup` replaces it in its last month (one
  password prompt). Two days before it expires the proxy stops decrypting, so websites keep
  working. (`shoo setup` also replaces certificates from older versions: YouTube-only ones,
  and ones without the excluded names.)
- If the proxy stops, Safari connects directly: websites keep working, with ad boxes, and
  ad domains stay blocked by DNS.

## Install

In Terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/kornelkaa/shoo/main/install.sh | sh
```

This downloads the latest release (one file for Apple Silicon and Intel Macs), checks its
SHA-256 checksum, puts `shoo` in `/usr/local/bin` owned by root (asks for your password; setup
later runs this file with sudo, so nothing running as you should be able to replace it) and
starts `shoo setup`. To read the script first: download [install.sh](install.sh), look at it, then run
`sh install.sh`. Run the same command again to update.

From source:

```sh
go build -o shoo ./cmd/shoo
./shoo setup
```

`setup` asks a few questions first (arrow keys + Enter):

- block ads on other websites: off, balanced, strict (default) or max
- start automatically at login (default yes; otherwise `shoo start` when you want it)
- a summary of the two password prompts, and whether to continue

Your answers are saved, so running `setup` again starts from them (`setup -yes` skips the
questions). Then it:

1. creates this Mac's certificate and trusts it (macOS password window)
2. downloads the ad-domain and element-hiding lists (refreshed automatically every week)
3. installs the background service
4. points macOS at the PAC file and, if blocking other websites, installs the DNS service
   and sets it as your DNS (sudo password in Terminal). Your previous DNS settings are
   saved and put back by `shoo uninstall`.

Then quit Safari (⌘Q) and open it again. Running `setup` again is safe.

## Everyday use

```sh
shoo status                      # is everything on?
shoo setup                       # change your choices
shoo start / shoo stop           # start or stop the background service
shoo allow example.com           # a site broke: never block it
shoo skip example.com            # a site or app broke: never decrypt it
shoo block ads.example.com       # block something extra
shoo update-lists -level balanced   # fewer blocked domains if sites break (strict = default, max = most)
```

Blocking levels, scored on the
[d3ward ad-block test](https://d3ward.github.io/toolz/adblock) domains:

| Level | Lists | Domains | Test score |
|---|---|---|---|
| `balanced` | StevenBlack | ~78k | 77% |
| `strict` (default) | StevenBlack + HaGeZi Pro | ~280k | 98% |
| `max` | StevenBlack + HaGeZi Pro++ | ~290k | 98%, blocks more trackers the test doesn't check |

Logs: `~/Library/Logs/shoo.log` (`removed N ad fields` on YouTube, list refreshes, errors) and
`/Library/Logs/shoo-dns.log`. Blocked domains aren't logged by name, so the logs don't become
a record of the sites you visit (`shoo status` shows the count; `shoo-debug` logs them).

Limits: ads served from a site's own domain (Facebook, Instagram, Reddit sponsored posts)
are only hidden where the lists have a rule for them. Rules that need scripts (uBlock's
scriptlets, `:has-text()` and other procedural filters) aren't supported, nor are URL rules
that redirect or rewrite requests. Never-decrypted sites aren't cleaned up. Apps
that use the system proxy settings also go through shoo. Browsers or apps with their own
encrypted DNS (and iCloud Private Relay) skip the DNS part.

## When an ad gets through

`shoo-debug` runs exactly like `shoo run` (same YouTube and other-site code,
unchanged) and also records what YouTube sends. Use it in place of the normal proxy
until an ad gets through:

```sh
go build -o shoo-debug ./cmd/shoo-debug
./shoo-debug        # stop `shoo run` first; Ctrl+C when done
```

Results go to `~/Library/Logs/shoo-debug/<time>/events.log` and stay on your Mac.
`AD-EVENT` lines are the player reporting an ad; `LEAK?` lines are responses that still
contain ad data after shoo's removal (saved in `responses/`).

## Uninstall

```sh
shoo uninstall                 # turns everything off; add -purge to also delete settings and lists
sudo rm /usr/local/bin/shoo    # removes the command itself
```

## Releasing

`scripts/release.sh 0.5.2` (from `main`, everything committed) runs the tests, builds one
universal `shoo` for Apple Silicon and Intel, tags `v0.5.2` and publishes `shoo-macos.tar.gz`
and its `.sha256` as a GitHub release. `install.sh` always installs the latest release.

## Layout

- `internal/proxy` – the proxy: decrypts sites (except the never-decrypt list), answers
  ad domains and ad URLs with a network error, links the hiding stylesheets into pages,
  removes YouTube ad data
- `internal/certs` – this Mac's certificate authority
- `internal/prune` – which YouTube responses to edit and which keys to delete
- `internal/ytskip` – backup for YouTube ads that get past the removal: a script in YouTube
  pages that, only while an ad is playing, mutes it, jumps to its end and presses Skip
- `internal/cosmetic` – element-hiding rules (EasyList syntax) → CSS, CSP patching, page
  injection; downloads the filter lists
- `internal/netfilter` – URL rules (EasyList syntax): parsing, an index for fast lookups,
  matching (shoo's own code, no uBlock Origin code)
- `internal/filterlist` – reads list files, skipping `!#if` blocks
- `internal/sites` – ad-domain list, never-decrypt list, PAC file
- `internal/dnsblock` – the DNS server: 0.0.0.0 for blocked domains, everything else passed on.
  Runs as a system service (`/Library/LaunchDaemons/com.kornelkaa.shoo.dns.plist`) from a
  root-owned copy of shoo in `/Library/Application Support/shoo`; it opens port 53 and then
  switches to your user
- `internal/local` – keeps shoo's servers reachable only from this Mac (loopback addresses)
- `cmd/shoo` – CLI, macOS integration (`security`, `networksetup`), `setup`/`uninstall` and the background service
- `cmd/shoo-debug` – the proxy plus YouTube recording, for when an ad gets through
- `install.sh` – the curl installer; `scripts/release.sh` – publishes a release

## License

shoo is free software under the [GNU GPL v3](LICENSE), with the additional terms in
[NOTICE](NOTICE). In short:

- You can use, study, change and share shoo.
- If you share a changed version, you must publish its source under the same license.
- You must keep the credit: "Based on shoo by kornelkaa".
- A fork must use its own name. The name "shoo" and its logo are not licensed for
  other projects.

Versions released before this change remain available under the MIT license.
