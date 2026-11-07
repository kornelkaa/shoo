# shoo

Blocks ads in Safari on macOS and in browsers on Windows, and hides the empty boxes they
leave behind. A local proxy decrypts the websites you visit, on your computer, and cleans
them up before the browser shows them. Most of this README describes macOS; see
[Windows](#windows) for what differs there.

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
  (Google, Apple, Microsoft), banks and payments (incl. Hungarian banks), password managers,
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

## Windows

Windows support is new. In a normal PowerShell window (not as administrator):

```powershell
irm https://raw.githubusercontent.com/kornelkaa/shoo/main/install.ps1 | iex
```

This downloads the latest release, checks its SHA-256 checksum, puts `shoo.exe` in
`%ProgramFiles%\shoo` (only admins can change it there) and starts `shoo setup`. From source:

```powershell
go build -o shoo.exe ./cmd/shoo
./shoo setup
```

Blocking, the lists and everyday commands are the same as on macOS. It works with browsers
that follow the Windows proxy settings and certificate store: Edge and Chrome; Firefox
depends on its own proxy and certificate settings. What's different:

- **The certificate** goes in your own Windows certificate store, after a security warning.
  Its private key is in `%LOCALAPPDATA%\shoo` and only your account can read it. Windows
  enforces the excluded names too: a stolen key can't fake a never-decrypted site.
- **The proxy** is your own setting (Settings > Network & internet > Proxy), so it needs no
  admin rights. It runs as a hidden scheduled task (`shoo-` and your account's ID).
- **Several people on one PC** can each use shoo: everyone gets their own proxy (on a
  port from 18000 up, chosen by setup), certificate, lists and settings. They share the
  DNS service, which blocks a domain if anyone's lists block it, unless someone ran
  `shoo allow` for it (DNS can't tell who is asking).
  It keeps running until the last of them runs `shoo uninstall`.
- **DNS** runs as a Windows service, `shoo-dns`, under the low-privilege LocalService
  account. It can read shoo's lists but not the private key. Its copy of shoo, its log
  (`shoo-dns.log`) and your previous DNS settings are in `%ProgramFiles%\shoo`. Installing
  it asks for admin rights once.
- **DNS is set on real Ethernet and Wi-Fi adapters**, for IPv4 and IPv6. VPN and virtual
  machine adapters are left alone, so their private names keep working. An adapter added
  later isn't covered until you run `shoo setup` again; `shoo status` shows which are.
- **Never decrypted** also covers Windows and Microsoft services, app updates and game
  launchers (`internal/sites/exclusions_windows.txt`). These additions only apply on Windows.
- `shoo stop` lasts until `shoo start`, including across logins.
- Antivirus software that scans HTTPS may conflict with shoo. Apps that check for revoked
  certificates may refuse shoo's, and shoo then stops decrypting them.

Logs: `%LOCALAPPDATA%\shoo\shoo.log` (moved to `shoo.log.old` once it passes 10 MB).
`shoo uninstall` also removes `%ProgramFiles%\shoo` and its PATH entry, in the same admin
step as the DNS service, unless someone else on the PC still uses shoo.

## When an ad gets through

`shoo-debug` runs exactly like `shoo run` (same YouTube and other-site code,
unchanged) and also records what YouTube sends. Use it in place of the normal proxy
until an ad gets through:

```sh
go build -o shoo-debug ./cmd/shoo-debug
./shoo-debug        # stop `shoo run` first; Ctrl+C when done
```

Results go to `~/Library/Logs/shoo-debug/<time>/events.log` (on Windows,
`%LOCALAPPDATA%\shoo\shoo-debug\<time>\events.log`) and stay on your computer.
`AD-EVENT` lines are the player reporting an ad; `LEAK?` lines are responses that still
contain ad data after shoo's removal (saved in `responses/`).

## Uninstall

```sh
shoo uninstall    # turns everything off and removes shoo itself; add -purge to also delete settings and lists
```

The command is removed only if install.sh or install.ps1 put it in place (a copy you built
yourself stays), and only once nobody else on the computer has shoo set up.

## Releasing

`scripts/release.sh 0.5.2` (from `main`, everything committed) runs the tests, builds one
universal `shoo` for Apple Silicon and Intel and `shoo.exe` for 64-bit Windows, tags `v0.5.2`
and publishes `shoo-macos.tar.gz`, `shoo-windows-amd64.zip`, `shoo-windows-arm64.zip` and
their `.sha256` files as a GitHub release. `install.sh` and `install.ps1` always install the
latest release.

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
- `internal/local` – keeps shoo's servers reachable only from this computer (loopback addresses)
- `internal/winacl`, `internal/winnet` – Windows file permissions, network adapters and their DNS settings
- `cmd/shoo` – CLI and `setup`/`uninstall`. `macos*.go` hold the macOS integration (`security`,
  `networksetup`, launchd); `*_windows.go` the Windows one (certificate store, proxy setting,
  scheduled task, DNS service)
- `cmd/shoo-debug` – the proxy plus YouTube recording, for when an ad gets through
- `install.sh`, `install.ps1` – the installers; `scripts/release.sh` – publishes a release

## License

MIT, see [LICENSE](LICENSE).
