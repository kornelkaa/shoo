# ytblock

Blocks ads in Safari on macOS.

- **YouTube:** a small local proxy removes the ad fields (`adPlacements`,
  `playerAds`, `adSlots`, `adBreakHeartbeatParams`) from YouTube's watch pages
  and API responses before Safari sees them.
- **Other websites:** connections to known ad and tracker domains are refused
  ([StevenBlack](https://github.com/StevenBlack/hosts) + [HaGeZi Pro](https://github.com/hagezi/dns-blocklists),
  ~280k domains). Nothing is decrypted for these sites.

The two parts are separate. YouTube always goes to the YouTube code, and YouTube
domains can never be blocked by the ad-domain list.

```
YouTube            → YouTube proxy (removes ad fields)   internal/proxy, prune, certs
known ad domain    → refused                              internal/sites
everything else    → direct, never touches ytblock
```

- Only YouTube and ad domains go through the proxy (via a PAC file). Everything else connects directly.
- The video stream (`*.googlevideo.com`) is never touched.
- The certificate is made on your Mac and macOS only accepts it for
  `youtube.com` and `youtubei.googleapis.com`, so it can't be used against other sites.
- If the proxy stops, Safari falls back to connecting directly: websites and YouTube keep
  working, YouTube with ads. Ad domains stay blocked.

## Install

With Homebrew (once the repo is public):

```sh
brew install kornelkaa/tap/ytblock
ytblock setup
```

From source:

```sh
go build -o ytblock ./cmd/ytblock
./ytblock setup
```

`setup` asks for your password twice (once to trust the certificate, once to change the
network setting), then:

1. creates this Mac's YouTube-only certificate and trusts it
2. downloads the ad-domain lists (refreshed automatically every week)
3. installs a background service that starts at login and restarts if it stops
4. points macOS at the PAC file

Then quit Safari (⌘Q) and open it again. Running `setup` again is safe.

## Everyday use

```sh
ytblock status                      # is everything on?
ytblock allow example.com           # a site broke: never block it
ytblock block ads.example.com       # block something extra
ytblock update-lists -level balanced   # fewer blocked domains if sites break (strict = default, max = most)
```

Blocking levels, scored on the
[d3ward ad-block test](https://d3ward.github.io/toolz/adblock) domains:

| Level | Lists | Domains | Test score |
|---|---|---|---|
| `balanced` | StevenBlack | ~78k | 77% |
| `strict` (default) | StevenBlack + HaGeZi Pro | ~280k | 98% |
| `max` | StevenBlack + HaGeZi Pro++ | ~290k | 98%, blocks more trackers the test doesn't check |

Log: `~/Library/Logs/ytblock.log` (`blocked <domain>` for other sites, `removed N ad fields` on YouTube).

Limits on other websites: empty ad boxes can remain, and ads served from a site's own
domain (Facebook, Instagram, Reddit sponsored posts) aren't blocked. Other Mac apps
that use the system proxy settings also get ad domains blocked.

## When an ad gets through

`ytblock-debug` runs exactly like `ytblock run` (same YouTube and other-site code,
unchanged) and also records what YouTube sends. Use it in place of the normal proxy
until an ad gets through:

```sh
go build -o ytblock-debug ./cmd/ytblock-debug
./ytblock-debug        # stop `ytblock run` first; Ctrl+C when done
```

Results go to `~/Library/Logs/ytblock-debug/<time>/events.log` and stay on your Mac.
`AD-EVENT` lines are the player reporting an ad; `LEAK?` lines are responses that still
contain ad data after ytblock's removal (saved in `responses/`).

## Uninstall

```sh
ytblock uninstall          # turns everything off; add -purge to also delete settings and lists
brew uninstall ytblock     # if installed with Homebrew
```

## Releasing

`scripts/release.sh 0.1.0` (from `main`, repo must be public) tags the release, creates it
on GitHub, and fills in `url` and `sha256` in `packaging/homebrew/ytblock.rb`. Copy that file
to `Formula/ytblock.rb` in the `kornelkaa/homebrew-tap` repo.

## Layout

YouTube (frozen; `scripts/check-youtube-untouched.sh` checks it matches `main`):
- `internal/prune` – which responses to edit and which keys to delete
- `internal/certs` – per-machine CA with a name constraint
- `internal/proxy` – CONNECT proxy; decrypts YouTube only

Next to the YouTube code:
- `internal/ytskip` – backup for ads that get past the removal: a script in YouTube pages that,
  only while an ad is playing, mutes it, jumps to its end and presses Skip (wraps `proxy.Proxy.Upstream`)

Other websites:
- `internal/sites` – ad-domain list, combined PAC file, refusing blocked domains

- `cmd/ytblock` – CLI, macOS integration (`security`, `networksetup`), `setup`/`uninstall` and the background service
- `packaging/homebrew` – Homebrew formula

## Next steps

- Signed rules file so YouTube rule fixes reach users without reinstalling
