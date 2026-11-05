# ytblock

Blocks ads in Safari on macOS.

- **YouTube:** a small local proxy removes the ad fields (`adPlacements`,
  `playerAds`, `adSlots`, `adBreakHeartbeatParams`) from YouTube's watch pages
  and API responses before Safari sees them.
- **Other websites:** connections to known ad and tracker domains are refused
  ([StevenBlack hosts list](https://github.com/StevenBlack/hosts), ~78k domains).
  Nothing is decrypted for these sites.

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

Status: steps 1–2 of 5 plus other-site blocking. No installer or background service yet.

## Try it

```sh
go build -o ytblock ./cmd/ytblock
./ytblock init-ca          # create this Mac's YouTube-only certificate
./ytblock trust            # trust it (macOS asks for your password)
./ytblock update-lists     # download the ad-domain list for other websites
./ytblock run              # leave running; logs each ad field removed
sudo ./ytblock enable      # in another terminal: point macOS at the PAC file
./ytblock status
```

Then quit and reopen Safari. The proxy logs `blocked <domain>` for ad requests on
other sites and `removed N ad fields` on YouTube.

If a website breaks: `./ytblock allow example.com`. To block something extra:
`./ytblock block ads.example.com`. Changes apply within a minute. Run YouTube-only
with `./ytblock run -sites=false`.

Limits on other websites: empty ad boxes can remain, and ads served from a site's own
domain (Facebook, Instagram, Reddit sponsored posts) aren't blocked. Other Mac apps
that use the system proxy settings also get ad domains blocked.

## Undo

```sh
sudo ./ytblock disable
./ytblock untrust
rm -rf ~/Library/Application\ Support/ytblock
```

## Layout

YouTube (frozen; `scripts/check-youtube-untouched.sh` checks it matches `main`):
- `internal/prune` – which responses to edit and which keys to delete
- `internal/certs` – per-machine CA with a name constraint
- `internal/proxy` – CONNECT proxy; decrypts YouTube only

Other websites:
- `internal/sites` – ad-domain list, combined PAC file, refusing blocked domains

- `cmd/ytblock` – CLI and macOS integration (`security`, `networksetup`)

## Next steps

3. launchd agent so the proxy starts at login
4. `install.sh` / `ytblock uninstall`
5. Signed rules updates, and a check that the PAC setting is still in place
