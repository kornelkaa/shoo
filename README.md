# ytblock

Blocks YouTube ads in Safari on macOS. A small local proxy removes the ad
fields (`adPlacements`, `playerAds`, `adSlots`, `adBreakHeartbeatParams`) from
YouTube's watch pages and API responses before Safari sees them.

- Only YouTube goes through the proxy (via a PAC file). Everything else connects directly.
- The video stream (`*.googlevideo.com`) is never touched.
- The certificate is made on your Mac and macOS only accepts it for
  `youtube.com` and `youtubei.googleapis.com`, so it can't be used against other sites.
- If the proxy stops, Safari falls back to connecting directly: YouTube keeps working, with ads.

Status: steps 1–2 of 5. No installer or background service yet.

## Try it

```sh
go build -o ytblock ./cmd/ytblock
./ytblock init-ca          # create this Mac's YouTube-only certificate
./ytblock trust            # trust it (macOS asks for your password)
./ytblock run              # leave running; logs each ad field removed
sudo ./ytblock enable      # in another terminal: point macOS at the PAC file
./ytblock status
```

Then open YouTube in Safari. If Safari had YouTube open before, quit and reopen it.

## Undo

```sh
sudo ./ytblock disable
./ytblock untrust
rm -rf ~/Library/Application\ Support/ytblock
```

## Layout

- `internal/prune` – which responses to edit and which keys to delete (future: signed remote rules)
- `internal/certs` – per-machine CA with a name constraint
- `internal/proxy` – CONNECT proxy and PAC file; decrypts YouTube only
- `cmd/ytblock`    – CLI and macOS integration (`security`, `networksetup`)

## Next steps

3. launchd agent so the proxy starts at login
4. `install.sh` / `ytblock uninstall`
5. Signed rules updates, and a check that the PAC setting is still in place
