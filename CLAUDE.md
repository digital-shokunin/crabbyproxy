# crabbyproxy

Lightweight Rust SOCKS5 proxy for domain-based split tunneling on macOS. Binds outgoing connections to a physical network interface via `IP_BOUND_IF`, bypassing WireGuard's Network Extension. Resolves DNS via DNS-over-HTTPS (Cloudflare/Google/Quad9 with fallback).

## Project structure

```
src/main.rs           SOCKS5 proxy with DoH + IP_BOUND_IF
Cargo.toml
install.sh            Build, install binary, config, and LaunchAgent
proxy.pac             Browser auto-proxy config (YouTube/Reddit/Netflix/Hulu -> SOCKS)
doh.conf.default      Default DoH server list
com.digisho.crabbyproxy.plist   LaunchAgent plist
diagram.png           Architecture diagram for README
```

## Installed locations

| File | Location |
|------|----------|
| Binary | `~/.local/bin/crabbyproxy` |
| DoH config | `~/.config/crabbyproxy/doh.conf` |
| PAC file | `~/.config/crabbyproxy/proxy.pac` |
| LaunchAgent | `~/Library/LaunchAgents/com.digisho.crabbyproxy.plist` |
| Log | `~/Library/Logs/crabbyproxy.log` |

## Build and install

```bash
./install.sh           # build, install, start LaunchAgent
cargo build --release  # build only
```

After install, configure browsers:
- **Firefox**: Settings > Network Settings > Automatic proxy configuration URL > `file:///Users/digisho/.config/crabbyproxy/proxy.pac`
- **Chrome/Safari**: System Settings > Network > Wi-Fi > Details > Proxies > Automatic Proxy Configuration > same URL

## Key behaviors

- **Dynamic interface detection**: re-detects the active physical interface (en0/en6/en1) on every connection. Handles Wi-Fi/Ethernet switching without restart.
- **DoH with fallback**: tries Cloudflare, Google, Quad9 in order. Configurable via `~/.config/crabbyproxy/doh.conf`.
- **TTL-aware DNS cache**: caches DoH responses, clamped to 30s-5min TTL.
- **Personal PAC file**: the installed PAC at `~/.config/crabbyproxy/proxy.pac` may differ from the repo default (personal domains like Gmail, Kagi added locally).

## Adding sites

Edit `~/.config/crabbyproxy/proxy.pac`, add `shExpMatch()` rules. Browser picks up changes on reload.

## Restart proxy

```bash
launchctl kickstart -k gui/$(id -u)/com.digisho.crabbyproxy
```

## Homebrew tap

Separate repo: `digital-shokunin/homebrew-crabbyproxy`. Update the formula SHA and version when tagging new releases.

## Dependencies

- `tokio`: async runtime
- `reqwest` + `serde`: DoH JSON API client
- `libc`: `IP_BOUND_IF` setsockopt
- `dirs`: config path resolution
