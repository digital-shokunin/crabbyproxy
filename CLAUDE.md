# crabbyproxy

Lightweight Rust SOCKS5 proxy for domain-based split tunneling on macOS. Binds outgoing connections to a physical network interface via `IP_BOUND_IF`, bypassing WireGuard's Network Extension. Resolves DNS via DNS-over-HTTPS (Cloudflare/Google/Quad9 with fallback).

## Architecture

```
Browser (Firefox/Chrome)
  |
  |-- youtube.com, reddit.com --> PAC file --> crabbyproxy (127.0.0.1:1080)
  |                                              |
  |                                              +--> DoH (1.1.1.1 / 8.8.8.8 / 9.9.9.9)
  |                                              +--> IP_BOUND_IF binds to en0
  |                                              |
  |                                              v
  |                                         Direct internet (home IP)
  |
  |-- everything else --> DIRECT --> WireGuard VPN tunnel (utun)
```

## Project structure

```
crabbyproxy/          Rust crate (binary)
  src/main.rs         SOCKS5 proxy with DoH + IP_BOUND_IF
  Cargo.toml
  install.sh          Build, install binary, config, and LaunchAgent
proxy.pac             Browser auto-proxy config (YouTube/Reddit -> SOCKS)
doh.conf.default      Default DoH server list
com.digisho.crabbyproxy.plist   LaunchAgent plist
```

## Installed locations

| File | Location |
|------|----------|
| Binary | `~/.local/bin/crabbyproxy` |
| DoH config | `~/.config/crabbyproxy/doh.conf` |
| PAC file | `~/.config/crabbyproxy/proxy.pac` |
| LaunchAgent | `~/Library/LaunchAgents/com.digisho.crabbyproxy.plist` |
| Log | `~/Library/Logs/crabbyproxy.log` |

## Setup

```bash
cd crabbyproxy && ./install.sh
```

Then configure browsers:
- **Firefox**: Settings > Network Settings > Automatic proxy configuration URL > `file:///Users/digisho/.config/crabbyproxy/proxy.pac`
- **Chrome/Safari**: System Settings > Network > Wi-Fi > Details > Proxies > Automatic Proxy Configuration > same URL

## Adding new sites

Edit `~/.config/crabbyproxy/proxy.pac` — add `shExpMatch()` rules. Browser reloads automatically or restart to pick up changes.

## Changing DoH servers

Edit `~/.config/crabbyproxy/doh.conf` (one URL per line). Restart proxy: `launchctl kickstart -k gui/$(id -u)/com.digisho.crabbyproxy`

## How it works

The macOS WireGuard app uses a Network Extension that intercepts all packets before the routing table. IP-based split tunneling (AllowedIPs, route add) cannot bypass it reliably. This proxy operates at the application layer instead:

1. Browser PAC file routes target domains to SOCKS5 proxy on localhost
2. Proxy resolves domains via DoH (bypasses VPN's DNS)
3. Proxy opens outgoing connections with `IP_BOUND_IF` set to the physical interface (en0/en6)
4. macOS honors `IP_BOUND_IF` even with the VPN NE active — traffic goes direct
5. All other browser traffic goes DIRECT through the VPN as normal

## Dependencies

- `tokio` — async runtime
- `reqwest` + `serde` — DoH JSON API client
- `libc` — `IP_BOUND_IF` setsockopt
- `dirs` — XDG config path resolution
