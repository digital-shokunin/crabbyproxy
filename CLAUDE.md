# crabbyproxy

Lightweight Rust SOCKS5 proxy for domain-based split tunneling on macOS. Binds outgoing connections to a physical network interface via `IP_BOUND_IF`, bypassing WireGuard's Network Extension. Resolves DNS via DNS-over-HTTPS (Cloudflare/Google/Quad9 with fallback).

## Project structure

```
src/main.rs              SOCKS5 proxy with DoH + IP_BOUND_IF
Cargo.toml
install.sh               Build, install binary, config, and LaunchAgent
config.toml.default      Default unified config (DoH servers + proxy domains)
crabbyproxy-setpac       Shell helper (runs as root via sudo) to set SCDynamicStore proxy
com.digisho.crabbyproxy.plist   LaunchAgent plist
diagram.png              Architecture diagram for README
```

## Installed locations

| File | Location |
|------|----------|
| Binary | `~/.local/bin/crabbyproxy` |
| setpac helper | `~/.local/bin/crabbyproxy-setpac` |
| Config | `~/.config/crabbyproxy/config.toml` |
| LaunchAgent | `~/Library/LaunchAgents/com.digisho.crabbyproxy.plist` |
| Log | `~/Library/Logs/crabbyproxy.log` |

## Build and install

```bash
./install.sh           # build, install, start LaunchAgent
cargo build --release  # build only
```

After install, configure browsers:
- **Firefox**: Settings > Network Settings > Automatic proxy configuration URL > `http://127.0.0.1:1081/proxy.pac`
- **Chrome/Safari**: System Settings > Network > Wi-Fi > Details > Proxies > Automatic Proxy Configuration > `http://127.0.0.1:1081/proxy.pac`

## Key behaviors

- **Dynamic interface detection**: re-detects the active physical interface (en0/en6/en1) on every connection. Handles Wi-Fi/Ethernet switching without restart.
- **DoH with fallback**: tries Cloudflare, Google, Quad9 in order. Configurable via `[doh] servers` in `config.toml`.
- **TTL-aware DNS cache**: caches DoH responses, clamped to 30s-5min TTL.
- **PAC generated in memory**: domains list in `config.toml` → PAC served over HTTP on port 1081. No separate proxy.pac needed.
- **WireGuard watcher**: detects utun interface, calls `sudo crabbyproxy-setpac` to write PAC URL into SCDynamicStore so Chrome picks it up automatically.
- **Personal config**: `~/.config/crabbyproxy/config.toml` may have personal domains added locally.

## Adding sites

Edit `~/.config/crabbyproxy/config.toml`, add domains to the `[proxy] domains` list. Restart proxy to apply.

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
- `toml`: config.toml parsing
