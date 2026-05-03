#!/bin/bash
# Install crabbyproxy — SOCKS5 proxy with interface binding and DoH
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
CONFIG_DIR="${HOME}/.config/crabbyproxy"
LAUNCH_DIR="${HOME}/Library/LaunchAgents"
LABEL="com.digisho.crabbyproxy"
PLIST_SRC="${SCRIPT_DIR}/com.digisho.crabbyproxy.plist"

echo "=== crabbyproxy installer ==="

# Build
echo "Building release binary..."
cd "$SCRIPT_DIR"
cargo build --release
BINARY="$SCRIPT_DIR/target/release/crabbyproxy"

# Install binary and setpac helper
echo "Installing to $BIN_DIR/"
mkdir -p "$BIN_DIR"
cp "$BINARY" "$BIN_DIR/crabbyproxy"
chmod 755 "$BIN_DIR/crabbyproxy"
cp "${SCRIPT_DIR}/crabbyproxy-setpac" "$BIN_DIR/crabbyproxy-setpac"
chmod 755 "$BIN_DIR/crabbyproxy-setpac"

# Sudoers entry for crabbyproxy-setpac (allows watcher to set SCDynamicStore proxy without password)
SUDOERS_FILE="/etc/sudoers.d/crabbyproxy-setpac"
SUDOERS_RULE="$(whoami) ALL=(ALL) NOPASSWD: $BIN_DIR/crabbyproxy-setpac"
if ! sudo -n grep -qF "$BIN_DIR/crabbyproxy-setpac" "$SUDOERS_FILE" 2>/dev/null; then
  echo "Configuring sudoers for crabbyproxy-setpac (may prompt for password)..."
  osascript -e "do shell script \"echo '$SUDOERS_RULE' > $SUDOERS_FILE && chmod 440 $SUDOERS_FILE\" with administrator privileges" 2>/dev/null \
    && echo "  sudoers entry added" \
    || echo "  WARNING: could not add sudoers entry — Chrome proxy won't auto-configure with WireGuard"
fi

# Install default config
echo "Setting up config in $CONFIG_DIR/"
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
  cp "${SCRIPT_DIR}/config.toml.default" "$CONFIG_DIR/config.toml"
  echo "  Created config.toml"
else
  echo "  config.toml already exists, skipping"
fi

# Install LaunchAgent
echo "Installing LaunchAgent..."
mkdir -p "$LAUNCH_DIR"
if [[ -f "$PLIST_SRC" ]]; then
  # Unload existing
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  cp "$PLIST_SRC" "$LAUNCH_DIR/${LABEL}.plist"
  launchctl bootstrap "gui/$(id -u)" "$LAUNCH_DIR/${LABEL}.plist"
  echo "  Daemon started"
else
  echo "  WARNING: plist not found at $PLIST_SRC"
fi

# Configure system proxy on all network services (requires admin)
# This is critical for Chrome to pick up the PAC when WireGuard is active
PAC_URL="http://127.0.0.1:1081/proxy.pac"
echo "Configuring system proxy (may prompt for password)..."
ALL_SERVICES=$(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
SCRIPT=""
while IFS= read -r svc; do
  SCRIPT+="networksetup -setautoproxyurl \"$svc\" \"$PAC_URL\" 2>/dev/null; networksetup -setautoproxystate \"$svc\" on 2>/dev/null; "
done <<< "$ALL_SERVICES"
osascript -e "do shell script \"$SCRIPT\" with administrator privileges" 2>/dev/null && echo "  Proxy set on all network services" || echo "  WARNING: could not set system proxy (skipped)"

echo ""
echo "Done."
echo ""
echo "Binary:   $BIN_DIR/crabbyproxy"
echo "Config:   $CONFIG_DIR/config.toml"
echo "Log:      ~/Library/Logs/crabbyproxy.log"
echo ""
echo "Browser PAC URL (Chrome/Safari — set in System Settings or auto-configured above):"
echo "  $PAC_URL"
echo "Firefox: file://$CONFIG_DIR/proxy.pac"
echo ""
echo "To uninstall:"
echo "  launchctl bootout gui/\$(id -u)/$LABEL"
echo "  rm $BIN_DIR/crabbyproxy"
echo "  rm $LAUNCH_DIR/${LABEL}.plist"
echo "  rm -rf $CONFIG_DIR"
