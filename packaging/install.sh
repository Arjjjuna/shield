#!/usr/bin/env bash
# Install Shield for the current user. No sudo, everything under ~/.local.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
bin_dir="${XDG_BIN_HOME:-$HOME/.local/bin}"
app_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
auto_dir="${XDG_CONFIG_HOME:-$HOME/.config}/autostart"

echo "Building release binary..."
( cd "$root" && cargo build --release -p shield-app )

mkdir -p "$bin_dir" "$app_dir" "$auto_dir"
install -m 0755 "$root/target/release/shield" "$bin_dir/shield"

sed "s|@EXEC@|$bin_dir/shield|g" "$here/shield.desktop" >"$app_dir/shield.desktop"
sed "s|@EXEC@|$bin_dir/shield|g" "$here/shield-autostart.desktop" >"$auto_dir/shield.desktop"

# Best-effort desktop icon on Cinnamon. Right-click -> "Allow Launching" if it
# shows as untrusted.
if [ -d "$HOME/Desktop" ]; then
  sed "s|@EXEC@|$bin_dir/shield|g" "$here/shield.desktop" >"$HOME/Desktop/shield.desktop"
  chmod +x "$HOME/Desktop/shield.desktop" 2>/dev/null || true
fi

echo
echo "Installed:"
echo "  binary    $bin_dir/shield"
echo "  launcher  $app_dir/shield.desktop"
echo "  autostart $auto_dir/shield.desktop"
echo
echo "Run it now with:  $bin_dir/shield --hidden"
echo "Uninstall with:   rm -f \"$bin_dir/shield\" \"$app_dir/shield.desktop\" \"$auto_dir/shield.desktop\" \"$HOME/Desktop/shield.desktop\""
