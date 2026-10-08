#!/bin/sh
# Installs the Vigil helper as a root systemd service. Vigil at Home runs this
# through your desktop's password dialog (pkexec), or you can run it yourself:
#   sudo sh <Vigil's resources>/helper/linux/install.sh
# Its one optional argument is the AppImage Vigil runs from, which the helper
# pins (by device and inode) as the app it was installed for.
# Everything it installs is root-owned, so nothing running as you can change
# what runs as root. uninstall.sh (next to this file) reverses it.
set -eu

if [ "$(id -u)" != 0 ]; then
  echo "Run this with sudo." >&2
  exit 1
fi

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(dirname "$HERE")
LIBEXEC=/usr/libexec
DEST=$LIBEXEC/vigil-helper.d
UNIT=/etc/systemd/system/vigil-helper.service
POLICY=/usr/share/polkit-1/actions/com.vigilathome.helper.policy
SOCKET=/run/vigil-helper.sock

for f in "$SRC/node" "$SRC/helper.mjs" "$HERE/vigil-helper" "$HERE/vigil-helper.service" \
  "$HERE/com.vigilathome.helper.policy"; do
  [ -f "$f" ] || { echo "Missing $f" >&2; exit 1; }
done
command -v systemctl >/dev/null || { echo "The helper needs systemd." >&2; exit 1; }

# Copy the new files first, then stop the running copy, if any, and swap them
# in, so an update leaves the helper stopped for as short a time as possible.
install -d -o root -g root -m 755 "$LIBEXEC"
rm -rf "$DEST.new"
install -d -o root -g root -m 755 "$DEST.new"
install -o root -g root -m 755 "$SRC/node" "$DEST.new/node"
install -o root -g root -m 644 "$SRC/helper.mjs" "$DEST.new/helper.mjs"
systemctl stop vigil-helper.service 2>/dev/null || true
rm -rf "$DEST"
mv "$DEST.new" "$DEST"
install -o root -g root -m 755 "$HERE/vigil-helper" "$LIBEXEC/vigil-helper"
install -o root -g root -m 644 "$HERE/vigil-helper.service" "$UNIT"
install -d -o root -g root -m 755 "$(dirname "$POLICY")"
install -o root -g root -m 644 "$HERE/com.vigilathome.helper.policy" "$POLICY"

# Point osquery at Vigil's queries, keeping any config it had before. Does
# nothing when osquery isn't installed yet; setup runs this again after.
"$LIBEXEC/vigil-helper" osquery-setup || echo "osquery setup failed; Vigil retries it later." >&2

# Pin the app that asked for this install, so the helper's rules stay off it
# (nothing is pinned for an app in the installer's folder). Without a pin the
# helper still works, unpinned.
if [ -n "${1:-}" ]; then
  "$LIBEXEC/vigil-helper" pin-app "$1" || echo "Could not pin the app; the helper runs without it." >&2
fi

systemctl daemon-reload
systemctl enable --now vigil-helper.service

i=0
while [ ! -S "$SOCKET" ] && [ "$i" -lt 40 ]; do
  sleep 0.25
  i=$((i + 1))
done
if [ ! -S "$SOCKET" ]; then
  echo "The helper did not start. See: journalctl -u vigil-helper" >&2
  exit 1
fi
echo "Vigil helper installed and running."
