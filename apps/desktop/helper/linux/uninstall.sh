#!/bin/sh
# Removes the Vigil helper. Run it with sudo, or use Settings in Vigil at Home.
# Keeps /var/lib/vigil, which holds quarantined files and the action journal,
# so nothing Vigil quarantined is lost. Network blocks already in place stay
# until the computer restarts.
set -eu
umask 022

if [ "$(id -u)" != 0 ]; then
  echo "Run this with sudo." >&2
  exit 1
fi

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(dirname "$HERE")
LIBEXEC=/usr/libexec
DEST=$LIBEXEC/vigil-helper.d
VH_GROUP=root
[ -f "$SRC/lib.sh" ] || { echo "Missing $SRC/lib.sh" >&2; exit 1; }
# Run as root, this sources lib.sh from beside itself, so it must not sit in
# a folder the user can write. The app runs it from a root-owned, checked
# copy (ELEVATED_ENTRY in helper-install.ts).
# shellcheck source=SCRIPTDIR/../lib.sh
. "$SRC/lib.sh"

# Stop Vigil's osquery setup and put back any osquery settings from before Vigil.
"$LIBEXEC/vigil-helper" osquery-remove 2>/dev/null || true
systemctl disable --now vigil-helper.service 2>/dev/null || true
# Remove the pin and its key once the helper has stopped. Older helpers lack
# the command; the lines below cover them.
"$LIBEXEC/vigil-helper" pin-remove 2>/dev/null || true
rm -f /etc/systemd/system/vigil-helper.service
systemctl daemon-reload 2>/dev/null || true
rm -f /usr/share/polkit-1/actions/com.vigilathome.helper.policy
rm -f "$LIBEXEC/vigil-helper"
# Every version and DEST/current, and what older installs left beside them.
if [ -d "$LIBEXEC" ]; then vh_remove_dest; fi
# The pin and its key are kept immutable by the helper; clear that before removing them.
chattr -i "/var/lib/vigil/pin/app-pin.json" "/var/lib/vigil/pin/app-pin.key" "/var/lib/vigil/pin/app-pin.gen" 2>/dev/null || true
rm -rf "/var/lib/vigil/pin"
rm -f "/var/lib/vigil/app-pin.json" "/var/lib/vigil/app-pin.json.tmp"
rm -f /run/vigil-helper.sock
echo "Vigil helper removed. Quarantined files are still in /var/lib/vigil."
