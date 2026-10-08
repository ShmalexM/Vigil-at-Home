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
# shellcheck source=SCRIPTDIR/../lib.sh
. "$SRC/lib.sh"

# Wait for an install that is still running, so nothing it writes is left behind.
if [ -d "$LIBEXEC" ]; then vh_lock_acquire; fi
# Stop Vigil's osquery setup and put back any osquery settings from before Vigil.
"$LIBEXEC/vigil-helper" osquery-remove 2>/dev/null || true
systemctl disable --now vigil-helper.service 2>/dev/null || true
rm -f /etc/systemd/system/vigil-helper.service
systemctl daemon-reload 2>/dev/null || true
rm -f /usr/share/polkit-1/actions/com.vigilathome.helper.policy
rm -f "$LIBEXEC/vigil-helper"
# Every version and DEST/current, and what older installs left beside them.
if [ -d "$LIBEXEC" ]; then vh_remove_dest; fi
rm -f /run/vigil-helper.sock
echo "Vigil helper removed. Quarantined files are still in /var/lib/vigil."
