#!/bin/sh
# Removes the Vigil helper. Run it with sudo, or use Settings in Vigil at Home.
# Keeps /Library/Application Support/Vigil, which holds quarantined files and
# the action journal, so nothing Vigil quarantined is lost. Network blocks
# already in place stay until the Mac restarts.
set -eu
umask 022

if [ "$(id -u)" != 0 ]; then
  echo "Run this with sudo." >&2
  exit 1
fi

SRC=$(cd "$(dirname "$0")" && pwd)
TOOLS=/Library/PrivilegedHelperTools
DEST=$TOOLS/vigil-helper.d
LABEL=com.vigilathome.helper
VH_GROUP=wheel
[ -f "$SRC/lib.sh" ] || { echo "Missing lib.sh next to uninstall.sh" >&2; exit 1; }
# shellcheck source=SCRIPTDIR/lib.sh
. "$SRC/lib.sh"

# Stop Vigil's osquery job and put back any osquery settings from before Vigil.
# Older helpers don't have this command, so a failure here doesn't stop the removal.
"$TOOLS/vigil-helper" osquery-remove 2>/dev/null || true
launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist"
rm -f "$TOOLS/vigil-helper"
# Every version and DEST/current, and what older installs left beside them.
if [ -d "$TOOLS" ]; then vh_remove_dest; fi
rm -f /var/run/vigil-helper.sock
echo "Vigil helper removed. Quarantined files are still in /Library/Application Support/Vigil."
