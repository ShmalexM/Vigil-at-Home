#!/bin/sh
# Removes the Vigil helper. Run it with sudo, or use Settings in Vigil at Home.
# Keeps /Library/Application Support/Vigil, which holds quarantined files and
# the action journal, so nothing Vigil quarantined is lost. Network blocks
# already in place stay until the Mac restarts.
set -eu

if [ "$(id -u)" != 0 ]; then
  echo "Run this with sudo." >&2
  exit 1
fi

LABEL=com.vigilathome.helper
launchctl bootout "system/$LABEL" 2>/dev/null || true
rm -f "/Library/LaunchDaemons/$LABEL.plist"
rm -f /Library/PrivilegedHelperTools/vigil-helper
rm -rf /Library/PrivilegedHelperTools/vigil-helper.d
rm -f /var/run/vigil-helper.sock
echo "Vigil helper removed. Quarantined files are still in /Library/Application Support/Vigil."
