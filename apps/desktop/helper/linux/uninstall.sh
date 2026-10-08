#!/bin/sh
# Removes the Vigil helper. Run it with sudo, or use Settings in Vigil at Home.
# Keeps /var/lib/vigil, which holds quarantined files and the action journal,
# so nothing Vigil quarantined is lost. Network blocks already in place stay
# until the computer restarts.
set -eu

if [ "$(id -u)" != 0 ]; then
  echo "Run this with sudo." >&2
  exit 1
fi

# Stop Vigil's osquery setup and put back any osquery settings from before Vigil.
/usr/libexec/vigil-helper osquery-remove 2>/dev/null || true
systemctl disable --now vigil-helper.service 2>/dev/null || true
rm -f /etc/systemd/system/vigil-helper.service
systemctl daemon-reload 2>/dev/null || true
rm -f /usr/share/polkit-1/actions/com.vigilathome.helper.policy
rm -f /usr/libexec/vigil-helper
rm -rf /usr/libexec/vigil-helper.d /usr/libexec/vigil-helper.d.*
rm -f /run/vigil-helper.sock
echo "Vigil helper removed. Quarantined files are still in /var/lib/vigil."
