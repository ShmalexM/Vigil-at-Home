#!/bin/sh
# Installs the Vigil helper as a root systemd service. Vigil at Home runs this
# through your desktop's password dialog (pkexec), or you can run it yourself:
#   sudo sh <Vigil's resources>/helper/linux/install.sh
# Its one optional argument is the AppImage Vigil runs from, which the helper
# pins (by device and inode) as the app it was installed for.
# Everything it installs is root-owned, so nothing running as you can change
# what runs as root. uninstall.sh (next to this file) reverses it.
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
UNIT=/etc/systemd/system/vigil-helper.service
POLICY=/usr/share/polkit-1/actions/com.vigilathome.helper.policy
SOCKET=/run/vigil-helper.sock
VH_GROUP=root

for f in "$SRC/node" "$SRC/helper.mjs" "$SRC/lib.sh" "$HERE/vigil-helper" \
  "$HERE/vigil-helper.service" "$HERE/com.vigilathome.helper.policy"; do
  [ -f "$f" ] || { echo "Missing $f" >&2; exit 1; }
done
command -v systemctl >/dev/null || { echo "The helper needs systemd." >&2; exit 1; }
# Run as root, this sources lib.sh from beside itself, so it must not sit in
# a folder the user can write. The app runs it from a root-owned, checked
# copy (ELEVATED_ENTRY in helper-install.ts).
# shellcheck source=SCRIPTDIR/../lib.sh
. "$SRC/lib.sh"

install -d -o root -g root -m 755 "$LIBEXEC"

# Each install adds a complete new version, DEST/versions/<id>, under a name
# of its own, and then points DEST/current at it in one rename. No version
# changes once written, so installs that overlap need no lock: the last
# switch wins, and each one switches only to a complete version. The running
# helper keeps its own version until systemd restarts it. Everything written
# here is under paths every helper version protects (/usr/libexec, /etc,
# /usr/share), so it can keep running meanwhile.
vh_prepare
vh_build "$SRC/node" "$SRC/helper.mjs"
# Nothing uses DEST/current before the new launcher, so a first install, or
# one over the layout from before versions, can point it at the new version now.
vh_current
[ -n "$VH_CURRENT" ] || vh_switch "$VH_VERSION"

# The launcher, unit and polkit policy run the helper through DEST/current,
# the same for every version. Write them first, so the switch is the one step
# that changes which helper runs.
vh_put 755 "$HERE/vigil-helper" "$LIBEXEC/vigil-helper"
vh_put 644 "$HERE/vigil-helper.service" "$UNIT"
install -d -o root -g root -m 755 "$(dirname "$POLICY")"
vh_put 644 "$HERE/com.vigilathome.helper.policy" "$POLICY"
vh_switch "$VH_VERSION"

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
systemctl enable vigil-helper.service
# Restart, so a helper that was running moves to the new version.
systemctl restart vigil-helper.service

i=0
while [ ! -S "$SOCKET" ] && [ "$i" -lt 40 ]; do
  sleep 0.25
  i=$((i + 1))
done
if [ ! -S "$SOCKET" ]; then
  echo "The helper did not start. See: journalctl -u vigil-helper" >&2
  exit 1
fi
# Now the old files can go: those from before versions, and old versions
# nothing uses (see vh_finish in lib.sh).
vh_finish
echo "Vigil helper installed and running."
