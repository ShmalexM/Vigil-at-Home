#!/bin/sh
# Installs the Vigil helper as a root launchd daemon. Vigil at Home runs this
# through the macOS password dialog, or you can run it yourself:
#   sudo "/Applications/Vigil at Home.app/Contents/Resources/helper/install.sh"
# Everything it installs is root-owned, so nothing running as you can change
# what runs as root. uninstall.sh (next to this file) reverses it.
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
PLIST=/Library/LaunchDaemons/$LABEL.plist
SOCKET=/var/run/vigil-helper.sock
VH_GROUP=wheel

for f in node helper.mjs vigil-helper "$LABEL.plist" lib.sh; do
  [ -f "$SRC/$f" ] || { echo "Missing $f next to install.sh" >&2; exit 1; }
done
# shellcheck source=SCRIPTDIR/lib.sh
. "$SRC/lib.sh"

install -d -o root -g wheel -m 755 "$TOOLS"
# One install or removal at a time; the lock goes when this script ends.
vh_lock_acquire

# Each install adds a complete new version, DEST/versions/<id>, and then
# points DEST/current at it in one rename. The running helper keeps its own
# version until launchd restarts it, and no version changes once written.
# Santa keeps enforcing the rules it already has while the helper restarts.
vh_prepare
vh_build "$SRC/node" "$SRC/helper.mjs"
# A downloaded app's files carry the quarantine flag; the copies don't need it.
xattr -cr "$DEST/versions/$VH_VERSION" 2>/dev/null || true
vh_current
PREVIOUS=$VH_CURRENT
# Nothing uses DEST/current before the new launcher, so a first install, or
# one over the layout from before versions, can point it at the new version now.
[ -n "$PREVIOUS" ] || vh_switch "$VH_VERSION"

# The launcher and launchd job run the helper through DEST/current, the same
# for every version. Write them first, so the switch is the one step that
# changes which helper runs.
vh_lock_check
vh_put 755 "$SRC/vigil-helper" "$TOOLS/vigil-helper"
vh_put 644 "$SRC/$LABEL.plist" "$PLIST"
xattr -c "$TOOLS/vigil-helper" "$PLIST" 2>/dev/null || true
vh_switch "$VH_VERSION"

launchctl bootout "system/$LABEL" 2>/dev/null || true
install -d -o root -g wheel -m 755 /Library/Logs/Vigil

# Point osquery at Vigil's queries, keeping any config it had before.
if [ -d /var/osquery ]; then
  for f in conf flags; do
    target=/var/osquery/osquery.$f
    if [ -f "$target" ] && [ ! -f "$target.before-vigil" ]; then
      cp -p "$target" "$target.before-vigil"
    fi
  done
  "$TOOLS/vigil-helper" osquery-config >/var/osquery/osquery.conf
  "$TOOLS/vigil-helper" osquery-flags >/var/osquery/osquery.flags
  launchctl kickstart -k system/io.osquery.agent 2>/dev/null || true
fi

launchctl bootstrap system "$PLIST"

i=0
while [ ! -S "$SOCKET" ] && [ "$i" -lt 40 ]; do
  sleep 0.25
  i=$((i + 1))
done
if [ ! -S "$SOCKET" ]; then
  echo "The helper did not start. See /Library/Logs/Vigil/helper.log" >&2
  exit 1
fi
# Now the old files can go: those from before versions, and every version
# but this one and the one before it.
vh_finish "$PREVIOUS"
echo "Vigil helper installed and running."
