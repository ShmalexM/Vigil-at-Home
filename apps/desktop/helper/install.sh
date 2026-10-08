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
# Stop the running helper before changing anything. An older helper doesn't
# know every file this script writes, so it could quarantine one halfway
# through; stopped, it can't. Santa keeps enforcing the rules it already has
# until the new helper starts.
launchctl bootout "system/$LABEL" 2>/dev/null || true

# Each install adds a complete new version, DEST/versions/<id>, under a name
# of its own, and then points DEST/current at it in one rename. No version
# changes once written, so installs that overlap need no lock: the last
# switch wins, and each one switches only to a complete version.
vh_prepare
vh_build "$SRC/node" "$SRC/helper.mjs"
# A downloaded app's files carry the quarantine flag; the copies don't need it.
xattr -cr "$DEST/versions/$VH_VERSION" 2>/dev/null || true
# Nothing uses DEST/current before the new launcher, so a first install, or
# one over the layout from before versions, can point it at the new version now.
vh_current
[ -n "$VH_CURRENT" ] || vh_switch "$VH_VERSION"

# The launcher and launchd job run the helper through DEST/current, the same
# for every version. Write them first, so the switch is the one step that
# changes which helper runs.
vh_put 755 "$SRC/vigil-helper" "$TOOLS/vigil-helper"
vh_put 644 "$SRC/$LABEL.plist" "$PLIST"
xattr -c "$TOOLS/vigil-helper" "$PLIST" 2>/dev/null || true
vh_switch "$VH_VERSION"

install -d -o root -g wheel -m 755 /Library/Logs/Vigil

# Point osquery at Vigil's queries, keeping any config it had before.
if [ -d /var/osquery ]; then
  for f in conf flags; do
    target=/var/osquery/osquery.$f
    if [ -f "$target" ] && [ ! -e "$target.before-vigil" ]; then
      # ln makes the backup only if no other install running now has, so the
      # first copy, taken before any install rewrote the file, is the one kept.
      cp -p "$target" "$target.before-vigil.tmp.$$"
      ln "$target.before-vigil.tmp.$$" "$target.before-vigil" 2>/dev/null || true
      rm -f "$target.before-vigil.tmp.$$"
    fi
  done
  "$TOOLS/vigil-helper" osquery-config >/var/osquery/osquery.conf
  "$TOOLS/vigil-helper" osquery-flags >/var/osquery/osquery.flags
  launchctl kickstart -k system/io.osquery.agent 2>/dev/null || true
fi

# Another install running at the same time may have started the job already;
# then restart it, so it runs whatever DEST/current names now.
if ! started=$(launchctl bootstrap system "$PLIST" 2>&1); then
  launchctl kickstart -k "system/$LABEL" || vh_die "The helper did not start: $started"
fi

i=0
while [ ! -S "$SOCKET" ] && [ "$i" -lt 40 ]; do
  sleep 0.25
  i=$((i + 1))
done
if [ ! -S "$SOCKET" ]; then
  echo "The helper did not start. See /Library/Logs/Vigil/helper.log" >&2
  exit 1
fi
# Now the old files can go: those from before versions, and old versions
# nothing uses (see vh_finish in lib.sh).
vh_finish
echo "Vigil helper installed and running."
