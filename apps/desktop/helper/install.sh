#!/bin/sh
# Installs the Vigil helper as a root launchd daemon. Vigil at Home runs this
# through the macOS password dialog, or you can run it yourself:
#   sudo "/Applications/Vigil at Home.app/Contents/Resources/helper/install.sh"
# Everything it installs is root-owned, so nothing running as you can change
# what runs as root. uninstall.sh (next to this file) reverses it.
set -eu

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

for f in node helper.mjs vigil-helper "$LABEL.plist"; do
  [ -f "$SRC/$f" ] || { echo "Missing $f next to install.sh" >&2; exit 1; }
done

# Copy the new files first, then stop the running copy, if any, and swap them
# in, so an update leaves the helper stopped for as short a time as possible.
# Santa keeps enforcing the rules it already has while the helper restarts.
install -d -o root -g wheel -m 755 "$TOOLS"
# One run at a time: mkdir is atomic, so a second run (the app and a
# terminal at once) waits here. A lock whose run died without its traps is
# taken over.
LOCK=$DEST.lock
i=0
until mkdir "$LOCK" 2>/dev/null; do
  pid=$(cat "$LOCK/pid" 2>/dev/null || true)
  if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
    rm -rf "$LOCK"
    continue
  fi
  i=$((i + 1))
  [ "$i" -lt 240 ] || { echo "Another helper install is still running." >&2; exit 1; }
  sleep 0.5
done
echo $$ >"$LOCK/pid"
NEW=
OLD=
cleanup() {
  # Never leave the computer without the helper's files: put the old copy
  # back if the new one didn't make it in.
  if [ -n "$OLD" ]; then
    [ -e "$DEST" ] || [ ! -e "$OLD" ] || mv "$OLD" "$DEST"
    rm -rf "${OLD%/helper.d}"
  fi
  [ -z "$NEW" ] || rm -rf "$NEW"
  rm -rf "$LOCK"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
# Each run stages in its own folder. Under the lock, anything left behind
# (DEST.new from older versions too) belongs to a run that is gone; a run
# killed mid-swap may have left the only copy aside, so put that back first.
if [ ! -e "$DEST" ]; then
  for o in "$DEST".old.*/helper.d; do
    if [ -d "$o" ]; then mv "$o" "$DEST" && break; fi
  done
fi
rm -rf "$DEST.new" "$DEST".new.* "$DEST".old.*
NEW=$(mktemp -d "$DEST.new.XXXXXX")
chown root:wheel "$NEW"
chmod 755 "$NEW"
install -o root -g wheel -m 755 "$SRC/node" "$NEW/node"
install -o root -g wheel -m 644 "$SRC/helper.mjs" "$NEW/helper.mjs"
launchctl bootout "system/$LABEL" 2>/dev/null || true
# Two renames and no delete in between, so DEST is never missing for long
# and is put back if the swap fails.
if [ -e "$DEST" ]; then
  OLD=$(mktemp -d "$DEST.old.XXXXXX")/helper.d
  mv "$DEST" "$OLD"
fi
mv "$NEW" "$DEST"
NEW=
[ -z "$OLD" ] || rm -rf "${OLD%/helper.d}"
OLD=
install -o root -g wheel -m 755 "$SRC/vigil-helper" "$TOOLS/vigil-helper"
install -o root -g wheel -m 644 "$SRC/$LABEL.plist" "$PLIST"
install -d -o root -g wheel -m 755 /Library/Logs/Vigil
# A downloaded app's files carry the quarantine flag; the copies don't need it.
xattr -cr "$DEST" "$TOOLS/vigil-helper" "$PLIST" 2>/dev/null || true

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
echo "Vigil helper installed and running."
