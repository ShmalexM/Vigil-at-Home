#!/bin/sh
# Installs the Vigil helper as a root systemd service. Vigil at Home runs this
# through your desktop's password dialog (pkexec), or you can run it yourself:
#   sudo sh <Vigil's resources>/helper/linux/install.sh
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
    [ -e "$DEST" ] || [ ! -e "$OLD" ] || mv -T "$OLD" "$DEST"
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
    if [ -d "$o" ]; then mv -T "$o" "$DEST" && break; fi
  done
fi
rm -rf "$DEST.new" "$DEST".new.* "$DEST".old.*
NEW=$(mktemp -d "$DEST.new.XXXXXX")
chown root:root "$NEW"
chmod 755 "$NEW"
install -o root -g root -m 755 "$SRC/node" "$NEW/node"
install -o root -g root -m 644 "$SRC/helper.mjs" "$NEW/helper.mjs"
systemctl stop vigil-helper.service 2>/dev/null || true
# Two renames and no delete in between, so DEST is never missing for long
# and is put back if the swap fails.
if [ -e "$DEST" ]; then
  OLD=$(mktemp -d "$DEST.old.XXXXXX")/helper.d
  mv -T "$DEST" "$OLD"
fi
mv -T "$NEW" "$DEST"
NEW=
[ -z "$OLD" ] || rm -rf "${OLD%/helper.d}"
OLD=
install -o root -g root -m 755 "$HERE/vigil-helper" "$LIBEXEC/vigil-helper"
install -o root -g root -m 644 "$HERE/vigil-helper.service" "$UNIT"
install -d -o root -g root -m 755 "$(dirname "$POLICY")"
install -o root -g root -m 644 "$HERE/com.vigilathome.helper.policy" "$POLICY"

# Point osquery at Vigil's queries, keeping any config it had before. Does
# nothing when osquery isn't installed yet; setup runs this again after.
"$LIBEXEC/vigil-helper" osquery-setup || echo "osquery setup failed; Vigil retries it later." >&2

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
