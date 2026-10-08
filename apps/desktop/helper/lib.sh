# Shared by install.sh and uninstall.sh (macOS, and linux/ on Linux). They
# source it after setting DEST (the helper's root-owned folder) and VH_GROUP.
#
# Layout:
#   DEST/versions/<id>/   one complete helper: node and helper.mjs. Each install
#                         writes a new one and never changes it afterwards.
#   DEST/current          a symlink to versions/<id>. The launcher runs the
#                         helper through it. Switching versions renames a new
#                         symlink over it, so it is never missing or half-made.
#   DEST.lock/            held while an install or removal runs, so separate
#                         runs (the app and a terminal, say) take turns.
#
# Only POSIX sh here: macOS runs it with its /bin/sh, Linux with dash or bash.
# shellcheck shell=sh

# Settings. Each real run uses these values; only the tests change them, after
# sourcing this file, so nothing in the environment can.
VH_LOCK_TIMEOUT=180 # seconds to wait for another run to finish
VH_LOCK_GRACE=10    # seconds a lock without a readable owner is left alone
VH_CHOWN=1          # 0 only in tests, which don't run as root
VH_OS=$(uname -s)
VH_LOCK_HELD=0
VH_LOCK_MINE=
VH_VERSION=
VH_CURRENT=

vh_die() {
  echo "$*" >&2
  exit 1
}

# Rename $1 over $2 in one step. When $2 is a symlink to a folder, plain mv
# would move $1 into that folder; GNU mv -T and BSD mv -h replace the link.
vh_mv_replace() {
  if [ "$VH_OS" = Darwin ]; then
    mv -fh "$1" "$2"
  else
    mv -fT "$1" "$2"
  fi
}

# Copy a file root-owned with the given mode.
vh_install() {
  if [ "$VH_CHOWN" = 1 ]; then
    install -o root -g "$VH_GROUP" -m "$1" "$2" "$3"
  else
    install -m "$1" "$2" "$3"
  fi
}

vh_install_dir() {
  if [ "$VH_CHOWN" = 1 ]; then
    install -d -o root -g "$VH_GROUP" -m 755 "$1"
  else
    install -d -m 755 "$1"
  fi
}

# Write a file through a temporary copy beside it, so whatever reads it sees
# the old file or the new one, never part of one.
vh_put() {
  vh_install "$1" "$2" "$3.tmp.$$"
  vh_mv_replace "$3.tmp.$$" "$3"
}

## Lock

vh_boot_id() {
  if [ "$VH_OS" = Darwin ]; then
    sysctl -n kern.bootsessionuuid 2>/dev/null || true
  else
    cat /proc/sys/kernel/random/boot_id 2>/dev/null || true
  fi
}

# When process $1 started, or nothing when it isn't running. With the pid
# this names one process: a pid reused later has a different start time.
vh_proc_start() {
  case $1 in '' | *[!0-9]*) return 0 ;; esac
  if [ "$VH_OS" = Darwin ]; then
    ps -o lstart= -p "$1" 2>/dev/null || true
  else
    # Field 22 of /proc/<pid>/stat. The command name (field 2) can hold
    # spaces and parentheses, so count from after its closing ") ".
    { sed 's/.*) //' "/proc/$1/stat" 2>/dev/null || true; } | awk '{ print $20 }'
  fi
}

vh_mtime() {
  if [ "$VH_OS" = Darwin ]; then
    stat -f %m "$1" 2>/dev/null || echo 0
  else
    stat -c %Y "$1" 2>/dev/null || echo 0
  fi
}

vh_owner_field() {
  printf '%s\n' "$1" | sed -n "s/^$2=//p"
}

# Whether the lock whose owner file reads $1 is stale: written before the
# last boot, or by a process that is no longer running. An owner file that is
# empty or unreadable may still be being written, so it only counts as stale
# once neither it nor the lock has changed for VH_LOCK_GRACE seconds.
vh_owner_stale() {
  _pid=$(vh_owner_field "$1" pid)
  _start=$(vh_owner_field "$1" start)
  _boot=$(vh_owner_field "$1" boot)
  case $_pid in '' | *[!0-9]*) _pid= ;; esac
  if [ -z "$_pid" ] || [ -z "$_start" ]; then
    # Gone already: not stale, just free.
    [ -e "$VH_LOCK" ] || return 1
    _age=$(vh_mtime "$VH_LOCK")
    _owner=$(vh_mtime "$VH_LOCK/owner")
    [ "$_owner" -gt "$_age" ] && _age=$_owner
    [ $(($(date +%s) - _age)) -ge "$VH_LOCK_GRACE" ]
    return
  fi
  _now_boot=$(vh_boot_id)
  if [ -n "$_boot" ] && [ -n "$_now_boot" ] && [ "$_boot" != "$_now_boot" ]; then
    return 0
  fi
  [ "$(vh_proc_start "$_pid")" != "$_start" ]
}

# Remove a stale lock. Renaming it away first means only one of several runs
# that found it stale can remove it. If what was renamed isn't the lock that
# was found stale, another run has taken the lock since: put it back.
vh_lock_takeover() {
  [ -e "$VH_LOCK" ] || [ -L "$VH_LOCK" ] || return 0
  _seen=$(cat "$VH_LOCK/owner" 2>/dev/null) || _seen=
  vh_owner_stale "$_seen" || return 1
  _n=0
  while [ -e "$VH_LOCK.stale.$$.$_n" ] || [ -L "$VH_LOCK.stale.$$.$_n" ]; do _n=$((_n + 1)); done
  _stale=$VH_LOCK.stale.$$.$_n
  mv "$VH_LOCK" "$_stale" 2>/dev/null || return 0
  _moved=$(cat "$_stale/owner" 2>/dev/null) || _moved=
  if [ "$_moved" = "$_seen" ]; then
    rm -rf "$_stale"
  elif [ ! -e "$VH_LOCK" ] && [ ! -L "$VH_LOCK" ]; then
    mv "$_stale" "$VH_LOCK" 2>/dev/null || true
  fi
  return 0
}

# Take DEST.lock, waiting up to VH_LOCK_TIMEOUT seconds for another run.
vh_lock_acquire() {
  VH_LOCK=$DEST.lock
  _pid=$$
  VH_LOCK_MINE=$(printf 'boot=%s\npid=%s\nstart=%s' "$(vh_boot_id)" "$_pid" "$(vh_proc_start "$_pid")")
  [ -n "$(vh_owner_field "$VH_LOCK_MINE" start)" ] || vh_die "Can't tell when this process started."
  trap vh_lock_release EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  _deadline=$(($(date +%s) + VH_LOCK_TIMEOUT))
  while :; do
    if mkdir "$VH_LOCK" 2>/dev/null; then
      VH_LOCK_HELD=1
      printf '%s\n' "$VH_LOCK_MINE" >"$VH_LOCK/owner.tmp.$$"
      vh_mv_replace "$VH_LOCK/owner.tmp.$$" "$VH_LOCK/owner"
      vh_lock_check
      return 0
    fi
    vh_lock_takeover && continue
    if [ "$(date +%s)" -ge "$_deadline" ]; then
      _other=$(vh_owner_field "$(cat "$VH_LOCK/owner" 2>/dev/null || true)" pid)
      vh_die "Another install or removal of the Vigil helper${_other:+ (process $_other)} is still running after ${VH_LOCK_TIMEOUT}s. Try again when it has finished."
    fi
    sleep 0.25
  done
}

vh_lock_held() {
  [ "$VH_LOCK_HELD" = 1 ] && [ "$(cat "$VH_LOCK/owner" 2>/dev/null)" = "$VH_LOCK_MINE" ]
}

# Stop unless this run still holds the lock. Checked before each change.
vh_lock_check() {
  vh_lock_held || vh_die "Lost the lock on $DEST to another run; stopping."
}

# Release the lock, only if it is this run's own.
vh_lock_release() {
  if vh_lock_held; then
    rm -f "$VH_LOCK/owner" "$VH_LOCK/owner.tmp.$$"
    rmdir "$VH_LOCK" 2>/dev/null || true
  fi
  VH_LOCK_HELD=0
}

## Versions

# Remove a path without following it if it is a symlink.
vh_remove() {
  if [ -L "$1" ]; then
    rm -f "$1"
  elif [ -d "$1" ]; then
    rm -rf "$1"
  elif [ -e "$1" ]; then
    rm -f "$1"
  fi
}

# Make DEST and DEST/versions, and clear what older or interrupted runs left.
vh_prepare() {
  vh_lock_check
  [ ! -L "$DEST" ] || vh_die "$DEST is a symlink; remove it and run this again."
  vh_install_dir "$DEST"
  [ ! -L "$DEST/versions" ] || rm -f "$DEST/versions"
  vh_install_dir "$DEST/versions"
  vh_remove "$DEST.new"
  for _p in "$DEST".old* "$DEST"/.current.tmp.*; do
    vh_remove "$_p"
  done
}

# Copy node ($1) and helper.mjs ($2) into a new, complete versions/<id>.
# Sets VH_VERSION to <id>.
vh_build() {
  vh_lock_check
  _dir=$(mktemp -d "$DEST/versions/$(date +%Y%m%d%H%M%S).XXXXXX")
  chmod 755 "$_dir"
  [ "$VH_CHOWN" != 1 ] || chown "root:$VH_GROUP" "$_dir"
  vh_install 755 "$1" "$_dir/node"
  vh_install 644 "$2" "$_dir/helper.mjs"
  # shellcheck disable=SC2034 # read by install.sh
  VH_VERSION=${_dir##*/}
}

# Sets VH_CURRENT to the version `current` points to, or empty when there is
# none (a first install, or one from before versions).
vh_current() {
  VH_CURRENT=
  [ -L "$DEST/current" ] || return 0
  _t=$(readlink "$DEST/current" 2>/dev/null) || return 0
  case $_t in
    versions/*/* | versions/.* | versions/) ;;
    versions/*) VH_CURRENT=${_t#versions/} ;;
  esac
}

# Point `current` at versions/$1 by renaming a new symlink over it.
vh_switch() {
  vh_lock_check
  case $1 in '' | */* | .*) vh_die "Bad helper version: $1" ;; esac
  _v=$DEST/versions/$1
  if [ ! -d "$_v" ] || [ -L "$_v" ] || [ ! -f "$_v/node" ] || [ ! -f "$_v/helper.mjs" ]; then
    vh_die "$_v is not a complete helper."
  fi
  _tmp=$DEST/.current.tmp.$$
  vh_remove "$_tmp"
  ln -s "versions/$1" "$_tmp"
  vh_mv_replace "$_tmp" "$DEST/current"
  [ "$(readlink "$DEST/current")" = "versions/$1" ] || vh_die "Couldn't switch $DEST/current."
}

# After the switch and restart: remove the files from before versions, and
# every version but the current one and $1 (the one before it, kept so there
# is something to go back to). Symlinks are removed, never followed.
vh_finish() {
  vh_lock_check
  vh_current
  [ -n "$VH_CURRENT" ] || vh_die "$DEST/current is missing; not removing anything."
  for _p in "$DEST/node" "$DEST/helper.mjs" "$DEST.new" "$DEST".old* "$DEST"/.current.tmp.*; do
    vh_remove "$_p"
  done
  for _p in "$DEST"/versions/* "$DEST"/versions/.*; do
    _name=${_p##*/}
    case $_name in . | .. | '*' | '.*') continue ;; esac
    [ "$_name" = "$VH_CURRENT" ] && continue
    [ -n "${1:-}" ] && [ "$_name" = "$1" ] && [ ! -L "$_p" ] && continue
    vh_remove "$_p"
  done
}

# Remove DEST and everything an older install left beside it.
vh_remove_dest() {
  vh_lock_check
  for _p in "$DEST" "$DEST.new" "$DEST".old*; do
    vh_remove "$_p"
  done
}
