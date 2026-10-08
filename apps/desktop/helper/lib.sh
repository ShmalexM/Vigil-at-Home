# Shared by install.sh and uninstall.sh (macOS, and linux/ on Linux). They
# source it after setting DEST (the helper's root-owned folder) and VH_GROUP.
#
# Layout:
#   DEST/versions/<id>/   one complete helper: node and helper.mjs. Each install
#                         writes its own, under a name no other run can share,
#                         and never changes it afterwards.
#   DEST/current          a symlink to versions/<id>. The launcher runs the
#                         helper through it. Switching versions renames a new
#                         symlink over it, so it is never missing or half-made.
#
# There is no lock. Runs that overlap (the app and a terminal, say) each build
# their own version and switch `current` to it once it is complete, so the last
# switch wins and `current` always names a complete version. Pruning leaves
# alone anything another run could still be using: see vh_finish.
#
# Only POSIX sh here: macOS runs it with its /bin/sh, Linux with dash or bash.
# shellcheck shell=sh

# Settings. Each real run uses these values; only the tests change them, after
# sourcing this file, so nothing in the environment can.
VH_GRACE_MINUTES=60 # a version younger than this may belong to a run still going
VH_CHOWN=1          # 0 only in tests, which don't run as root
VH_OS=$(uname -s)
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
# the old file or the new one, never part of one. The pid keeps runs that
# overlap from sharing a temporary copy.
vh_put() {
  vh_install "$1" "$2" "$3.tmp.$$"
  vh_mv_replace "$3.tmp.$$" "$3"
}

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

# Whether $1 itself (a symlink's own time, never its target's) was last
# changed more than VH_GRACE_MINUTES ago. find -mmin means the same with GNU
# and BSD find, and -prune keeps it from looking inside a folder.
vh_is_old() {
  [ -n "$(find "$1" -prune -mmin +"$VH_GRACE_MINUTES" 2>/dev/null)" ]
}

# Whether $1 is a complete version: a real folder (not a symlink) holding
# node and helper.mjs. vh_build renames each file into place once it is
# fully written, so a file that is there is whole.
vh_complete() {
  [ -d "$1" ] && [ ! -L "$1" ] && [ -f "$1/node" ] && [ -f "$1/helper.mjs" ]
}

## Versions

# Make DEST and DEST/versions.
vh_prepare() {
  [ ! -L "$DEST" ] || vh_die "$DEST is a symlink; remove it and run this again."
  vh_install_dir "$DEST"
  [ ! -L "$DEST/versions" ] || rm -f "$DEST/versions"
  vh_install_dir "$DEST/versions"
}

# Copy node ($1) and helper.mjs ($2) into a new, complete versions/<id>, and
# set VH_VERSION to <id>. The id is the time (UTC, so names sort by age), this
# process's id and random letters; mktemp makes the folder only if no other
# run has that name, so two runs in the same second still get their own.
vh_build() {
  _dir=$(mktemp -d "$DEST/versions/$(date -u +%Y%m%d%H%M%S).$$.XXXXXX")
  chmod 755 "$_dir"
  [ "$VH_CHOWN" != 1 ] || chown "root:$VH_GROUP" "$_dir"
  vh_put 755 "$1" "$_dir/node"
  vh_put 644 "$2" "$_dir/helper.mjs"
  vh_complete "$_dir" || vh_die "Couldn't copy the helper into $_dir."
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

# Point `current` at versions/$1 by renaming a new symlink over it. Another
# run may switch it again right after; whichever renames last wins, and every
# run only ever switches to a complete version.
vh_switch() {
  case $1 in '' | */* | .*) vh_die "Bad helper version: $1" ;; esac
  vh_complete "$DEST/versions/$1" || vh_die "$DEST/versions/$1 is not a complete helper."
  _tmp=$DEST/.current.tmp.$$
  vh_remove "$_tmp"
  ln -s "versions/$1" "$_tmp"
  vh_mv_replace "$_tmp" "$DEST/current"
  vh_current
  if [ -z "$VH_CURRENT" ] || ! vh_complete "$DEST/versions/$VH_CURRENT"; then
    vh_die "Couldn't switch $DEST/current."
  fi
}

# After the switch and restart: remove the files from before versions, and
# prune versions/. A version folder goes only when all of these hold:
#   - it was last changed more than VH_GRACE_MINUTES ago, so it isn't one
#     another run is still writing or about to switch to;
#   - it isn't one of the two newest complete versions (the running one and
#     the one before it, kept so there is something to go back to);
#   - `current` doesn't point to it, read again right before each removal,
#     since another run may have switched it meanwhile.
# Anything else in versions/ (a symlink or a file) is never made by an
# install, so it goes whatever its age, unless `current` points to it.
# Symlinks are removed, never followed.
vh_finish() {
  for _p in "$DEST/node" "$DEST/helper.mjs" "$DEST.new" "$DEST".old*; do
    vh_remove "$_p"
  done
  # Another run's switch uses its own .current.tmp.<pid> for a moment; only
  # old ones are left over from runs that were stopped.
  for _p in "$DEST"/.current.tmp.*; do
    if [ -L "$_p" ] && vh_is_old "$_p"; then vh_remove "$_p"; fi
  done
  # The two newest complete versions, by name, which starts with the time.
  _newest=$(
    for _p in "$DEST"/versions/*; do
      _name=${_p##*/}
      case $_name in *[!A-Za-z0-9._-]*) continue ;; esac
      if vh_complete "$_p"; then printf '%s\n' "$_name"; fi
    done | LC_ALL=C sort | tail -n 2
  )
  for _p in "$DEST"/versions/* "$DEST"/versions/.*; do
    _name=${_p##*/}
    case $_name in . | ..) continue ;; esac
    # An unmatched pattern stays as it is; nothing is there.
    if [ ! -e "$_p" ] && [ ! -L "$_p" ]; then continue; fi
    if [ -d "$_p" ] && [ ! -L "$_p" ]; then
      case "
$_newest
" in *"
$_name
"*) continue ;;
      esac
      vh_is_old "$_p" || continue
    fi
    vh_current
    [ -n "$VH_CURRENT" ] || vh_die "$DEST/current is missing; not removing anything more."
    [ "$_name" != "$VH_CURRENT" ] || continue
    vh_remove "$_p"
  done
}

# Remove DEST and everything an older install left beside it.
vh_remove_dest() {
  for _p in "$DEST" "$DEST.new" "$DEST".old*; do
    vh_remove "$_p"
  done
}
