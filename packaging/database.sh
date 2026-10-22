#!/bin/sh
# Change collector storage using a consistent SQLite backup, never overwrite history.
set -eu
bundle=$1
root=$2
old=$3
new=$4
fail() { printf 'pigeon: %s\n' "$*" >&2; exit 1; }
case "$new" in /*) ;; *) fail 'database location must be an absolute file path' ;; esac
cr=$(printf '\r')
case "$new" in *'
'*|*"$cr"*) fail 'database path must not contain newlines' ;; esac
[ "$old" != "$new" ] || { printf 'Database location unchanged.\n'; exit 0; }
[ ! -e "$new" ] && [ ! -L "$new" ] || fail 'destination already exists; choose a new database file'
[ -z "${PIGEON_DATABASE:-}" ] || fail 'remove the PIGEON_DATABASE environment override before changing settings'
parent=$(dirname "$new")
mkdir -p "$parent"
parent=$(readlink -f "$parent")
new="$parent/$(basename "$new")"
[ "$old" != "$new" ] || { printf 'Database location unchanged.\n'; exit 0; }
[ ! -e "$new" ] && [ ! -L "$new" ] || fail 'destination already exists; choose a new database file'
was_running=0
if "$bundle/bin/pigeon-control" status "$old" >/dev/null; then
    was_running=1
else
    status=$?
    [ "$status" = 1 ] || fail 'could not check collector status'
fi
boot=$(sh "$bundle/share/autostart.sh" "$bundle" "$root" "$old" status)
if [ "$boot" = 'Start at boot: on' ]; then
    sh "$bundle/share/autostart.sh" "$bundle" "$root" "$old" authorize
fi
"$bundle/bin/pigeon-control" stop "$old"

work=$(mktemp -d "$parent/.pigeon-database.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
if [ -f "$old" ]; then
    "$bundle/bin/pigeon-control" backup "$old" "$work/pigeon.db"
    # Hard link provides atomic no-overwrite publication on the same filesystem.
    ln -T "$work/pigeon.db" "$new" || fail 'cannot create destination database'
fi

mkdir -p "$root"
config=$(mktemp "$root/.database.conf.XXXXXX")
printf '%s\n' "$new" > "$config"
trap 'rm -rf "$work"; rm -f "$config"' EXIT HUP INT TERM

# Reconfigure a boot service before publishing the user preference. A cancelled
# authorization leaves the old configuration and original database untouched.
if [ "$boot" = 'Start at boot: on' ]; then
    sh "$bundle/share/autostart.sh" "$bundle" "$root" "$new" on ||
        fail 'database setting was not changed; run pigeon start to resume the previous location'
fi
mv -f "$config" "$root/database.conf"
if [ "$boot" != 'Start at boot: on' ] && [ "$was_running" = 1 ]; then
    if ! "$bundle/bin/pigeon" start; then
        printf 'Database location saved. Run pigeon start to resume capture.\n'
        exit 0
    fi
fi
printf 'Database location saved. Existing history was preserved; the original file remains at %s.\n' "$old"
