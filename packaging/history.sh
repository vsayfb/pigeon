#!/bin/sh
set -eu
bundle=$1
root=$2
database=$3
action=$4
identity=${5:-}
case "$database" in /*) ;; *) printf 'History database path must be absolute.\n' >&2; exit 2 ;; esac
case "$action" in
    clear) set -- clear "$database" ;;
    delete) set -- delete "$database" "$identity" ;;
    *) exit 2 ;;
esac
if "$bundle/bin/pigeon-control" "$@"; then
    exit 0
else
    result=$?
fi
[ "$result" = 3 ] || exit "$result"
if [ "${PIGEON_GUI_AUTH:-0}" = 1 ] && ! command -v pkexec >/dev/null 2>&1; then
    exit 3
fi
exec sh "$bundle/share/autostart.sh" "$bundle" "$root" "$database" "$action" "$identity"
