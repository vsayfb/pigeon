#!/bin/sh
# Installed entry point. The capture executable remains available via `capture`.
set -eu

self=$(readlink -f "$0")
bundle=$(dirname "$(dirname "$self")")
default_data=$(dirname "$(dirname "$bundle")")
if [ "$(basename "$(dirname "$bundle")")" != versions ]; then
    default_data=${XDG_DATA_HOME:-$HOME/.local/share}/pigeon
fi
data=${PIGEON_DATA_DIR:-$default_data}
configured_database=$data/pigeon.db
if [ -f "$data/database.conf" ]; then
    configured_database=$(cat "$data/database.conf")
fi
database=${PIGEON_DATABASE:-$configured_database}
log=$data/pigeon.log
collector=$bundle/bin/pigeon-collector
control=$bundle/bin/pigeon-control

fail() { printf 'pigeon: %s\n' "$*" >&2; exit 1; }

case "$data:$database" in /*:/*) ;; *) fail 'data and database paths must be absolute' ;; esac

validate_interface() {
    [ "$#" -le 1 ] || fail 'usage: pigeon start|restart [interface]'
    if [ "$#" = 1 ]; then
        case "$1" in -*) fail 'usage: pigeon start|restart [interface]' ;; esac
    fi
}

start() {
    validate_interface "$@"
    if state=$("$control" status "$database"); then
        printf '%s\n' "$state"
        return 0
    else
        result=$?
        [ "$result" = 1 ] || return "$result"
    fi
    mkdir -p "$data"
    touch "$log" || fail "cannot write $log"
    if [ "${PIGEON_GUI_AUTH:-0}" = 1 ]; then
        sh "$bundle/share/autostart.sh" "$bundle" "$data" "$database" start
        return
    fi
    if [ "$(id -u)" != 0 ]; then
        command -v sudo >/dev/null 2>&1 || fail 'sudo is required to start capture'
        printf 'Capture needs administrator privileges.\n'
        sudo -v || return 1
    fi
    printf 'Starting Pigeon in the background...\n'
    (
        umask 022
        if [ "$(id -u)" = 0 ]; then
            "$collector" --background --db "$database" "$@" >> "$log" 2>&1 < /dev/null
        else
            sudo -n "$collector" --background --db "$database" "$@" >> "$log" 2>&1 < /dev/null
        fi
    )
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        sleep 1
        if state=$("$control" status "$database" 2>/dev/null); then
            printf '%s\n' "$state"
            return 0
        fi
    done
    tail -n 10 "$log" >&2
    fail 'collector did not start; see pigeon logs'
}

case "${1:-}" in
    '')
        start
        exec "$bundle/bin/pigeon-tui" --db "$database" ;;
    database)
        [ "$#" -le 2 ] || fail 'usage: pigeon database [absolute-file-path]'
        if [ "$#" = 1 ]; then
            printf '%s\n' "$database"
            exit 0
        fi
        exec sh "$bundle/share/database.sh" "$bundle" "$data" "$database" "$2" ;;
    autostart)
        [ "$#" -le 2 ] || fail 'usage: pigeon autostart on|off|status'
        exec sh "$bundle/share/autostart.sh" "$bundle" "$data" "$database" "${2:-status}" ;;
    uninstall)
        [ "$#" = 1 ] || fail 'usage: pigeon uninstall'
        exec sh "$bundle/share/uninstall.sh" "$bundle" core ;;
    start)
        shift
        start "$@" ;;
    stop)
        [ "$#" = 1 ] || fail 'usage: pigeon stop'
        "$control" stop "$database" ;;
    restart)
        shift
        validate_interface "$@"
        "$control" stop "$database"
        start "$@" ;;
    status)
        [ "$#" = 1 ] || fail 'usage: pigeon status'
        "$control" status "$database" ;;
    logs)
        [ "$#" = 1 ] || fail 'usage: pigeon logs'
        if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "pigeon-$(id -u).service" 2>/dev/null; then
            exec sudo journalctl -u "pigeon-$(id -u).service" -n 50 -f
        fi
        [ -f "$log" ] || fail 'no collector log yet; run pigeon start'
        exec tail -n 50 -f "$log" ;;
    tui)
        shift
        exec "$bundle/bin/pigeon-tui" --db "$database" "$@" ;;
    capture)
        shift
        exec "$collector" "$@" ;;
    --version)
        exec "$collector" --version ;;
    help|--help|-h)
        printf '%s\n' 'Pigeon — see whom your device communicates with.' '' \
            'pigeon                    Start capture if needed, then open the TUI' \
            'pigeon start [interface]  Start background capture' \
            'pigeon stop               Stop capture and save pending traffic' \
            'pigeon restart [iface]    Restart background capture' \
            'pigeon database [path]    Show or change storage, preserving history' \
            'pigeon autostart on|off|status  Configure start at boot (default on)' \
            'pigeon uninstall          Remove CLI/TUI, keeping traffic history' \
            'pigeon status             Show collector status' \
            'pigeon logs               Follow the collector log' \
            'pigeon tui                Open the TUI without starting capture' \
            'pigeon capture <args>     Run the foreground collector directly' ;;
    *) fail 'unknown command; run pigeon --help' ;;
esac
