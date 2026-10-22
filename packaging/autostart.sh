#!/bin/sh
# User-facing boot preference; no privileged operations unless configuration changes.
set -eu
bundle=$1
root=$2
database=$3
action=${4:-status}
uid=$(id -u)
unit="pigeon-$uid.service"
config="$root/autostart.conf"
service_database="/usr/local/lib/pigeon-$uid/PIGEON_DATABASE"
owned=0
if [ -f "$service_database" ] && [ "$(cat "$service_database")" = "$database" ]; then
    owned=1
fi

case "$action" in on|off|status|remove) ;; *) printf 'Usage: pigeon autostart on|off|status\n' >&2; exit 2 ;; esac
if [ "$action" = status ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        if [ "$owned" = 1 ] && systemctl is-enabled --quiet "$unit" 2>/dev/null; then
            printf 'Start at boot: on\n'
        else
            printf 'Start at boot: off\n'
        fi
    else
        printf 'Start at boot: unavailable (systemd is required)\n'
    fi
    exit 0
fi

if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
    printf 'Automatic boot startup requires systemd on this installation.\n' >&2
    [ "$action" != on ] || exit 1
else
    # No administrator prompt is necessary for an already-disabled, never-installed service.
    if [ "$action" = on ] || [ "$owned" = 1 ]; then
        if [ "$uid" = 0 ]; then
            sh "$bundle/share/service-install.sh" "$action" "$uid" "$bundle" "$database"
        else
            command -v sudo >/dev/null 2>&1 || { printf 'sudo is required to configure boot startup.\n' >&2; exit 1; }
            sudo sh "$bundle/share/service-install.sh" "$action" "$uid" "$bundle" "$database"
        fi
    fi
fi

mkdir -p "$root"
[ "$action" != remove ] || action=off
printf '%s\n' "$action" > "$config"
printf 'Start at boot: %s\n' "$action"
