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
service_database="/usr/local/lib/pigeon-$uid/INSTALL_ROOT"
owned=0
if [ -f "$service_database" ] && [ "$(cat "$service_database")" = "$(readlink -f "$root")" ]; then
    owned=1
fi

case "$action" in on|off|status|remove|start|authorize) ;; *) printf 'Usage: pigeon autostart on|off|status\n' >&2; exit 2 ;; esac
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
    [ "$action" != on ] && [ "$action" != start ] && [ "$action" != authorize ] || exit 1
else
    # No administrator prompt is necessary for an already-disabled, never-installed service.
    if [ "$action" = on ] || [ "$action" = start ] || [ "$action" = authorize ] || [ "$owned" = 1 ]; then
        if [ "$uid" = 0 ]; then
            sh "$bundle/share/service-install.sh" "$action" "$uid" "$bundle" "$database"
        elif [ "${PIGEON_GUI_AUTH:-0}" = 1 ]; then
            command -v pkexec >/dev/null 2>&1 || {
                printf 'Desktop authorization is unavailable. Run pigeon autostart %s in a terminal.\n' "$action" >&2
                exit 1
            }
            pkexec /bin/sh "$bundle/share/service-install.sh" "$action" "$uid" "$bundle" "$database"
        else
            command -v sudo >/dev/null 2>&1 || { printf 'sudo is required to configure boot startup.\n' >&2; exit 1; }
            sudo sh "$bundle/share/service-install.sh" "$action" "$uid" "$bundle" "$database"
        fi
    fi
fi

[ "$action" != start ] && [ "$action" != authorize ] || exit 0
mkdir -p "$root"
[ "$action" != remove ] || action=off
printf '%s\n' "$action" > "$config"
printf 'Start at boot: %s\n' "$action"
