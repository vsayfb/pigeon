#!/bin/sh
# User-facing boot preference; no privileged operations unless configuration changes.
set -eu
bundle=$1
root=$2
database=$3
action=${4:-status}
identity=${5:-}
uid=$(id -u)
unit="pigeon-$uid.service"
config="$root/autostart.conf"
service_database="/usr/local/lib/pigeon-$uid/INSTALL_ROOT"
owned=0
if [ -r "$service_database" ] && [ "$(cat "$service_database")" = "$(readlink -f "$root")" ]; then
    owned=1
fi

run_privileged() {
    if [ "$uid" = 0 ]; then
        sh "$bundle/share/service-install.sh" "$action" "$uid" "$bundle" "$database" "$identity"
    elif [ "${PIGEON_GUI_AUTH:-0}" = 1 ]; then
        command -v pkexec >/dev/null 2>&1 || {
            printf 'Desktop authorization is unavailable. Run the command in a terminal.\n' >&2
            exit 1
        }
        pkexec /bin/sh "$bundle/share/service-install.sh" "$action" "$uid" "$bundle" "$database" "$identity"
    else
        command -v sudo >/dev/null 2>&1 || { printf 'sudo is required.\n' >&2; exit 1; }
        sudo sh "$bundle/share/service-install.sh" "$action" "$uid" "$bundle" "$database" "$identity"
    fi
}

case "$action" in on|off|status|remove|start|authorize|clear|delete) ;; *) printf 'Usage: pigeon autostart on|off|status\n' >&2; exit 2 ;; esac
if [ "$action" = clear ] || [ "$action" = delete ]; then
    run_privileged
    exit 0
fi
if [ "$action" = status ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        if [ "$owned" = 1 ] && systemctl is-enabled --quiet "$unit" 2>/dev/null; then
            printf 'Start at boot: on\n'
        elif [ -e "/etc/systemd/system/$unit" ] && [ ! -r "$service_database" ]; then
            printf 'Start at boot: unknown (service metadata is not readable; update the CLI)\n'
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
    if [ "$action" = on ] || [ "$action" = start ] || [ "$action" = authorize ] || [ "$action" = clear ] || [ "$action" = delete ] || [ "$owned" = 1 ]; then
        run_privileged
    fi
fi

[ "$action" != start ] && [ "$action" != authorize ] && [ "$action" != clear ] && [ "$action" != delete ] || exit 0
mkdir -p "$root"
[ "$action" != remove ] || action=off
printf '%s\n' "$action" > "$config"
printf 'Start at boot: %s\n' "$action"
