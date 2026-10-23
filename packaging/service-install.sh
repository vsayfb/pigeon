#!/bin/sh
# Invoked once through sudo. Service code is copied to root-owned storage.
set -eu
action=$1
uid=$2
bundle=$3
database=$4
case "$uid" in ''|*[!0-9]*) exit 2 ;; esac
case "$bundle:$database" in /*:/*) ;; *) exit 2 ;; esac
cr=$(printf '\r')
case "$bundle$database" in *'
'*|*"$cr"*) printf 'Unsupported newline in service paths.\n' >&2; exit 2 ;; esac
[ "$(id -u)" = 0 ] || exit 1
unit="pigeon-$uid.service"
base="/usr/local/lib/pigeon-$uid"
installation=$(dirname "$(dirname "$(readlink -f "$bundle")")")
file="/etc/systemd/system/$unit"
if [ -e "$file" ]; then
    if [ ! -f "$base/INSTALL_ROOT" ] || [ "$(cat "$base/INSTALL_ROOT")" != "$installation" ]; then
        printf 'A boot service for another Pigeon installation already exists.\n' >&2
        exit 1
    fi
fi

case "$action" in
    authorize) exit 0 ;;
    clear) exec "$bundle/bin/pigeon-control" clear "$database" ;;
    delete) exec "$bundle/bin/pigeon-control" delete "$database" "${5:-}" ;;
    off)
        systemctl disable "$unit"
        exit 0 ;;
    remove)
        systemctl disable --now "$unit"
        rm -f "$file"
        rm -rf "$base"
        systemctl daemon-reload
        exit 0 ;;
    on|start) ;;
    *) exit 2 ;;
esac

[ "$(cat "$bundle/COMPONENT")" = core ] || exit 2
[ -x "$bundle/bin/pigeon-collector" ] || exit 2
# Never run writable per-user binaries as root at every boot.
mkdir -p /usr/local/lib
staging=$(mktemp -d /usr/local/lib/.pigeon-service.XXXXXX)
trap 'rm -rf "$staging"' EXIT HUP INT TERM
cp -R "$bundle/." "$staging/"
printf '%s\n' "$database" > "$staging/PIGEON_DATABASE"
printf '%s\n' "$installation" > "$staging/INSTALL_ROOT"
chown -R root:root "$staging"
chmod -R go-w "$staging"
# mktemp creates a private directory; status checks need read-only metadata access.
chmod 755 "$staging"
chmod 644 "$staging/INSTALL_ROOT" "$staging/PIGEON_DATABASE"

# Gracefully stop an existing foreground service or detached collector first.
if [ -f "$base/PIGEON_DATABASE" ]; then
    "$bundle/bin/pigeon-control" stop "$(cat "$base/PIGEON_DATABASE")"
fi
"$bundle/bin/pigeon-control" stop "$database"
if [ -f "$file" ]; then
    systemctl stop "$unit"
fi
rm -rf "$base"
mv "$staging" "$base"
# A systemd unit applies both C-style escapes and specifier/variable expansion.
escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/%/%%/g'; }
{
    printf '%s\n' '[Unit]' 'Description=Pigeon network watcher' 'After=network.target' 'StartLimitIntervalSec=0'
    printf 'RequiresMountsFor="%s"\n' "$(escape "$(dirname "$database")")"
    printf '%s\n' '' '[Service]' 'Type=simple' 'User=root' 'UMask=0022'
    printf 'Environment=SUDO_UID=%s\n' "$uid"
    printf 'ExecStart="%s/bin/pigeon-collector" --db "%s"\n' "$base" "$(escape "$database" | sed 's/\$/$$/g')"
    printf '%s\n' 'Restart=on-failure' 'RestartSec=5' 'TimeoutStopSec=30' 'StandardOutput=journal' 'StandardError=journal' '' '[Install]' 'WantedBy=multi-user.target'
} > "$file"
chmod 644 "$file"
systemctl daemon-reload
if [ "$action" = on ]; then
    systemctl enable --now "$unit"
else
    systemctl start "$unit"
fi
