#!/bin/sh
# Remove only files owned by this component; preserve shared traffic history.
set -eu
main() {
    bundle=$1
    component=$2
    root=$(dirname "$(dirname "$bundle")")
    [ "$(basename "$(dirname "$bundle")")" = versions ] || {
        printf 'Uninstall is available for installed release bundles only.\n' >&2
        exit 1
    }
    [ "$(cat "$bundle/COMPONENT")" = "$component" ] || exit 1
    bin=$(cat "$bundle/INSTALL_BIN")
    case "$bin" in /*) ;; *) exit 1 ;; esac

    if [ "$component" = core ]; then
        # The control command waits for pending traffic to be saved.
        "$bundle/bin/pigeon" stop || {
            printf 'Could not stop capture; installation was not removed.\n' >&2
            exit 1
        }
        commands='pigeon pigeon-tui'
    else
        commands=pigeon-gui
        data=$(cat "$bundle/INSTALL_DESKTOP_DATA")
        case "$data" in /*) ;; *) exit 1 ;; esac
        desktop="$data/applications/pigeon-gui.desktop"
        if [ -f "$desktop" ] && grep -qx 'X-Pigeon-Managed=true' "$desktop"; then
            # Only remove the launcher if it still points at this installation.
            if cmp -s "$desktop" "$root/desktop/pigeon-gui.desktop"; then
                rm -f "$desktop" "$root/desktop/pigeon.png" "$root/desktop/pigeon-gui.desktop"
                rmdir "$root/desktop" 2>/dev/null || :
                if command -v update-desktop-database >/dev/null 2>&1; then
                    update-desktop-database "$data/applications" >/dev/null 2>&1 || :
                fi
            fi
        fi
    fi

    for command in $commands; do
        link="$bin/$command"
        if [ -L "$link" ]; then
            case "$(readlink "$link")" in
                "$root"/versions/*/bin/"$command") rm -f "$link" ;;
            esac
        fi
    done

    for version in "$root"/versions/*; do
        [ -d "$version" ] && [ ! -L "$version" ] || continue
        [ -f "$version/COMPONENT" ] || continue
        [ "$(cat "$version/COMPONENT")" = "$component" ] || continue
        rm -rf -- "$version"
    done
    rmdir "$root/versions" 2>/dev/null || :
    printf 'Pigeon %s uninstalled. Database and logs kept in %s.\n' "$component" "$root"
}
main "$@"
