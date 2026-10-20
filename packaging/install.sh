#!/bin/sh
# Install a verified release without changing the system's package database.
set -eu

base=${PIGEON_DOWNLOAD_URL:-https://piigeon.pages.dev/cli}
root=${PIGEON_INSTALL_ROOT:-${HOME:?HOME is required}/.local/share/pigeon}
bin=${PIGEON_BIN_DIR:-$HOME/.local/bin}
version=latest
component=core
local_dir=
work=

fail() { printf 'pigeon installer: %s\n' "$*" >&2; exit 1; }
cleanup() { [ -z "$work" ] || rm -rf "$work"; }
progress() {
    completed=$(printf '%*s' "$1" '' | tr ' ' '#')
    remaining=$(printf '%*s' "$((6 - $1))" '' | tr ' ' '.')
    printf '[%s%s] %s/6 %s\n' "$completed" "$remaining" "$1" "$2" >&2
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version|--from)
            [ "$#" -ge 2 ] || fail "$1 requires a value"
            case "$1" in --version) version=$2 ;; --from) local_dir=$2 ;; esac
            shift ;;
        --help)
            printf '%s\n' 'Usage: install.sh [--version X.Y.Z] [--from RELEASE_DIRECTORY]' \
                'Defaults: ~/.local/share/pigeon and ~/.local/bin.' \
                'Override with PIGEON_INSTALL_ROOT, PIGEON_BIN_DIR, PIGEON_DOWNLOAD_URL.'
            exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
    shift
done

case "$root:$bin" in /*:/*) ;; *) fail 'installation directories must be absolute paths' ;; esac
for command in uname tar awk mktemp cat mkdir cp mv ln chmod readlink gzip tr; do
    command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done
if command -v sha256sum >/dev/null 2>&1; then
    sha() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
    sha() { shasum -a 256 "$1" | awk '{print $1}'; }
else
    fail 'sha256sum or shasum is required'
fi
[ "$(uname -s)" = Linux ] || fail 'this installer supports Linux'
case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) fail "no release for architecture $(uname -m)" ;;
esac
libc=glibc
if ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
    for loader in /lib/ld-musl-*.so.1; do
        [ ! -e "$loader" ] || libc=musl
    done
fi
[ "$component" = core ] || [ "$libc" = glibc ] || fail 'GUI releases currently require glibc; core/TUI support musl'

fetch() {
    if [ -n "$local_dir" ]; then
        cp "$local_dir/$1" "$2" || fail "release file unavailable: $1"
    else
        command -v curl >/dev/null 2>&1 || fail 'curl is required for downloads'
        if [ "${3:-}" = progress ] && [ -t 2 ]; then
            curl -fL --progress-bar --retry 3 "$base/$1" -o "$2" || fail "download failed: $1"
        else
            curl -fsSL --retry 3 "$base/$1" -o "$2" || fail "download failed: $1"
        fi
    fi
}

progress 1 'Finding the release'
work=$(mktemp -d "${TMPDIR:-/tmp}/pigeon-install.XXXXXX")
if [ "$version" = latest ]; then
    fetch latest.txt "$work/latest.txt"
    version=$(cat "$work/latest.txt")
fi
printf '%s\n' "$version" | awk '/^[0-9]+\.[0-9]+\.[0-9]+$/ {ok=1} END {exit !ok}' || fail 'invalid release version'

components=$component
# Download, validate and smoke-test all requested components before activating any.
for component in $components; do
    package="pigeon-$component-linux-$arch-$libc"
    fetch "releases/$version/$package.manifest" "$work/$component.manifest"
    archive="$work/$component.tar.gz"
    : > "$archive"
    expected=
    part_count=$(awk 'END { print NR - 1 }' "$work/$component.manifest")
    part_number=0
    progress 2 "Downloading Pigeon $version ($arch, $libc)"
    while read -r hash name extra; do
        [ -z "${extra:-}" ] || fail 'invalid manifest entry'
        [ "${#hash}" = 64 ] || fail 'invalid manifest checksum'
        case "$hash" in *[!0-9a-f]*) fail 'invalid manifest checksum' ;; esac
        if [ -z "$expected" ]; then
            [ "$name" = "$package.tar.gz" ] || fail 'unexpected archive name'
            expected=$hash
            continue
        fi
        case "$name" in "$package.tar.gz.part"[0-9][0-9][0-9]) ;; *) fail 'unexpected archive part name' ;; esac
        part_number=$((part_number + 1))
        if [ "$part_count" -gt 1 ]; then
            printf 'Downloading part %s/%s\n' "$part_number" "$part_count" >&2
        fi
        fetch "releases/$version/$name" "$work/part" progress
        [ "$(sha "$work/part")" = "$hash" ] || fail 'archive part checksum mismatch'
        cat "$work/part" >> "$archive"
    done < "$work/$component.manifest"
    progress 3 'Verifying the download'
    [ -n "$expected" ] && [ "$(sha "$archive")" = "$expected" ] || fail 'archive checksum mismatch'
    tar -tzf "$archive" > "$work/entries"
    awk ' /^\// || /(^|\/)\.\.(\/|$)/ {bad=1} END {exit bad}' "$work/entries" || fail 'unsafe archive path'
    tar -tvzf "$archive" > "$work/types"
    awk 'substr($0,1,1)!="-" && substr($0,1,1)!="d" {bad=1} END {exit bad}' "$work/types" || fail 'archive must contain only regular files and directories'
    progress 4 'Extracting and checking compatibility'
    mkdir "$work/$component"
    tar -xzf "$archive" -C "$work/$component"
    staged="$work/$component"
    [ "$(cat "$staged/VERSION")" = "$version" ] || fail 'package version mismatch'
    [ "$(cat "$staged/PLATFORM")" = "$arch-$libc" ] || fail 'package platform mismatch'
    [ "$(cat "$staged/COMPONENT")" = "$component" ] || fail 'package component mismatch'
    if [ "$component" = core ]; then
        [ "$("$staged/bin/pigeon" --version)" = "pigeon $version" ] || fail 'collector cannot run on this system'
        "$staged/bin/pigeon-tui" --help >/dev/null || fail 'TUI cannot run on this system'
    else
        [ -x "$staged/bin/pigeon-gui" ] || fail 'GUI executable missing'
        QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software "$staged/bin/pigeon-gui" --help >/dev/null || fail 'GUI cannot run on this system'
    fi
done

progress 5 'Installing commands'
mkdir -p "$root/versions" "$bin"
for component in $components; do
    commands='pigeon pigeon-tui'
    [ "$component" = core ] || commands=pigeon-gui
    for command in $commands; do
        link="$bin/$command"
        if [ -e "$link" ] || [ -L "$link" ]; then
            [ -L "$link" ] || fail "refusing to replace existing command: $link"
            case "$(readlink "$link")" in "$root"/versions/*/bin/"$command") ;; *) fail "command belongs to another installation: $link" ;; esac
        fi
    done
done
for component in $components; do
    # Unique destination also permits reinstalling the same version safely.
    destination=$(mktemp -d "$root/versions/$version-$component.XXXXXX")
    cp -R "$work/$component/." "$destination/"
    commands='pigeon pigeon-tui'
    [ "$component" = core ] || commands=pigeon-gui
    for command in $commands; do
        temporary="$bin/.$command.$$"
        ln -s "$destination/bin/$command" "$temporary"
        mv -fT "$temporary" "$bin/$command"
    done
done
progress 6 'Ready'
if [ "$component" = core ]; then
    printf '\nInstalled Pigeon CLI %s. Commands: pigeon, pigeon-tui\n' "$version"
else
    printf '\nInstalled Pigeon GUI %s. Command: pigeon-gui\n' "$version"
fi
case ":${PATH:-}:" in
    *":$bin:"*) ;;
    *) printf 'Add this to your shell configuration: export PATH="%s:$PATH"\n' "$bin" ;;
esac
if [ "$component" = core ]; then
    printf '\nRun: pigeon\n'
    printf 'Capture starts in the background; sudo is requested when needed.\n'
    printf 'Manage: pigeon start | stop | restart | status | logs\n'
    printf 'Database: %s/pigeon.db\n' "$root"
else
    printf 'Viewer: "%s/pigeon-gui" --database "%s/pigeon.db"\n' "$bin" "$root"
    printf 'The collector is installed separately using /cli/install.sh.\n'
fi
