#!/usr/bin/env python3
"""Build relocatable Linux release bundles and a Pages download directory."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
# Keep the host's libc/loader and graphics driver interface. Bundle the rest.
SYSTEM = re.compile(r'^(linux-vdso|ld-linux|ld-musl|libc\.so|libc\.musl|libm\.so|libpthread\.so|libdl\.so|librt\.so|libresolv\.so|libutil\.so|libanl\.so|libGL\.so|libEGL\.so|libGLX\.so|libOpenGL\.so|libGLESv2\.so|libGLdispatch\.so|libvulkan\.so)')


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def output(*args):
    return run(*args, stdout=subprocess.PIPE, text=True).stdout.strip()


def digest(path):
    with path.open('rb') as stream:
        checksum = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            checksum.update(chunk)
        return checksum.hexdigest()


def is_elf(path):
    with path.open('rb') as stream:
        return stream.read(4) == b'\x7fELF'


def copy_tree(source, destination):
    if source.exists():
        shutil.copytree(source, destination, dirs_exist_ok=True, symlinks=False)


def bundle_runtime(stage):
    libraries = stage / 'lib'
    libraries.mkdir(exist_ok=True)
    queue = [p for p in stage.rglob('*') if p.is_file() and is_elf(p)]
    seen = set()
    origins = {}
    while queue:
        binary = queue.pop()
        if binary in seen:
            continue
        seen.add(binary)
        result = output('ldd', binary)
        if 'not found' in result:
            raise RuntimeError(f'Unresolved runtime dependency of {binary}:\n{result}')
        for line in result.splitlines():
            match = re.search(r'(?:=>\s+|^\s*)(/\S+)', line)
            if not match:
                continue
            source = Path(match[1])
            if SYSTEM.match(source.name):
                continue
            target = libraries / source.name
            if target.exists():
                if digest(source) != digest(target):
                    raise RuntimeError(f'Conflicting library basename: {source.name}')
            else:
                shutil.copy2(source, target)
                origins[target.name] = str(source)
                queue.append(target)
    # Patch only after dependency collection, so ldd can use the build host paths.
    for binary in seen:
        relative = os.path.relpath(libraries, binary.parent)
        run('patchelf', '--set-rpath', '$ORIGIN/' + relative, binary)
    (stage / 'RUNTIME_DEPENDENCIES.json').write_text(json.dumps(origins, indent=2) + '\n')
    # Keep the installed distribution's third-party notices with the binaries.
    notices = stage / 'LICENSES'
    notices.mkdir()
    packages = set()
    if shutil.which('dpkg-query'):
        candidates = {str(candidate) for source in origins.values()
                      for candidate in [Path(source), Path(source).resolve()]}
        if candidates:
            result = subprocess.run(['dpkg-query', '-S', *sorted(candidates)],
                                    capture_output=True, text=True)
            for line in result.stdout.splitlines():
                packages.add(line.split(': ')[0].split(':')[0])
        if (stage / 'qml').exists():
            for notice in Path('/usr/share/doc').glob('*/copyright'):
                if notice.parent.name.startswith(('libqt6', 'qml6-', 'qt6-')):
                    packages.add(notice.parent.name)
    for package in packages:
        notice = Path('/usr/share/doc') / package / 'copyright'
        if notice.exists():
            shutil.copy2(notice, notices / (package + '.copyright'))
    copy_tree(Path('/usr/share/licenses'), notices / 'distribution')
    if not shutil.which('dpkg-query'):
        for notice in Path('/usr/share/doc').rglob('*'):
            if notice.is_file() and notice.name.lower().startswith(('copying', 'copyright', 'license')):
                relative = notice.relative_to('/usr/share/doc')
                target = notices / 'distribution-doc' / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(notice, target)


def build(args):
    arch = {'x86_64': 'x86_64', 'aarch64': 'aarch64'}.get(platform.machine())
    if platform.system() != 'Linux' or arch is None:
        raise RuntimeError('Build on Linux x86_64 or aarch64')
    libc = 'musl' if list(Path('/lib').glob('ld-musl-*.so.1')) else 'glibc'
    source = ROOT
    build_dir = ROOT / 'release-build' / f'core-{arch}-{libc}'
    stage = build_dir / 'package'
    run('cmake', '-S', source, '-B', build_dir, '-G', 'Ninja',
        '-DCMAKE_BUILD_TYPE=Release', '-DPIGEON_SANITIZE=OFF', '-DBUILD_TESTING=OFF')
    targets = ['pigeon', 'pigeon-tui', 'pigeon-control']
    run('cmake', '--build', build_dir, '--parallel', str(args.jobs), '--target', *targets)
    shutil.rmtree(stage, ignore_errors=True)
    (stage / 'bin').mkdir(parents=True)
    for target in targets:
        name = 'pigeon-collector' if target == 'pigeon' else target
        shutil.copy2(build_dir / target, stage / 'bin' / name)
    (stage / 'share').mkdir(exist_ok=True)
    for helper in ['uninstall.sh', 'autostart.sh', 'service-install.sh', 'database.sh']:
        shutil.copy2(ROOT / 'packaging' / helper, stage / 'share' / helper)
    shutil.copy2(ROOT / 'packaging/pigeon.sh', stage / 'bin' / 'pigeon')
    # Resolve the executable from its public symlink before locating resources.
    executable = stage / 'bin' / 'pigeon-tui'
    executable.rename(stage / 'bin' / 'pigeon-tui.real')
    executable.write_text('''#!/bin/sh
set -eu
self=$(readlink -f "$0")
bundle=$(dirname "$(dirname "$self")")
export TERMINFO_DIRS="$bundle/share/terminfo:${TERMINFO_DIRS:-/etc/terminfo:/lib/terminfo:/usr/share/terminfo}"
if [ "$#" = 0 ]; then
    default_data=$(dirname "$(dirname "$bundle")")
    if [ "$(basename "$(dirname "$bundle")")" != versions ]; then
        default_data=${XDG_DATA_HOME:-$HOME/.local/share}/pigeon
    fi
    data=${PIGEON_DATA_DIR:-$default_data}
    set -- --db "${PIGEON_DATABASE:-$data/pigeon.db}"
fi
exec "$bundle/bin/pigeon-tui.real" "$@"
''')
    executable.chmod(0o755)
    copy_tree(Path('/usr/share/terminfo'), stage / 'share' / 'terminfo')
    copy_tree(Path('/lib/terminfo'), stage / 'share' / 'terminfo')
    bundle_runtime(stage)
    (stage / 'VERSION').write_text(args.version + '\n')
    (stage / 'COMPONENT').write_text('core\n')
    (stage / 'PLATFORM').write_text(f'{arch}-{libc}\n')
    (stage / 'README.md').write_text(
        'Pigeon Linux release\n\nBinaries locate bundled libraries relative to themselves.\n'
        'The host supplies libc/ELF loader, kernel interfaces, and graphics drivers.\n'
        'See RUNTIME_DEPENDENCIES.json and LICENSES for bundled runtime dependencies.\n'
        'No boot service is installed. Existing databases are not changed by installation.\n')
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    name = f'pigeon-core-linux-{arch}-{libc}.tar.gz'
    archive = destination / name
    with archive.open('wb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', dereference=True) as tar:
                for path in sorted(stage.rglob('*')):
                    if not path.is_file():
                        continue
                    info = tar.gettarinfo(str(path), arcname=str(path.relative_to(stage)))
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ''
                    with path.open('rb') as stream:
                        tar.addfile(info, stream)
    for old_part in destination.glob(name + '.part[0-9][0-9][0-9]'):
        old_part.unlink()
    entries = [f'{digest(archive)}  {name}']
    with archive.open('rb') as stream:
        index = 0
        while chunk := stream.read(24 * 1024 * 1024):
            part = destination / f'{name}.part{index:03d}'
            part.write_bytes(chunk)
            entries.append(f'{digest(part)}  {part.name}')
            index += 1
    (destination / name.replace('.tar.gz', '.manifest')).write_text('\n'.join(entries) + '\n')
    print(archive)


def site(args):
    destination = args.output.resolve()
    releases = destination / 'releases' / args.version
    releases.mkdir(parents=True, exist_ok=True)
    seen = set()
    artifact_root = args.artifacts.resolve()
    candidates = [*artifact_root.glob('*'), *artifact_root.glob('*/*')]
    for path in candidates:
        if destination in path.parents:
            continue
        if path.is_file() and path.name.startswith('pigeon-core-') and (path.name.endswith('.manifest') or re.search(r'\.part[0-9]{3}$', path.name)):
            target = releases / path.name
            if path.name in seen:
                raise RuntimeError(f'Duplicate artifact: {path.name}')
            seen.add(path.name)
            shutil.copy2(path, target)
    for stale in releases.iterdir():
        if stale.name not in seen and (stale.name.endswith('.manifest') or re.search(r'\.part[0-9]{3}$', stale.name)):
            stale.unlink()
    manifests = list(releases.glob('*.manifest'))
    if not manifests:
        raise RuntimeError('No release artifacts found')
    if args.complete:
        expected = {f'pigeon-{component}-linux-{arch}-{libc}.manifest'
                    for arch in ['x86_64', 'aarch64']
                    for component, libc in [('core', 'glibc'), ('core', 'musl')]}
        if {p.name for p in manifests} != expected:
            raise RuntimeError('Release is missing required platform artifacts')
    for manifest in manifests:
        entries = manifest.read_text().splitlines()
        combined = hashlib.sha256()
        for entry in entries[1:]:
            checksum, name = entry.split()
            if Path(name).name != name:
                raise RuntimeError('Invalid part filename')
            part = releases / name
            if part.stat().st_size > 24 * 1024 * 1024 or digest(part) != checksum:
                raise RuntimeError(f'Invalid release part: {name}')
            combined.update(part.read_bytes())
        if not entries or combined.hexdigest() != entries[0].split()[0]:
            raise RuntimeError(f'Invalid archive checksum: {manifest.name}')
    shutil.copy2(ROOT / 'packaging/install.sh', destination / 'install.sh')
    (destination / 'latest.txt').write_text(args.version + '\n')
    files = [destination / 'install.sh', destination / 'latest.txt',
             *sorted(p for p in releases.iterdir() if p.is_file())]
    catalog = {'schema': 1, 'component': 'cli', 'version': args.version,
               'files': [{'path': p.relative_to(destination).as_posix(), 'sha256': digest(p)} for p in files]}
    (destination / 'files.json').write_text(json.dumps(catalog, indent=2) + '\n')




def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    builder = commands.add_parser('build')
    builder.add_argument('--jobs', type=int, default=4)
    publisher = commands.add_parser('site')
    publisher.add_argument('--artifacts', type=Path, required=True)
    publisher.add_argument('--complete', action='store_true', help='require all platform bundles for this repository')
    for command in [builder, publisher]:
        command.add_argument('--version', required=True)
        command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', args.version):
        parser.error('version must be X.Y.Z')
    (build if args.command == 'build' else site)(args)


if __name__ == '__main__':
    main()
