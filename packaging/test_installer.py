#!/usr/bin/env python3
"""Check install, reinstall, command collisions and corrupt downloads locally."""
import argparse
import os
import platform
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--site', type=Path, required=True)
args = parser.parse_args()
installer = Path(__file__).with_name('install.sh').resolve()

with tempfile.TemporaryDirectory(prefix='pigeon-installer-test-') as temporary:
    work = Path(temporary)
    site = work / 'site'
    shutil.copytree(args.site, site)
    root, commands = work / 'data', work / 'bin'
    environment = dict(os.environ, PIGEON_INSTALL_ROOT=str(root), PIGEON_BIN_DIR=str(commands))

    def install(success=True):
        result = subprocess.run(['sh', str(installer), '--from', str(site)],
                                env=environment, capture_output=True, text=True)
        assert (result.returncode == 0) == success, result.stdout + result.stderr
        return result

    # Never overwrite an unrelated command, even after all downloads succeed.
    commands.mkdir()
    (commands / 'pigeon').write_text('existing command')
    assert 'refusing to replace' in install(False).stderr
    assert (commands / 'pigeon').read_text() == 'existing command'
    assert not list(root.glob('versions/*'))
    (commands / 'pigeon').unlink()

    install()
    first = (commands / 'pigeon').resolve()
    assert (commands / 'pigeon').is_symlink()
    assert (commands / 'pigeon-tui').is_symlink()
    version = subprocess.check_output([str(commands / 'pigeon'), '--version'], text=True)
    assert version.startswith('pigeon ')
    assert subprocess.check_output([str(commands / 'pigeon'), 'capture', '--version'], text=True) == version
    assert (first.parent / 'pigeon-collector').is_file()
    assert (first.parent / 'pigeon-control').is_file()
    status = subprocess.run([str(commands / 'pigeon'), 'status'], capture_output=True, text=True)
    assert status.returncode == 1 and 'stopped' in status.stdout
    assert not (root / 'pigeon.db').exists()  # Status must not start capture.

    database = root / 'pigeon.db'
    database.write_bytes(b'preserve existing history')
    install()
    second = (commands / 'pigeon').resolve()
    assert first != second and first.exists()
    assert database.read_bytes() == b'preserve existing history'

    # Failed verification must leave the currently active commands untouched.
    libc = 'musl' if list(Path('/lib').glob('ld-musl-*.so.1')) else 'glibc'
    manifest = next(site.glob(f'releases/*/pigeon-core-linux-{platform.machine()}-{libc}.manifest'))
    part_name = manifest.read_text().splitlines()[1].split()[1]
    with (manifest.parent / part_name).open('ab') as stream:
        stream.write(b'corruption')
    assert 'checksum mismatch' in install(False).stderr
    assert (commands / 'pigeon').resolve() == second
    assert database.read_bytes() == b'preserve existing history'

    # Exercise the public uninstall command against the installed bundle.
    gui = root / 'versions' / 'gui-preserve'
    gui.mkdir()
    (gui / 'COMPONENT').write_text('gui')
    subprocess.run([str(commands / 'pigeon'), 'uninstall'], env=environment, check=True)
    assert database.read_bytes() == b'preserve existing history'
    assert gui.exists()
    assert not (commands / 'pigeon').is_symlink()
    assert not (commands / 'pigeon-tui').is_symlink()
    assert not first.exists() and not second.exists()

print('Installer checks passed: collision, install, reinstall, corrupt download, history preservation')
