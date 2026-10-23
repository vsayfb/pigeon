#!/usr/bin/env python3
"""Exercise service installation using fake systemctl and isolated system paths."""
import os
from pathlib import Path
import subprocess
import tempfile

source = Path(__file__).parent
with tempfile.TemporaryDirectory(prefix='pigeon-boot-check-') as temporary:
    work = Path(temporary)
    bundle = work / 'bundle'
    (bundle / 'bin').mkdir(parents=True)
    (bundle / 'COMPONENT').write_text('core')
    for name in ('pigeon-control', 'pigeon-collector'):
        binary = bundle / 'bin' / name
        binary.write_text('#!/bin/sh\nexit 0\n')
        binary.chmod(0o755)
    mocks = work / 'mocks'
    mocks.mkdir()
    for name, body in {
        'id': 'echo 0',
        'chown': 'exit 0',
        'systemctl': 'printf "%s\\n" "$*" >> "$BOOT_TEST_LOG"',
    }.items():
        path = mocks / name
        path.write_text('#!/bin/sh\n' + body + '\n')
        path.chmod(0o755)
    lib, units = work / 'lib', work / 'units'
    units.mkdir()
    helper = work / 'service-install.sh'
    helper.write_text((source / 'service-install.sh').read_text()
                      .replace('/usr/local/lib', str(lib))
                      .replace('/etc/systemd/system', str(units)))
    log = work / 'systemctl.log'
    env = os.environ | {'PATH': str(mocks) + ':' + os.environ['PATH'], 'BOOT_TEST_LOG': str(log)}
    database = work / 'data space % $cash' / 'pigeon.db'
    args = ['sh', str(helper), 'on', '1000', str(bundle), str(database)]
    subprocess.run(args, env=env, check=True)
    unit = units / 'pigeon-1000.service'
    text = unit.read_text()
    assert 'Restart=on-failure' in text and 'RestartSec=5' in text
    assert 'Environment=SUDO_UID=1000' in text
    assert 'data space %% $$cash' in text
    assert str(bundle / 'bin/pigeon-collector') not in text
    snapshot = lib / 'pigeon-1000/bin/pigeon-collector'
    assert snapshot.exists() and not snapshot.stat().st_mode & 0o022
    assert (lib / 'pigeon-1000').stat().st_mode & 0o777 == 0o755
    assert (lib / 'pigeon-1000/INSTALL_ROOT').stat().st_mode & 0o777 == 0o644
    assert 'enable --now pigeon-1000.service' in log.read_text()
    subprocess.run(args[:2] + ['off'] + args[3:], env=env, check=True)
    assert snapshot.exists() and 'disable pigeon-1000.service' in log.read_text()
    assert 'disable --now' not in log.read_text()
    subprocess.run(args[:2] + ['remove'] + args[3:], env=env, check=True)
    assert not snapshot.exists() and not unit.exists()
    assert 'disable --now pigeon-1000.service' in log.read_text()
print('Boot service checks passed: root snapshot, escaping, enable, disable and removal')

# Exercise installer defaults and upgrade preferences without sudo or real services.
import hashlib
import io
import platform
import tarfile
with tempfile.TemporaryDirectory(prefix='pigeon-boot-installer-') as temporary:
    work = Path(temporary)
    release = work / 'release'
    version = '0.0.3'
    arch = platform.machine()
    libc = 'musl' if list(Path('/lib').glob('ld-musl-*.so.1')) else 'glibc'
    package = f'pigeon-core-linux-{arch}-{libc}'
    files = {
        'VERSION': version.encode(), 'PLATFORM': f'{arch}-{libc}'.encode(), 'COMPONENT': b'core',
        'bin/pigeon': f'#!/bin/sh\necho "pigeon {version}"\n'.encode(),
        'bin/pigeon-tui': b'#!/bin/sh\nexit 0\n',
        'share/autostart.sh': b'#!/bin/sh\nprintf "%s\\n" "$4" > "$2/autostart.conf"\n',
    }
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(content), 0o755
            tar.addfile(info, io.BytesIO(content))
    directory = release / 'releases' / version
    directory.mkdir(parents=True)
    content = archive.getvalue()
    checksum = hashlib.sha256(content).hexdigest()
    (directory / f'{package}.tar.gz.part000').write_bytes(content)
    (directory / f'{package}.manifest').write_text(
        f'{checksum} {package}.tar.gz\n{checksum} {package}.tar.gz.part000\n')
    (release / 'latest.txt').write_text(version)
    # Force the supported-system branch using only an isolated marker directory.
    marker = work / 'systemd-running'
    marker.mkdir()
    installer = work / 'install.sh'
    installer.write_text((source / 'install.sh').read_text().replace('/run/systemd/system', str(marker)))
    mock = work / 'mocks'
    mock.mkdir()
    (mock / 'systemctl').write_text('#!/bin/sh\nexit 0\n')
    (mock / 'systemctl').chmod(0o755)
    root = work / 'data'
    env = os.environ | {'PIGEON_INSTALL_ROOT': str(root), 'PIGEON_BIN_DIR': str(work/'bin'),
                        'PATH': str(mock) + ':' + os.environ['PATH']}
    for options, expected in [([], 'on'), (['--no-autostart'], 'off'), ([], 'off')]:
        subprocess.run(['sh', str(installer), '--from', str(release), *options],
                       env=env, check=True, capture_output=True)
        assert (root / 'autostart.conf').read_text().strip() == expected
print('Boot installer checks passed: default on, explicit opt-out, off preserved across upgrades')
