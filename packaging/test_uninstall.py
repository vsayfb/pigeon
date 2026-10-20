#!/usr/bin/env python3
"""Check component isolation, history preservation and safe command removal."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

script = Path(__file__).with_name('uninstall.sh').resolve()
with tempfile.TemporaryDirectory(prefix='pigeon-uninstall-') as temporary:
    work = Path(temporary)
    root, commands, data = work / 'data space', work / 'bin', work / 'desktop'
    commands.mkdir()
    bundles = {}
    for component in ('core', 'gui'):
        bundle = root / 'versions' / f'0.0.2-{component}.test'
        (bundle / 'bin').mkdir(parents=True)
        (bundle / 'COMPONENT').write_text(component)
        (bundle / 'INSTALL_BIN').write_text(str(commands))
        (bundle / 'INSTALL_DESKTOP_DATA').write_text(str(data))
        names = ['pigeon', 'pigeon-tui'] if component == 'core' else ['pigeon-gui']
        for name in names:
            executable = bundle / 'bin' / name
            executable.write_text('#!/bin/sh\nexit 0\n')
            executable.chmod(0o755)
            (commands / name).symlink_to(executable)
        bundles[component] = bundle
    (root / 'pigeon.db').write_text('history')
    (root / 'pigeon.log').write_text('log')
    (data / 'applications').mkdir(parents=True)
    (root / 'desktop').mkdir()
    entry = '[Desktop Entry]\nX-Pigeon-Managed=true\n'
    desktop = data / 'applications/pigeon-gui.desktop'
    desktop.write_text(entry)
    (root / 'desktop/pigeon-gui.desktop').write_text(entry)
    (root / 'desktop/pigeon.png').write_bytes(b'icon')

    # A command replaced by another program must survive uninstallation.
    (commands / 'pigeon-tui').unlink()
    (commands / 'pigeon-tui').write_text('unrelated')
    subprocess.run(['sh', str(script), str(bundles['gui']), 'gui'], check=True)
    assert not desktop.exists() and not (commands / 'pigeon-gui').is_symlink()
    assert (commands / 'pigeon').exists() and bundles['core'].exists()
    subprocess.run(['sh', str(script), str(bundles['core']), 'core'], check=True)
    assert not (commands / 'pigeon').is_symlink()
    assert (commands / 'pigeon-tui').read_text() == 'unrelated'
    assert (root / 'pigeon.db').read_text() == 'history'
    assert (root / 'pigeon.log').read_text() == 'log'
    assert not (root / 'versions').exists()
print('Uninstall checks passed: component isolation, desktop cleanup, unrelated commands and history preserved')
