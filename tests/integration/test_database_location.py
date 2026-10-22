#!/usr/bin/env python3
"""Change storage with live WAL data; keep original and reject existing targets."""
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile

control = Path(sys.argv[1]).resolve()
source = Path(__file__).resolve().parents[2] / 'packaging'
with tempfile.TemporaryDirectory(prefix='pigeon-storage-') as temporary:
    root = Path(temporary)
    bundle = root / 'versions' / 'test-core'
    (bundle / 'bin').mkdir(parents=True)
    (bundle / 'share').mkdir()
    for name in ('database.sh', 'pigeon.sh'):
        shutil.copy2(source / name, bundle / ('bin/pigeon' if name == 'pigeon.sh' else 'share/database.sh'))
    (bundle / 'bin/pigeon').chmod(0o755)
    shutil.copy2(control, bundle / 'bin/pigeon-control')
    (bundle / 'share/autostart.sh').write_text('#!/bin/sh\necho "Start at boot: off"\n')
    old = root / 'pigeon.db'
    connection = sqlite3.connect(old)
    connection.execute('pragma journal_mode=wal')
    connection.execute('create table history(value text)')
    connection.execute("insert into history values ('recorded traffic')")
    connection.commit()
    target = root / 'new data' / 'new.db'
    command = [str(bundle / 'bin/pigeon'), 'database', str(target)]
    environment = dict(os.environ)
    environment.pop('PIGEON_DATABASE', None)
    environment.pop('PIGEON_DATA_DIR', None)
    result = subprocess.run(command, env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert connection.execute('select value from history').fetchone()[0] == 'recorded traffic'
    with sqlite3.connect(target) as copied:
        assert copied.execute('pragma integrity_check').fetchone()[0] == 'ok'
        assert copied.execute('select value from history').fetchone()[0] == 'recorded traffic'
    assert (root / 'database.conf').read_text().strip() == str(target)
    assert subprocess.check_output([str(bundle / 'bin/pigeon'), 'database'], env=environment, text=True).strip() == str(target)
    existing = root / 'existing.db'
    existing.write_text('keep this')
    result = subprocess.run([str(bundle / 'bin/pigeon'), 'database', str(existing)], env=environment, capture_output=True)
    assert result.returncode != 0 and existing.read_text() == 'keep this'
    assert (root / 'database.conf').read_text().strip() == str(target)
    connection.close()
print('Database location: WAL history preserved, default persisted, existing destination protected')
