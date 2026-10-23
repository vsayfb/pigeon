#!/usr/bin/env python3
"""Verify exact-key and clear-all deletion through the installed control helper."""
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

pigeon, helper, fixture = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='pigeon-history-control-') as temporary:
    database = Path(temporary) / 'history.db'
    subprocess.run([pigeon, '--db', str(database), '--local-ip', '192.0.2.10', '-r', fixture],
                   check=True, capture_output=True)
    with sqlite3.connect(database) as db:
        rows = db.execute('SELECT us_ip, remote_ip, remote_port, protocol, application FROM conversations').fetchall()
        assert len(rows) == 2
        us, remote, port, protocol, application = rows[0]
        identity = (bytes([len(us)]) + us + bytes([len(remote)]) + remote +
                    port.to_bytes(2, 'big') + bytes([protocol]) + application.encode()).hex()
        subprocess.run([helper, 'delete', str(database), identity], check=True)
        assert db.execute('SELECT count(*) FROM conversations').fetchone()[0] == 1
        assert subprocess.run([helper, 'delete', str(database), identity + '00'], capture_output=True).returncode != 0
        assert db.execute('SELECT count(*) FROM conversations').fetchone()[0] == 1
        subprocess.run([helper, 'clear', str(database)], check=True)
        assert db.execute('SELECT count(*) FROM conversations').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM dns_cache').fetchone()[0] == 0
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    assert not Path(str(database) + '.control').exists()
print('History control: exact identity deletion, invalid-key rejection, clear history, integrity intact')
