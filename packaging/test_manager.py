#!/usr/bin/env python3
"""Exercise the installed command manager with a fake collector, never sudo/capture."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--control', type=Path, required=True)
args = parser.parse_args()

with tempfile.TemporaryDirectory(prefix='pigeon-manager-') as temporary:
    root = Path(temporary) / 'data space'
    binaries = root / 'versions' / 'test-core' / 'bin'
    binaries.mkdir(parents=True)
    mocks = Path(temporary) / 'mocks'
    mocks.mkdir()
    shutil.copy2(Path(__file__).with_name('pigeon.sh'), binaries / 'pigeon')
    shutil.copy2(args.control, binaries / 'pigeon-control')
    sudo_log = Path(temporary) / 'sudo.log'
    (mocks / 'id').write_text('#!/bin/sh\necho 1000\n')
    (mocks / 'sudo').write_text('''#!/bin/sh
printf '%s\\n' "$1" >> "$MOCK_SUDO_LOG"
case "$1" in -v) exit 0 ;; -n) shift; exec "$@" ;; esac
exit 2
''')
    for path in mocks.iterdir():
        path.chmod(0o755)
    (binaries / 'pigeon-tui').write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
Path(os.environ['MOCK_TUI_ARGS']).write_text(json.dumps(sys.argv[1:]))
''')
    (binaries / 'pigeon-collector').write_text('''#!/usr/bin/env python3
import os, socket, sys, time
from pathlib import Path
if sys.argv[1:] == ['--version']:
    print('pigeon test')
    sys.exit(0)
if '--background' in sys.argv:
    if os.fork():
        sys.exit(0)
    os.setsid()
database = Path(sys.argv[sys.argv.index('--db') + 1])
database.touch()
Path(str(database) + '.pid').write_text(str(os.getpid()))
listener = socket.socket(socket.AF_UNIX)
path = str(database) + '.control'
listener.bind(path)
listener.listen()
while True:
    connection, _ = listener.accept()
    with connection:
        request = b''
        while not request.endswith(b'\\n'):
            request += connection.recv(128)
        if request.strip() == b'STOP':
            connection.sendall(b'OK\\tStopping\\n')
            break
        connection.sendall(b'OK\\twlo1\\tauto\\n')
time.sleep(0.2)
Path(str(database) + '.flushed').touch()
listener.close()
Path(path).unlink()
''')
    for name in ['pigeon-tui', 'pigeon-collector']:
        (binaries / name).chmod(0o755)
    arguments = Path(temporary) / 'tui.json'
    environment = dict(os.environ, PATH=str(mocks) + ':' + os.environ['PATH'],
                       MOCK_SUDO_LOG=str(sudo_log), MOCK_TUI_ARGS=str(arguments))
    environment.pop('PIGEON_DATA_DIR', None)
    environment.pop('PIGEON_DATABASE', None)

    def call(*commands):
        return subprocess.run([str(binaries / 'pigeon'), *commands], env=environment,
                              capture_output=True, text=True, timeout=20)

    def succeed(*commands):
        result = call(*commands)
        if result.returncode != 0:
            log = root / 'pigeon.log'
            details = log.read_text() if log.exists() else ''
            raise AssertionError(f'{commands}: {result.stdout}{result.stderr}{details}')
        return result

    try:
        succeed('--help')
        assert call('capture', '--version').stdout.strip() == 'pigeon test'
        assert call('status').returncode == 1
        succeed('stop')
        assert call('start', '--db', '/wrong').returncode != 0
        succeed('start')
        pid = (root / 'pigeon.db.pid').read_text()
        assert os.getsid(int(pid)) != os.getsid(0)
        assert call('restart', '--db', '/wrong').returncode != 0
        assert call('status').returncode == 0
        succeed('start')
        assert (root / 'pigeon.db.pid').read_text() == pid
        assert sudo_log.read_text().splitlines().count('-v') == 1
        succeed()
        assert json.loads(arguments.read_text()) == ['--db', str(root / 'pigeon.db')]
        assert call('status').returncode == 0  # Closing the TUI leaves capture alive.
        succeed('restart')
        assert (root / 'pigeon.db.pid').read_text() != pid
        assert (root / 'pigeon.db.flushed').exists()
        succeed('stop')
        assert call('status').returncode == 1
        succeed('stop')
    finally:
        call('stop')

print('Manager checks passed: start, duplicate start, TUI defaults, restart, graceful stop, no real sudo/capture')
