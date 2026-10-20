#!/usr/bin/env python3
"""Verify lifecycle client replies and waiting for a graceful collector flush."""
from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

executable = sys.argv[1]

with tempfile.TemporaryDirectory(prefix='pigeon-control-client-') as temporary:
    database = Path(temporary) / 'pigeon.db'
    database.touch()
    path = str(database) + '.control'

    def call(action):
        return subprocess.run([executable, action, str(database)], capture_output=True, text=True, timeout=5)

    @contextmanager
    def server(replies, delay=0):
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(path)
        listener.listen()
        errors = []

        def answer():
            try:
                for expected, reply in replies:
                    connection, _ = listener.accept()
                    with connection:
                        request = b''
                        while not request.endswith(b'\n'):
                            request += connection.recv(128)
                        assert request.decode().strip() == expected
                        connection.sendall(reply.encode())
                time.sleep(delay)
            except Exception as error:
                errors.append(error)
            finally:
                listener.close()
                Path(path).unlink(missing_ok=True)

        thread = threading.Thread(target=answer, daemon=True)
        thread.start()
        try:
            yield
        finally:
            thread.join(timeout=5)
            assert not thread.is_alive(), 'client did not send expected requests'
            assert not errors, errors

    assert call('status').returncode == 1
    assert call('stop').returncode == 0
    with server([('STATUS', 'OK\twlo1\tauto\n')]):
        result = call('status')
        assert result.returncode == 0 and 'wlo1' in result.stdout
    with server([('STATUS', 'ERROR\tNot authorized to control this collector\n')]):
        result = call('status')
        assert result.returncode == 2 and 'Not authorized' in result.stderr
    with server([('STATUS', 'ERROR\tInvalid interface request\n'),
                 ('LIST', 'OK\teth0\tmanual\neth0\tactive\tsupported\n')]):
        result = call('status')
        assert result.returncode == 0 and 'eth0' in result.stdout
    with server([('STOP', 'OK\tStopping\n')], delay=0.25):
        started = time.monotonic()
        assert call('stop').returncode == 0
        assert time.monotonic() - started >= 0.2
        assert not Path(path).exists()

print('Collector control client checks passed')
