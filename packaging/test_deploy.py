#!/usr/bin/env python3
"""Exercise static deployment preservation without app builds or network calls."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

spec = importlib.util.spec_from_file_location('assembly', Path(__file__).with_name('assemble.py'))
assembly = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assembly)


def component(directory, kind, version):
    package = 'core' if kind == 'cli' else 'gui'
    files = {'install.sh': f'install {kind}'.encode(), 'latest.txt': version.encode(),
             f'releases/{version}/pigeon-{package}-linux-x86_64-glibc.tar.gz.part000': b'archive part',
             f'releases/{version}/pigeon-{package}-linux-x86_64-glibc.manifest': b'manifest'}
    directory.mkdir()
    for name, data in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    catalog = {'schema': 1, 'component': kind, 'version': version,
               'files': [{'path': name, 'sha256': hashlib.sha256(data).hexdigest()}
                         for name, data in files.items()]}
    (directory / 'files.json').write_text(json.dumps(catalog))


def published(directory):
    return {'https://example.test/' + path.relative_to(directory).as_posix(): path.read_bytes()
            for path in directory.rglob('*') if path.is_file()}


with tempfile.TemporaryDirectory(prefix='pigeon-pages-check-') as temporary:
    work = Path(temporary)
    component(work / 'cli', 'cli', '0.0.1')
    component(work / 'gui', 'gui', '0.1.0')
    component(work / 'cli-new', 'cli', '0.0.2')
    assembly.COMPONENT = 'cli'
    assembly.assemble(work / 'cli', work / 'first', first=True)
    assert (work / 'first/cli/install.sh').exists()
    assert not (work / 'first/gui').exists()
    live = published(work / 'first')
    assembly.fetch = lambda url: live.get(url)

    # GUI publishing carries all CLI bytes forward.
    assembly.COMPONENT = 'gui'
    assembly.assemble(work / 'gui', work / 'second', 'https://example.test')
    assert published(work / 'second')['https://example.test/cli/files.json'] == live['https://example.test/cli/files.json']
    for path in (work / 'first/cli').rglob('*'):
        if path.is_file():
            assert path.read_bytes() == (work / 'second/cli' / path.relative_to(work / 'first/cli')).read_bytes()
    live = published(work / 'second')

    # Updating CLI leaves GUI intact, including its independent version.
    assembly.COMPONENT = 'cli'
    assembly.assemble(work / 'cli-new', work / 'third', 'https://example.test')
    for path in (work / 'second/gui').rglob('*'):
        if path.is_file():
            assert path.read_bytes() == (work / 'third/gui' / path.relative_to(work / 'second/gui')).read_bytes()
    assert (work / 'third/cli/latest.txt').read_text() == '0.0.2'
    assert not (work / 'third/cli/releases/0.0.1').exists()

    # Corrupt or incomplete published components must stop the deployment.
    part = next(key for key in live if '/gui/' in key and '.part' in key)
    live[part] = b'corrupt'
    try:
        assembly.assemble(work / 'cli-new', work / 'corrupt', 'https://example.test')
        raise AssertionError('corrupt download accepted')
    except RuntimeError as error:
        assert 'verify' in str(error)
    del live['https://example.test/gui/files.json']
    try:
        assembly.assemble(work / 'cli-new', work / 'missing-catalog', 'https://example.test')
        raise AssertionError('existing component without catalog accepted')
    except RuntimeError as error:
        assert 'without files.json' in str(error)
    live.clear()
    assembly.assemble(work / 'cli-new', work / 'unpublished-other', 'https://example.test')
    assert not (work / 'unpublished-other/gui').exists()

print('Static deployment checks passed: first publish, independent updates, preservation, corrupt/missing downloads')
