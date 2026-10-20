#!/usr/bin/env python3
"""Preserve the other published component, then assemble a static Pages deploy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import time
import urllib.error
import urllib.request

COMPONENT = 'cli'
BASE = 'https://piigeon.pages.dev'


def fetch(url):
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={'Cache-Control': 'no-cache'})
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            if attempt == 2:
                raise RuntimeError(f'Cannot preserve published files: HTTP {error.code}') from None
        except (OSError, TimeoutError):
            if attempt == 2:
                raise RuntimeError('Cannot reach the published site; refusing to discard the other component') from None
        time.sleep(attempt + 1)


def restore_other(base, component, destination):
    catalog_bytes = fetch(f'{base}/{component}/files.json')
    if catalog_bytes is None:
        for filename in ['install.sh', 'latest.txt']:
            if fetch(f'{base}/{component}/{filename}') is not None:
                raise RuntimeError(f'{component} is published without files.json; refusing to discard it')
        print(f'No {component} release published yet')
        return
    catalog = json.loads(catalog_bytes)
    if catalog.get('schema') != 1 or catalog.get('component') != component:
        raise RuntimeError('Invalid published file catalog')
    version = catalog.get('version', '')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise RuntimeError('Invalid published release version')
    files = catalog.get('files')
    if not isinstance(files, list) or not files or len(files) > 10000:
        raise RuntimeError('Invalid published file list')
    package = 'core' if component == 'cli' else 'gui'
    pattern = re.compile(rf'(install\.sh|latest\.txt|releases/{re.escape(version)}/pigeon-{package}-linux-(x86_64|aarch64)-(glibc|musl)\.(manifest|tar\.gz\.part[0-9]{{3}}))')
    seen = set()
    for entry in files:
        name, checksum = entry.get('path', ''), entry.get('sha256', '')
        if not pattern.fullmatch(name) or name in seen or not re.fullmatch(r'[0-9a-f]{64}', checksum):
            raise RuntimeError('Unsafe or duplicate published file entry')
        seen.add(name)
        data = fetch(f'{base}/{component}/{name}')
        if data is None or hashlib.sha256(data).hexdigest() != checksum:
            raise RuntimeError(f'Cannot verify published {component}/{name}; refusing to deploy')
        target = destination / component / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    if not {'install.sh', 'latest.txt'}.issubset(seen):
        raise RuntimeError('Published catalog is missing its installer or version')
    (destination / component / 'files.json').write_bytes(catalog_bytes)
    print(f'Preserved {component} {version}: {len(files)} files')


def assemble(source, destination, base=BASE, first=False):
    if destination.exists() and any(destination.iterdir()):
        raise RuntimeError('Deployment output must be empty')
    destination.mkdir(parents=True, exist_ok=True)
    other = 'gui' if COMPONENT == 'cli' else 'cli'
    if not first:
        restore_other(base.rstrip('/'), other, destination)
    shutil.copytree(source, destination / COMPONENT)
    shutil.copytree(Path(__file__).parent / 'site', destination, dirs_exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base-url', default=BASE)
    args = parser.parse_args()
    assemble(args.source, args.output, args.base_url,
             first=os.environ.get('PIGEON_FIRST_DEPLOYMENT') == 'true')


if __name__ == '__main__':
    main()
