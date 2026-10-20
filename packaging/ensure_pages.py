#!/usr/bin/env python3
"""Create the Direct Upload Pages project if missing; never log credentials."""
import json
import os
import urllib.error
import urllib.request

account = os.environ['CLOUDFLARE_ACCOUNT_ID']
token = os.environ['CLOUDFLARE_API_TOKEN']
if not account or not token:
    raise SystemExit('CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID are required')
project = 'piigeon'
url = f'https://api.cloudflare.com/client/v4/accounts/{account}/pages/projects'
headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}


def request(endpoint, data=None):
    req = urllib.request.Request(endpoint, headers=headers, data=data)
    with urllib.request.urlopen(req, timeout=60) as response:
        result = json.load(response)
    if not result.get('success'):
        raise SystemExit('Cloudflare rejected the Pages project request')
    return result['result']


try:
    result = request(f'{url}/{project}')
except urllib.error.HTTPError as error:
    if error.code != 404:
        raise SystemExit(f'Cannot inspect Pages project (HTTP {error.code}); check account and token permissions') from None
    try:
        result = request(url, json.dumps({'name': project, 'production_branch': 'main'}).encode())
    except urllib.error.HTTPError as error:
        raise SystemExit(f'Cannot create Pages project (HTTP {error.code}); check permissions and project-name availability') from None

if result.get('subdomain') != 'piigeon.pages.dev':
    raise SystemExit('Cloudflare did not assign piigeon.pages.dev; the requested address may already be taken')

if result.get('production_branch') != 'main':
    raise SystemExit('The piigeon project must use production branch main')
if (result.get('source') or {}).get('type'):
    raise SystemExit('The piigeon project must use Direct Upload, not Git integration')
if os.environ.get('GITHUB_OUTPUT'):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as outputs:
        first = 'false' if result.get('canonical_deployment') else 'true'
        outputs.write(f'first_deployment={first}\n')

print('Pages project ready: piigeon.pages.dev')
