"""Read-only export of a completed Proof recovery artifact; no project execution."""
from __future__ import annotations
import base64
from hashlib import sha1, sha256
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

REPOSITORY = 'TrillionniumFoundation/Hepta'
RUN = 43262449848
HEAD = '4d058332ac0d1ac0071f3ef91f5db45d149cdf5e'
ARTIFACT = 13964771080
ARTIFACT_NAME = 'hia-proof-recovery-v79-r1-development-43262449848-1'
BYTES = 89330390
SHA = '98795dc7c398ba58a5a959c13e7806f37310ab266ed657dc9484d0da8b313e71'
PREFIX = 'proof-recovery-development-evidence/'
SELECTED_SOURCES = ('examples/hia_bootstrap/proof_contract.hiaasm',
                    'docs/HIA_SELFHOST_CORE_SUPPORT.json')

def digest(raw):
    return sha256(raw).hexdigest()

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def safe(name):
    p = PurePosixPath(name)
    if (not name or p.is_absolute() or '\\' in name or '\x00' in name
            or p.as_posix() != name or any(x in ('', '.', '..') for x in p.parts)):
        raise ValueError('ordinary exact relative member path required')
    return name

def meta(raw):
    return {'bytes': len(raw), 'sha256': digest(raw),
            'git_blob_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None

def api(path):
    request = urllib.request.Request(
        'https://api.github.com/repos/' + REPOSITORY + path,
        headers={'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
                 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28',
                 'User-Agent': 'hia-proof-original-artifact-readback'})
    return urllib.request.build_opener(NoRedirect()).open(request, timeout=60)

def main():
    output = Path('original-proof-readback')
    output.mkdir(mode=0o700, exist_ok=False)
    with api('/actions/artifacts/' + str(ARTIFACT)) as response:
        info = json.loads(response.read())
    if (info['id'] != ARTIFACT or info['size_in_bytes'] != BYTES
            or info['digest'] != 'sha256:' + SHA
            or info['workflow_run']['id'] != RUN
            or info['workflow_run']['head_sha'] != HEAD):
        raise ValueError('original artifact identity differs')
    try:
        response = api('/actions/artifacts/' + str(ARTIFACT) + '/zip')
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise
        location = error.headers['Location']
        if urllib.parse.urlsplit(location).scheme != 'https':
            raise ValueError('HTTPS redirect required')
        response = urllib.request.urlopen(location, timeout=60)
    raw = response.read(BYTES + 1)
    response.close()
    if len(raw) != BYTES or digest(raw) != SHA:
        raise ValueError('original whole ZIP differs')
    result = {'schema': 'hia.proof-recovery.original-whitespace-readback.v79.r1',
              'scope': 'READ_ONLY_NO_PROJECT_EXECUTION',
              'run': RUN, 'head': HEAD, 'artifact': ARTIFACT,
              'original_zip': {'bytes': BYTES, 'sha256': SHA}, 'files': {}}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for name in ('source-whitespace.stdout.log', 'source-whitespace.stderr.log',
                     'source-whitespace.terminal.json'):
            value = archive.read(PREFIX + name)
            result['files'][name] = dict(meta(value), text=value.decode('utf-8', 'strict'))
    body = wire(result)
    (output / 'WHITESPACE-READBACK.json').write_bytes(body)
    print('HIA_PROOF_WHITESPACE_READBACK ' + base64.b64encode(body).decode('ascii'), flush=True)
    print('HIA_PROOF_WHITESPACE_SHA256 ' + digest(body), flush=True)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
