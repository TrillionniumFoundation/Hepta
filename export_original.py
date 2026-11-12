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
RUN = 43265223561
HEAD = '4ac2fd31d88b9b31ab4c25fd1b28aa6a49b9e3c5'
ARTIFACT = 13964439231
ARTIFACT_NAME = 'hia-proof-recovery-v79-r2-development-43265223561-1'
BYTES = 91672293
SHA = '8e480bfb6a3a6e9109db1cb15f591f1a26eb30490c1b04a4cff97c3b709649c3'
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
        original_metadata = response.read()
    info = json.loads(original_metadata)
    if (info['id'] != ARTIFACT or info['name'] != ARTIFACT_NAME
            or info['size_in_bytes'] != BYTES or info['digest'] != 'sha256:' + SHA
            or info['expired'] is not False
            or info['workflow_run']['id'] != RUN or info['workflow_run']['head_sha'] != HEAD):
        raise ValueError('authoritative original artifact identity differs')
    (output / 'original-artifact-metadata.json').write_bytes(original_metadata)
    try:
        response = api('/actions/artifacts/' + str(ARTIFACT) + '/zip')
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise
        location = error.headers['Location']
        if urllib.parse.urlsplit(location).scheme != 'https':
            raise ValueError('artifact redirect must use HTTPS')
        # The repository token is deliberately not forwarded to blob storage.
        response = urllib.request.urlopen(urllib.request.Request(
            location, headers={'User-Agent': 'hia-proof-original-artifact-readback'}), timeout=60)
    original_zip = output / 'original-artifact.zip'
    received = 0
    checksum = sha256()
    with response, original_zip.open('xb') as target:
        while True:
            block = response.read(1 << 20)
            if not block:
                break
            received += len(block)
            if received > BYTES:
                raise ValueError('original ZIP exceeds frozen extent')
            checksum.update(block)
            target.write(block)
    if received != BYTES or checksum.hexdigest() != SHA:
        raise ValueError('complete original ZIP bytes differ')
    members = {}
    exported = {}
    binary_files = {}
    tar_name = PREFIX + 'complete-development-source.tar.gz'
    manifest_name = PREFIX + 'frozen-source.json'
    with zipfile.ZipFile(original_zip) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('duplicate original ZIP member')
        for item in archive.infolist():
            name = safe(item.filename.rstrip('/'))
            if item.is_dir():
                continue
            # ZipFile.read checks each original CRC; no extraction executes code.
            raw = archive.read(item)
            members[name] = dict(meta(raw), crc32=format(item.CRC, '08x'),
                transport_mode=format((item.external_attr >> 16) & 0o777, '04o'))
            if not name.startswith(PREFIX):
                continue
            relative = name[len(PREFIX):]
            parts = PurePosixPath(relative).parts
            selected = (len(parts) <= 2 and relative.endswith(('.log', '.json')))
            if relative.endswith('.source.json') or (relative.startswith('source-') and not relative.endswith('.log')):
                selected = False
            if relative in ('ARTIFACT-FILES.json', 'TEXT-CAPSULE.json', 'TEXT-CAPSULE.zlib.json'):
                selected = False
            if relative in ('REPORT.json', 'frozen-source.json', 'actual-table.json',
                            'component-85/REPORT.json', 'original-proof-40/report.json'):
                selected = True
            if relative == 'build/proof-contract.image.bin':
                binary_files[name] = dict(meta(raw), encoding='base64', data=base64.b64encode(raw).decode('ascii'))
            if selected:
                text = raw.decode('utf-8', 'strict')
                exported[name] = dict(meta(raw), text=text, source='original ZIP bytes')
        frozen = json.loads(archive.read(manifest_name))
        source_count = 0
        source_names = set()
        with archive.open(tar_name) as compressed:
            with tarfile.open(fileobj=compressed, mode='r|gz') as source_tar:
                for item in source_tar:
                    name = safe(item.name)
                    if not name.startswith('source/') or not item.isfile():
                        raise ValueError('original complete-source member type differs')
                    relative = safe(name[len('source/'):])
                    if relative in source_names or relative not in frozen:
                        raise ValueError('original complete-source member inventory differs')
                    source_names.add(relative)
                    raw = source_tar.extractfile(item).read()
                    expected = frozen[relative]
                    observed = meta(raw)
                    if (any(observed[key] != expected[key] for key in observed)
                            or format(item.mode & 0o777, '04o') != expected['posix_mode']):
                        raise ValueError('original full source bytes/mode differs: ' + relative)
                    source_count += 1
                    if relative in SELECTED_SOURCES:
                        exported['complete-source/' + relative] = dict(observed,
                            text=raw.decode('utf-8', 'strict'),
                            mode=format(item.mode & 0o777, '04o'),
                            source='original complete-development-source.tar.gz')
        if source_names != set(frozen) or source_count != 3201:
            raise ValueError('complete original3201 source identity differs')
    report = {'schema': 'hia.proof-recovery.original-artifact-readback.v79.r2',
              'scope': 'READ_ONLY_NO_PROJECT_IMPORT_OR_TEST_OR_COMPILATION',
              'original_run': RUN, 'original_head': HEAD, 'original_artifact': ARTIFACT,
              'original_zip': {'bytes': BYTES, 'sha256': SHA},
              'all_zip_members': members, 'source_files_verified': source_count,
              'prior_r1_failure_retained': True, 'current_source_cold': False,
              'whole_stack_native': False, 'files': exported, 'binary_files': binary_files}
    raw = wire(report)
    (output / 'READBACK.json').write_bytes(raw)
    compressed = zlib.compress(raw, 9)
    encoded = base64.b64encode(compressed).decode('ascii')
    capsule = {'schema': 'hia.zlib-source-capsule.v1', 'encoding': 'zlib+base64',
               'source_packet': dict(meta(raw), mode='100644'), 'payload': encoded}
    body = wire(capsule)
    (output / 'READBACK.zlib.json').write_bytes(body)
    header = {'capsule': meta(body), 'packet': meta(raw),
              'payload_chars': len(encoded), 'chunks': (len(encoded) + 15999) // 16000,
              'original_zip_verified': True, 'all_zip_members': len(members),
              'source_files_verified': source_count}
    print('HIA_PROOF_READBACK_HEADER ' + json.dumps(header, sort_keys=True), flush=True)
    for index, start in enumerate(range(0, len(encoded), 16000)):
        print('HIA_PROOF_READBACK_CHUNK ' + str(index) + ' ' + encoded[start:start + 16000],
              flush=True)
    print('HIA_PROOF_READBACK_COMPLETE ' + digest(body), flush=True)
    # Keep the byte-identical original ZIP as an independently downloadable artifact.
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
