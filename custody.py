#!/usr/bin/env python3
"""Retain one original GitHub artifact as verified contiguous byte parts.

No original workflow or product test is run. The API token is used only on
api.github.com. The signed storage GET uses a separate opener with no token,
cookies, proxy credentials or redirects. Signed URLs are never logged/saved.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = 'hepta.hia.artifact-byte-custody-target.v1'
REPOSITORY = 'TrillionniumFoundation/Hepta'
API_ORIGIN = 'https://api.github.com'
FIELDS = {'schema','repository','artifact_id','artifact_name','original_run_id',
          'original_run_attempt','original_job_id','original_head_sha','original_conclusion',
          'size_in_bytes','sha256','part_bytes','part_count','original_download_refusal_sha256'}
HARNESS_FILES = {'.github/workflows/custody.yml':'custody.yml', 'custody.py':'custody.py',
                 'target.json':'target.json', 'original-download-refusal.json':'original-download-refusal.json',
                 'README.md':'README.md'}


class CustodyError(Exception):
    """Messages contain only fixed text and public numeric/hash identities."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def opener():
    # Explicit empty proxy map avoids inherited proxy-auth credentials. Neither
    # opener carries cookie/auth state from the other origin.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')


def load_target(path):
    value = json.loads(Path(path).read_bytes())
    if not isinstance(value,dict) or set(value)!=FIELDS or value['schema']!=SCHEMA or value['repository']!=REPOSITORY:
        raise CustodyError('unexpected fixed custody target schema or repository')
    for key in ('artifact_id','original_run_id','original_run_attempt','original_job_id','size_in_bytes','part_bytes','part_count'):
        if type(value[key]) is not int or value[key] <= 0:
            raise CustodyError('invalid positive integer in fixed target')
    if (value['part_bytes'] > 239_000_000 or value['part_count'] != 3
            or math.ceil(value['size_in_bytes']/value['part_bytes']) != 3
            or value['original_conclusion'] not in {'failure', 'success'}
            or not re.fullmatch(r'[0-9a-f]{40}', value['original_head_sha'])
            or not re.fullmatch(r'[0-9a-f]{64}', value['sha256'])
            or not re.fullmatch(r'[0-9a-f]{64}', value['original_download_refusal_sha256'])
            or not isinstance(value['artifact_name'],str) or not value['artifact_name']):
        raise CustodyError('fixed target count, bounds, failure scope or digest differs')
    return value


def api_request(path, token):
    if not path.startswith('/repos/' + REPOSITORY + '/actions/'):
        raise CustodyError('API request is outside the fixed repository action scope')
    return urllib.request.Request(API_ORIGIN + path, headers={
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'hia-original-artifact-byte-custody',
    }, method='GET')


def read_api_json(client, request, destination):
    with client.open(request, timeout=60) as response:
        if response.status != 200:
            raise CustodyError('GitHub metadata response was not HTTP 200')
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise CustodyError('GitHub metadata exceeded its fixed read bound')
    value = json.loads(raw)
    # Preserve the original API body, without normalization.
    destination.write_bytes(raw)
    return value


def original_redirect(client, request):
    try:
        response = client.open(request, timeout=60)
    except urllib.error.HTTPError as error:
        try:
            if error.code != 302:
                raise CustodyError('original archive API did not return HTTP 302') from None
            location = error.headers.get('Location')
        finally:
            error.close()
    else:
        response.close()
        raise CustodyError('archive API unexpectedly followed or omitted its redirect')
    parsed = urllib.parse.urlsplit(location or '')
    if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
        raise CustodyError('archive redirect did not supply an ordinary HTTPS storage URL')
    return location


def storage_request(location):
    request = urllib.request.Request(location, headers={'Accept':'application/octet-stream'}, method='GET')
    if any(key.lower() in {'authorization','proxy-authorization','cookie'} for key, _ in request.header_items()):
        raise CustodyError('storage request unexpectedly contains an authorization or cookie header')
    return request


def download_original(client, request, target, destination):
    observed = hashlib.sha256(); count = 0
    with client.open(request, timeout=60) as response, destination.open('xb') as stream:
        if response.status != 200:
            raise CustodyError('signed storage response was not HTTP 200')
        length = response.headers.get('Content-Length')
        if length is not None and (not length.isdecimal() or int(length) != target['size_in_bytes']):
            raise CustodyError('storage Content-Length differs from original GitHub metadata')
        while True:
            block = response.read(min(1 << 20, target['size_in_bytes'] - count + 1))
            if not block: break
            count += len(block)
            if count > target['size_in_bytes']:
                raise CustodyError('original ZIP exceeds its declared byte count')
            stream.write(block); observed.update(block)
    if count != target['size_in_bytes'] or observed.hexdigest() != target['sha256']:
        raise CustodyError('downloaded original ZIP size or SHA-256 differs')
    return {'bytes': count, 'sha256': observed.hexdigest()}


def split_original(original, target, output):
    # Re-read the entire file while splitting, then independently read back all
    # parts in order before admitting their metadata for upload.
    combined = hashlib.sha256(); parts = []; offset = 0
    with original.open('rb') as stream:
        for index in range(1, target['part_count'] + 1):
            count = min(target['part_bytes'], target['size_in_bytes'] - offset)
            directory = output / ('part-' + str(index)); directory.mkdir()
            part = directory / ('original.zip.part-' + format(index, '03d'))
            part_hash = hashlib.sha256(); written = 0
            with part.open('xb') as destination:
                while written < count:
                    block = stream.read(min(1 << 20, count - written))
                    if not block: raise CustodyError('original ZIP ended during splitting')
                    destination.write(block); written += len(block)
                    part_hash.update(block); combined.update(block)
            parts.append({'index': index, 'file': part.name, 'offset': offset, 'bytes': written,
                          'end_offset_exclusive': offset + written, 'sha256': part_hash.hexdigest()})
            offset += written
        if stream.read(1): raise CustodyError('original ZIP gained bytes while splitting')
    if offset != target['size_in_bytes'] or combined.hexdigest() != target['sha256']:
        raise CustodyError('original ZIP changed between download and splitting')
    readback = hashlib.sha256(); readback_count = 0
    for row in parts:
        part = output / ('part-' + str(row['index'])) / row['file']
        if sha(part) != row['sha256'] or part.stat().st_size != row['bytes']:
            raise CustodyError('part readback differs')
        with part.open('rb') as stream:
            while block := stream.read(1 << 20):
                readback.update(block); readback_count += len(block)
    if readback_count != target['size_in_bytes'] or readback.hexdigest() != target['sha256']:
        raise CustodyError('ordered part concatenation differs from original ZIP')
    return parts


def transfer(args):
    target_path = args.target.resolve(strict=True)
    harness = Path(__file__).resolve().parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    metadata = output / 'metadata'; metadata.mkdir()
    stage = 'fixed-target'
    started = time.monotonic()
    try:
        target = load_target(target_path)
        if target_path != harness / 'target.json':
            raise CustodyError('target must be the adjacent committed harness declaration')
        if sha(harness / 'original-download-refusal.json') != target['original_download_refusal_sha256']:
            raise CustodyError('original connector refusal bytes changed')
        for source, name in HARNESS_FILES.items():
            shutil.copy2(harness / source, metadata / name)
        write_json(metadata / 'custody-start.json', {
            'schema':'hepta.hia.original-artifact-custody-start.v1', 'target':target,
            'custody_harness_commit':os.environ.get('GITHUB_SHA'),
            'custody_run_id':os.environ.get('GITHUB_RUN_ID'),
            'custody_run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),
            'scope':'TRANSPORT_OF_FIXED_ORIGINAL_FAILURE_ARTIFACT_BYTES_ONLY',
            'product_or_original_workflow_executed':False, 'original_failure_reclassified':False,
            'original_download_tool_retried':False,
        })
        token = os.environ.get('HIA_CUSTODY_TOKEN')
        if not token: raise CustodyError('the step-scoped actions-read token is absent')
        client = opener()
        base = '/repos/' + target['repository'] + '/actions/'
        stage = 'original-artifact-metadata'
        artifact = read_api_json(client, api_request(base + 'artifacts/' + str(target['artifact_id']), token), metadata / 'original-artifact-metadata.json')
        expected = {'id':target['artifact_id'], 'name':target['artifact_name'], 'size_in_bytes':target['size_in_bytes'],
                    'digest':'sha256:' + target['sha256'], 'expired':False}
        if any(artifact.get(key) != value for key, value in expected.items()):
            raise CustodyError('current original artifact identity differs from fixed target')
        if artifact.get('workflow_run',{}).get('id') != target['original_run_id'] or artifact.get('workflow_run',{}).get('head_sha') != target['original_head_sha']:
            raise CustodyError('original artifact run/source binding differs')
        stage = 'original-run-metadata'
        run = read_api_json(client, api_request(base + 'runs/' + str(target['original_run_id']), token), metadata / 'original-run-metadata.json')
        if (run.get('id') != target['original_run_id'] or run.get('head_sha') != target['original_head_sha']
                or run.get('run_attempt') != target['original_run_attempt'] or run.get('status') != 'completed'
                or run.get('conclusion') != target['original_conclusion']):
            raise CustodyError('original run terminal failure or attempt identity differs')
        stage = 'api-redirect'
        location = original_redirect(client, api_request(base + 'artifacts/' + str(target['artifact_id']) + '/zip', token))
        # A new opener and an explicitly unsigned request cross the origin.
        # Neither the signed URL nor either request's headers enter evidence.
        stage = 'unsigned-storage-download'
        original = output / 'original-artifact.zip'
        observation = download_original(opener(), storage_request(location), target, original)
        del location, token
        write_json(metadata / 'original-zip-verification.json', {
            'original_artifact_id':target['artifact_id'], **observation,
            'matched_original_github_size_and_digest':True,
            'api_redirect_status':302, 'storage_request_authorization_sent':False,
            'signed_storage_url_retained_or_printed':False,
        })
        stage = 'split-and-independent-readback'
        parts = split_original(original, target, output)
        for row in parts:
            directory = output / ('part-' + str(row['index']))
            write_json(directory / 'part.json', {
                'schema':'hepta.hia.original-artifact-byte-part.v1', 'original':target, 'part':row,
                'original_zip_verified_before_split':True, 'all_parts_read_back_in_order':True,
                'original_zip_recompressed_or_rewritten':False,
                'original_product_tests_executed':False, 'original_failure_reclassified':False,
            })
            for name in ('original-artifact-metadata.json','target.json','original-download-refusal.json'):
                shutil.copy2(metadata / name, directory / name)
        write_json(metadata / 'parts-manifest.json', {
            'schema':'hepta.hia.original-artifact-split-custody.v1', 'status':'ORIGINAL_BYTES_VERIFIED_AND_SPLIT',
            'original':target, 'parts':parts, 'original_zip_sha256':observation['sha256'],
            'original_zip_bytes':observation['bytes'], 'concatenation_readback_matches_original':True,
            'signed_storage_url_retained_or_printed':False, 'storage_authorization_sent':False,
            'product_test_execution_or_qualification_claimed':False,
            'elapsed_seconds':time.monotonic()-started,
        })
        print(json.dumps({'status':'ORIGINAL_BYTES_VERIFIED_AND_SPLIT','artifact_id':target['artifact_id'],
                          'bytes':observation['bytes'],'sha256':observation['sha256'],'parts':parts}))
        return 0
    except Exception as error:
        # urllib exceptions can contain a signed request URL. Preserve fixed
        # phase/type/status diagnostics without rendering exception text or URLs.
        detail = str(error) if isinstance(error,CustodyError) else None
        code = getattr(error,'code',None)
        failure = {'schema':'hepta.hia.artifact-custody-failure.v1','status':'CUSTODY_INCOMPLETE',
                   'stage':stage,'exception_type':type(error).__name__,
                   'http_status':code if type(code) is int else None,'controlled_detail':detail,
                   'signed_storage_url_retained_or_printed':False,
                   'original_product_or_workflow_executed':False,'original_failure_reclassified':False,
                   'elapsed_seconds':time.monotonic()-started}
        write_json(metadata / 'custody-failure.json', failure)
        print(json.dumps(failure), file=sys.stderr)
        return 1


def reassemble(args):
    """Read verified part directories without any network or credentials."""
    target = load_target(args.target)
    output = args.output.resolve()
    pending = output.with_name(output.name + '.unverified')
    if output.exists() or pending.exists():
        raise CustodyError('reassembly requires a new output pathname')
    rows = []
    for directory in args.parts:
        value = json.loads((directory / 'part.json').read_bytes())
        if (value.get('schema') != 'hepta.hia.original-artifact-byte-part.v1'
                or value.get('original') != target
                or value.get('original_zip_verified_before_split') is not True
                or value.get('all_parts_read_back_in_order') is not True):
            raise CustodyError('part metadata is not bound to the same original target')
        rows.append((value['part'], directory))
    rows.sort(key=lambda item: item[0]['index'])
    offset = 0
    for index, (row, directory) in enumerate(rows, 1):
        expected_size = min(target['part_bytes'], target['size_in_bytes'] - offset)
        if (row.get('index') != index or row.get('file') != 'original.zip.part-' + format(index,'03d')
                or row.get('offset') != offset or row.get('bytes') != expected_size
                or row.get('end_offset_exclusive') != offset + expected_size):
            raise CustodyError('part index, filename or byte-range continuity differs')
        path = directory / row['file']
        if path.stat().st_size != expected_size or sha(path) != row['sha256']:
            raise CustodyError('downloaded part bytes differ from its original custody receipt')
        offset += expected_size
    if len(rows) != target['part_count'] or offset != target['size_in_bytes']:
        raise CustodyError('part count or final byte offset differs')
    observed = hashlib.sha256(); total = 0
    with pending.open('xb') as destination:
        for row, directory in rows:
            with (directory / row['file']).open('rb') as source:
                while block := source.read(1 << 20):
                    destination.write(block); observed.update(block); total += len(block)
    if total != target['size_in_bytes'] or observed.hexdigest() != target['sha256']:
        raise CustodyError('reassembled ZIP differs from original GitHub size or digest')
    pending.rename(output)
    print(json.dumps({'status':'ORIGINAL_ZIP_REASSEMBLED_IDENTICALLY','artifact_id':target['artifact_id'],
                      'bytes':total,'sha256':observed.hexdigest(),'output':str(output),
                      'original_conclusion':target['original_conclusion'],'product_tests_executed':False}))
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--parts', nargs=3, type=Path, help='reassemble three downloaded part directories locally; no network')
    args = parser.parse_args()
    raise SystemExit(reassemble(args) if args.parts else transfer(args))
