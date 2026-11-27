"""Read-only transport verification of one exact existing Actions artifact.

This does not rerun, replace or grant authority to any source or native test.
API credentials stay on api.github.com; the signed download request has no
Authorization header and is never printed or retained.
"""
from pathlib import Path
from hashlib import sha256
from urllib.request import Request, build_opener, HTTPRedirectHandler, urlopen
from urllib.error import HTTPError
from urllib.parse import urlsplit
import base64
import json
import os
import platform
import stat
import subprocess
import sys
import time
import traceback
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent
EXPECTED = json.loads((ROOT / os.environ['HIA_CUSTODY_EXPECTED']).read_bytes())
REPO = EXPECTED['repository']
API = 'https://api.github.com/repos/' + REPO
OUT = Path(os.environ['RUNNER_TEMP']) / 'hia-original-artifact-custody'
TOKEN = os.environ['GITHUB_TOKEN']


class SafeFailure(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
    if path.read_bytes() != raw:
        raise SafeFailure('publication readback differs')


def api_request(path):
    return Request(API + path, headers={
        'Authorization': 'Bearer ' + TOKEN,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'HIA-original-artifact-custody',
    })


def api_json(path):
    with build_opener(NoRedirect()).open(api_request(path), timeout=60) as response:
        return json.loads(response.read())


def snapshot():
    names = sorted(subprocess.check_output(
        ['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0'))
    result = {}
    for name in names:
        if not name:
            continue
        path = ROOT / name
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise SafeFailure('regular tracked harness files required')
        raw = path.read_bytes()
        result[name] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                        'mode': '100755' if mode & 0o111 else '100644'}
    return result


def admit(artifact, run):
    workflow = artifact.get('workflow_run', {})
    if (artifact.get('id') != EXPECTED['artifact_id']
            or artifact.get('size_in_bytes') != EXPECTED['bytes']
            or artifact.get('digest') != 'sha256:' + EXPECTED['sha256']
            or artifact.get('expired') is not False
            or workflow.get('id') != EXPECTED['run_id']
            or workflow.get('head_sha') != EXPECTED['head_sha']
            or run.get('id') != EXPECTED['run_id']
            or run.get('head_sha') != EXPECTED['head_sha']
            or run.get('status') != 'completed'
            or run.get('conclusion') != 'success'):
        raise SafeFailure('exact original artifact/run identity differs')


def download(path):
    location = None
    try:
        response = build_opener(NoRedirect()).open(api_request(
            '/actions/artifacts/' + str(EXPECTED['artifact_id']) + '/zip'), timeout=60)
    except HTTPError as error:
        try:
            if error.code != 302:
                raise SafeFailure('artifact redirect status differs: ' + str(error.code))
            location = error.headers.get('Location')
        finally:
            error.close()
    else:
        response.close()
        raise SafeFailure('expected separate unauthenticated signed download redirect')
    parsed = urlsplit(location or '')
    if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password:
        raise SafeFailure('ordinary HTTPS artifact download required')
    digest = sha256()
    size = 0
    started = time.monotonic()
    # This new request intentionally has no API Authorization header.
    with urlopen(Request(location), timeout=60) as response, path.open('xb') as stream:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > EXPECTED['bytes'] or time.monotonic() - started > 300:
                raise SafeFailure('artifact download exceeds fixed transport extent/time')
            digest.update(block)
            stream.write(block)
    if size != EXPECTED['bytes'] or digest.hexdigest() != EXPECTED['sha256']:
        raise SafeFailure('complete original ZIP bytes differ')
    return {'bytes': size, 'sha256': digest.hexdigest(),
            'seconds': time.monotonic() - started}


def verify_zip(path):
    records = []
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            digest = sha256()
            size = 0
            # Opening by ZipInfo also preserves distinct duplicate-name entries.
            # Reading to EOF performs the original entry CRC check.
            with archive.open(entry) as stream:
                while True:
                    block = stream.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    digest.update(block)
            if size != entry.file_size:
                raise SafeFailure('outer ZIP member extent differs')
            records.append({
                'path': entry.filename, 'bytes': size, 'sha256': digest.hexdigest(),
                'crc32': format(entry.CRC, '08x'), 'compressed_bytes': entry.compress_size,
                'external_attr': entry.external_attr, 'flag_bits': entry.flag_bits,
                'is_directory': entry.is_dir(), 'crc_checked_by_complete_read': True,
            })
    return records


def main():
    OUT.mkdir(mode=0o700)
    started = time.monotonic()
    before = None
    report = {
        'schema': 'hia.original-actions-artifact-custody.v1',
        'scope': 'READ_ONLY_TRANSPORT_VERIFICATION_NO_SOURCE_OR_NATIVE_REQUALIFICATION',
        'status': 'FAIL', 'expected': EXPECTED, 'phase': 'admit-runtime',
        'source_or_native_tests_reexecuted': False, 'whole_native': False,
        'product_modified': False, 'original_artifact_modified': False,
        'python': sys.version, 'platform': platform.platform(),
    }
    try:
        if sys.version_info[:3] != (3, 14, 4) or os.environ.get('GITHUB_REPOSITORY') != REPO:
            raise SafeFailure('expected actual runner interpreter/repository')
        report['harness_head'] = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip()
        if report['harness_head'] != os.environ['GITHUB_SHA']:
            raise SafeFailure('actual harness checkout/head differs')
        if subprocess.check_output(['git', 'status', '--porcelain=v1', '--untracked-files=all'], cwd=ROOT):
            raise SafeFailure('original harness checkout is not clean')
        before = snapshot()
        report['harness_before'] = before
        report['phase'] = 'read-original-authority'
        artifact = api_json('/actions/artifacts/' + str(EXPECTED['artifact_id']))
        run = api_json('/actions/runs/' + str(EXPECTED['run_id']))
        admit(artifact, run)
        write(OUT / 'original-artifact-metadata.json', wire(artifact))
        write(OUT / 'original-run-metadata.json', wire(run))
        report['phase'] = 'download-original-zip'
        archive = OUT / ('artifact' + str(EXPECTED['artifact_id']) + '.zip')
        report['complete_original_zip'] = download(archive)
        report['phase'] = 'read-all-original-outer-zip-members'
        report['members'] = verify_zip(archive)
        report['member_count'] = len(report['members'])
        report['all_outer_members_size_sha_crc_verified'] = True
        report['nested_archive_members_not_separately_expanded'] = True
        report['phase'] = 'recheck-original-authority'
        artifact_after = api_json('/actions/artifacts/' + str(EXPECTED['artifact_id']))
        run_after = api_json('/actions/runs/' + str(EXPECTED['run_id']))
        admit(artifact_after, run_after)
        write(OUT / 'original-artifact-metadata-after.json', wire(artifact_after))
        report['harness_after'] = snapshot()
        if report['harness_after'] != before:
            raise SafeFailure('harness changed during read-only verification')
        report['harness_unchanged'] = True
        report['phase'] = 'complete'
        report['status'] = 'ORIGINAL_ZIP_BYTES_AND_OUTER_CRC_PASS'
    except BaseException as error:
        # Never print an exception representation that could contain a signed URL.
        report['failure'] = {'type': type(error).__name__,
            'safe_message': str(error) if isinstance(error, SafeFailure) else None,
            'http_code': error.code if isinstance(error, HTTPError) else None,
            'stack': [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                      for frame in traceback.extract_tb(error.__traceback__)]}
    finally:
        report['seconds'] = time.monotonic() - started
        raw = wire(report)
        write(OUT / 'REPORT.json', raw)
        compressed = zlib.compress(raw, 9)
        encoded = base64.b64encode(compressed).decode('ascii')
        pieces = [encoded[index:index + 10000] for index in range(0, len(encoded), 10000)]
        for index, data in enumerate(pieces):
            print('HIA_ORIGINAL_ARTIFACT_CUSTODY_ZLIB_BASE64 ' + json.dumps({
                'index': index, 'count': len(pieces),
                'raw_bytes': len(raw), 'raw_sha256': sha256(raw).hexdigest(),
                'compressed_bytes': len(compressed), 'compressed_sha256': sha256(compressed).hexdigest(),
                'data': data,
            }), flush=True)
        print(json.dumps({'status': report['status'], 'phase': report['phase'],
            'member_count': report.get('member_count'), 'seconds': report['seconds'],
            'source_or_native_tests_reexecuted': False}), flush=True)
    return int(report['status'] != 'ORIGINAL_ZIP_BYTES_AND_OUTER_CRC_PASS')


if __name__ == '__main__':
    raise SystemExit(main())
