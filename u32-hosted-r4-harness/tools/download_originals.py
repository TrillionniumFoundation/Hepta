"""Retrieve only the two exact original R20 ZIPs before product entry.

The GitHub credential is sent only to fixed api.github.com endpoints. Provider
requests have no Authorization header and cannot follow further redirects.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

SPEC = importlib.util.spec_from_file_location('u32_hosted_harness', Path(__file__).with_name('materialize_hosted.py'))
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)
REPO = 'TrillionniumFoundation/Hepta'
RUN = 43553551892
HEAD = '28b8e6f5b44022f9d6e90d561573d41f0f7e8633'
ARTIFACTS = (
    {'key': 'combined-source', 'id': 14097884196, 'name': 'hia-combined-source-v120-r20-43553551892-1',
     'file': 'combined-source.zip', 'bytes': 383629576,
     'sha256': '7a6c07fb57593fd282fe4a2854bcd6ec0eb3ddca001b217c41c62f2843d570b9',
     'git_blob': 'b9a8c9d944555532f891e944f8bebb956b45c23f'},
    {'key': 'parser-bounded', 'id': 14098053733, 'name': 'hia-parser-bounded-v120-r20-43553551892-1',
     'file': 'parser-bounded.zip', 'bytes': 48115943,
     'sha256': 'efdca0795d327ff70cf27e2a4feddeb96cc78d14661226361b2ec6bf125c9b9e',
     'git_blob': 'ff338564d6a5f8e00474570d53963261f0c19f5d'},
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def api_request(artifact, token, out, *, download=False):
    endpoint = 'https://api.github.com/repos/' + REPO + '/actions/artifacts/' + str(artifact['id'])
    if download:
        endpoint += '/zip'
    label = 'redirect' if download else 'metadata'
    H.dump(out / (label + '.REQUEST.json'), {'url': endpoint, 'method': 'GET',
        'authorization_scope': 'this_fixed_GitHub_API_only', 'credential_value_recorded': False,
        'redirect_following': False})
    request = urllib.request.Request(endpoint, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28', 'Accept-Encoding': 'identity',
        'User-Agent': 'hepta-frozen-u32-qualification-input-receiver'})
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(request, timeout=60)
    except urllib.error.HTTPError as error:
        if download and error.code == 302:
            location = error.headers.get('Location')
            H.require(type(location) is str, 'GitHub artifact redirect is absent')
            parsed = urllib.parse.urlsplit(location)
            H.require(parsed.scheme == 'https' and parsed.hostname is not None
                and parsed.username is None and parsed.password is None and parsed.port in (None, 443)
                and not parsed.fragment and (parsed.hostname.endswith('.blob.core.windows.net')
                or parsed.hostname.endswith('.githubusercontent.com')), 'unrecognized artifact storage provider')
            H.dump(out / 'redirect.RESPONSE.json', {'status': 302,
                'provider_origin': parsed.scheme + '://' + parsed.netloc,
                'provider_path': parsed.path, 'query_redacted': bool(parsed.query),
                'complete_URL_sha256': hashlib.sha256(location.encode()).hexdigest(),
                'authorization_forwarded_to_provider': False})
            error.close()
            return location
        body = error.read((1 << 20) + 1)
        H.write_new(out / (label + '.ERROR.body'), body)
        H.dump(out / (label + '.ERROR.json'), {'status': error.code,
            'body_bytes_captured': len(body), 'body_capture_limit': (1 << 20) + 1,
            'body_may_be_truncated': len(body) > (1 << 20), 'credential_value_recorded': False})
        error.close()
        raise RuntimeError('fixed artifact API request failed with status ' + str(error.code)) from None
    with response:
        H.require(not download and response.status == 200, 'artifact redirect protocol differs')
        raw = response.read((1 << 20) + 1)
        H.write_new(out / 'metadata.RESPONSE.json', raw)
        H.require(len(raw) <= (1 << 20), 'artifact metadata exceeds bounded capture')
    metadata = json.loads(raw)
    H.require(metadata['id'] == artifact['id'] and metadata['name'] == artifact['name']
        and metadata['expired'] is False and metadata['size_in_bytes'] == artifact['bytes']
        and metadata['digest'] == 'sha256:' + artifact['sha256']
        and metadata['workflow_run']['id'] == RUN and metadata['workflow_run']['head_sha'] == HEAD,
        'actual artifact metadata differs from original R20 input')
    return metadata


def one_archive(artifact, token, root, out):
    H.directory(out, new=True)
    metadata = api_request(artifact, token, out)
    location = api_request(artifact, token, out, download=True)
    target = root / artifact['file']
    partial = root / (artifact['file'] + '.partial')
    H.require(not target.exists() and not target.is_symlink() and not partial.exists() and not partial.is_symlink(),
              'existing artifact/partial requires explicit reconciliation; no retry')
    free = shutil.disk_usage(root).free
    H.require(free >= artifact['bytes'] + (128 << 20), 'download space floor not met')
    H.dump(out / 'TRANSFER-INTENT.json', {'artifact': artifact, 'run_id': RUN, 'head_sha': HEAD,
        'free_bytes_before': free, 'minimum_remaining_bytes': 128 << 20,
        'provider_request_has_authorization': False, 'provider_redirects_allowed': False})
    total = 0
    digest = hashlib.sha256()
    git = hashlib.sha1(b'blob ' + str(artifact['bytes']).encode() + b'\0')
    opener = urllib.request.build_opener(NoRedirect())
    request = urllib.request.Request(location, headers={'Accept-Encoding': 'identity'})
    with opener.open(request, timeout=60) as incoming:
        H.require(incoming.status == 200, 'provider did not return complete artifact')
        length = incoming.headers.get('Content-Length')
        H.require(length is None or int(length) == artifact['bytes'], 'artifact Content-Length differs')
        H.require(incoming.headers.get('Content-Encoding') in (None, 'identity'), 'encoded transfer not admitted')
        H.dump(out / 'PROVIDER-HEADERS.json', {name: incoming.headers.get(name)
              for name in ('Content-Length', 'Content-Type', 'Content-Encoding', 'ETag')})
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            while True:
                block = incoming.read(min(1 << 20, artifact['bytes'] + 1 - total))
                if not block:
                    break
                total += len(block)
                H.require(total <= artifact['bytes'], 'artifact transfer exceeds original length')
                digest.update(block)
                git.update(block)
                stream.write(block)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
    H.require(total == artifact['bytes'] and digest.hexdigest() == artifact['sha256']
              and git.hexdigest() == artifact['git_blob'], 'complete original artifact bytes do not match')
    H.require(not target.exists(), 'artifact target appeared during transfer')
    partial.rename(target)
    before = target.lstat()
    H.require(stat.S_ISREG(before.st_mode) and before.st_size == artifact['bytes'], 'stored artifact is not regular')
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    rows = []
    with os.fdopen(fd, 'rb') as stream:
        H.require(H.stamp(os.fstat(stream.fileno())) == H.stamp(before), 'stored artifact changed before readback')
        stored_sha = hashlib.sha256()
        stored_git = hashlib.sha1(b'blob ' + str(artifact['bytes']).encode() + b'\0')
        stored_bytes = 0
        while block := stream.read(1 << 20):
            stored_bytes += len(block)
            H.require(stored_bytes <= artifact['bytes'], 'stored artifact grew during readback')
            stored_sha.update(block)
            stored_git.update(block)
        H.require(stored_bytes == artifact['bytes'] and stored_sha.hexdigest() == artifact['sha256']
                  and stored_git.hexdigest() == artifact['git_blob'], 'stored outer ZIP full readback differs')
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            for ordinal, info in enumerate(archive.infolist()):
                count = 0
                checksum = 0
                member_sha = hashlib.sha256()
                with archive.open(info) as member:
                    while block := member.read(1 << 20):
                        count += len(block)
                        H.require(count <= info.file_size, 'ZIP member grew beyond its declared extent')
                        checksum = zlib.crc32(block, checksum)
                        member_sha.update(block)
                H.require(count == info.file_size and (checksum & 0xffffffff) == info.CRC, 'complete member CRC differs')
                rows.append({'ordinal': ordinal, 'path': info.filename, 'bytes': count,
                    'sha256': member_sha.hexdigest(), 'crc32': '%08x' % info.CRC,
                    'compressed_bytes': info.compress_size, 'compression': info.compress_type,
                    'external_attr': info.external_attr, 'create_system': info.create_system,
                    'flag_bits': info.flag_bits, 'date_time': list(info.date_time), 'is_directory': info.is_dir()})
        H.require(H.stamp(os.fstat(stream.fileno())) == H.stamp(before), 'stored artifact changed while verifying CRC')
    after = target.lstat()
    H.require(H.stamp(after) == H.stamp(before), 'stored artifact pathname changed')
    H.dump(out / 'COMPLETE-MEMBER-CRC.json', rows)
    result = {'path': str(target), 'artifact_id': artifact['id'], 'run_id': RUN, 'head_sha': HEAD,
        'identity': {key: artifact[key] for key in ('file', 'bytes', 'sha256', 'git_blob')},
        'metadata': metadata, 'post_verification_stat': H.stamp(after),
        'stored_outer_full_bytes_rehashed': True, 'full_crc_verified': True,
        'member_count': len(rows), 'logical_member_bytes': sum(row['bytes'] for row in rows),
        'original_historical_REPORT_and_TRANSFER_not_modified': True,
        'provider_authorization_header': False, 'provider_redirects_followed': False}
    H.dump(out / 'TRANSFER-READBACK.json', result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archives', required=True)
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args()
    root, evidence = H.absolute(args.archives), H.absolute(args.evidence)
    H.directory(evidence)
    out = evidence / 'download'
    H.directory(out, new=True)
    result = {'status': 'FAIL', 'product_invocations': 0, 'archives': {}}
    code = 1
    started = time.monotonic_ns()
    try:
        controls = H.harness_guard()
        H.directory(root, new=True)
        token = os.environ.get('GITHUB_TOKEN')
        H.require(type(token) is str and token, 'read-only GitHub Actions credential is unavailable')
        for artifact in ARTIFACTS:
            result['archives'][artifact['key']] = one_archive(artifact, token, root, out / artifact['key'])
        H.require(H.harness_guard() == controls, 'harness changed during original artifact capture')
        result.update(status='TWO_ORIGINAL_ZIPS_FULL_SHA_AND_ALL_MEMBER_CRC_PASS',
                      harness_controls=controls, outer_bytes=sum(item['bytes'] for item in ARTIFACTS))
        H.dump(root / 'VERIFIED-ARCHIVES.json', result)
        code = 0
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        result.update(exit_code=code, elapsed_ns=time.monotonic_ns() - started)
        H.dump(out / 'RESULT.json', result)
        print(json.dumps({key: result.get(key) for key in ('status', 'exit_code', 'elapsed_ns', 'outer_bytes')}, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
