"""Read one exact970 historical artifact; never execute product payloads."""
from __future__ import annotations

from hashlib import sha256
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = 'TrillionniumFoundation/Hepta'
TOKEN_VARIABLE = 'HIA_CUSTODY_GITHUB_TOKEN'
API_VERSION = '2026-03-10'
CHUNK = 1 << 20


class Refusal(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def read(path, maximum, expected=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and before.st_size <= maximum,
                'bounded single-link original required')
        raw = stream.read(maximum + 1)
        require(len(raw) == before.st_size
                and identity(before) == identity(os.fstat(stream.fileno()))
                and identity(before) == identity(Path(path).lstat()), 'original changed')
    require(expected is None or sha256(raw).hexdigest() == expected, 'original SHA differs')
    return raw


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o400)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def new_client():
    # Each caller gets an independent client: there is no cookie jar, global
    # authentication handler, ambient proxy, or automatically followed redirect.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def deadline_check(deadline):
    require(time.monotonic_ns() < deadline, 'combined original transfer deadline exceeded')


def api_request(token, path):
    require(path.startswith('/repos/' + REPO + '/actions/artifacts/')
            and '\n' not in token and '\r' not in token, 'fixed API credential boundary differs')
    return urllib.request.Request('https://api.github.com' + path, method='GET', headers={
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': API_VERSION,
        'Accept-Encoding': 'identity',
        'User-Agent': 'HIA-original-artifact-custody/1',
    })


def bounded_response(response, maximum, deadline):
    count, chunks = 0, []
    while True:
        deadline_check(deadline)
        block = response.read1(min(CHUNK, maximum + 1 - count))
        deadline_check(deadline)
        if not block:
            break
        count += len(block)
        require(count <= maximum, 'API metadata exceeds bound')
        chunks.append(block)
    return b''.join(chunks)


def metadata(token, pin, root, deadline, report, helper):
    path = '/repos/' + REPO + '/actions/artifacts/%d' % pin['id']
    attempt = {'artifact_id': pin['id'], 'role': 'official_metadata',
               'method': 'GET', 'host': 'api.github.com', 'path': path,
               'attempt': 1, 'retries': 0, 'credential_sent_only_to_official_API': True}
    report['API_attempts'].append(attempt)
    helper.checkpoint(report)
    deadline_check(deadline)
    request = api_request(token, path)
    with new_client().open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == request.full_url,
                'exact metadata HTTP200 required')
        require(response.headers.get('Content-Encoding', 'identity').lower() == 'identity',
                'encoded API metadata refused')
        raw = bounded_response(response, 1 << 20, deadline)
    value = json.loads(raw)
    require(type(value) is dict and value.get('id') == pin['id']
            and value.get('size_in_bytes') == pin['bytes']
            and value.get('digest') == 'sha256:' + pin['sha256']
            and value.get('expired') is False
            and value.get('workflow_run', {}).get('id') == pin['run_id']
            and value.get('workflow_run', {}).get('head_sha') == pin['checkout_commit']
            and value.get('archive_download_url') == 'https://api.github.com' + path + '/zip',
            'official artifact identity differs from external pins')
    output = root / 'api' / ('artifact-%d.metadata.original.json' % pin['id'])
    create(output, raw)
    require(read(output, 1 << 20) == raw, 'metadata independent readback differs')
    record = {'path': str(output), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
              'artifact_id': pin['id'], 'run_id': pin['run_id'],
              'provider_head_sha_observed': value.get('workflow_run', {}).get('head_sha')}
    attempt.update(status=200, original_metadata=record)
    helper.checkpoint(report)
    return record


def official_location(token, pin, deadline, report, helper):
    path = '/repos/' + REPO + '/actions/artifacts/%d/zip' % pin['id']
    attempt = {'artifact_id': pin['id'], 'role': 'official_download_redirect',
               'method': 'GET', 'host': 'api.github.com', 'path': path,
               'attempt': 1, 'retries': 0, 'automatic_redirects': 0,
               'credential_sent_only_to_official_API': True}
    report['API_attempts'].append(attempt)
    helper.checkpoint(report)
    deadline_check(deadline)
    request = api_request(token, path)
    try:
        response = new_client().open(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    try:
        require(response.code == 302 and response.geturl() == request.full_url,
                'official archive endpoint must return exactly302')
        locations = response.headers.get_all('Location', [])
        require(len(locations) == 1, 'one signed location required')
        url = locations[0]
        require(type(url) is str and 0 < len(url) <= 16384
                and not any(ord(c) < 32 or ord(c) == 127 for c in url),
                'bounded signed location required')
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == 'https' and parsed.hostname
                and parsed.hostname.endswith(('.blob.core.windows.net', '.actions.githubusercontent.com'))
                and parsed.port in (None, 443) and not parsed.username
                and not parsed.password and not parsed.fragment,
                'official signed storage endpoint refused')
    finally:
        response.close()
    deadline_check(deadline)
    attempt.update(status=302, storage_host=parsed.hostname,
                   location_sha256=sha256(url.encode()).hexdigest(),
                   signed_Location_recorded=False, authorization_forwarded=False)
    helper.checkpoint(report)
    return url


def storage_download(url, pin, root, deadline, report, helper):
    # This completely new request/client carries no Authorization or Cookie.
    # The signed Location is never serialized, printed, or passed as argv.
    parsed = urllib.parse.urlsplit(url)
    path = root / 'original' / ('artifact-%d.zip' % pin['id'])
    partial = path.with_name(path.name + '.partial')
    require(not os.path.lexists(path) and not os.path.lexists(partial), 'original archive already exists')
    attempt = {'artifact_id': pin['id'], 'method': 'GET', 'attempt': 1,
               'host': parsed.hostname, 'url_sha256': sha256(url.encode()).hexdigest(),
               'started_ns': time.monotonic_ns(), 'socket_seconds': 30,
               'redirects': 0, 'retries': 0, 'authorization_sent': False, 'cookies_sent': False}
    report['GET_attempts'].append(attempt)
    helper.checkpoint(report)
    request = urllib.request.Request(url, method='GET', headers={
        'User-Agent': 'HIA-original-artifact-custody/1', 'Accept-Encoding': 'identity'})
    require(not request.has_header('Authorization') and not request.has_header('Cookie'),
            'storage credential boundary differs')
    count, digest = 0, sha256()
    deadline_check(deadline)
    with new_client().open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url, 'exact storage HTTP200 required')
        require(response.headers.get('Content-Encoding', 'identity').lower() == 'identity',
                'encoded original body refused')
        length = response.headers.get('Content-Length')
        require(length is None or int(length) == pin['bytes'], 'original HTTP size differs')
        fd = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'w+b') as target:
            while True:
                deadline_check(deadline)
                block = response.read1(min(CHUNK, pin['bytes'] + 1 - count))
                deadline_check(deadline)
                if not block:
                    break
                count += len(block)
                require(count <= pin['bytes'], 'original HTTP body exceeded fixed size')
                target.write(block)
                digest.update(block)
            require(count == pin['bytes'] and digest.hexdigest() == pin['sha256'],
                    'downloaded original ZIP differs from external seal')
            target.flush()
            os.fsync(target.fileno())
            os.fchmod(target.fileno(), 0o400)
            os.fsync(target.fileno())
    os.link(partial, path, follow_symlinks=False)
    os.unlink(partial)
    helper.sync_dir(path.parent)
    attempt.update(bytes=count, sha256=digest.hexdigest(),
                   finished_ns=time.monotonic_ns(), output=str(path))
    helper.checkpoint(report)
    return path


def load_helper(control, policy, root):
    expected = policy['control_files']['original_receiver.py']
    path = control / 'original_receiver.py'
    raw = read(path, 1 << 20, expected['sha256'])
    require(len(raw) == expected['bytes'], 'fixed original helper size differs')
    spec = importlib.util.spec_from_file_location('fixed_original_ci_custody', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # This is a fixed evidence-only control module, never project/product code.
    # Only the destination is rebound. The complete 15103-byte ZIP/CRC/hash
    # span remains reviewed original bytes;354-path/header logic is this revision.
    module.ROOT = root
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    control = root / 'control'
    policy_raw = read(control / 'policy.json', 1 << 20, args.policy_sha256)
    policy = json.loads(policy_raw)
    require(policy.get('schema') == 'hia.actions.970-original-custody-policy.v1',
            'custody policy schema differs')
    require(root == Path(os.environ['RUNNER_TEMP']).resolve() / policy['work_root_name'],
            'private runner root differs')
    token = os.environ.pop(TOKEN_VARIABLE, None)
    require(type(token) is str and 0 < len(token) < 16384, 'Actions read token required')
    helper = load_helper(control, policy, root)
    pins = json.loads(read(control / 'artifact-pins.json', 1 << 20,
                          policy['control_files']['artifact-pins.json']['sha256']))
    require(pins['selected_count'] == 354 and pins['artifacts'] == policy['artifacts']
            and len(pins['artifacts']) == 1 and pins['source'] == policy['source']
            and pins['required_members'] == pins['selected_members']
            and pins['selected_members'] == policy['selected_members'],
            'original artifact/source/354-path policy differs')
    started = time.monotonic_ns()
    deadline = started + 720 * 1000000000
    report = {'schema': 'hia.actions.970-original-custody-worker.v1',
              'status': 'CUSTODY_HOLD', 'root': str(root),
              'policy_sha256': args.policy_sha256,
              'original_receiver_sha256': policy['control_files']['original_receiver.py']['sha256'],
              'source': pins['source'], 'API_attempts': [], 'GET_attempts': [], 'artifacts': [],
              'qualification_executed': False, 'project_code_executed': False,
              'old_runs_replayed': False, 'original_product_statuses_reclassified': False,
              'unselected_inner_phase_ZIPs_replayed': False,
              'source_file_payloads_independently_read': False,
              'token_or_signed_URL_recorded': False,
              'natural_guardian_acceptance_required': True}
    stage = 'FIXED_INPUTS'
    try:
        helper.checkpoint(report)
        for pin in pins['artifacts']:
            stage = 'OFFICIAL_METADATA_%d' % pin['id']
            meta = metadata(token, pin, root, deadline, report, helper)
            stage = 'OFFICIAL_LOCATION_%d' % pin['id']
            url = official_location(token, pin, deadline, report, helper)
            stage = 'ORIGINAL_GET_%d' % pin['id']
            path = storage_download(url, pin, root, deadline, report, helper)
            del url
            stage = 'FULL_ORIGINAL_BEFORE_%d' % pin['id']
            before = helper.read_file_hash(path, pin['bytes'], pin['sha256'])
            stage = 'SAFE_DIRECTORY_AND_ORIGINAL_MEMBERS_%d' % pin['id']
            item = helper.inspect(path, pin, pins)
            stage = 'FULL_ORIGINAL_AFTER_%d' % pin['id']
            after = helper.read_file_hash(path, pin['bytes'], pin['sha256'])
            require(before == after, 'original ZIP changed across selected full reads')
            item.update(zip_before=before, zip_after=after, official_metadata=meta)
            report['artifacts'].append(item)
            helper.checkpoint(report)
        report.update(status='ONE_ORIGINAL_RETAINED_PENDING_NATURAL_GUARDIAN',
                      elapsed_ns=time.monotonic_ns() - started,
                      full_original_ZIP_bytes_per_read=sum(x['bytes'] for x in pins['artifacts']))
        helper.create(root / 'recovery-terminal.json', wire(report))
        helper.checkpoint(report)
        print(json.dumps({'status': report['status'], 'artifacts': len(report['artifacts']),
                          'qualification_executed': False}), flush=True)
        return 0
    except BaseException as error:
        # Never serialize exceptions, HTTP response headers, token or signed URLs.
        # Only the fixed refusal text defined by our two reviewed controls is safe.
        safe = str(error) if type(error) in (Refusal, helper.Refusal) else None
        report.update(status='CUSTODY_HOLD', failed_stage=stage,
                      error_type=type(error).__name__, safe_refusal=safe,
                      errno=getattr(error, 'errno', None), http_status=getattr(error, 'code', None),
                      elapsed_ns=time.monotonic_ns() - started)
        try:
            if not os.path.lexists(root / 'recovery-terminal.json'):
                helper.create(root / 'recovery-terminal.json', wire(report))
            helper.checkpoint(report)
        except BaseException:
            pass
        print(json.dumps({'status': 'CUSTODY_HOLD', 'stage': stage,
                          'error_type': type(error).__name__}), flush=True)
        return 1
    finally:
        token = None


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Refusal as error:
        print(json.dumps({'status': 'INPUT_HOLD', 'safe_refusal': str(error)}), flush=True)
        raise SystemExit(1)
