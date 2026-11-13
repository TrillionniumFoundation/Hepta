"""Read one exact failed v92 CI artifact, every ZIP body and fixed diagnostic originals; never execute payloads."""
from __future__ import annotations

from hashlib import sha256
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
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
    # Honor the environment's configured proxies, including required CONNECT
    # routing. Each call has a fresh client, no cookie jar or global auth
    # handler, and no automatic redirects. Proxy URLs/credentials are not logged.
    return urllib.request.build_opener(urllib.request.ProxyHandler(), NoRedirect())


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




def fixed_policy(policy):
    require(policy.get('schema') == 'hia.actions.v92-ci-diagnostics-only-policy.v2'
            and policy.get('status') == 'FROZEN_OFFICIAL_TRANSPORT_INPUTS_UNEXECUTED'
            and policy.get('input_pins_frozen') is True,
            'draft policy has no frozen official artifact identity; execution refused')
    pin = policy.get('artifact')
    require(type(pin) is dict
            and all(type(pin.get(name)) is int and 0 < pin[name] < 1 << 63
                    for name in ('id', 'run_id', 'job_id'))
            and type(pin.get('run_attempt')) is int and pin['run_attempt'] == 1
            and type(pin.get('sha256')) is str and re.fullmatch(r'[0-9a-f]{64}', pin['sha256'])
            and all(type(pin.get(name)) is str and re.fullmatch(r'[0-9a-f]{40}', pin[name])
                    for name in ('checkout_commit', 'checkout_tree'))
            and pin.get('event') in ('push', 'pull_request', 'create')
            and pin.get('workflow_terminal') in ('success', 'failure', 'cancelled', 'timed_out'),
            'complete original artifact identity is not frozen')
    require(policy.get('repository') == REPO
            and policy.get('limits') == {
                'controller_seconds': 900, 'cleanup_seconds': 3, 'transfer_seconds': 720,
                'maximum_original_bytes': 3 << 30, 'maximum_parts': 10,
                'part_bytes': 256 << 20, 'public_part_bytes': 320 << 20,
                'diagnostic_bytes_per_part': 2 << 20, 'document_bytes_per_part': 3 << 20,
                'private_metadata_reserve_bytes': 64 << 20,
                'minimum_free_bytes': 8 << 30, 'minimum_free_inodes': 100000},
            'original ownership or new bounded transport scope differs')
    source = policy.get('source')
    require(type(source) is dict and source.get('head') == pin['checkout_commit']
            and source.get('tree') == pin['checkout_tree']
            and type(source.get('cold_source_count')) is int and 0 < source['cold_source_count'] < 100000
            and all(type(source.get(name)) is str and re.fullmatch(r'[0-9a-f]{64}', source[name])
                    for name in ('contract_sha256', 'source_manifest_canonical_sha256'))
            and type(source.get('profile')) is str and 0 < len(source['profile']) <= 256,
            'source provenance identity differs')
    require(set(policy.get('control_files', {})) == {
        'controller.py', 'worker.py', 'guardian.py', 'process_owner_impl.py', 'original_receiver.py', 'diagnostics.py'},
        'fixed six custody controls differ')
    require(policy.get('proxy_policy') == 'USE_CONFIGURED_ENVIRONMENT_PROXIES'
            and policy.get('slice_publication') == 'NONE_DIAGNOSTICS_ONLY'
            and policy.get('diagnostic_publication') == 'RELOCATE_SAME_FILESYSTEM_AFTER_CLOSED_ECHILD'
            and policy.get('original_product_thresholds_changed') is False
            and policy.get('new_product_execution') is False,
            'transport credential, disk or product scope differs')
    require(type(pin.get('bytes')) is int and 0 < pin['bytes'] <= 3 << 30
            and policy.get('parts') == [] and policy.get('partition_files_created') is False,
            'this request permits no partition production or publication')
    require(policy.get('expected_diagnostics') == {'members': 22385, 'expanded_bytes': 1987786640, 'selected_count': 460, 'selected_bytes': 3012789, 'missing_expected': ['hia-core-unpack-evidence/callers/integer-report.json', 'hia-core-unpack-evidence/callers/numeric/numeric-report.json', 'hia-core-unpack-evidence/callers/numeric/callers/report.json', 'hia-core-unpack-evidence/callers/numeric/callers/progress.receipt.json', 'hia-core-unpack-evidence/callers/numeric/callers/core-callers/report.json'], 'metadata_files': 3},
            'fixed full original inventory or available diagnostic population differs')
    return pin



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    control = root / 'control'
    policy_raw = read(control / 'policy.json', 1 << 20, args.policy_sha256)
    policy = json.loads(policy_raw)
    require(policy.get('schema') == 'hia.actions.v92-ci-diagnostics-only-policy.v2',
            'diagnostics-only policy schema differs')
    require(root == Path(os.environ['RUNNER_TEMP']).resolve() / policy['work_root_name'],
            'private runner root differs')
    pin = fixed_policy(policy)
    token = os.environ.pop(TOKEN_VARIABLE, None)
    require(type(token) is str and 0 < len(token) < 16384, 'Actions read token required')
    helper = load_helper(control, policy, root)
    started = time.monotonic_ns()
    deadline = started + 720 * 1000000000
    report = {'schema': 'hia.actions.v92-ci-diagnostics-only-worker.v2',
              'status': 'FULL_ZIP_CUSTODY_HOLD', 'root': str(root),
              'policy_sha256': args.policy_sha256,
              'source': policy['source'], 'artifact': pin,
              'API_attempts': [], 'GET_attempts': [],
              'qualification_executed': False, 'project_code_executed': False,
              'old_runs_replayed': False, 'original_product_statuses_reclassified': False,
              'original_ZIP_member_inspection_started': False,
              'token_or_signed_URL_recorded': False,
              'natural_guardian_acceptance_required': True,
              'proxy_policy': 'USE_CONFIGURED_ENVIRONMENT_PROXIES',
              'configured_proxy_schemes': sorted(urllib.request.getproxies()),
              'proxy_URLs_or_credentials_recorded': False, 'partition_files_created': False}
    stage = 'FIXED_INPUTS'
    try:
        helper.checkpoint(report)
        stage = 'OFFICIAL_METADATA'
        report['official_metadata'] = metadata(token, pin, root, deadline, report, helper)
        stage = 'OFFICIAL_LOCATION'
        url = official_location(token, pin, deadline, report, helper)
        stage = 'ONE_ORIGINAL_GET'
        path = storage_download(url, pin, root, deadline, report, helper)
        del url
        stage = 'FULL_ORIGINAL_BEFORE'
        report['zip_before'] = helper.read_file_hash(path, pin['bytes'], pin['sha256'])
        helper.checkpoint(report)
        stage = 'FULL_ZIP_AND_FIXED_DIAGNOSTICS'
        diagnostic_source = root / 'control/diagnostics.py'
        diagnostic_pin = policy['control_files']['diagnostics.py']
        diagnostic_raw = read(diagnostic_source, 1 << 20, diagnostic_pin['sha256'])
        require(len(diagnostic_raw) == diagnostic_pin['bytes'], 'fixed diagnostic source size differs')
        spec = importlib.util.spec_from_file_location('v92_full_zip_diagnostics', diagnostic_source)
        diagnostics = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diagnostics)
        report['original_ZIP_member_inspection_started'] = True
        report['diagnostics'] = diagnostics.inspect_zip(path, pin, root, deadline, helper, policy['diagnostics'])
        helper.checkpoint(report)
        stage = 'FULL_ORIGINAL_AFTER'
        report['zip_after'] = helper.read_file_hash(path, pin['bytes'], pin['sha256'])
        require(report['zip_before'] == report['zip_after'],
                'original ZIP changed across the two complete reads')
        deadline_check(deadline)
        report.update(status='SEALED_DIAGNOSTICS_PENDING_NATURAL_GUARDIAN',
                      elapsed_ns=time.monotonic_ns() - started)
        helper.create(root / 'recovery-terminal.json', wire(report))
        helper.checkpoint(report)
        deadline_check(deadline)
        print(json.dumps({'status': report['status'], 'partition_files_created': False,
                          'bytes': pin['bytes'], 'qualification_executed': False}), flush=True)
        return 0
    except BaseException as error:
        safe = str(error) if type(error) in (Refusal, helper.Refusal) else None
        report.update(status='FULL_ZIP_CUSTODY_HOLD', failed_stage=stage,
                      error_type=type(error).__name__, safe_refusal=safe,
                      errno=getattr(error, 'errno', None), http_status=getattr(error, 'code', None),
                      elapsed_ns=time.monotonic_ns() - started)
        try:
            if not os.path.lexists(root / 'recovery-terminal.json'):
                helper.create(root / 'recovery-terminal.json', wire(report))
            helper.checkpoint(report)
        except BaseException:
            pass
        print(json.dumps({'status': 'FULL_ZIP_CUSTODY_HOLD', 'stage': stage,
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
