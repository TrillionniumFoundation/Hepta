"""Read the sealed970 HOLD small artifact; recover bytes without reclassifying it."""
from __future__ import annotations

from hashlib import sha256
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import re
import zipfile
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
    # Only its destination path is re-rooted. Its complete 15103-byte shared
    # helper span remains original bytes; this reader does not execute its product-header checks.
    module.ROOT = root
    return module



def load_selector(control, policy):
    path = control / 'diagnostic_selection.py'
    pin = policy['control_files']['diagnostic_selection.py']
    raw = read(path, 1 << 20, pin['sha256'])
    require(len(raw) == pin['bytes'], 'fixed pure diagnostic selector size differs')
    spec = importlib.util.spec_from_file_location('_hia_970_diagnostic_selection', path)
    require(spec is not None and spec.loader is not None, 'diagnostic selector loader unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(list(module.HISTORICAL_TARGETS) == policy['diagnostic_targets']['historical']
            and list(module.CURRENT_READER_TARGETS) == policy['diagnostic_targets']['reader']
            and module.RAW_LIMIT == 512 << 10 and module.STDOUT_LIMIT == 1 << 20
            and module.FRAME_BYTES == 24 << 10
            and module.HISTORICAL_ALLOWANCE == 448 << 10
            and module.CURRENT_READER_ALLOWANCE == 64 << 10,
            'fixed pure diagnostic selector contract differs')
    return module


FRAME_RAW_LIMIT = 512 << 10
SMALL_UNCOMPRESSED_LIMIT = 32 << 20
ORIGINAL_ARTIFACT_ID = 13911977275
ORIGINAL_BASE_RECORDS = (
    'context.json', 'setup.json', 'recovery.json', 'recovery-terminal.json',
    'supervisor.stdout.log', 'supervisor.stderr.log', 'guard/request.json',
    'guard/guardian.json', 'guard/child.stdout.log', 'guard/child.stderr.log',
    'api/artifact-13911977275.metadata.original.json',
    'selected/13911977275/DIRECTORY.json', 'selected/13911977275/SELECTED.json',
    'selected/13911977275/CUSTODY.json', 'selected/13911977275/OBSERVATIONS.json',
)


def safe_info(info, maximum):
    require(not info.is_dir() and not info.flag_bits & 1
            and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
            and 0 <= info.file_size <= maximum and 0 <= info.compress_size,
            'bounded regular unencrypted ZIP member required')
    mode = info.external_attr >> 16
    require(stat.S_IFMT(mode) in (0, stat.S_IFREG), 'ZIP special member refused')


def retain(archive, info, target, maximum, expected=None):
    safe_info(info, maximum)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    count, digest = 0, sha256()
    with os.fdopen(fd, 'wb') as output, archive.open(info, 'r') as member:
        os.fchmod(output.fileno(), 0o400)
        while True:
            part = member.read(CHUNK)
            if not part:
                break
            count += len(part)
            require(count <= info.file_size and count <= maximum,
                    'ZIP expansion exceeds original bound')
            digest.update(part)
            output.write(part)
        require(count == info.file_size, 'ZIP full member read length differs')
        if expected is not None:
            require(count == expected['bytes'] and digest.hexdigest() == expected['sha256'],
                    'member differs from original captured record')
        output.flush()
        os.fsync(output.fileno())
    return {'path': str(target), 'bytes': count, 'sha256': digest.hexdigest(),
            'full_member_CRC_read': True}


def original_record_matches(record, original):
    return (record.get('bytes') == original.get('bytes')
            and record.get('sha256') == original.get('sha256'))


def frame_target_names(policy):
    names = policy['diagnostic_targets']['historical']
    require(type(names) is list and len(names) == len(set(names)) == 1
            and all(type(name) is str and name.startswith('custody/') for name in names),
            'fixed1 historical SELECTED target differs')
    return names


def select_small(path, pin, policy, root, helper, report):
    outer = root / 'captured'
    outer.mkdir(mode=0o700, exist_ok=False)
    before = helper.read_file_hash(path, pin['bytes'], pin['sha256'])
    report['small_zip_before'] = before
    outer_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    actual = {}
    with os.fdopen(outer_fd, 'rb') as source, zipfile.ZipFile(source, 'r') as archive:
        infos = archive.infolist()
        require(len(infos) == policy['expected_outer_member_count'] == 17
                and len({i.filename for i in infos}) == len(infos),
                'actual small ZIP member count differs from original upload')
        require(sum(i.file_size for i in infos) <= SMALL_UNCOMPRESSED_LIMIT,
                'small ZIP uncompressed limit exceeded')
        report['original_outer_directory'] = [
            {'name': info.filename, 'bytes': info.file_size,
             'compressed_bytes': info.compress_size, 'CRC32': info.CRC,
             'compression': info.compress_type, 'external_attr': info.external_attr,
             'flags': info.flag_bits} for info in infos]
        for info in infos:
            require(re.fullmatch(r'(?:[0-9]{3}\.original|FINAL\.json|FRAME-RESULT\.json)',
                                 info.filename) is not None,
                    'small ZIP fixed flat path refused')
            maximum = (2 << 20) if not info.filename.endswith('.original') else SMALL_UNCOMPRESSED_LIMIT
            actual[info.filename] = retain(archive, info, outer / info.filename, maximum)
    require({'FINAL.json', 'FRAME-RESULT.json'} <= set(actual),
            'original FINAL or framing failure record is missing')
    final_raw = read(outer / 'FINAL.json', 1 << 20, policy['original_final_sha256'])
    final = json.loads(final_raw)
    context = final.get('context', {})
    old = policy['original_operation']
    require(final.get('schema') == 'hia.actions.970-original-custody-final.v1'
            and context.get('repository') == REPO
            and context.get('event') == 'create' and context.get('event_ref_type') == 'branch'
            and context.get('event_ref') == old['branch']
            and context.get('run_id') == old['run_id'] and context.get('run_attempt') == 1
            and context.get('actual_workflow_commit') == old['workflow_commit']
            and context.get('actual_control_checkout') == old['control_commit']
            and context.get('policy_sha256') == old['policy_sha256']
            and context.get('original_product_commit') == policy['source']['head']
            and context.get('original_product_tree') == policy['source']['tree']
            and final.get('artifacts') == policy['original_artifacts']
            and final.get('status') == 'CUSTODY_HOLD'
            and final.get('original_600MB_ZIPs_included') is False
            and final.get('token_or_signed_URL_included') is False
            and final.get('qualification_executed') is False
            and final.get('project_code_executed') is False
            and final.get('original_product_statuses_reclassified') is False
            and final.get('original_CI_rerun') is False,
            'small artifact belongs to a different historical HOLD or scope')
    original_frame = json.loads(read(outer / 'FRAME-RESULT.json', 2 << 20))
    require(original_frame.get('schema') == 'hia.actions.970-original-log-result.v1'
            and original_frame.get('status') == 'FRAMING_HOLD'
            and original_frame.get('context') == context
            and original_frame.get('qualification_executed') is False
            and original_frame.get('original_product_statuses_reclassified') is False,
            'original framing failure receipt identity differs')
    aid = str(ORIGINAL_ARTIFACT_ID)
    prefix_name = 'selected/' + aid + '/'
    allowed = set(ORIGINAL_BASE_RECORDS) | {prefix_name + 'selected-originals.zip'}
    allowed.update(prefix_name + '%04d.raw' % i for i in range(354))
    rows = final.get('captured')
    require(type(rows) is list and len(rows) == policy['expected_captured_count'] == 15
            and all(type(x) is dict for x in rows)
            and len({x.get('source_relative_path') for x in rows}) == len(rows)
            and [x.get('retained_file') for x in rows] == ['%03d.original' % i for i in range(len(rows))]
            and {x['retained_file'] for x in rows} | {'FINAL.json', 'FRAME-RESULT.json'} == set(actual),
            'complete captured member inventory differs')
    captured = {}
    for row in rows:
        name = row['source_relative_path']
        require(name in allowed and row.get('independent_copy_readback') is True
                and type(row.get('source_identity')) is list and len(row['source_identity']) == 9
                and original_record_matches(actual[row['retained_file']], row),
                'captured original bytes differ from sealed FINAL')
        captured[name] = (outer / row['retained_file'], row)
    require(sum(x['bytes'] for x in rows) == final.get('actual_public_original_bytes')
            and sum(x['bytes'] for x in rows) + len(final_raw) ==
                policy['original_public_bytes_before_framing_result'] == 22383795,
            'captured original byte denominator differs')
    require(type(final.get('missing_capture_paths')) is list
            and len(set(final['missing_capture_paths'])) == len(final['missing_capture_paths'])
            and set(final['missing_capture_paths']) <= allowed
            and not set(final['missing_capture_paths']) & set(captured),
            'original missing-capture accounting differs')
    original_inputs = json.loads(read(root / 'control/artifact-pins.json', 1 << 20,
        policy['control_files']['artifact-pins.json']['sha256']))
    require(original_inputs['artifacts'] == policy['original_artifacts']
            and original_inputs['source'] == policy['source']
            and original_inputs['selected_members'] == policy['selected_members']
            and len(policy['selected_members']) == len(set(policy['selected_members'])) == 354,
            'unchanged354 original target policy differs')
    requested = policy['selected_members']
    frame_files = []
    requested_diagnostic = frame_target_names(policy)
    for name in ORIGINAL_BASE_RECORDS:
        if 'custody/' + name in requested_diagnostic and name in captured:
            frame_files.append({'logical_path': 'custody/' + name,
                'record': actual[captured[name][1]['retained_file']],
                'origin': 'original captured custody record'})
    selected_pin = policy['selected_manifest']
    require(selected_pin['source_relative_path'] == 'selected/13911977275/SELECTED.json'
            and selected_pin['bytes'] == 317307
            and selected_pin['sha256'] == 'b0760d77746721d441067b63c8442dafbf0ad3e2bc6f9c79f26770b448965fff',
            'external SELECTED original pin differs')
    if frame_files:
        require(len(frame_files) == 1
                and frame_files[0]['logical_path'] == 'custody/' + selected_pin['source_relative_path']
                and frame_files[0]['record']['bytes'] == selected_pin['bytes']
                and frame_files[0]['record']['sha256'] == selected_pin['sha256'],
                'actual SELECTED original differs from previously recovered CUSTODY')
    for item in frame_files:
        item['record'] = helper.read_file_hash(Path(item['record']['path']),
                                              item['record']['bytes'], item['record']['sha256'])
    report.update(original_final_status=final['status'], original_final_sha256=sha256(final_raw).hexdigest(),
        original_custody_context=context, original_custody_errors=final.get('errors'),
        original_custody_capture_complete=final.get('capture_complete'),
        original_custody_missing_capture_paths=final['missing_capture_paths'],
        original_frame_status=original_frame['status'], original_frame_errors=original_frame.get('errors'),
        original_captured_count=len(rows), original_captured_bytes=sum(x['bytes'] for x in rows),
        original_small_inventory=actual, original_captured_inventory=rows,
        outer_originals_verified=True, frame_files=frame_files,
        expected_frame_targets=requested_diagnostic)
    helper.checkpoint(report)

    # The complete inner selected ZIP is one SHA/CRC-verified outer member.
    # This SELECTED metadata receiver never opens it or reads any of the354 original bodies.
    by_name = {item['logical_path']: item for item in frame_files}
    frame_files = [by_name[name] for name in requested_diagnostic if name in by_name]
    missing = [name for name in requested_diagnostic if name not in by_name]
    require(len(frame_files) + len(missing) == 1
            and len(by_name) == len(frame_files),
            'fixed1 SELECTED present/missing accounting differs')
    selector = load_selector(root / 'control', policy)
    metadata = {item['logical_path']: {
        'bytes': item['record']['bytes'], 'sha256': item['record']['sha256']}
        for item in frame_files}
    # The finalizer adds its own five controls only after this guardian closes.
    # Selection here is metadata-only; it is never an assertion of frame output.
    historical_plan = selector.plan_original_frames(metadata, {})
    after = helper.read_file_hash(path, pin['bytes'], pin['sha256'])
    require(after == before, 'small original ZIP changed during full outer inspection')
    selected_pin = policy['selected_manifest']
    require(selected_pin['source_relative_path'] == 'selected/13911977275/SELECTED.json'
            and selected_pin['bytes'] == 317307
            and selected_pin['sha256'] == 'b0760d77746721d441067b63c8442dafbf0ad3e2bc6f9c79f26770b448965fff',
            'external SELECTED original pin differs')
    if frame_files:
        require(len(frame_files) == 1
                and frame_files[0]['logical_path'] == 'custody/' + selected_pin['source_relative_path']
                and frame_files[0]['record']['bytes'] == selected_pin['bytes']
                and frame_files[0]['record']['sha256'] == selected_pin['sha256'],
                'actual SELECTED original differs from previously recovered CUSTODY')
    for item in frame_files:
        item['record'] = helper.read_file_hash(Path(item['record']['path']),
                                              item['record']['bytes'], item['record']['sha256'])
    report.update(small_zip_after=after, frame_files=frame_files,
        missing_frame_targets=missing, historical_selection_plan=historical_plan,
        inner_selected_archive_opened=False, original354_bodies_read=False,
        original_cold_or_compiler_headers_reclassified=False,
        unselected_original_product_members_executed=False,
        original_product_statuses_reclassified=False,
        actual_present_frame_bytes=sum(item['record']['bytes'] for item in frame_files),
        framing_budget_is_separate_from_product_thresholds=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    control = root / 'control'
    policy = json.loads(read(control / 'policy.json', 1 << 20, args.policy_sha256))
    require(policy.get('schema') == 'hia.actions.970-selected-index-policy.v1',
            'small original recovery policy differs')
    pin = policy['small_artifact']
    require(pin.get('id') == 13913382201 and pin.get('bytes') == 22390611
            and pin.get('sha256') == '58424f2690a09f10e2f06557985648aa89d0dab1c37be89833b0f2653344976d'
            and pin.get('run_id') == 43150215535
            and policy.get('original_final_sha256') == 'afc25dc9c884a935441b75c276760e6e6455085ddc2c34186fed237fc65d1345',
            'external small artifact and original FINAL pins differ')
    require(root == Path(os.environ['RUNNER_TEMP']).resolve() / policy['work_root_name'],
            'private small-reader root differs')
    token = os.environ.pop(TOKEN_VARIABLE, None)
    require(type(token) is str and 0 < len(token) < 16384, 'Actions read token required')
    helper = load_helper(control, policy, root)
    started = time.monotonic_ns()
    deadline = started + 720 * 1000000000
    report = {'schema': 'hia.actions.970-selected-index-worker.v1', 'status': 'READ_HOLD',
        'root': str(root), 'policy_sha256': args.policy_sha256,
        'API_attempts': [], 'GET_attempts': [], 'small_artifact': pin,
        'original_large_artifacts_downloaded': False, 'project_code_executed': False,
        'qualification_executed': False, 'original_product_statuses_reclassified': False,
        'token_or_signed_URL_recorded': False}
    stage = 'FROZEN_INPUTS'
    try:
        helper.checkpoint(report)
        stage = 'SMALL_METADATA'
        report['official_metadata'] = metadata(token, pin, root, deadline, report, helper)
        stage = 'SMALL_LOCATION'
        url = official_location(token, pin, deadline, report, helper)
        stage = 'SMALL_GET'
        path = storage_download(url, pin, root, deadline, report, helper)
        del url
        stage = 'FULL_OUTER_AND_EXACT_SELECTED_INDEX_ORIGINAL'
        select_small(path, pin, policy, root, helper, report)
        report.update(status='SELECTED_INDEX_OUTER_VERIFIED_PENDING_NATURAL_GUARDIAN',
                      elapsed_ns=time.monotonic_ns() - started)
        helper.create(root / 'recovery-terminal.json', wire(report))
        helper.checkpoint(report)
        print(json.dumps({'status': report['status'], 'original_final_status': report['original_final_status'],
                          'actual_original_targets': len(report['frame_files']),
                          'missing_original_targets': len(report['missing_frame_targets']),
                          'qualification_executed': False}), flush=True)
        return 0
    except BaseException as error:
        report.update(status='READ_HOLD', failed_stage=stage, error_type=type(error).__name__,
            safe_refusal=str(error) if type(error) in (Refusal, helper.Refusal) else None,
            errno=getattr(error, 'errno', None), http_status=getattr(error, 'code', None),
            elapsed_ns=time.monotonic_ns() - started)
        try:
            if not os.path.lexists(root / 'recovery-terminal.json'):
                helper.create(root / 'recovery-terminal.json', wire(report))
            helper.checkpoint(report)
        except BaseException:
            pass
        print(json.dumps({'status': 'READ_HOLD', 'stage': stage,
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
