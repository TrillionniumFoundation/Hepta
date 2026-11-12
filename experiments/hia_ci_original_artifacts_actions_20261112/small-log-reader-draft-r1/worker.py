"""Read the one small custody artifact and retain bounded original log inputs."""
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
    # helper span and all ZIP/17-member/header checks remain original bytes.
    module.ROOT = root
    return module



FRAME_RAW_LIMIT = 8 << 20
SMALL_UNCOMPRESSED_LIMIT = 480 << 20
FRAME_TARGETS = (
    'hia-machine-elf-caller-gate.json',
    'hia-machine-elf-callers-evidence/report.json',
    'hia-machine-elf-callers-owner/run-result.json',
    'hia-machine-elf-callers-owner/process-owner.json',
    'hia-machine-elf-callers-owner/stdout.log',
    'hia-machine-elf-callers-owner/stderr.log',
    'hia-machine-elf-callers-owner/process-owner.json.stdout.log',
    'hia-machine-elf-callers-owner/process-owner.json.stderr.log',
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
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    count, digest = 0, sha256()
    with os.fdopen(fd, 'wb') as output, archive.open(info, 'r') as member:
        os.fchmod(output.fileno(), 0o400)
        while True:
            part = member.read(CHUNK)
            if not part:
                break
            count += len(part)
            require(count <= info.file_size and count <= maximum, 'ZIP expansion exceeds original bound')
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


def select_small(path, pin, policy, root, helper, report):
    outer = root / 'captured'
    outer.mkdir(mode=0o700, exist_ok=False)
    before = helper.read_file_hash(path, pin['bytes'], pin['sha256'])
    outer_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    actual = {}
    with os.fdopen(outer_fd, 'rb') as source, zipfile.ZipFile(source, 'r') as archive:
        infos = archive.infolist()
        require(0 < len(infos) <= 65 and len({i.filename for i in infos}) == len(infos),
                'small ZIP flat member denominator differs')
        require(sum(i.file_size for i in infos) <= SMALL_UNCOMPRESSED_LIMIT,
                'small ZIP uncompressed limit exceeded')
        for info in infos:
            require(re.fullmatch(r'(?:[0-9]{3}\.original|FINAL\.json)', info.filename) is not None,
                    'small ZIP fixed flat path refused')
            maximum = (1 << 20) if info.filename == 'FINAL.json' else SMALL_UNCOMPRESSED_LIMIT
            actual[info.filename] = retain(archive, info, outer / info.filename, maximum)
    require('FINAL.json' in actual, 'original FINAL is missing')
    final_raw = read(outer / 'FINAL.json', 1 << 20, policy['original_final_sha256'])
    final = json.loads(final_raw)
    context = final.get('context', {})
    require(final.get('schema') == 'hia.actions.elf-original-custody-final.v1'
            and context.get('repository') == REPO
            and context.get('event') == 'create' and context.get('event_ref_type') == 'branch'
            and context.get('run_id') == 43128015294 and context.get('run_attempt') == 1
            and context.get('actual_workflow_commit') == '2c26958e14e5b84e03c02811a4f081dd9adc3ac1'
            and context.get('actual_control_checkout') == '4126571681bfcbee2dbc65cc71d844e16dbae19c'
            and context.get('policy_sha256') == '26e37ca1cda26363318163ce369d6d0f7deb53b98800f9cb8632ef5e9f5a96df'
            and final.get('artifacts') == policy['original_artifacts']
            and final.get('status') in ('CUSTODY_HOLD',
                'TWO_HISTORICAL_CI_ORIGINALS_SMALL_CUSTODY_READY_NOT_QUALIFICATION')
            and final.get('original_600MB_ZIPs_included') is False
            and final.get('token_or_signed_URL_included') is False
            and final.get('qualification_executed') is False
            and final.get('project_code_executed') is False
            and final.get('original_product_statuses_reclassified') is False,
            'small artifact belongs to a different original operation or scope')
    source_ids = [str(x['id']) for x in policy['original_artifacts']]
    allowed = {'context.json', 'setup.json', 'recovery.json', 'recovery-terminal.json',
               'supervisor.stdout.log', 'supervisor.stderr.log',
               'guard/request.json', 'guard/guardian.json', 'guard/child.stdout.log', 'guard/child.stderr.log'}
    for aid in source_ids:
        allowed.add('api/artifact-' + aid + '.metadata.original.json')
        allowed.update('selected/' + aid + '/' + name for name in
                       ('DIRECTORY.json', 'SELECTED.json', 'CUSTODY.json',
                        'OBSERVATIONS.json', 'selected-originals.zip'))
        allowed.update('selected/' + aid + '/%04d.raw' % i for i in range(17))
    rows = final.get('captured')
    require(type(rows) is list and len(rows) <= 64
            and len({x['source_relative_path'] for x in rows}) == len(rows)
            and len({x['retained_file'] for x in rows}) == len(rows)
            and {x['retained_file'] for x in rows} | {'FINAL.json'} == set(actual),
            'complete captured member inventory differs')
    captured = {}
    for row in rows:
        name = row['source_relative_path']
        require(name in allowed and row.get('independent_copy_readback') is True
                and original_record_matches(actual[row['retained_file']], row),
                'captured original bytes differ from FINAL')
        captured[name] = (outer / row['retained_file'], row)
    require(sum(x['bytes'] for x in rows) == final.get('actual_public_original_bytes'),
            'captured original full-byte denominator differs')
    originals = json.loads(read(root / 'control/artifact-pins.json', 1 << 20,
        policy['control_files']['artifact-pins.json']['sha256']))
    require(originals['artifacts'] == policy['original_artifacts']
            and originals['source'] == policy['source']
            and len(originals['selected_members']) == 17
            and len(set(originals['selected_members'])) == 17,
            'unchanged original seventeen-path policy differs')
    requested = originals['selected_members']
    frame_files = [{'logical_path': 'small/FINAL.json', 'record': actual['FINAL.json'],
                    'origin': 'original small artifact FINAL bytes'}]
    missing = []
    selection_observations = []
    for aid in source_ids:
        prefix = 'selected/' + aid + '/'
        recovered = {}
        for name in ('CUSTODY.json', 'SELECTED.json', 'OBSERVATIONS.json'):
            logical = 'original/' + aid + '/' + name
            if prefix + name in captured:
                candidate, row = captured[prefix + name]
                frame_files.append({'logical_path': logical, 'record': actual[row['retained_file']],
                                    'origin': 'captured original metadata'})
            else:
                missing.append(logical)
        complete = False
        selected_path = captured.get(prefix + 'SELECTED.json')
        custody_path = captured.get(prefix + 'CUSTODY.json')
        archive_path = captured.get(prefix + 'selected-originals.zip')
        try:
            if selected_path and custody_path and archive_path:
                selection = json.loads(read(selected_path[0], 64 << 20))
                custody = json.loads(read(custody_path[0], 16 << 20))
                archive_record = custody.get('selected_custody', {}).get('archive', {})
                require(custody.get('schema') == 'hia.acffa.elf.original-CI-artifact-readback.v1'
                        and custody.get('artifact') == next(x for x in policy['original_artifacts']
                                                          if str(x['id']) == aid)
                        and custody.get('requested_member_count') == 17
                        and custody.get('selected_custody', {}).get('all_member_SHA_and_CRC_verified') is True
                        and original_record_matches(archive_record, archive_path[1])
                        and original_record_matches(custody['selected'], selected_path[1])
                        and selection.get('schema') == 'hia.ci-selected-original-members.v1',
                        'complete selected archive marker differs')
                members = selection['selected_members']
                require(type(members) is list and len(members) <= 17
                        and len({x['original_name'] for x in members}) == len(members)
                        and len({x['retained_file'] for x in members}) == len(members)
                        and all(x['original_name'] in requested
                                and x['retained_file'] == '%04d.raw' % requested.index(x['original_name'])
                                for x in members), 'selected original member mapping differs')
                directory = captured.get(prefix + 'DIRECTORY.json')
                require(directory is not None
                        and original_record_matches(custody['directory'], directory[1]),
                        'selected archive directory original differs')
                expected = {x['retained_file']: x for x in members}
                expected['DIRECTORY.json'] = directory[1]
                expected['SELECTED.json'] = selected_path[1]
                destination = root / 'selected' / aid
                destination.mkdir(mode=0o700, exist_ok=False)
                fd = os.open(archive_path[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                with os.fdopen(fd, 'rb') as stream, zipfile.ZipFile(stream, 'r') as bundle:
                    infos = bundle.infolist()
                    require(len(infos) == len(expected)
                            and {i.filename for i in infos} == set(expected)
                            and len(infos) == custody['selected_custody']['member_count'],
                            'selected complete archive inventory differs')
                    require(sum(i.file_size for i in infos) <= (288 << 20),
                            'selected original full expansion limit exceeded')
                    retained = {}
                    for info in infos:
                        retained[info.filename] = retain(bundle, info, destination / info.filename,
                                                         128 << 20, expected[info.filename])
                    for member in members:
                        recovered[member['original_name']] = retained[member['retained_file']]
                complete = True
        except Exception as error:
            if final['status'] != 'CUSTODY_HOLD':
                raise
            selection_observations.append({'artifact_id': int(aid), 'complete_archive': False,
                'error_type': type(error).__name__,
                'safe_refusal': str(error) if type(error) is Refusal else None})
            recovered = {}
        for index, name in enumerate(requested):
            fallback = captured.get(prefix + '%04d.raw' % index)
            if fallback:
                fallback_record = actual[fallback[1]['retained_file']]
                if name in recovered:
                    require(original_record_matches(recovered[name], fallback_record),
                            'duplicate raw and complete archive bytes differ')
                else:
                    recovered[name] = fallback_record
        if final['status'] != 'CUSTODY_HOLD':
            require(complete, 'successful original custody lacks its complete selected archive')
        selection_observations.append({'artifact_id': int(aid), 'complete_archive': complete,
            'actual_present_requested_members': [n for n in requested if n in recovered],
            'actual_missing_requested_members': [n for n in requested if n not in recovered],
            'all_present_complete_archive_payloads_independently_read': complete})
        for name in FRAME_TARGETS:
            logical = 'original/' + aid + '/' + name
            if name in recovered:
                frame_files.append({'logical_path': logical, 'record': recovered[name],
                                    'origin': 'complete selected archive' if complete else 'partial raw fallback'})
            else:
                missing.append(logical)
    require(len(frame_files) + len(missing) == 23
            and len({x['logical_path'] for x in frame_files}) == len(frame_files)
            and len(set(missing)) == len(missing)
            and not set(missing) & {x['logical_path'] for x in frame_files},
            'fixed twenty-three frame target denominator differs')
    require(sum(x['record']['bytes'] for x in frame_files) <= FRAME_RAW_LIMIT,
            'fixed original frame data exceed eight MiB; do not silently truncate')
    after = helper.read_file_hash(path, pin['bytes'], pin['sha256'])
    require(after == before, 'small original ZIP changed during full inspection')
    for item in frame_files:
        item['record'] = helper.read_file_hash(Path(item['record']['path']),
                                             item['record']['bytes'], item['record']['sha256'])
    report.update(original_final_status=final['status'], original_final_sha256=sha256(final_raw).hexdigest(),
        original_custody_capture_complete=final.get('capture_complete'),
        small_zip_before=before, small_zip_after=after,
        original_captured_count=len(rows), original_captured_bytes=sum(x['bytes'] for x in rows),
        frame_files=frame_files, missing_frame_targets=missing,
        selection_observations=selection_observations,
        unselected_original_product_members_executed=False,
        original_product_statuses_reclassified=False)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    control = root / 'control'
    policy = json.loads(read(control / 'policy.json', 1 << 20, args.policy_sha256))
    require(policy.get('schema') == 'hia.actions.small-original-frames-policy.v1',
            'small original frame policy differs')
    pin = policy['small_artifact']
    require(type(pin.get('id')) is int and 0 < pin['id']
            and type(pin.get('bytes')) is int and 0 < pin['bytes'] < 512 << 20
            and re.fullmatch(r'[0-9a-f]{64}', pin.get('sha256', '')) is not None
            and pin.get('run_id') == 43128015294
            and re.fullmatch(r'[0-9a-f]{64}', policy.get('original_final_sha256', '')) is not None,
            'external small artifact and original FINAL pins are not frozen')
    require(root == Path(os.environ['RUNNER_TEMP']).resolve() / policy['work_root_name'],
            'private small-reader root differs')
    token = os.environ.pop(TOKEN_VARIABLE, None)
    require(type(token) is str and 0 < len(token) < 16384, 'Actions read token required')
    helper = load_helper(control, policy, root)
    started = time.monotonic_ns()
    deadline = started + 720 * 1000000000
    report = {'schema': 'hia.actions.small-original-frames-worker.v1', 'status': 'READ_HOLD',
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
        stage = 'FULL_SMALL_AND_SELECTED_ORIGINALS'
        select_small(path, pin, policy, root, helper, report)
        report.update(status='SMALL_ORIGINALS_VERIFIED_PENDING_NATURAL_GUARDIAN',
                      elapsed_ns=time.monotonic_ns() - started)
        helper.create(root / 'recovery-terminal.json', wire(report))
        helper.checkpoint(report)
        print(json.dumps({'status': report['status'], 'original_final_status': report['original_final_status'],
                          'framed_original_targets': len(report['frame_files']),
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
