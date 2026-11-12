"""Recover the exact 39 generated Core Emitter units; never regenerate or execute them."""
from __future__ import annotations

from hashlib import sha1, sha256
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
            and value.get('workflow_run', {}).get('head_sha') == pin['head_sha']
            and value.get('name') == pin['name']
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
    # Only its destination path is re-rooted. The complete historical module is
    # preserved. This reader calls only checkpoint/create/read_file_hash/sync_dir;
    # its old download and CI-specific selection routines are not invoked.
    module.ROOT = root
    return module



FRAME_RAW_LIMIT = 8 << 20
ARCHIVE_RAW_LIMIT = 32 << 20


def load_pins(control, policy):
    pin = policy['control_files']['asset-pins.json']
    raw = read(control / 'asset-pins.json', 1 << 20, pin['sha256'])
    require(len(raw) == pin['bytes'], 'fixed asset pin size differs')
    value = json.loads(raw)
    rows = value.get('archive_members')
    require(value.get('schema') == 'hia.core-emitter-generated-assets-external-pins.v1'
            and value.get('artifact') == policy['source_artifact']
            and type(rows) is list and len(rows) == 103
            and value.get('archive_file_count') == 103
            and value.get('selected_file_count') == 54
            and value.get('assembly_count') == 39
            and value.get('assembly_bytes') == 7085393
            and value.get('abi_bytes') == 3856
            and value.get('source_generated_again') is False
            and value.get('product_execution') is False
            and value.get('cold_qualification') is False,
            'complete frozen asset policy differs')
    require(len({row['archive_path'] for row in rows}) == 103,
            'duplicate frozen archive path')
    selected = [row for row in rows if row['logical_path'] is not None]
    require(len(selected) == 54 and len({row['logical_path'] for row in selected}) == 54
            and sum(row['bytes'] for row in selected) == value['selected_raw_bytes'] == 7251108
            and sum(row['bytes'] for row in rows) == value['archive_uncompressed_bytes'] == 12024858,
            'complete original byte denominator differs')
    for row in rows:
        name = row['archive_path']
        require(type(name) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', name) is not None
                and not name.startswith('/') and all(part not in ('', '.', '..')
                    for part in name.split('/'))
                and type(row['bytes']) is int and 0 <= row['bytes'] <= 2 << 20
                and re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is not None
                and re.fullmatch(r'[0-9a-f]{40}', row['git_blob_sha1']) is not None,
                'unsafe or unbound original member')
        logical = row['logical_path']
        require(logical is None or (type(logical) is str
                and re.fullmatch(r'[A-Za-z0-9_./-]+', logical) is not None
                and not logical.startswith('/') and all(part not in ('', '.', '..')
                    for part in logical.split('/'))), 'unsafe logical frame path')
    return value


def safe_info(info, expected):
    require(not info.is_dir() and not info.flag_bits & 1
            and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
            and info.file_size == expected['bytes'] and info.compress_size >= 0,
            'exact regular unencrypted original ZIP member required')
    require(stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG),
            'ZIP link or special member refused')


def read_member(archive, info, expected, target):
    safe_info(info, expected)
    count, digest = 0, sha256()
    git_digest = sha1(b'blob ' + str(info.file_size).encode('ascii') + b'\0')
    output = None
    try:
        if target is not None:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
            output = os.fdopen(fd, 'wb')
            os.fchmod(output.fileno(), 0o400)
        with archive.open(info, 'r') as member:
            while True:
                part = member.read(CHUNK)
                if not part:
                    break
                count += len(part)
                require(count <= info.file_size, 'member exceeds fixed original size')
                digest.update(part)
                git_digest.update(part)
                if output is not None:
                    output.write(part)
        require(count == expected['bytes'] and digest.hexdigest() == expected['sha256']
                and git_digest.hexdigest() == expected['git_blob_sha1'],
                'full member differs from its external original pin')
        if output is not None:
            output.flush()
            os.fsync(output.fileno())
        return {'archive_path': info.filename, 'bytes': count,
                'sha256': digest.hexdigest(), 'git_blob_sha1': git_digest.hexdigest(),
                'zip_crc32': info.CRC, 'compressed_bytes': info.compress_size,
                'external_attr': info.external_attr, 'full_member_CRC_read': True}
    finally:
        if output is not None:
            output.close()


def validate_original_operation(pins, records):
    def raw(name):
        item = records['original/' + name]
        return read(Path(item['path']), 2 << 20, item['sha256'])
    def document(name):
        return json.loads(raw(name))
    context = document('context.json')
    setup = document('setup.json')
    config = document('guard/request.json')
    guardian = document('guard/guardian.json')
    original = document('evidence/report.json')
    final = document('FINAL.json')
    expected = pins['original_run']
    old_root = expected['root']
    require(context.get('schema') == 'hia.core-emitter-actions-context.v1'
            and context.get('repository') == REPO and context.get('event') == 'create'
            and context.get('run_id') == expected['run_id']
            and context.get('run_attempt') == 1
            and context.get('workflow_commit') == expected['workflow_commit']
            and context.get('actual_control_commit') == expected['control_commit']
            and context.get('policy_sha256') == expected['policy_sha256']
            and context.get('root') == old_root and context.get('source') == expected['source']
            and context.get('candidate_commit') == expected['candidate_commit']
            and context.get('candidate_tree') == expected['candidate_tree']
            and context.get('candidate_leaves') == 4023
            and context.get('controller_seconds') == 180 and context.get('cleanup_seconds') == 3,
            'original source authoring context differs')
    require(setup.get('context') == context
            and config.get('schema') == 'hia-external-guardian-request.v1'
            and config.get('command') == setup.get('command')
            and config.get('cwd') == old_root and config.get('controller_seconds') == 180
            and config.get('source_identities') == setup.get('source_identities')
            and sha256(raw('guard/request.json')).hexdigest() == setup.get('guardian_config_sha256'),
            'original setup and owner request differ')
    life = guardian.get('lifecycle', {})
    cleanup = life.get('cleanup', {})
    events = life.get('events', [])
    require(guardian.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and guardian.get('status') == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and guardian.get('command') == config['command'] and guardian.get('cwd') == old_root
            and guardian.get('external_controller_seconds') == 180
            and guardian.get('input_identity_preserved') is True
            and guardian.get('source_identities_before') == config['source_identities']
            and guardian.get('source_identities_after') == config['source_identities']
            and guardian.get('lifecycle_implementation_sha256') ==
                config['source_identities'][old_root + '/control/process_owner_impl.py']
            and life.get('status') == 'OWNED_PROCESS_COMPLETED' and life.get('returncode') == 0
            and life.get('qualification_seconds') == 180 and life.get('cleanup_seconds') == 3
            and life.get('timed_out') is False and life.get('exit_observed_before_deadline') is True
            and life.get('subreaper_enabled') is True and life.get('qualification_started') is True
            and life.get('event_overflow') is False and life.get('interrupted_signals') == []
            and life.get('owner_error') is None
            and cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == []
            and type(events) is list and len(events) == 4
            and {event.get('kind') for event in events} ==
                {'qualification_started', 'owned_child_observed',
                 'qualification_exit_observed', 'owned_child_reaped'},
            'original authoring natural lifecycle differs')
    require(guardian.get('logs') == {
                old_root + '/guard/' + name: sha256(raw('guard/' + name)).hexdigest()
                for name in ('child.stdout.log', 'child.stderr.log')},
            'original authoring log identity differs')
    require(original.get('schema') == 'hia.core-emitter-actions-authoring.v1'
            and original.get('status') == 'DEVELOPMENT_ACTIONS_EMITTER_AUTHORING_PASS'
            and original.get('context_sha256') == sha256(raw('context.json')).hexdigest()
            and original.get('candidate_commit') == expected['candidate_commit']
            and original.get('candidate_tree') == expected['candidate_tree']
            and original.get('source_preserved') is True
            and original.get('candidate_physical_namespace_verified') is True
            and original.get('error') is None and original.get('preservation_error') is None
            and original.get('original_AST', {}).get('original_bodies') == 33
            and original.get('original_AST', {}).get('all_exact') is True
            and original.get('finite_IR', {}).get('functions') == 36
            and original.get('expected_unit_count') == 39,
            'original source-only observation differs')
    for name in ('native_compiler_executed', 'Core_VM_executed', 'product_tests_executed',
                 'cold_qualified', 'old_v1_results_inherited', 'original_limits_changed',
                 'derived_global_contracts_regenerated'):
        require(original.get(name) is False, 'original source-only scope differs')
    require(final.get('schema') == 'hia.core-emitter-actions-final.v1'
            and final.get('status') == 'SOURCE_ONLY_CORE_EMITTER_V2_AUTHORING_PASS'
            and final.get('context') == context
            and final.get('closed_ECHILD_before_output_read') is True
            and final.get('outputs', {}).get('units') == 39
            and final.get('outputs', {}).get('modes') == 36
            and final.get('outputs', {}).get('complete_AST_bodies') == 33,
            'original finalizer source-only observation differs')
    for name in ('native_compiler_executed', 'Core_VM_executed', 'product_tests_executed',
                 'cold_qualified', 'old_v1_results_inherited', 'original_limits_changed',
                 'qualification_executed'):
        require(final.get(name) is False, 'original finalizer scope differs')
    by_name = {row['archive_path']: row for row in pins['archive_members']}
    prefix = old_root.removeprefix('/home/runner/work/_temp/') + '/'
    def match_pin(value):
        require(type(value) is dict and value['path'].startswith(old_root + '/'),
                'original report pin escapes its own root')
        name = value['path'].removeprefix('/home/runner/work/_temp/')
        frozen = by_name[name]
        require(value['size'] == frozen['bytes'] and value['sha256'] == frozen['sha256']
                and value['git_blob_sha1'] == frozen['git_blob_sha1'],
                'original report pin differs from the independently frozen member')
    units = original['units']
    expected_names = ['core_lowering_pool'] + ['core_lowering_%03d' % n for n in range(38)]
    require(type(units) is list and [row['name'] for row in units] == expected_names,
            'original complete 39-unit order differs')
    limits = {'source_bytes': 1048576, 'source_lines': 16384, 'functions': 128,
              'blocks_total': 1536, 'blocks_per_function': 256, 'instructions': 8192,
              'ssa_names_per_function': 2048, 'parameters_or_arguments': 16}
    require(original.get('unchanged_limits') == limits, 'original compiler limits differ')
    for row in units:
        require(row.get('status') == 'PASS' and row.get('public_core_roundtrip') is True
                and re.fullmatch(r'[0-9a-f]{64}', row['checked_core_sha256']) is not None
                and all(type(row['structure'][key]) is int
                        and 0 <= row['structure'][key] <= maximum for key, maximum in limits.items()),
                'original unit roundtrip or unchanged limit observation differs')
        match_pin(row)
        match_pin(row['authoring'])
    for name in ('abi', 'candidate_before', 'candidate_after',
                 'candidate_physical_before', 'candidate_physical_after'):
        match_pin(original[name])
    for field, logical in (('report', 'original/evidence/report.json'),
                           ('abi', 'source/hepta/hia_core_lowering_abi.json')):
        value, record = final['outputs'][field], records[logical]
        require(value['bytes'] == record['bytes'] and value['sha256'] == record['sha256'],
                'original finalizer bytes differ from retained source')
    require(final['guardian_original']['sha256'] ==
                records['original/guard/guardian.json']['sha256'],
            'original finalizer guardian identity differs')
    return {'original_final_status': final['status'], 'original_authoring_status': original['status'],
            'original_report_sha256': records['original/evidence/report.json']['sha256'],
            'original_guardian_sha256': records['original/guard/guardian.json']['sha256'],
            'original_final_sha256': records['original/FINAL.json']['sha256'],
            'original_unit_count': 39, 'original_complete_AST_bodies': 33,
            'original_mode_count': 36, 'original_source_only_scope_preserved': True}


def select_assets(path, pin, policy, root, helper, report):
    pins = load_pins(root / 'control', policy)
    expected = {row['archive_path']: row for row in pins['archive_members']}
    selected = [row for row in pins['archive_members'] if row['logical_path'] is not None]
    selected_index = {row['archive_path']: index for index, row in enumerate(selected)}
    before = helper.read_file_hash(path, pin['bytes'], pin['sha256'])
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    observed, retained = [], {}
    report['archive_inventory'] = observed
    with os.fdopen(descriptor, 'rb') as source, zipfile.ZipFile(source, 'r') as archive:
        original_stat = os.fstat(source.fileno())
        infos = archive.infolist()
        require(len(infos) == len(expected) == 103
                and len({info.filename for info in infos}) == 103
                and {info.filename for info in infos} == set(expected)
                and sum(info.file_size for info in infos) == pins['archive_uncompressed_bytes']
                and sum(info.file_size for info in infos) <= ARCHIVE_RAW_LIMIT,
                'complete fixed 103-member original archive inventory differs')
        for info in infos:
            frozen = expected[info.filename]
            index = selected_index.get(info.filename)
            target = root / 'selected' / ('%03d.original' % index) if index is not None else None
            row = read_member(archive, info, frozen, target)
            observed.append(row)
            if target is not None:
                retained[frozen['logical_path']] = helper.read_file_hash(
                    target, frozen['bytes'], frozen['sha256'])
            if len(observed) % 16 == 0:
                helper.checkpoint(report)
        require(identity(original_stat) == identity(os.fstat(source.fileno()))
                and identity(original_stat) == identity(path.lstat()),
                'original archive changed during complete CRC read')
    require(len(observed) == 103 and len(retained) == 54,
            'full original member read denominator differs')
    source_observation = validate_original_operation(pins, retained)
    frames = [{'logical_path': row['logical_path'],
               'record': retained[row['logical_path']],
               'origin': 'exact original artifact member ' + row['archive_path']}
              for row in selected]
    require(sum(item['record']['bytes'] for item in frames) == pins['selected_raw_bytes']
            and pins['selected_raw_bytes'] <= FRAME_RAW_LIMIT,
            'complete original source framing budget differs')
    after = helper.read_file_hash(path, pin['bytes'], pin['sha256'])
    require(after == before, 'original ZIP changed across full inspection')
    report.update(source_observation)
    report.update(artifact_before=before, artifact_after=after,
        archive_member_count=len(observed),
        archive_uncompressed_bytes=sum(row['bytes'] for row in observed),
        all_archive_members_fully_read_and_CRC_verified=True,
        all_archive_members_match_external_SHA_and_Git_blob=True,
        unframed_authoring_count=39, unframed_source_inventory_count=4,
        unframed_control_source_count=6,
        unframed_originals_verified_not_in_log=True,
        frame_files=frames, missing_frame_targets=[],
        selected_original_bytes=sum(item['record']['bytes'] for item in frames))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    control = root / 'control'
    policy = json.loads(read(control / 'policy.json', 1 << 20, args.policy_sha256))
    require(policy.get('schema') == 'hia.actions.core-emitter-assets-policy.v1',
            'Core original asset policy differs')
    pin = policy['source_artifact']
    require(pin.get('id') == 13907470026 and pin.get('bytes') == 12049642
            and pin.get('sha256') == 'e6d54cec5c3788221827bf25a3189838dbc884211d89c3ef86afa129117319d8'
            and pin.get('run_id') == 43131161021
            and pin.get('head_sha') == '4d508b8e7b66d8f2801e76f6b6bb4794eb4bdac7',
            'fixed actual source artifact differs')
    require(root == Path(os.environ['RUNNER_TEMP']).resolve() / policy['work_root_name'],
            'private original-asset reader root differs')
    token = os.environ.pop(TOKEN_VARIABLE, None)
    require(type(token) is str and 0 < len(token) < 16384, 'Actions read token required')
    helper = load_helper(control, policy, root)
    started = time.monotonic_ns()
    deadline = started + 720 * 1000000000
    report = {'schema': 'hia.actions.core-emitter-assets-worker.v1', 'status': 'READ_HOLD',
        'root': str(root), 'policy_sha256': args.policy_sha256,
        'external_pins_sha256': policy['control_files']['asset-pins.json']['sha256'],
        'API_attempts': [], 'GET_attempts': [], 'source_artifact': pin,
        'project_code_executed': False, 'qualification_executed': False,
        'original_product_statuses_reclassified': False,
        'source_generated_again': False, 'native_compiler_executed': False,
        'Core_VM_executed': False, 'product_tests_executed': False,
        'token_or_signed_URL_recorded': False}
    stage = 'FROZEN_INPUTS'
    try:
        load_pins(control, policy)
        helper.checkpoint(report)
        stage = 'OFFICIAL_METADATA'
        report['official_metadata'] = metadata(token, pin, root, deadline, report, helper)
        stage = 'OFFICIAL_LOCATION'
        url = official_location(token, pin, deadline, report, helper)
        stage = 'ORIGINAL_ZIP_GET'
        path = storage_download(url, pin, root, deadline, report, helper)
        del url
        stage = 'ALL_103_ORIGINAL_MEMBERS'
        select_assets(path, pin, policy, root, helper, report)
        report.update(status='CORE_EMITTER_ASSETS_VERIFIED_PENDING_NATURAL_GUARDIAN',
                      elapsed_ns=time.monotonic_ns() - started)
        helper.create(root / 'recovery-terminal.json', wire(report))
        helper.checkpoint(report)
        print(json.dumps({'status': report['status'], 'original_final_status': report['original_final_status'],
                          'actual_original_units': 39, 'framed_original_targets': len(report['frame_files']),
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
