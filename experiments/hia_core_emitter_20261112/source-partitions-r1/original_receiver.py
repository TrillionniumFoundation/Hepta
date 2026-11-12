"""Recover two fixed original CI artifacts without executing project code.

The complete ZIP is independently hashed twice after its one GET. Only the
frozen list of original JSON and log members is decompressed and retained. The remaining ZIP
payload and the nested phase archives are not independently replayed.
Signed transport URLs remain in private input files and never enter receipts.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import time
import urllib.parse
import urllib.request
import zipfile

ROOT = Path('/home/qian-qi/he26-acffa-elf-ci-originals-r1')
KEY = 'hia-e26e-desktop-acffa-two-elf-ci-originals-recovery-r1'
PIN_SHA = '91bb6f6a1d138a7118f0d38ba473aecc3689ec803f4300fda7d7beb1a2755b86'
CHUNK = 1 << 20


class Refusal(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(path, raw, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as target:
        os.fchmod(target.fileno(), mode)
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())


def checkpoint(report):
    temporary = ROOT / 'recovery.next.json'
    create(temporary, wire(report), 0o600)
    os.replace(temporary, ROOT / 'recovery.json')
    sync_dir(ROOT)


def read_small(path, expected=None, maximum=1 << 20):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and before.st_size <= maximum,
                'owned bounded single-link input required')
        raw = source.read(maximum + 1)
        require(len(raw) == before.st_size
                and identity(before) == identity(os.fstat(source.fileno()))
                and identity(before) == identity(Path(path).lstat()), 'small input changed')
    if expected is not None:
        require(sha256(raw).hexdigest() == expected, 'small input hash differs')
    return raw


def read_file_hash(path, expected_size=None, expected_sha=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    digest, count = sha256(), 0
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o400,
                'retained input must be an independent owned read-only regular file')
        if expected_size is not None:
            require(before.st_size == expected_size, 'retained size differs')
        while True:
            block = source.read(CHUNK)
            if not block:
                break
            count += len(block)
            require(count <= before.st_size, 'retained input grew')
            digest.update(block)
        require(count == before.st_size
                and identity(before) == identity(os.fstat(source.fileno()))
                and identity(before) == identity(Path(path).lstat()), 'retained input changed')
    if expected_sha is not None:
        require(digest.hexdigest() == expected_sha, 'retained hash differs')
    return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
            'identity': list(identity(before)), 'actual_bytes_independently_read': count}


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        raise Refusal('transport redirect refused')


def download(transport, pin, deadline, report):
    url = transport['url']
    require(type(url) is str and len(url) <= 16384, 'bounded transport URL required')
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname
            and parsed.hostname.endswith('.oaiusercontent.com')
            and parsed.port in (None, 443) and not parsed.username
            and not parsed.password and not parsed.fragment, 'transport endpoint refused')
    require(parsed.hostname == transport['host']
            and sha256(url.encode()).hexdigest() == transport['url_sha256'],
            'private URL binding differs')
    path = ROOT / 'original' / ('artifact-%d.zip' % pin['id'])
    partial = path.with_name(path.name + '.partial')
    require(not os.path.lexists(path) and not os.path.lexists(partial),
            'create-only archive already exists')
    attempt = {'artifact_id': pin['id'], 'method': 'GET', 'attempt': 1,
               'host': parsed.hostname, 'url_sha256': transport['url_sha256'],
               'tool_response_sha256': transport['tool_response_sha256'],
               'started_ns': time.monotonic_ns(), 'socket_seconds': 30,
               'redirects': 0, 'retries': 0}
    report['GET_attempts'].append(attempt)
    checkpoint(report)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RefuseRedirects())
    request = urllib.request.Request(url, method='GET', headers={
        'User-Agent': 'HIA-original-CI-custody/1', 'Accept-Encoding': 'identity'})
    count, digest = 0, sha256()
    with opener.open(request, timeout=30) as response:
        require(response.status == 200 and response.geturl() == url, 'exact HTTP 200 required')
        encoding = response.headers.get('Content-Encoding')
        require(encoding is None or encoding.lower() == 'identity', 'encoded HTTP body refused')
        length = response.headers.get('Content-Length')
        require(length is None or int(length) == pin['bytes'], 'HTTP size differs')
        fd = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'w+b') as target:
            while True:
                require(time.monotonic_ns() < deadline, 'combined transfer deadline exceeded')
                block = response.read1(min(CHUNK, pin['bytes'] + 1 - count))
                require(time.monotonic_ns() < deadline, 'combined transfer deadline exceeded')
                if not block:
                    break
                count += len(block)
                require(count <= pin['bytes'], 'HTTP body exceeds fixed size')
                target.write(block)
                digest.update(block)
            require(count == pin['bytes'] and digest.hexdigest() == pin['sha256'],
                    'downloaded original ZIP differs')
            target.flush()
            os.fsync(target.fileno())
            os.fchmod(target.fileno(), 0o400)
            os.fsync(target.fileno())
    os.link(partial, path, follow_symlinks=False)
    os.unlink(partial)
    sync_dir(path.parent)
    attempt.update(bytes=count, sha256=digest.hexdigest(),
                   finished_ns=time.monotonic_ns(), output=str(path))
    checkpoint(report)
    return path


def catalog(archive, pin, bounds):
    infos = archive.infolist()
    require(len(infos) <= bounds['zip_entries'], 'ZIP entry limit exceeded')
    rows, names, kinds, total, metadata_bytes = [], set(), {}, 0, 0
    for index, info in enumerate(infos):
        name = info.filename
        require(type(name) is str and name and info.orig_filename == name and len(name) <= 4096
                and not name.startswith('/') and '\\' not in name
                and not any(ord(c) < 32 or ord(c) == 127 for c in name),
                'unsafe ZIP name')
        metadata_bytes += len(name.encode('utf-8')) + len(info.extra) + len(info.comment)
        require(metadata_bytes <= bounds['zip_directory_metadata_bytes'], 'ZIP directory metadata limit exceeded')
        directory = info.is_dir()
        key = name[:-1] if directory else name
        parts = key.split('/')
        require(parts and all(p and p not in ('.', '..') and ':' not in p for p in parts),
                'noncanonical ZIP path')
        require(name not in names and key not in kinds, 'duplicate ZIP entry')
        names.add(name)
        mode = info.external_attr >> 16
        kind = stat.S_IFMT(mode)
        require(not info.flag_bits & 1, 'encrypted ZIP entry refused')
        require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                'unsupported ZIP compression')
        require(not stat.S_IMODE(mode) & 0o7000, 'privileged ZIP mode refused')
        require(kind in ((0, stat.S_IFDIR) if directory else (0, stat.S_IFREG)),
                'link or special ZIP entry refused')
        require(info.file_size >= 0 and info.compress_size >= 0
                and 0 <= info.header_offset < pin['bytes'], 'ZIP extent differs')
        if directory:
            require(info.file_size == 0, 'nonempty ZIP directory')
        total += info.file_size
        require(total <= bounds['zip_declared_total_uncompressed_bytes'],
                'declared ZIP expansion limit exceeded')
        kinds[key] = 'directory' if directory else 'regular'
        rows.append({'index': index, 'name': name, 'kind': kinds[key],
                     'uncompressed_bytes': info.file_size, 'compressed_bytes': info.compress_size,
                     'crc32_from_directory': info.CRC, 'compression': info.compress_type,
                     'flags': info.flag_bits, 'external_attr': info.external_attr,
                     'internal_attr': info.internal_attr, 'create_system': info.create_system,
                     'create_version': info.create_version, 'extract_version': info.extract_version,
                     'header_offset': info.header_offset, 'date_time': list(info.date_time),
                     'extra_hex': info.extra.hex(), 'comment_hex': info.comment.hex(),
                     'uncompressed_payload_independently_read': False})
    for key in kinds:
        parents = key.split('/')[:-1]
        for count in range(1, len(parents) + 1):
            require(kinds.get('/'.join(parents[:count]), 'directory') == 'directory',
                    'ZIP file is an ancestor of another entry')
    return rows, {i.filename: i for i in infos}, total


def retain_member(archive, info, target, maximum):
    require(info.file_size <= maximum, 'selected member size exceeds bound')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    count, digest = 0, sha256()
    with os.fdopen(fd, 'wb') as output:
        with archive.open(info, 'r') as member:
            while True:
                block = member.read(CHUNK)
                if not block:
                    break
                count += len(block)
                require(count <= info.file_size, 'selected member exceeded declared size')
                output.write(block)
                digest.update(block)
        require(count == info.file_size, 'selected member ended early')
        output.flush()
        os.fsync(output.fileno())
        os.fchmod(output.fileno(), 0o400)
        os.fsync(output.fileno())
    observed = read_file_hash(target, count, digest.hexdigest())
    return {'original_name': info.filename, 'retained_file': target.name,
            'bytes': count, 'sha256': digest.hexdigest(), 'crc32': info.CRC,
            'original_mode': info.external_attr >> 16,
            'actual_entire_member_read': True, 'original_CRC_checked': True,
            'independent_retained_file_readback': observed}


def bundle_selected(folder, selected, directory_record):
    manifest = {'schema': 'hia.ci-selected-original-members.v1',
                'selected_members': selected, 'directory': directory_record,
                'unselected_nested_phase_archives_replayed': False}
    create(folder / 'SELECTED.json', wire(manifest))
    expected = {x['retained_file']: {'bytes': x['bytes'], 'sha256': x['sha256']}
                for x in selected}
    for name in ('DIRECTORY.json', 'SELECTED.json'):
        raw = read_small(folder / name, maximum=64 << 20)
        expected[name] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
    path = folder / 'selected-originals.zip'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'w+b') as output:
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED,
                             compresslevel=6, allowZip64=True) as archive:
            for name, pinned in expected.items():
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o400) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                raw_path = folder / name
                source_fd = os.open(raw_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                with os.fdopen(source_fd, 'rb') as source, archive.open(info, 'w', force_zip64=True) as member:
                    before = os.fstat(source.fileno())
                    count, digest = 0, sha256()
                    while True:
                        block = source.read(CHUNK)
                        if not block:
                            break
                        count += len(block)
                        require(count <= pinned['bytes'], 'selected input grew while packaging')
                        digest.update(block)
                        member.write(block)
                    require(count == pinned['bytes'] and digest.hexdigest() == pinned['sha256']
                            and identity(before) == identity(os.fstat(source.fileno()))
                            and identity(before) == identity(raw_path.lstat()), 'selected input changed while packaging')
        output.flush()
        os.fsync(output.fileno())
        os.fchmod(output.fileno(), 0o400)
        os.fsync(output.fileno())
    before = read_file_hash(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    actual_bytes = 0
    with os.fdopen(fd, 'rb') as source, zipfile.ZipFile(source, 'r') as archive:
        infos = archive.infolist()
        require(len(infos) == len(expected) and {i.filename for i in infos} == set(expected),
                'selected custody archive inventory differs')
        for info in infos:
            pin = expected[info.filename]
            require(info.file_size == pin['bytes'], 'custody member size differs')
            count, digest = 0, sha256()
            with archive.open(info, 'r') as member:
                while True:
                    block = member.read(CHUNK)
                    if not block:
                        break
                    count += len(block)
                    require(count <= pin['bytes'], 'custody member expanded past bound')
                    digest.update(block)
            require(count == pin['bytes'] and digest.hexdigest() == pin['sha256'],
                    'custody member full readback differs')
            actual_bytes += count
    after = read_file_hash(path, before['bytes'], before['sha256'])
    require(after == before, 'selected custody archive changed')
    sync_dir(folder)
    return {'archive': after, 'member_count': len(expected),
            'actual_all_member_bytes_read': actual_bytes,
            'all_member_SHA_and_CRC_verified': True,
            'raw_files_included_without_transformation': True}


def observations(folder, rows, pins):
    by_name = {x['original_name']: x for x in rows}
    def document(name):
        row = by_name.get(name)
        if row is None:
            return None
        raw = read_small(folder / row['retained_file'], row['sha256'],
                         pins['bounds']['json_observation_bytes'])
        value = json.loads(raw)
        require(type(value) is dict, 'expected original JSON object')
        return value

    cold = document('hia-cold.json')
    require(cold is not None and cold.get('schema') == 'hepta.hia.selfhost-cold-replay.v1',
            'original cold schema differs')
    source = cold.get('source_manifest')
    require(type(source) is dict and len(source) == pins['source']['cold_source_count'],
            'actual cold source denominator differs')
    canonical = json.dumps(source, sort_keys=True, separators=(',', ':')).encode()
    require(sha256(canonical).hexdigest() == pins['source']['source_manifest_canonical_sha256']
            and source.get('docs/HIA_SELFHOST_CORE_SUPPORT.json') == pins['source']['contract_sha256'],
            'original cold mapping differs from canonical acffa source')
    nested = by_name.get('hia-cold.cold/qualification.json')
    if nested is not None:
        require(cold.get('nested_report_sha256') == nested['sha256'],
                'nested cold report raw identity differs')
    gate = document('hia-machine-elf-caller-gate.json')
    require(gate is not None and gate.get('schema') == 'hepta.hia.compiler-owner-gate.v1'
            and gate.get('owner') == 'elf' and gate.get('operation') == 'owned-callers',
            'actual ELF caller gate identity differs')
    product = document('hia-machine-elf-callers-evidence/report.json')
    owner = document('hia-machine-elf-callers-owner/process-owner.json')
    request = document('hia-machine-elf-callers-owner/process-owner.json.request.json')
    returned = document('hia-machine-elf-callers-owner/run-result.json')
    manifest = document('hia-machine-elf-callers-evidence/qualified/manifest.json')
    build = document('hia-machine-elf-callers-evidence/qualified/build.json')
    component_gate = document('hia-machine-elf-component-gate.json')
    component = document('hia-machine-elf-component-evidence/report.json')
    generation = document('hia-cold.cold/qualification.evidence/B3.receipt.json')

    def project(value, keys):
        return None if value is None else {key: value.get(key) for key in keys}
    result = {
        'schema': 'hia.acffa.elf-original-CI-observations.v1',
        'canonical_source_manifest_sha256': sha256(canonical).hexdigest(),
        'source_manifest_matches_canonical_mapping': True,
        'cold': project(cold, ('schema', 'status', 'checks', 'wall_elapsed_ns',
                              'nested_report_sha256', 'generation_sha256')),
        'B3_receipt': project(generation, ('status', 'abi_status', 'produced_bytes',
                                           'produced_sha256', 'artifact_sha256')),
        'gate': project(gate, ('schema', 'owner', 'operation', 'status', 'error',
                              'final_identity_error', 'source_preserved',
                              'cold_inputs_preserved', 'seconds', 'gates')),
        'product_report_present': product is not None,
        'product': project(product, ('schema', 'status', 'scope', 'failure',
            'source_failure', 'tests_loaded', 'tests_run', 'expected_count',
            'expected_test_ids', 'loaded_test_ids', 'executed_test_ids', 'loader_errors',
            'anomaly_counts', 'failures', 'errors', 'retained_writer_calls',
            'native_operation_counts', 'source_stable', 'bundle_stable',
            'cold_report_sha256', 'manifest_sha256', 'image_sha256', 'seconds')),
        'owner_receipt_present': owner is not None,
        'owner': project(owner, ('schema', 'status', 'returncode', 'timed_out',
            'qualification_seconds', 'cleanup_seconds', 'qualification_started',
            'exit_observed_before_deadline', 'subreaper_enabled', 'event_overflow',
            'interrupted_signals', 'owner_error', 'cleanup', 'events')),
        'request': project(request, ('schema', 'command', 'cwd',
                                    'qualification_seconds', 'cleanup_seconds')),
        'returned_owner_wrapper': project(returned, ('schema', 'status', 'error',
            'final_identity_error', 'source_preserved', 'cold_inputs_preserved')),
        'build': project(build, ('schema', 'status', 'scope', 'failure',
            'compiler_sha256', 'cold_report_sha256', 'build_inputs_stable',
            'manifest_sha256', 'native_compile_receipt')),
        'manifest': manifest,
        'component_gate': project(component_gate, ('schema', 'owner', 'operation',
            'status', 'error', 'source_preserved', 'cold_inputs_preserved', 'seconds')),
        'component_report': project(component, ('schema', 'status', 'tests_run',
            'loaded_test_ids', 'executed_test_ids', 'anomaly_counts', 'source_preserved',
            'cold_inputs_preserved', 'builds_preserved', 'seconds')),
        'original_statuses_reclassified': False,
        'original_checks_independently_rerun': False,
        'exported_source_file_payloads_independently_read': False,
    }
    if returned is not None and owner is not None:
        value = returned.get('returned_owner')
        if type(value) is dict:
            projected = {key: item for key, item in value.items()
                         if key not in ('supervisor_returncode', 'receipt_sha256')}
            result['returned_owner_raw_binding'] = {
                'supervisor_returncode': value.get('supervisor_returncode'),
                'receipt_sha_matches': value.get('receipt_sha256') ==
                    by_name['hia-machine-elf-callers-owner/process-owner.json']['sha256'],
                'full_original_projection_equal': projected == owner,
            }
    return result

def inspect(path, pin, pins):
    folder = ROOT / 'selected' / str(pin['id'])
    folder.mkdir(mode=0o700, exist_ok=False)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    rows, selected, selected_bytes = [], [], 0
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        with zipfile.ZipFile(source, 'r') as archive:
            rows, infos, declared_bytes = catalog(archive, pin, pins['bounds'])
            require(len(pins['selected_members']) == pins['selected_count'] == 17
                    and len(set(pins['selected_members'])) == 17,
                    'fixed requested member denominator differs')
            missing = []
            for number, name in enumerate(pins['selected_members']):
                if name not in infos or infos[name].is_dir():
                    missing.append(name)
                    continue
                info = infos[name]
                selected_bytes += info.file_size
                require(selected_bytes <= pins['bounds']['selected_total_bytes_per_artifact'],
                        'selected total expansion limit exceeded')
                target = folder / ('%04d.raw' % number)
                selected.append(retain_member(archive, info, target, pins['bounds']['selected_member_bytes']))
            read_names = {x['original_name'] for x in selected}
            for row in rows:
                row['uncompressed_payload_independently_read'] = row['name'] in read_names
            directory = {'schema': 'hia.original-ci-ZIP-directory.v1',
                         'artifact': pin, 'entries': rows, 'entry_count': len(rows),
                         'declared_uncompressed_bytes': declared_bytes,
                         'selected_uncompressed_bytes_read': selected_bytes,
                         'requested_members': pins['selected_members'],
                         'missing_requested_members': missing,
                         'archive_comment_hex': archive.comment.hex(),
                         'central_directory_paths_types_checked': True,
                         'unselected_member_CRC_or_payload_SHA_checked': False}
        require(identity(before) == identity(os.fstat(source.fileno()))
                and identity(before) == identity(path.lstat()), 'original ZIP changed during selection')
    raw = wire(directory)
    create(folder / 'DIRECTORY.json', raw)
    directory_record = read_file_hash(folder / 'DIRECTORY.json', len(raw), sha256(raw).hexdigest())
    # Raw custody is completed before semantic header observations. A later
    # observation refusal preserves the originals and the independently read archive.
    custody = bundle_selected(folder, selected, directory_record)
    selected_record = read_file_hash(folder / 'SELECTED.json')
    stage_report = {'schema': 'hia.acffa.elf.original-CI-artifact-readback.v1',
                    'artifact': pin, 'directory': directory_record, 'selected': selected_record,
                    'requested_member_count': pins['selected_count'],
                    'selected_member_count': len(selected), 'selected_raw_bytes': selected_bytes,
                    'selected_member_names': [row['original_name'] for row in selected],
                    'missing_requested_members': missing,
                    'selected_custody': custody, 'header_observations': None,
                    'inner_phase_ZIPs_replayed': False, 'project_code_executed': False}
    create(folder / 'CUSTODY.json', wire(stage_report))
    require(not set(pins['required_members']).intersection(missing),
            'required original gate/cold record missing; available originals retained')
    stage_report['header_observations'] = observations(folder, selected, pins)
    create(folder / 'OBSERVATIONS.json', wire(stage_report['header_observations']))
    return stage_report


def main():
    os.umask(0o077)
    started = time.monotonic_ns()
    report = {'schema': 'hia.acffa.elf.two-original-CI-recovery.v1', 'status': 'RECOVERY_HOLD',
              'root': str(ROOT), 'stable_key': KEY, 'pins_sha256': PIN_SHA,
              'GET_attempts': [], 'artifacts': [], 'qualification_executed': False,
              'project_code_executed': False, 'old_runs_replayed': False,
              'unselected_inner_stage_binaries_independently_replayed': False,
              'natural_outer_guardian_acceptance_required': True}
    stage = 'INPUT_VALIDATION'
    try:
        pins = json.loads(read_small(ROOT / 'control/artifact-pins.json', PIN_SHA))
        require(pins['root'] == str(ROOT) and pins['stable_key'] == KEY, 'fixed recovery root/key differs')
        private_raw = read_small(ROOT / 'control/request.private.json')
        private = json.loads(private_raw)
        require(private.get('schema') == 'hia.acffa.elf.ci-original-private-request.v1'
                and private.get('stable_key') == KEY
                and private.get('artifact_pins_sha256') == PIN_SHA, 'private request identity differs')
        transports = private['transports']
        require(type(transports) is list and len(transports) == 2
                and [x['artifact_id'] for x in transports] == [x['id'] for x in pins['artifacts']],
                'private transport population/order differs')
        report['private_request_sha256'] = sha256(private_raw).hexdigest()
        deadline = time.monotonic_ns() + 720 * 1_000_000_000
        checkpoint(report)
        for pin, transport in zip(pins['artifacts'], transports, strict=True):
            stage = 'GET_%d' % pin['id']
            path = download(transport, pin, deadline, report)
            stage = 'ORIGINAL_BEFORE_%d' % pin['id']
            first = read_file_hash(path, pin['bytes'], pin['sha256'])
            stage = 'SAFE_DIRECTORY_AND_SELECTED_ORIGINALS_%d' % pin['id']
            result = inspect(path, pin, pins)
            stage = 'ORIGINAL_AFTER_%d' % pin['id']
            second = read_file_hash(path, pin['bytes'], pin['sha256'])
            require(first == second, 'original ZIP changed across selected-member verification')
            result.update(zip_before=first, zip_after=second)
            report['artifacts'].append(result)
            checkpoint(report)
        report.update(status='ORIGINALS_AND_SELECTED_REPORTS_VERIFIED_PENDING_NATURAL_GUARDIAN',
                      elapsed_ns=time.monotonic_ns() - started,
                      full_original_ZIP_bytes_per_read=sum(x['bytes'] for x in pins['artifacts']))
        create(ROOT / 'recovery-terminal.json', wire(report))
        checkpoint(report)
        print(json.dumps({'status': report['status'], 'artifacts': len(report['artifacts']),
                          'root': str(ROOT), 'qualification_executed': False}), flush=True)
        return 0
    except BaseException as error:
        # Do not leak URL-bearing exception text from urllib or private input.
        report.update(status='RECOVERY_HOLD', failed_stage=stage,
                      error_type=type(error).__name__, safe_refusal=str(error) if type(error) is Refusal else None,
                      errno=getattr(error, 'errno', None),
                      http_status=getattr(error, 'code', None),
                      elapsed_ns=time.monotonic_ns() - started)
        try:
            if not os.path.lexists(ROOT / 'recovery-terminal.json'):
                create(ROOT / 'recovery-terminal.json', wire(report))
            checkpoint(report)
        except BaseException:
            pass
        print(json.dumps({'status': 'RECOVERY_HOLD', 'failed_stage': stage,
                          'error_type': type(error).__name__}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
