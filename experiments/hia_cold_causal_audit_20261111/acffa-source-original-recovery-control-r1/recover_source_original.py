"""Receive one externally sealed exact-Git source artifact without running it.

Only standard-library archival operations execute. The pack is streamed in
full for CRC/SHA custody, but no Git object is imported and no package script,
project module, clone, prerequisite or product test executes here.
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

ROOT = Path('/home/qian-qi/he26stackv9-source-original-r1')
KEY = 'hia-e26e-desktop-acffa-source-original-recovery-r1'
PIN_SHA = '6948cf7f54d74533237baf2c48d3eccf560ed155f53406f9a0160dcc83acf2f0'
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



def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON member')
        value[key] = item
    return value


def stream_pack(archive, info, expected):
    require(info.file_size == expected['size'], 'externally fixed pack size differs')
    count, digest = 0, sha256()
    with archive.open(info, 'r') as member:
        while True:
            block = member.read(CHUNK)
            if not block:
                break
            count += len(block)
            require(count <= expected['size'], 'pack member exceeds fixed size')
            digest.update(block)
    require(count == expected['size'] and digest.hexdigest() == expected['sha256'],
            'entire original pack member differs')
    return {'original_name': info.filename, 'bytes': count,
            'sha256': digest.hexdigest(), 'crc32': info.CRC,
            'original_mode': info.external_attr >> 16,
            'actual_entire_member_read': True, 'original_CRC_checked': True,
            'retained_inside_exact_original_ZIP': True,
            'objects_imported_or_reconstructed': False}


def inspect_source_metadata(folder, retained, pack, pins):
    rows = {x['original_name']: x for x in retained}
    def document(name):
        row = rows[name]
        raw = read_small(folder / row['retained_file'], row['sha256'],
                         pins['bounds']['metadata_member_bytes'])
        value = json.loads(raw, object_pairs_hook=unique_object)
        require(type(value) is dict, 'original JSON object required')
        return value
    expected = pins['source']
    artifact = pins['artifact']
    require(rows['package/manifest.json']['sha256'] == expected['manifest_sha256']
            and rows['package/source-package.py']['sha256'] == expected['consumer_sha256']
            and rows['package/source-package.py']['bytes'] == expected['consumer_bytes'],
            'original manifest or unexecuted consumer identity differs')
    manifest = document('package/manifest.json')
    require(manifest.get('schema') == 'hepta.hia.git-source-package.v1'
            and manifest.get('object_format') == 'sha1'
            and manifest.get('commit', {}).get('oid') == expected['commit']
            and manifest['commit'].get('tree') == expected['tree']
            and manifest.get('tree') == expected['tree']
            and manifest.get('counts') == expected['counts']
            and manifest.get('pack') == expected['pack'], 'sealed package header differs')
    require(len(manifest.get('entries', [])) == expected['counts']['entries']
            and len(manifest.get('objects', {})) == expected['counts']['objects']
            and len(manifest.get('leaves', [])) == expected['counts']['leaves'],
            'sealed package inventory populations differ')
    before = document('package/source-state-before.json')
    after = document('package/source-state-after.json')
    require(before == after and before.get('head') == expected['commit']
            and before.get('tree') == expected['tree'] and before.get('status') == ''
            and type(before.get('files')) is dict
            and len(before['files']) == expected['counts']['leaves']
            and before['files'].get('docs/HIA_SELFHOST_CORE_SUPPORT.json') == expected['contract_sha256'],
            'exported full source state header differs')
    for name in ('source-state-before.json', 'source-state-after.json'):
        original = rows['package/' + name]
        require(manifest.get('source_states', {}).get(name) ==
                {'size': original['bytes'], 'sha256': original['sha256']},
                'source-state original-byte hash differs')
    shallow = manifest.get('shallow', {})
    boundary = [expected['commit']]
    require(shallow.get('exported_boundary') == boundary
            and shallow.get('source_boundary') == boundary
            and shallow.get('ancestor_history_included') is False
            and shallow.get('original_parent_headers_preserved') is True,
            'original shallow-boundary statement differs')
    identity_report = document('IDENTITY.json')
    require(identity_report.get('schema') == 'hepta.hia.actions-source-custody.v1'
            and identity_report.get('status') == 'PASS'
            and identity_report.get('repository') == 'TrillionniumFoundation/Hepta'
            and identity_report.get('commit') == expected['commit']
            and identity_report.get('tree') == expected['tree']
            and identity_report.get('workflow_ref') == expected['workflow_ref']
            and identity_report.get('workflow_sha') == expected['commit']
            and identity_report.get('run_id') == str(artifact['run_id'])
            and identity_report.get('run_attempt') == str(artifact['run_attempt'])
            and identity_report.get('event_name') == artifact['event']
            and identity_report.get('manifest_sha256') == expected['manifest_sha256']
            and identity_report.get('pack') == expected['pack']
            and identity_report.get('counts') == expected['counts']
            and identity_report.get('shallow_boundary') == boundary
            and identity_report.get('ancestor_history_included') is False
            and identity_report.get('qualification_executed') is False,
            'original official Actions identity differs')
    export_report = document('package/export-report.json')
    require(export_report.get('schema') == 'hepta.hia.git-source-export.v1'
            and export_report.get('status') == 'PASS'
            and export_report.get('commit') == expected['commit']
            and export_report.get('tree') == expected['tree']
            and export_report.get('manifest_sha256') == expected['manifest_sha256']
            and export_report.get('pack') == expected['pack']
            and export_report.get('counts') == expected['counts']
            and export_report.get('source_before_equals_after') is True
            and export_report.get('qualification_executed') is False,
            'original source export report differs')
    reconstruction = document('reconstruction.json')
    require(reconstruction.get('schema') == 'hepta.hia.git-source-materialization.v1'
            and reconstruction.get('status') == 'PASS'
            and reconstruction.get('commit') == expected['commit']
            and reconstruction.get('tree') == expected['tree']
            and reconstruction.get('manifest_sha256') == expected['manifest_sha256']
            and reconstruction.get('pack') == expected['pack']
            and reconstruction.get('counts') == expected['counts']
            and reconstruction.get('qualification_executed') is False,
            'original Actions reconstruction report differs')
    for name in ('fsck_full_strict', 'exact_object_database', 'all_leaves_bytes_modes_verified',
                 'original_source_state_matches_export', 'original_parent_headers_preserved'):
        require(reconstruction.get(name) is True, 'original Actions report lacks ' + name)
    clone = reconstruction.get('clone_reproduction', {})
    require(reconstruction.get('original_source_state_before') == before
            and reconstruction.get('original_source_state_after') == before
            and reconstruction.get('shallow_boundary') == boundary
            and reconstruction.get('ancestor_history_included') is False
            and clone.get('status') == 'PASS' and clone.get('fsck_full_strict') is True
            and clone.get('exact_object_database') is True
            and clone.get('all_leaves_bytes_modes_verified') is True
            and clone.get('object_storage_hardlinks') == 0
            and clone.get('original_source_state_before') == before
            and clone.get('original_source_state_after') == before
            and clone.get('shallow_boundary') == boundary
            and clone.get('ancestor_history_included') is False,
            'original Actions independent-clone report differs')
    members = [pack, *retained]
    external = {row['original_name']: {'bytes': row['bytes'], 'sha256': row['sha256']}
                for row in members}
    return {'head': expected['commit'], 'tree': expected['tree'],
            'manifest_sha256': expected['manifest_sha256'],
            'package_files': {name.removeprefix('package/'): record for name, record in external.items()
                              if name.startswith('package/')},
            'receipt_files': {name: record for name, record in external.items()
                              if not name.startswith('package/')},
            'exact_original_eight_member_pins': external,
            'original_Actions_reports_checked': True,
            'original_Actions_reported_reconstruction_rerun_here': False,
            'source_pack_objects_imported_or_reconstructed_here': False,
            'qualification_executed': False}


def inspect(path, pins):
    artifact = pins['artifact']
    folder = ROOT / 'selected'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    retained, all_rows, original_members = [], [], []
    metadata_bytes = 0
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        with zipfile.ZipFile(source, 'r') as archive:
            all_rows, infos, declared_bytes = catalog(archive, artifact, pins['bounds'])
            require({name for name, info in infos.items() if not info.is_dir()} == set(pins['members'])
                    and set(name for name, info in infos.items() if info.is_dir()) <= {'package/'},
                    'exact eight original source artifact members required')
            pack = stream_pack(archive, infos['package/source.pack'], pins['source']['pack'])
            original_members.append(pack)
            for number, name in enumerate(pins['members']):
                if name == 'package/source.pack':
                    continue
                info = infos[name]
                metadata_bytes += info.file_size
                require(metadata_bytes <= pins['bounds']['total_metadata_bytes'],
                        'source metadata expansion bound exceeded')
                row = retain_member(archive, info, folder / ('%04d.original' % number),
                                    pins['bounds']['metadata_member_bytes'])
                retained.append(row)
                original_members.append(row)
            for row in all_rows:
                row['uncompressed_payload_independently_read'] = row['kind'] == 'regular'
            directory = {'schema': 'hia.original-source-artifact-ZIP-directory.v1',
                         'artifact': artifact, 'entries': all_rows, 'entry_count': len(all_rows),
                         'declared_uncompressed_bytes': declared_bytes,
                         'actual_all_regular_member_bytes_read': sum(x['bytes'] for x in original_members),
                         'all_eight_regular_member_CRC_and_SHA_checked': True,
                         'archive_comment_hex': archive.comment.hex(),
                         'central_directory_paths_types_checked': True,
                         'pack_objects_imported_or_reconstructed': False}
        require(identity(before) == identity(os.fstat(source.fileno()))
                and identity(before) == identity(path.lstat()), 'original source ZIP changed during inspection')
    directory_raw = wire(directory)
    create(folder / 'DIRECTORY.json', directory_raw)
    directory_record = read_file_hash(folder / 'DIRECTORY.json', len(directory_raw), sha256(directory_raw).hexdigest())
    custody = bundle_selected(folder, retained, directory_record)
    observed = inspect_source_metadata(folder, retained, pack, pins)
    result = {'schema': 'hia.stack-source-original-artifact-readback.v1',
              'artifact': artifact, 'directory': directory_record,
              'original_members': original_members,
              'original_regular_member_count': 8,
              'all_original_regular_members_fully_read': True,
              'actual_all_member_bytes_read': sum(x['bytes'] for x in original_members),
              'retained_metadata_count': 7, 'metadata_custody': custody,
              'source_observations': observed,
              'original_statuses_reclassified': False,
              'project_code_executed': False,
              'source_pack_objects_imported_or_reconstructed': False}
    create(folder / 'CUSTODY.json', wire(result))
    return result


def main():
    os.umask(0o077)
    started = time.monotonic_ns()
    report = {'schema': 'hia.stack-source-original-recovery.v1', 'status': 'RECOVERY_HOLD',
              'root': str(ROOT), 'stable_key': KEY, 'pins_sha256': PIN_SHA,
              'GET_attempts': [], 'artifacts': [], 'qualification_executed': False,
              'project_code_executed': False, 'old_runs_replayed': False,
              'source_pack_objects_imported_or_reconstructed': False,
              'source_package_program_executed': False,
              'consumer_clone_prerequisites_or_tests_requested': False,
              'natural_outer_guardian_acceptance_required': True}
    stage = 'INPUT_VALIDATION'
    try:
        pins = json.loads(read_small(ROOT / 'control/artifact-pins.json', PIN_SHA),
                          object_pairs_hook=unique_object)
        require(pins['root'] == str(ROOT) and pins['stable_key'] == KEY, 'fixed recovery root/key differs')
        private_raw = read_small(ROOT / 'control/request.private.json')
        private = json.loads(private_raw, object_pairs_hook=unique_object)
        require(private.get('schema') == 'hia.stack-source-original-private-request.v1'
                and private.get('stable_key') == KEY
                and private.get('artifact_pins_sha256') == PIN_SHA, 'private request identity differs')
        transports = private['transports']
        require(type(transports) is list and len(transports) == 1
                and transports[0]['artifact_id'] == pins['artifact']['id'],
                'single fixed transport required')
        report['private_request_sha256'] = sha256(private_raw).hexdigest()
        checkpoint(report)
        stage = 'ONE_ORIGINAL_GET'
        path = download(transports[0], pins['artifact'], time.monotonic_ns() + 720 * 1_000_000_000, report)
        stage = 'ORIGINAL_ZIP_BEFORE'
        first = read_file_hash(path, pins['artifact']['bytes'], pins['artifact']['sha256'])
        stage = 'ALL_EIGHT_MEMBERS_AND_ORIGINAL_REPORTS'
        result = inspect(path, pins)
        stage = 'ORIGINAL_ZIP_AFTER'
        second = read_file_hash(path, pins['artifact']['bytes'], pins['artifact']['sha256'])
        require(first == second, 'original source ZIP changed across full member inspection')
        result.update(zip_before=first, zip_after=second)
        report['artifacts'].append(result)
        report.update(status='SOURCE_ORIGINAL_AND_ALL_EIGHT_MEMBERS_VERIFIED_PENDING_NATURAL_GUARDIAN',
                      elapsed_ns=time.monotonic_ns() - started,
                      full_original_ZIP_bytes_per_read=pins['artifact']['bytes'])
        create(ROOT / 'recovery-terminal.json', wire(report))
        checkpoint(report)
        print(json.dumps({'status': report['status'], 'root': str(ROOT),
                          'artifact_id': pins['artifact']['id'],
                          'member_pins': result['source_observations']['exact_original_eight_member_pins'],
                          'qualification_executed': False}), flush=True)
        return 0
    except BaseException as error:
        report.update(status='RECOVERY_HOLD', failed_stage=stage,
                      error_type=type(error).__name__, safe_refusal=str(error) if type(error) is Refusal else None,
                      errno=getattr(error, 'errno', None), http_status=getattr(error, 'code', None),
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
