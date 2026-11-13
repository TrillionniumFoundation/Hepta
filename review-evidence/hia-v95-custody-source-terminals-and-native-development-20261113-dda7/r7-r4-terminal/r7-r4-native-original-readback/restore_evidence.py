"""Restore and audit frozen CI evidence; never execute any restored file."""
from __future__ import annotations

import base64
from collections import Counter
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import traceback
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT.parent
OUTPUT = ROOT / 'restored'
CHUNK = 1024 * 1024
EXPECTED = {
    'native.zip': (98307377, '1f9590a096fab0ae05f87a296cd2db821e17929e7bc9111182add0d9f8f8a1c9', 10178, 577070871),
    'source-vm.zip': (296429, '8356b4fb59577e7ff809490c558f255368771c7753039f350a4399f06fd5695c', 69, 616820),
    'wire.zip': (67563, 'f5dd72900fb18a1c9e5d62fcef1194184a8b27c49a4661a708384db9dd4c1886', 1, 167806),
}
LOGS = {
    'FULL-JOB.log': (69590, 'd304602ea70e0bcc541c215f1265e5b17448e22b'),
    'SOURCE-JOB.log': (370073, '7cd5bf57c7ac02807c1855f3403a0e80d5470f7b'),
}
NATIVE_MODES = {'100644': 8628, '100600': 71, '100755': 2,
                '100700': 7, '100400': 1452, '100500': 18}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()


def put(name, value):
    path = ROOT / name
    assert not path.exists(), path
    path.write_bytes(encode(value))


def file_identity(path):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and not path.is_symlink(), path
    sha, git = hashlib.sha256(), hashlib.sha1(b'blob ' + str(info.st_size).encode() + b'\0')
    size = 0
    with path.open('rb') as stream:
        while chunk := stream.read(CHUNK):
            sha.update(chunk); git.update(chunk); size += len(chunk)
    assert size == info.st_size
    return {'bytes': size, 'sha256': sha.hexdigest(), 'git_blob': git.hexdigest(),
            'mode': format(stat.S_IMODE(info.st_mode), '04o'), 'mtime_ns': info.st_mtime_ns}


def safe_name(value, directory=False):
    assert type(value) is str and value and '\x00' not in value and '\\' not in value
    raw = value[:-1] if directory and value.endswith('/') else value
    assert raw and not raw.startswith('/') and not re.match(r'^[A-Za-z]:', raw)
    parts = raw.split('/')
    assert all(part not in ('', '.', '..') for part in parts), value
    assert PurePosixPath(raw).as_posix() == raw
    return raw, parts


def member_metadata(info):
    raw_mode = info.external_attr >> 16
    return {'path': info.filename, 'file_size': info.file_size, 'compressed_size': info.compress_size,
            'stored_crc32': f'{info.CRC:08x}', 'compression': info.compress_type,
            'create_system': info.create_system, 'create_version': info.create_version,
            'extract_version': info.extract_version, 'flag_bits': info.flag_bits,
            'external_attr': info.external_attr, 'internal_attr': info.internal_attr,
            'unix_mode_raw': format(raw_mode, '06o'),
            'unix_file_type_bits': format(stat.S_IFMT(raw_mode), '06o'),
            'unix_permission_bits': format(stat.S_IMODE(raw_mode), '04o'),
            'zip_datetime_no_timezone': list(info.date_time), 'header_offset': info.header_offset,
            'extra_base64': base64.b64encode(info.extra).decode(),
            'comment_base64': base64.b64encode(info.comment).decode(),
            'directory_entry': info.is_dir()}


def preflight(zf, strict_original=False):
    infos = zf.infolist()
    assert len({info.filename for info in infos}) == len(infos), 'duplicate ZIP member name'
    paths, files = set(), set()
    for info in infos:
        assert not info.flag_bits & 1, 'encrypted evidence member'
        name, parts = safe_name(info.filename, info.is_dir())
        assert name not in paths, 'file/directory member collision'
        paths.add(name)
        raw_mode = info.external_attr >> 16
        kind = stat.S_IFMT(raw_mode)
        assert kind in (0, stat.S_IFREG, stat.S_IFDIR), ('special or symlink ZIP member', info.filename, raw_mode)
        if info.is_dir():
            assert kind in (0, stat.S_IFDIR) and info.file_size == 0
        else:
            assert kind in (0, stat.S_IFREG)
            files.add(name)
            if strict_original:
                assert info.create_system == 3 and kind == stat.S_IFREG
                assert format(raw_mode, '06o') in NATIVE_MODES
    for name in paths:
        parts = name.split('/')
        assert not any('/'.join(parts[:i]) in files for i in range(1, len(parts))), name
    return infos


def open_new_file(directory_fd, parts):
    current = os.dup(directory_fd)
    try:
        for component in parts[:-1]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=current)
            except FileExistsError:
                pass
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current); current = next_fd
        return os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=current)
    finally:
        os.close(current)


def read_stream(stream, size, destination=None):
    sha = hashlib.sha256()
    git = hashlib.sha1(b'blob ' + str(size).encode() + b'\0')
    crc, total = 0, 0
    while chunk := stream.read(CHUNK):
        total += len(chunk)
        assert total <= size, 'member exceeded its recorded size'
        sha.update(chunk); git.update(chunk); crc = zlib.crc32(chunk, crc)
        if destination is not None:
            destination.write(chunk)
    assert total == size, 'member shorter than its recorded size'
    return {'bytes': total, 'sha256': sha.hexdigest(), 'git_blob': git.hexdigest(),
            'actual_crc32': f'{crc & 0xffffffff:08x}'}


def audit_nested(stream, container, records, depth=0):
    assert depth < 16, 'unexpected archive nesting depth'
    with zipfile.ZipFile(stream) as zf:
        infos = preflight(zf)
        nested = {'container': container, 'depth': depth, 'members': [],
                  'archive_comment_base64': base64.b64encode(zf.comment).decode(),
                  'restoration': 'read-only nested integrity audit; original complete nested ZIP is retained in restored outer member'}
        for index, info in enumerate(infos):
            row = dict(member_metadata(info), index=index)
            if not info.is_dir():
                with zf.open(info, 'r') as source:
                    row.update(read_stream(source, info.file_size))
                assert row['stored_crc32'] == row['actual_crc32']
                if info.filename.lower().endswith('.zip'):
                    with zf.open(info, 'r') as child:
                        audit_nested(child, container + '!/' + info.filename, records, depth + 1)
            nested['members'].append(row)
        nested['member_count'] = len(infos)
        nested['file_count'] = sum(not info.is_dir() for info in infos)
        nested['uncompressed_bytes'] = sum(info.file_size for info in infos)
        records.append(nested)


def main():
    assert not OUTPUT.exists(), 'exclusive recovery directory is required'
    assert not (ROOT / 'RESTORATION-RESULT.json').exists()
    result = {'schema': 'hia.r7-r4.original-evidence-restoration.v1', 'status': 'RUNNING',
              'started_at_utc': now(), 'product_execution': False, 'product_tests_executed': 0,
              'product_refs_changed': False, 'input_directory': str(ORIGINAL),
              'output_directory': str(OUTPUT), 'archives': [], 'failures': []}
    manifest = {'schema': 'hia.r7-r4.complete-original-zip-member-manifest.v1',
                'archives': [], 'nested_archives': [],
                'directory_permissions': {
                    'original_outer_zip_directory_entries': 0,
                    'original_directory_modes': 'NOT_RECORDED_BY_ORIGINAL_ZIPS',
                    'local_creation_policy': '0700; this is recovery policy, not an assertion about original directories',
                    'zip_file_modes': 'actual Unix regular-file modes restored only after byte/CRC/hash verification',
                },
                'timestamp_policy': 'ZIP DOS date_time is recorded without inventing timezone or original filesystem precision. Local extracted mtimes are not claimed to reproduce original mtimes.'}
    input_names = ['DOWNLOAD.json', *EXPECTED, *LOGS]
    before = {}
    try:
        downloads_raw = (ORIGINAL / 'DOWNLOAD.json').read_bytes()
        downloads = {row['name']: row for row in json.loads(downloads_raw)}
        assert set(downloads) == set(EXPECTED)
        for name in input_names:
            before[name] = file_identity(ORIGINAL / name)
        for name, (size, digest, count, expanded) in EXPECTED.items():
            assert downloads[name]['status'] == 'DOWNLOADED_EXACT'
            assert downloads[name]['bytes'] == size and downloads[name]['sha'] == digest
            assert before[name]['bytes'] == size and before[name]['sha256'] == digest
            with zipfile.ZipFile(ORIGINAL / name) as zf:
                infos = preflight(zf, strict_original=True)
                assert len(infos) == count and sum(info.file_size for info in infos) == expanded
                assert not any(info.is_dir() for info in infos)
                if name == 'native.zip':
                    assert dict(Counter(format(info.external_attr >> 16, '06o') for info in infos)) == NATIVE_MODES
        for name, (size, oid) in LOGS.items():
            assert before[name]['bytes'] == size and before[name]['git_blob'] == oid
        put('INPUTS.json', {'download_record': downloads, 'actual_input_identities': before,
                           'all_root_download_size_sha_pins_matched': True,
                           'all_three_archives_preflighted_before_first_extraction': True,
                           'expected_native_mode_counts': NATIVE_MODES})
        OUTPUT.mkdir(mode=0o700)
        for name, (_, _, count, expanded) in EXPECTED.items():
            destination = OUTPUT / name.removesuffix('.zip')
            destination.mkdir(mode=0o700)
            root_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            archive_row = {'name': name, 'artifact_id': downloads[name]['id'],
                           'outer_identity': before[name], 'members': [],
                           'restored_relative_directory': destination.relative_to(ROOT).as_posix()}
            try:
                with zipfile.ZipFile(ORIGINAL / name) as zf:
                    infos = preflight(zf, strict_original=True)
                    archive_row['archive_comment_base64'] = base64.b64encode(zf.comment).decode()
                    for index, info in enumerate(infos):
                        relative, parts = safe_name(info.filename)
                        fd = open_new_file(root_fd, parts)
                        with os.fdopen(fd, 'wb') as target, zf.open(info, 'r') as source:
                            observed = read_stream(source, info.file_size, target)
                        row = dict(member_metadata(info), index=index, **observed)
                        assert row['stored_crc32'] == row['actual_crc32']
                        path = destination / relative
                        info_before_mode = path.lstat()
                        assert stat.S_ISREG(info_before_mode.st_mode)
                        os.chmod(path, stat.S_IMODE(info.external_attr >> 16), follow_symlinks=False)
                        readback = file_identity(path)
                        assert readback['bytes'] == row['bytes'] and readback['sha256'] == row['sha256']
                        assert readback['git_blob'] == row['git_blob']
                        assert readback['mode'] == row['unix_permission_bits']
                        row['restored_mode'] = readback['mode']
                        row['complete_restored_file_readback'] = True
                        archive_row['members'].append(row)
                        if relative.lower().endswith('.zip'):
                            with path.open('rb') as nested_stream:
                                audit_nested(nested_stream, name + '!/' + relative, manifest['nested_archives'])
                        if (index + 1) % 1000 == 0:
                            print(json.dumps({'archive': name, 'restored_members': index + 1, 'expected': count}), flush=True)
            finally:
                os.close(root_fd)
            actual_paths = {p.relative_to(destination).as_posix() for p in destination.rglob('*') if p.is_file()}
            assert actual_paths == {row['path'] for row in archive_row['members']}
            assert len(actual_paths) == count and sum(row['bytes'] for row in archive_row['members']) == expanded
            archive_row.update({'member_count': count, 'uncompressed_bytes': expanded,
                                'mode_counts': dict(Counter(row['unix_mode_raw'] for row in archive_row['members'])),
                                'safe_complete_restoration_and_readback': True})
            manifest['archives'].append(archive_row)
            result['archives'].append({key: value for key, value in archive_row.items() if key != 'members'})
            print(json.dumps({'archive': name, 'status': 'RESTORED_AND_FULLY_VERIFIED',
                              'members': count, 'bytes': expanded}), flush=True)
        after = {name: file_identity(ORIGINAL / name) for name in input_names}
        assert after == before, 'an original input changed during readback'
        put('ORIGINALS-AFTER.json', after)
        local_dirs = [{'path': p.relative_to(OUTPUT).as_posix(), 'local_mode': format(stat.S_IMODE(p.stat().st_mode), '04o'),
                       'original_mode': None} for p in sorted(OUTPUT.rglob('*')) if p.is_dir()]
        assert all(row['local_mode'] == '0700' for row in local_dirs)
        manifest['directory_permissions']['local_created_directories'] = local_dirs
        manifest['original_inputs_unchanged'] = True
        manifest['outer_member_count'] = sum(row['member_count'] for row in manifest['archives'])
        manifest['nested_archive_count'] = len(manifest['nested_archives'])
        manifest['nested_member_count'] = sum(row['member_count'] for row in manifest['nested_archives'])
        put('MEMBER-MANIFEST.json', manifest)
        result.update({'status': 'EVIDENCE_INTEGRITY_AND_RESTORATION_PASS',
                       'original_inputs_unchanged': True, 'outer_member_count': manifest['outer_member_count'],
                       'nested_archive_count': manifest['nested_archive_count'],
                       'nested_member_count': manifest['nested_member_count'],
                       'member_manifest': file_identity(ROOT / 'MEMBER-MANIFEST.json'),
                       'qualification_inferred': False})
    except BaseException as error:
        result['status'] = 'FAIL'
        result['failures'].append({'type': type(error).__name__, 'message': str(error),
                                   'traceback': traceback.format_exc()})
        put('PARTIAL-MEMBER-MANIFEST.json', manifest)
    finally:
        result['finished_at_utc'] = now()
        put('RESTORATION-RESULT.json', result)
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['status'] == 'EVIDENCE_INTEGRITY_AND_RESTORATION_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
