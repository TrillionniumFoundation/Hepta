"""Read every original ZIP body and retain 24 exact Core lowering diagnostics.

This control never imports project code, executes an original, or interprets
an original failure as a qualification success. Missing reports are explicit.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import stat
import time
import zipfile
import zlib

CHUNK = 1 << 20
EXPECTED = (
    'hia-core-lowering-owner/process-owner.json',
    'hia-core-lowering-owner/process-owner.json.request.json',
    'hia-core-lowering-owner/run-result.json',
    'hia-core-lowering-gate.json',
    'hia-core-lowering-owner/stdout.log',
    'hia-core-lowering-owner/stderr.log',
    'hia-core-lowering-owner/process-owner.json.stdout.log',
    'hia-core-lowering-owner/process-owner.json.stderr.log',
    'hia-core-lowering-callers-evidence/report.json',
    'hia-core-lowering-callers-evidence/component.unittest.log',
    'hia-core-lowering-callers-evidence/original-machine.unittest.log',
    'hia-core-lowering-callers-evidence/original-core.unittest.log',
    'hia-core-lowering-callers-evidence/build/build.json',
    'hia-core-lowering-callers-evidence/build/manifest.json',
    'hia-core-lowering-callers-evidence/component-fixture/qualified/build.json',
    'hia-core-lowering-callers-evidence/component-fixture/qualified/manifest.json',
    'hia-core-lowering-callers-evidence/component-fixture/installed-control/processes.json',
    'hia-core-lowering-callers-evidence/component-fixture/installed-control/wheel-build.stdout',
    'hia-core-lowering-callers-evidence/component-fixture/installed-control/wheel-build.stderr',
    'hia-core-lowering-callers-evidence/component-fixture/installed-control/wheel-install.stdout',
    'hia-core-lowering-callers-evidence/component-fixture/installed-control/installed-execution.stdout',
    'hia-core-lowering-callers-evidence/component-fixture/installed-control/installed-execution.stderr',
    'hia-core-lowering-callers-evidence/component-fixture/installed-control/report.json',
    'hia-cold.json',
)

LIMITS = {'maximum_members': 65536, 'maximum_expanded_bytes': 8 << 30,
          'maximum_selected_files': 1024, 'maximum_selected_file_bytes': 64 << 20,
          'maximum_selected_bytes': 128 << 20, 'maximum_metadata_bytes': 64 << 20,
          'maximum_public_small_bytes': 224 << 20}


class Refusal(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def clock(deadline):
    require(time.monotonic_ns() < deadline, 'fixed original transfer deadline exceeded')


def safe_name(name, directory=False):
    require(type(name) is str and 0 < len(name.encode('utf-8')) <= 4096
            and '\\' not in name and '\x00' not in name
            and not any(ord(c) < 32 or ord(c) == 127 for c in name),
            'unsafe original ZIP member name')
    normalized = name[:-1] if directory and name.endswith('/') else name
    path = PurePosixPath(normalized)
    require(normalized and not path.is_absolute()
            and all(part not in ('', '.', '..') for part in normalized.split('/'))
            and str(path) == normalized, 'noncanonical original ZIP member name')
    return name


def selected_name(name):
    return name in EXPECTED


def inspect_zip(path, pin, root, deadline, helper, limits):
    require(limits == LIMITS, 'fixed diagnostics scope or bounds differ')
    folder = root / 'diagnostics'
    folder.mkdir(mode=0o700, exist_ok=False)
    summary = {'schema': 'hia.core-lowering-owner-diagnostics.v1', 'status': 'HOLD',
        'artifact': pin, 'original_workflow_status': 'failure',
        'qualification_executed': False, 'product_code_imported': False,
        'original_failure_reclassified': False, 'all_members_fully_read': False,
        'complete_selection_of_available_originals': False,
        'selection': {'match': 'EXACT_CANONICAL_MEMBER_NAMES',
                      'expected_names': list(EXPECTED)},
        'limits': limits, 'members': 0, 'expanded_bytes': 0,
        'selected': [], 'selected_bytes': 0, 'missing_expected': list(EXPECTED),
        'errors': []}
    metadata_reserved = 0
    names = set()
    journals = []
    directory_path = folder / 'DIRECTORY.jsonl'
    inventory_path = folder / 'FULL-INVENTORY.jsonl'
    def create_stream(target):
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
        os.fchmod(descriptor, 0o400)
        return os.fdopen(descriptor, 'wb')
    def row(stream, value):
        nonlocal metadata_reserved
        raw = wire(value)
        require(metadata_reserved + len(raw) <= limits['maximum_metadata_bytes'] - (4 << 20),
                'complete original metadata exceeds reserved bound')
        metadata_reserved += len(raw)
        stream.write(raw)
    archive_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(archive_fd, 'rb') as archive_source:
        initial = os.fstat(archive_source.fileno())
        require(stat.S_ISREG(initial.st_mode) and initial.st_uid == os.geteuid()
                and initial.st_nlink == 1 and initial.st_size == pin['bytes']
                and stat.S_IMODE(initial.st_mode) == 0o400, 'sealed original ZIP differs')
        try:
            with create_stream(directory_path) as directory, create_stream(inventory_path) as inventory:
                journals = [directory, inventory]
                with zipfile.ZipFile(archive_source, 'r') as archive:
                    infos = archive.infolist()
                    # Preserve the reviewed helper's complete directory rules:
                    # canonical names, no file ancestors, encryption, special
                    # leaves, privileged modes and declared ZIP expansion.
                    helper.catalog(archive, pin, {
                        'zip_entries': limits['maximum_members'],
                        'zip_directory_metadata_bytes': limits['maximum_metadata_bytes'],
                        'zip_declared_total_uncompressed_bytes': limits['maximum_expanded_bytes']})
                    clock(deadline)
                    require(0 < len(infos) <= limits['maximum_members'],
                            'complete original member count exceeds bound')
                    require(sum(info.file_size for info in infos) <= limits['maximum_expanded_bytes'],
                            'complete expanded original body count exceeds bound')
                    summary['archive_comment_base64'] = base64.b64encode(archive.comment).decode()
                    for index, info in enumerate(infos):
                        clock(deadline)
                        name = safe_name(info.filename, info.is_dir())
                        require(name not in names, 'duplicate original ZIP member')
                        names.add(name)
                        mode = (info.external_attr >> 16) & 0xffff
                        kind = stat.S_IFMT(mode)
                        require(not info.flag_bits & 1 and kind in (0, stat.S_IFREG, stat.S_IFDIR)
                                and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                                and (not info.is_dir() or info.file_size == 0),
                                'encrypted, special or unsupported original member')
                        row(directory, {'index': index, 'name': name, 'bytes': info.file_size,
                            'compressed_bytes': info.compress_size, 'crc32': info.CRC,
                            'compression': info.compress_type, 'flags': info.flag_bits,
                            'header_offset': info.header_offset, 'external_attr': info.external_attr,
                            'internal_attr': info.internal_attr, 'create_system': info.create_system,
                            'create_version': info.create_version, 'extract_version': info.extract_version,
                            'date_time': list(info.date_time),
                            'extra_base64': base64.b64encode(info.extra).decode(),
                            'comment_base64': base64.b64encode(info.comment).decode()})
                        selected = not info.is_dir() and selected_name(name)
                        target = None
                        output = None
                        if selected:
                            require(len(summary['selected']) < limits['maximum_selected_files']
                                    and info.file_size <= limits['maximum_selected_file_bytes']
                                    and summary['selected_bytes'] + info.file_size <= limits['maximum_selected_bytes'],
                                    'whole fixed diagnostic original exceeds bound; never truncate')
                            target = folder / ('member-%05d.bin' % index)
                            output = create_stream(target)
                            # Reserve the entire declared original before creating another one.
                            summary['selected_bytes'] += info.file_size
                        count, digest, crc = 0, sha256(), 0
                        try:
                            with archive.open(info, 'r') as original:
                                while True:
                                    clock(deadline)
                                    block = original.read(min(CHUNK, info.file_size + 1 - count))
                                    clock(deadline)
                                    if not block:
                                        break
                                    count += len(block)
                                    require(count <= info.file_size, 'original expanded body grew')
                                    digest.update(block)
                                    crc = zlib.crc32(block, crc)
                                    if output is not None:
                                        output.write(block)
                            require(count == info.file_size and crc & 0xffffffff == info.CRC,
                                    'original body length or CRC differs')
                        finally:
                            if output is not None:
                                output.flush()
                                os.fsync(output.fileno())
                                output.close()
                        observed = {'index': index, 'name': name, 'bytes': count,
                                    'sha256': digest.hexdigest(), 'crc32': crc & 0xffffffff,
                                    'directory': info.is_dir(), 'body_fully_read': True}
                        if target is not None:
                            actual = helper.read_file_hash(target, count, digest.hexdigest())
                            summary['selected'].append({**observed, 'retained_name': target.name,
                                                        'actual': actual, 'truncated': False})
                        row(inventory, observed)
                        summary['members'] += 1
                        summary['expanded_bytes'] += count
                    require(summary['members'] == len(infos), 'full original member read incomplete')
                for stream in journals:
                    stream.flush()
                    os.fsync(stream.fileno())
            require(helper.identity(initial) == helper.identity(os.fstat(archive_source.fileno()))
                    and helper.identity(initial) == helper.identity(path.lstat()),
                    'sealed original identity changed during full ZIP inspection')
            summary['directory'] = helper.read_file_hash(directory_path)
            summary['inventory'] = helper.read_file_hash(inventory_path)
            summary['missing_expected'] = [name for name in EXPECTED if name not in names]
            summary['expected_originals_all_present'] = not summary['missing_expected']
            summary.update(status='AVAILABLE_CORE_LOWERING_ORIGINALS_PRESERVED_NOT_QUALIFICATION',
                           all_members_fully_read=True,
                           complete_selection_of_available_originals=True)
            clock(deadline)
        except BaseException as error:
            summary['status'] = 'HOLD'
            summary['errors'].append({'type': type(error).__name__,
                'refusal': str(error) if type(error) in (Refusal, helper.Refusal) else None})
            raise
        finally:
            raw = wire(summary)
            require(metadata_reserved + len(raw) <= limits['maximum_metadata_bytes'],
                    'complete diagnostic index exceeds reserved bound')
            helper.create(folder / 'INDEX.json', raw)
            require(helper.read_small(folder / 'INDEX.json', maximum=4 << 20) == raw,
                    'diagnostic INDEX full original readback differs')
            helper.sync_dir(folder)
    clock(deadline)
    return helper.read_file_hash(folder / 'INDEX.json')
