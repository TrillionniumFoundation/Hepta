"""Exact official containers -> seekable STORED ranges -> whole original ZIP.

All bytes are read. No whole 656 MB reconstruction file is created. Diagnostics
are original bytes; neither their contents nor any source file is executed.
"""
import base64
import hashlib
import io as stream_io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import zipfile
import zlib
import v92_view_common as c

io, require, CHUNK = c.io, c.require, c.CHUNK
helper = c.module('v92_original_catalog', c.ROOT / 'control/original_receiver.py')
PREFIX = 'hia-core-unpack-evidence/'
TOP_LEVEL = ('hia-core-unpack-callers-admission.json', 'hia-core-unpack-gates.json', 'hia-cold.json')
EXPECTED = ('hia-core-unpack-callers-admission.json',
    PREFIX + 'callers-owner/process-owner.json', PREFIX + 'callers-owner/run-result.json',
    PREFIX + 'callers-owner/stdout.log', PREFIX + 'callers-owner/stderr.log',
    PREFIX + 'callers/integer-report.json', PREFIX + 'callers/numeric/numeric-report.json',
    PREFIX + 'callers/numeric/callers/report.json', PREFIX + 'callers/numeric/callers/progress.jsonl',
    PREFIX + 'callers/numeric/callers/progress.receipt.json',
    PREFIX + 'callers/numeric/callers/core-callers/report.json',
    PREFIX + 'callers/numeric/callers/core-callers/component-fixture/installed-control/report.json')
LIMITS = {'maximum_members': 65536, 'maximum_expanded_bytes': 8 << 30,
          'maximum_selected_files': 1024, 'maximum_selected_file_bytes': 64 << 20,
          'maximum_selected_bytes': 128 << 20, 'maximum_metadata_bytes': 64 << 20,
          'maximum_public_small_bytes': 224 << 20}

def selected(name):
    return name in TOP_LEVEL or (name.startswith(PREFIX) and name.endswith(('.json', '.jsonl', '.log')))

def name_ok(name, directory=False):
    require(type(name) is str and 0 < len(name.encode('utf-8')) <= 4096
            and '\\' not in name and not any(ord(ch) < 32 or ord(ch) == 127 for ch in name),
            'unsafe original member name')
    value = name[:-1] if directory and name.endswith('/') else name
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and all(p not in ('', '.', '..') for p in value.split('/'))
            and str(path) == value, 'noncanonical original member name')
    return name

def read_exact(source, count, deadline):
    io.check_deadline(deadline); require(type(count) is int and 0 <= count <= 4 << 20, 'bounded header read required')
    raw = source.read(count); require(len(raw) == count, 'truncated fixed header')
    return raw

def dense_outer_headers(source, archive, infos, total, deadline):
    """Validate ZIP32 directory, exact end, every local span and descriptor.

    These fourteen-member official containers are each below 320 MiB. Their
    actual producer uses ordinary ZIP32, not a ZIP64 archive end directory.
    ZIP64 local sizes/descriptor are accepted only when exactly represented.
    """
    require(0 < len(infos) < 65535 and total < 1 << 32, 'fixed ordinary container bounds differ')
    tail_size = min(total, 65557); source.seek(total - tail_size)
    tail = read_exact(source, tail_size, deadline)
    at = tail.rfind(b'PK\x05\x06'); require(at >= 0 and at + 22 <= len(tail), 'container end record missing')
    e = struct.unpack('<IHHHHIIH', tail[at:at + 22])
    require(e[1:3] == (0, 0) and e[3] == e[4] == len(infos)
            and at + 22 + e[7] == len(tail) and e[6] == archive.start_dir
            and e[6] + e[5] == total - tail_size + at,
            'container directory count/extent/end differs')
    source.seek(e[6]); central_end = e[6] + e[5]
    for info in infos:
        h = struct.unpack('<IHHHHHHIIIHHHHHII', read_exact(source, 46, deadline))
        require(h[0] == 0x02014b50 and h[13] == 0, 'container central header or disk differs')
        raw_name = read_exact(source, h[10], deadline)
        extra = read_exact(source, h[11], deadline); comment = read_exact(source, h[12], deadline)
        name = raw_name.decode('utf-8' if h[3] & 0x800 else 'cp437')
        require(name == info.filename and h[3] == info.flag_bits and h[4] == info.compress_type
                and h[7:10] == (info.CRC, info.compress_size, info.file_size)
                and h[14] == info.internal_attr and h[15] == info.external_attr
                and h[16] == info.header_offset and extra == info.extra and comment == info.comment,
                'container central entry differs from parsed original')
    require(source.tell() == central_end, 'unaccounted central bytes')
    ordered = sorted(infos, key=lambda x: x.header_offset)
    require(ordered[0].header_offset == 0, 'container prepended bytes refused')
    positions = {}
    for index, info in enumerate(ordered):
        source.seek(info.header_offset)
        h = struct.unpack('<IHHHHHIIIHH', read_exact(source, 30, deadline))
        require(h[0] == 0x04034b50 and h[2] == info.flag_bits and h[3] == info.compress_type
                and not h[2] & ~(0x800 | 8), 'container local flags or method differs')
        raw_name = read_exact(source, h[9], deadline); extra = read_exact(source, h[10], deadline)
        require(raw_name.decode('utf-8' if h[2] & 0x800 else 'cp437') == info.filename,
                'container local name differs')
        data_offset = source.tell(); end = data_offset + info.compress_size
        next_header = ordered[index + 1].header_offset if index + 1 < len(ordered) else archive.start_dir
        require(info.header_offset < data_offset <= end <= next_header, 'overlapping container spans')
        wide = h[7] == 0xffffffff or h[8] == 0xffffffff
        if h[2] & 8:
            source.seek(end); length = next_header - end
            require(length in ((20, 24) if wide else (12, 16)), 'container descriptor length differs')
            descriptor = read_exact(source, length, deadline)
            if length in (16, 24):
                require(descriptor[:4] == b'PK\x07\x08', 'descriptor signature differs')
                descriptor = descriptor[4:]
            values = struct.unpack('<IQQ' if wide else '<III', descriptor)
            require(values == (info.CRC, info.compress_size, info.file_size), 'descriptor CRC or sizes differ')
            require(h[6] in (0, info.CRC) and h[7] in (0, info.compress_size, 0xffffffff)
                    and h[8] in (0, info.file_size, 0xffffffff), 'streamed local values differ')
        else:
            require(not wide and end == next_header and h[6:9] == (info.CRC, info.compress_size, info.file_size),
                    'ordinary local CRC/sizes or dense extent differs')
        positions[info.filename] = data_offset
    return positions

def outer_container(path, part, prior_final_raw, prior_controls, policy, deadline):
    """Complete official size/SHA, every body+CRC, fixed PART/FINAL and range."""
    before = c.seal(path, part['artifact']['bytes'], deadline=deadline)
    require(before['bytes'] == part['artifact']['bytes'] and before['sha256'] == part['artifact']['sha256']
            and before['identity'][3] == os.geteuid() and stat.S_IMODE(before['identity'][2]) == 0o600,
            'official complete container seal differs')
    expected_names = set(prior_controls) | {'PART.json', 'FINAL.json', 'slice.bin'}
    require(len(expected_names) == 14, 'fixed fourteen-file container contract differs')
    bodies, rows, slice_record = {}, [], None
    with c.held_parent(path) as (parent, leaf):
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, 'rb') as source, zipfile.ZipFile(source) as archive:
            require(io.ident(os.fstat(source.fileno())) == before['identity'], 'container reopen identity differs')
            infos = archive.infolist()
            require(len(infos) == 14 and len({x.filename for x in infos}) == 14
                    and {x.filename for x in infos} == expected_names, 'missing/duplicate/unexpected container member')
            positions = dense_outer_headers(source, archive, infos, before['bytes'], deadline)
            for info in infos:
                io.check_deadline(deadline); name_ok(info.filename)
                require(not info.is_dir() and not info.flag_bits & 1
                        and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
                        and info.compress_type in (0, 8), 'non-regular container member refused')
                if info.filename == 'slice.bin':
                    require(info.compress_type == zipfile.ZIP_STORED
                            and info.file_size == info.compress_size == part['bytes'], 'slice is not exact STORED original')
                else:
                    require(info.file_size <= 2 << 20, 'whole container control exceeds fixed cap')
                count, crc, digest, chunks = 0, 0, hashlib.sha256(), []
                with archive.open(info) as member:
                    while True:
                        io.check_deadline(deadline)
                        raw = member.read(min(CHUNK, info.file_size + 1 - count))
                        if not raw: break
                        count += len(raw); require(count <= info.file_size, 'container body grew')
                        crc = zlib.crc32(raw, crc); digest.update(raw)
                        if info.filename != 'slice.bin': chunks.append(raw)
                require(count == info.file_size and crc & 0xffffffff == info.CRC, 'container body CRC/size differs')
                row = {'name': info.filename, 'bytes': count, 'sha256': digest.hexdigest(),
                       'crc32': crc & 0xffffffff, 'compression': info.compress_type,
                       'physical_data_offset': positions[info.filename]}
                rows.append(row)
                if info.filename == 'slice.bin': slice_record = row
                else: bodies[info.filename] = b''.join(chunks)
            require(io.ident(os.fstat(source.fileno())) == before['identity'], 'container changed during read')
    require(bodies['FINAL.json'] == prior_final_raw, 'same actual failed FINAL bytes differ')
    for name, raw in prior_controls.items():
        require(bodies[name] == raw, 'same original recovery control body differs')
    record = io.json_value(bodies['PART.json']); old = io.json_value(prior_final_raw)
    exact_part = {'schema': 'hia.v92-original-zip-part.v1', 'artifact': policy['original_artifact'],
        'expected': {k: part[k] for k in ('ordinal', 'name', 'offset', 'bytes')},
        'observed': old['parts'][part['ordinal']], 'status': 'FULL_ZIP_CUSTODY_HOLD',
        'run_id': policy['receiver']['run_id'], 'run_attempt': 1,
        'workflow_commit': policy['receiver']['workflow_commit'],
        'control_commit': policy['receiver']['control_commit'],
        'policy_sha256': policy['receiver']['policy_sha256'], 'qualification_executed': False,
        'artifact_upload_not_yet_observed': True}
    require(bodies['PART.json'] == io.wire(exact_part), 'exact producer PART original bytes differ')
    require(set(record) == {'schema', 'artifact', 'expected', 'observed', 'status', 'run_id', 'run_attempt',
                           'workflow_commit', 'control_commit', 'policy_sha256', 'qualification_executed',
                           'artifact_upload_not_yet_observed'}, 'PART exact field contract differs')
    require(record['schema'] == 'hia.v92-original-zip-part.v1' and record['artifact'] == policy['original_artifact']
            and record['expected'] == {k: part[k] for k in ('ordinal', 'name', 'offset', 'bytes')}
            and record['observed'] == old['parts'][part['ordinal']]
            and record['status'] == old['status'] == 'FULL_ZIP_CUSTODY_HOLD'
            and record['run_id'] == policy['receiver']['run_id'] and record['run_attempt'] == 1
            and record['workflow_commit'] == policy['receiver']['workflow_commit']
            and record['control_commit'] == policy['receiver']['control_commit']
            and record['policy_sha256'] == policy['receiver']['policy_sha256']
            and record['qualification_executed'] is False and record['artifact_upload_not_yet_observed'] is True,
            'PART current original/custody binding differs')
    require(slice_record['sha256'] == part['sha256'] == old['parts'][part['ordinal']]['retained']['sha256'],
            'actual raw range SHA differs')
    after = c.seal(path, before['bytes'], deadline=deadline)
    require(after == before, 'official container changed after complete read')
    return {'ordinal': part['ordinal'], 'container': after, 'range': slice_record,
            'members': rows, 'PART': {'bytes': len(bodies['PART.json']),
                                     'sha256': hashlib.sha256(bodies['PART.json']).hexdigest()},
            'whole_original_container_read': True}

class StoredView(stream_io.RawIOBase):
    """Only validated dense, contiguous STORED byte spans. No data copy file."""
    def __init__(self, specs, total, deadline):
        super().__init__(); self.specs = specs; self.total = total; self.position = 0
        self.deadline = deadline; self.held = []; self.parents = []
        cursor = 0
        try:
            require(len(specs) == 3, 'exact three range view required')
            for index, spec in enumerate(specs):
                require(spec['ordinal'] == index and type(spec['offset']) is int and spec['offset'] == cursor
                        and type(spec['bytes']) is int and spec['bytes'] > 0, 'view range gap/overlap/order differs')
                cursor += spec['bytes']
                ctx = c.held_parent(spec['path']); parent, name = ctx.__enter__(); self.parents.append(ctx)
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                self.held.append(fd); s = os.fstat(fd)
                require(io.ident(s) == spec['identity'] and stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid()
                        and s.st_nlink == 1 and 0 <= spec['data_offset']
                        and spec['data_offset'] + spec['bytes'] <= s.st_size, 'held STORED span identity or extent differs')
            require(cursor == total, 'view total differs')
        except BaseException:
            self.close(); raise
    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position
    def seek(self, offset, whence=0):
        io.check_deadline(self.deadline)
        require(type(offset) is int and whence in (0, 1, 2), 'integer view seek required')
        value = offset + (0 if whence == 0 else self.position if whence == 1 else self.total)
        require(value >= 0, 'negative view seek refused'); self.position = value; return value
    def read(self, size=-1):
        require(type(size) is int and size >= -1 and not self.closed, 'open bounded view read required')
        size = max(0, self.total - self.position) if size == -1 else min(size, max(0, self.total - self.position))
        # ZipFile directory <=64 MiB; callers never materialize the whole ZIP.
        require(size <= 64 << 20, 'unbounded whole-view allocation refused')
        out = bytearray()
        while size:
            io.check_deadline(self.deadline)
            index = next((i for i, x in enumerate(self.specs)
                          if x['offset'] <= self.position < x['offset'] + x['bytes']), None)
            require(index is not None, 'view offset outside complete partition')
            s = self.specs[index]; relative = self.position - s['offset']
            count = min(size, s['bytes'] - relative, CHUNK)
            raw = os.pread(self.held[index], count, s['data_offset'] + relative)
            require(len(raw) == count, 'truncated held range')
            self.position += count; size -= count; out.extend(raw)
        return bytes(out)
    def stable(self):
        for fd, spec in zip(self.held, self.specs):
            require(io.ident(os.fstat(fd)) == io.ident(Path(spec['path']).lstat()) == spec['identity'],
                    'held official container changed')
    def whole_hash(self):
        self.seek(0); count, digest = 0, hashlib.sha256()
        while count < self.total:
            raw = self.read(min(CHUNK, self.total - count)); require(raw, 'whole view ended early')
            digest.update(raw); count += len(raw)
        self.stable(); return {'bytes': count, 'sha256': digest.hexdigest()}
    def close(self):
        if self.closed: return
        try:
            self.stable()
        finally:
            for fd in reversed(self.held): os.close(fd)
            self.held = []
            for ctx in reversed(self.parents): ctx.__exit__(None, None, None)
            self.parents = []; super().close()

class Journal:
    def __init__(self, path, budget, maximum, deadline, verify):
        self.path, self.budget, self.maximum, self.deadline, self.verify = Path(path), budget, maximum, deadline, verify
        self.count = self.lines = 0; self.ctx = c.held_parent(path); parent, name = self.ctx.__enter__()
        self.before = None
        try:
            flags = os.O_RDONLY if verify else os.O_WRONLY | os.O_CREAT | os.O_EXCL
            fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
            self.stream = os.fdopen(fd, 'rb' if verify else 'wb'); self.before = os.fstat(fd)
        except BaseException:
            self.ctx.__exit__(None, None, None); raise
    def row(self, value):
        io.check_deadline(self.deadline)
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        require(self.count + len(raw) <= self.maximum, 'whole metadata journal exceeds cap')
        if self.verify:
            require(self.stream.readline(len(raw) + 1) == raw, 'independent original journal row differs')
        else:
            self.budget.reserve(len(raw), 'metadata'); self.stream.write(raw); self.budget.wrote(len(raw), 'metadata')
        self.count += len(raw); self.lines += 1
    def close(self, success=False):
        if self.stream.closed: return
        try:
            if self.verify:
                if success: require(self.stream.read(1) == b'', 'extra original journal rows')
                require(io.ident(self.before) == io.ident(os.fstat(self.stream.fileno())), 'journal changed during read')
            else:
                self.stream.flush(); os.fsync(self.stream.fileno())
        finally:
            self.stream.close(); self.ctx.__exit__(None, None, None)

def inspect_original(view, policy, roots, budgets, deadline, *, verify=False):
    """Same selection/caps as frozen remote inspector, complete all bodies."""
    limits = policy['diagnostics']; require(limits == LIMITS, 'unchanged original diagnostic selection bounds differ')
    folder = roots['workspace'] / 'readback'; captured = roots['tmp'] / 'selected'
    summary = {'schema': 'hia.v92-three-part-original-diagnostics.v1', 'status': 'HOLD',
               'original_artifact': policy['original_artifact'], 'members': 0, 'expanded_bytes': 0,
               'selected': [], 'selected_bytes': 0, 'missing_expected': list(EXPECTED), 'errors': [],
               'original_CI_failure_preserved': True, 'original_receiver_HOLD_preserved': True,
               'product_execution': False, 'complete_all_member_bodies': False}
    directory = Journal(folder / 'DIRECTORY.jsonl', budgets['workspace'], 32 << 20, deadline, verify)
    inventory = None; success = False; names = set()
    try:
        inventory = Journal(folder / 'FULL-INVENTORY.jsonl', budgets['workspace'], 28 << 20, deadline, verify)
        with zipfile.ZipFile(view) as archive:
            infos = archive.infolist()
            helper.catalog(archive, policy['original_artifact'], {'zip_entries': limits['maximum_members'],
                'zip_directory_metadata_bytes': limits['maximum_metadata_bytes'],
                'zip_declared_total_uncompressed_bytes': limits['maximum_expanded_bytes']})
            require(0 < len(infos) <= limits['maximum_members'], 'original member bound differs')
            summary['archive_comment_base64'] = base64.b64encode(archive.comment).decode()
            for index, info in enumerate(infos):
                io.check_deadline(deadline); budgets['tmp'].capacity(); budgets['workspace'].capacity()
                name_ok(info.filename, info.is_dir()); require(info.filename not in names, 'duplicate original member')
                names.add(info.filename)
                require(not info.flag_bits & 1 and info.compress_type in (0, 8)
                        and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG, stat.S_IFDIR)
                        and (not info.is_dir() or info.file_size == 0), 'unsupported original member type')
                directory.row({'index': index, 'name': info.filename, 'bytes': info.file_size,
                    'compressed_bytes': info.compress_size, 'crc32': info.CRC, 'compression': info.compress_type,
                    'flags': info.flag_bits, 'header_offset': info.header_offset, 'external_attr': info.external_attr,
                    'internal_attr': info.internal_attr, 'create_system': info.create_system,
                    'create_version': info.create_version, 'extract_version': info.extract_version,
                    'date_time': list(info.date_time), 'extra_base64': base64.b64encode(info.extra).decode(),
                    'comment_base64': base64.b64encode(info.comment).decode()})
                chosen = not info.is_dir() and selected(info.filename)
                output, context, target = None, None, None
                if chosen:
                    require(len(summary['selected']) < limits['maximum_selected_files']
                            and info.file_size <= limits['maximum_selected_file_bytes']
                            and summary['selected_bytes'] + info.file_size <= limits['maximum_selected_bytes'],
                            'complete selected original exceeds cap; never truncate')
                    target = captured / ('member-%05d.bin' % index); summary['selected_bytes'] += info.file_size
                    if not verify:
                        budgets['tmp'].reserve(info.file_size, 'selected')
                        context = c.held_parent(target); parent, leaf = context.__enter__()
                        try: output = os.fdopen(os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent), 'wb')
                        except BaseException: context.__exit__(None, None, None); raise
                count, crc, digest = 0, 0, hashlib.sha256()
                try:
                    with archive.open(info) as source:
                        while True:
                            io.check_deadline(deadline)
                            raw = source.read(min(CHUNK, info.file_size + 1 - count))
                            if not raw: break
                            count += len(raw); require(count <= info.file_size, 'original body exceeds declared size')
                            digest.update(raw); crc = zlib.crc32(raw, crc)
                            if output is not None:
                                output.write(raw); budgets['tmp'].wrote(len(raw), 'selected')
                    require(count == info.file_size and crc & 0xffffffff == info.CRC, 'original body CRC/size differs')
                finally:
                    if output is not None:
                        try: output.flush(); os.fsync(output.fileno())
                        finally: output.close(); context.__exit__(None, None, None)
                row = {'index': index, 'name': info.filename, 'bytes': count, 'sha256': digest.hexdigest(),
                       'crc32': crc & 0xffffffff, 'directory': info.is_dir(), 'body_fully_read': True}
                if chosen:
                    actual = c.seal(target, limits['maximum_selected_file_bytes'], deadline=deadline)
                    require(actual['bytes'] == count and actual['sha256'] == digest.hexdigest()
                            and actual['identity'][3] == os.geteuid(), 'whole selected original copy differs')
                    summary['selected'].append({**row, 'copy': actual, 'truncated': False})
                inventory.row(row); summary['members'] += 1; summary['expanded_bytes'] += count
                require(summary['expanded_bytes'] <= limits['maximum_expanded_bytes'], 'complete expansion cap exceeded')
        require(summary['members'] == len(infos), 'not every original member read')
        view.stable(); summary['missing_expected'] = [name for name in EXPECTED if name not in names]
        summary.update(status='ALL_AVAILABLE_STEP42_ORIGINALS_READ_NOT_QUALIFICATION', complete_all_member_bodies=True)
        success = True
    except BaseException as error:
        summary['status'] = 'HOLD'; summary['errors'].append(io.safe_error(error)); raise
    finally:
        directory.close(success)
        if inventory is not None: inventory.close(success)
        raw = io.wire(summary)
        if verify:
            if success:
                pin, actual = c.seal(folder / 'INDEX.json', 4 << 20, body=True, deadline=deadline)
                require(actual == raw, 'complete independent original INDEX differs')
        else:
            c.create(folder / 'INDEX.json', raw, raw=True, budget=budgets['workspace'],
                     deadline=deadline if success else None)
    return summary
