"""Bounded, evidence-only gzip ranges and typed-original inspection.

No network, subprocess, project import, archive extraction, permissions repair,
or product execution. Compressed ranges reproduce exact original ZIP bytes.
The small channel contains complete originals plus explicitly derived indexes.
"""
from __future__ import annotations

from hashlib import sha256
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time
import zipfile
import zlib

CHUNK = 1 << 20
GZIP_LIMIT = 313 << 20
SMALL_ORIGINAL_LIMIT = 160 << 20
SMALL_DERIVED_LIMIT = 32 << 20
SMALL_PUBLIC_LIMIT = 224 << 20
MAX_CAPTURE_FILES = 4096
MAX_CATALOG = 64 << 20
MAX_INNER_BYTES = 16 << 30
MAX_OUTER_BYTES = 4 << 30
TAR_NAME = 'hia-v87-full-public/full-retained-originals.tar.gz'
CAT_NAME = 'hia-v87-full-public/ORIGINAL-CATALOG.json'
CUSTODY_NAME = 'hia-v87-full-public/CUSTODY.json'
FINAL_NAME = 'hia-v87-full-public/FINAL.json'
MANIFEST = '.FULL-RETAINED-TYPED-MANIFEST.json'
SMALL_DOCUMENTS = {'DIRECTORY.json', 'OUTER-INVENTORY.json', 'INNER-INVENTORY.json',
                   'PHYSICAL-READBACK.json', 'INDEX.json', 'INSPECTION-ERROR.json'}
APT_NAMES = ('config.json', 'root-process.json', 'environment.json', 'guardian.json',
             'child.stdout.log', 'child.stderr.log')
CRITICAL_INNER = ('RUN-INTENT.json', 'supply/SUPPLY.json',
    'guard/request.json', 'guard/guardian.json', 'guard/child.stdout.log', 'guard/child.stderr.log') + tuple(
    'supply/evidence/apt-owned-' + phase + '/' + name
    for phase in ('update', 'install') for name in APT_NAMES) + tuple(
    'supply/' + directory + '/apt-' + phase + suffix
    for phase in ('update', 'install')
    for directory, suffix in (('requests', '.worker.json'), ('reports', '.result.json')))


class Refusal(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Refusal(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def check_deadline(deadline):
    require(deadline is None or time.monotonic_ns() < deadline, 'original custody deadline exceeded')


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON member')
        result[key] = value
    return result


def json_value(raw):
    def bad_constant(_):
        raise Refusal('nonfinite JSON constant')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)


def safe_path(name, root_allowed=False):
    require(type(name) is str and 0 < len(name) <= 4096 and '\\' not in name
            and not any(ord(ch) < 32 or ord(ch) == 127 for ch in name), 'unsafe original member name')
    if root_allowed and name == '.':
        return name
    require(not name.startswith('/') and not name.endswith('/')
            and all(part not in ('', '.', '..') and ':' not in part for part in name.split('/')),
            'noncanonical original member name')
    require(PurePosixPath(name).as_posix() == name, 'normalized original name differs')
    return name


def record(path, maximum, deadline=None):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
                'bounded owned single-link original required')
        digest, count = sha256(), 0
        while True:
            check_deadline(deadline)
            block = stream.read(CHUNK)
            if not block:
                break
            count += len(block)
            require(count <= before.st_size, 'original grew')
            digest.update(block)
        require(count == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
                and identity(before) == identity(path.lstat()), 'original changed during full read')
    return {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
            'identity': list(identity(before)), 'actual_bytes_independently_read': count}


def raw_read(path, maximum):
    pin = record(path, maximum)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        require(list(identity(os.fstat(stream.fileno()))) == pin['identity'], 'read identity differs')
        raw = stream.read(maximum + 1)
        require(len(raw) == pin['bytes'] and sha256(raw).hexdigest() == pin['sha256']
                and list(identity(os.fstat(stream.fileno()))) == pin['identity']
                and list(identity(Path(path).lstat())) == pin['identity'], 'read original differs')
    return raw, pin


def save(path, raw):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o400)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    actual = record(path, len(raw))
    require(actual['bytes'] == len(raw) and actual['sha256'] == sha256(raw).hexdigest(),
            'complete saved bytes readback differs')
    return actual


class BoundedWriter:
    def __init__(self, stream, maximum, deadline):
        self.stream, self.maximum, self.deadline = stream, maximum, deadline
        self.count, self.digest = 0, sha256()

    def write(self, raw):
        check_deadline(self.deadline)
        require(self.count + len(raw) <= self.maximum, 'compressed range exceeds fixed bound')
        written = self.stream.write(raw)
        require(written == len(raw), 'short compressed write')
        self.count += written
        self.digest.update(raw)
        return written

    def flush(self):
        return self.stream.flush()


def encode_range(incoming, target, count, deadline=None):
    """Encode exactly count bytes; the input cursor is already at the fixed offset."""
    require(type(count) is int and 0 <= count <= 312 << 20, 'fixed raw range bound differs')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    raw_count, digest = 0, sha256()
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), 0o400)
        counted = BoundedWriter(output, GZIP_LIMIT, deadline)
        with gzip.GzipFile(fileobj=counted, mode='wb', filename='', mtime=0, compresslevel=1) as compressed:
            while raw_count < count:
                check_deadline(deadline)
                block = incoming.read(min(CHUNK, count - raw_count))
                require(block, 'raw range ended early')
                compressed.write(block)
                digest.update(block)
                raw_count += len(block)
        output.flush()
        os.fsync(output.fileno())
    actual = record(target, GZIP_LIMIT, deadline)
    require(actual['bytes'] == counted.count and actual['sha256'] == counted.digest.hexdigest(),
            'compressed range independent full read differs')
    return {'original': actual, 'raw_bytes': raw_count, 'raw_sha256': digest.hexdigest(),
            'compression': 'gzip', 'compresslevel': 1, 'mtime': 0,
            'original_bytes_rewritten': False}


def decode_range(path, expected, original, consume=None, deadline=None):
    """Verify one single gzip stream and emit bounded raw blocks to a hash consumer."""
    require(type(expected['bytes']) is int and 0 <= expected['bytes'] <= 312 << 20,
            'raw range size differs')
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        require(list(identity(before)) == original['identity'] and stat.S_ISREG(before.st_mode)
                and before.st_uid == os.geteuid() and before.st_nlink == 1
                and before.st_size == original['bytes'] <= GZIP_LIMIT,
                'compressed range identity differs')
        unpack = zlib.decompressobj(31)
        compressed_digest, raw_digest = sha256(), sha256()
        compressed_count = raw_count = 0
        while True:
            check_deadline(deadline)
            block = source.read(CHUNK)
            if not block:
                break
            require(not unpack.eof, 'bytes follow the one gzip stream')
            compressed_count += len(block)
            compressed_digest.update(block)
            remaining = block
            while remaining:
                check_deadline(deadline)
                out = unpack.decompress(remaining, min(CHUNK, expected['bytes'] + 1 - raw_count))
                remaining = unpack.unconsumed_tail
                raw_count += len(out)
                require(raw_count <= expected['bytes'], 'gzip raw range exceeds exact bound')
                raw_digest.update(out)
                if consume is not None:
                    consume(out)
                require(not unpack.unused_data, 'extra gzip member or trailing bytes refused')
                if unpack.eof:
                    require(not remaining, 'compressed data after end')
        require(unpack.eof and not unpack.unconsumed_tail and not unpack.unused_data
                and raw_count == expected['bytes'] and compressed_count == original['bytes']
                and compressed_digest.hexdigest() == original['sha256']
                and identity(before) == identity(os.fstat(source.fileno()))
                and identity(before) == identity(path.lstat()), 'complete gzip range readback differs')
    return {'bytes': raw_count, 'sha256': raw_digest.hexdigest(),
            'compressed_bytes': compressed_count, 'compressed_sha256': compressed_digest.hexdigest(),
            'gzip_streams': 1, 'trailing_bytes': 0}


def split_original(path, pin, parts, root, deadline):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    produced, total = [], 0
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o400
                and before.st_size == pin['bytes'], 'sealed original differs')
        for item in parts:
            require(source.tell() == total == item['offset'], 'original range order differs')
            value = encode_range(source, root / 'parts' / item['name'], item['bytes'], deadline)
            produced.append({**item, **value})
            total += value['raw_bytes']
        require(source.read(1) == b'' and total == pin['bytes']
                and identity(before) == identity(os.fstat(source.fileno()))
                and identity(before) == identity(Path(path).lstat()), 'original changed during compression')
    combined = sha256()
    for item in produced:
        decoded = decode_range(item['original']['path'], item, item['original'], combined.update, deadline)
        require(decoded['bytes'] == item['raw_bytes'] and decoded['sha256'] == item['raw_sha256'],
                'complete raw range differs after gzip restoration')
        item['restoration'] = decoded
    require(combined.hexdigest() == pin['sha256'], 'all gzip ranges do not restore exact original ZIP')
    return {'parts': produced, 'total_bytes': total, 'concatenated_sha256': combined.hexdigest(),
            'exact_contiguous_partition': True, 'original_identity': list(identity(before)),
            'encoding': 'INDEPENDENT_SINGLE_GZIP_STREAM_PER_FIXED_RAW_RANGE',
            'no_second_complete_raw_copy_created': True}


def concat_parts(records, pin, parts, deadline=None):
    require(len(records) == len(parts), 'complete gzip range population required')
    combined, total, observations = sha256(), 0, []
    for item, actual in zip(parts, records):
        require(item['offset'] == total, 'gzip raw ranges are not contiguous')
        value = decode_range(actual['path'], item, actual, combined.update, deadline)
        total += value['bytes']
        observations.append({**item, **value})
    require(total == pin['bytes'] and combined.hexdigest() == pin['sha256'],
            'restored complete original ZIP seal differs')
    return {'bytes': total, 'sha256': combined.hexdigest(), 'ranges': observations,
            'exact_contiguous_partition': True, 'raw_output_files_created': False}


class DigestReader:
    def __init__(self, source, maximum, deadline):
        self.source, self.maximum, self.deadline = source, maximum, deadline
        self.count, self.digest = 0, sha256()

    def read(self, size=-1):
        check_deadline(self.deadline)
        require(type(size) is int and size >= 0, 'unbounded streaming read refused')
        raw = self.source.read(min(size, CHUNK, self.maximum + 1 - self.count))
        self.count += len(raw)
        require(self.count <= self.maximum, 'expanded original stream exceeds frozen bound')
        self.digest.update(raw)
        return raw


def inner_wanted(name):
    return name in CRITICAL_INNER or name == 'supply/reports/apt-supply.json' or name.startswith((
        'control/', 'checkpoints/', 'preparation-logs/', 'guard/',
        'supply/logs/', 'supply/requests/', 'supply/reports/'))


def inspect_original(path, pin, root, deadline, cataloguer):
    """Read the authenticated ZIP and typed TAR; save only bounded whole originals."""
    directory = root / 'small'
    directory.mkdir(mode=0o700, exist_ok=False)
    captures, omitted, outer, inner, critical = [], [], [], [], []
    original_bytes = derived_bytes = 0
    counters = {'outer_sequence': 0, 'inner_sequence': 0}
    result = {'schema': 'hia.failed-full32.physical-original-inspection.v1', 'status': 'HOLD',
              'artifact': pin, 'qualification_executed': False, 'project_code_executed': False,
              'original_results_reclassified': False, 'special_members_opened_or_extracted': False,
              'complete_original_ZIP_preserved_separately': True}

    def doc(name, value):
        nonlocal derived_bytes
        require(name in SMALL_DOCUMENTS, 'fixed derived document required')
        raw = wire(value)
        require(derived_bytes + len(raw) <= SMALL_DERIVED_LIMIT, 'derived small inventory budget exceeded')
        derived_bytes += len(raw)
        return save(directory / name, raw)

    def body(stream, size, scope, original_path, keep, maximum=16 << 20):
        nonlocal original_bytes
        require(type(size) is int and 0 <= size <= MAX_INNER_BYTES, 'original body bound differs')
        target, fd, output, count, digest = None, None, None, 0, sha256()
        sequence = scope.lower() + '_sequence'
        if keep:
            reason = ('FILE_BOUND' if size > maximum else 'TOTAL_BOUND' if original_bytes + size > SMALL_ORIGINAL_LIMIT
                      else 'FILE_COUNT' if len(captures) >= MAX_CAPTURE_FILES else None)
            if reason is not None:
                omitted.append({'scope': scope, 'path': original_path, 'bytes': size,
                                'status': 'OMITTED_WHOLE_ORIGINAL', 'reason': reason})
                keep = False
            else:
                original_bytes += size  # Reserve before opening; failure cannot donate occupied bytes.
                counters[sequence] += 1
                target = directory / ('%s%06d.original' % (scope[0], counters[sequence]))
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
                output = os.fdopen(fd, 'wb')
                os.fchmod(output.fileno(), 0o400)
        try:
            while True:
                check_deadline(deadline)
                block = stream.read(min(CHUNK, size + 1 - count))
                if not block:
                    break
                count += len(block)
                require(count <= size, 'original body grew beyond declared size')
                digest.update(block)
                if output is not None:
                    output.write(block)
            require(count == size, 'original body truncated')
            if output is not None:
                output.flush()
                os.fsync(output.fileno())
        finally:
            if output is not None:
                output.close()
        item = {'path': original_path, 'bytes': count, 'sha256': digest.hexdigest()}
        if target is not None:
            actual = record(target, maximum, deadline)
            require(actual['bytes'] == count and actual['sha256'] == item['sha256'], 'small original copy differs')
            captures.append({'scope': scope, **item, 'saved': target.name, 'actual': actual,
                             'derived': False, 'whole_original': True})
        return item

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as original:
            before = os.fstat(original.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
                    and before.st_size == pin['bytes'], 'sealed inspection input differs')
            with zipfile.ZipFile(original) as archive:
                # The unchanged reviewed catalogue validates ZIP names, flags, extents and types.
                catalog, _, declared_bytes = cataloguer(archive, pin, {
                    'zip_entries': 256, 'zip_declared_total_uncompressed_bytes': MAX_OUTER_BYTES,
                    'zip_directory_metadata_bytes': 4 << 20})
                directory_pin = doc('DIRECTORY.json', {'schema': 'hia.complete-original-zip-directory.v1',
                    'declared_total_bytes': declared_bytes, 'members': catalog,
                    'body_hashes_are_in_separate_full_read_inventory': True})
                infos = archive.infolist()
                require(4 <= len(infos) <= 256, 'bounded observed outer population differs')
                require(sum(x.file_size for x in infos) <= MAX_OUTER_BYTES, 'outer expanded bytes exceed bound')
                names = {x.filename: x for x in infos}
                require(all(name in names and not names[name].is_dir()
                            for name in (TAR_NAME, CAT_NAME, CUSTODY_NAME, FINAL_NAME)),
                        'four fixed original custody members missing')
                # Read identity-defining originals first; preserve them even if later payload inspection fails.
                ordered = [names[n] for n in (CAT_NAME, CUSTODY_NAME, FINAL_NAME)] + [
                    x for x in infos if x.filename not in {CAT_NAME, CUSTODY_NAME, FINAL_NAME, TAR_NAME}]
                parsed = {}
                for info in ordered:
                    safe_path(info.filename.rstrip('/') if info.is_dir() else info.filename)
                    keep = not info.is_dir() and '/wheels/' not in info.filename
                    with archive.open(info) as stream:
                        item = body(stream, info.file_size, 'OUTER', info.filename, keep,
                                    MAX_CATALOG if info.filename == CAT_NAME else 16 << 20)
                    outer.append({**item, 'kind': 'directory' if info.is_dir() else 'regular',
                                  'crc32': '%08x' % info.CRC})
                    if info.filename in (CAT_NAME, CUSTODY_NAME, FINAL_NAME):
                        selected = next((x for x in captures if x['scope'] == 'OUTER' and x['path'] == info.filename), None)
                        require(selected is not None, 'required identity original was omitted')
                        raw, _ = raw_read(directory / selected['saved'], MAX_CATALOG)
                        parsed[info.filename] = (json_value(raw), raw)
                manifest, manifest_raw = parsed[CAT_NAME]
                custody, _ = parsed[CUSTODY_NAME]
                historical_final, _ = parsed[FINAL_NAME]
                require(type(manifest) is dict and manifest.get('schema') == 'hia.v87.full-retained-typed-custody.v1'
                        and type(custody) is dict and custody.get('schema') == 'hia.v87.full-retained-custody-result.v1'
                        and type(historical_final) is dict, 'original custody schemas differ')
                rows = manifest.get('originals')
                require(type(rows) is list and 1 <= len(rows) <= 100000, 'typed catalog count exceeds bound')
                by_path = {}
                for row in rows:
                    require(type(row) is dict, 'typed catalog row differs')
                    name = safe_path(row.get('path'), root_allowed=True)
                    require(name not in by_path and name != MANIFEST, 'duplicate/reserved typed original')
                    require(row.get('kind') in ('regular', 'directory', 'symlink', 'fifo', 'special')
                            and type(row.get('identity')) is list and len(row['identity']) == 9
                            and all(type(x) is int for x in row['identity']), 'typed original identity differs')
                    if row['kind'] == 'regular':
                        require(type(row.get('bytes')) is int and row['bytes'] == row['identity'][6]
                                and 0 <= row['bytes'] <= MAX_INNER_BYTES, 'typed regular size differs')
                        if 'read_error' not in row:
                            require(type(row.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
                                    'typed regular SHA absent')
                    by_path[name] = row
                require(custody.get('original_members') == len(rows)
                        and custody.get('catalog', {}).get('bytes') == len(manifest_raw)
                        and custody.get('catalog', {}).get('sha256') == sha256(manifest_raw).hexdigest(),
                        'actual catalog bytes do not match original custody pin')
                unreadable = [x['path'] for x in rows if 'read_error' in x]
                unlisted = [x['path'] for x in rows if 'traversal_error' in x]
                require(manifest.get('unreadable_regular_paths') == custody.get('unreadable_regular_paths') == unreadable
                        and manifest.get('unlisted_directory_paths') == custody.get('unlisted_directory_paths') == unlisted,
                        'original declared custody gaps differ')
                expected = {k: v for k, v in by_path.items() if k != '.' and v['kind'] != 'special'
                            and 'read_error' not in v}
                require(sum(x['bytes'] for x in expected.values() if x['kind'] == 'regular') <= MAX_INNER_BYTES,
                        'typed originals exceed fixed streaming byte limit')
                for name in CRITICAL_INNER:
                    row = by_path.get(name)
                    critical.append({'path': name, 'status': 'ORIGINAL_MISSING' if row is None else
                                     'ORIGINAL_UNREADABLE' if 'read_error' in row else 'PRESENT',
                                     'original': row})
                info = names[TAR_NAME]
                require(custody.get('archive', {}).get('bytes') == info.file_size,
                        'inner original TAR size differs from custody')
                seen, total_regular = set(), 0
                with archive.open(info) as compressed:
                    counted = DigestReader(compressed, info.file_size, deadline)
                    with gzip.GzipFile(fileobj=counted, mode='rb') as gunzip:
                        decoded = DigestReader(gunzip, MAX_INNER_BYTES + (512 << 20), deadline)
                        with tarfile.open(fileobj=decoded, mode='r|') as tar:
                            for member in tar:
                                name = safe_path(member.name)
                                require(name not in seen, 'duplicate typed TAR member')
                                seen.add(name)
                                if name == MANIFEST:
                                    require(member.isfile() and member.size == len(manifest_raw), 'embedded catalog type/size differs')
                                    raw = tar.extractfile(member).read(len(manifest_raw) + 1)
                                    require(raw == manifest_raw, 'embedded original catalog bytes differ')
                                    inner.append({'path': name, 'kind': 'catalog', 'bytes': len(raw), 'sha256': sha256(raw).hexdigest()})
                                    continue
                                require(name in expected, 'TAR member not in complete original catalog')
                                row, old = expected[name], expected[name]['identity']
                                require(member.mode == stat.S_IMODE(old[2]) and member.uid == old[3]
                                        and member.gid == old[4] and member.mtime == old[7] // 10**9,
                                        'original TAR metadata differs')
                                item = {'path': name, 'kind': row['kind'], 'mode': member.mode,
                                        'uid': member.uid, 'gid': member.gid, 'mtime': member.mtime}
                                if row['kind'] == 'regular':
                                    require(member.isfile() and member.size == row['bytes'], 'TAR regular size/type differs')
                                    value = body(tar.extractfile(member), row['bytes'], 'INNER', name, inner_wanted(name))
                                    require(value['sha256'] == row['sha256'], 'full original TAR member SHA differs')
                                    item.update(value)
                                    total_regular += value['bytes']
                                elif row['kind'] == 'directory':
                                    require(member.isdir() and member.size == 0, 'TAR directory differs')
                                elif row['kind'] == 'symlink':
                                    require(member.issym() and member.linkname == row['target'] and member.size == 0,
                                            'original symbolic-link metadata differs')
                                    item['target'] = member.linkname
                                else:
                                    require(row['kind'] == 'fifo' and member.isfifo() and member.size == 0,
                                            'TAR FIFO metadata differs')
                                inner.append(item)
                        while True:
                            trailing = decoded.read(CHUNK)
                            if not trailing:
                                break
                            require(not trailing.strip(b'\0'), 'nonzero TAR trailing bytes')
                    while counted.read(CHUNK):
                        pass
                    require(counted.count == info.file_size
                            and counted.digest.hexdigest() == custody['archive']['sha256'],
                            'whole inner gzip original SHA/CRC differs')
                    outer.append({'path': TAR_NAME, 'kind': 'regular', 'bytes': counted.count,
                                  'sha256': counted.digest.hexdigest(), 'crc32': '%08x' % info.CRC})
                require(seen == set(expected) | {MANIFEST} and custody.get('archive_members') == len(seen)
                        and custody.get('regular_bytes') == total_regular,
                        'complete selected TAR population or bytes differ')
                require(len(outer) == len(infos) and {x['path'] for x in outer} == set(names),
                        'complete outer original CRC/SHA population differs')
                result.update(outer_entries=len(outer),
                    outer_files=sum(x['kind'] == 'regular' for x in outer),
                    outer_directories=sum(x['kind'] == 'directory' for x in outer),
                    outer_bytes=sum(x['bytes'] for x in outer),
                    typed_originals=len(rows), inner_archive_members=len(seen), inner_regular_bytes=total_regular,
                    original_final_status=historical_final.get('status'),
                    original_complete_custody=historical_final.get('complete_custody'),
                    original_custody_status=custody.get('status'),
                    original_unreadable_paths=unreadable, original_unlisted_directories=unlisted,
                    original_whole_qualification=historical_final.get('whole_native_delivery_qualified'),
                    all_available_original_bodies_independently_read=True, directory=directory_pin)
            require(identity(before) == identity(os.fstat(original.fileno()))
                    and identity(before) == identity(Path(path).lstat()), 'inspection input identity changed')
        result['status'] = 'ALL_AVAILABLE_BODIES_VERIFIED_HISTORICAL_RESULTS_UNCHANGED'
    except BaseException as error:
        result.update(status='HOLD', error_type=type(error).__name__,
                      safe_refusal=str(error) if type(error) is Refusal else None,
                      errno=getattr(error, 'errno', None))
        doc('INSPECTION-ERROR.json', result)
    finally:
        result['outer_inventory'] = doc('OUTER-INVENTORY.json', {'complete': result['status'] != 'HOLD', 'files': outer})
        result['inner_inventory'] = doc('INNER-INVENTORY.json', {'complete': result['status'] != 'HOLD', 'members': inner})
        result['whole_originals_omitted_for_transport'] = omitted
        result['critical_originals'] = critical
        result['selected_original_files'] = len(captures)
        result['selected_original_bytes_reserved'] = original_bytes
        result['diagnostic_channel_complete'] = result['status'] != 'HOLD' and not omitted
        proof = doc('PHYSICAL-READBACK.json', result)
        index = {'schema': 'hia.failed-full32.small-original-index.v1', 'artifact': pin,
                 'status': result['status'], 'diagnostic_channel_complete': result['diagnostic_channel_complete'],
                 'originals': captures, 'omitted_whole_originals': omitted,
                 'critical_originals': critical, 'physical_readback': proof,
                 'derived_index_not_original': True, 'original_results_reclassified': False}
        index_pin = doc('INDEX.json', index)
        result['index'] = index_pin
        result['derived_bytes_reserved'] = derived_bytes
    return result
