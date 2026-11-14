"""Qualification-only lossless reader for fixed native/C fd4 audit pipes.

This module is NOT a Pager/provider implementation. It reads only the supplied
audit pipe and its own trace files. It never opens the DB/WAL/SHM, calls HIA,
loads native code, compiles anything, or decides a SQLite operation.

Each data read/decompression step is <=64KiB; a decoded record is <=73,792B.
No whole raw log is accumulated. One zlib stream spans <=4MiB physical files.
The 256MiB physical aggregate includes INDEX.json; 64KiB is reserved for that
index, not added to the bound. A caller must freeze max_raw_bytes/max_records
explicitly for its finite schedule; those are not production Pager limits.
Capture success alone never confers owner/test/SQLite qualification success.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import threading
import zlib

BLOCK = 65536
PART = 4 * 1024 * 1024
PHYSICAL = 256 * 1024 * 1024
INDEX_RESERVE = 65536
MAGIC = int.from_bytes(b'HIAPGAU2', 'little')
FIXED = {13:128, 14:73728, 11:128, 12:73728,
         20:128, 22:65664, 23:4096, 21:65664, 25:4096}
PRE = {10, 13, 14, 20, 22, 23}
C_MAGIC = int.from_bytes(b'HIAPGCA2', 'little')
C_FIXED = {30:128, 31:65536, 32:128, 33:128, 34:65536, 35:48}
C_PRE = {30, 31, 32}
PROFILES = ('native-owner-v2', 'sqlite-reference-v2')

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')

def require(value, message):
    if not value:
        raise ValueError(message)


class PhysicalBudget:
    """One instance for ALL native and C-oracle trace streams in a request."""
    def __init__(self, token):
        require(type(token) is str and token, 'aggregate budget token')
        self.token = token
        self.used = 0
        self.reserved = 0
        self.lock = threading.Lock()

    def reserve_index(self):
        with self.lock:
            require(self.used + self.reserved + INDEX_RESERVE <= PHYSICAL,
                    'shared index reserve')
            self.reserved += INDEX_RESERVE

    def available(self):
        with self.lock:
            return PHYSICAL - self.used - self.reserved

    def take(self, count):
        with self.lock:
            require(type(count) is int and count >= 0
                    and self.used+self.reserved+count <= PHYSICAL,
                    'shared 256MiB physical aggregate')
            # Charge before write; a failed/short write never frees guessed
            # capacity. The final independent reader counts actual file bytes.
            self.used += count

    def commit_index(self, count):
        with self.lock:
            require(0 <= count <= INDEX_RESERVE
                    and self.reserved >= INDEX_RESERVE, 'shared index accounting')
            self.reserved -= INDEX_RESERVE
            self.used += count

class Parts:
    def __init__(self, root, budget):
        require(type(budget) is PhysicalBudget, 'one shared physical budget')
        self.budget = budget
        self.budget.reserve_index()
        self.root = Path(root)
        self.root.mkdir(mode=0o700)
        self.parts = []
        self.stream = None
        self.count = 0
        self.total = 0
        self.sha = hashlib.sha256()
        self.part_sha = None
        self.name = None

    def finish_part(self):
        if self.stream is None:
            return
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()
        self.parts.append({'path': self.name, 'bytes': self.count,
                           'sha256': self.part_sha.hexdigest()})
        self.stream = None

    def append(self, data):
        view = memoryview(data)
        while view:
            require(self.budget.available() > 0,
                    'physical aggregate exhausted before complete EOF')
            if self.stream is None:
                self.name = 'part-%04d.zlib' % len(self.parts)
                self.stream = (self.root / self.name).open('xb')
                os.chmod(self.root / self.name, 0o600)
                self.count = 0
                self.part_sha = hashlib.sha256()
            count = min(len(view), PART-self.count,
                        self.budget.available())
            piece = view[:count]
            self.budget.take(count)
            written = self.stream.write(piece)
            require(written == count, 'short trace file write')
            self.part_sha.update(piece)
            self.sha.update(piece)
            self.count += count
            self.total += count
            view = view[count:]
            if self.count == PART:
                self.finish_part()

    def index(self, value):
        self.finish_part()
        value = dict(value, parts=self.parts, compressed_bytes=self.total,
                     compressed_sha256=self.sha.hexdigest(),
                     part_limit=PART, physical_limit=PHYSICAL,
                     physical_budget_token=self.budget.token)
        raw = canonical(value)
        require(len(raw) <= INDEX_RESERVE, 'index reserve exceeded')
        require(self.total + len(raw) <= PHYSICAL, 'aggregate index overflow')
        self.budget.commit_index(len(raw))
        path = self.root / 'INDEX.json'
        with path.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            require(stream.write(raw) == len(raw), 'short index write')
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return value

def header(raw, nonce, ordinal, profile):
    require(len(raw) == 64, 'audit header size')
    magic, version, owner, sequence, kind, count, status, hia_seq = struct.unpack('<8Q', raw)
    require(type(profile) is str and profile in PROFILES, 'record profile')
    fixed = FIXED if profile == 'native-owner-v2' else C_FIXED
    pre = PRE if profile == 'native-owner-v2' else C_PRE
    expected_magic = MAGIC if profile == 'native-owner-v2' else C_MAGIC
    require(magic == expected_magic and version == 2, 'audit profile')
    require(owner == nonce and sequence == ordinal, 'nonce/ordinal')
    variable_event = profile == 'native-owner-v2' and kind == 10
    require(kind in fixed or variable_event, 'unknown record kind')
    if variable_event:
        require(128 <= count <= 65664, 'event extent')
    else:
        require(count == fixed[kind], 'fixed full span missing')
    require(status <= 0xffffffff, 'returned status width')
    if kind in pre:
        require(status == 0, 'pre-record has a return value')
    return kind, count, status, hia_seq

def capture_pipe(fd, destination, *, nonce, max_raw_bytes, max_records, budget, profile):
    """Take ownership only of fd (the audit pipe's read end). Source-only draft."""
    require(type(profile) is str and profile in PROFILES, 'record profile')
    require(type(fd) is int and fd >= 0, 'pipe fd')
    require(stat.S_ISFIFO(os.fstat(fd).st_mode), 'fd4 sink must be a pipe')
    require(type(nonce) is int and 0 < nonce < (1 << 64), 'nonce')
    require(type(max_raw_bytes) is int and max_raw_bytes > 0, 'frozen expanded bound')
    require(type(max_records) is int and max_records > 0, 'frozen record bound')
    sink = Parts(destination, budget)
    compressor = zlib.compressobj(level=6, wbits=zlib.MAX_WBITS)
    raw_hash = hashlib.sha256()
    raw_count = 0
    records = 0
    closed_pipe = False
    finished = False
    error = None

    def read_piece(count):
        nonlocal raw_count
        require(raw_count <= max_raw_bytes, 'expanded bound')
        # A one-byte oversize probe permits observing EOF at the exact bound.
        # If present it is retained and forces HOLD; it never authorizes PASS.
        piece = os.read(fd, min(count, BLOCK, max_raw_bytes-raw_count+1))
        if piece:
            raw_count += len(piece)
            raw_hash.update(piece)
            # Preserve every received byte before semantic interpretation.
            sink.append(compressor.compress(piece))
            require(raw_count <= max_raw_bytes, 'expanded overflow probe')
        return piece

    def exact(count, *, boundary=False):
        pieces = []
        left = count
        while left:
            piece = read_piece(left)
            if not piece:
                if boundary and left == count:
                    return None
                raise EOFError('partial audit record at pipe EOF')
            pieces.append(piece)
            left -= len(piece)
        # Only a 64-byte header is assembled here, never a raw logfile.
        return b''.join(pieces)

    try:
        while True:
            prefix = exact(64, boundary=True)
            if prefix is None:
                closed_pipe = True
                break
            require(records < max_records, 'record bound')
            kind, count, status, hia_seq = header(prefix, nonce, records+1, profile)
            left = count
            event_prefix = None
            while left:
                piece = read_piece(left)
                if not piece:
                    raise EOFError('partial audit body at pipe EOF')
                if kind == 10 and event_prefix is None:
                    # A pipe may return less than 128 bytes. Header/payload
                    # identity is checked by the independent decoded parser.
                    event_prefix = True
                left -= len(piece)
            records += 1
        sink.append(compressor.flush(zlib.Z_FINISH))
        finished = True
    except BaseException as exc:
        # Zlib EOF for a retained prefix is distinct from audit-pipe EOF.
        # A partial record/limit failure always stays HOLD with pipe_eof=False.
        error = {'type': type(exc).__name__, 'message': str(exc)[:1024]}
        if not finished:
            try:
                sink.append(compressor.flush(zlib.Z_FINISH))
                finished = True
            except BaseException as close_error:
                error['retention_error'] = {'type': type(close_error).__name__,
                                            'message': str(close_error)[:1024]}
    finally:
        os.close(fd)
    result = {
        'schema': 'hia.sqlite-pager.audit-zlib-parts.v2',
        'record_profile': profile,
        'status': 'CAPTURE_CLOSED_PIPE' if closed_pipe and finished and error is None
                  else 'CAPTURE_HOLD_INCOMPLETE',
        'nonce': nonce, 'raw_bytes_received': raw_count,
        'raw_sha256_received': raw_hash.hexdigest(),
        'complete_records': records, 'max_raw_bytes': max_raw_bytes,
        'max_records': max_records, 'pipe_eof': closed_pipe,
        'zlib_finished': finished, 'error': error,
        'owner_or_product_qualification': False,
    }
    # On failure the index describes the actual retained compressed prefix.
    # raw_bytes_received need not all be decodable until zlib_finished=True.
    return sink.index(result)

def inspect_parts(root, *, nonce, max_raw_bytes, max_records, consume_record, profile):
    """Independent streaming decode. consume_record receives <=73728B bodies."""
    root = Path(root)
    with (root/'INDEX.json').open('rb') as stream:
        index_raw = stream.read(INDEX_RESERVE+1)
        require(len(index_raw) <= INDEX_RESERVE and not stream.read(1), 'index size/EOF')
    q = json.loads(index_raw)
    require(canonical(q) == index_raw, 'noncanonical index')
    require(type(profile) is str and profile in PROFILES, 'record profile')
    require(q['schema'] == 'hia.sqlite-pager.audit-zlib-parts.v2'
            and type(q['record_profile']) is str
            and q['record_profile'] == profile, 'fixed stream identity')
    require(q['status'] == 'CAPTURE_CLOSED_PIPE'
            and q['pipe_eof'] is True and q['zlib_finished'] is True
            and q['error'] is None, 'incomplete capture')
    require(q['nonce'] == nonce and type(q['nonce']) is int, 'nonce type')
    require(q['max_raw_bytes'] == max_raw_bytes
            and type(q['max_raw_bytes']) is int, 'expanded bound identity')
    require(q['max_records'] == max_records
            and type(q['max_records']) is int, 'record bound identity')
    require(q['part_limit'] == PART and q['physical_limit'] == PHYSICAL,
            'physical bound identity')
    for name in ('raw_bytes_received', 'complete_records', 'compressed_bytes'):
        require(type(q[name]) is int and q[name] >= 0, 'exact integer counts')
    expected = {'INDEX.json'} | {row['path'] for row in q['parts']}
    found = set()
    def onerror(error):
        raise error
    for parent, directories, files in os.walk(root, onerror=onerror, followlinks=False):
        require(Path(parent) == root and not directories, 'unexpected directory')
        for name in files:
            st = os.lstat(root/name)
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
                    'nonregular or aliased trace file')
            found.add(name)
    require(found == expected, 'full namespace differs')
    inflater = zlib.decompressobj(zlib.MAX_WBITS)
    compressed_hash = hashlib.sha256()
    raw_hash = hashlib.sha256()
    compressed_count = 0
    raw_count = 0
    pending = bytearray()
    need = 64
    info = None
    records = 0

    def receive(data):
        nonlocal raw_count, need, info, records
        raw_count += len(data)
        require(raw_count <= max_raw_bytes, 'expanded overflow')
        raw_hash.update(data)
        offset = 0
        while offset < len(data):
            count = min(need-len(pending), len(data)-offset)
            pending.extend(data[offset:offset+count])
            offset += count
            if len(pending) != need:
                continue
            if info is None:
                require(records < max_records, 'record overflow')
                info = header(bytes(pending), nonce, records+1, profile)
                pending.clear()
                need = info[1]
            else:
                body = bytes(pending)
                if info[0] == 10:
                    require(struct.unpack_from('<Q', body, 56)[0] == len(body)-128,
                            'event payload extent')
                consume_record(records+1, info, body)
                records += 1
                pending.clear()
                need = 64
                info = None

    for ordinal, row in enumerate(q['parts']):
        require(row['path'] == 'part-%04d.zlib' % ordinal, 'part sequence')
        require(type(row['bytes']) is int and 0 < row['bytes'] <= PART,
                'part extent type/bound')
        part_hash = hashlib.sha256()
        part_count = 0
        with (root/row['path']).open('rb') as stream:
            while True:
                block = stream.read(BLOCK)
                if not block:
                    break
                part_count += len(block)
                compressed_count += len(block)
                require(compressed_count + len(index_raw) <= PHYSICAL,
                        'physical aggregate')
                part_hash.update(block)
                compressed_hash.update(block)
                data = block
                while True:
                    require(not inflater.eof, 'bytes after single zlib EOF')
                    out = inflater.decompress(data, BLOCK)
                    receive(out)
                    require(not inflater.unused_data, 'trailing compressed data')
                    data = inflater.unconsumed_tail
                    if data:
                        continue
                    if len(out) == BLOCK and not inflater.eof:
                        continue
                    break
        require(part_count == row['bytes'] and part_hash.hexdigest() == row['sha256'],
                'full part identity')
    require(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail,
            'missing exact zlib EOF')
    require(not pending and info is None, 'partial final record')
    require(raw_count == q['raw_bytes_received']
            and raw_hash.hexdigest() == q['raw_sha256_received'], 'full expanded identity')
    require(compressed_count == q['compressed_bytes']
            and compressed_hash.hexdigest() == q['compressed_sha256'], 'full compressed identity')
    require(records == q['complete_records'], 'complete record population')
    return {'records': records, 'raw_bytes': raw_count,
            'physical_bytes': compressed_count+len(index_raw),
            'owner_or_product_qualification': False}
