"""Exact, bounded evidence formats; never extract or execute a ZIP/TAR member.

The target original ZIP's authenticated directory uses STORED members. The
reader still parses every local header, data descriptor, central entry and end
record from the actual concatenated bytes. A directory row never substitutes
for a member-body read. Unsupported compression/types fail explicitly.
"""
from hashlib import sha256
import io
import json
import stat
import struct
import tarfile
import zlib

CHUNK = 1 << 20
TAR_NAME = 'hia-v87-full-public/full-retained-originals.tar.gz'
CATALOG_NAME = '.FULL-RETAINED-TYPED-MANIFEST.json'

class Refusal(Exception):
    pass

def require(value, message):
    if not value:
        raise Refusal(message)

def safe_name(name, root=False):
    require(type(name) is str and name and '\x00' not in name and '\\' not in name
            and not name.startswith('/') and (root and name == '.' or
                all(x not in ('', '.', '..') for x in name.rstrip('/').split('/'))),
            'unsafe or ambiguous archive name')
    return name

class ChunkReader:
    """One bounded buffer; SHA covers every byte actually returned to the consumer."""
    def __init__(self, chunks, maximum, check=lambda: None):
        self.chunks, self.maximum, self.check = iter(chunks), maximum, check
        self.buffer, self.ended = b'', False
        self.count, self.digest = 0, sha256()
        self.last_returned_tail = b''
    def read(self, size):
        require(type(size) is int and 0 <= size <= CHUNK, 'bounded read size required')
        if not size:
            return b''
        pieces, count = [], 0
        while count < size:
            self.check()
            if not self.buffer and not self.ended:
                try:
                    self.buffer = next(self.chunks)
                    require(type(self.buffer) is bytes and len(self.buffer) <= CHUNK,
                            'bounded byte chunk required')
                except StopIteration:
                    self.ended = True
            if not self.buffer:
                if self.ended:
                    break
                continue
            take = min(size - count, len(self.buffer))
            pieces.append(self.buffer[:take]); self.buffer = self.buffer[take:]; count += take
        raw = b''.join(pieces)
        self.count += len(raw)
        require(self.count <= self.maximum, 'stream exceeds complete fixed bound')
        self.digest.update(raw)
        self.last_returned_tail = (self.last_returned_tail + raw[-65536:])[-65536:]
        return raw
    def exact(self, size):
        require(type(size) is int and 0 <= size <= CHUNK, 'small exact read required')
        raw = self.read(size)
        require(len(raw) == size, 'original stream truncated')
        return raw
    def tell(self):
        return self.count

class LimitedReader:
    def __init__(self, source, size, progress=None):
        self.source, self.size, self.count = source, size, 0
        self.digest, self.crc = sha256(), 0
        self.progress = progress if progress is not None else {}
    def read(self, size):
        require(type(size) is int and 0 <= size <= CHUNK, 'bounded member read required')
        if not size or self.count == self.size:
            return b''
        raw = self.source.read(min(size, self.size - self.count))
        require(raw, 'member body truncated')
        self.count += len(raw); self.digest.update(raw); self.crc = zlib.crc32(raw, self.crc)
        self.progress['body_bytes_read'] = self.count
        return raw
    def finish(self):
        require(self.count == self.size, 'whole member body not consumed')
        return {'bytes': self.count, 'sha256': self.digest.hexdigest(), 'crc32': '%08x' % (self.crc & 0xffffffff)}

def gzip_chunks(source, *, compressed_bytes, compressed_sha256, raw_limit,
                state, check=lambda: None, raw_bytes=None, raw_sha256=None):
    """Exactly one gzip stream: CRC/trailer, no trailing bytes, bounded inflation."""
    codec = zlib.decompressobj(31)
    input_hash, output_hash = sha256(), sha256()
    input_count = output_count = 0
    while True:
        check()
        block = source.read(CHUNK)
        if not block:
            break
        require(not codec.eof, 'bytes after the single gzip stream')
        input_count += len(block); input_hash.update(block)
        require(input_count <= compressed_bytes, 'gzip compressed length exceeded')
        tail = block
        while tail:
            check()
            output = codec.decompress(tail, min(CHUNK, raw_limit + 1 - output_count))
            tail = codec.unconsumed_tail
            output_count += len(output); output_hash.update(output)
            require(output_count <= raw_limit, 'gzip expanded length exceeded')
            require(not codec.unused_data, 'concatenated gzip or trailing bytes refused')
            state.update(compressed_bytes_read=input_count, raw_bytes_read=output_count)
            if output:
                yield output
            if codec.eof:
                require(not tail, 'unconsumed bytes after gzip end')
    require(codec.eof and not codec.unused_data and not codec.unconsumed_tail,
            'gzip end/CRC/trailer missing')
    require(input_count == compressed_bytes and input_hash.hexdigest() == compressed_sha256,
            'complete gzip seal differs')
    require(raw_bytes is None or output_count == raw_bytes, 'complete raw range length differs')
    require(raw_sha256 is None or output_hash.hexdigest() == raw_sha256, 'complete raw range SHA differs')
    state.update(complete=True, compressed_bytes=input_count, compressed_sha256=input_hash.hexdigest(),
                 raw_bytes=output_count, raw_sha256=output_hash.hexdigest(), gzip_streams=1, trailing_bytes=0)

def extra_fields(raw):
    fields, offset = {}, 0
    while offset < len(raw):
        require(offset + 4 <= len(raw), 'truncated ZIP extra header')
        key, count = struct.unpack_from('<HH', raw, offset); offset += 4
        require(key not in fields and offset + count <= len(raw), 'duplicate or truncated ZIP extra field')
        fields[key] = raw[offset:offset + count]; offset += count
    return fields

def zip64_values(extra, requested):
    raw = extra_fields(extra).get(1, b'')
    answer, position = [], 0
    for old, marker, width in requested:
        if old == marker:
            require(position + width <= len(raw), 'missing ZIP64 value')
            answer.append(int.from_bytes(raw[position:position + width], 'little')); position += width
        else:
            answer.append(old)
    require(not raw or position == len(raw), 'unaccounted ZIP64 values')
    return answer

def dos_time(values):
    year, month, day, hour, minute, second = values
    return (hour << 11) | (minute << 5) | (second // 2), ((year - 1980) << 9) | (month << 5) | day

def original_zip(source, directory, inventory, body_consumer, record, progress):
    rows = directory['members']
    require(4 <= len(rows) <= 256 and [r['index'] for r in rows] == list(range(len(rows))),
            'complete observed directory sequence required')
    names = [safe_name(r['name']) for r in rows]
    require(len(set(names)) == len(names), 'duplicate original ZIP member')
    original_inventory = inventory['files']
    require(type(original_inventory) is list and len(original_inventory) == len(rows)
            and len({r['path'] for r in original_inventory}) == len(original_inventory),
            'original full inventory length or unique paths differ')
    expected = {r['path']: r for r in original_inventory}
    require(inventory.get('complete') is True and len(expected) == len(rows)
            and set(expected) == set(names), 'whole-body inventory set differs')
    for name in (TAR_NAME, 'hia-v87-full-public/ORIGINAL-CATALOG.json',
                 'hia-v87-full-public/CUSTODY.json', 'hia-v87-full-public/FINAL.json'):
        require(name in expected, 'mandatory original custody member missing')
    actual_rows, local_end = [], 0
    for row in sorted(rows, key=lambda r: r['header_offset']):
        name = row['name']; progress['current_member'] = {'name': name, 'body_bytes_read': 0}
        require(source.tell() == local_end == row['header_offset'], 'ZIP local range gap or overlap')
        fixed = source.exact(30)
        sig, needed, flags, method, clock, date, crc, compressed, expanded, nlen, xlen = struct.unpack('<4s5H3I2H', fixed)
        require(sig == b'PK\x03\x04' and 0 < nlen <= 65535 and xlen <= 65535,
                'invalid local ZIP header')
        raw_name, extra = source.exact(nlen), source.exact(xlen)
        decoded = raw_name.decode('utf-8' if flags & 0x800 else 'cp437', 'strict')
        require(decoded == name and row['kind'] == 'regular' and method == row['compression'] == 0
                and flags == row['flags'] and flags & ~(0x800 | 8) == 0
                and needed == row['extract_version']
                and (clock, date) == dos_time(row['date_time']), 'local ZIP metadata differs')
        zip64 = compressed == 0xffffffff or expanded == 0xffffffff
        actual_expanded, actual_compressed = zip64_values(extra,
            [(expanded, 0xffffffff, 8), (compressed, 0xffffffff, 8)])
        require(row['compressed_bytes'] == row['uncompressed_bytes'] == expected[name]['bytes'],
                'STORED whole-body extent differs')
        if flags & 8:
            require(crc in (0, row['crc32_from_directory'])
                    and actual_compressed in (0, row['compressed_bytes'])
                    and actual_expanded in (0, row['uncompressed_bytes']), 'local descriptor placeholders differ')
        else:
            require(crc == row['crc32_from_directory'] and actual_compressed == row['compressed_bytes']
                    and actual_expanded == row['uncompressed_bytes'], 'local CRC/size differs')
        body = LimitedReader(source, row['compressed_bytes'], progress['current_member'])
        body_consumer(name, body, expected[name])
        readback = body.finish()
        require(readback['bytes'] == row['uncompressed_bytes'] and readback['sha256'] == expected[name]['sha256']
                and readback['crc32'] == expected[name]['crc32'] == '%08x' % row['crc32_from_directory'],
                'actual full ZIP body CRC/SHA/size differs')
        descriptor = b''
        if flags & 8:
            first = source.exact(4)
            has_signature = first == b'PK\x07\x08'
            crc_raw = source.exact(4) if has_signature else first
            size_raw = source.exact(16 if zip64 else 8)
            descriptor = first + (crc_raw if has_signature else b'') + size_raw
            desc_crc = int.from_bytes(crc_raw, 'little')
            desc_compressed, desc_expanded = struct.unpack('<QQ' if zip64 else '<II', size_raw)
            require(desc_crc == row['crc32_from_directory'] and desc_compressed == row['compressed_bytes']
                    and desc_expanded == row['uncompressed_bytes'], 'ZIP data descriptor differs')
        local_end = source.tell()
        actual = {'path': name, 'kind': 'regular', **readback, 'whole_body_independently_read': True,
                  'local_header_offset': row['header_offset'], 'data_end_with_descriptor': local_end,
                  'local_header_sha256': sha256(fixed + raw_name + extra).hexdigest(),
                  'local_extra_hex': extra.hex(), 'descriptor_hex': descriptor.hex()}
        actual_rows.append(actual); record(actual)
    central_start = source.tell()
    central_hash = sha256()
    for expected_row in rows:
        fixed = source.exact(46)
        values = struct.unpack('<4s6H3I5H2I', fixed)
        (sig, made, needed, flags, method, clock, date, crc, compressed, expanded,
         nlen, xlen, clen, disk, internal, external, offset) = values
        require(sig == b'PK\x01\x02', 'missing complete central directory entry')
        raw_name, extra, comment = source.exact(nlen), source.exact(xlen), source.exact(clen)
        central_hash.update(fixed + raw_name + extra + comment)
        expanded, compressed, offset, disk = zip64_values(extra,
            [(expanded, 0xffffffff, 8), (compressed, 0xffffffff, 8), (offset, 0xffffffff, 8), (disk, 0xffff, 4)])
        name = raw_name.decode('utf-8' if flags & 0x800 else 'cp437', 'strict')
        require(name == expected_row['name'] and made & 255 == expected_row['create_version']
                and made >> 8 == expected_row['create_system'] and needed == expected_row['extract_version']
                and flags == expected_row['flags'] and method == expected_row['compression']
                and (clock, date) == dos_time(expected_row['date_time'])
                and crc == expected_row['crc32_from_directory'] and compressed == expected_row['compressed_bytes']
                and expanded == expected_row['uncompressed_bytes'] and disk == 0
                and internal == expected_row['internal_attr'] and external == expected_row['external_attr']
                and offset == expected_row['header_offset'] and extra.hex() == expected_row['extra_hex']
                and comment.hex() == expected_row['comment_hex'], 'actual central directory metadata differs')
        require(source.tell() - central_start <= 4 << 20, 'central directory bound exceeded')
    central_size = source.tell() - central_start
    marker = source.exact(4)
    zip64_end = None
    if marker == b'PK\x06\x06':
        z64_offset = source.tell() - 4
        size = int.from_bytes(source.exact(8), 'little')
        require(size == 44, 'unsupported ZIP64 end extension')
        made, needed, disk, central_disk, disk_count, count, csize, coff = struct.unpack('<2H2I4Q', source.exact(44))
        require(disk == central_disk == 0 and disk_count == count == len(rows)
                and csize == central_size and coff == central_start, 'ZIP64 end directory differs')
        locator, disk, actual_offset, disks = struct.unpack('<4sIQI', source.exact(20))
        require(locator == b'PK\x06\x07' and disk == 0 and actual_offset == z64_offset and disks == 1,
                'ZIP64 locator differs')
        zip64_end = {'offset': z64_offset, 'version_made': made, 'version_needed': needed}
        marker = source.exact(4)
    require(marker == b'PK\x05\x06', 'ZIP end record missing')
    disk, central_disk, disk_count, count, csize, coff, comment_count = struct.unpack('<4H2IH', source.exact(18))
    require(disk == central_disk == 0 and disk_count == count
            and count in ((len(rows), 0xffff) if zip64_end else (len(rows),))
            and csize in ((central_size, 0xffffffff) if zip64_end else (central_size,))
            and coff in ((central_start, 0xffffffff) if zip64_end else (central_start,)),
            'complete end record directory/count differs')
    comment = source.exact(comment_count)
    require(source.read(1) == b'', 'bytes follow original ZIP end record')
    require(sum(r['bytes'] for r in actual_rows) == directory['declared_total_bytes'],
            'all actual outer-body totals differ')
    progress['current_member'] = None
    return {'members': len(actual_rows), 'regular_bytes': sum(r['bytes'] for r in actual_rows),
            'local_extents_contiguous': True, 'central_directory_offset': central_start,
            'central_directory_bytes': central_size, 'central_directory_sha256': central_hash.hexdigest(),
            'central_and_local_complete_set_equal': True, 'ZIP64_end': zip64_end,
            'archive_comment_hex': comment.hex(), 'whole_ZIP_bytes': source.count,
            'whole_ZIP_sha256': source.digest.hexdigest(), 'all_member_bodies_actually_read': True}

def inner_tar(compressed, catalog_raw, custody, record, capture, progress, check=lambda: None):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate catalog JSON key')
            result[key] = value
        return result
    def bad_constant(_):
        raise Refusal('non-finite catalog JSON constant')
    catalog = json.loads(catalog_raw, object_pairs_hook=pairs, parse_constant=bad_constant)
    rows = catalog['originals']
    require(catalog.get('schema') == 'hia.v87.full-retained-typed-custody.v1'
            and type(rows) is list and 1 <= len(rows) <= 100000, 'typed catalog differs')
    by_path = {}
    for row in rows:
        name = safe_name(row['path'], root=True)
        require(name not in by_path and name != CATALOG_NAME, 'duplicate/reserved typed path')
        require(row['kind'] in ('regular', 'directory', 'symlink', 'fifo', 'special')
                and type(row['identity']) is list and len(row['identity']) == 9
                and all(type(x) is int for x in row['identity']), 'original typed identity differs')
        by_path[name] = row
    unreadable = [r['path'] for r in rows if 'read_error' in r]
    unlisted = [r['path'] for r in rows if 'traversal_error' in r]
    require(catalog['unreadable_regular_paths'] == custody['unreadable_regular_paths'] == unreadable
            and catalog['unlisted_directory_paths'] == custody['unlisted_directory_paths'] == unlisted,
            'original partial-custody declaration differs')
    expected = {k: v for k, v in by_path.items() if k != '.' and v['kind'] != 'special' and 'read_error' not in v}
    require(custody['original_members'] == len(rows) and custody['catalog']['bytes'] == len(catalog_raw)
            and custody['catalog']['sha256'] == sha256(catalog_raw).hexdigest(), 'catalog whole seal differs')
    gzip_state = {}
    decoded = ChunkReader(gzip_chunks(compressed, compressed_bytes=custody['archive']['bytes'],
        compressed_sha256=custody['archive']['sha256'], raw_limit=(16 << 30) + (512 << 20),
        state=gzip_state, check=check), (16 << 30) + (512 << 20), check)
    seen, regular_bytes, regular_files = set(), 0, 0
    with tarfile.open(fileobj=decoded, mode='r|', bufsize=10240) as archive:
        for member in archive:
            check()
            name = safe_name(member.name)
            require(name not in seen, 'duplicate typed TAR member')
            seen.add(name)
            require(len(seen) <= 100000, 'typed member count exceeds bound')
            progress['inner_current'] = {'path': name, 'bytes_read': 0}
            if name == CATALOG_NAME:
                require(member.isfile() and member.size == len(catalog_raw), 'embedded catalog size/type differs')
                body = archive.extractfile(member)
                digest, count = sha256(), 0
                while True:
                    chunk = body.read(min(CHUNK, len(catalog_raw) + 1 - count))
                    if not chunk:
                        break
                    require(chunk == catalog_raw[count:count + len(chunk)], 'embedded original catalog bytes differ')
                    digest.update(chunk); count += len(chunk)
                require(count == len(catalog_raw), 'embedded catalog truncated')
                record({'path': name, 'kind': 'catalog', 'bytes': count, 'sha256': digest.hexdigest(),
                        'whole_body_independently_read': True})
                continue
            require(name in expected, 'TAR original absent from complete catalog')
            row, old = expected[name], expected[name]['identity']
            require(member.mode == stat.S_IMODE(old[2]) and member.uid == old[3] and member.gid == old[4]
                    and member.mtime == old[7] // 10**9, 'original TAR metadata differs')
            actual = {'path': name, 'kind': row['kind'], 'mode': member.mode, 'uid': member.uid,
                      'gid': member.gid, 'mtime': member.mtime}
            if row['kind'] == 'regular':
                require(member.isfile() and member.size == row['bytes'] == old[6], 'regular original size/type differs')
                require(0 <= member.size <= 16 << 30, 'regular original bound exceeded')
                body = archive.extractfile(member)
                target = capture(name, row)
                digest, crc, count = sha256(), 0, 0
                try:
                    while True:
                        check()
                        chunk = body.read(min(CHUNK, row['bytes'] + 1 - count))
                        if not chunk:
                            break
                        count += len(chunk); require(count <= row['bytes'], 'TAR body grew')
                        digest.update(chunk); crc = zlib.crc32(chunk, crc)
                        progress['inner_current']['bytes_read'] = count
                        if target is not None:
                            target.write(chunk)
                    require(count == row['bytes'] and digest.hexdigest() == row['sha256'],
                            'actual complete TAR body SHA/length differs')
                    if target is not None:
                        target.finish(count, digest.hexdigest())
                finally:
                    if target is not None:
                        target.close()
                actual.update(bytes=count, sha256=digest.hexdigest(), crc32='%08x' % (crc & 0xffffffff),
                              whole_body_independently_read=True)
                regular_files += 1; regular_bytes += count
            elif row['kind'] == 'directory':
                require(member.isdir() and member.size == 0, 'directory metadata differs')
            elif row['kind'] == 'symlink':
                require(member.issym() and member.size == 0 and member.linkname == row['target'], 'symlink metadata differs')
                actual['target'] = member.linkname
            else:
                require(row['kind'] == 'fifo' and member.isfifo() and member.size == 0, 'FIFO metadata differs')
            record(actual)
            progress['inner_members_read'] = len(seen)
        # The TAR reader can have a final bounded read-ahead buffer. Those
        # already-inflated bytes must also be zero padding, not hidden entries.
        logical_end = archive.fileobj.tell()
        ahead = decoded.count - logical_end
        require(0 <= ahead <= 10240, 'unexpected TAR read-ahead extent')
        require(ahead == 0 or not decoded.last_returned_tail[-ahead:].strip(b'\0'),
                'nonzero buffered bytes after TAR terminal header')
    # tarfile may stop at its first zero header; drain and authenticate every
    # remaining gzip/plain-TAR byte, accepting only TAR's zero padding.
    while True:
        trailing = decoded.read(CHUNK)
        if not trailing:
            break
        require(not trailing.strip(b'\0'), 'nonzero bytes after TAR terminal padding')
    require(gzip_state.get('complete') is True and seen == set(expected) | {CATALOG_NAME}
            and len(seen) == custody['archive_members'] and regular_bytes == custody['regular_bytes'],
            'complete typed-original denominator or gzip termination differs')
    progress['inner_current'] = None
    return {'typed_catalog_rows': len(rows), 'TAR_members': len(seen), 'regular_files': regular_files,
            'regular_bytes': regular_bytes, 'unreadable_originals': unreadable, 'unlisted_original_directories': unlisted,
            'complete_all_available_bodies_read': True, 'whole_original_namespace_complete': not unreadable and not unlisted,
            'gzip': gzip_state, 'TAR_stream_bytes': decoded.count, 'TAR_stream_sha256': decoded.digest.hexdigest(),
            'special_nodes_opened_or_extracted': False}
