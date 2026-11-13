"""Exact mapped-ELF admission for experimental CPython 3.12 CALL ownership.

The four-component source result never executed this mechanism.  Private
runtime functions are resolved from the admitted interpreter ELF's actual symbol
table, then matched against its loaded mapping.  No offset from another
runtime, public CallOneArg substitute, compilation, network or fallback is
provided here.  This is a development ABI prerequisite, not a JSON input
restriction or a public selector.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import os
from pathlib import Path
import stat
import struct
import sys

SYMBOLS = (
    '_PyEval_EvalFrameDefault', '_PyFunction_Vectorcall',
    '_PyThreadState_PushFrame', '_PyThreadState_PopFrame',
    '_PyFrame_ClearExceptCode', '_PyTuple_FromArraySteal',
    '_PyFrame_MakeAndSetFrameObject', '_Py_MakeCoro',
    '_PyList_AppendTakeRefListResize', 'list_resize', '_Py_CheckRecursiveCallPy',
)
HEADER = struct.Struct('<16sHHIQQQIHHHHHH')
PROGRAM = struct.Struct('<IIQQQQQQ')
SECTION = struct.Struct('<IIQQQQIIQQ')
SYMBOL = struct.Struct('<IBBHQQ')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_runtime(path, expected_sha256, expected_bytes):
    if (type(expected_sha256) is not str or len(expected_sha256) != 64
            or any(c not in '0123456789abcdef' for c in expected_sha256)
            or type(expected_bytes) is not int or expected_bytes <= 0):
        raise ValueError('fixed runtime size and SHA256 are required')
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('an absolute physical runtime path is required')
    directories = []
    links = []
    leaf = None
    try:
        directories.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for name in path.parts[1:-1]:
            parent = directories[-1]
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError('runtime parent is not a physical directory')
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                 dir_fd=parent)
            directories.append(descriptor)
            if identity(os.fstat(descriptor)) != identity(before):
                raise ValueError('runtime parent changed during open')
            links.append((parent, name, descriptor, identity(before)))
        parent = directories[-1]
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size != expected_bytes):
            raise ValueError('runtime regular-file extent differs')
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                       dir_fd=parent)
        if identity(os.fstat(leaf)) != identity(before):
            raise ValueError('runtime name/descriptor identity differs')
        pieces = []
        digest = sha256()
        remaining = expected_bytes
        while remaining:
            chunk = os.read(leaf, min(1 << 20, remaining))
            if not chunk:
                raise ValueError('runtime ended before its frozen extent')
            pieces.append(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(leaf, 1):
            raise ValueError('runtime grew after its frozen extent')
        if (digest.hexdigest() != expected_sha256
                or identity(os.fstat(leaf)) != identity(before)
                or identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
                != identity(before)):
            raise ValueError('runtime bytes or identity changed')
        for parent_fd, name, descriptor, original in links:
            if (identity(os.fstat(descriptor)) != original
                    or identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
                    != original):
                raise ValueError('runtime parent chain changed')
        return b''.join(pieces), {
            'path': str(path), 'bytes': expected_bytes, 'sha256': expected_sha256,
            'identity': list(identity(before)),
        }
    finally:
        if leaf is not None:
            os.close(leaf)
        for descriptor in reversed(directories):
            os.close(descriptor)

def _runtime_profile(raw):
    """Read link-time coordinates without treating a mapping base as a bias."""
    def extent(offset, size):
        if offset < 0 or size < 0 or offset > len(raw) - size:
            raise ValueError('ELF span exceeds the frozen runtime')
        return raw[offset:offset + size]

    if len(raw) < HEADER.size:
        raise ValueError('ELF header is incomplete')
    (ident, kind, machine, version, _entry, program_at, section_at, _flags,
     header_bytes, program_bytes, program_count, section_bytes,
     section_count, section_names) = HEADER.unpack_from(raw)
    if (ident[:7] != b'\x7fELF\x02\x01\x01' or kind not in (2, 3) or machine != 62
            or version != 1 or header_bytes != HEADER.size
            or program_bytes != PROGRAM.size or section_bytes != SECTION.size
            or not program_count or not section_count
            or section_names >= section_count):
        raise ValueError('runtime ELF profile differs')
    extent(program_at, program_count * PROGRAM.size)
    extent(section_at, section_count * SECTION.size)
    page_bytes = os.sysconf('SC_PAGE_SIZE')
    if (type(page_bytes) is not int or page_bytes <= 0
            or page_bytes & (page_bytes - 1)):
        raise ValueError('runtime page size is not a positive power of two')
    loads = []
    for index in range(program_count):
        (p_kind, flags, file_at, address, _physical, file_size,
         memory_size, alignment) = PROGRAM.unpack_from(raw, program_at + index * PROGRAM.size)
        if p_kind != 1:
            continue
        extent(file_at, file_size)
        if (file_size > memory_size or memory_size > (1 << 64) - address
                or flags & ~7 or address % page_bytes != file_at % page_bytes
                or (alignment not in (0, 1)
                    and (alignment & (alignment - 1)
                         or address % alignment != file_at % alignment))):
            raise ValueError('runtime load segment is not a valid file/memory extent')
        if loads and address < loads[-1]['virtual_address']:
            raise ValueError('runtime load segments are not in virtual-address order')
        loads.append({'program_index': index, 'flags': flags,
                      'file_offset': file_at, 'virtual_address': address,
                      'file_bytes': file_size, 'memory_bytes': memory_size,
                      'alignment': alignment})
    nonempty = [p for p in loads if p['memory_bytes']]
    if not nonempty or not any(p['flags'] & 1 and p['file_bytes'] for p in nonempty):
        raise ValueError('runtime has no nonempty executable load segment')
    sections = [SECTION.unpack_from(raw, section_at + i * SECTION.size)
                for i in range(section_count)]
    layout = {'elf_type': kind, 'elf_type_name': 'ET_EXEC' if kind == 2 else 'ET_DYN',
              'page_bytes': page_bytes, 'load_segments': loads,
              'lowest_load_page': min(p['virtual_address'] & -page_bytes for p in nonempty)}
    return layout, sections


def _symbol_records(raw, names):
    layout, sections = _runtime_profile(raw)

    def extent(offset, size):
        if offset < 0 or size < 0 or offset > len(raw) - size:
            raise ValueError('ELF span exceeds the frozen runtime')
        return raw[offset:offset + size]

    if (type(names) is not tuple or not names or len(set(names)) != len(names)
            or any(type(name) is not str for name in names)):
        raise ValueError('an exact unique symbol population is required')
    found = {name: set() for name in names}
    tables = 0
    for section in sections:
        _name, section_kind, _flags, _address, at, size, link, _info, _align, stride = section
        if section_kind != 2:
            continue
        tables += 1
        if stride != SYMBOL.size or size % stride or link >= len(sections):
            raise ValueError('runtime ELF symbol table differs')
        extent(at, size)
        string_section = sections[link]
        if string_section[1] != 3:
            raise ValueError('runtime symbol-name table differs')
        strings = extent(string_section[4], string_section[5])
        for offset in range(at, at + size, stride):
            name_at, info, other, index, value, symbol_size = SYMBOL.unpack_from(raw, offset)
            if name_at >= len(strings):
                raise ValueError('runtime symbol name exceeds its table')
            end = strings.find(b'\0', name_at)
            if end < 0:
                raise ValueError('runtime symbol name is unterminated')
            name = strings[name_at:end].decode('ascii', 'strict')
            if name not in found:
                continue
            if (info & 15) != 2 or not index or index >= len(sections) or not symbol_size:
                raise ValueError('required runtime symbol is not a defined function')
            found[name].add((value, symbol_size, other, index))
    if not tables or any(len(rows) != 1 for rows in found.values()):
        raise ValueError('exact private runtime functions are unavailable or ambiguous')
    records = []
    for name in names:
        value, size, _visibility, section_index = next(iter(found[name]))
        section = sections[section_index]
        if (section[1] != 1 or section[2] & 6 != 6 or value < section[3]
                or value - section[3] > section[5]
                or size > section[5] - (value - section[3])):
            raise ValueError('runtime function is outside its allocated executable section')
        section_file_at = section[4] + value - section[3]
        extent(section_file_at, size)
        matches = []
        for program in layout['load_segments']:
            address = program['virtual_address']
            file_size = program['file_bytes']
            if program['flags'] & 5 == 5 and value >= address:
                relative = value - address
                if relative <= file_size and size <= file_size - relative:
                    matches.append((program['file_offset'] + relative, program['program_index']))
        if len(matches) != 1 or matches[0][0] != section_file_at:
            raise ValueError('runtime function has no unique consistent executable file mapping')
        code = extent(matches[0][0], size)
        records.append({'name': name, 'value': value, 'bytes': size,
                        'file_offset': matches[0][0], 'section': section_index,
                        'segment_index': matches[0][1],
                        'sha256': sha256(code).hexdigest()})
    return records, layout


def symbol_table(raw):
    return _symbol_records(raw, SYMBOLS)[0]


def _parse_runtime_maps(raw, runtime):
    """Keep only the admitted inode; a same-path replacement is a refusal."""
    device, inode = runtime['identity'][:2]
    expected_device = (os.major(device), os.minor(device))
    rows = []
    for line in raw.splitlines():
        parts = line.split(None, 5)
        if len(parts) not in (5, 6):
            raise ValueError('process map record is malformed')
        try:
            start, end = [int(x, 16) for x in parts[0].split(b'-')]
            major, minor = [int(x, 16) for x in parts[3].split(b':')]
            offset, observed_inode = int(parts[2], 16), int(parts[4], 10)
            permissions = parts[1].decode('ascii', 'strict')
        except (ValueError, UnicodeError):
            raise ValueError('process map fields are malformed') from None
        if (not 0 <= start < end <= 1 << 64 or offset < 0 or observed_inode < 0
                or len(permissions) != 4 or permissions[0] not in 'r-'
                or permissions[1] not in 'w-' or permissions[2] not in 'x-'
                or permissions[3] not in 'ps'):
            raise ValueError('process map extent or permissions are malformed')
        path = os.fsdecode(parts[5]) if len(parts) == 6 else ''
        same_file = (major, minor) == expected_device and observed_inode == inode
        if path != runtime['path'] and not same_file:
            continue
        if not same_file or path != runtime['path']:
            raise ValueError('runtime map pathname and physical inode differ')
        if rows and start < rows[-1]['end']:
            raise ValueError('runtime file maps overlap or are not ordered')
        rows.append({'start': start, 'end': end, 'permissions': permissions,
                     'file_offset': offset, 'device_major': major,
                     'device_minor': minor, 'inode': observed_inode, 'path': path})
    if not rows:
        raise ValueError('the admitted runtime has no process file mapping')
    return rows


def _runtime_maps(runtime):
    # This is a kernel metadata observation in the current process, not a
    # stored map from the failed child. The limit bounds evidence only.
    fd = os.open('/proc/%d/maps' % os.getpid(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('process maps is not a regular proc record')
        parts = []
        length = 0
        while True:
            part = os.read(fd, min(65536, (1 << 20) + 1 - length))
            if not part:
                break
            parts.append(part)
            length += len(part)
            if length > 1 << 20:
                raise ValueError('process mapping evidence exceeds one MiB')
    finally:
        os.close(fd)
    return _parse_runtime_maps(b''.join(parts), runtime)


def _cover_file_span(rows, start, size, file_offset, flags):
    if (type(start) is not int or type(size) is not int or start < 0 or size <= 0
            or start > (1 << 64) - size):
        raise ValueError('mapped runtime span is outside the address domain')
    cursor = start
    end = start + size
    covered = []
    while cursor < end:
        matches = [(i, row) for i, row in enumerate(rows) if row['start'] <= cursor < row['end']]
        if len(matches) != 1:
            raise ValueError('runtime span has no unique actual map')
        index, row = matches[0]
        permissions = row['permissions']
        if (permissions[3] != 'p' or bool(flags & 4) != (permissions[0] == 'r')
                or bool(flags & 1) != (permissions[2] == 'x')
                or (permissions[1] == 'w' and not flags & 2)
                or (flags & 1 and permissions[1] != '-')
                or row['file_offset'] + cursor - row['start'] != file_offset + cursor - start):
            raise ValueError('runtime map permissions or file-coordinate relation differs')
        covered.append(index)
        cursor = min(row['end'], end)
    return covered


def _mapping_relation(layout, records, runtime, anchor, image_base, rows):
    if (type(anchor) is not int or type(image_base) is not int
            or not 0 < anchor < 1 << 64 or not 0 < image_base < 1 << 64):
        raise ValueError('runtime anchor and loader mapping base must be actual addresses')
    if not records or records[0]['name'] != '_PyEval_EvalFrameDefault':
        raise ValueError('the exact evaluator anchor must head the table')
    bias = anchor - records[0]['value']
    if (bias < 0 or bias % layout['page_bytes']
            or (layout['elf_type'] == 2 and bias != 0)
            or image_base != bias + layout['lowest_load_page']
            or image_base != rows[0]['start']):
        raise ValueError('runtime ELF coordinates, relocation bias and mapping base disagree')
    file_segments = []
    for segment in layout['load_segments']:
        if not segment['file_bytes']:
            continue
        start = bias + segment['virtual_address']
        covered = _cover_file_span(rows, start, segment['file_bytes'],
                                   segment['file_offset'], segment['flags'])
        file_segments.append({'program_index': segment['program_index'],
                              'actual_start': start, 'bytes': segment['file_bytes'],
                              'file_offset': segment['file_offset'], 'map_indices': covered})
    for row in rows:
        # Every page of this inode must be explainable by a file-backed LOAD.
        candidates = []
        for segment in layout['load_segments']:
            if not segment['file_bytes']:
                continue
            begin = bias + (segment['virtual_address'] & -layout['page_bytes'])
            finish = bias + ((segment['virtual_address'] + segment['file_bytes']
                              + layout['page_bytes'] - 1) & -layout['page_bytes'])
            mapped_offset = segment['file_offset'] & -layout['page_bytes']
            if (begin <= row['start'] < row['end'] <= finish
                    and row['file_offset'] == mapped_offset + row['start'] - begin):
                candidates.append(segment['program_index'])
        if not candidates:
            raise ValueError('an actual runtime file map has no matching load segment')
    for record in records:
        _cover_file_span(rows, bias + record['value'], record['bytes'], record['file_offset'], 5)
    return {'elf_type': layout['elf_type'], 'elf_type_name': layout['elf_type_name'],
            'page_bytes': layout['page_bytes'], 'lowest_load_page': layout['lowest_load_page'],
            'image_mapping_base': image_base, 'relocation_bias': bias,
            'load_segments': layout['load_segments'], 'mapped_file_segments': file_segments,
            'process_file_maps': rows,
            'physical_device': runtime['identity'][0], 'physical_inode': runtime['identity'][1]}


class DlInfo(ctypes.Structure):
    _fields_ = [('filename', ctypes.c_char_p), ('base', ctypes.c_void_p),
                ('symbol_name', ctypes.c_char_p), ('symbol_address', ctypes.c_void_p)]


def _live_symbols(raw, runtime, records, layout, required_mapping=None):
    dladdr = ctypes.CDLL(None).dladdr
    dladdr.argtypes = (ctypes.c_void_p, ctypes.POINTER(DlInfo))
    dladdr.restype = ctypes.c_int
    anchor = ctypes.cast(ctypes.pythonapi._PyEval_EvalFrameDefault, ctypes.c_void_p).value
    info = DlInfo()
    if not anchor or not dladdr(anchor, ctypes.byref(info)) or not info.base or not info.filename:
        raise ValueError('the running Python evaluator mapping is unavailable')
    actual_path = Path(os.fsdecode(info.filename)).resolve(strict=True)
    if str(actual_path) != runtime['path']:
        raise ValueError('runtime file does not identify the running interpreter')
    maps = _runtime_maps(runtime)
    mapping = _mapping_relation(layout, records, runtime, anchor, info.base, maps)
    if required_mapping is not None and mapping != required_mapping:
        raise ValueError('base and additional tables have different actual runtime mappings')
    words = [31214]
    for record in records:
        address = mapping['relocation_bias'] + record['value']
        for edge in (address, address + record['bytes'] - 1):
            observed = DlInfo()
            if (not dladdr(edge, ctypes.byref(observed)) or observed.base != info.base
                    or not observed.filename
                    or Path(os.fsdecode(observed.filename)).resolve(strict=True) != actual_path):
                raise ValueError('private function is outside the admitted runtime mapping')
        actual = ctypes.string_at(address, record['bytes'])
        expected = raw[record['file_offset']:record['file_offset'] + record['bytes']]
        if actual != expected:
            raise ValueError('mapped runtime function bytes differ from the frozen ELF')
        record['actual_address'] = address
        record['actual_sha256'] = sha256(actual).hexdigest()
        words.append(address)
    if _runtime_maps(runtime) != maps:
        raise ValueError('runtime file mappings changed during live-code admission')
    return tuple(words), mapping


def admit_runtime(path, *, sha256_pin, bytes_pin):
    """Return the original twelve-word table with distinct ELF address origins."""
    if sys.implementation.name != 'cpython' or tuple(sys.version_info[:3]) != (3, 12, 14):
        raise ValueError('this private runtime binding requires exact CPython 3.12.14')
    raw, before = read_runtime(path, sha256_pin, bytes_pin)
    records, layout = _symbol_records(raw, SYMBOLS)
    words, mapping = _live_symbols(raw, before, records, layout)
    vectorcall = ctypes.cast(ctypes.pythonapi._PyFunction_Vectorcall, ctypes.c_void_p).value
    if words[2] != vectorcall:
        raise ValueError('running Python function-call entry differs')
    after_raw, after = read_runtime(path, sha256_pin, bytes_pin)
    if after != before or after_raw != raw:
        raise ValueError('runtime changed during mapped-code admission')
    return words, {
        'schema': 'hia.cli-json.cpython312-runtime-binding.v1',
        'profile': 31214, 'runtime': before, 'runtime_after': after,
        'load_base': mapping['image_mapping_base'],
        'relocation_bias': mapping['relocation_bias'], 'mapping': mapping,
        'symbols': records, 'owned_call_executed': False, 'graph_qualified': False,
    }
