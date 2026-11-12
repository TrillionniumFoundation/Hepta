"""Exact mapped-ELF admission for experimental CPython 3.12 CALL ownership.

The four-component source result never executed this mechanism.  Private
runtime functions are resolved from the admitted libpython's actual symbol
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


def symbol_table(raw):
    def extent(offset, size):
        if offset < 0 or size < 0 or offset > len(raw) - size:
            raise ValueError('ELF span exceeds the frozen runtime')
        return raw[offset:offset + size]

    if len(raw) < HEADER.size:
        raise ValueError('ELF header is incomplete')
    fields = HEADER.unpack_from(raw)
    (ident, kind, machine, version, _entry, program_at, section_at, _flags,
     header_bytes, program_bytes, program_count, section_bytes,
     section_count, section_names) = fields
    if (ident[:7] != b'\x7fELF\x02\x01\x01' or kind != 3 or machine != 62
            or version != 1 or header_bytes != HEADER.size
            or program_bytes != PROGRAM.size or section_bytes != SECTION.size
            or not program_count or not section_count
            or section_names >= section_count):
        raise ValueError('runtime ELF profile differs')
    extent(program_at, program_count * PROGRAM.size)
    extent(section_at, section_count * SECTION.size)
    programs = [PROGRAM.unpack_from(raw, program_at + i * PROGRAM.size)
                for i in range(program_count)]
    sections = [SECTION.unpack_from(raw, section_at + i * SECTION.size)
                for i in range(section_count)]
    found = {name: set() for name in SYMBOLS}
    tables = 0
    for section in sections:
        _name, section_kind, _flags, _address, at, size, link, _info, _align, stride = section
        if section_kind != 2:  # SHT_SYMTAB, including hidden/local functions
            continue
        tables += 1
        if stride != SYMBOL.size or size % stride or link >= section_count:
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
            if (info & 15) != 2 or not index or index >= section_count or not symbol_size:
                raise ValueError('required runtime symbol is not a defined function')
            found[name].add((value, symbol_size, other, index))
    if not tables or any(len(rows) != 1 for rows in found.values()):
        raise ValueError('exact private runtime functions are unavailable or ambiguous')
    records = []
    for name in SYMBOLS:
        value, size, _visibility, section_index = next(iter(found[name]))
        matches = []
        for program in programs:
            p_kind, flags, file_at, address, _physical, file_size, _memory, _alignment = program
            if p_kind == 1 and (flags & 1) and value >= address:
                relative = value - address
                if relative <= file_size and size <= file_size - relative:
                    matches.append(file_at + relative)
        if len(matches) != 1:
            raise ValueError('runtime function has no unique executable file mapping')
        code = extent(matches[0], size)
        records.append({'name': name, 'value': value, 'bytes': size,
                        'file_offset': matches[0], 'section': section_index,
                        'sha256': sha256(code).hexdigest()})
    return records


class DlInfo(ctypes.Structure):
    _fields_ = [('filename', ctypes.c_char_p), ('base', ctypes.c_void_p),
                ('symbol_name', ctypes.c_char_p), ('symbol_address', ctypes.c_void_p)]


def admit_runtime(path, *, sha256_pin, bytes_pin):
    """Return the exact twelve-word table and physical/live input pins."""
    if sys.implementation.name != 'cpython' or tuple(sys.version_info[:3]) != (3, 12, 14):
        raise ValueError('this private runtime binding requires exact CPython 3.12.14')
    raw, before = read_runtime(path, sha256_pin, bytes_pin)
    records = symbol_table(raw)
    dladdr = ctypes.CDLL(None).dladdr
    dladdr.argtypes = (ctypes.c_void_p, ctypes.POINTER(DlInfo))
    dladdr.restype = ctypes.c_int
    anchor = ctypes.cast(ctypes.pythonapi._PyEval_EvalFrameDefault, ctypes.c_void_p).value
    info = DlInfo()
    if not anchor or not dladdr(anchor, ctypes.byref(info)) or not info.base or not info.filename:
        raise ValueError('the running Python evaluator mapping is unavailable')
    # Resolve the loader's reported pathname, then admit that exact physical
    # path against the independently supplied frozen input.  No search path.
    actual_path = Path(os.fsdecode(info.filename)).resolve(strict=True)
    if str(actual_path) != before['path'] or anchor != info.base + records[0]['value']:
        raise ValueError('runtime file does not identify the running interpreter')
    words = [31214]
    for record in records:
        address = info.base + record['value']
        observed = DlInfo()
        if (not dladdr(address, ctypes.byref(observed)) or observed.base != info.base
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
    vectorcall = ctypes.cast(ctypes.pythonapi._PyFunction_Vectorcall, ctypes.c_void_p).value
    if words[2] != vectorcall:
        raise ValueError('running Python function-call entry differs')
    after_raw, after = read_runtime(path, sha256_pin, bytes_pin)
    if after != before or after_raw != raw:
        raise ValueError('runtime changed during mapped-code admission')
    return tuple(words), {
        'schema': 'hia.cli-json.cpython312-runtime-binding.v1',
        'profile': 31214, 'runtime': before, 'runtime_after': after,
        'load_base': info.base, 'symbols': records,
        'owned_call_executed': False, 'graph_qualified': False,
    }
