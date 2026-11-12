"""Mapped-ELF admission of the additional exact-3.12 evaluator helpers.

Source-only WIP. It neither loads a CLI HIA image nor calls a generator body.
The original twelve-function admission remains intact. This independent
five-function table is bound to the same physical and loaded CPython image, with
full symbol spans and live instruction-byte comparisons. No address may be
inferred from another runtime or replaced by a Python callback.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import os
from pathlib import Path
import sys

from hepta.hia_cli_json_runtime312 import (
    HEADER, PROGRAM, SECTION, SYMBOL, DlInfo, admit_runtime, read_runtime,
)

CONTROL_SYMBOLS = (
    '_PyEval_EvalFrameDefault', '_Py_Instrument',
    '_Py_call_instrumentation_arg', '_Py_HandlePending', '_PyErr_ChainStackItem',
)


def control_symbol_table(raw):
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
    found = {name: set() for name in CONTROL_SYMBOLS}
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
    for name in CONTROL_SYMBOLS:
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


def admit_runtime_control(path, *, sha256_pin, bytes_pin):
    """Admit the unchanged base table and five additional live functions.

    No new C leaf is called here. The returned six words are a separate
    input to ``hia_cli_json_bind_runtime_312_control`` only after the leaf
    library itself has been independently admitted by its complete bytes.
    """
    if sys.implementation.name != 'cpython' or tuple(sys.version_info[:3]) != (3, 12, 14):
        raise ValueError('the additional private table requires exact CPython 3.12.14')
    base_words, base_binding = admit_runtime(path, sha256_pin=sha256_pin, bytes_pin=bytes_pin)
    raw, before = read_runtime(path, sha256_pin, bytes_pin)
    if before != base_binding['runtime'] or before != base_binding['runtime_after']:
        raise ValueError('base and additional tables do not share one unchanged runtime')
    records = control_symbol_table(raw)
    dladdr = ctypes.CDLL(None).dladdr
    dladdr.argtypes = (ctypes.c_void_p, ctypes.POINTER(DlInfo))
    dladdr.restype = ctypes.c_int
    anchor = ctypes.cast(ctypes.pythonapi._PyEval_EvalFrameDefault, ctypes.c_void_p).value
    info = DlInfo()
    if (not anchor or anchor != base_words[1] or not dladdr(anchor, ctypes.byref(info))
            or not info.base or not info.filename or info.base != base_binding['load_base']):
        raise ValueError('the additional table has a different live evaluator mapping')
    actual_path = Path(os.fsdecode(info.filename)).resolve(strict=True)
    if str(actual_path) != before['path'] or anchor != info.base + records[0]['value']:
        raise ValueError('the additional symbols do not identify the admitted interpreter')
    words = [31214]
    for record in records:
        address = info.base + record['value']
        observed = DlInfo()
        if (not dladdr(address, ctypes.byref(observed)) or observed.base != info.base
                or not observed.filename
                or Path(os.fsdecode(observed.filename)).resolve(strict=True) != actual_path):
            raise ValueError('additional private function lies outside the admitted mapping')
        actual = ctypes.string_at(address, record['bytes'])
        expected = raw[record['file_offset']:record['file_offset'] + record['bytes']]
        if actual != expected:
            raise ValueError('additional mapped function bytes differ from the frozen ELF')
        record['actual_address'] = address
        record['actual_sha256'] = sha256(actual).hexdigest()
        words.append(address)
    after_raw, after = read_runtime(path, sha256_pin, bytes_pin)
    if after != before or after_raw != raw:
        raise ValueError('the additional runtime changed during its actual-byte admission')
    return tuple(words), {
        'schema': 'hia.cli-json.cpython312-control-runtime-binding.v1',
        'profile': 31214,
        'runtime': before,
        'runtime_after': after,
        'load_base': info.base,
        'symbols': records,
        'base_words': base_words,
        'base_binding': base_binding,
        'activation_executed': False,
        'body_driver_qualified': False,
        'original17_executed': False,
        'original46_executed': False,
    }

