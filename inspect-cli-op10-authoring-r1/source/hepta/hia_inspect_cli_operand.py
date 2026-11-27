"""Unexecuted private CPython import-operand capture proposal.

This records op35's actual second IMPORT_NAME result, not canonical authority.
There is no import of hepta or any business module in this file.
"""
from __future__ import annotations
import dis
import sys
from types import FunctionType

TYPE = type
BOUND_LOCALS = ('self', 'operation', 'a', 'b', 'c', 'd',
                'value', 'register', 'field', 'argument', 'zero')
FIRST_NAMES = ('verify_program',)
SECOND_NAMES = ('read_bounded', 'decode_json', 'inspect_program',
                'apply_program_patch', 'publish_program')
RESULT_NAMES = FIRST_NAMES + SECOND_NAMES

def _require(value, message):
    if not value:
        raise ValueError(message)

def _word(opname, value):
    _require(TYPE(value) is int and 0 <= value < 1 << 32, 'bounded bytecode operand required')
    chunks = [value & 255]
    value >>= 8
    while value:
        chunks.append(value & 255)
        value >>= 8
    result = bytearray()
    for byte in reversed(chunks[1:]):
        result.extend((dis.opmap['EXTENDED_ARG'], byte))
    result.extend((dis.opmap[opname], chunks[0]))
    return bytes(result)

def _level(row):
    return (row.opname in ('LOAD_CONST', 'LOAD_SMALL_INT')
            and TYPE(row.argval) is int and row.argval == 1)

def _fromlist(row, names):
    return (row.opname == 'LOAD_CONST' and TYPE(row.argval) is tuple
            and len(row.argval) == len(names)
            and all(TYPE(a) is str and a == b for a, b in zip(row.argval, names)))

def _sequence(instructions, start, module, names):
    needed = 4 + 2 * len(names)
    if start + needed > len(instructions):
        return None
    rows = instructions[start:start + needed]
    if not (_level(rows[0]) and _fromlist(rows[1], names)
            and rows[2].opname == 'IMPORT_NAME' and rows[2].argval == module
            and rows[-1].opname == 'POP_TOP'):
        return None
    for index, name in enumerate(names):
        imported, stored = rows[3 + 2 * index:5 + 2 * index]
        if not (imported.opname == 'IMPORT_FROM' and imported.argval == name
                and stored.opname == 'STORE_FAST' and stored.argval == name):
            return None
    return start + needed - 1

class Import35Port:
    """Opcode slice with original globals, builtins, constants and local slots.

    Construction does not execute imports. Calling entry executes exactly the
    two imports. The additional private frame and delayed second-module POP
    are explicit limitations, not proved reference-count/traceback equivalence.
    """
    __slots__ = ('effect', 'effect_code', 'entry', 'entry_code', 'source_slice', 'slice_offsets')

    def __init__(self, effect):
        _require(sys.implementation.name == 'cpython' and sys.version_info[:3] == (3, 14, 4),
                 'new import port is restricted to the actual 3.14.4 ABI')
        _require(TYPE(effect) is FunctionType, 'captured effect must be an exact function')
        code = effect.__code__
        _require(code.co_argcount == 6 and code.co_posonlyargcount == code.co_kwonlyargcount == 0
                 and code.co_varnames[:11] == BOUND_LOCALS
                 and not code.co_freevars and not code.co_cellvars
                 and not code.co_exceptiontable and not code.co_flags & (0x04 | 0x08 | 0x20 | 0x80 | 0x200),
                 'original effect frame shape differs')
        instructions = tuple(dis.get_instructions(code, show_caches=True, adaptive=False))
        meaningful = tuple(row for row in instructions if row.opname not in ('CACHE', 'EXTENDED_ARG'))
        matches = []
        for index in range(len(meaningful)):
            first = _sequence(meaningful, index, 'hia_program', FIRST_NAMES)
            if first is None:
                continue
            last = _sequence(meaningful, first + 1, 'hia_program_tools', SECOND_NAMES)
            if last is not None:
                matches.append((index, first, last))
        _require(len(matches) == 1, 'exact two-from-import slice is not unique')
        begin, first, last = matches[0]
        first_byte = meaningful[begin].offset
        while first_byte >= 2 and code.co_code[first_byte - 2] == dis.opmap['EXTENDED_ARG']:
            first_byte -= 2
        last_byte = meaningful[last].offset
        source_slice = code.co_code[first_byte:last_byte + 2]
        _require(code.co_code[last_byte:last_byte + 2] == bytes((dis.opmap['POP_TOP'], 0)),
                 'original second module release differs')
        _require(not any(row.opname == 'CACHE' for row in instructions
                         if first_byte <= row.offset <= last_byte), 'import slice contains unexpected caches')
        operand_slot = len(code.co_varnames)
        raw = (bytes((dis.opmap['RESUME'], 0)) + source_slice[:-2]
               + _word('STORE_FAST', operand_slot))
        for name in RESULT_NAMES:
            raw += _word('LOAD_FAST', code.co_varnames.index(name))
        raw += _word('LOAD_FAST', operand_slot) + _word('BUILD_TUPLE', 7) + _word('RETURN_VALUE', 0)
        projected = code.replace(co_code=raw, co_argcount=11,
            co_nlocals=operand_slot + 1, co_varnames=code.co_varnames + ('_inspect_import_operand',),
            co_stacksize=max(code.co_stacksize, 7), co_exceptiontable=b'', co_linetable=b'',
            co_filename=__file__, co_name='_inspect_import35_operand_port',
            co_qualname='_inspect_import35_operand_port', co_firstlineno=1)
        entry = FunctionType(projected, effect.__globals__)
        _require(entry.__globals__ is effect.__globals__ and entry.__builtins__ is effect.__builtins__,
                 'port globals/builtins do not retain the original identities')
        self.effect, self.effect_code = effect, code
        self.entry, self.entry_code = entry, projected
        self.source_slice, self.slice_offsets = source_slice, (first_byte, last_byte + 2)

    def current(self):
        return (self.effect.__code__ is self.effect_code
                and self.entry.__code__ is self.entry_code
                and self.entry.__globals__ is self.effect.__globals__
                and self.entry.__builtins__ is self.effect.__builtins__)
