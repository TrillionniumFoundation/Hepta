"""Selected HIA effects/resources grammar and a validated value-only bridge.

The native image makes all clause grammar and duplicate-name decisions. Its
separate measurement command publishes no arena; full admission checks names
before any output write. Python retains allocation, diagnostics, dictionary/set
construction and the surrounding declarations/statements/expression parser.
"""
from __future__ import annotations

import ctypes
import math
from pathlib import Path
import struct

from .ast import Diagnostic, HeptaError, Span
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_source_lexer_native import ERRORS, installed_source_lexer

SOURCE = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/source_clauses.hiaasm'
SCHEMA = 'hepta.hia.source-clauses-native.v1'
MAGIC = 5208780291424916339
WORKSPACE_HEADER = 384
MAX_BYTES = 8 << 20
MAX_ENTRIES = 1 << 20


def materialize(raw: bytes, wire: bytes, lexer, *, mode: int):
    """Validate ranges and construct values without parsing host source grammar."""
    if (type(raw) is not bytes or len(raw) < 64 or type(wire) is not bytes
            or type(mode) is not int):
        raise ValueError('invalid HIA clause arena')
    magic, version, actual_mode, count, used, chars, consumed, reserved = struct.unpack_from('<8Q', raw)
    if (magic != MAGIC or version != 1 or mode not in (1, 2) or actual_mode != mode
            or count > MAX_ENTRIES or used != 64 + count * 40 or used != len(raw)
            or not 0 < consumed <= len(wire) or not 0 < chars <= consumed or reserved):
        raise ValueError('invalid HIA clause arena header')
    try:
        if len(wire[:consumed].decode('utf-8')) != chars:
            raise ValueError('invalid HIA clause consumed character count')
    except UnicodeDecodeError as error:
        raise ValueError('invalid HIA clause consumed UTF-8') from error
    values = {}
    prior_end = 0
    for i in range(count):
        begin, end, kind, value_begin, value_end = struct.unpack_from('<5Q', raw, 64 + i * 40)
        if not prior_end <= begin < end <= consumed:
            raise ValueError('invalid HIA clause name range')
        try:
            name = wire[begin:end].decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('invalid HIA clause name') from error
        if not name.isidentifier() or name in values:
            raise ValueError('invalid or duplicate HIA clause name')
        if mode == 1:
            if kind or value_begin or value_end:
                raise ValueError('unexpected HIA effect value')
            value = None
            prior_end = end
        else:
            if not end <= value_begin < value_end <= consumed:
                raise ValueError('invalid HIA resource value range')
            literal = wire[value_begin:value_end]
            if kind == 1:
                value = lexer.integer_value(literal)
                if type(value) is not int or value < 0:
                    raise ValueError('invalid HIA resource integer magnitude')
            elif kind == 2:
                value = lexer.float_value(literal)
                if type(value) is not float or not math.isfinite(value):
                    raise ValueError('invalid HIA resource finite binary64 value')
            elif kind in (3, 4):
                if literal != (b'false' if kind == 3 else b'true'):
                    raise ValueError('invalid HIA resource boolean value')
                value = kind == 4
            else:
                raise ValueError('invalid HIA resource literal kind')
            prior_end = value_end
        values[name] = value
    return (set(values) if mode == 1 else values), chars, consumed


def workspace_size(entries: int) -> int:
    if type(entries) is not int or not 0 <= entries <= MAX_ENTRIES:
        raise ValueError('outside HIA clause entry profile')
    slots = 2
    while slots < entries * 2:
        slots *= 2
    return WORKSPACE_HEADER + slots * 16


class NativeSourceClauses(NativeHiaJsonImage):
    def run(self, wire: bytes, *, mode: int):
        if (type(wire) is not bytes or len(wire) > MAX_BYTES
                or type(mode) is not int or mode not in (1, 2)):
            raise ValueError('outside native HIA source clause profile')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        state = ctypes.create_string_buffer(WORKSPACE_HEADER)
        struct.pack_into('<Q', state, 208, mode)
        output = ctypes.create_string_buffer(1)
        required = self._entry(source, len(wire), output, 0, state, WORKSPACE_HEADER)
        measurement_failed = required == 0xffffffff
        count = struct.unpack_from('<Q', state, 200)[0]
        if count > MAX_ENTRIES or (not measurement_failed and required != 64 + count * 40):
            raise RuntimeError('invalid HIA clause measurement')
        # Measurement deliberately does not admit names. A later syntax error
        # must not mask an earlier duplicate, so even a failed measurement is
        # replayed through the native uniqueness check before exposing an error.
        # One incomplete resource key may precede the unrecorded failing value.
        state_size = workspace_size(min(MAX_ENTRIES, count + int(measurement_failed)))
        required = 64 + count * 40
        state = ctypes.create_string_buffer(state_size)
        struct.pack_into('<Q', state, 208, mode)
        struct.pack_into('<Q', state, 224, 1)
        output = ctypes.create_string_buffer(required)
        result = self._entry(source, len(wire), output, required, state, state_size)
        if result == 0xffffffff:
            return None, state.raw[:WORKSPACE_HEADER]
        if result != required or measurement_failed:
            raise RuntimeError('HIA clause parser rejected declared buffers')
        return output.raw, state.raw[:WORKSPACE_HEADER]


def _diagnostic(state, wire, source, origin, current_kind):
    lex = struct.unpack_from('<Q', state, 48)[0]
    code = struct.unpack_from('<Q', state, 216)[0]
    if lex:
        start, line, column = struct.unpack_from('<3Q', state, 64)
        end = struct.unpack_from('<Q', state, 112)[0]
        if lex == 10:
            if not start < len(source):
                raise RuntimeError('invalid HIA clause lexer character')
            tag, message = 'E_LEX_CHARACTER', f'Unsupported character {source[start]!r}'
        elif lex in ERRORS:
            tag, message = ERRORS[lex]
        else:
            raise RuntimeError('invalid HIA clause scanner diagnostic')
        phase = 'lex'
    else:
        start, end, line, column, begin, finish = struct.unpack_from('<6Q', state, 304)
        messages = {
            1: 'Every function requires an explicit effects clause',
            2: f"Expected '{{', found {current_kind!r}",
            3: 'Expected an effect name',
            5: "Expected ',' or '}' after an effect",
            6: f"Expected 'resources', found {current_kind!r}",
            7: 'Expected a resource constraint name',
            9: f"Expected '=', found {current_kind!r}",
            10: 'Resource constraints require an integer, float, or boolean literal',
            11: "A resource constraint must end with ';'",
            12: f"Expected '}}', found {current_kind!r}",
        }
        tag = 'E_PARSE_DUPLICATE' if code in (4, 8) else 'E_PARSE'
        if code in (4, 8):
            if not begin < finish <= len(wire):
                raise RuntimeError('invalid HIA duplicate clause name range')
            name = wire[begin:finish].decode('ascii')
            if not name.isidentifier():
                raise RuntimeError('invalid HIA duplicate clause name')
            message = (f'Duplicate effect {name!r}' if code == 4
                       else f'Duplicate resource constraint {name!r}')
        elif code == 13:
            raise RuntimeError('HIA clause key table rejected declared capacity')
        elif code == 14:
            raise OverflowError('HIA source clauses exceed 1M-entry profile')
        elif code in messages:
            message = messages[code]
        else:
            raise RuntimeError('invalid HIA clause parser diagnostic')
        phase = 'parse'
    if not 0 <= start <= end <= len(source) or line < 1 or column < 1:
        raise RuntimeError('invalid HIA clause diagnostic span')
    return HeptaError(Diagnostic(tag, message,
        Span(origin.start + start, origin.start + end, origin.line + line - 1,
             column + (origin.column - 1 if line == 1 else 0), origin.path), phase=phase))


def installed_source_clauses(path: str):
    image = _installed_json_image(path, SOURCE, SCHEMA, NativeSourceClauses)
    lexer = installed_source_lexer(str(Path(path).resolve(strict=True).parent / 'source-lexer/manifest.json'))
    return image, lexer


def parse_clause(parser, native, lexer, mode: int):
    """Consume an actual Parser clause using only native grammar decisions."""
    origin = parser.current.span
    source = parser.source[origin.start:]
    wire = source.encode('utf-8')
    raw, state = native.run(wire, mode=mode)
    consumed = struct.unpack_from('<Q', state, 184)[0]
    if not 0 <= consumed <= len(source):
        raise RuntimeError('invalid HIA clause cursor')
    boundary = origin.start + consumed
    while parser.current.kind != 'EOF' and parser.current.span.start < boundary:
        if parser.current.span.end > boundary:
            raise RuntimeError('HIA clause cursor splits a token')
        parser.position += 1
    if raw is None:
        raise _diagnostic(state, wire, source, origin, parser.current.kind)
    value, characters, _ = materialize(raw, wire, lexer, mode=mode)
    if characters != consumed:
        raise RuntimeError('HIA clause cursor disagrees with arena')
    return value
