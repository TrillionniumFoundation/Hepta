"""Native qualified-name and declaration-parameter grammar with value bridging.

HIA decides grammar and exact token consumption. This module validates the
returned arena and constructs Python strings/tuples/dictionaries and diagnostics.
"""
from __future__ import annotations
import ctypes
from pathlib import Path
import struct
from .ast import Diagnostic, HeptaError, Span
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_source_lexer_native import ERRORS, installed_source_lexer

SOURCE = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/source_names.hiaasm'
SCHEMA = 'hepta.hia.source-names-native.v1'
MAGIC = 5208780291693556274
MAX_BYTES = 8 << 20
MAX_ROWS = 1 << 20
WORKSPACE = 320


def materialize(raw: bytes, wire: bytes, mode: int):
    if type(raw) is not bytes or len(raw) < 64:
        raise ValueError('invalid HIA name arena')
    magic, count, used, chars, consumed, selected, version, reserved = struct.unpack_from('<8Q', raw)
    if (magic != MAGIC or selected != mode or mode not in (1, 2, 3) or version != 1 or reserved
            or count > MAX_ROWS or used != len(raw) or used != 64 + count * 64
            or not 0 <= chars <= consumed <= len(wire)
            or (mode == 1 and (not count or not consumed))):
        raise ValueError('invalid HIA name arena header')
    if len(wire[:consumed].decode('utf-8')) != chars:
        raise ValueError('invalid HIA name character cursor')
    names, lifetimes, bounds = [], [], {}
    last = 0
    for index in range(count):
        role, begin, end, bb, be, r0, r1, r2 = struct.unpack_from('<8Q', raw, 64 + index * 64)
        if (r0 or r1 or r2 or role not in ({1} if mode == 1 else {2} if mode == 2 else {2, 3})
                or not last <= begin < end <= consumed
                or (bool(bb) != bool(be)) or (bb and not end < bb < be <= consumed)
                or ((mode != 3 or role != 2) and (bb or be))):
            raise ValueError('invalid HIA name row')
        name = wire[begin:end].decode('ascii')
        if not name.isidentifier():
            raise ValueError('invalid HIA name bytes')
        last = be or end
        if role == 3:
            lifetimes.append(name)
        else:
            names.append(name)
            if mode == 3:
                bound = wire[bb:be].decode('ascii') if bb else 'Copy'
                if not bound.isidentifier():
                    raise ValueError('invalid HIA bound bytes')
                bounds[name] = bound
    value = '::'.join(names) if mode == 1 else tuple(names) if mode == 2 else (tuple(names), bounds, tuple(lifetimes))
    return value, chars


class NativeSourceNames(NativeHiaJsonImage):
    def run(self, wire: bytes, mode: int):
        if type(wire) is not bytes or len(wire) > MAX_BYTES or type(mode) is not int or mode not in (1, 2, 3):
            raise ValueError('outside native HIA source names profile')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        state = ctypes.create_string_buffer(WORKSPACE)
        struct.pack_into('<Q', state, 224, mode)
        capacity = 4096
        output = ctypes.create_string_buffer(capacity)
        result = self._entry(source, len(wire), output, capacity, state, WORKSPACE)
        if result == 0xfffffffe:
            count = struct.unpack_from('<Q', state, 200)[0]
            if not 0 <= count <= MAX_ROWS:
                raise RuntimeError('invalid HIA name capacity request')
            capacity = 64 + count * 64
            output = ctypes.create_string_buffer(capacity)
            result = self._entry(source, len(wire), output, capacity, state, WORKSPACE)
        if result == 0xffffffff:
            return None, state.raw
        if not 64 <= result <= capacity:
            raise RuntimeError('HIA name parser rejected declared buffers')
        return output.raw[:result], state.raw


def installed_source_names(path: str):
    image = _installed_json_image(path, SOURCE, SCHEMA, NativeSourceNames)
    lexer = installed_source_lexer(str(Path(path).resolve(strict=True).parent / 'source-lexer/manifest.json'))
    return image, lexer


def parse_names(parser, native, mode: int):
    from .lexer import Token
    origin = parser.current.span
    source = parser.source[origin.start:]
    wire = source.encode('utf-8')
    raw, state = native.run(wire, mode)
    consumed = struct.unpack_from('<Q', state, 184)[0]
    if consumed > len(source):
        raise RuntimeError('invalid HIA name cursor')
    boundary = origin.start + consumed
    while parser.current.kind != 'EOF' and parser.current.span.start < boundary:
        token = parser.current
        if token.kind in ('>>', '>='):
            p = token.span
            parser.tokens[parser.position:parser.position + 1] = [
                Token('>', '>', Span(p.start, p.start + 1, p.line, p.column, p.path)),
                Token(token.kind[1], token.kind[1], Span(p.start + 1, p.end, p.line, p.column + 1, p.path))]
            token = parser.current
        if token.span.end > boundary:
            raise RuntimeError('HIA name cursor splits a token')
        parser.position += 1
    if raw is not None:
        value, chars = materialize(raw, wire, mode)
        if chars != consumed:
            raise RuntimeError('HIA name value and token cursors disagree')
        return value
    lex = struct.unpack_from('<Q', state, 48)[0]
    if lex:
        start, line, column = struct.unpack_from('<3Q', state, 64)
        end = struct.unpack_from('<Q', state, 112)[0]
        if lex == 10 and start < len(source):
            tag, message = 'E_LEX_CHARACTER', f'Unsupported character {source[start]!r}'
        elif lex in ERRORS:
            tag, message = ERRORS[lex]
        else:
            raise RuntimeError('invalid HIA name scanner diagnostic')
        phase = 'lex'
    else:
        start, end, line, column = struct.unpack_from('<4Q', state, 152)
        code = struct.unpack_from('<Q', state, 216)[0]
        messages = {1: 'Expected a name', 2: "Expected a name after '::'",
                    3: 'Expected a generic parameter', 4: 'Expected a type or lifetime parameter',
                    5: 'Expected Copy or Owned constraint', 6: "Expected '>' after a generic element type"}
        if code == 7:
            raise OverflowError('HIA name arena exceeds 1M rows')
        if code not in messages:
            raise RuntimeError('invalid HIA name parser diagnostic')
        tag, message, phase = 'E_PARSE', messages[code], 'parse'
    if not 0 <= start <= end <= len(source) or line < 1 or column < 1:
        raise RuntimeError('invalid HIA name diagnostic span')
    raise HeptaError(Diagnostic(tag, message, Span(origin.start + start, origin.start + end,
        origin.line + line - 1, column + (origin.column - 1 if line == 1 else 0), origin.path), phase=phase))
