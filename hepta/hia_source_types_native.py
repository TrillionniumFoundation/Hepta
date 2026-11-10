"""Operator-selected HIA source type grammar, with a validated AST value bridge.

Type recognition and bounded parsing frames execute in HIA. Python retains
Token/Span/Type allocation and orchestration. Declarations, expressions, name
resolution and the rest of the frontend are not rewritten by this application.
The image is trusted local executable code, not an untrusted-code sandbox.
"""
from __future__ import annotations
import ctypes
from pathlib import Path
import struct
from .ast import Diagnostic, HeptaError, Span, Type
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_source_lexer_native import ERRORS, installed_source_lexer

SOURCE = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/source_types.hiaasm'
SCHEMA = 'hepta.hia.source-types-native.v1'
MAGIC = 5208780291693556273
NONE = (1 << 64) - 1
WORKSPACE = 8512
MAX_BYTES = 8 << 20
MAX_NODES = 1 << 20


def materialize(raw: bytes, wire: bytes, integer_value, *, max_depth: int = 128):
    """Validate every arena edge/range before publishing an immutable Type tree.

    This bridge does not tokenize, recognize type syntax or parse integer
    literals: integer_value must be the selected HIA lexer magnitude decoder.
    """
    if type(raw) is not bytes or len(raw) < 64:
        raise ValueError('invalid HIA type arena')
    magic, count, base, used, chars, consumed, version, root = struct.unpack_from('<8Q', raw)
    if (magic != MAGIC or version != 1 or not 1 <= count <= MAX_NODES
            or base != 64 + count * 80 or not base <= used == len(raw)
            or root != 0 or not 0 < consumed <= len(wire)
            or not 0 < chars <= consumed or not 1 <= max_depth <= 128):
        raise ValueError('invalid HIA type arena header')
    try:
        if len(wire[:consumed].decode('utf-8')) != chars:
            raise ValueError('invalid HIA type consumed character count')
    except UnicodeDecodeError as error:
        raise ValueError('invalid HIA type consumed UTF-8') from error
    rows = [struct.unpack_from('<10Q', raw, 64 + i * 80) for i in range(count)]
    children = [[] for _ in rows]
    depths = [0] * count
    depths[0] = 1
    seen = {0}
    payload_ranges = []
    for i, row in enumerate(rows):
        kind, parent, first, last, sibling, start, size, begin, length, reserved = row
        if (not 1 <= kind <= 8 or reserved != 0 or depths[i] == 0
                or depths[i] > max_depth + (kind == 8)
                or (i == 0 and (parent != NONE or sibling != NONE))):
            raise ValueError('invalid HIA type node ownership')
        if kind in (1, 8):
            if not 0 < size or not start <= start + size <= used - base or begin or length:
                raise ValueError('invalid HIA type name range')
            payload_ranges.append((start, start + size))
        elif start or size:
            raise ValueError('unexpected HIA type name')
        if kind == 3:
            if not 0 < length or not begin < begin + length <= consumed:
                raise ValueError('invalid HIA array literal range')
        elif begin or length:
            raise ValueError('unexpected HIA array literal')
        cursor = first
        while cursor != NONE:
            if (not i < cursor < count or cursor in seen or rows[cursor][1] != i):
                raise ValueError('invalid HIA type arena edge')
            seen.add(cursor)
            children[i].append(cursor)
            depths[cursor] = depths[i] + (rows[cursor][0] != 8)
            cursor = rows[cursor][4]
        if last != (children[i][-1] if children[i] else NONE):
            raise ValueError('invalid HIA type last child')
    if len(seen) != count:
        raise ValueError('orphan HIA type nodes')
    cursor = 0
    for begin, end in sorted(payload_ranges):
        if begin != cursor:
            raise ValueError('overlapping or unowned HIA type name payload')
        cursor = end
    if cursor != used - base:
        raise ValueError('unowned HIA type payload')
    values = [None] * count
    names = {2: 'slice', 3: 'array', 4: 'ref_read', 5: 'ref_mut', 6: 'raw_const', 7: 'raw_mut'}
    for i in range(count - 1, -1, -1):
        kind, _, _, _, _, start, size, begin, length, _ = rows[i]
        if kind in (1, 8):
            try: name = raw[base + start:base + start + size].decode('ascii')
            except UnicodeDecodeError as error: raise ValueError('invalid HIA type identifier') from error
            if not name or any(not part.isidentifier() for part in name.split('::')) or (kind == 8 and '::' in name):
                raise ValueError('invalid HIA type identifier')
        else: name = names[kind]
        type_children = [values[c] for c in children[i] if rows[c][0] != 8]
        lifetimes = [values[c] for c in children[i] if rows[c][0] == 8]
        if kind == 8:
            if children[i]: raise ValueError('HIA lifetime has children')
            values[i] = name
            continue
        if kind in (2, 3, 6, 7) and (len(type_children) != 1 or lifetimes):
            raise ValueError('invalid HIA unary type children')
        if kind in (4, 5) and (len(type_children) != 1 or len(lifetimes) != 1
                               or rows[children[i][0]][0] != 8):
            raise ValueError('invalid HIA stored reference children')
        value = integer_value(wire[begin:begin + length]) if kind == 3 else None
        if kind == 3 and (type(value) is not int or value < 0):
            raise ValueError('invalid HIA array magnitude')
        values[i] = Type(name, tuple(type_children), value, tuple(lifetimes))
    if not isinstance(values[0], Type): raise ValueError('HIA type root is not a type')
    return values[0], chars, consumed


class NativeSourceTypes(NativeHiaJsonImage):
    def run(self, wire: bytes, *, max_depth: int):
        if (type(wire) is not bytes or len(wire) > MAX_BYTES
                or type(max_depth) is not int or not 1 <= max_depth <= 128):
            raise ValueError('outside native HIA source type profile')
        capacity = 64 + min(len(wire) + 1, MAX_NODES) * 80 + len(wire)
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(capacity)
        state = ctypes.create_string_buffer(WORKSPACE)
        struct.pack_into('<Q', state, 224, max_depth)
        result = self._entry(source, len(wire), output, capacity, state, WORKSPACE)
        if result == 0xffffffff:
            return None, state.raw
        if not 64 <= result <= capacity:
            raise RuntimeError('HIA type parser rejected declared buffers')
        return output.raw[:result], state.raw


def _diagnostic(state, wire, source, origin, nesting_limit, current_kind):
    lex = struct.unpack_from('<Q', state, 48)[0]
    code = struct.unpack_from('<Q', state, 216)[0]
    if lex:
        start, line, column = struct.unpack_from('<3Q', state, 64)
        end = struct.unpack_from('<Q', state, 112)[0]
        if lex == 10:
            if not start < len(source): raise RuntimeError('invalid HIA lexer error character')
            tag, message = 'E_LEX_CHARACTER', f'Unsupported character {source[start]!r}'
        elif lex in ERRORS: tag, message = ERRORS[lex]
        else: raise RuntimeError('invalid HIA type scanner diagnostic')
        phase = 'lex'
    else:
        start, end, line, column = struct.unpack_from('<4Q', state, 152)
        tag = 'E_PARSE_DEPTH' if code == 1 else 'E_PARSE'
        messages = {1: f'Syntax exceeds the bootstrap nesting limit of {nesting_limit}',
            2: "Stored references require an explicit lifetime: read 'a T",
            3: 'Array lengths must be nonnegative integer literals',
            4: f"Expected ']', found {current_kind!r}", 5: "A raw pointer type requires 'const' or 'mut'",
            6: 'Expected a name', 7: "Expected a name after '::'",
            8: "Expected '>' after a generic element type"}
        if code == 9:
            begin, finish = struct.unpack_from('<2Q', state, 280)
            if not begin < finish <= len(wire): raise RuntimeError('invalid HIA builtin arity name')
            name = wire[begin:finish].decode('ascii')
            if name not in ('Buffer', 'Task', 'Sender'): raise RuntimeError('invalid HIA builtin arity name')
            message = f'{name} requires exactly one element type: {name}<T>'
        elif code in messages: message = messages[code]
        elif code == 10: raise OverflowError('HIA source type exceeds 1M-node profile')
        else: raise RuntimeError('invalid HIA type parser diagnostic')
        phase = 'parse'
    if not 0 <= start <= end <= len(source) or line < 1 or column < 1:
        raise RuntimeError('invalid HIA type diagnostic span')
    return HeptaError(Diagnostic(tag, message,
        Span(origin.start + start, origin.start + end, origin.line + line - 1,
             column + (origin.column - 1 if line == 1 else 0), origin.path), phase=phase))


def installed_source_types(path: str):
    image = _installed_json_image(path, SOURCE, SCHEMA, NativeSourceTypes)
    lexer = installed_source_lexer(str(Path(path).resolve(strict=True).parent / 'source-lexer/manifest.json'))
    return image, lexer


def parse_type(parser, native, lexer, max_depth, nesting_limit):
    """Translate positions and values, never host-recognize the type grammar."""
    from .lexer import Token
    origin = parser.current.span
    source = parser.source[origin.start:]
    wire = source.encode('utf-8')
    raw, state = native.run(wire, max_depth=max_depth)
    consumed = struct.unpack_from('<Q', state, 184)[0]
    if not 0 <= consumed <= len(source): raise RuntimeError('invalid HIA type cursor')
    boundary = origin.start + consumed
    # A consumed half of >> or >= is explicitly reported by HIA. Preserve both
    # split tokens (including exact spans) just as _type_close does, so every
    # declaration/expression caller sees the same previous/current tokens.
    while parser.current.kind != 'EOF' and parser.current.span.start < boundary:
        token = parser.current
        if token.kind in ('>>', '>='):
            p = token.span
            parser.tokens[parser.position:parser.position + 1] = [
                Token('>', '>', Span(p.start, p.start + 1, p.line, p.column, p.path)),
                Token(token.kind[1], token.kind[1], Span(p.start + 1, p.end, p.line, p.column + 1, p.path))]
            token = parser.current
        if token.span.end > boundary: raise RuntimeError('HIA type cursor splits a non-operator token')
        parser.position += 1
    if raw is None: raise _diagnostic(state, wire, source, origin, nesting_limit, parser.current.kind)
    value, characters, _ = materialize(raw, wire, lexer.integer_value, max_depth=max_depth)
    if characters != consumed: raise RuntimeError('HIA type cursor disagrees with arena')
    return value
