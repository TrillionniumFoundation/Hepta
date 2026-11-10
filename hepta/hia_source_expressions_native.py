"""Explicitly selected HIA Pratt grammar and a checked AST-construction bridge.

HIA recognizes every existing expression production with explicit frames. The
bridge only constructs shared Expr/Type/Span objects from native decisions.
Declarations, statements, semantic checking and production activation remain
outside this component. Images are trusted executable code, not a sandbox.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass, field
from pathlib import Path
import struct
from .ast import Diagnostic, Expr, HeptaError, Span, Type
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_source_types_native import installed_source_types, materialize as materialize_type, _diagnostic as type_diagnostic
from .hia_source_lexer_native import KEYWORD_ORDER, PAIR_ORDER

SOURCE = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/source_expressions.hiaasm'
SCHEMA = 'hepta.hia.source-expressions-native.v1'
MAGIC = 0x3152505845414948
WORKSPACE = 29184
MAX_BYTES = 8 << 20
MAX_EVENTS = 2 << 20
RECORD_BYTES = 96


def token_kind(code):
    if code in (0, 1, 2, 3, 4, 5):
        return ('EOF', 'IDENT', 'LIFETIME', 'INT', 'FLOAT', 'STRING')[code]
    if 128 <= code < 128 + len(KEYWORD_ORDER): return KEYWORD_ORDER[code - 128]
    if 512 <= code < 512 + len(PAIR_ORDER): return PAIR_ORDER[code - 512]
    if 256 <= code < 384 and chr(code - 256) in '{}()[],:;=+-*/%!<>.&|^':
        return chr(code - 256)
    raise ValueError('invalid HIA expression token code')


@dataclass
class _Name:
    parts: list[str]
    types: list[Type] = field(default_factory=list)


@dataclass
class _Field:
    name: str
    value: Expr


def materialize(raw: bytes, wire: bytes, native_types, lexer, *, origin: Span = Span()):
    """Validate and execute a postfix object-construction arena, without grammar."""
    if type(raw) is not bytes or type(wire) is not bytes or len(raw) < 64:
        raise ValueError('invalid HIA expression arena')
    magic, count, used, chars, consumed, version, root_kind, reserved = struct.unpack_from('<8Q', raw)
    if (magic != MAGIC or version != 1 or reserved or not 1 <= count <= MAX_EVENTS
            or used != 64 + count * RECORD_BYTES or used != len(raw)
            or not 0 < consumed <= len(wire) or not 0 < chars <= consumed):
        raise ValueError('invalid HIA expression arena header')
    try:
        if len(wire[:consumed].decode('utf-8')) != chars:
            raise ValueError('invalid HIA expression consumed character count')
    except UnicodeDecodeError as error:
        raise ValueError('invalid HIA expression UTF-8') from error
    source_char_count = len(wire.decode('utf-8'))
    stack = []
    qualified = []
    splits = []
    seen_splits = set()

    def pop(count, cls=Expr):
        if count > len(stack): raise ValueError('HIA expression stack underflow')
        result = stack[len(stack) - count:] if count else []
        if any(not isinstance(item, cls) for item in result):
            raise ValueError('HIA expression stack kind mismatch')
        if count: del stack[-count:]
        return result

    def identifier(begin, finish):
        if not begin < finish <= consumed: raise ValueError('invalid HIA expression name range')
        try: value = wire[begin:finish].decode('ascii')
        except UnicodeDecodeError as error: raise ValueError('invalid HIA expression identifier') from error
        if not value.isidentifier(): raise ValueError('invalid HIA expression identifier')
        return value

    def type_value(begin, finish, depth):
        if not begin < finish <= consumed or not 1 <= depth <= 128:
            raise ValueError('invalid HIA expression type range/depth')
        data = wire[begin:finish]
        arena, _ = native_types.run(data, max_depth=depth)
        if arena is None: raise ValueError('HIA expression type range was not admitted')
        value, characters, byte_count = materialize_type(arena, data, lexer.integer_value, max_depth=depth)
        if byte_count != len(data) or characters != len(data.decode('utf-8')):
            raise ValueError('HIA expression type range has trailing bytes')
        return value

    for i in range(count):
        (kind, arity, start, end, line, column, begin, finish, aux, r0, r1, r2) = struct.unpack_from('<12Q', raw, 64 + i * RECORD_BYTES)
        if (not 1 <= kind <= 18 or r0 or r1 or r2 or not 0 <= start <= end <= chars + (kind == 18)
                or end > source_char_count
                or not 0 <= begin <= finish <= consumed + (kind == 18) or finish > len(wire) or line < 1 or column < 1):
            raise ValueError('invalid HIA expression event')
        span = Span(origin.start + start, origin.start + end, origin.line + line - 1,
                    column + (origin.column - 1 if line == 1 else 0), origin.path)
        if kind in (1, 2, 3):
            if arity or not begin < finish: raise ValueError('invalid HIA expression literal')
            if kind == 1:
                if aux != 3: raise ValueError('invalid HIA integer event')
                value = lexer.integer_value(wire[begin:finish]); name = 'int'
            elif kind == 2:
                if aux != 4: raise ValueError('invalid HIA float event')
                value = lexer.float_value(wire[begin:finish]); name = 'float'
            else:
                keyword = token_kind(aux)
                if keyword not in ('true', 'false') or wire[begin:finish] != keyword.encode():
                    raise ValueError('invalid HIA boolean event')
                value = keyword == 'true'; name = 'bool'
            stack.append(Expr(name, value, span=span))
        elif kind == 6:
            if arity or aux: raise ValueError('invalid HIA name builder')
            stack.append(_Name([identifier(begin, finish)]))
        elif kind == 17:
            if arity or aux or not stack or not isinstance(stack[-1], _Name):
                raise ValueError('invalid HIA name continuation')
            stack[-1].parts.append(identifier(begin, finish))
        elif kind == 7:
            if arity or not stack or not isinstance(stack[-1], _Name):
                raise ValueError('invalid HIA type argument event')
            stack[-1].types.append(type_value(begin, finish, aux))
        elif kind == 8:
            if begin or finish: raise ValueError('invalid HIA name finalizer payload')
            builder, = pop(1, _Name)
            if arity != len(builder.types) or aux != len(builder.parts):
                raise ValueError('HIA name builder counts differ')
            name = '::'.join(builder.parts)
            stack.append(Expr('name', name, span=span, type_args=tuple(builder.types)))
            if aux > 1: qualified.append((name, span))
        elif kind in (4, 5):
            if arity != (1 if kind == 4 else 2) or begin or finish:
                raise ValueError('invalid HIA operator arity')
            operator = token_kind(aux)
            allowed = ('-', '!', 'read', 'mut', 'move') if kind == 4 else (
                '||', '&&', '|', '^', '&', '==', '!=', '<', '<=', '>', '>=', '<<', '>>', '+', '-', '*', '/', '%')
            if operator not in allowed: raise ValueError('invalid HIA expression operator')
            stack.append(Expr('unary' if kind == 4 else 'binary', operator, pop(arity), span))
        elif kind == 9:
            if begin or finish or aux: raise ValueError('invalid HIA call event')
            args = pop(arity); name, = pop(1)
            if name.kind != 'name': raise ValueError('HIA call target is not a name')
            stack.append(Expr('call', name.value, args, span, name.type_args))
        elif kind == 10:
            if arity != 2 or begin or finish or aux: raise ValueError('invalid HIA index event')
            stack.append(Expr('index', children=pop(2), span=span))
        elif kind == 11:
            if arity != 1 or aux: raise ValueError('invalid HIA field event')
            stack.append(Expr('field', identifier(begin, finish), pop(1), span))
        elif kind == 12:
            if arity != 1: raise ValueError('invalid HIA cast event')
            value = type_value(begin, finish, aux)
            stack.append(Expr('cast', value, pop(1), span))
        elif kind == 13:
            if arity != 1 or begin or finish or aux: raise ValueError('invalid HIA grouping event')
            child, = pop(1); child.span = span; stack.append(child)
        elif kind == 14:
            if begin or finish or aux: raise ValueError('invalid HIA array event')
            stack.append(Expr('array', children=pop(arity), span=span))
        elif kind == 15:
            if arity != 1 or aux: raise ValueError('invalid HIA struct field event')
            child, = pop(1); stack.append(_Field(identifier(begin, finish), child))
        elif kind == 18:
            if arity or aux not in (521, 517) or end - start != 2 or finish - begin != 2:
                raise ValueError('invalid HIA type operator split')
            if wire[begin:finish] != token_kind(aux).encode('ascii') or start in seen_splits:
                raise ValueError('invalid HIA type operator split payload')
            splits.append(start); seen_splits.add(start)
        else:
            if begin or finish or aux: raise ValueError('invalid HIA struct event')
            fields = pop(arity, _Field); name, = pop(1)
            if name.kind != 'name': raise ValueError('invalid HIA struct name')
            stack.append(Expr('struct', {'name': name.value, 'fields': [item.name for item in fields]},
                              [item.value for item in fields], span, name.type_args))
    if len(stack) != 1 or not isinstance(stack[0], Expr):
        raise ValueError('HIA expression arena leaves unfinished values')
    expected = {1:'int', 2:'float', 3:'bool', 4:'unary', 5:'binary', 6:'name',
                9:'call', 10:'index', 11:'field', 12:'cast', 14:'array', 16:'struct'}
    if expected.get(root_kind) != stack[0].kind:
        raise ValueError('HIA expression root kind differs')
    return stack[0], qualified, chars, consumed, splits


class NativeSourceExpressions(NativeHiaJsonImage):
    def run(self, wire: bytes, *, max_depth: int, minimum: int = 0, allow_struct: bool = True):
        if (type(wire) is not bytes or len(wire) > MAX_BYTES or type(max_depth) is not int
                or not 1 <= max_depth <= 128 or type(minimum) is not int or not 0 <= minimum <= 12
                or type(allow_struct) is not bool):
            raise ValueError('outside native HIA source expression profile')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        # Start bounded and resize from the HIA count pass, not from the entire
        # remaining source suffix. Every call has private input/output/scratch.
        capacity = 4096
        while True:
            output = ctypes.create_string_buffer(capacity)
            state = ctypes.create_string_buffer(WORKSPACE)
            struct.pack_into('<Q', state, 8528, max_depth)
            struct.pack_into('<2Q', state, 8640, minimum, int(allow_struct))
            result = self._entry(source, len(wire), output, capacity, state, WORKSPACE)
            if result == 0xffffffff: return None, state.raw
            if result == 0xfffffffe:
                count = struct.unpack_from('<Q', state, 8536)[0]
                required = 64 + count * RECORD_BYTES
                if not 1 <= count <= MAX_EVENTS or not capacity < required <= 64 + MAX_EVENTS * RECORD_BYTES:
                    raise RuntimeError('invalid HIA expression required capacity')
                capacity = required
                continue
            if not 64 <= result <= capacity: raise RuntimeError('HIA expression parser rejected declared buffers')
            return output.raw[:result], state.raw


def installed_source_expressions(path: str):
    image = _installed_json_image(path, SOURCE, SCHEMA, NativeSourceExpressions)
    types, lexer = installed_source_types(str(Path(path).resolve(strict=True).parent / 'source-types/manifest.json'))
    return image, types, lexer


def _diagnostic(state, wire, source, origin, nesting_limit):
    if struct.unpack_from('<Q', state, 48)[0] or struct.unpack_from('<Q', state, 216)[0]:
        return type_diagnostic(state, wire, source, origin, nesting_limit,
                               token_kind(struct.unpack_from('<Q', state, 128)[0]))
    code, start, end, line, column, kind = struct.unpack_from('<6Q', state, 8592)
    if not 0 <= start <= end <= len(source) or line < 1 or column < 1:
        raise RuntimeError('invalid HIA expression diagnostic span')
    found = token_kind(kind)
    messages = {1:f'Syntax exceeds the bootstrap nesting limit of {nesting_limit}',
        2:'Strings are supported only as the ABI literal "C"', 3:'Expected an expression',
        4:'Only ordinary named function calls are supported', 6:f"Expected ')', found {found!r}",
        7:f"Expected ']', found {found!r}", 8:'Expected a field name',
        9:f"Expected ':', found {found!r}", 10:"Expected ',' or '}' after a field value",
        11:"Expected a name or '<' after '::'", 12:'Only one explicit generic argument list is supported'}
    if code == 13: raise OverflowError('HIA expression exceeds 2M construction events')
    if code not in messages: raise RuntimeError('invalid HIA expression parser diagnostic')
    tag = 'E_PARSE_DEPTH' if code == 1 else 'E_PARSE_STRING' if code == 2 else 'E_PARSE'
    return HeptaError(Diagnostic(tag, messages[code], Span(origin.start + start, origin.start + end,
        origin.line + line - 1, column + (origin.column - 1 if line == 1 else 0), origin.path), phase='parse'))


def parse_expression(parser, native, native_types, lexer, *, minimum, allow_struct, max_depth, nesting_limit):
    """Synchronize only native positions/objects into the surrounding parser."""
    from .lexer import Token
    origin = parser.current.span
    source = parser.source[origin.start:]
    wire = source.encode('utf-8')
    raw, state = native.run(wire, max_depth=max_depth, minimum=minimum, allow_struct=allow_struct)
    consumed = struct.unpack_from('<Q', state, 184)[0]
    if not 0 <= consumed <= len(source): raise RuntimeError('invalid HIA expression cursor')
    boundary = origin.start + consumed
    splits = set()
    if raw is not None:
        value, qualified, chars, _, relative_splits = materialize(raw, wire, native_types, lexer, origin=origin)
        if chars != consumed: raise RuntimeError('HIA expression cursor disagrees with arena')
        splits = {origin.start + offset for offset in relative_splits}
    while parser.current.kind != 'EOF' and parser.current.span.start < boundary:
        token = parser.current
        if token.kind in ('>>', '>=') and (token.span.start in splits or token.span.end > boundary):
            p = token.span
            parser.tokens[parser.position:parser.position + 1] = [
                Token('>', '>', Span(p.start, p.start + 1, p.line, p.column, p.path)),
                Token(token.kind[1], token.kind[1], Span(p.start + 1, p.end, p.line, p.column + 1, p.path))]
            token = parser.current
        if token.span.end > boundary: raise RuntimeError('HIA expression cursor splits a non-operator token')
        parser.position += 1
    if raw is None: raise _diagnostic(state, wire, source, origin, nesting_limit)
    parser.qualified_expressions.extend(qualified)
    return value
