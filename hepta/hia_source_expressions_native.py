"""Operator-selected HIA expression grammar with a validated object bridge.

HIA recognizes expressions/types/tokens. Python retains immutable image
loading, token/AST objects, arena validation and orchestration. Statements,
declarations, name resolution and all other frontend passes remain foreign.
The image is trusted local code, not a hostile-code security boundary.
"""
from __future__ import annotations
import ctypes
from pathlib import Path
import struct
from .ast import Diagnostic, Expr, HeptaError, Span, Type
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_source_lexer_native import installed_source_lexer, KEYWORD_ORDER, PAIR_ORDER
from .hia_source_types_native import _diagnostic as type_diagnostic

SOURCE = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/source_expressions.hiaasm'
SCHEMA = 'hepta.hia.source-expressions-native.v1'
MAGIC = int.from_bytes(b'HIAEXP01', 'little')
NONE = (1 << 64) - 1
WORKSPACE = 25024
MAX_BYTES = 8 << 20
MAX_NODES = 1 << 20


def token_kind(value):
    if value in KEYWORD_ORDER: return 128 + KEYWORD_ORDER.index(value)
    if value in PAIR_ORDER: return 512 + PAIR_ORDER.index(value)
    return 256 + ord(value)


OPERATORS = {token_kind(s): s for s in ('-', '!', 'read', 'mut', 'move',
    '||', '&&', '|', '^', '&', '==', '!=', '<', '<=', '>', '>=', '<<', '>>', '+', '*', '/', '%')}


def materialize(raw: bytes, wire: bytes, integer_value, literal_value, *, _extension=None):
    """Validate the complete ownership graph before creating any Expr/Type.

    This is a value/graph decoder, not a host expression or type recognizer.
    `literal_value` supplies the actual selected HIA lexer's typed Token value.
    """
    if type(raw) is not bytes or type(wire) is not bytes or len(raw) < 64:
        raise ValueError('invalid HIA expression arena')
    magic, count, base, used, chars, consumed, version, root = struct.unpack_from('<8Q', raw)
    if (magic != (MAGIC if _extension is None else _extension.MAGIC) or version != 1 or not 1 <= count <= MAX_NODES
            or base != 64 + count * 128 or not base <= used == len(raw)
            or not 0 <= root < count or not 0 < consumed <= len(wire)
            or not 0 < chars <= consumed):
        raise ValueError('invalid HIA expression header')
    try:
        if len(wire[:consumed].decode('utf-8')) != chars:
            raise ValueError('invalid HIA expression consumed character count')
    except UnicodeDecodeError as error:
        raise ValueError('invalid HIA expression consumed UTF-8') from error
    rows = [struct.unpack_from('<16Q', raw, 64 + i * 128) for i in range(count)]
    children = [[] for _ in rows]
    splits = set()
    payload_ranges = []
    text_values = {}
    kinds = set(range(1, 9)) | set(range(16, 31))
    if _extension is not None: kinds |= _extension.KINDS
    for i, row in enumerate(rows):
        kind, parent, first, last, sibling, start, size, begin, length, tag, a, z, line, col, path_end, parts = row
        if kind not in kinds:
            raise ValueError('invalid HIA expression kind')
        if kind == 30:
            if (parent != NONE or first != NONE or last != NONE or sibling != NONE
                    or any((start, size, a, z, line, col, path_end, parts)) or length != 2
                    or not begin < begin + length <= len(wire) or begin in splits
                    or tag not in (517, 521) or wire[begin:begin + 2] != (b'>=' if tag == 517 else b'>>')):
                raise ValueError('invalid HIA generic split record')
            splits.add(begin)
            continue
        if kind in (1, 8, 23, 28, 29) or (_extension is not None and kind in _extension.TEXT):
            if size == 0 or not start <= start + size <= used - base:
                raise ValueError('invalid HIA expression text range')
            payload_ranges.append((start, start + size))
            try: name = raw[base + start:base + start + size].decode('ascii')
            except UnicodeDecodeError as error: raise ValueError('invalid HIA expression identifier') from error
            if not name or any(not part.isidentifier() for part in name.split('::')) or (kind not in (1, 43) and '::' in name):
                raise ValueError('invalid HIA expression identifier')
            text_values[i] = name
        elif start or size:
            raise ValueError('unexpected HIA expression text')
        if kind in (3, 16, 17, 18):
            if not length or not begin < begin + length <= consumed:
                raise ValueError('invalid HIA expression literal range')
        elif begin or length:
            raise ValueError('unexpected HIA expression literal')
        if kind <= 8:
            if any((tag, a, z, line, col, path_end, parts)):
                raise ValueError('unexpected HIA type extension')
        else:
            if not 0 <= a < z <= chars or line < 1 or col < 1:
                raise ValueError('invalid HIA expression span')
            if kind not in (20, 21, 26) and (path_end or parts):
                raise ValueError('unexpected HIA qualified name metadata')
            if kind in (20, 21, 26) and not 0 < path_end <= chars:
                raise ValueError('invalid HIA qualified name extent')
            if kind not in (16, 17, 18, 19, 25, *(() if _extension is None else _extension.TAGS)) and tag:
                raise ValueError('unexpected HIA expression operator')
        cursor = first
        linked = set()
        while cursor != NONE:
            if (not 0 <= cursor < count or cursor in linked or rows[cursor][1] != i
                    or rows[cursor][0] == 30):
                raise ValueError('invalid HIA expression edge')
            linked.add(cursor)
            children[i].append(cursor)
            cursor = rows[cursor][4]
        if last != (children[i][-1] if children[i] else NONE):
            raise ValueError('invalid HIA expression last child')
    if rows[root][1] != NONE or rows[root][4] != NONE or (not 16 <= rows[root][0] <= 27 if _extension is None else rows[root][0] not in _extension.ROOTS):
        raise ValueError('invalid HIA expression root ownership')
    seen = set()
    order = []
    pending = [(root, False)]
    while pending:
        i, leave = pending.pop()
        if leave:
            order.append(i)
        else:
            if i in seen: raise ValueError('cyclic/shared HIA expression node')
            seen.add(i)
            pending.append((i, True))
            pending.extend((c, False) for c in reversed(children[i]))
    if seen != {i for i, row in enumerate(rows) if row[0] != 30}:
        raise ValueError('orphan HIA expression nodes')
    cursor = 0
    for begin, end in sorted(payload_ranges):
        if begin != cursor: raise ValueError('overlapping/unowned HIA expression text')
        cursor = end
    if cursor != used - base: raise ValueError('unowned HIA expression payload')
    values = [None] * count
    observations = []
    type_names = {2: 'slice', 3: 'array', 4: 'ref_read', 5: 'ref_mut', 6: 'raw_const', 7: 'raw_mut'}
    expr_names = {16: 'int', 17: 'float', 18: 'bool', 19: 'unary', 20: 'name', 21: 'call',
                  22: 'index', 23: 'field', 24: 'cast', 25: 'binary', 26: 'struct', 27: 'array'}
    for i in order:
        kind, _, _, _, _, start, size, begin, length, tag, a, z, line, col, path_end, parts = rows[i]
        kids = children[i]
        typekids = [values[c] for c in kids if rows[c][0] < 8]
        lives = [values[c] for c in kids if rows[c][0] == 8]
        exprkids = [values[c] for c in kids if 16 <= rows[c][0] <= 27]
        if kind <= 8:
            if exprkids or any(rows[c][0] > 8 for c in kids): raise ValueError('invalid HIA type children')
            if kind == 8:
                if kids: raise ValueError('HIA lifetime has children')
                values[i] = text_values[i]
                continue
            if kind in (2, 3, 6, 7) and (len(typekids) != 1 or lives):
                raise ValueError('invalid HIA unary type children')
            if kind in (4, 5) and (len(typekids) != 1 or len(lives) != 1 or rows[kids[0]][0] != 8):
                raise ValueError('invalid HIA stored reference children')
            magnitude = integer_value(wire[begin:begin + length]) if kind == 3 else None
            if kind == 3 and (type(magnitude) is not int or magnitude < 0):
                raise ValueError('invalid HIA array magnitude')
            values[i] = Type(text_values[i] if kind == 1 else type_names[kind], tuple(typekids), magnitude, tuple(lives))
            continue
        if kind in (28, 29):
            if kids: raise ValueError('HIA name part has children')
            values[i] = text_values[i]
            continue
        if _extension is not None and kind in _extension.KINDS:
            values[i] = _extension.decode(i, kind, rows[i], kids, rows, values, text_values)
            continue
        if any(rows[c][0] >= 32 for c in kids): raise ValueError('statement inside HIA expression')
        if lives: raise ValueError('expression has direct lifetime')
        names = [c for c in kids if rows[c][0] == 28]
        fields = [c for c in kids if rows[c][0] == 29]
        if kind not in (20, 21, 26) and (names or typekids and kind != 24):
            raise ValueError('unexpected HIA expression name/type children')
        if kind != 26 and fields: raise ValueError('unexpected HIA field records')
        value = None
        span = Span(a, z, line, col)
        if kind in (16, 17, 18):
            if kids: raise ValueError('HIA literal has children')
            expected = {16: 'INT', 17: 'FLOAT', 18: 'true' if tag == token_kind('true') else 'false'}[kind]
            if kind == 18 and tag not in (token_kind('true'), token_kind('false')):
                raise ValueError('invalid HIA boolean tag')
            if kind in (16, 17) and tag != kind - 13: raise ValueError('invalid HIA numeric tag')
            value = literal_value(begin, length, expected)
            if kind == 18: value = expected == 'true'
        elif kind in (19, 25):
            allowed = ('-', '!', 'read', 'mut', 'move') if kind == 19 else ('||','&&','|','^','&','==','!=','<','<=','>','>=','<<','>>','+','-','*','/','%')
            if tag not in OPERATORS or OPERATORS[tag] not in allowed or len(exprkids) != (1 if kind == 19 else 2):
                raise ValueError('invalid HIA operator children')
            value = OPERATORS[tag]
        elif kind in (20, 21, 26):
            if not names or parts != len(names): raise ValueError('invalid HIA name part count')
            value = '::'.join(values[c] for c in names)
            if len(names) > 1:
                original = rows[names[0]]
                if not original[10] < path_end: raise ValueError('invalid HIA qualified name span')
                observations.append((original[10], value, Span(original[10], path_end, original[12], original[13])))
            if kind == 20 and exprkids: raise ValueError('HIA name has expression children')
            if kind == 26:
                # Native records declare each field/value pair explicitly.
                remainder = [c for c in kids if rows[c][0] not in (*range(1, 8), 28)]
                if len(remainder) != 2 * len(fields) or any(
                        rows[remainder[j]][0] != 29 if j % 2 == 0
                        else not 16 <= rows[remainder[j]][0] <= 27
                        for j in range(len(remainder))):
                    raise ValueError('invalid HIA struct field ownership')
                value = {'name': value, 'fields': [values[c] for c in fields]}
        elif kind == 22:
            if len(exprkids) != 2: raise ValueError('invalid HIA index children')
        elif kind == 23:
            if len(exprkids) != 1: raise ValueError('invalid HIA field children')
            value = text_values[i]
        elif kind == 24:
            if len(typekids) != 1 or len(exprkids) != 1 or len(kids) != 2 or rows[kids[0]][0] < 16:
                raise ValueError('invalid HIA cast children')
            value = typekids[0]
        elif kind != 27:
            raise ValueError('invalid HIA expression node')
        values[i] = Expr(expr_names[kind], value, exprkids, span, tuple(typekids) if kind in (20,21,26) else ())
    observations.sort(key=lambda row: row[0])
    return values[root], chars, consumed, [(name, span) for _, name, span in observations], splits


def materialize_diagnostic_names(raw, wire, *, _extension=None):
    """Decode only completed HIA namespace observations after a failed parse.

    Diagnostic mode is a distinct arena, never an AST and never execution
    authority. Incomplete type/expression nodes may remain unlinked. Every
    traversed edge/name range is validated; no source grammar is recognized.
    """
    if type(raw) is not bytes or len(raw) < 64:
        raise ValueError('invalid HIA expression diagnostic arena')
    magic,count,base,used,chars,consumed,version,code=struct.unpack_from('<8Q',raw)
    if (magic != (MAGIC if _extension is None else _extension.MAGIC) ^ 1 or version != 2 or not 0 <= count <= MAX_NODES
            or base != 64 + count*128 or not base <= used == len(raw)
            or not 0 <= consumed <= len(wire) or len(wire[:consumed].decode('utf-8')) != chars
            or not code):
        raise ValueError('invalid HIA expression diagnostic header')
    rows=[struct.unpack_from('<16Q',raw,64+i*128) for i in range(count)]
    children=[[] for _ in rows];incoming=set()
    for i,row in enumerate(rows):
        if row[0] not in (*range(1,9),*range(16,31),*(() if _extension is None else _extension.KINDS)):
            raise ValueError('invalid HIA diagnostic node kind')
        cursor=row[2];linked=set()
        while cursor != NONE:
            if (not 0 <= cursor < count or cursor in linked or cursor in incoming
                    or rows[cursor][1] != i):
                raise ValueError('invalid HIA diagnostic edge')
            linked.add(cursor);incoming.add(cursor);children[i].append(cursor);cursor=rows[cursor][4]
        if row[3] != (children[i][-1] if children[i] else NONE):
            raise ValueError('invalid HIA diagnostic last child')
    finished=set();active=set()
    for root in range(count):
        if root in finished:continue
        pending=[(root,False)]
        while pending:
            i,leave=pending.pop()
            if leave:active.remove(i);finished.add(i);continue
            if i in active:raise ValueError('cyclic HIA diagnostic graph')
            if i in finished:continue
            active.add(i);pending.append((i,True));pending.extend((c,False) for c in children[i])
    observations=[]
    source_length=len(wire.decode('utf-8'))
    for i,row in enumerate(rows):
        if row[0] not in (20,21,26) or row[14] == 0:continue
        parts=[c for c in children[i] if rows[c][0] == 28]
        if not parts or len(parts) != row[15]:raise ValueError('invalid HIA diagnostic name count')
        names=[]
        for c in parts:
            part=rows[c];begin,size=part[5:7]
            if not size or not begin <= begin+size <= used-base or children[c]:
                raise ValueError('invalid HIA diagnostic name range')
            name=raw[base+begin:base+begin+size].decode('ascii')
            if not name.isidentifier():raise ValueError('invalid HIA diagnostic identifier')
            names.append(name)
        if len(parts)>1:
            part=rows[parts[0]];a,z,line,col=part[10],row[14],part[12],part[13]
            if not 0 <= a < z <= source_length or line < 1 or col < 1:
                raise ValueError('invalid HIA diagnostic namespace span')
            observations.append((a,'::'.join(names),Span(a,z,line,col)))
    observations.sort(key=lambda row:row[0])
    return [(name,span) for _,name,span in observations]


class NativeSourceExpressions(NativeHiaJsonImage):
    def run(self, wire: bytes, *, max_depth: int, minimum: int = 0, allow_struct: bool = True, initial_kind: int = 0, diagnostic_trace: bool = False):
        if (type(wire) is not bytes or len(wire) > MAX_BYTES or type(max_depth) is not int
                or not 1 <= max_depth <= 128 or type(minimum) is not int or not 0 <= minimum <= 128
                or type(allow_struct) is not bool or type(diagnostic_trace) is not bool or initial_kind not in (0,317,318)):
            raise ValueError('outside native HIA expression profile')
        capacity = 64 + min(3 * (len(wire) + 1), MAX_NODES) * 128 + len(wire)
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(capacity)
        workspace = WORKSPACE + ((len(wire) + 7) >> 3)
        state = ctypes.create_string_buffer(workspace)
        for offset, value in ((8520,max_depth),(8544,minimum),(8552,int(allow_struct)),(8600,initial_kind),(8616,int(diagnostic_trace))):
            struct.pack_into('<Q', state, offset, value)
        result = self._entry(source, len(wire), output, capacity, state, workspace)
        if result == 0xffffffff: return None, state.raw
        if not 64 <= result <= capacity: raise RuntimeError('HIA expression rejected declared buffers')
        return output.raw[:result], state.raw


def installed_source_expressions(path: str):
    image = _installed_json_image(path, SOURCE, SCHEMA, NativeSourceExpressions)
    lexer = installed_source_lexer(str(Path(path).resolve(strict=True).parent / 'source-lexer/manifest.json'))
    return image, lexer


def _error(state, wire, source, origin, nesting_limit, current_kind):
    code = struct.unpack_from('<Q', state, 216)[0]
    if code <= 10 or struct.unpack_from('<Q', state, 48)[0]:
        return type_diagnostic(state, wire, source, origin, nesting_limit, current_kind)
    messages = {101:'Only ordinary named function calls are supported', 102:'Expected a field name',
        103:f"Expected ':', found {current_kind!r}", 104:f"Expected ')', found {current_kind!r}",
        105:f"Expected ']', found {current_kind!r}", 106:"Expected ',' or '}' after a field value",
        107:'Strings are supported only as the ABI literal "C"',108:'Expected an expression',
        109:'Only one explicit generic argument list is supported',110:"Expected a name or '<' after '::'"}
    if code not in messages: raise RuntimeError('invalid HIA expression diagnostic')
    present = struct.unpack_from('<Q', state, 8560)[0]
    a, z, line, col = struct.unpack_from('<4Q', state, 8568 if present else 152)
    if not 0 <= a <= z <= len(source) or line < 1 or col < 1:
        raise RuntimeError('invalid HIA expression diagnostic span')
    return HeptaError(Diagnostic('E_PARSE_STRING' if code == 107 else 'E_PARSE', messages[code],
        Span(origin.start+a,origin.start+z,origin.line+line-1,col+(origin.column-1 if line==1 else 0),origin.path),phase='parse'))


def parse_expression(parser, native, lexer, max_depth, nesting_limit, minimum, allow_struct):
    return _parse_application(parser, native, lexer, nesting_limit,
        dict(max_depth=max_depth,minimum=minimum,allow_struct=allow_struct),
        WORKSPACE, _error, None, lambda expr: expr.children)


def _parse_application(parser, native, lexer, nesting_limit, options, workspace, error, extension, children):
    from .lexer import Token
    origin = parser.current.span
    source = parser.source[origin.start:]
    wire = source.encode('utf-8')
    raw, state = native.run(wire,**options,
        initial_kind=token_kind(parser.current.kind) if parser.current.kind in ('>','=') else 0)
    consumed = struct.unpack_from('<Q',state,184)[0]
    if not 0 <= consumed <= len(source): raise RuntimeError('invalid HIA expression cursor')
    split_bytes = {index * 8 + bit for index, value in enumerate(state[workspace:])
                   for bit in range(8) if value & (1 << bit)}
    split_chars = set(); previous_byte=0; previous_char=0
    for begin in sorted(split_bytes):
        if wire[begin:begin+2] not in (b'>>', b'>='):
            raise RuntimeError('invalid HIA expression split trace')
        previous_char+=len(wire[previous_byte:begin].decode('utf-8'));previous_byte=begin
        split_chars.add(previous_char+origin.start)
    # Literal objects originate from the actual selected HIA token stream.
    literals = {}; char_cursor = 0; byte_cursor = 0
    for token in parser.tokens[parser.position:]:
        begin = token.span.start-origin.start; end=token.span.end-origin.start
        byte_cursor += len(source[char_cursor:begin].encode('utf-8')); size=len(source[begin:end].encode('utf-8'))
        literals[(byte_cursor,size,token.kind)]=token.value
        byte_cursor += size; char_cursor=end
    def literal_value(begin,length,kind):
        try:return literals[(begin,length,kind)]
        except KeyError as error:raise ValueError('HIA literal does not own a matching token') from error
    boundary=origin.start+consumed
    while parser.current.kind!='EOF' and parser.current.span.start<boundary:
        token=parser.current
        if token.span.start in split_chars:
            if token.kind not in ('>>','>='):raise RuntimeError('HIA split does not own a paired token')
            p=token.span
            parser.tokens[parser.position:parser.position+1]=[
                Token('>','>',Span(p.start,p.start+1,p.line,p.column,p.path)),
                Token(token.kind[1],token.kind[1],Span(p.start+1,p.end,p.line,p.column+1,p.path))]
        if parser.current.span.end>boundary:raise RuntimeError('HIA expression cursor splits an unreported token')
        parser.position+=1
    if raw is None:
        diagnostic,again=native.run(wire,**options,
            initial_kind=struct.unpack_from('<Q',state,8600)[0],diagnostic_trace=True)
        if diagnostic is None or again[48:56]!=state[48:56] or again[184:224]!=state[184:224] or again[8560:8600]!=state[8560:8600]:
            raise RuntimeError('HIA expression diagnostic replay disagrees')
        observations=materialize_diagnostic_names(diagnostic,wire,_extension=extension)
        for name,p in observations:
            parser.qualified_expressions.append((name,Span(origin.start+p.start,origin.start+p.end,origin.line+p.line-1,p.column+(origin.column-1 if p.line==1 else 0),origin.path)))
        raise error(state,wire,source,origin,nesting_limit,parser.current.kind)
    expr,chars,_,observations,splits=materialize(raw,wire,lexer.integer_value,literal_value,_extension=extension)
    if chars!=consumed or splits!=split_bytes:raise RuntimeError('HIA expression arena disagrees with cursor/trace')
    pending=[expr]
    while pending:
        current=pending.pop();p=current.span
        current.span=Span(origin.start+p.start,origin.start+p.end,origin.line+p.line-1,p.column+(origin.column-1 if p.line==1 else 0),origin.path)
        pending.extend(children(current))
    for name,p in observations:
        parser.qualified_expressions.append((name,Span(origin.start+p.start,origin.start+p.end,origin.line+p.line-1,p.column+(origin.column-1 if p.line==1 else 0),origin.path)))
    return expr
