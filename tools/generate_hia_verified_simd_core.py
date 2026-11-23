"""Author the HIA matcher for verified SIMD kernels from an admitted primitive Core.

The first matching operand fixes each identifier. Later uses must agree and
distinct slots cannot alias. Block declarations are found using the actual
entry and branch targets, so their declaration order has no effect.
"""
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_inspect_json import document, source_program
from tools.generate_hia_core_json_frontend import packed
from tools.hia_verified_simd_core_spec import recurrence

MODULE = 'verified_simd_core'
KINDS = ('sum_u8', 'all_zero_u8', 'copy_u8')
OBJ, ARRAY, FIELD, ITEM, BLOCK, UP, LITERAL, INTEGER, IDENT, MODULE_NAME, EXPORT = range(1, 12)

def encode(profile, vocabulary):
    tape = bytearray()
    slots = ({}, {})
    def word(text):
        return vocabulary.setdefault(text, len(vocabulary))
    def slot(text):
        group = slots[text[0] == '@']
        pos = group.setdefault(text, len(group))
        assert pos < (8 if text[0] == '@' else 48)
        return pos + (48 if text[0] == '@' else 0)
    def emit(code, arg=0):
        tape.extend((code, arg))
    def walk(node, field=None):
        if isinstance(node, dict):
            emit(OBJ, len(node))
            for key, child in node.items():
                emit(FIELD, word(key))
                walk(child, key)
                emit(UP)
        elif isinstance(node, list):
            emit(ARRAY, len(node))
            for index, child in enumerate(node):
                if field == 'blocks':
                    emit(BLOCK, slot(child['id']))
                else:
                    emit(ITEM, index)
                walk(child)
                emit(UP)
        elif type(node) is int:
            emit(INTEGER, node)
        elif node == '%module':
            emit(MODULE_NAME)
        elif node == '%export':
            emit(EXPORT)
        elif node[0] in '$@':
            emit(IDENT, slot(node))
        else:
            emit(LITERAL, word(node))
    walk(profile)
    return tape


POLICY = '''
def recognize(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 32768 or length(w) < 8192:
        return 0
    put(o, 48, 4096)
    put(o, 56, 64)
    end = widen(decode_json(s, w, o))
    if end >= 4294967292 or end + 8192 > length(w):
        return 0
    shape = 1
    while shape <= 3:
        size = pattern(w, end, shape)
        if matches(s, w, end, size) == 1:
            name = get(w, end + 5072)
            size = count(w, name)
            start = get(w, 64 + name * 56 + 24)
            put(o, 0, SIMD_SUBJECT)
            put(o, 8, shape)
            put(o, 16, size)
            i = 0
            while i < size:
                store(o, 24 + i, byte(w, start + i))
                i = i + 1
            return narrow(24 + size)
        shape = shape + 1
    # The syscall adapter reads this only on a declined SIMD match. A valid
    # source tree and its actual block count distinguish older scalar CFGs.
    schema = member(w, 0, REPORT_SCHEMA_KEY)
    functions = member(w, 0, REPORT_FUNCTIONS_KEY)
    if schema == NONE or functions == NONE:
        return 0
    if kind(w, schema) != 4 or kind(w, functions) != 5 or count(w, functions) != 1:
        return 0
    position = get(w, 64 + schema * 56 + 24)
    if same(w, position, count(w, schema), REPORT_V1_LITERAL) == 0:
        return 0
    blocks = member(w, child(w, functions), REPORT_BLOCKS_KEY)
    if blocks != NONE and kind(w, blocks) == 5 and count(w, blocks) != 0:
        put(o, 0, REPORT_SHAPE_MAGIC)
        put(o, 8, choose(count(w, blocks) > 1, 3, 1))
    return 0

def matches(s:readbuf, w:mutbuf, base:u64, size:u64) -> u64:
    i = 0
    while i < 56:
        put(w, base + 4096 + i * 8, NONE)
        i = i + 1
    depth = 0
    node = 0
    cursor = 0
    while cursor < size:
        code = byte(w, base + cursor)
        arg = byte(w, base + cursor + 1)
        cursor = cursor + 2
        if code == 1:
            if kind(w, node) != 6:
                return 0
            if node == 0 and count(w, node) == 4:
                if field(w, node, K_exports) == NONE:
                    return 0
            else:
                if count(w, node) != arg:
                    return 0
        elif code == 2:
            if kind(w, node) != 5 or count(w, node) != arg:
                return 0
        elif code >= 3 and code <= 5:
            put(w, base + 4608 + depth * 8, node)
            depth = depth + 1
            if code == 3:
                node = member(w, node, arg)
            elif code == 4:
                node = child(w, node)
                i = 0
                while i < arg:
                    node = next_node(w, node)
                    i = i + 1
            else:
                node = find_block(w, node, get(w, base + 4096 + arg * 8))
            if node == NONE:
                return 0
        elif code == 6:
            depth = depth - 1
            node = get(w, base + 4608 + depth * 8)
        elif code == 7:
            if kind(w, node) != 4 or literal(w, get(w, 64 + node * 56 + 24), count(w, node), arg) == 0:
                return 0
        elif code == 8:
            if kind(w, node) != 3:
                return 0
            at = get(w, 64 + node * 56 + 24)
            digits = count(w, node)
            if digits == 2 and arg == 0 and byte(s, at) == 45:
                at = at + 1
                digits = 1
            if digits != 1 or byte(s, at) != 48 + arg:
                return 0
        else:
            if valid_id(w, node) == 0:
                return 0
            if code == 9:
                if bind_id(w, base, node, arg) == 0:
                    return 0
            elif code == 11:
                put(w, base + 5072, node)
    exports = field(w, 0, K_exports)
    if exports != NONE:
        if kind(w, exports) != 5 or count(w, exports) != 0:
            return 0
    return 1

def member(w:mutbuf, node:u64, which:u64) -> u64:
    n = child(w, node)
    while n != NONE:
        at = 64 + n * 56
        if literal(w, get(w, at + 40), get(w, at + 48), which) == 1:
            return n
        n = next_node(w, n)
    return NONE

def find_block(w:mutbuf, nodes:u64, name:u64) -> u64:
    n = child(w, nodes)
    while n != NONE:
        if equals(w, field(w, n, K_id), name) == 1:
            return n
        n = next_node(w, n)
    return NONE

def equals(w:mutbuf, a:u64, b:u64) -> u64:
    if kind(w, a) != 4 or kind(w, b) != 4 or count(w, a) != count(w, b):
        return 0
    first = get(w, 64 + a * 56 + 24)
    second = get(w, 64 + b * 56 + 24)
    i = 0
    while i < count(w, a):
        if byte(w, first + i) != byte(w, second + i):
            return 0
        i = i + 1
    return 1

def bind_id(w:mutbuf, base:u64, node:u64, slot:u64) -> u64:
    table = base + 4096
    old = get(w, table + slot * 8)
    if old != NONE:
        return equals(w, node, old)
    i = choose(slot < 48, 0, 48)
    end = choose(slot < 48, 48, 56)
    while i < end:
        if equals(w, node, get(w, table + i * 8)) == 1:
            return 0
        i = i + 1
    put(w, table + slot * 8, node)
    return 1

def valid_id(w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 4 or count(w, node) == 0 or count(w, node) > 128:
        return 0
    at = get(w, 64 + node * 56 + 24)
    if count(w, node) >= 6 and same(w, at, 6, 6, RESERVED_PREFIX, 0, 0) == 1:
        return 0
    i = 0
    while i < count(w, node):
        ch = byte(w, at + i)
        if ch != 95 and (ch < 65 or ch > 90) and (ch < 97 or ch > 122):
            if i == 0 or ch < 48 or ch > 57:
                return 0
        i = i + 1
    return 1

def narrow(n:u64) -> u32:
    return n
'''

def matcher_source():
    vocabulary = {}
    entry = POLICY.replace('SIMD_SUBJECT', str(int.from_bytes(b'HIASIMC1', 'little')))
    entry = entry.replace('RESERVED_PREFIX', str(int.from_bytes(b'__hia_', 'little')))
    entry += '\ndef pattern(w:mutbuf, base:u64, shape:u64) -> u64:\n'
    tapes = [encode(recurrence(kind), vocabulary) for kind in KINDS]
    for marker, field in (('REPORT_SCHEMA_KEY', 'schema'), ('REPORT_FUNCTIONS_KEY', 'functions'),
                          ('REPORT_BLOCKS_KEY', 'blocks')):
        entry = entry.replace(marker, str(vocabulary[field]))
    entry = entry.replace('REPORT_V1_LITERAL', ', '.join(map(str, packed('hepta.hia.program.v1'))))
    entry = entry.replace('REPORT_SHAPE_MAGIC', str(int.from_bytes(b'HIASCS01', 'little')))
    for index, tape in enumerate(tapes, 1):
        assert len(tape) < 4096
        entry += f'    if shape == {index}:\n        return pattern_{index}(w, base)\n'
    entry += '    return 0\n'
    for index, tape in enumerate(tapes, 1):
        entry += f'\ndef pattern_{index}(w:mutbuf, base:u64) -> u64:\n'
        for offset in range(0, len(tape), 8):
            value = int.from_bytes(tape[offset:offset + 8], 'little')
            entry += f'    put(w, base + {offset}, {value})\n'
        entry += f'    return {len(tape)}\n'
    entry += '\ndef literal(w:mutbuf, start:u64, size:u64, which:u64) -> u64:\n'
    for token, number in vocabulary.items():
        words = ', '.join(map(str, packed(token)))
        entry += f'    if which == {number}:\n        return same(w, start, size, {words})\n'
    entry += '    return 0\n'
    return entry


def program():
    nodes = ast.parse(source_program(entry=matcher_source())).body
    required = {'recognize'}
    while True:
        calls = {call.func.id for fn in nodes if fn.name in required for call in ast.walk(fn)
                 if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)}
        if calls <= required:
            break
        required |= calls
    policy = ast.unparse(ast.Module(body=[fn for fn in nodes if fn.name in required], type_ignores=[]))
    return document(policy, MODULE)


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap' / (MODULE + '.hepta')
    target.write_text(render_assembly(program()))
