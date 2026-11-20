"""Author ordinary Agent JSON and worker request admission in HIA.

The existing integer JSON, exact binary64 conversion/printing and SHA-256
algorithms are composed at development time. The checked-in HIA owns all
payload parsing, canonical byte production and request identity computation.
Foreign objects, executable custody and the durable service remain separate.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_agent_contract import VERSION
from tools.generate_hia_agent_data_json import source_program as data_source
from tools.generate_hia_agent_binary64 import source_program as decimal_source
from tools.generate_hia_agent_binary64_format import source_program as format_source
from tools.generate_hia_json_canonical import SOURCE as CANONICAL
from tools.generate_hia_sha256 import source_program as hash_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

PRIVATE_BYTES = 16384
SOURCE_PATH = 'examples/hia_bootstrap/worker_request.hepta'

ENTRY = r'''
def worker_request(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8:
        return 4294967293
    mode = get(w, 0)
    if mode == 4:
        return terminal_header(s)
    if length(s) > 8388608 or length(o) < 128 or length(w) < 16512:
        return 4294967293
    if mode == 2:
        return terminal_wire(s, o, w)
    bound = (length(s) + 1) >> 1
    bound = bound + 1
    if bound > 262144:
        bound = 262144
    if length(w) < 64 + bound * 56 + length(s) + 16384:
        return 4294967293
    digits = get(w, 8)
    if mode > 3:
        return 4294967293
    private = length(w) - 16384
    put(w, private + 512, 0)
    put(w, private, digits)
    put(o, 48, 262144)
    put(o, 56, 128)
    result = widen(decode_json(s, w, o))
    if result >= 4294967292:
        return result
    # Prevalidate every numeric token before field checks, like decode_data.
    index = 0
    while index < get(w, 8):
        record = 64 + index * 56
        kind = get(w, record)
        start = get(w, record + 24)
        size = get(w, record + 32)
        if kind == 3:
            count = size
            if byte(s, start) == 45:
                count = count - 1
            if digits != 0 and count > digits:
                return 4294967280
        if kind == 7:
            if widen(decimal_convert(s, w, start, size)) != 8:
                return 4294967280
        index = index + 1
    status = finish_request(s, o, w, mode)
    restore_order(w)
    put(w, 56, 0)
    if mode == 1 and status <= 8388608:
        put(w, private + 512, 3544423407010851144)
    return status

def finish_request(s:readbuf, o:mutbuf, w:mutbuf, mode:u64) -> u64:
    private = length(w) - 16384
    if mode == 1:
        status = request_fields(w)
        if status != 0:
            return status
        # Only the root request_sha256 member is omitted. Nested names remain.
        sort_object(w, 0)
        request = get(w, private + 24)
        previous = 18446744073709551615
        node = get(w, 88)
        while node != request:
            previous = node
            node = get(w, 64 + node * 56 + 16)
        following = get(w, 64 + request * 56 + 16)
        if previous == 18446744073709551615:
            put(w, 88, following)
        else:
            put(w, 64 + previous * 56 + 16, following)
        put(w, 96, 5)
        count = serialize(s, o, w)
        # Restore the complete admitted tree on both success and refusal.
        if previous == 18446744073709551615:
            put(w, 88, request)
        else:
            put(w, 64 + previous * 56 + 16, request)
        put(w, 96, 6)
        put(w, 56, 0)
        if count >= 4294967000:
            return count
        if widen(hash_sha256(o, w, count)) != 32:
            return 4294967293
        start = get(w, 64 + request * 56 + 24)
        index = 0
        while index < 32:
            value = byte(w, length(w) - 4096 + 1088 + index)
            if byte(w, start + index * 2) != hex_digit(value >> 4) or byte(w, start + index * 2 + 1) != hex_digit(value & 15):
                return 4294967273
            index = index + 1
        catalog = get(w, private + 32)
        start = get(w, 64 + catalog * 56 + 24)
        index = 0
        while index < 64:
            if byte(w, start + index) != byte(w, private + 64 + index):
                return 4294967276
            index = index + 1
        tool = get(w, private + 40)
        record = 64 + tool * 56
        if get(w, record) != 4:
            return 4294967275
        start = get(w, record + 24)
        size = get(w, record + 32)
        characters = 0
        index = 0
        while index < size:
            if (byte(w, start + index) & 192) != 128:
                characters = characters + 1
            index = index + 1
        if characters > 128:
            return 4294967275
        # The hosted protocol bounds only the digest's five-field payload.
        # Re-encoding the full envelope here would add a stricter byte gate.
        return count
    if mode == 3 and terminal_body(w) == 0:
        return 4294967279
    count = serialize(s, o, w)
    put(w, 56, 0)
    return count

def restore_order(w:mutbuf) -> u64:
    # Serialization changes sibling links for lexical key ordering. Preserve
    # the decoder's source-preorder arena ABI and Python insertion order.
    count = get(w, 8)
    index = 0
    while index < count:
        record = 64 + index * 56
        kind = get(w, record)
        if kind == 5 or kind == 6:
            put(w, record + 24, 18446744073709551615)
        index = index + 1
    while index > 1:
        index = index - 1
        record = 64 + index * 56
        parent = get(w, record + 8)
        previous = get(w, 64 + parent * 56 + 24)
        put(w, record + 16, previous)
        put(w, 64 + parent * 56 + 24, index)
    return 0

def request_fields(w:mutbuf) -> u64:
    if get(w, 64) != 6 or get(w, 96) != 6:
        return 4294967279
    private = length(w) - 16384
    node = get(w, 88)
    mask = 0
    index = 0
    while index < 6:
        record = 64 + node * 56
        key = request_key(w, get(w, record + 40), get(w, record + 48))
        if key == 0:
            return 4294967279
        mask = mask | (1 << key)
        put(w, private + 256 + key * 8, node)
        node = get(w, record + 16)
        index = index + 1
    if mask != 126:
        return 4294967279
    schema = get(w, private + 264)
    record = 64 + schema * 56
    if get(w, record) != 4 or request_schema(w, get(w, record + 24), get(w, record + 32)) == 0:
        return 4294967278
    index = 4
    while index <= 6:
        node = get(w, private + 256 + index * 8)
        record = 64 + node * 56
        if get(w, record) != 4 or get(w, record + 32) != 64:
            return 4294967277
        offset = get(w, record + 24)
        cursor = 0
        while cursor < 64:
            ch = byte(w, offset + cursor)
            if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
                return 4294967277
            cursor = cursor + 1
        index = index + 1
    put(w, private + 24, get(w, private + 288))
    put(w, private + 32, get(w, private + 304))
    put(w, private + 40, get(w, private + 272))
    return 0

def terminal_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    # The request arena belongs to the same worker invocation. The body is
    # an already serialized terminal service object, not request input.
    private = length(w) - 16384
    if get(w, private + 512) != 3544423407010851144:
        return 4294967293
    put(w, private + 512, 0)
    helpers = get(w, private + 520)
    if helpers > 1 or length(s) < 2:
        return 4294967293
    if byte(s, 0) != 123 or byte(s, length(s) - 1) != 125:
        return 4294967293
    extent = 128 + helpers * 64
    i = 0
    while i < extent:
        ch = byte(w, private + 528 + i)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return 4294967277
        i = i + 1
    put(w, 56, 0)
    text(o, w, '{"backend_sha256":')
    append_string(o, w, private + 528, 64)
    text(o, w, ',"catalog_sha256":')
    report_request_field(o, w, 6)
    text(o, w, ',"complete":true')
    if helpers == 1:
        text(o, w, ',"native_helpers_sha256":')
        append_string(o, w, private + 656, 64)
    text(o, w, ',"profile_sha256":')
    report_request_field(o, w, 5)
    text(o, w, ',"request_sha256":')
    report_request_field(o, w, 4)
    text(o, w, ',"response":')
    if get(w, 56) > 8388608 - length(s):
        return 4294967274
    i = 0
    while i < length(s):
        append_byte(o, w, byte(s, i))
        i = i + 1
    text(o, w, ',"schema":"hia-agent-worker-report-v1","tool":')
    report_request_field(o, w, 2)
    text(o, w, ',"worker_sha256":')
    append_string(o, w, private + 592, 64)
    append_byte(o, w, 125)
    result = get(w, 56)
    if result > 8388608:
        return 4294967274
    return result

def terminal_body(w:mutbuf) -> u64:
    if get(w, 64) != 6 or get(w, 96) != 4:
        return 0
    node = get(w, 88)
    fields = 0
    outcome = 0
    index = 0
    while index < 4:
        record = 64 + node * 56
        key = terminal_body_key(w, get(w, record + 40), get(w, record + 48))
        if key == 0:
            return 0
        kind = get(w, record)
        if key <= 3:
            if kind != 4:
                return 0
            start = get(w, record + 24)
            size = get(w, record + 32)
            if key == 1 and terminal_contract(w, start, size) == 0:
                return 0
            if size == 0:
                return 0
            if key == 3:
                outcome = terminal_outcome(w, start, size)
        else:
            if kind != 6:
                return 0
        fields = fields | (1 << key)
        node = get(w, record + 16)
        index = index + 1
    return choose(fields == outcome, 1, 0)

def report_request_field(o:mutbuf, w:mutbuf, key:u64) -> u64:
    node = get(w, length(w) - 16384 + 256 + key * 8)
    record = 64 + node * 56
    append_string(o, w, get(w, record + 24), get(w, record + 32))
    return 0

def emit_word(o:mutbuf, w:mutbuf, word:u64, size:u64) -> u64:
    index = 0
    while index < size:
        append_byte(o, w, (word >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('authoring dependency changed: ' + old[:100])
    return source.replace(old, new)


def renamed(source, prefix, *, scratch=0):
    """Prefix symbols and relocate private numeric scratch without aliasing."""
    tree = ast.parse(source)
    names = {node.name for node in tree.body}

    class Transform(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            self.generic_visit(node)
            node.name = prefix + node.name
            return node

        def visit_Call(self, node):
            self.generic_visit(node)
            if isinstance(node.func, ast.Name):
                if node.func.id in names:
                    node.func.id = prefix + node.func.id
                elif (scratch and node.func.id in ('byte', 'store', 'word_load', 'word_store')
                      and isinstance(node.args[0], ast.Name) and node.args[0].id == 'w'):
                    base = ast.parse(f'length(w) - {scratch}', mode='eval').body
                    node.args[1] = ast.BinOp(base, ast.Add(), node.args[1])
            return node

    return ast.unparse(ast.fix_missing_locations(Transform().visit(tree))) + '\n'


def decimal_program():
    source = decimal_source()
    source = replace_once(source, 'def convert(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
                          'def convert(s:readbuf, w:mutbuf, start:u64, n:u64) -> u32:')
    source = replace_once(source, '    n = length(s)\n', '')
    source = replace_once(source, 'if length(o) < 8 or length(w) < 4096:', 'if length(w) < 8192:')
    tree = ast.parse(source)
    # Only convert reads source bytes; helpers use its private integer limbs.
    class Slice(ast.NodeTransformer):
        def visit_Call(self, node):
            self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id == 'byte' and isinstance(node.args[0], ast.Name) and node.args[0].id == 's':
                node.args[1] = ast.BinOp(ast.Name('start', ast.Load()), ast.Add(), node.args[1])
            if isinstance(node.func, ast.Name) and node.func.id == 'put' and isinstance(node.args[0], ast.Name) and node.args[0].id == 'o':
                node.args[0] = ast.Name('w', ast.Load())
                node.args[1] = ast.Constant(8000)
            return node
    source = ast.unparse(ast.fix_missing_locations(Slice().visit(tree)))
    return renamed(source, 'decimal_', scratch=8192)


def format_program():
    source = format_source()
    source = replace_once(source, 'def render_binary64(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
                          'def render_binary64(w:mutbuf) -> u32:')
    source = replace_once(source, '    if length(s) != 8:\n        return 4294967295\n', '')
    source = replace_once(source, 'original = read64(s, 0)', 'original = get(w, 8000)')
    begin = source.index('    if length(o) < cursor:')
    end = source.index('    return cursor', begin)
    source = source[:begin] + source[end:]
    return renamed(source, 'format_', scratch=8192)


def _hash_source():
    source = hash_source()
    source = replace_once(source, 'def sha256(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
                          'def sha256(s:mutbuf, w:mutbuf, n:u64) -> u32:')
    source = replace_once(source, ' or length(o) < 32', '')
    source = source.replace('length(s)', 'n')
    source = replace_once(source, 'padded_byte(s, block + i * 4 + j, padded)', 'padded_byte(s, block + i * 4 + j, padded, n)')
    source = replace_once(source, 'def padded_byte(s:readbuf, index:u64, total:u64)', 'def padded_byte(s:mutbuf, index:u64, total:u64, n:u64)')
    return replace_once(source, 'store(o, i * 4 + j,', 'store(w, 1088 + i * 4 + j,')


def hash_program():
    return renamed(_hash_source(), 'hash_', scratch=4096)


def worker_hash_program():
    # SHA state and schedule occupy full little-endian cells within the final
    # 4096 bytes. The Worker admits that whole area before hashing; its v9
    # helpers are separate from the byte helpers reused by the pager and Journal.
    source = _hash_source()
    source = source[:source.index('\ndef get(w:mutbuf, index:u64)')]
    source += """
def get(w:mutbuf, index:u64) -> u64:
    return word_load(w, index)

def put(w:mutbuf, index:u64, value:u64) -> u64:
    word_store(w, index, value)
    return 0
"""
    return renamed(source, 'hash_', scratch=4096)


def canonical_program():
    source = CANONICAL
    begin = source.index('    # The decoded arena')
    source = 'def serialize(s:readbuf, o:mutbuf, w:mutbuf) -> u64:\n' + source[begin:]
    original = '''            if kind == 4:
                append_string(o, w, start, size)
            else:'''
    replacement = '''            if kind == 4:
                append_string(o, w, start, size)
            elif kind == 7:
                if widen(decimal_convert(s, w, start, size)) != 8:
                    return 4294967280
                count = widen(format_render_binary64(w))
                if count >= 4294967000:
                    return 4294967280
                i = 0
                while i < count:
                    append_byte(o, w, byte(w, length(w) - 8192 + 6144 + i))
                    i = i + 1
            else:'''
    source = replace_once(source, original, replacement)
    source = replace_once(source, '        if complete:\n', '''        if get(w, 56) > 8388608:
            return 4294967274
        if complete:
''')
    source = replace_once(source, '    store(o, index, value)\n', '''    if index >= length(o) or index >= 8388608:
        put(w, 56, 8388609)
        return 0
    store(o, index, value)
''')
    # Closing ancestor brackets are appended after the per-node check too.
    source = replace_once(source, '    return get(w, 56)\n', '''    if get(w, 56) > 8388608:
        return 4294967274
    return get(w, 56)
''')
    return source


def key_program():
    tables = {
        'request_key': tuple(enumerate(
            ('schema', 'tool', 'arguments', 'request_sha256', 'profile_sha256', 'catalog_sha256'), 1)),
        'request_schema': ((1, 'hia-agent-worker-request-v1'),),
        'terminal_body_key': tuple(enumerate(
            ('contract_version', 'request_id', 'status', 'result', 'error'), 1)),
        'terminal_contract': ((1, VERSION),),
        'terminal_outcome': ((30, 'completed'), (46, 'rejected')),
    }
    functions = []
    for function, entries in tables.items():
        source = f'def {function}(w:mutbuf, start:u64, size:u64) -> u64:\n'
        for number, name in entries:
            checks = [f'size == {len(name)}'] + [
                f'byte(w, start + {i}) == {value}' for i, value in enumerate(name.encode('ascii'))]
            source += '    if ' + ' and '.join(checks) + f':\n        return {number}\n'
        functions.append(source + '    return 0\n')
    return '\n'.join(functions)


def terminal_frame_program():
    source = '''
def terminal_header(s:readbuf) -> u32:
    size = length(s)
    if size < 8:
        return 4294967293
    magic = frame_word(s, 0)
    if magic == ADMISSION_INPUT:
        if size == 8:
            return 88
        if size != 88:
            return 4294967293
        if frame_word(s, 8) > 8388608:
            return 4294967294
        if valid_digits(frame_word(s, 16)) == 0:
            return 4294967293
        return 88
    if magic != REPORT_INPUT:
        return 4294967293
    if size == 8:
        return 296
    if size != 296:
        return 4294967293
    request = frame_word(s, 8)
    response = frame_word(s, 16)
    if request == 0 or response == 0:
        return 4294967293
    if request > 8388608 or response > 8388608:
        return 4294967294
    if valid_digits(frame_word(s, 24)) == 0:
        return 4294967293
    pins = frame_word(s, 32)
    if pins > 1:
        return 4294967293
    if pins == 0:
        at = 232
        while at < 296:
            if frame_word(s, at) != 0:
                return 4294967293
            at = at + 8
    return 296

def valid_digits(digits:u64) -> u64:
    if digits == 0 or (digits >= 640 and digits <= 2147483647):
        return 1
    return 0

def frame_word(s:readbuf, at:u64) -> u64:
    return word_load(s, at)
'''
    return (source.replace('ADMISSION_INPUT', str(int.from_bytes(b'HIAWRA02', 'little')))
                  .replace('REPORT_INPUT', str(int.from_bytes(b'HIATRP01', 'little'))))


def source_program():
    return '\n'.join((ENTRY, canonical_program(), key_program(), data_source(),
                       decimal_program(), format_program(), worker_hash_program(), terminal_frame_program()))


class WorkerRequestBuilder(Builder):
    def expr(self, node):
        if isinstance(node, ast.Call) and node.func.id == 'word_store':
            buffer, index, value = (self.expr(argument) for argument in node.args)
            return self.op('buffer.store.u64.le', [buffer, self.cast(index, 'usize'), value])
        return super().expr(node)


def document():
    class Text(ast.NodeTransformer):
        def visit_Expr(self, node):
            call = node.value
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id == 'text'):
                return self.generic_visit(node)
            o, w, literal = call.args
            body = literal.value.encode('ascii')
            words = (body[start:start + 8] for start in range(0, len(body), 8))
            return [
                ast.Expr(ast.Call(ast.Name('emit_word', ast.Load()),
                                  [o, w, ast.Constant(int.from_bytes(word, 'little')),
                                   ast.Constant(len(word))], []))
                for word in words
            ]

    nodes = ast.fix_missing_locations(Text().visit(ast.parse(source_program()))).body
    if len({node.name for node in nodes}) != len(nodes):
        raise ValueError('duplicate composed HIA symbol')
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = WorkerRequestBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v9', 'module': 'worker_request', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / SOURCE_PATH
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
