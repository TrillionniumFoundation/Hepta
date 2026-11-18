"""Author inspection of admitted primitive Core using the native JSON arena."""
import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_schema import PRIMITIVE_PROFILES
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_core_json_frontend import KEYS, FRONTEND, packed
from tools.generate_hia_json_canonical import core_pretty_source
from tools.generate_hia_json_decode import source_program as decoder
from tools.generate_hia_sha256 import source_program as sha_source


POLICY = r'''
def inspect_core(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 128:
        return 4294967293
    put(o, 48, 262144)
    put(o, 56, 64)
    decoded_size = widen(decode_json(s, w, o))
    if decoded_size >= 4294967292:
        return decoded_size
    # Hash the exact canonical Core, not the original whitespace or key order.
    if decoded_size + 9280 > length(w):
        return 4294967293
    put(w, 56, 0)
    fragment(s, o, w, 0, 0, 0)
    size = get(w, 56)
    if size > length(o):
        return 4294967294
    digest(o, w, size)
    put(w, 56, 0)
    schema = field(w, 0, K_schema)
    version = byte(w, get(w, 64 + schema * 56 + 24) + 19)
    functions = field(w, 0, K_functions)
    lit(o, w, '{\n  "claims": {\n    "native_executed": false,\n    "whole_language_soundness_proved": false\n  },\n')
    lit(o, w, '  "functions": [')
    fn = child(w, functions)
    while fn != NONE:
        lit(o, w, '\n    {')
        render_function(s, o, w, fn, version)
        lit(o, w, '\n    }')
        fn = next_node(w, fn)
        comma(o, w, fn)
    lit(o, w, '\n  ],\n  "input_sha256": ')
    quoted_hash(o, w)
    lit(o, w, ',\n  "module": ')
    fragment(s, o, w, field(w, 0, K_module), 1, 1)
    lit(o, w, ',\n  "normalization": {')
    render_normalization(s, o, w, schema, functions, version)
    lit(o, w, '\n  },\n  "ok": true,\n  "program_sha256": ')
    quoted_hash(o, w)
    if version == 56:
        lit(o, w, ',\n  "schema": "hepta.hia.inspect.v2"\n}\n')
    else:
        lit(o, w, ',\n  "schema": "hepta.hia.inspect.v1"\n}\n')
    size = get(w, 56)
    if size > length(o):
        return 4294967294
    return size

def render_function(s:readbuf, o:mutbuf, w:mutbuf, fn:u64, version:u64) -> u64:
    lit(o, w, '\n      "blocks": [')
    block = child(w, field(w, fn, K_blocks))
    while block != NONE:
        lit(o, w, '\n        {\n          "id": ')
        fragment(s, o, w, field(w, block, K_id), 5, 1)
        lit(o, w, ',\n          "operations": [')
        ins = child(w, field(w, block, K_ops))
        index = 0
        while ins != NONE:
            lit(o, w, '\n            {\n              "args": ')
            fragment(s, o, w, field(w, ins, K_args), 7, 1)
            lit(o, w, ',\n              "attrs": ')
            fragment(s, o, w, field(w, ins, K_attrs), 7, 1)
            lit(o, w, ',\n              "index": ')
            number(o, w, index)
            lit(o, w, ',\n              "op": ')
            fragment(s, o, w, field(w, ins, K_op), 7, 1)
            lit(o, w, ',\n              "out": ')
            fragment(s, o, w, field(w, ins, K_out), 7, 1)
            lit(o, w, '\n            }')
            index = index + 1
            ins = next_node(w, ins)
            comma(o, w, ins)
        if index != 0:
            lit(o, w, '\n          ')
        lit(o, w, '],\n          "params": ')
        fragment(s, o, w, field(w, block, K_params), 5, 1)
        lit(o, w, ',\n          "term": ')
        fragment(s, o, w, field(w, block, K_term), 5, 1)
        lit(o, w, '\n        }')
        block = next_node(w, block)
        comma(o, w, block)
    lit(o, w, '\n      ],\n      "effects": ')
    fragment(s, o, w, field(w, fn, K_effects), 3, 1)
    lit(o, w, ',\n      "name": ')
    fragment(s, o, w, field(w, fn, K_name), 3, 1)
    lit(o, w, ',\n      "params": ')
    fragment(s, o, w, field(w, fn, K_params), 3, 1)
    returns = field(w, fn, K_returns)
    if version == 56:
        lit(o, w, ',\n      "return_loans": ')
        loans = field(w, fn, K_return_loans)
        if loans != NONE:
            fragment(s, o, w, loans, 3, 1)
        else:
            lit(o, w, '[')
            slot = child(w, returns)
            while slot != NONE:
                lit(o, w, '\n        null')
                slot = next_node(w, slot)
                comma(o, w, slot)
            if count(w, returns) != 0:
                lit(o, w, '\n      ')
            lit(o, w, ']')
    lit(o, w, ',\n      "returns": ')
    return fragment(s, o, w, returns, 3, 1)

def render_normalization(s:readbuf, o:mutbuf, w:mutbuf, schema:u64, functions:u64, version:u64) -> u64:
    lit(o, w, '\n    "core_profile": ')
    profile(o, w, version)
    lit(o, w, ',\n    "core_schema": ')
    fragment(s, o, w, schema, 2, 1)
    lit(o, w, ',\n    "core_sha256": ')
    quoted_hash(o, w)
    lit(o, w, ',\n    "input_profile": ')
    profile(o, w, version)
    lit(o, w, ',\n    "input_schema": ')
    fragment(s, o, w, schema, 2, 1)
    lit(o, w, ',\n    "input_sha256": ')
    quoted_hash(o, w)
    lit(o, w, ',\n    "primitive_core_rechecked": true,\n    "public_scalar_entrypoints": [')
    base = length(w) - 9280
    size = export_names(w, functions, base)
    i = 0
    while i < size:
        lit(o, w, '\n      ')
        fragment(s, o, w, get(w, base + i * 8), 3, 1)
        i = i + 1
        if i < size:
            lit(o, w, ',')
    if size != 0:
        lit(o, w, '\n    ')
    lit(o, w, '],\n    "source_ast_required": false,\n    "structured_elaboration_rechecked": false')
    return 0

def export_names(w:mutbuf, functions:u64, base:u64) -> u64:
    explicit = field(w, 0, K_exports)
    size = 0
    if explicit != NONE:
        name = child(w, explicit)
        while name != NONE:
            size = insert_name(w, base, size, name)
            name = next_node(w, name)
    else:
        fn = child(w, functions)
        while fn != NONE:
            scalar = 1
            arg = child(w, field(w, fn, K_params))
            while arg != NONE:
                if scalar_type(w, field(w, arg, K_type)) == 0:
                    scalar = 0
                arg = next_node(w, arg)
            result = child(w, field(w, fn, K_returns))
            while result != NONE:
                if scalar_type(w, result) == 0:
                    scalar = 0
                result = next_node(w, result)
            if scalar == 1:
                size = insert_name(w, base, size, field(w, fn, K_name))
            fn = next_node(w, fn)
    return size

def insert_name(w:mutbuf, base:u64, size:u64, name:u64) -> u64:
    left = 0
    right = size
    while left < right:
        mid = left + ((right - left) >> 1)
        if name_before(w, name, get(w, base + mid * 8)) == 1:
            right = mid
        else:
            left = mid + 1
    at = size
    while at > left:
        put(w, base + at * 8, get(w, base + (at - 1) * 8))
        at = at - 1
    put(w, base + left * 8, name)
    return size + 1

def name_before(w:mutbuf, a:u64, b:u64) -> u64:
    ra = 64 + a * 56
    rb = 64 + b * 56
    aa = get(w, ra + 24)
    bb = get(w, rb + 24)
    na = get(w, ra + 32)
    nb = get(w, rb + 32)
    i = 0
    while i < na and i < nb:
        x = byte(w, aa + i)
        y = byte(w, bb + i)
        if x != y:
            return choose(x < y, 1, 0)
        i = i + 1
    return choose(na < nb, 1, 0)

def scalar_type(w:mutbuf, node:u64) -> u64:
    # The admission kernel already checked the closed primitive type set.
    start = get(w, 64 + node * 56 + 24)
    first = byte(w, start)
    if first == 105 or first == 117:
        return 1
    return choose(first == 98 and byte(w, start + 1) == 111, 1, 0)

def comma(o:mutbuf, w:mutbuf, following:u64) -> u64:
    if following != NONE:
        append_byte(o, w, 44)
    return 0

def number(o:mutbuf, w:mutbuf, value:u64) -> u64:
    # No block can have more instructions than the Core JSON node budget.
    power = 100000
    while power > 1 and value < power:
        power = quotient10(power)
    remaining = value
    while power != 0:
        digit = 0
        while remaining >= power:
            remaining = remaining - power
            digit = digit + 1
        append_byte(o, w, digit + 48)
        power = quotient10(power)
    return 0

def quotient10(value:u64) -> u64:
    if value == 100000:
        return 10000
    if value == 10000:
        return 1000
    if value == 1000:
        return 100
    if value == 100:
        return 10
    return choose(value == 10, 1, 0)

def quoted_hash(o:mutbuf, w:mutbuf) -> u64:
    append_byte(o, w, 34)
    i = 0
    while i < 32:
        word = hash_get(w, 1024 + (i >> 2) * 8)
        value = (word >> ((3 - (i & 3)) * 8)) & 255
        append_byte(o, w, hex_digit(value >> 4))
        append_byte(o, w, hex_digit(value & 15))
        i = i + 1
    append_byte(o, w, 34)
    return 0
'''


def fragment_source():
    pretty = core_pretty_source()
    nodes = ast.parse(pretty).body
    root = nodes[0]
    root.name = 'fragment'
    root.returns.id = 'u64'
    root.args.args += [ast.arg(arg=name, annotation=ast.Name(id='u64', ctx=ast.Load()))
                       for name in ('root', 'base_depth', 'pretty')]
    start = next(i for i, stmt in enumerate(root.body) if isinstance(stmt, ast.Assign)
                 and stmt.targets[0].id == 'node')
    root.body = root.body[start:]
    fragment = ast.unparse(root).replace('node = 0', 'node = root', 1)
    fragment = fragment.replace('depth = 0', 'depth = base_depth', 1)
    fragment = fragment.replace('if parent != 18446744073709551615:', 'if node != root:')
    fragment = fragment.replace('sibling = get(w, record + 16)',
                                'sibling = choose(node == root, NONE, get(w, record + 16))')
    fragment = fragment.replace('if parent == 18446744073709551615:', 'if node == root:')
    fragment = fragment.replace('newline(o, w, depth)', 'pretty_line(o, w, depth, pretty)')
    fragment = fragment.replace('append_byte(o, w, 32)', 'colon_space(o, w, pretty)')
    fragment = fragment[:fragment.rindex('    append_byte(o, w, 10)')] + '    return 0\n'
    helper = ast.unparse(ast.Module(body=nodes[1:], type_ignores=[]))
    return fragment + helper + '''
def pretty_line(o:mutbuf, w:mutbuf, depth:u64, pretty:u64) -> u64:
    if pretty == 1:
        newline(o, w, depth)
    return 0

def colon_space(o:mutbuf, w:mutbuf, pretty:u64) -> u64:
    if pretty == 1:
        append_byte(o, w, 32)
    return 0
'''


def hash_source():
    source = sha_source()
    root = source[source.index('    put(w, 0,'):source.index('    i = 0\n    while i < 8:')]
    root = root.replace('length(s)', 'size').replace('padded_byte(s,', 'padded_byte(o, size,')
    padded = source[source.index('def padded_byte'):source.index('def get(')]
    padded = padded.replace('s:readbuf,', 'o:mutbuf, size:u64,').replace('length(s)', 'size')
    padded = padded.replace('byte(s,', 'byte(o,')
    return ('def digest(o:mutbuf, w:mutbuf, size:u64) -> u64:\n' + root + '    return 0\n' + padded
            ).replace('put(w,', 'hash_put(w,').replace('get(w,', 'hash_get(w,') + '''
def hash_get(w:mutbuf, offset:u64) -> u64:
    return get(w, length(w) - 1088 + offset)

def hash_put(w:mutbuf, offset:u64, value:u64) -> u64:
    return put(w, length(w) - 1088 + offset, value)
'''


def source_program():
    helpers = FRONTEND[FRONTEND.index('def kind('):FRONTEND.index('def shape(')]
    match = FRONTEND[FRONTEND.index('def same('):]
    key_fn = '''def key_id(w:mutbuf, node:u64) -> u64:
    start = get(w, 64 + node * 56 + 40)
    size = get(w, 64 + node * 56 + 48)
'''
    constants = {'NONE': (1 << 64) - 1}
    for i, name in enumerate(KEYS):
        constants['K_' + name] = 1 << i
        key_fn += '    if same(w, start, size, ' + ', '.join(map(str, packed(name))) + ') == 1:\n'
        key_fn += f'        return {1 << i}\n'
    key_fn += '    return 0\n'
    profile = 'def profile(o:mutbuf, w:mutbuf, version:u64) -> u64:\n'
    for index, value in enumerate(PRIMITIVE_PROFILES.values(), ord('1')):
        profile += f'    if version == {index}:\n        lit(o, w, {chr(34) + value + chr(34)!r})\n'
    profile += '    return 0\n'

    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.Constant(constants[node.id]) if node.id in constants else node

        def visit_Expr(self, node):
            call = node.value
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id == 'lit'):
                o, w, literal = call.args
                value = literal.value
                return [ast.Expr(ast.Call(ast.Name('emit', ast.Load()),
                                         [o, w, *map(ast.Constant, packed(value[i:i+24]))], []))
                        for i in range(0, len(value), 24)]
            return self.generic_visit(node)

    source = POLICY + profile + fragment_source() + helpers + match + key_fn + hash_source() + decoder()
    return ast.unparse(ast.fix_missing_locations(Expand().visit(ast.parse(source))))


def main():
    file = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_inspect_json.hepta'
    file.write_text(render_assembly(document(source_program(), 'core_inspect_json')))


if __name__ == '__main__':
    main()
