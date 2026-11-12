"""Author the ordinary inspect transformation in HIA.

Core verification and structured elaboration remain adjacent and mandatory.
The image owns both hashes, profile/entrypoint selection and the complete inspect
report. Python supplies exact captured bytes and transports the native report.
"""
from __future__ import annotations
import ast
import json
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_opcodes import SCALARS
from hepta.hia_schema import PRIMITIVE_PROFILES, COMPOSITE_PROFILES
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_sha256 import source_program as hash_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

REQUEST_MAGIC = int.from_bytes(b'HIAINSQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAINSR1', 'little')
LITERALS = {
  "schema": "schema",
  "module": "module",
  "name": "name",
  "params": "params",
  "returns": "returns",
  "effects": "effects",
  "return_loans": "return_loans",
  "blocks": "blocks",
  "id": "id",
  "ops": "ops",
  "term": "term",
  "functions": "functions",
  "exports": "exports",
  "type": "type",
  "report_start": "{\"schema\":",
  "inspect_v1": "\"hepta.hia.inspect.v1\"",
  "inspect_v2": "\"hepta.hia.inspect.v2\"",
  "ok_hash": ",\"ok\":true,\"program_sha256\":",
  "module_colon": ",\"module\":",
  "input_hash_colon": ",\"input_sha256\":",
  "normalization_start": ",\"normalization\":{\"input_sha256\":",
  "core_hash_colon": ",\"core_sha256\":",
  "input_schema_colon": ",\"input_schema\":",
  "input_profile_colon": ",\"input_profile\":",
  "core_schema_colon": ",\"core_schema\":",
  "core_profile_colon": ",\"core_profile\":",
  "structured_colon": ",\"structured_elaboration_rechecked\":",
  "true": "true",
  "false": "false",
  "null": "null",
  "normalization_rest": ",\"primitive_core_rechecked\":true,\"source_ast_required\":false,\"public_scalar_entrypoints\":",
  "functions_start": "},\"functions\":[",
  "claims_end": "],\"claims\":{\"native_executed\":false,\"whole_language_soundness_proved\":false}}",
  "function_start": "{\"name\":",
  "params_colon": ",\"params\":",
  "returns_colon": ",\"returns\":",
  "effects_colon": ",\"effects\":",
  "return_loans_colon": ",\"return_loans\":",
  "blocks_start": ",\"blocks\":[",
  "array_object_end": "]}",
  "block_start": "{\"id\":",
  "operations_start": ",\"operations\":[",
  "term_colon": "],\"term\":",
  "operation_start": "{\"index\":",
  "escape_b": "\\b",
  "escape_t": "\\t",
  "escape_n": "\\n",
  "escape_f": "\\f",
  "escape_r": "\\r",
  "escape_u": "\\u00"
}
SOURCE = r'''
def inspect_entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64 or length(w) < 32768 or length(o) < 4194304:
        return 4294967293
    if read_word(s, 0) != REQUEST_MAGIC or read_word(s, 8) != 1:
        return 4294967293
    size = read_word(s, 16)
    original_size = read_word(s, 24)
    structured = read_word(s, 32)
    if size == 0 or size > 8388608 or original_size > 8388608 or structured > 1:
        return 4294967293
    if (structured == 0 and original_size != 0) or (structured == 1 and original_size == 0):
        return 4294967293
    if read_word(s, 40) != 0 or read_word(s, 48) != 0 or read_word(s, 56) != 0:
        return 4294967293
    if length(s) != 64 + size + original_size:
        return 4294967293
    largest = size
    if original_size > largest:
        largest = original_size
    nodes = ((largest + 1) >> 1) + 1
    if nodes > 262144:
        nodes = 262144
    if length(w) < 64 + nodes * 56 + largest + 32768:
        return 4294967293
    if length(o) < 4 * largest + 1048576:
        return 4294967293
    state = length(w) - 32768
    put(w, state + 32, structured)
    put(w, state + 72, size)
    if widen(hash_sha256(s, o, w, (size << 32) | 64)) != 32:
        return 4294967293
    i = 0
    while i < 4:
        put(w, state + 128 + i * 8, get(o, i * 8))
        put(w, state + 160 + i * 8, get(o, i * 8))
        i = i + 1
    if structured == 1:
        if widen(hash_sha256(s, o, w, (original_size << 32) | (64 + size))) != 32:
            return 4294967293
        i = 0
        while i < 4:
            put(w, state + 160 + i * 8, get(o, i * 8))
            i = i + 1
        put(o, 48, 262144)
        put(o, 56, 64)
        result = widen(decode_json(s, w, o, (original_size << 32) | (64 + size)))
        if result > length(w) - 32768:
            return 4294967292
        input_schema = schema_id(w, field(w, 0, L_schema))
        if input_schema < 9 or input_schema > 12:
            return 4294967292
        put(w, state + 24, input_schema)
    put(o, 48, 262144)
    put(o, 56, 64)
    result = widen(decode_json(s, w, o, (size << 32) | 64))
    if result > length(w) - 32768:
        return 4294967292
    core_schema = schema_id(w, field(w, 0, L_schema))
    if core_schema < 1 or core_schema > 8:
        return 4294967292
    put(w, state + 16, core_schema)
    if structured == 0:
        put(w, state + 24, core_schema)
    put(w, 56, state)
    put(w, state, 64)
    put(w, state + 8, 0)
    put(w, state + 40, 0)
    put(w, state + 48, 0)
    put(w, state + 56, 0)
    put(w, state + 64, 0)
    i = 0
    while i < 64:
        store(o, i, 0)
        i = i + 1
    collect_public(w)
    sort_public(w)
    report(s, o, w)
    if get(w, state + 8) != 0:
        return 4294967291
    put(o, 8, 1)
    put(o, 16, get(w, state) - 64)
    put(o, 24, get(w, state + 40))
    put(o, 32, get(w, state + 48))
    put(o, 40, get(w, state + 56))
    put(o, 48, structured)
    put(o, 56, 0)
    put(o, 0, RESULT_MAGIC)
    return get(w, state)

def report(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    state = get(w, 56)
    emit(o, w, L_report_start)
    if get(w, state + 16) == 8:
        emit(o, w, L_inspect_v2)
    else:
        emit(o, w, L_inspect_v1)
    emit(o, w, L_ok_hash)
    digest_out(o, w, state + 128)
    emit(o, w, L_module_colon)
    copy_tree(s, o, w, field(w, 0, L_module))
    emit(o, w, L_input_hash_colon)
    digest_out(o, w, state + 160)
    emit(o, w, L_normalization_start)
    digest_out(o, w, state + 160)
    emit(o, w, L_core_hash_colon)
    digest_out(o, w, state + 128)
    emit(o, w, L_input_schema_colon)
    schema_out(o, w, get(w, state + 24))
    emit(o, w, L_input_profile_colon)
    profile_out(o, w, get(w, state + 24))
    emit(o, w, L_core_schema_colon)
    schema_out(o, w, get(w, state + 16))
    emit(o, w, L_core_profile_colon)
    profile_out(o, w, get(w, state + 16))
    emit(o, w, L_structured_colon)
    if get(w, state + 32) == 1:
        emit(o, w, L_true)
    else:
        emit(o, w, L_false)
    emit(o, w, L_normalization_rest)
    public_out(o, w)
    emit(o, w, L_functions_start)
    functions = field(w, 0, L_functions)
    if kind(w, functions) != 5 or count(w, functions) > 1024:
        mark(w)
        return 0
    put(w, state + 40, count(w, functions))
    fn = child(w, functions)
    first = 1
    while fn != NONE:
        if first == 0:
            one(o, w, 44)
        first = 0
        function_out(s, o, w, fn)
        fn = next_node(w, fn)
    emit(o, w, L_claims_end)
    return 0

def function_out(s:readbuf, o:mutbuf, w:mutbuf, fn:u64) -> u64:
    emit(o, w, L_function_start)
    copy_tree(s, o, w, field(w, fn, L_name))
    emit(o, w, L_params_colon)
    copy_tree(s, o, w, field(w, fn, L_params))
    emit(o, w, L_returns_colon)
    returns = field(w, fn, L_returns)
    copy_tree(s, o, w, returns)
    emit(o, w, L_effects_colon)
    copy_tree(s, o, w, field(w, fn, L_effects))
    if get(w, get(w, 56) + 16) == 8:
        emit(o, w, L_return_loans_colon)
        loans = field(w, fn, L_return_loans)
        if loans != NONE:
            copy_tree(s, o, w, loans)
        else:
            one(o, w, 91)
            i = 0
            while i < count(w, returns):
                if i != 0:
                    one(o, w, 44)
                emit(o, w, L_null)
                i = i + 1
            one(o, w, 93)
    emit(o, w, L_blocks_start)
    blocks = field(w, fn, L_blocks)
    if kind(w, blocks) != 5 or count(w, blocks) > 4096:
        mark(w)
        return 0
    block = child(w, blocks)
    first = 1
    while block != NONE:
        if first == 0:
            one(o, w, 44)
        first = 0
        block_out(s, o, w, block)
        block = next_node(w, block)
    emit(o, w, L_array_object_end)
    return 0

def block_out(s:readbuf, o:mutbuf, w:mutbuf, block:u64) -> u64:
    state = get(w, 56)
    put(w, state + 48, get(w, state + 48) + 1)
    emit(o, w, L_block_start)
    copy_tree(s, o, w, field(w, block, L_id))
    emit(o, w, L_params_colon)
    copy_tree(s, o, w, field(w, block, L_params))
    emit(o, w, L_operations_start)
    operations = field(w, block, L_ops)
    if kind(w, operations) != 5:
        mark(w)
        return 0
    node = child(w, operations)
    index = 0
    while node != NONE:
        if index != 0:
            one(o, w, 44)
        operation_out(s, o, w, node, index)
        index = index + 1
        node = next_node(w, node)
    put(w, state + 56, get(w, state + 56) + index)
    emit(o, w, L_term_colon)
    copy_tree(s, o, w, field(w, block, L_term))
    one(o, w, 125)
    return 0

def operation_out(s:readbuf, o:mutbuf, w:mutbuf, node:u64, index:u64) -> u64:
    if kind(w, node) != 6:
        mark(w)
        return 0
    emit(o, w, L_operation_start)
    unsigned_out(o, w, index)
    item = child(w, node)
    while item != NONE:
        one(o, w, 44)
        key_out(o, w, item)
        copy_tree(s, o, w, item)
        item = next_node(w, item)
    one(o, w, 125)
    return 0

def collect_public(w:mutbuf) -> u64:
    state = get(w, 56)
    exports = field(w, 0, L_exports)
    if exports != NONE:
        if kind(w, exports) != 5 or count(w, exports) > 1024:
            mark(w)
            return 0
        item = child(w, exports)
        while item != NONE:
            add_public(w, item)
            item = next_node(w, item)
    else:
        functions = field(w, 0, L_functions)
        if kind(w, functions) != 5 or count(w, functions) > 1024:
            mark(w)
            return 0
        fn = child(w, functions)
        while fn != NONE:
            ready = 1
            params = field(w, fn, L_params)
            returns = field(w, fn, L_returns)
            if kind(w, params) != 5 or kind(w, returns) != 5:
                mark(w)
                return 0
            item = child(w, params)
            while item != NONE:
                if scalar_type(w, field(w, item, L_type)) == 0:
                    ready = 0
                item = next_node(w, item)
            item = child(w, returns)
            while item != NONE:
                if scalar_type(w, item) == 0:
                    ready = 0
                item = next_node(w, item)
            if ready == 1:
                add_public(w, field(w, fn, L_name))
            fn = next_node(w, fn)
    return 0

def add_public(w:mutbuf, node:u64) -> u64:
    state = get(w, 56)
    amount = get(w, state + 64)
    if kind(w, node) != 4 or amount >= 1024:
        mark(w)
        return 0
    put(w, state + 256 + amount * 8, node)
    put(w, state + 64, amount + 1)
    return 0

def sort_public(w:mutbuf) -> u64:
    state = get(w, 56)
    amount = get(w, state + 64)
    width = 1
    while width < amount:
        left = 0
        while left < amount:
            middle = left + width
            if middle > amount:
                middle = amount
            end = middle + width
            if end > amount:
                end = amount
            i = left
            j = middle
            at = left
            while at < end:
                take_left = 0
                if i < middle:
                    if j == end:
                        take_left = 1
                    else:
                        if text_le(w, get(w, state + 256 + i * 8), get(w, state + 256 + j * 8)) != 0:
                            take_left = 1
                if take_left == 1:
                    put(w, state + 8448 + at * 8, get(w, state + 256 + i * 8))
                    i = i + 1
                else:
                    put(w, state + 8448 + at * 8, get(w, state + 256 + j * 8))
                    j = j + 1
                at = at + 1
            left = end
        at = 0
        while at < amount:
            put(w, state + 256 + at * 8, get(w, state + 8448 + at * 8))
            at = at + 1
        width = width * 2
    return 0

def text_le(w:mutbuf, a:u64, b:u64) -> u64:
    ap = get(w, 64 + a * 56 + 24)
    bp = get(w, 64 + b * 56 + 24)
    an = count(w, a)
    bn = count(w, b)
    i = 0
    while i < an and i < bn:
        av = byte(w, ap + i)
        bv = byte(w, bp + i)
        if av < bv:
            return 1
        if av > bv:
            return 0
        i = i + 1
    if an <= bn:
        return 1
    return 0

def public_out(o:mutbuf, w:mutbuf) -> u64:
    state = get(w, 56)
    one(o, w, 91)
    i = 0
    while i < get(w, state + 64):
        if i != 0:
            one(o, w, 44)
        node = get(w, state + 256 + i * 8)
        quote(o, w, get(w, 64 + node * 56 + 24), count(w, node))
        i = i + 1
    one(o, w, 93)
    return 0

def copy_tree(s:readbuf, o:mutbuf, w:mutbuf, root:u64) -> u64:
    if root == NONE:
        mark(w)
        return 0
    node = root
    entering = 1
    steps = 0
    while steps < get(w, 8) * 2 + 1:
        steps = steps + 1
        if entering == 1:
            tag = kind(w, node)
            if tag == 5 or tag == 6:
                if tag == 5:
                    one(o, w, 91)
                else:
                    one(o, w, 123)
                first = child(w, node)
                if first == NONE:
                    if tag == 5:
                        one(o, w, 93)
                    else:
                        one(o, w, 125)
                    entering = 0
                else:
                    if tag == 6:
                        key_out(o, w, first)
                    node = first
            else:
                atom_out(s, o, w, node)
                entering = 0
        else:
            if node == root:
                return 0
            following = next_node(w, node)
            parent = get(w, 64 + node * 56 + 8)
            if following != NONE:
                one(o, w, 44)
                if kind(w, parent) == 6:
                    key_out(o, w, following)
                node = following
                entering = 1
            else:
                if kind(w, parent) == 5:
                    one(o, w, 93)
                else:
                    one(o, w, 125)
                node = parent
    mark(w)
    return 0

def atom_out(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:
    tag = kind(w, node)
    if tag == 0:
        emit(o, w, L_null)
        return 0
    if tag == 1:
        emit(o, w, L_false)
        return 0
    if tag == 2:
        emit(o, w, L_true)
        return 0
    start = get(w, 64 + node * 56 + 24)
    amount = count(w, node)
    if tag == 4:
        quote(o, w, start, amount)
        return 0
    if tag != 3 or start > get(w, get(w, 56) + 72) or amount > get(w, get(w, 56) + 72) - start:
        mark(w)
        return 0
    i = 0
    while i < amount:
        one(o, w, byte(s, 64 + start + i))
        i = i + 1
    return 0

def key_out(o:mutbuf, w:mutbuf, node:u64) -> u64:
    quote(o, w, get(w, 64 + node * 56 + 40), get(w, 64 + node * 56 + 48))
    one(o, w, 58)
    return 0

def quote(o:mutbuf, w:mutbuf, start:u64, amount:u64) -> u64:
    one(o, w, 34)
    i = 0
    while i < amount:
        value = byte(w, start + i)
        if value == 34 or value == 92:
            one(o, w, 92)
            one(o, w, value)
        else:
            if value < 32:
                if value == 8:
                    emit(o, w, L_escape_b)
                else:
                    if value == 9:
                        emit(o, w, L_escape_t)
                    else:
                        if value == 10:
                            emit(o, w, L_escape_n)
                        else:
                            if value == 12:
                                emit(o, w, L_escape_f)
                            else:
                                if value == 13:
                                    emit(o, w, L_escape_r)
                                else:
                                    emit(o, w, L_escape_u)
                                    one(o, w, hex_digit(value >> 4))
                                    one(o, w, hex_digit(value & 15))
            else:
                one(o, w, value)
        i = i + 1
    one(o, w, 34)
    return 0

def unsigned_out(o:mutbuf, w:mutbuf, value:u64) -> u64:
    start = get(w, 56) + 200
    amount = 0
    while value >= 10:
        quotient = divide_ten(value)
        store(w, start + amount, 48 + value - quotient * 10)
        amount = amount + 1
        value = quotient
    store(w, start + amount, 48 + value)
    amount = amount + 1
    while amount != 0:
        amount = amount - 1
        one(o, w, byte(w, start + amount))
    return 0

def divide_ten(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit != 0:
        bit = bit - 1
        remainder = (remainder << 1) | ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def digest_out(o:mutbuf, w:mutbuf, start:u64) -> u64:
    one(o, w, 34)
    i = 0
    while i < 32:
        value = byte(w, start + i)
        one(o, w, hex_digit(value >> 4))
        one(o, w, hex_digit(value & 15))
        i = i + 1
    one(o, w, 34)
    return 0

def hex_digit(value:u64) -> u64:
    if value < 10:
        return 48 + value
    return 87 + value

def one(o:mutbuf, w:mutbuf, value:u64) -> u64:
    state = get(w, 56)
    index = get(w, state)
    if get(w, state + 8) == 0:
        if index < length(o):
            store(o, index, value)
            put(w, state, index + 1)
        else:
            mark(w)
    return 0

def emit(o:mutbuf, w:mutbuf, size:u64, a:u64, b:u64, c:u64) -> u64:
    i = 0
    while i < size:
        value = a
        shift = i
        if i >= 8:
            value = b
            shift = i - 8
        if i >= 16:
            value = c
            shift = i - 16
        one(o, w, (value >> (shift * 8)) & 255)
        i = i + 1
    return 0

def mark(w:mutbuf) -> u64:
    put(w, get(w, 56) + 8, 1)
    return 0

def kind(w:mutbuf, node:u64) -> u64:
    if node == NONE or node >= get(w, 8):
        return NONE
    return get(w, 64 + node * 56)

def count(w:mutbuf, node:u64) -> u64:
    if node == NONE or node >= get(w, 8):
        return 0
    return get(w, 64 + node * 56 + 32)

def child(w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 5 and kind(w, node) != 6:
        return NONE
    return get(w, 64 + node * 56 + 24)

def next_node(w:mutbuf, node:u64) -> u64:
    if node == NONE or node >= get(w, 8):
        return NONE
    return get(w, 64 + node * 56 + 16)

def field(w:mutbuf, node:u64, size:u64, a:u64, b:u64, c:u64) -> u64:
    if kind(w, node) != 6:
        return NONE
    item = child(w, node)
    while item != NONE:
        start = get(w, 64 + item * 56 + 40)
        amount = get(w, 64 + item * 56 + 48)
        if same(w, start, amount, size, a, b, c) != 0:
            return item
        item = next_node(w, item)
    return NONE

def text_is(w:mutbuf, node:u64, size:u64, a:u64, b:u64, c:u64) -> u64:
    if kind(w, node) != 4:
        return 0
    return same(w, get(w, 64 + node * 56 + 24), count(w, node), size, a, b, c)

def same(w:mutbuf, start:u64, amount:u64, size:u64, a:u64, b:u64, c:u64) -> u64:
    if amount != size:
        return 0
    i = 0
    while i < size:
        value = a
        shift = i
        if i >= 8:
            value = b
            shift = i - 8
        if i >= 16:
            value = c
            shift = i - 16
        if byte(w, start + i) != ((value >> (shift * 8)) & 255):
            return 0
        i = i + 1
    return 1

def read_word(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value
'''

def packed(text):
    raw = text.encode('utf-8')
    if len(raw) > 24:
        raise ValueError('packed text exceeds three native words')
    return (len(raw), *(int.from_bytes(raw[i:i+8].ljust(8, b'\0'), 'little')
                         for i in (0, 8, 16)))


def _sliced(nodes):
    names = {node.name for node in nodes if any(
        arg.arg == 's' and isinstance(arg.annotation, ast.Name)
        and arg.annotation.id == 'readbuf' for arg in node.args.args)}
    class Slice(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            self.active = node.name in names
            if self.active:
                node.args.args.append(ast.arg(arg='source_view', annotation=ast.Name(id='u64', ctx=ast.Load())))
            node = self.generic_visit(node)
            self.active = False
            return node
        def visit_Call(self, node):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name):
                if self.active and node.func.id == 'length' and len(node.args) == 1 and isinstance(node.args[0], ast.Name) and node.args[0].id == 's':
                    return ast.BinOp(left=ast.Name(id='source_view', ctx=ast.Load()), op=ast.RShift(), right=ast.Constant(32))
                if self.active and node.func.id == 'byte' and isinstance(node.args[0], ast.Name) and node.args[0].id == 's':
                    node.args[1] = ast.BinOp(left=ast.BinOp(left=ast.Name(id='source_view', ctx=ast.Load()),
                        op=ast.BitAnd(), right=ast.Constant(4294967295)), op=ast.Add(), right=node.args[1])
                if node.func.id in names:
                    if not self.active:
                        raise ValueError('read-only source view escaped its source-bearing function')
                    node.args.append(ast.Name(id='source_view', ctx=ast.Load()))
            return node
    return Slice().visit(ast.Module(body=nodes, type_ignores=[])).body


def source_program():
    constants = {'REQUEST_MAGIC': REQUEST_MAGIC, 'RESULT_MAGIC': RESULT_MAGIC, 'NONE': (1 << 64)-1}
    class Expand(ast.NodeTransformer):
        def visit_Expr(self, node):
            call = node.value
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == 'emit':
                label = call.args[-1]
                if isinstance(label, ast.Name) and label.id.startswith('L_'):
                    raw = LITERALS[label.id[2:]]
                    # All report syntax/profile literals are ASCII; slicing at
                    # 24 codepoints therefore also slices at 24 wire bytes.
                    if not raw.isascii():
                        raise ValueError('non-ASCII static inspect syntax')
                    return [ast.Expr(value=ast.Call(func=ast.Name(id='emit', ctx=ast.Load()),
                        args=[ast.Name(id='o', ctx=ast.Load()), ast.Name(id='w', ctx=ast.Load()),
                              *[ast.Constant(x) for x in packed(raw[i:i+24])]], keywords=[]))
                        for i in range(0, len(raw), 24)]
            return self.generic_visit(node)
        def visit_Call(self, node):
            node = self.generic_visit(node)
            args = []
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id.startswith('L_'):
                    args.extend(ast.Constant(x) for x in packed(LITERALS[arg.id[2:]]))
                else:
                    args.append(arg)
            node.args = args
            return node
        def visit_Name(self, node):
            return ast.Constant(constants[node.id]) if node.id in constants else node

    extra = ['def schema_id(w:mutbuf, node:u64) -> u64:']
    profiles = list(PRIMITIVE_PROFILES.items()) + list(COMPOSITE_PROFILES.items())
    for i, (schema, profile) in enumerate(profiles, 1):
        LITERALS['schema_' + str(i)] = schema
        LITERALS['quoted_schema_' + str(i)] = json.dumps(schema)
        LITERALS['profile_' + str(i)] = json.dumps(profile)
        extra += [f'    if text_is(w, node, L_schema_{i}) != 0:', f'        return {i}']
    extra += ['    return 0', '', 'def schema_out(o:mutbuf, w:mutbuf, schema:u64) -> u64:']
    for i in range(1, 13):
        extra += [f'    if schema == {i}:', f'        emit(o, w, L_quoted_schema_{i})', '        return 0']
    extra += ['    mark(w)', '    return 0', '', 'def profile_out(o:mutbuf, w:mutbuf, schema:u64) -> u64:']
    for i in range(1, 13):
        extra += [f'    if schema == {i}:', f'        emit(o, w, L_profile_{i})', '        return 0']
    extra += ['    mark(w)', '    return 0', '', 'def scalar_type(w:mutbuf, node:u64) -> u64:']
    for i, name in enumerate(sorted(SCALARS)):
        LITERALS['scalar_' + str(i)] = name
        extra += [f'    if text_is(w, node, L_scalar_{i}) != 0:', '        return 1']
    extra += ['    return 0']
    primary = Expand().visit(ast.parse(SOURCE + '\n' + '\n'.join(extra))).body

    # Both pre-existing algorithms are retained as complete source ASTs.
    # The only decoder change is a bounded read-only view. Hash helpers are
    # renamed to avoid collisions before receiving that same view transform.
    decoder = _sliced(ast.parse(decoder_source()).body)
    hash_nodes = ast.parse(hash_source()).body
    hash_names = {node.name: 'hash_' + node.name for node in hash_nodes}
    class Rename(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            node.name = hash_names[node.name]
            return self.generic_visit(node)
        def visit_Name(self, node):
            if node.id in hash_names:
                node.id = hash_names[node.id]
            return node
    hashes = _sliced(Rename().visit(ast.Module(body=hash_nodes, type_ignores=[])).body)
    nodes = primary + decoder + hashes
    if len({node.name for node in nodes}) != len(nodes):
        raise ValueError('duplicate inspect authoring function')
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])))


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'cli_inspect', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/cli_inspect.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
