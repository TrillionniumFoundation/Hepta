"""Bootstrap authoring for the snapshot-bound HIA Core patch transducer.

The checked-in HIA source performs parsing, canonical SHA-256, four edit kinds,
overlap and interface policy, and candidate serialization. This authoring tool
is not used by the native transducer. Whole Core admission is a mandatory
separate stage before and after it, never inferred from a matching digest.
"""
from __future__ import annotations
import ast
import json
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed, source_program as frontend_source
from tools.generate_hia_sha256 import source_program as sha_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIAPAT01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAPAR01', 'little')
KEYS = ('schema', 'expected_sha256', 'interface_policy', 'edits', 'action',
        'function', 'definition', 'block', 'index', 'operation', 'term',
        'functions', 'name', 'params', 'returns', 'effects', 'return_loans',
        'blocks', 'id', 'ops')
LITERALS = {'patch_v1':'hepta.hia.patch.v1', 'patch_v2':'hepta.hia.patch.v2',
            'preserve':'preserve', 'migrate':'migrate',
            'replace_function':'replace_function', 'add_function':'add_function',
            'replace_operation':'replace_operation', 'replace_terminator':'replace_terminator'}
PUBLIC_DIAGNOSTICS = {
    0xfffffffa: 'invalid expected snapshot digest',
    0xfffffff9: 'stale base snapshot',
    0xfffffff8: 'patch needs 1..64 edits',
    0xfffffff4: 'invalid operation index',
    0xfffffff7: 'unknown edit action',
    0xffffffe1: 'edit needs an action',
    0xffffffe2: 'function identity must be a string',
    0xffffffe3: 'function not found',
    0xffffffe4: 'added function already exists',
    0xffffffe5: 'block identity must be a string',
    0xffffffe6: 'block not found',
    0xffffffe7: 'duplicate operation edit',
    0xffffffe8: 'duplicate terminator edit',
    0xffffffe9: 'overlapping whole-function and local edits',
    0xffffffea: 'v2 interface_policy must be preserve or migrate',
    0xffffffeb: 'unsupported patch schema',
    0xffffffec: 'patch requires exactly its declared fields; unknown or missing fields',
    0xffffffed: 'function edit requires exactly its declared fields; unknown or missing fields',
    0xffffffee: 'operation edit requires exactly its declared fields; unknown or missing fields',
    0xffffffef: 'terminator edit requires exactly its declared fields; unknown or missing fields',
    0xfffffff0: 'function edit must retain its declared identity',
}
PUBLIC_STATUS = {
    'D_ACTION_TYPE': (0xffffffe1, 0xfffffff7),
    'D_FUNCTION_TYPE': (0xffffffe2, 0xfffffff6),
    'D_FUNCTION_ABSENT': (0xffffffe3, 0xfffffff6),
    'D_FUNCTION_EXISTS': (0xffffffe4, 0xfffffff6),
    'D_BLOCK_TYPE': (0xffffffe5, 0xfffffff5),
    'D_BLOCK_ABSENT': (0xffffffe6, 0xfffffff5),
    'D_DUPLICATE_OP': (0xffffffe7, 0xfffffff3),
    'D_DUPLICATE_TERM': (0xffffffe8, 0xfffffff3),
    'D_OVERLAP': (0xffffffe9, 0xfffffff3),
    'D_POLICY': (0xffffffea, 0xfffffffb),
    'D_SCHEMA': (0xffffffeb, 0xfffffffb),
    'D_PATCH_FIELDS': (0xffffffec, 0xfffffffb),
    'D_FUNCTION_FIELDS': (0xffffffed, 0xfffffffb),
    'D_OPERATION_FIELDS': (0xffffffee, 0xfffffffb),
    'D_TERMINATOR_FIELDS': (0xffffffef, 0xfffffffb),
    'D_DEFINITION': (0xfffffff0, 0xfffffff6),
}

BODY = r'''
def patch_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8192 or length(o) < 8192 or length(s) > 16777219:
        return 4294967293
    mode = get(w, 0)
    declared = 0
    if mode == 2:
        declared = get(w, 8)
        if declared < 1 or declared > 2:
            return 4294967293
    if mode > 2:
        return 4294967293
    put(o, 48, 524289)
    put(o, 56, 129)
    status = widen(decode_json(s, w, o))
    if status >= 4294967292:
        return status
    if kind(w, 0) != 5 or count(w, 0) != 2:
        return 4294967291
    base = child(w, 0)
    request = next_node(w, base)
    if kind(w, base) != 6 or kind(w, request) != 6:
        return 4294967291
    # Strict decoding has established the envelope grammar. Count the actual
    # object spans as well as canonical output: internal whitespace must not
    # conceal a component exceeding the existing 8-MiB input quota.
    start = whitespace(s, whitespace(s, 0) + 1)
    end = component_end(s, start)
    if end - start > 8388608:
        return 4294967294
    start = whitespace(s, whitespace(s, end) + 1)
    end = component_end(s, start)
    if end - start > 8388608:
        return 4294967294
    scratch = get(w, 32)
    if scratch > length(w) or length(w) - scratch < 8192:
        return 4294967293
    put(w, 40, scratch)
    put(w, scratch + 1280, mode)
    put(w, scratch + 1288, declared)
    put(w, scratch + 1296, 0)
    put(w, 48, 0)
    put(w, 56, 32)
    render_fragment(s, o, w, base)
    size = get(w, 56)
    if get(w, 48) != 0 or size > 8388640:
        return 4294967294
    # The extractor grants no semantic or mutation authority. Its caller must
    # check the complete original Core before invoking application mode.
    if mode == 0:
        put(o, 0, MAGIC)
        put(o, 8, 0)
        put(o, 16, 0)
        put(o, 24, 0)
        return size
    if tree_limit(w, base, 64) == 0 or tree_limit(w, request, 128) == 0:
        return 4294967294
    tag = field(w, request, K_schema)
    v1 = text_is(w, tag, L_patch_v1)
    v2 = text_is(w, tag, L_patch_v2)
    if v1 == 0 and v2 == 0:
        return D_SCHEMA
    if mode == 2:
        if declared == 1 and v1 == 0:
            return 4294967281
        if declared == 2 and v2 == 0:
            return 4294967281
    schema = 0
    policy = 0
    if v1 != 0:
        schema = 1
        if shape(w, request, K_schema | K_expected_sha256 | K_edits) == 0:
            return D_PATCH_FIELDS
    else:
        schema = 2
        if shape(w, request, K_schema | K_expected_sha256 | K_edits | K_interface_policy) == 0:
            return D_PATCH_FIELDS
        selected = field(w, request, K_interface_policy)
        if text_is(w, selected, L_migrate) != 0:
            policy = 1
        elif text_is(w, selected, L_preserve) == 0:
            return D_POLICY
    expected = field(w, request, K_expected_sha256)
    if kind(w, expected) != 4 or count(w, expected) != 64:
        return 4294967290
    digest_fragment(o, w, size - 32)
    offset = get(w, 64 + expected * 56 + 24)
    i = 0
    mismatch = False
    while i < 32:
        a = lower_nibble(byte(w, offset + i * 2))
        b = lower_nibble(byte(w, offset + i * 2 + 1))
        if a > 15 or b > 15:
            return 4294967290
        mismatch = mismatch or byte(w, scratch + 1088 + i) != ((a << 4) | b)
        i = i + 1
    if mismatch:
        return 4294967289
    edits = field(w, request, K_edits)
    if kind(w, edits) != 5 or count(w, edits) < 1 or count(w, edits) > 64:
        return 4294967288
    functions = field(w, base, K_functions)
    if kind(w, functions) != 5:
        return 4294967291
    # Bound the independent patch component before any tree mutation. Its
    # canonical form cannot hide oversized nested values or a huge node set.
    put(w, 56, 32)
    render_fragment(s, o, w, request)
    if get(w, 48) != 0 or get(w, 56) > 8388640:
        return 4294967294
    applied = apply_edits(s, o, w, functions, edits, policy)
    if applied >= 4294967264:
        return applied
    put(w, 56, 32)
    render_fragment(s, o, w, base)
    if get(w, 48) != 0 or get(w, 56) > 8388640:
        return 4294967294
    if mode == 2:
        return patch_result(o, w, schema, policy, applied, expected)
    put(o, 0, MAGIC)
    put(o, 8, schema)
    put(o, 16, policy)
    put(o, 24, applied)
    return get(w, 56)

def apply_edits(s:readbuf, o:mutbuf, w:mutbuf, functions:u64, edits:u64, policy:u64) -> u64:
    edit = child(w, edits)
    applied = 0
    while edit != 18446744073709551615:
        status = edit_target(s, w, functions, edit)
        if status != 0:
            return status
        status = edit_overlap(w, applied)
        if status != 0:
            return status
        status = edit_materialize(s, o, w, functions, edit, policy)
        if status != 0:
            return status
        scratch = get(w, 40)
        entry = scratch + 2048 + applied * 32
        put(w, entry, get(w, scratch + 1216))
        put(w, entry + 8, get(w, scratch + 1232))
        put(w, entry + 16, get(w, scratch + 1240))
        put(w, entry + 24, get(w, scratch + 1200))
        applied = applied + 1
        edit = next_node(w, edit)
    return applied

def edit_target(s:readbuf, w:mutbuf, functions:u64, edit:u64) -> u64:
    action = 0
    if kind(w, edit) != 6:
        return D_ACTION_TYPE
    tag = field(w, edit, K_action)
    if kind(w, tag) != 4:
        return D_ACTION_TYPE
    if text_is(w, tag, L_replace_function) != 0:
        action = 1
    if text_is(w, tag, L_add_function) != 0:
        action = 2
    if text_is(w, tag, L_replace_operation) != 0:
        action = 3
    if text_is(w, tag, L_replace_terminator) != 0:
        action = 4
    if action == 0:
        return 4294967287
    fields = K_action | K_function
    if action <= 2:
        fields = fields | K_definition
    elif action == 3:
        fields = fields | K_block | K_index | K_operation
    else:
        fields = fields | K_block | K_term
    if shape(w, edit, fields) == 0:
        if action <= 2:
            return D_FUNCTION_FIELDS
        return choose(action == 3, D_OPERATION_FIELDS, D_TERMINATOR_FIELDS)
    name = field(w, edit, K_function)
    if kind(w, name) != 4:
        return D_FUNCTION_TYPE
    fn = named(w, functions, K_name, name)
    if action == 2:
        if fn != 18446744073709551615:
            return D_FUNCTION_EXISTS
    elif fn == 18446744073709551615:
        return D_FUNCTION_ABSENT
    block = 18446744073709551615
    block_name = 18446744073709551615
    index = 18446744073709551615
    if action >= 3:
        block_name = field(w, edit, K_block)
        if kind(w, block_name) != 4:
            return D_BLOCK_TYPE
        block = named(w, field(w, fn, K_blocks), K_id, block_name)
        if block == 18446744073709551615:
            return D_BLOCK_ABSENT
        if action == 3:
            index = exact_index(s, w, field(w, edit, K_index))
            ops = field(w, block, K_ops)
            if kind(w, ops) != 5 or index >= count(w, ops):
                return 4294967284
    scratch = get(w, 40)
    put(w, scratch + 1200, action)
    put(w, scratch + 1208, fn)
    put(w, scratch + 1216, name)
    put(w, scratch + 1224, block)
    put(w, scratch + 1232, block_name)
    put(w, scratch + 1240, index)
    return 0

def edit_overlap(w:mutbuf, applied:u64) -> u64:
    scratch = get(w, 40)
    action = get(w, scratch + 1200)
    name = get(w, scratch + 1216)
    block_name = get(w, scratch + 1232)
    index = get(w, scratch + 1240)
    previous = 0
    while previous < applied:
        entry = scratch + 2048 + previous * 32
        if same_text(w, name, get(w, entry)) != 0:
            old_action = get(w, entry + 24)
            if action <= 2 or old_action <= 2:
                return D_OVERLAP
            if same_text(w, block_name, get(w, entry + 8)) != 0:
                if action == old_action and index == get(w, entry + 16):
                    return choose(action == 3, D_DUPLICATE_OP, D_DUPLICATE_TERM)
        previous = previous + 1
    return 0

def edit_materialize(s:readbuf, o:mutbuf, w:mutbuf, functions:u64, edit:u64, policy:u64) -> u64:
    scratch = get(w, 40)
    action = get(w, scratch + 1200)
    fn = get(w, scratch + 1208)
    name = get(w, scratch + 1216)
    block = get(w, scratch + 1224)
    index = get(w, scratch + 1240)
    if action <= 2:
        replacement = field(w, edit, K_definition)
        if kind(w, replacement) != 6 or same_text(w, name, field(w, replacement, K_name)) == 0:
            return D_DEFINITION
        changed = 0
        if action == 2:
            changed = 1
        elif policy == 0 or get(w, scratch + 1280) == 2:
            changed = choose(same_interface(s, o, w, fn, replacement) == 0, 1, 0)
        if changed != 0:
            if policy == 0:
                return 4294967282
            if get(w, scratch + 1280) == 2:
                remember_change(w, name)
        if action == 2:
            append_node(w, functions, replacement)
        else:
            replace_node(w, functions, fn, replacement)
    elif action == 3:
        target = child(w, field(w, block, K_ops))
        j = 0
        while j < index:
            target = next_node(w, target)
            j = j + 1
        replace_node(w, field(w, block, K_ops), target, field(w, edit, K_operation))
    else:
        target = field(w, block, K_term)
        if target == 18446744073709551615:
            return 4294967285
        replace_node(w, block, target, field(w, edit, K_term))
    return 0

def component_end(s:readbuf, start:u64) -> u64:
    # Only called on the already-decoded two-object envelope. This captures
    # lexical extent; syntax, nesting, Unicode and duplicate keys stay owned
    # by the single native JSON decoder above.
    index = start
    depth = 0
    while index < length(s):
        ch = byte(s, index)
        if ch == 34:
            index = index + 1
            going = True
            while going and index < length(s):
                ch = byte(s, index)
                if ch == 92:
                    index = index + 2
                elif ch == 34:
                    index = index + 1
                    going = False
                else:
                    index = index + 1
        else:
            if ch == 123 or ch == 91:
                depth = depth + 1
            if ch == 125 or ch == 93:
                depth = depth - 1
                if depth == 0:
                    return index + 1
            index = index + 1
    return length(s)

def lower_nibble(value:u64) -> u64:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    return 256

def tree_limit(w:mutbuf, root:u64, maximum_depth:u64) -> u64:
    node = root
    depth = 0
    nodes = 0
    going = True
    while going:
        nodes = nodes + 1
        if nodes > 262144 or depth > maximum_depth:
            return 0
        if (kind(w, node) == 5 or kind(w, node) == 6) and count(w, node) > 0:
            node = child(w, node)
            depth = depth + 1
        else:
            moving = True
            while moving:
                if node == root:
                    going = False
                    moving = False
                elif next_node(w, node) != 18446744073709551615:
                    node = next_node(w, node)
                    moving = False
                else:
                    node = get(w, 64 + node * 56 + 8)
                    depth = depth - 1
    return 1

def same_text(w:mutbuf, a:u64, b:u64) -> u64:
    if kind(w, a) != 4 or kind(w, b) != 4 or count(w, a) != count(w, b):
        return 0
    start_a = get(w, 64 + a * 56 + 24)
    start_b = get(w, 64 + b * 56 + 24)
    i = 0
    while i < count(w, a):
        if byte(w, start_a + i) != byte(w, start_b + i):
            return 0
        i = i + 1
    return 1

def named(w:mutbuf, array:u64, key:u64, name:u64) -> u64:
    if kind(w, array) != 5:
        return 18446744073709551615
    node = child(w, array)
    found = 18446744073709551615
    while node != 18446744073709551615:
        if same_text(w, field(w, node, key), name) != 0:
            if found != 18446744073709551615:
                return 18446744073709551615
            found = node
        node = next_node(w, node)
    return found

def exact_index(s:readbuf, w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 3:
        return 18446744073709551615
    start = get(w, 64 + node * 56 + 24)
    size = count(w, node)
    if size == 2 and byte(s, start) == 45 and byte(s, start + 1) == 48:
        return 0
    if size == 0 or size > 20:
        return 18446744073709551615
    value = 0
    i = 0
    while i < size:
        ch = byte(s, start + i)
        if ch < 48 or ch > 57 or value > 1844674407370955161:
            return 18446744073709551615
        digit = ch - 48
        if value == 1844674407370955161 and digit > 5:
            return 18446744073709551615
        value = value * 10 + digit
        i = i + 1
    return value

def replace_node(w:mutbuf, parent:u64, old:u64, replacement:u64) -> u64:
    node = child(w, parent)
    previous = 18446744073709551615
    while node != old:
        previous = node
        node = next_node(w, node)
    record = 64 + replacement * 56
    old_record = 64 + old * 56
    put(w, record + 8, parent)
    put(w, record + 16, next_node(w, old))
    put(w, record + 40, get(w, old_record + 40))
    put(w, record + 48, get(w, old_record + 48))
    if previous == 18446744073709551615:
        put(w, 64 + parent * 56 + 24, replacement)
    else:
        put(w, 64 + previous * 56 + 16, replacement)
    return 0

def append_node(w:mutbuf, parent:u64, replacement:u64) -> u64:
    node = child(w, parent)
    if node == 18446744073709551615:
        put(w, 64 + parent * 56 + 24, replacement)
    else:
        while next_node(w, node) != 18446744073709551615:
            node = next_node(w, node)
        put(w, 64 + node * 56 + 16, replacement)
    put(w, 64 + parent * 56 + 32, count(w, parent) + 1)
    put(w, 64 + replacement * 56 + 8, parent)
    put(w, 64 + replacement * 56 + 16, 18446744073709551615)
    put(w, 64 + replacement * 56 + 40, 0)
    put(w, 64 + replacement * 56 + 48, 0)
    return 0

def equal_json(s:readbuf, o:mutbuf, w:mutbuf, a:u64, b:u64) -> u64:
    if a == 18446744073709551615 or b == 18446744073709551615:
        return 0
    put(w, 56, 32)
    render_fragment(s, o, w, a)
    first_end = get(w, 56)
    render_fragment(s, o, w, b)
    if get(w, 48) != 0 or get(w, 56) - first_end != first_end - 32:
        return 0
    i = 0
    while i < first_end - 32:
        if byte(o, 32 + i) != byte(o, first_end + i):
            return 0
        i = i + 1
    return 1

def default_loans(w:mutbuf, loans:u64, results:u64) -> u64:
    if kind(w, loans) != 5 or kind(w, results) != 5 or count(w, loans) != count(w, results):
        return 0
    node = child(w, loans)
    while node != 18446744073709551615:
        if kind(w, node) != 0:
            return 0
        node = next_node(w, node)
    return 1

def same_interface(s:readbuf, o:mutbuf, w:mutbuf, a:u64, b:u64) -> u64:
    if same_text(w, field(w, a, K_name), field(w, b, K_name)) == 0:
        return 0
    if equal_json(s, o, w, field(w, a, K_params), field(w, b, K_params)) == 0:
        return 0
    if equal_json(s, o, w, field(w, a, K_returns), field(w, b, K_returns)) == 0:
        return 0
    if equal_json(s, o, w, field(w, a, K_effects), field(w, b, K_effects)) == 0:
        return 0
    x = field(w, a, K_return_loans)
    y = field(w, b, K_return_loans)
    if x == 18446744073709551615:
        if y == 18446744073709551615:
            return 1
        return default_loans(w, y, field(w, a, K_returns))
    if y == 18446744073709551615:
        return default_loans(w, x, field(w, b, K_returns))
    return equal_json(s, o, w, x, y)

def text_less(w:mutbuf, a:u64, b:u64) -> u64:
    left = get(w, 64 + a * 56 + 24)
    right = get(w, 64 + b * 56 + 24)
    i = 0
    while i < count(w, a) and i < count(w, b):
        x = byte(w, left + i)
        y = byte(w, right + i)
        if x < y:
            return 1
        if x > y:
            return 0
        i = i + 1
    return choose(count(w, a) < count(w, b), 1, 0)

def remember_change(w:mutbuf, name:u64) -> u64:
    scratch = get(w, 40)
    size = get(w, scratch + 1296)
    if size >= 64:
        put(w, 48, 4294967294)
        return 0
    index = size
    moving = True
    while index > 0 and moving:
        previous = get(w, scratch + 4096 + (index - 1) * 8)
        if text_less(w, name, previous) != 0:
            put(w, scratch + 4096 + index * 8, previous)
            index = index - 1
        else:
            moving = False
    put(w, scratch + 4096 + index * 8, name)
    put(w, scratch + 1296, size + 1)
    return 0

def receipt_digest(o:mutbuf, w:mutbuf) -> u64:
    start = get(w, 40) + 1088
    i = 0
    while i < 32:
        value = byte(w, start + i)
        append_byte(o, w, hex_digit(value >> 4))
        append_byte(o, w, hex_digit(value & 15))
        i = i + 1
    return 0

def receipt_count(o:mutbuf, w:mutbuf, value:u64) -> u64:
    tens = 0
    while value >= 10:
        value = value - 10
        tens = tens + 1
    if tens != 0:
        append_byte(o, w, tens + 48)
    append_byte(o, w, value + 48)
    return 0

def receipt_changes(o:mutbuf, w:mutbuf) -> u64:
    scratch = get(w, 40)
    append_byte(o, w, 91)
    i = 0
    while i < get(w, scratch + 1296):
        if i != 0:
            append_byte(o, w, 44)
        name = get(w, scratch + 4096 + i * 8)
        append_string(o, w, get(w, 64 + name * 56 + 24), count(w, name))
        i = i + 1
    append_byte(o, w, 93)
    return 0

def receipt_claims(o:mutbuf, w:mutbuf, schema:u64) -> u64:
    emit_text(o, w, ',"claims":{"behavior_equivalence_proved":false,')
    if schema == 2:
        emit_text(o, w, '"external_callers_revalidated":false,"interface_preserved":')
        if get(w, get(w, 40) + 1296) == 0:
            emit_text(o, w, 'true,')
        else:
            emit_text(o, w, 'false,')
    emit_text(o, w, '"native_executed":false,"whole_module_rechecked":true}')
    return 0

def patch_result(o:mutbuf, w:mutbuf, schema:u64, policy:u64, edits:u64, expected:u64) -> u32:
    # This receipt remains private until the caller admits the whole candidate.
    # No image header, digest or receipt grants semantic/publication authority.
    candidate_end = get(w, 56)
    digest_fragment(o, w, candidate_end - 32)
    emit_text(o, w, '{"after_sha256":"')
    receipt_digest(o, w)
    emit_text(o, w, '","before_sha256":')
    append_string(o, w, get(w, 64 + expected * 56 + 24), 64)
    receipt_claims(o, w, schema)
    emit_text(o, w, ',"edit_domain":"independently_verified_normalized_core","edits":')
    receipt_count(o, w, edits)
    emit_text(o, w, ',"interface_changes":')
    receipt_changes(o, w)
    if schema == 2:
        emit_text(o, w, ',"interface_policy":"')
        if policy == 0:
            emit_text(o, w, 'preserve')
        else:
            emit_text(o, w, 'migrate')
        append_byte(o, w, 34)
    emit_text(o, w, ',"ok":true,"original_input_sha256":')
    append_string(o, w, get(w, 64 + expected * 56 + 24), 64)
    emit_text(o, w, ',"schema":"hepta.hia.patch-result.v')
    append_byte(o, w, schema + 48)
    emit_text(o, w, '","status":"verified_unpublished"}')
    size = get(w, 56)
    if get(w, 48) != 0 or size - candidate_end > 8388608:
        return 4294967294
    put(o, 0, RESULT_MAGIC)
    put(o, 8, candidate_end - 32)
    put(o, 16, size - candidate_end)
    put(o, 24, 0)
    return size

def hash_get(w:mutbuf, index:u64) -> u64:
    return get(w, get(w, 40) + index)

def hash_put(w:mutbuf, index:u64, value:u64) -> u64:
    return put(w, get(w, 40) + index, value)
'''


def source_program(*, public=False):
    constants = {'K_'+key:1 << i for i,key in enumerate(KEYS)}
    constants['MAGIC'] = MAGIC
    constants['RESULT_MAGIC'] = RESULT_MAGIC
    constants.update({name: codes[0 if public else 1] for name, codes in PUBLIC_STATUS.items()})
    literals = {'L_'+key:packed(value) for key,value in LITERALS.items()}
    class Expand(ast.NodeTransformer):
        def visit_Expr(self, node):
            if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == 'emit_text'):
                output, workspace, literal = node.value.args
                assert isinstance(literal, ast.Constant) and type(literal.value) is str
                return [ast.Expr(value=ast.Call(func=ast.Name(id='emit', ctx=ast.Load()),
                    args=[output, workspace, *(ast.Constant(value) for value in packed(literal.value[i:i+24]))],
                    keywords=[])) for i in range(0, len(literal.value), 24)]
            return self.generic_visit(node)
        def visit_Name(self, node):
            return ast.Constant(constants[node.id]) if node.id in constants else node
        def visit_Call(self, node):
            node = self.generic_visit(node)
            args = []
            for arg in node.args:
                args.extend(ast.Constant(value) for value in literals[arg.id]) if isinstance(arg,ast.Name) and arg.id in literals else args.append(arg)
            node.args = args
            return node
    own = Expand().visit(ast.parse(BODY))
    # Reuse the exact JSON/key/Unicode/sorting algorithms. Only this envelope's
    # outer framing budget is larger; subtree ceilings are checked separately.
    keep = {'kind','count','child','field','shape','same','text_is','render_fragment',
            'append_byte','hex_digit','append_string','next_node','key_less','sort_object','emit'}
    helper_nodes = [node for node in ast.parse(frontend_source()).body if node.name in keep]
    helper_text = ast.unparse(ast.fix_missing_locations(ast.Module(body=helper_nodes,type_ignores=[])))
    helper_text = helper_text.replace('index >= 1048576', 'index >= 16777248')
    helper_text = helper_text.replace('4294967290)', '4294967294)')
    key = ['def key_id(w:mutbuf, node:u64) -> u64:',
           '    start = get(w, 64 + node * 56 + 40)',
           '    size = get(w, 64 + node * 56 + 48)']
    for i,name in enumerate(KEYS):
        key += ['    if same(w, start, size, '+', '.join(map(str,packed(name)))+') == 1:',
                '        return '+str(1 << i)]
    key += ['    return 0']
    from tools.generate_hia_json_decode import source_program as decoder_source
    decoder = decoder_source().replace('8388608','16777219').replace('maximum_depth > 128','maximum_depth > 129')
    digest_nodes = ast.parse(sha_source()).body
    digest_nodes = [node for node in digest_nodes if node.name not in {'get','put'}]
    digest = ast.unparse(ast.fix_missing_locations(ast.Module(body=digest_nodes,type_ignores=[])))
    digest = digest.replace('def sha256(s: readbuf, o: mutbuf, w: mutbuf)', 'def digest_fragment(s: mutbuf, w: mutbuf, size: u64)')
    digest = digest.replace('def padded_byte(s: readbuf, index: u64, total: u64)', 'def padded_byte(s: mutbuf, index: u64, total: u64, size: u64)')
    digest = digest.replace('length(s)', 'size')
    digest = digest.replace('size > 8388608 or length(o) < 32 or length(w) < 1088', 'size > 8388608')
    digest = digest.replace('padded_byte(s, block + i * 4 + j, padded)', 'padded_byte(s, block + i * 4 + j, padded, size)')
    digest = digest.replace('byte(s, index)', 'byte(s, 32 + index)')
    digest = digest.replace('get(w,', 'hash_get(w,').replace('put(w,', 'hash_put(w,')
    digest = digest.replace('store(o, i * 4 + j,', 'store(w, get(w, 40) + 1088 + i * 4 + j,')
    return ast.unparse(ast.fix_missing_locations(own))+'\n'+helper_text+'\n'+'\n'.join(key)+'\n'+decoder+'\n'+digest+'\n'


def document(source=None, *, module='core_patch'):
    nodes = ast.parse(source_program() if source is None else source).body
    assert len({node.name for node in nodes}) == len(nodes)
    names = {node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures = {node.name:([arg.annotation.id for arg in node.args.args],node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node,names,signatures,total)
        builder.statements(node.body)
        functions.append({'name':names[node.name], 'params':[builder.param(p) for p in builder.params],
            'returns':[builder.returns], 'effects':['read','write','trap'],
            'entry':'b0', 'blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':module,'functions':functions})


def diagnostic_source():
    lines = [
        'def patch_diagnostic(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
        '    if length(s) != 8 or length(o) < 512:',
        '        return 0',
        '    status = 0',
        '    index = 0',
        '    while index < 8:',
        '        status = status | (byte(s, index) << (8 * index))',
        '        index = index + 1',
    ]
    for code, message in PUBLIC_DIAGNOSTICS.items():
        raw = (json.dumps({
            'diagnostics': [{'code': 'E_DRIVER', 'message': 'E_HIA_EDIT: ' + message, 'phase': 'driver'}],
            'ok': False, 'status': 'error',
        }, indent=2, sort_keys=True) + '\n').encode('ascii')
        lines.append(f'    if status == {code}:')
        for offset in range(0, len(raw), 8):
            word = int.from_bytes(raw[offset:offset + 8], 'little')
            lines.append(f'        put(o, {offset}, {word})')
        lines.append(f'        return {len(raw)}')
    lines += ['    return 0', '',
              'def put(output:mutbuf, offset:u64, word:u64) -> u64:',
              '    index = 0',
              '    while index < 8:',
              '        store(output, offset + index, (word >> (8 * index)) & 255)',
              '        index = index + 1',
              '    return 0']
    return '\n'.join(lines) + '\n'


def update_public_edit_kernels(directory):
    # These sealed kernels share the five patch-policy functions. Their
    # underlying parser, output/custody and imported tables intentionally stay
    # variant-specific. Update only the shared functions, not those adapters.
    public = render_assembly(document(source_program(public=True)))
    shared = re.findall(r'^fn f[0-4]\(.*?^end\n', public, re.MULTILINE | re.DOTALL)
    if len(shared) != 5:
        raise ValueError('incomplete public patch policy')
    presenter = render_assembly(document(diagnostic_source())).split('\n', 1)[1]
    presenter = re.sub(r'\bf0(?=["(])', 'patch_diagnostic', presenter)
    presenter = re.sub(r'\bf1(?=["(])', 'patch_diagnostic_word', presenter)
    # An eight-byte immutable status with no workspace is disjoint from both
    # established execution ABIs. All other requests use the original entry.
    gate = '''block patch_driver_start(v0:readbuf,v1:mutbuf,v2:mutbuf)
  patch_input_bytes:usize = buffer.len(v0)
  patch_workspace_bytes:usize = buffer.len(v2)
  patch_eight:usize = const() {"value":8}
  patch_zero:usize = const() {"value":0}
  patch_input_ok:bool = compare.eq(patch_input_bytes,patch_eight)
  patch_workspace_ok:bool = compare.eq(patch_workspace_bytes,patch_zero)
  patch_diagnostic_only:bool = bool.and(patch_input_ok,patch_workspace_ok)
  branch patch_diagnostic_only patch_driver_report(v0,v1,v2) b0(v0,v1,v2)
block patch_driver_report(patch_status2:readbuf,patch_output2:mutbuf,patch_workspace2:mutbuf)
  patch_amount:u32 = call(patch_status2,patch_output2,patch_workspace2) {"function":"patch_diagnostic"}
  ret(patch_amount)
'''
    for name, function_offset in (('impact_patch', 0), ('publication_patch_policy', 26)):
        path = directory / (name + '.hepta')
        source = path.read_text()
        source = source.split('\nfn patch_diagnostic(', 1)[0].rstrip() + '\n'
        source = re.sub(r'entry\(patch_driver_start\)\n.*?(?=^block b0\()', 'entry(b0)\n',
                        source, count=1, flags=re.MULTILINE | re.DOTALL)
        for index, function in enumerate(shared):
            identity = function_offset + index
            shifted = re.sub(r'(?<=\bf)(\d+)(?=["(])', lambda match: str(int(match[1]) + function_offset), function)
            source, count = re.subn(rf'^fn f{identity}\(.*?^end\n', lambda _: shifted, source,
                                    flags=re.MULTILINE | re.DOTALL)
            if count != 1:
                raise ValueError('missing unique patch policy function for ' + name)
        header = (r'^(fn f0\([^\n]*\) -> \(u32\) effects\(read,write,trap\)) entry\(b0\)\n'
                  r'(block b0\([^\n]*\)\n.*?)(?=^block |^end\n)')
        def gate_entry(match):
            ports = {'v0': 'patch_source', 'v1': 'patch_output', 'v2': 'patch_workspace'}
            original = re.sub(r'\bv[0-2]\b', lambda name: ports[name[0]], match[2])
            return match[1] + ' entry(patch_driver_start)\n' + gate + original
        source, count = re.subn(header, gate_entry, source, flags=re.MULTILINE | re.DOTALL)
        if count != 1:
            raise ValueError('missing unique patch transport function for ' + name)
        path.write_text(source + presenter)


def main():
    target = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/core_patch.hepta'
    target.write_text(render_assembly(document()))
    update_public_edit_kernels(target.parent / 'core_edit')
    print(target.name, target.stat().st_size)


if __name__ == '__main__':
    main()
