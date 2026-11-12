"""Author the complete bounded nominal type/layout owner in ordinary HIA.

The native image owns declaration validation, exact structural interning,
symbolic loan constraints and partial typestates. Python is authoring only.
Sessions use private arenas; nominal keys are exact DAG identities, not hashes
and not exponentially expanded display strings.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_core_json_frontend import packed
from tools.generate_hia_json_decode import source_program as decoder_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIATYP01', 'little')
ORIGINS_MAGIC = int.from_bytes(b'HIALOR01', 'little')
PARAMETERS_MAGIC = int.from_bytes(b'HIAPRM01', 'little')
STATE_MAGIC = int.from_bytes(b'HIATYS01', 'little')
OUTPUT_BYTES = 64 * 1024 * 1024
WORKSPACE_BYTES = 128 * 1024 * 1024
MAX_COMMAND_BYTES = (8 * 1024 * 1024) + 128
# Ordinary Core keeps its existing 8 MiB limit. The private init envelope has
# at most five more bytes than a structurally admitted composite document
# whose functions value is invalid (for example 0), so framing must not hide
# the earlier nominal declaration diagnostic. This allowance is transport only.
# Transport capacity is derived from the existing language quotas, not a new
# semantic limit. At most 128 cached/active types contain 32 * 64 enum fields;
# each identifier is at most 128 ASCII bytes. Even repeating every field name
# in every descriptor needs under 37 MiB (including variants, 512 flat IDs,
# primitive rows and all fixed fields), below OUTPUT_BYTES.
#
# The private state uses 144 * 40960 bytes for 16 primitives plus 128 nominal
# records, four MiB for at most 262144 declaration-partial references, and two
# MiB for exact intern/memo tables. Symbol nodes grow upwards and known-loan
# frames downwards within the same 18 MiB arena. A symbolic visit charges one
# original declaration step and allocates at most 32 header + 65*8 partial
# payload + 8 application-edge bytes; a known-loan call charges one step and
# needs a 192-byte frame. Thus even the conservative joint bound
# 560 * 32768 + one pending frame + the root environment is below 18 MiB.
# This also covers same-depth lexical alias forwarding: layout depth alone is
# deliberately not used as a bound on the known-loan call stack.
PRIMITIVES = ('bool', 'unit', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16',
              'u32', 'u64', 'isize', 'usize', 'buffer', 'readbuf', 'mutbuf', 'chain')
KEYS = ('op', 'definitions', 'recursive_chain', 'partial_records', 'ref', 'base',
        'initialized', 'kind', 'name', 'params', 'fields', 'variants', 'state',
        'result', 'poll', 'cancel', 'type', 'args', 'partial', 'returns', 'return_loans', 'param',
        'task', 'functions')
LITERALS = {name:name for name in ('init', 'resolve', 'partial', 'origins', 'parameters',
                                  'task_protocol', 'pending', 'ready', 'record', 'enum', 'task',
                                  *PRIMITIVES)}
LITERALS.update(reserved_core='__hia_', reserved_nominal='h2internal_')
ERRORS = {
    1: ('E_HIA_FORMAT', 'nominal type object has an unexpected field inventory'),
    2: ('E_HIA_LIMIT', 'invalid nominal type inventory'),
    3: ('E_HIA_TYPE', 'nominal type requires a kind'),
    4: ('E_HIA_TYPE', 'unknown nominal type kind'),
    5: ('E_HIA_NAME', 'invalid/reserved ASCII identifier'),
    6: ('E_HIA_NAME', 'identifier uses the elaborator namespace'),
    7: ('E_HIA_TYPE', 'duplicate/reserved nominal type'),
    8: ('E_HIA_TYPE', 'invalid type parameter list'),
    9: ('E_HIA_TYPE', 'reserved type parameter'),
    10: ('E_HIA_TYPE', 'duplicate type parameter'),
    11: ('E_HIA_TYPE', 'task protocols have concrete state/result signatures'),
    12: ('E_HIA_TYPE', 'enum requires 1..32 variants'),
    13: ('E_HIA_TYPE', 'duplicate enum variant'),
    14: ('E_HIA_LIMIT', 'nominal fields exceed the finite profile'),
    15: ('E_HIA_TYPE', 'duplicate nominal field'),
    16: ('E_HIA_LIMIT', 'type reference nesting exceeds budget'),
    17: ('E_HIA_TYPE', 'recursive chain types require composite v2'),
    18: ('E_HIA_TYPE', 'unknown or unapplied nominal type'),
    19: ('E_HIA_LIMIT', 'invalid partial-record field inventory'),
    20: ('E_HIA_INIT', 'duplicate initialized record field'),
    21: ('E_HIA_TYPE', 'partial type requires a declared nominal record'),
    22: ('E_HIA_INIT', 'initialized fields must exist in declaration order'),
    23: ('E_HIA_TYPE', 'generic type arity mismatch'),
    24: ('E_HIA_TYPE', 'recursive by-value nominal declarations'),
    25: ('E_HIA_LIMIT', 'partial declaration analysis budget exceeded'),
    26: ('E_HIA_LIMIT', 'nominal layout nesting exceeds budget'),
    27: ('E_HIA_LIMIT', 'symbolic type argument nesting exceeds budget'),
    28: ('E_HIA_LOAN', 'partial record fields may not contain stored loans'),
    29: ('E_HIA_TYPE', 'recursive by-value nominal layout'),
    30: ('E_HIA_LIMIT', 'generic instantiation budget exceeded'),
    31: ('E_HIA_LOAN', 'enum payloads cannot contain loans in composite v1'),
    32: ('E_HIA_LOAN', 'task state/results may not retain loans'),
    33: ('E_HIA_LIMIT', 'flattened nominal layout exceeds budget'),
    34: ('E_HIA_TYPE', 'partial type requires a nominal record in composite v3/v4'),
    35: ('E_HIA_LIMIT', 'generic/partial instantiation budget exceeded'),
    36: ('E_HIA_LIMIT', 'flattened partial-record layout exceeds budget'),
    37: ('E_HIA_LOAN', 'nominal return_loans must match return arity'),
    38: ('E_HIA_LOAN', 'nonloan nominal result requires a null origin'),
    39: ('E_HIA_LOAN', 'returned loan names no original parameter'),
    40: ('E_HIA_LOAN', 'returned-loan origin requires an incoming loan-only parameter'),
    41: ('E_HIA_LIMIT', 'returned-loan field path exceeds finite budget'),
    42: ('E_HIA_LOAN', 'returned-loan path must traverse record fields'),
    43: ('E_HIA_LOAN', 'returned-loan path names no record field'),
    44: ('E_HIA_LOAN', 'returned-loan field must be an incoming loan with sufficient permission'),
    45: ('E_HIA_FORMAT', 'parameters must be a list'),
    46: ('E_HIA_SSA', 'duplicate nominal parameter'),
    47: ('E_HIA_CALL', 'task protocol names a missing function'),
    48: ('E_HIA_TYPE', 'task poll must consume one state and return one step enum'),
    49: ('E_HIA_TYPE', 'task poll result must be pending(state) | ready(result)'),
    50: ('E_HIA_TYPE', 'task cancellation must consume one state and return no values'),
}

CONSTANTS = {
    'N': (1 << 64) - 1, 'MAGIC': MAGIC, 'ORIGINS_MAGIC': ORIGINS_MAGIC, 'STATE_MAGIC': STATE_MAGIC,
    'PARAMETERS_MAGIC': PARAMETERS_MAGIC,
    'O_BYTES': OUTPUT_BYTES, 'W_BYTES': WORKSPACE_BYTES,
    'INPUT_BYTES': MAX_COMMAND_BYTES,
    'Q': 32 * 1024 * 1024, 'D': 64 * 1024 * 1024,
    'S': 96 * 1024 * 1024,
    'DEFS': 96 * 1024 * 1024 + 4096,
    'GRAPH': 96 * 1024 * 1024 + 8192,
    'TYPES': 96 * 1024 * 1024 + 65536,
    'PARTIALS': 102 * 1024 * 1024,
    'SYMHASH': 106 * 1024 * 1024,
    'MEMO': 106 * 1024 * 1024 + 524288,
    'SYMHEAP': 108 * 1024 * 1024,
    'FRAMES': 126 * 1024 * 1024,
    'REFSTACK': 126 * 1024 * 1024,
    'RESSTACK': 126 * 1024 * 1024 + 65536,
    'SYMSTACK': 126 * 1024 * 1024 + 131072,
    'MISC': 126 * 1024 * 1024 + 524288,
    # An origins command has at most floor((262144 - 4) / 3) parameters.
    # 131072 eight-byte slots therefore fit every admitted command without
    # an additional language limit. This scratch is separate from type state.
    'ORIGIN_HASH': 126 * 1024 * 1024 + 589824,
}

BODY = r'''
def types_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < O_BYTES or length(w) < W_BYTES or length(s) > INPUT_BYTES:
        return 4294967280
    put(w, 48, 262144)
    put(w, 56, 128)
    decoded_size = widen(decode_json(s, o, w))
    if decoded_size >= 4294967292:
        return decoded_size
    copy_words(o, w, Q, decoded_size)
    root = Q + 64
    operation = field(w, root, K_op)
    result = 0
    if text_is(w, operation, L_init) == 1:
        if shape(w, root, K_op | K_definitions | K_recursive_chain | K_partial_records) == 0:
            return 4294967281
        recursive = field(w, root, K_recursive_chain)
        partial = field(w, root, K_partial_records)
        if (kind(w, recursive) != 1 and kind(w, recursive) != 2) or (kind(w, partial) != 1 and kind(w, partial) != 2):
            return 4294967281
        fill_range(w, S, 33554432, 0)
        put(w, S, STATE_MAGIC)
        put(w, S + 56, choose(kind(w, recursive) == 2, 1, 0))
        put(w, S + 64, choose(kind(w, partial) == 2, 1, 0))
        copy_words(o, w, D, decoded_size)
        put(w, S + 80, 1)
        put(w, S + 96, SYMHEAP)
        put(w, S + 160, FRAMES)
        init_primitives(w)
        init_types(w, field(w, D + 64, K_definitions))
        if error(w) == 0:
            put(w, S + 48, 1)
    else:
        if get(w, S) != STATE_MAGIC or get(w, S + 48) != 1:
            return 4294967282
        put(w, S + 8, 0)
        if text_is(w, operation, L_resolve) == 1:
            if shape(w, root, K_op | K_ref) == 0:
                return 4294967281
            result = resolve_type(w, field(w, root, K_ref))
        elif text_is(w, operation, L_partial) == 1:
            if shape(w, root, K_op | K_base | K_initialized) == 0:
                return 4294967281
            base = input_id(s, w, field(w, root, K_base))
            if base == 0 or base > get(w, S + 16) or get(w, type_at(base) + 37872) == 0:
                return 4294967281
            result = partial_type(w, base, field(w, root, K_initialized))
        elif text_is(w, operation, L_origins) == 1:
            if admit_origins(s, w, root) == 0:
                return 4294967281
            return render_origins(s, o, w, root)
        elif text_is(w, operation, L_parameters) == 1:
            if shape(w, root, K_op | K_params) == 0:
                return 4294967281
            params = field(w, root, K_params)
            resolve_parameters(w, params)
            return render_parameters(o, w, params)
        elif text_is(w, operation, L_task_protocol) == 1:
            result = task_protocol(s, w, root)
            if result == N:
                return 4294967281
        else:
            return 4294967281
    if error(w) != 0:
        result = 0
    return render_result(o, w, result)

def copy_words(o:mutbuf, w:mutbuf, target:u64, size:u64) -> u64:
    i = 0
    while i + 8 <= size:
        put(w, target + i, get(o, i))
        i = i + 8
    while i < size:
        store(w, target + i, byte(o, i))
        i = i + 1
    return 0

def error(w:mutbuf) -> u64:
    return get(w, S + 8)

def reject(w:mutbuf, code:u64) -> u64:
    if error(w) == 0:
        put(w, S + 8, code)
    return 0

def arena(node:u64) -> u64:
    return choose(node < D, Q, D)

def kind(w:mutbuf, node:u64) -> u64:
    if node == N:
        return N
    return get(w, node)

def count(w:mutbuf, node:u64) -> u64:
    if node == N:
        return 0
    return get(w, node + 32)

def data(w:mutbuf, node:u64) -> u64:
    return arena(node) + get(w, node + 24)

def child(w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 5 and kind(w, node) != 6:
        return N
    value = get(w, node + 24)
    return choose(value == N, N, arena(node) + 64 + value * 56)

def next_node(w:mutbuf, node:u64) -> u64:
    if node == N:
        return N
    value = get(w, node + 16)
    return choose(value == N, N, arena(node) + 64 + value * 56)

def at(w:mutbuf, node:u64, index:u64) -> u64:
    current = child(w, node)
    i = 0
    while i < index and current != N:
        current = next_node(w, current)
        i = i + 1
    return current

def field(w:mutbuf, node:u64, flag:u64) -> u64:
    if kind(w, node) != 6:
        return N
    item = child(w, node)
    while item != N:
        if key_id(w, item) == flag:
            return item
        item = next_node(w, item)
    return N

def shape(w:mutbuf, node:u64, expected:u64) -> u64:
    if kind(w, node) != 6:
        return 0
    actual = 0
    item = child(w, node)
    while item != N:
        flag = key_id(w, item)
        if flag == 0:
            return 0
        actual = actual | flag
        item = next_node(w, item)
    return choose(actual == expected, 1, 0)

def same(w:mutbuf, start:u64, size:u64, n:u64, a:u64, b:u64, c:u64) -> u64:
    if size != n:
        return 0
    i = 0
    while i < n:
        word = a
        shift = i * 8
        if i >= 8:
            word = b
            shift = (i - 8) * 8
        if i >= 16:
            word = c
            shift = (i - 16) * 8
        if byte(w, start + i) != ((word >> shift) & 255):
            return 0
        i = i + 1
    return 1

def text_is(w:mutbuf, node:u64, n:u64, a:u64, b:u64, c:u64) -> u64:
    if kind(w, node) != 4:
        return 0
    return same(w, data(w, node), count(w, node), n, a, b, c)

def equal_text(w:mutbuf, a:u64, b:u64) -> u64:
    if a == b:
        return 1
    if kind(w, a) != 4 or kind(w, b) != 4 or count(w, a) != count(w, b):
        return 0
    i = 0
    while i < count(w, a):
        if byte(w, data(w, a) + i) != byte(w, data(w, b) + i):
            return 0
        i = i + 1
    return 1

def has_name(w:mutbuf, array:u64, name:u64) -> u64:
    item = child(w, array)
    while item != N:
        if equal_text(w, item, name) == 1:
            return 1
        item = next_node(w, item)
    return 0

def name_ok(w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 4 or count(w, node) < 1 or count(w, node) > 128:
        return reject(w, 5)
    start = data(w, node)
    n = count(w, node)
    if n >= 6 and same(w, start, 6, L_reserved_core) == 1:
        return reject(w, 5)
    if n >= 11 and same(w, start, 11, L_reserved_nominal) == 1:
        return reject(w, 6)
    i = 0
    while i < n:
        ch = byte(w, start + i)
        valid = (ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122) or ch == 95
        if i > 0:
            valid = valid or (ch >= 48 and ch <= 57)
        if valid == False:
            return reject(w, 5)
        i = i + 1
    return 1

def definition(w:mutbuf, name:u64) -> u64:
    i = 0
    while i < get(w, S + 88):
        if equal_text(w, name, get(w, DEFS + i * 24)) == 1:
            return i + 1
        i = i + 1
    return 0

def def_node(w:mutbuf, identifier:u64) -> u64:
    return get(w, DEFS + (identifier - 1) * 24 + 8)

def type_at(identifier:u64) -> u64:
    return TYPES + (identifier - 1) * 40960

def init_primitives(w:mutbuf) -> u64:
    i = 1
    while i <= 16:
        slot = type_at(i)
        put(w, slot + 152, 1)
        put(w, slot + 160, i)
        put(w, slot + 37840, choose(i >= 13, 1, 0))
        put(w, slot + 37848, choose(i == 14 or i == 15, 1, 0))
        put(w, slot + 37856, choose(i == 13 or i == 16, 1, 0))
        put(w, slot + 37872, 1)
        i = i + 1
    put(w, S + 16, 16)
    return 0

def init_types(w:mutbuf, definitions:u64) -> u64:
    if kind(w, definitions) != 5 or count(w, definitions) > 128:
        return reject(w, 2)
    item = child(w, definitions)
    while item != N and error(w) == 0:
        register_definition(w, item)
        item = next_node(w, item)
    i = 1
    while i <= get(w, S + 88) and error(w) == 0:
        validate_definition(w, i)
        i = i + 1
    if error(w) != 0:
        return 0
    check_graph(w)
    put(w, S + 80, 0)
    i = 0
    while i < get(w, S + 40) and error(w) == 0:
        ref = get(w, PARTIALS + i * 16)
        params = get(w, PARTIALS + i * 16 + 8)
        symbolic = has_parameters(w, ref, params)
        if error(w) == 0:
            if symbolic == 0:
                resolve_type(w, ref)
            else:
                if known_loans(w, field(w, ref, K_partial), params) == 1 and error(w) == 0:
                    reject(w, 28)
        i = i + 1
    return 0

def register_definition(w:mutbuf, item:u64) -> u64:
    tag = field(w, item, K_kind)
    if kind(w, item) != 6 or kind(w, tag) != 4:
        return reject(w, 3)
    category = 0
    fields = K_name | K_params | K_kind
    if text_is(w, tag, L_record) == 1:
        category = 1
        fields = fields | K_fields
    elif text_is(w, tag, L_enum) == 1:
        category = 2
        fields = fields | K_variants
    elif text_is(w, tag, L_task) == 1:
        category = 3
        fields = fields | K_state | K_result | K_poll | K_cancel
    else:
        return reject(w, 4)
    if shape(w, item, fields) == 0:
        return reject(w, 1)
    name = field(w, item, K_name)
    if name_ok(w, name) == 0:
        return 0
    if primitive(w, name) != 0 or definition(w, name) != 0:
        return reject(w, 7)
    params = field(w, item, K_params)
    if kind(w, params) != 5 or count(w, params) > 16:
        return reject(w, 8)
    param = child(w, params)
    while param != N:
        if name_ok(w, param) == 0:
            return 0
        if primitive(w, param) != 0 or equal_text(w, param, name) == 1:
            return reject(w, 9)
        param = next_node(w, param)
    if duplicates(w, params) == 1:
        return reject(w, 10)
    if category == 3 and count(w, params) != 0:
        return reject(w, 11)
    slot = DEFS + get(w, S + 88) * 24
    put(w, slot, name)
    put(w, slot + 8, item)
    put(w, slot + 16, category)
    put(w, S + 88, get(w, S + 88) + 1)
    return 0

def duplicates(w:mutbuf, array:u64) -> u64:
    item = child(w, array)
    while item != N:
        earlier = child(w, array)
        while earlier != item:
            if equal_text(w, item, earlier) == 1:
                return 1
            earlier = next_node(w, earlier)
        item = next_node(w, item)
    return 0

def validate_definition(w:mutbuf, identifier:u64) -> u64:
    item = def_node(w, identifier)
    params = field(w, item, K_params)
    category = get(w, DEFS + (identifier - 1) * 24 + 16)
    put(w, S + 104, identifier)
    if category == 1:
        validate_fields(w, field(w, item, K_fields), params)
    elif category == 2:
        variants = field(w, item, K_variants)
        if kind(w, variants) != 5 or count(w, variants) < 1 or count(w, variants) > 32:
            return reject(w, 12)
        variant = child(w, variants)
        while variant != N and error(w) == 0:
            if shape(w, variant, K_name | K_fields) == 0:
                return reject(w, 1)
            name = field(w, variant, K_name)
            if name_ok(w, name) == 0:
                return 0
            earlier = child(w, variants)
            while earlier != variant:
                if equal_text(w, name, field(w, earlier, K_name)) == 1:
                    return reject(w, 13)
                earlier = next_node(w, earlier)
            validate_fields(w, field(w, variant, K_fields), params)
            variant = next_node(w, variant)
    else:
        validate_ref(w, field(w, item, K_state), params)
        if error(w) == 0:
            validate_ref(w, field(w, item, K_result), params)
        if error(w) == 0:
            name_ok(w, field(w, item, K_poll))
        if error(w) == 0:
            name_ok(w, field(w, item, K_cancel))
    return 0

def validate_fields(w:mutbuf, fields:u64, params:u64) -> u64:
    if kind(w, fields) != 5 or count(w, fields) > 64:
        return reject(w, 14)
    item = child(w, fields)
    while item != N and error(w) == 0:
        if shape(w, item, K_name | K_type) == 0:
            return reject(w, 1)
        name = field(w, item, K_name)
        if name_ok(w, name) == 0:
            return 0
        earlier = child(w, fields)
        while earlier != item:
            if equal_text(w, name, field(w, earlier, K_name)) == 1:
                return reject(w, 15)
            earlier = next_node(w, earlier)
        validate_ref(w, field(w, item, K_type), params)
        item = next_node(w, item)
    return 0

def add_edge(w:mutbuf, target:u64) -> u64:
    if get(w, S + 80) == 1 and target != 0:
        store(w, GRAPH + (get(w, S + 104) - 1) * 128 + target - 1, 1)
    return 0

def validate_ref(w:mutbuf, root:u64, params:u64) -> u64:
    depth = 1
    put(w, REFSTACK, root)
    put(w, REFSTACK + 8, 0)
    put(w, REFSTACK + 16, 0)
    while depth != 0 and error(w) == 0:
        slot = REFSTACK + (depth - 1) * 32
        ref = get(w, slot)
        level = get(w, slot + 8)
        phase = get(w, slot + 16)
        if phase == 0:
            if level > 32:
                return reject(w, 16)
            if kind(w, ref) == 4:
                if primitive(w, ref) == 0 and has_name(w, params, ref) == 0:
                    target = definition(w, ref)
                    if text_is(w, ref, L_chain) == 1 and get(w, S + 56) == 0 and target == 0:
                        return reject(w, 17)
                    if name_ok(w, ref) == 0:
                        return 0
                    if target == 0 or count(w, field(w, def_node(w, target), K_params)) != 0:
                        return reject(w, 18)
                    add_edge(w, target)
                depth = depth - 1
            elif field(w, ref, K_partial) != N:
                if get(w, S + 64) == 0 or shape(w, ref, K_partial | K_initialized) == 0:
                    return reject(w, 1)
                initialized = field(w, ref, K_initialized)
                if kind(w, initialized) != 5 or count(w, initialized) > 64:
                    return reject(w, 19)
                item = child(w, initialized)
                while item != N:
                    if name_ok(w, item) == 0:
                        return 0
                    item = next_node(w, item)
                if duplicates(w, initialized) == 1:
                    return reject(w, 20)
                put(w, slot + 16, 1)
                put(w, slot + 32, field(w, ref, K_partial))
                put(w, slot + 40, level + 1)
                put(w, slot + 48, 0)
                depth = depth + 1
            else:
                if shape(w, ref, K_name | K_args) == 0:
                    return reject(w, 1)
                name = field(w, ref, K_name)
                if name_ok(w, name) == 0:
                    return 0
                target = definition(w, name)
                args = field(w, ref, K_args)
                if target == 0 or kind(w, args) != 5 or count(w, args) != count(w, field(w, def_node(w, target), K_params)):
                    return reject(w, 23)
                add_edge(w, target)
                put(w, slot + 16, 2)
                put(w, slot + 24, child(w, args))
        elif phase == 1:
            base = field(w, ref, K_partial)
            name = base
            if kind(w, base) != 4:
                name = field(w, base, K_name)
            target = definition(w, name)
            if (kind(w, base) == 4 and has_name(w, params, name) == 1) or target == 0:
                return reject(w, 21)
            if get(w, DEFS + (target - 1) * 24 + 16) != 1:
                return reject(w, 21)
            if ordered_names(w, field(w, def_node(w, target), K_fields), field(w, ref, K_initialized)) == 0:
                return reject(w, 22)
            if get(w, S + 80) == 1:
                position = PARTIALS + get(w, S + 40) * 16
                put(w, position, ref)
                put(w, position + 8, params)
                put(w, S + 40, get(w, S + 40) + 1)
            depth = depth - 1
        else:
            item = get(w, slot + 24)
            if item == N:
                depth = depth - 1
            else:
                put(w, slot + 24, next_node(w, item))
                put(w, slot + 32, item)
                put(w, slot + 40, level + 1)
                put(w, slot + 48, 0)
                depth = depth + 1
    return 0

def ordered_names(w:mutbuf, fields:u64, initialized:u64) -> u64:
    expected = child(w, initialized)
    item = child(w, fields)
    while item != N:
        name = field(w, item, K_name)
        if has_name(w, initialized, name) == 1:
            if expected == N or equal_text(w, name, expected) == 0:
                return 0
            expected = next_node(w, expected)
        item = next_node(w, item)
    return choose(expected == N, 1, 0)

def check_graph(w:mutbuf) -> u64:
    fill_range(w, MISC, 128, 0)
    start = 0
    while start < get(w, S + 88):
        if byte(w, MISC + start) == 0:
            depth = 1
            put(w, MISC + 128, start)
            put(w, MISC + 136, 0)
            store(w, MISC + start, 1)
            while depth != 0:
                slot = MISC + 128 + (depth - 1) * 16
                current = get(w, slot)
                target = get(w, slot + 8)
                if target == get(w, S + 88):
                    store(w, MISC + current, 2)
                    depth = depth - 1
                else:
                    put(w, slot + 8, target + 1)
                    if byte(w, GRAPH + current * 128 + target) != 0:
                        if byte(w, MISC + target) == 1:
                            return reject(w, 24)
                        if byte(w, MISC + target) == 0:
                            store(w, MISC + target, 1)
                            put(w, slot + 16, target)
                            put(w, slot + 24, 0)
                            depth = depth + 1
        start = start + 1
    return 0

def binding(w:mutbuf, environment:u64, name:u64) -> u64:
    if environment == 0:
        return 0
    slot = type_at(environment)
    params = field(w, def_node(w, get(w, slot + 8)), K_params)
    item = child(w, params)
    index = 0
    while item != N:
        if equal_text(w, item, name) == 1:
            return get(w, slot + 24 + index * 8)
        index = index + 1
        item = next_node(w, item)
    return 0

def push_resolution(w:mutbuf, slot:u64, ref:u64, environment:u64, depth:u64) -> u64:
    fill_range(w, slot, 256, 0)
    put(w, slot, ref)
    put(w, slot + 8, environment)
    put(w, slot + 16, depth)
    return 0

def resolve_type(w:mutbuf, ref:u64) -> u64:
    push_resolution(w, RESSTACK, ref, 0, 0)
    depth = 1
    while depth != 0 and error(w) == 0:
        slot = RESSTACK + (depth - 1) * 256
        phase = get(w, slot + 24)
        action = 0
        if phase == 0:
            action = resolve_enter(w, slot)
        elif phase == 1:
            action = resolve_arguments(w, slot)
        elif phase == 2:
            action = resolve_fields(w, slot)
        elif phase == 3:
            resolve_field_done(w, slot)
            action = 1
        elif phase == 4:
            put(w, slot + 24, 8)
            identifier = get(w, slot + 56)
            item = def_node(w, get(w, slot + 48))
            push_resolution(w, slot + 256, field(w, item, K_state), identifier, get(w, slot + 16) + 1)
            action = 2
        elif phase == 5:
            identifier = partial_type(w, get(w, S + 112), field(w, get(w, slot), K_initialized))
            put(w, S + 112, identifier)
        elif phase == 6:
            index = get(w, slot + 40)
            put(w, slot + 96 + index * 8, get(w, S + 112))
            put(w, slot + 40, index + 1)
            put(w, slot + 24, 1)
            action = 1
        elif phase == 7:
            action = resolve_variant(w, slot)
        elif phase == 8:
            identifier = get(w, slot + 56)
            record = type_at(identifier)
            child_id = get(w, S + 112)
            put(w, record + 37808, child_id)
            append_flat(w, record, child_id)
            put(w, slot + 24, 9)
            item = def_node(w, get(w, slot + 48))
            push_resolution(w, slot + 256, field(w, item, K_result), identifier, get(w, slot + 16) + 1)
            action = 2
        else:
            identifier = get(w, slot + 56)
            record = type_at(identifier)
            child_id = get(w, S + 112)
            put(w, record + 37816, child_id)
            append_flat(w, record, child_id)
            finish_type(w, identifier)
        if action == 0:
            depth = depth - 1
        elif action == 2:
            depth = depth + 1
    if error(w) != 0:
        return 0
    return get(w, S + 112)

def resolve_enter(w:mutbuf, slot:u64) -> u64:
    ref = get(w, slot)
    if get(w, slot + 16) > 32:
        reject(w, 26)
        return 0
    environment = get(w, slot + 8)
    params = N
    if kind(w, ref) == 4:
        selected = binding(w, environment, ref)
        if selected == 0:
            selected = primitive(w, ref)
        if selected != 0:
            put(w, S + 112, selected)
            return 0
    if environment != 0:
        params = field(w, def_node(w, get(w, type_at(environment) + 8)), K_params)
    validate_ref(w, ref, params)
    if error(w) != 0:
        return 0
    if field(w, ref, K_partial) != N:
        put(w, slot + 24, 5)
        push_resolution(w, slot + 256, field(w, ref, K_partial), environment, get(w, slot + 16) + 1)
        return 2
    name = ref
    args = N
    if kind(w, ref) != 4:
        name = field(w, ref, K_name)
        args = field(w, ref, K_args)
    put(w, slot + 48, definition(w, name))
    put(w, slot + 32, child(w, args))
    put(w, slot + 40, 0)
    put(w, slot + 24, 1)
    return 1

def resolve_arguments(w:mutbuf, slot:u64) -> u64:
    item = get(w, slot + 32)
    if item != N:
        put(w, slot + 32, next_node(w, item))
        put(w, slot + 24, 6)
        push_resolution(w, slot + 256, item, get(w, slot + 8), get(w, slot + 16) + 1)
        return 2
    identifier = 17
    while identifier <= get(w, S + 16):
        record = type_at(identifier)
        if get(w, record) != 4 and get(w, record + 8) == get(w, slot + 48) and get(w, record + 16) == get(w, slot + 40):
            i = 0
            same_args = 1
            while i < get(w, slot + 40):
                if get(w, record + 24 + i * 8) != get(w, slot + 96 + i * 8):
                    same_args = 0
                i = i + 1
            if same_args == 1:
                if get(w, record + 37872) == 0:
                    reject(w, 29)
                else:
                    put(w, S + 112, identifier)
                return 0
        identifier = identifier + 1
    if get(w, S + 16) >= 144:
        reject(w, 30)
        return 0
    identifier = get(w, S + 16) + 1
    put(w, S + 16, identifier)
    put(w, slot + 56, identifier)
    record = type_at(identifier)
    definition_id = get(w, slot + 48)
    category = get(w, DEFS + (definition_id - 1) * 24 + 16)
    put(w, record, category)
    put(w, record + 8, definition_id)
    put(w, record + 16, get(w, slot + 40))
    i = 0
    while i < get(w, slot + 40):
        put(w, record + 24 + i * 8, get(w, slot + 96 + i * 8))
        i = i + 1
    item = def_node(w, definition_id)
    if category == 1:
        put(w, slot + 64, child(w, field(w, item, K_fields)))
        put(w, slot + 24, 2)
    elif category == 2:
        put(w, record + 152, 1)
        put(w, record + 160, 9)
        put(w, slot + 72, child(w, field(w, item, K_variants)))
        put(w, slot + 24, 7)
    else:
        put(w, record + 152, 2)
        put(w, record + 160, 7)
        put(w, record + 168, 13)
        put(w, record + 37824, field(w, item, K_poll))
        put(w, record + 37832, field(w, item, K_cancel))
        put(w, record + 37840, 1)
        put(w, record + 37856, 1)
        put(w, slot + 24, 4)
    return 1

def resolve_fields(w:mutbuf, slot:u64) -> u64:
    identifier = get(w, slot + 56)
    record = type_at(identifier)
    item = get(w, slot + 64)
    if item == N:
        if get(w, record) == 2:
            variant = record + 37040 + (get(w, record + 37032) - 1) * 24
            put(w, variant + 16, get(w, record + 4256) - get(w, variant + 8))
            put(w, slot + 24, 7)
            return 1
        finish_type(w, identifier)
        return 0
    put(w, slot + 24, 3)
    push_resolution(w, slot + 256, field(w, item, K_type), identifier, get(w, slot + 16) + 1)
    return 2

def resolve_field_done(w:mutbuf, slot:u64) -> u64:
    item = get(w, slot + 64)
    record = type_at(get(w, slot + 56))
    index = get(w, record + 4256)
    put(w, record + 4264 + index * 16, field(w, item, K_name))
    put(w, record + 4272 + index * 16, get(w, S + 112))
    put(w, record + 4256, index + 1)
    append_flat(w, record, get(w, S + 112))
    put(w, slot + 64, next_node(w, item))
    put(w, slot + 24, 2)
    return 0

def resolve_variant(w:mutbuf, slot:u64) -> u64:
    item = get(w, slot + 72)
    record = type_at(get(w, slot + 56))
    if item == N:
        finish_type(w, get(w, slot + 56))
        return 0
    index = get(w, record + 37032)
    position = record + 37040 + index * 24
    put(w, position, field(w, item, K_name))
    put(w, position + 8, get(w, record + 4256))
    put(w, record + 37032, index + 1)
    put(w, slot + 72, next_node(w, item))
    put(w, slot + 64, child(w, field(w, item, K_fields)))
    put(w, slot + 24, 2)
    return 1

def append_flat(w:mutbuf, record:u64, child_id:u64) -> u64:
    source = type_at(child_id)
    size = get(w, record + 152)
    i = 0
    while i < get(w, source + 152):
        if size + i < 512:
            put(w, record + 160 + (size + i) * 8, get(w, source + 160 + i * 8))
        i = i + 1
    put(w, record + 152, size + i)
    put(w, record + 37840, get(w, record + 37840) | get(w, source + 37840))
    put(w, record + 37848, get(w, record + 37848) | get(w, source + 37848))
    put(w, record + 37856, get(w, record + 37856) | get(w, source + 37856))
    return 0

def finish_type(w:mutbuf, identifier:u64) -> u64:
    record = type_at(identifier)
    if get(w, record) == 2 and get(w, record + 37848) == 1:
        return reject(w, 31)
    if get(w, record) == 3 and get(w, record + 37848) == 1:
        return reject(w, 32)
    if get(w, record + 152) > 512:
        return reject(w, 33)
    put(w, record + 37872, 1)
    put(w, S + 24, get(w, S + 24) + 1)
    put(w, S + 112, identifier)
    return 0

def partial_type(w:mutbuf, base:u64, initialized:u64) -> u64:
    source = type_at(base)
    if get(w, S + 64) == 0 or get(w, source) != 1:
        return reject(w, 34)
    if get(w, source + 37848) == 1:
        return reject(w, 28)
    if kind(w, initialized) != 5:
        return reject(w, 22)
    selected = 0
    flat_size = 1
    expected = child(w, initialized)
    i = 0
    while i < get(w, source + 4256):
        name = get(w, source + 4264 + i * 16)
        if has_name(w, initialized, name) == 1:
            if expected == N or equal_text(w, name, expected) == 0:
                return reject(w, 22)
            expected = next_node(w, expected)
            put(w, MISC + 4096 + selected * 8, i)
            selected = selected + 1
            flat_size = flat_size + get(w, type_at(get(w, source + 4272 + i * 16)) + 152)
        i = i + 1
    if expected != N:
        return reject(w, 22)
    identifier = 17
    while identifier <= get(w, S + 16):
        record = type_at(identifier)
        if get(w, record) == 4 and get(w, record + 37864) == base and get(w, record + 4256) == selected:
            same_fields = 1
            i = 0
            while i < selected:
                original_index = get(w, MISC + 4096 + i * 8)
                if get(w, record + 4264 + i * 16) != get(w, source + 4264 + original_index * 16):
                    same_fields = 0
                i = i + 1
            if same_fields == 1:
                return identifier
        identifier = identifier + 1
    if get(w, S + 16) >= 144:
        return reject(w, 35)
    if flat_size > 512:
        return reject(w, 36)
    identifier = get(w, S + 16) + 1
    put(w, S + 16, identifier)
    record = type_at(identifier)
    put(w, record, 4)
    put(w, record + 152, 1)
    put(w, record + 160, 13)
    put(w, record + 4256, selected)
    put(w, record + 37840, 1)
    put(w, record + 37856, 1)
    put(w, record + 37864, base)
    i = 0
    while i < selected:
        original_index = get(w, MISC + 4096 + i * 8)
        put(w, record + 4264 + i * 16, get(w, source + 4264 + original_index * 16))
        child_id = get(w, source + 4272 + original_index * 16)
        put(w, record + 4272 + i * 16, child_id)
        append_flat(w, record, child_id)
        i = i + 1
    put(w, record + 37872, 1)
    put(w, S + 24, get(w, S + 24) + 1)
    return identifier

def input_id(s:readbuf, w:mutbuf, node:u64) -> u64:
    if kind(w, node) != 3 or count(w, node) < 1 or count(w, node) > 3:
        return 0
    start = get(w, node + 24)
    i = 0
    value = 0
    while i < count(w, node):
        digit = byte(s, start + i)
        if digit < 48 or digit > 57:
            return 0
        value = value * 10 + digit - 48
        i = i + 1
    return value

def complete_id(s:readbuf, w:mutbuf, node:u64) -> u64:
    identifier = input_id(s, w, node)
    if identifier == 0 or identifier > get(w, S + 16) or get(w, type_at(identifier) + 37872) != 1:
        return 0
    return identifier

def resolve_parameters(w:mutbuf, params:u64) -> u64:
    if kind(w, params) != 5:
        return reject(w, 45)
    fill_range(w, ORIGIN_HASH, 1048576, 0)
    item = child(w, params)
    while item != N:
        if shape(w, item, K_name | K_type) == 0:
            return reject(w, 1)
        name = field(w, item, K_name)
        if name_ok(w, name) == 0:
            return 0
        index = text_hash(w, name) & 131071
        while get(w, ORIGIN_HASH + index * 8) != 0:
            if equal_text(w, name, get(w, ORIGIN_HASH + index * 8)) == 1:
                return reject(w, 46)
            index = (index + 1) & 131071
        put(w, ORIGIN_HASH + index * 8, name)
        identifier = resolve_type(w, field(w, item, K_type))
        if error(w) != 0:
            return 0
        # Decoder parent indices are not used after decoding. Retain the
        # resolved ID in that word of this command's parameter object only.
        # Child/sibling links, keys, references and immutable definitions stay
        # intact; later parameters resolve in the original source order.
        put(w, item + 8, identifier)
        item = next_node(w, item)
    return 1

def render_parameters(o:mutbuf, w:mutbuf, params:u64) -> u32:
    extent = widen(render_result(o, w, 0))
    if extent >= 4294967280:
        return extent
    put(w, S + 136, extent - 1)
    emit_text(o, w, ',"params":[')
    item = child(w, params)
    emitted = 0
    while item != N and error(w) == 0:
        if emitted != 0:
            append_byte(o, w, 44)
        append_byte(o, w, 91)
        emit_name(o, w, field(w, item, K_name))
        append_byte(o, w, 44)
        emit_number(o, w, get(w, item + 8))
        append_byte(o, w, 93)
        emitted = emitted + 1
        item = next_node(w, item)
    emit_text(o, w, ']}')
    if get(w, S + 144) != 0:
        return 4294967280
    put(o, 0, PARAMETERS_MAGIC)
    put(o, 16, emitted)
    put(o, 24, get(w, S + 136) - 64)
    return get(w, S + 136)

def task_protocol(s:readbuf, w:mutbuf, root:u64) -> u64:
    if shape(w, root, K_op | K_task | K_functions) == 0:
        return N
    task = complete_id(s, w, field(w, root, K_task))
    if task == 0 or get(w, type_at(task)) != 3:
        return N
    functions = field(w, root, K_functions)
    if kind(w, functions) != 5 or count(w, functions) > 1024:
        return N
    record = type_at(task)
    poll = N
    cancel = N
    fill_range(w, ORIGIN_HASH, 1048576, 0)
    item = child(w, functions)
    while item != N:
        if kind(w, item) != 5 or count(w, item) != 3:
            return N
        name = child(w, item)
        if name_ok(w, name) == 0:
            return N
        index = text_hash(w, name) & 131071
        while get(w, ORIGIN_HASH + index * 8) != 0:
            if equal_text(w, name, get(w, ORIGIN_HASH + index * 8)) == 1:
                return N
            index = (index + 1) & 131071
        put(w, ORIGIN_HASH + index * 8, name)
        params = next_node(w, name)
        returns = next_node(w, params)
        if kind(w, params) != 5 or kind(w, returns) != 5:
            return N
        child_id = child(w, params)
        while child_id != N:
            if complete_id(s, w, child_id) == 0:
                return N
            child_id = next_node(w, child_id)
        child_id = child(w, returns)
        while child_id != N:
            if complete_id(s, w, child_id) == 0:
                return N
            child_id = next_node(w, child_id)
        if equal_text(w, name, get(w, record + 37824)) == 1:
            poll = item
        if equal_text(w, name, get(w, record + 37832)) == 1:
            cancel = item
        item = next_node(w, item)
    if poll == N or cancel == N:
        return reject(w, 47)
    params = next_node(w, child(w, poll))
    returns = next_node(w, params)
    state = get(w, record + 37808)
    if count(w, params) != 1 or input_id(s, w, child(w, params)) != state or count(w, returns) != 1:
        return reject(w, 48)
    step = input_id(s, w, child(w, returns))
    step_record = type_at(step)
    if get(w, step_record) != 2 or get(w, step_record + 37032) != 2:
        return reject(w, 49)
    pending = 0
    ready = 0
    index = 0
    while index < 2:
        variant = step_record + 37040 + index * 24
        if get(w, variant + 16) != 1:
            return reject(w, 49)
        field_type = get(w, step_record + 4272 + get(w, variant + 8) * 16)
        if text_is(w, get(w, variant), L_pending) == 1 and field_type == state:
            pending = 1
        elif text_is(w, get(w, variant), L_ready) == 1 and field_type == get(w, record + 37816):
            ready = 1
        else:
            return reject(w, 49)
        index = index + 1
    if pending == 0 or ready == 0:
        return reject(w, 49)
    params = next_node(w, child(w, cancel))
    returns = next_node(w, params)
    if count(w, params) != 1 or input_id(s, w, child(w, params)) != state or count(w, returns) != 0:
        return reject(w, 50)
    return step

def admit_origins(s:readbuf, w:mutbuf, root:u64) -> u64:
    expected = K_op | K_params | K_returns
    if field(w, root, K_return_loans) != N:
        expected = expected | K_return_loans
    params = field(w, root, K_params)
    returns = field(w, root, K_returns)
    if shape(w, root, expected) == 0 or kind(w, params) != 5 or kind(w, returns) != 5:
        return 0
    fill_range(w, ORIGIN_HASH, 1048576, 0)
    item = child(w, params)
    while item != N:
        if kind(w, item) != 5 or count(w, item) != 2:
            return 0
        name = child(w, item)
        if name_ok(w, name) == 0:
            return 0
        identifier = input_id(s, w, next_node(w, name))
        if identifier == 0 or identifier > get(w, S + 16) or get(w, type_at(identifier) + 37872) != 1:
            return 0
        index = text_hash(w, name) & 131071
        while get(w, ORIGIN_HASH + index * 8) != 0:
            if equal_text(w, name, child(w, get(w, ORIGIN_HASH + index * 8))) == 1:
                return 0
            index = (index + 1) & 131071
        put(w, ORIGIN_HASH + index * 8, item)
        item = next_node(w, item)
    item = child(w, returns)
    while item != N:
        identifier = input_id(s, w, item)
        if identifier == 0 or identifier > get(w, S + 16) or get(w, type_at(identifier) + 37872) != 1:
            return 0
        item = next_node(w, item)
    return 1

def origin_parameter(s:readbuf, w:mutbuf, name:u64) -> u64:
    index = text_hash(w, name) & 131071
    parameter = get(w, ORIGIN_HASH + index * 8)
    while parameter != 0:
        first = child(w, parameter)
        if equal_text(w, name, first) == 1:
            return input_id(s, w, next_node(w, first))
        index = (index + 1) & 131071
        parameter = get(w, ORIGIN_HASH + index * 8)
    return 0

def resolve_origin(s:readbuf, w:mutbuf, typ:u64, annotation:u64) -> u64:
    put(w, S + 176, N)
    put(w, S + 184, 0)
    if get(w, type_at(typ) + 37848) == 0:
        if annotation != N and kind(w, annotation) != 0:
            return reject(w, 38)
        return 1
    if shape(w, annotation, K_param | K_fields) == 0:
        return reject(w, 1)
    name = field(w, annotation, K_param)
    if name_ok(w, name) == 0:
        return 0
    selected = origin_parameter(s, w, name)
    if selected == 0:
        return reject(w, 39)
    record = type_at(selected)
    if get(w, record) > 1 or get(w, record + 37856) != 0:
        return reject(w, 40)
    path = field(w, annotation, K_fields)
    if kind(w, path) != 5 or count(w, path) > 32:
        return reject(w, 41)
    offset = 0
    item = child(w, path)
    while item != N:
        if name_ok(w, item) == 0:
            return 0
        record = type_at(selected)
        if get(w, record) != 1:
            return reject(w, 42)
        index = 0
        found = 0
        while index < get(w, record + 4256) and found == 0:
            nested = get(w, record + 4272 + index * 16)
            if equal_text(w, item, get(w, record + 4264 + index * 16)) == 1:
                found = 1
                selected = nested
            else:
                offset = offset + get(w, type_at(nested) + 152)
            index = index + 1
        if found == 0:
            return reject(w, 43)
        item = next_node(w, item)
    if (selected != 14 and selected != 15) or (typ == 15 and selected != 15):
        return reject(w, 44)
    put(w, S + 176, name)
    put(w, S + 184, offset)
    return 1

def render_origins(s:readbuf, o:mutbuf, w:mutbuf, root:u64) -> u32:
    returns = field(w, root, K_returns)
    annotations = field(w, root, K_return_loans)
    if annotations != N and (kind(w, annotations) != 5 or count(w, annotations) != count(w, returns)):
        reject(w, 37)
    put(w, S + 136, 64)
    put(w, S + 144, 0)
    emit_text(o, w, '{"origins":[')
    item = child(w, returns)
    annotation = child(w, annotations)
    emitted = 0
    while item != N and error(w) == 0:
        resolve_origin(s, w, input_id(s, w, item), annotation)
        if error(w) == 0:
            if emitted != 0:
                append_byte(o, w, 44)
            name = get(w, S + 176)
            if name == N:
                emit_text(o, w, 'null')
            else:
                append_byte(o, w, 91)
                emit_name(o, w, name)
                append_byte(o, w, 44)
                emit_number(o, w, get(w, S + 184))
                append_byte(o, w, 93)
            emitted = emitted + 1
        item = next_node(w, item)
        annotation = next_node(w, annotation)
    if error(w) != 0:
        put(w, S + 136, 64)
        emitted = 0
        emit_text(o, w, '{"origins":[')
    emit_text(o, w, ']}')
    if get(w, S + 144) != 0:
        return 4294967280
    put(o, 0, ORIGINS_MAGIC)
    put(o, 8, error(w))
    put(o, 16, emitted)
    put(o, 24, get(w, S + 136) - 64)
    put(o, 32, get(w, S + 24))
    put(o, 40, get(w, S + 16) - 16 - get(w, S + 24))
    put(o, 48, get(w, S + 32))
    put(o, 56, 0)
    return get(w, S + 136)

def partial_step(w:mutbuf) -> u64:
    steps = get(w, S + 32) + 1
    put(w, S + 32, steps)
    if steps > 32768:
        return reject(w, 25)
    return 1

def has_parameters(w:mutbuf, root:u64, params:u64) -> u64:
    depth = 1
    put(w, REFSTACK, root)
    put(w, REFSTACK + 8, 0)
    while depth != 0 and error(w) == 0:
        slot = REFSTACK + (depth - 1) * 24
        ref = get(w, slot)
        if get(w, slot + 8) == 0:
            if partial_step(w) == 0:
                return 0
            if kind(w, ref) == 4:
                if has_name(w, params, ref) == 1:
                    return 1
                depth = depth - 1
            elif field(w, ref, K_partial) != N:
                put(w, slot, field(w, ref, K_partial))
            else:
                put(w, slot + 8, 1)
                put(w, slot + 16, child(w, field(w, ref, K_args)))
        else:
            item = get(w, slot + 16)
            if item == N:
                depth = depth - 1
            else:
                put(w, slot + 16, next_node(w, item))
                put(w, slot + 24, item)
                put(w, slot + 32, 0)
                depth = depth + 1
    return 0

def symbolic_binding(w:mutbuf, environment:u64, name:u64) -> u64:
    if environment == 0:
        return 0
    params = child(w, get(w, environment))
    index = 1
    while params != N:
        if equal_text(w, params, name) == 1:
            return index
        params = next_node(w, params)
        index = index + 1
    return 0

def text_hash(w:mutbuf, node:u64) -> u64:
    value = 1469598103934665603
    i = 0
    while i < count(w, node):
        value = (value ^ byte(w, data(w, node) + i)) * 1099511628211
        i = i + 1
    return value

def symbol_intern(w:mutbuf, category:u64, name:u64, size:u64, payload:u64) -> u64:
    hash_value = category * 1099511628211
    if name != N:
        hash_value = hash_value ^ text_hash(w, name)
    i = 0
    while i < size:
        item = get(w, payload + i * 8)
        if category == 4 and i > 0:
            item = text_hash(w, item)
        hash_value = (hash_value ^ item) * 1099511628211
        i = i + 1
    index = hash_value & 65535
    found = get(w, SYMHASH + index * 8)
    while found != 0:
        if get(w, found) == category and get(w, found + 16) == size and get(w, found + 24) == hash_value:
            matches = 1
            if name != N and equal_text(w, get(w, found + 8), name) == 0:
                matches = 0
            i = 0
            while i < size and matches == 1:
                a = get(w, found + 32 + i * 8)
                b = get(w, payload + i * 8)
                if category == 4 and i > 0:
                    matches = equal_text(w, a, b)
                elif a != b:
                    matches = 0
                i = i + 1
            if matches == 1:
                return found
        index = (index + 1) & 65535
        found = get(w, SYMHASH + index * 8)
    target = get(w, S + 96)
    # The 32768 semantic-step budget bounds this exact DAG's node/edge volume.
    # This guard is corruption containment, never an alternative work quota.
    if target + 32 + size * 8 > get(w, S + 160):
        return reject(w, 25)
    put(w, target, category)
    put(w, target + 8, name)
    put(w, target + 16, size)
    put(w, target + 24, hash_value)
    i = 0
    while i < size:
        put(w, target + 32 + i * 8, get(w, payload + i * 8))
        i = i + 1
    put(w, S + 96, target + 32 + size * 8)
    put(w, SYMHASH + index * 8, target)
    return target

def push_symbol(w:mutbuf, slot:u64, ref:u64, environment:u64, depth:u64) -> u64:
    put(w, slot, ref)
    put(w, slot + 8, environment)
    put(w, slot + 16, depth)
    put(w, slot + 24, 0)
    put(w, slot + 56, 0)
    return 0

def symbolic_reference(w:mutbuf, ref:u64, environment:u64) -> u64:
    push_symbol(w, SYMSTACK, ref, environment, 0)
    depth = 1
    while depth != 0 and error(w) == 0:
        slot = SYMSTACK + (depth - 1) * 640
        phase = get(w, slot + 24)
        action = 0
        if phase == 0:
            action = symbol_enter(w, slot)
        elif phase == 1:
            item = get(w, slot + 48)
            if item == N:
                value = symbol_intern(w, 3, get(w, slot + 40), get(w, slot + 56), slot + 96)
                put(w, S + 120, value)
            else:
                put(w, slot + 48, next_node(w, item))
                put(w, slot + 24, 2)
                push_symbol(w, slot + 640, item, get(w, slot + 8), get(w, slot + 16) + 1)
                action = 2
        elif phase == 2:
            index = get(w, slot + 56)
            put(w, slot + 96 + index * 8, get(w, S + 120))
            put(w, slot + 56, index + 1)
            put(w, slot + 24, 1)
            action = 1
        elif phase == 4:
            put(w, slot + 96, get(w, S + 120))
            item = child(w, field(w, get(w, slot), K_initialized))
            size = 1
            while item != N:
                put(w, slot + 96 + size * 8, item)
                size = size + 1
                item = next_node(w, item)
            put(w, S + 120, symbol_intern(w, 4, N, size, slot + 96))
        if action == 0:
            depth = depth - 1
        elif action == 2:
            depth = depth + 1
    if error(w) != 0:
        return 0
    return get(w, S + 120)

def symbol_enter(w:mutbuf, slot:u64) -> u64:
    if partial_step(w) == 0:
        return 0
    if get(w, slot + 16) > 64:
        reject(w, 27)
        return 0
    ref = get(w, slot)
    environment = get(w, slot + 8)
    if kind(w, ref) == 4:
        index = symbolic_binding(w, environment, ref)
        if index != 0:
            if get(w, environment + 24) == 1:
                put(w, S + 120, 1)
                return 0
            put(w, slot + 24, 3)
            argument = at(w, get(w, environment + 8), index - 1)
            push_symbol(w, slot + 640, argument, get(w, environment + 16), get(w, slot + 16) + 1)
            return 2
        put(w, S + 120, symbol_intern(w, 2, ref, 0, slot + 96))
        return 0
    if field(w, ref, K_partial) != N:
        put(w, slot + 24, 4)
        push_symbol(w, slot + 640, field(w, ref, K_partial), environment, get(w, slot + 16) + 1)
        return 2
    put(w, slot + 40, field(w, ref, K_name))
    put(w, slot + 48, child(w, field(w, ref, K_args)))
    put(w, slot + 24, 1)
    return 1

def memo_get(w:mutbuf, symbol:u64, depth:u64) -> u64:
    index = ((symbol * 1099511628211) ^ depth) & 65535
    slot = MEMO + index * 24
    while get(w, slot) != 0:
        if get(w, slot) == symbol and get(w, slot + 8) == depth:
            return get(w, slot + 16)
        index = (index + 1) & 65535
        slot = MEMO + index * 24
    return 0

def memo_store(w:mutbuf, symbol:u64, depth:u64, result:u64) -> u64:
    index = ((symbol * 1099511628211) ^ depth) & 65535
    slot = MEMO + index * 24
    while get(w, slot) != 0:
        if get(w, slot) == symbol and get(w, slot + 8) == depth:
            put(w, slot + 16, result + 1)
            return 0
        index = (index + 1) & 65535
        slot = MEMO + index * 24
    put(w, slot, symbol)
    put(w, slot + 8, depth)
    put(w, slot + 16, result + 1)
    return 0

def push_loan(w:mutbuf, slot:u64, ref:u64, environment:u64, depth:u64) -> u64:
    if slot < get(w, S + 96):
        return reject(w, 25)
    put(w, slot, ref)
    put(w, slot + 8, environment)
    put(w, slot + 16, depth)
    put(w, slot + 24, 0)
    return 0

def known_loans(w:mutbuf, ref:u64, params:u64) -> u64:
    environment = FRAMES - 32
    put(w, environment, params)
    put(w, environment + 8, N)
    put(w, environment + 16, 0)
    put(w, environment + 24, 1)
    push_loan(w, environment - 192, ref, environment, 0)
    depth = 1
    while depth != 0 and error(w) == 0:
        slot = environment - depth * 192
        put(w, S + 160, slot)
        phase = get(w, slot + 24)
        action = 0
        if phase == 0:
            action = loan_enter(w, slot)
        elif phase == 1:
            next_ref = loan_next(w, slot)
            if next_ref == N:
                loan_finish(w, slot, 0)
            else:
                put(w, slot + 24, 3)
                push_loan(w, slot - 192, next_ref, slot + 128, get(w, slot + 16) + 1)
                action = 2
        elif phase == 2:
            loan_finish(w, slot, get(w, S + 128))
        else:
            if get(w, S + 128) == 1:
                loan_finish(w, slot, 1)
            else:
                put(w, slot + 24, 1)
                action = 1
        if action == 0:
            depth = depth - 1
        elif action == 2:
            depth = depth + 1
    put(w, S + 160, FRAMES)
    if error(w) != 0:
        return 0
    return get(w, S + 128)

def loan_enter(w:mutbuf, slot:u64) -> u64:
    if partial_step(w) == 0:
        return 0
    if get(w, slot + 16) > 32:
        reject(w, 26)
        return 0
    ref = get(w, slot)
    environment = get(w, slot + 8)
    symbol = symbolic_reference(w, ref, environment)
    if error(w) != 0:
        return 0
    put(w, slot + 32, symbol)
    cached = memo_get(w, symbol, get(w, slot + 16))
    if cached != 0:
        put(w, S + 128, cached - 1)
        return 0
    if kind(w, ref) == 4:
        index = symbolic_binding(w, environment, ref)
        if index != 0:
            if get(w, environment + 24) == 1:
                loan_finish(w, slot, 0)
                return 0
            put(w, slot + 24, 2)
            argument = at(w, get(w, environment + 8), index - 1)
            push_loan(w, slot - 192, argument, get(w, environment + 16), get(w, slot + 16))
            return 2
        identifier = primitive(w, ref)
        if identifier != 0:
            loan_finish(w, slot, choose(identifier == 14 or identifier == 15, 1, 0))
            return 0
    elif field(w, ref, K_partial) != N:
        put(w, slot + 24, 2)
        push_loan(w, slot - 192, field(w, ref, K_partial), environment, get(w, slot + 16) + 1)
        return 2
    name = ref
    args = N
    if kind(w, ref) != 4:
        name = field(w, ref, K_name)
        args = field(w, ref, K_args)
    identifier = definition(w, name)
    item = def_node(w, identifier)
    category = get(w, DEFS + (identifier - 1) * 24 + 16)
    put(w, slot + 48, category)
    put(w, slot + 56, item)
    put(w, slot + 64, N)
    put(w, slot + 72, N)
    put(w, slot + 80, 0)
    put(w, slot + 128, field(w, item, K_params))
    put(w, slot + 136, args)
    put(w, slot + 144, environment)
    put(w, slot + 152, 0)
    if category == 1:
        put(w, slot + 72, child(w, field(w, item, K_fields)))
    elif category == 2:
        put(w, slot + 64, child(w, field(w, item, K_variants)))
    put(w, slot + 24, 1)
    return 1

def loan_next(w:mutbuf, slot:u64) -> u64:
    category = get(w, slot + 48)
    if category == 3:
        index = get(w, slot + 80)
        put(w, slot + 80, index + 1)
        if index == 0:
            return field(w, get(w, slot + 56), K_state)
        if index == 1:
            return field(w, get(w, slot + 56), K_result)
        return N
    if category == 2:
        while get(w, slot + 72) == N and get(w, slot + 64) != N:
            variant = get(w, slot + 64)
            put(w, slot + 72, child(w, field(w, variant, K_fields)))
            put(w, slot + 64, next_node(w, variant))
    item = get(w, slot + 72)
    if item == N:
        return N
    put(w, slot + 72, next_node(w, item))
    return field(w, item, K_type)

def loan_finish(w:mutbuf, slot:u64, result:u64) -> u64:
    memo_store(w, get(w, slot + 32), get(w, slot + 16), result)
    put(w, S + 128, result)
    return 0

def append_byte(o:mutbuf, w:mutbuf, value:u64) -> u64:
    index = get(w, S + 136)
    if index >= O_BYTES:
        put(w, S + 144, 1)
    else:
        store(o, index, value)
        put(w, S + 136, index + 1)
    return 0

def emit(o:mutbuf, w:mutbuf, n:u64, a:u64, b:u64, c:u64) -> u64:
    i = 0
    while i < n:
        word = a
        shift = i * 8
        if i >= 8:
            word = b
            shift = (i - 8) * 8
        if i >= 16:
            word = c
            shift = (i - 16) * 8
        append_byte(o, w, (word >> shift) & 255)
        i = i + 1
    return 0

def emit_name(o:mutbuf, w:mutbuf, node:u64) -> u64:
    append_byte(o, w, 34)
    i = 0
    while i < count(w, node):
        append_byte(o, w, byte(w, data(w, node) + i))
        i = i + 1
    append_byte(o, w, 34)
    return 0

def emit_number(o:mutbuf, w:mutbuf, value:u64) -> u64:
    hundreds = 0
    while value >= 100:
        value = value - 100
        hundreds = hundreds + 1
    tens = 0
    while value >= 10:
        value = value - 10
        tens = tens + 1
    if hundreds != 0:
        append_byte(o, w, 48 + hundreds)
    if hundreds != 0 or tens != 0:
        append_byte(o, w, 48 + tens)
    append_byte(o, w, 48 + value)
    return 0

def emit_optional_id(o:mutbuf, w:mutbuf, value:u64) -> u64:
    if value == 0:
        emit_text(o, w, 'null')
    else:
        emit_number(o, w, value)
    return 0

def emit_optional_name(o:mutbuf, w:mutbuf, value:u64) -> u64:
    if value == 0:
        emit_text(o, w, 'null')
    else:
        emit_name(o, w, value)
    return 0

def render_result(o:mutbuf, w:mutbuf, result:u64) -> u32:
    put(w, S + 136, 64)
    put(w, S + 144, 0)
    emit_text(o, w, '{"types":[')
    identifier = 1
    previous = 0
    while identifier <= get(w, S + 16):
        slot = type_at(identifier)
        if get(w, slot + 37872) == 1 and get(w, slot + 37880) == 0:
            if previous != 0:
                append_byte(o, w, 44)
            render_type(o, w, identifier)
            previous = 1
        identifier = identifier + 1
    emit_text(o, w, ']}')
    if get(w, S + 144) != 0:
        return 4294967280
    identifier = 1
    while identifier <= get(w, S + 16):
        slot = type_at(identifier)
        if get(w, slot + 37872) == 1:
            put(w, slot + 37880, 1)
        identifier = identifier + 1
    put(o, 0, MAGIC)
    put(o, 8, error(w))
    put(o, 16, result)
    put(o, 24, get(w, S + 136) - 64)
    put(o, 32, get(w, S + 24))
    put(o, 40, get(w, S + 16) - 16 - get(w, S + 24))
    put(o, 48, get(w, S + 32))
    put(o, 56, 0)
    return get(w, S + 136)

def render_type(o:mutbuf, w:mutbuf, identifier:u64) -> u64:
    record = type_at(identifier)
    category = get(w, record)
    emit_text(o, w, '{"args":[')
    i = 0
    while i < get(w, record + 16):
        if i != 0:
            append_byte(o, w, 44)
        emit_number(o, w, get(w, record + 24 + i * 8))
        i = i + 1
    emit_text(o, w, '],"cancel":')
    emit_optional_name(o, w, get(w, record + 37832))
    emit_text(o, w, ',"fields":')
    if category == 2:
        emit_text(o, w, '[]')
    else:
        render_fields(o, w, record, 0, get(w, record + 4256))
    emit_text(o, w, ',"flat":[')
    i = 0
    while i < get(w, record + 152):
        if i != 0:
            append_byte(o, w, 44)
        emit_number(o, w, get(w, record + 160 + i * 8))
        i = i + 1
    emit_text(o, w, '],"id":')
    emit_number(o, w, identifier)
    emit_text(o, w, ',"kind":"')
    if category == 0:
        emit_text(o, w, 'primitive')
    elif category == 1:
        emit_text(o, w, 'record')
    elif category == 2:
        emit_text(o, w, 'enum')
    elif category == 3:
        emit_text(o, w, 'task')
    else:
        emit_text(o, w, 'partial_record')
    emit_text(o, w, '","linear":')
    if get(w, record + 37840) == 0:
        emit_text(o, w, 'false')
    else:
        emit_text(o, w, 'true')
    emit_text(o, w, ',"name":')
    if category == 0:
        append_byte(o, w, 34)
        primitive_name(o, w, identifier)
        append_byte(o, w, 34)
    elif category == 4:
        emit_text(o, w, 'null')
    else:
        emit_name(o, w, field(w, def_node(w, get(w, record + 8)), K_name))
    emit_text(o, w, ',"poll":')
    emit_optional_name(o, w, get(w, record + 37824))
    emit_text(o, w, ',"record":')
    emit_optional_id(o, w, get(w, record + 37864))
    emit_text(o, w, ',"result":')
    emit_optional_id(o, w, get(w, record + 37816))
    emit_text(o, w, ',"state":')
    emit_optional_id(o, w, get(w, record + 37808))
    emit_text(o, w, ',"variants":[')
    i = 0
    while i < get(w, record + 37032):
        if i != 0:
            append_byte(o, w, 44)
        variant = record + 37040 + i * 24
        append_byte(o, w, 91)
        emit_name(o, w, get(w, variant))
        append_byte(o, w, 44)
        render_fields(o, w, record, get(w, variant + 8), get(w, variant + 16))
        append_byte(o, w, 93)
        i = i + 1
    emit_text(o, w, ']}')
    return 0

def render_fields(o:mutbuf, w:mutbuf, record:u64, start:u64, size:u64) -> u64:
    append_byte(o, w, 91)
    i = 0
    while i < size:
        if i != 0:
            append_byte(o, w, 44)
        append_byte(o, w, 91)
        emit_name(o, w, get(w, record + 4264 + (start + i) * 16))
        append_byte(o, w, 44)
        emit_number(o, w, get(w, record + 4272 + (start + i) * 16))
        append_byte(o, w, 93)
        i = i + 1
    append_byte(o, w, 93)
    return 0
'''


def source_program():
    constants = {**CONSTANTS, **{'K_' + key: 1 << i for i, key in enumerate(KEYS)}}
    literals = {'L_' + key: packed(value) for key, value in LITERALS.items()}

    class Expand(ast.NodeTransformer):
        def visit_Expr(self, node):
            if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == 'emit_text'):
                output, workspace, literal = node.value.args
                assert isinstance(literal, ast.Constant) and type(literal.value) is str
                return [ast.Expr(value=ast.Call(func=ast.Name(id='emit', ctx=ast.Load()),
                    args=[output, workspace, *(ast.Constant(value) for value in packed(literal.value[i:i + 24]))],
                    keywords=[])) for i in range(0, len(literal.value), 24)]
            return self.generic_visit(node)

        def visit_Name(self, node):
            return ast.Constant(constants[node.id]) if node.id in constants else node

        def visit_Call(self, node):
            node = self.generic_visit(node)
            args = []
            for arg in node.args:
                args.extend(ast.Constant(value) for value in literals[arg.id]) if isinstance(arg, ast.Name) and arg.id in literals else args.append(arg)
            node.args = args
            return node

    own = Expand().visit(ast.parse(BODY))
    key = ['def key_id(w:mutbuf, node:u64) -> u64:',
           '    start = arena(node) + get(w, node + 40)',
           '    size = get(w, node + 48)']
    for i, name in enumerate(KEYS):
        key += ['    if same(w, start, size, ' + ', '.join(map(str, packed(name))) + ') == 1:',
                '        return ' + str(1 << i)]
    key += ['    return 0']
    primitive = ['def primitive(w:mutbuf, node:u64) -> u64:']
    for i, name in enumerate(PRIMITIVES, 1):
        primitive += ['    if text_is(w, node, ' + ', '.join(map(str, packed(name))) + ') == 1:']
        if name == 'chain':
            primitive += ['        return choose(get(w, ' + str(CONSTANTS['S'] + 56) + ') == 1, 16, 0)']
        else:
            primitive += ['        return ' + str(i)]
    primitive += ['    return 0']
    labels = ['def primitive_name(o:mutbuf, w:mutbuf, identifier:u64) -> u64:']
    for i, name in enumerate(PRIMITIVES, 1):
        labels += ['    if identifier == ' + str(i) + ':',
                   '        return emit(o, w, ' + ', '.join(map(str, packed(name))) + ')']
    labels += ['    return 0']
    decoder = decoder_source()
    # Only this private framed command uses the allowance. Keep both the
    # decoder entry and its embedded lexical preflight in the same profile;
    # the shared decoder and all public Core limits remain unchanged.
    assert decoder.count('length(s) > 8388608') == 2
    decoder = decoder.replace('length(s) > 8388608', 'length(s) > ' + str(MAX_COMMAND_BYTES))
    return ast.unparse(ast.fix_missing_locations(own)) + '\n' + '\n'.join(key + primitive + labels) + '\n' + decoder


def document():
    nodes = ast.parse(source_program()).body
    assert len({node.name for node in nodes}) == len(nodes)
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'composite_types', 'functions': functions})


def main():
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/composite_types.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)


if __name__ == '__main__':
    main()
