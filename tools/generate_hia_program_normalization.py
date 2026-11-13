"""Author the complete public object/text normalization coordinator in HIA.

Foreign requests observe exact builtin objects or call the two explicitly held
HIA byte codecs.  Snapshot traversal, cycle/queued-node admission, structure
order, Unicode/decimal accounting, sorting and serialization live in this
program.  No smaller object, integer or serialized-byte profile is introduced.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.hia_program_normalization_materialize import (
    FRAGMENT_FUNCTIONS, exported_bindings, fragment_functions,
)
from tools.hia_program_normalization_encoding import BODY as ENCODING

MAX_BYTES = 8 << 20
MAX_NODES = 262144
NODE_BASE = 4096
NODE_CAPACITY = MAX_NODES * 2 + 65
POOL_BASE = NODE_BASE + NODE_CAPACITY * 128
BINARY_BASE = POOL_BASE + MAX_BYTES
DECIMAL_BASE = BINARY_BASE + MAX_BYTES // 2 + 16
WORKSPACE_BYTES = 128 << 20
ENCODE_STACK_BASE = DECIMAL_BASE + MAX_BYTES * 2
CONSTANTS = {
    'MAX_BYTES': MAX_BYTES, 'MAX_NODES': MAX_NODES, 'MAX_DEPTH': 64,
    'NODE_BASE': NODE_BASE, 'NODE_CAPACITY': NODE_CAPACITY, 'POOL_BASE': POOL_BASE, 'BINARY_BASE': BINARY_BASE,
    'DECIMAL_BASE': DECIMAL_BASE, 'WORKSPACE_BYTES': WORKSPACE_BYTES,
    'ENCODE_STACK_BASE': ENCODE_STACK_BASE, 'PRE_STACK_BASE': 1024,
    'NONE': (1 << 64) - 1, 'BAD_ABI': 0xffffffff,
    'INPUT_MAGIC': int.from_bytes(b'HIANORQ2', 'little'),
    'STATE_MAGIC': int.from_bytes(b'HIANORS2', 'little'),
    'OUTPUT_MAGIC': int.from_bytes(b'HIANORP2', 'little'),
}

# Fixed state fields are byte offsets. Nodes contain kind/opaque handle,
# parent/next/previous/first/last/count, key handle/key offset/key bytes,
# scalar offset/scalar bytes and three reserved/capture words.
for index, name in enumerate(('MAGIC', 'NONCE_LO', 'NONCE_HI', 'SEQUENCE', 'ACTION',
        'LAUNCHED', 'PHASE', 'ERROR', 'CALLER', 'NODES', 'SNAP_COUNT', 'SNAP_QUEUED',
        'CURRENT', 'AVAILABLE', 'ITERATOR', 'STRUCT_COUNT', 'STRUCT_QUEUED', 'SIZE',
        'POOL_USED', 'KEY_NODE', 'STRING_NODE', 'STRING_KEY', 'STRING_LENGTH',
        'STRING_OFFSET', 'STRING_SIZE', 'STRING_START', 'RAW_LENGTH', 'RAW_OFFSET',
        'RAW_BYTES', 'OUT_CURSOR', 'INT_BITS', 'INT_NEGATIVE', 'DECIMAL_COUNT',
        'DIGITS', 'REQUEST_HANDLE', 'REQUEST_A', 'REQUEST_B', 'ROOT_HANDLE', 'TYPE_HANDLE', 'DECLARED', 'DIRECT_KEY', 'FINAL_SIZE', 'MAT_BASE', 'MAT_POSITION',
        'MAT_DEPTH', 'MAT_COUNT', 'MAT_ROOT', 'MAT_KIND', 'MAT_START', 'MAT_LENGTH',
        'MAT_VALUE', 'EXPECT_COUNT', 'E_DEPTH', 'E_OVERFLOW', 'E_SURROGATE', 'E_NODE',
        'E_HANDLE', 'E_KEY', 'E_KIND', 'E_CAPTURE', 'E_PUSH_MODE', 'E_STRING_LENGTH',
        'E_STRING_OFFSET', 'E_BITS', 'E_LIMIT', 'E_BINARY', 'E_DECIMAL', 'E_INTEGER_BYTES',
        'E_SCOPE_CURRENT', 'E_SCOPE_SEQUENCE', 'E_PENDING_ERROR', 'FOREIGN_ERROR',
        'STAGE', 'PRE_DEPTH', 'PRE_NODE', 'PRE_NEXT', 'PRE_CLEANUP', 'E_OUTPUT_RESUME',
        'PYTHON_NOTES', 'E_NOTE_OLD_ERROR')):
    CONSTANTS['H_' + name] = index * 8


class NormalizationBuilder(Builder):
    def expr(self, value):
        if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.FloorDiv, ast.Mod)):
            left, right = self.expr(value.left), self.expr(value.right)
            if left[1] != 'u64' or right[1] != 'u64':
                raise ValueError('normalization division/remainder requires u64')
            return self.op('int.div.checked' if isinstance(value.op, ast.FloorDiv)
                           else 'int.rem.checked', [left, right], 'u64')
        return super().expr(value)


SOURCE = r'''
def normalize_state(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 128 or length(o) < MAX_BYTES + 64 or length(w) < WORKSPACE_BYTES:
        return BAD_ABI
    if norm_read(s, 0, 8) != INPUT_MAGIC or norm_read(s, 80, 8) != length(s) - 128:
        return BAD_ABI
    if norm_read(s, 88, 8) != 0 or norm_read(s, 96, 8) != 0 or norm_read(s, 104, 8) != 0 or norm_read(s, 112, 8) != 0 or norm_read(s, 120, 8) != 0:
        return BAD_ABI
    event = norm_read(s, 8, 8)
    if event == 0:
        if get(w, H_MAGIC) != 0 or length(s) != 128 or norm_read(s, 32, 8) != 0 or norm_read(s, 40, 8) != 0 or norm_read(s, 48, 8) != 0 or norm_read(s, 72, 8) > 1:
            return BAD_ABI
        handle = norm_read(s, 56, 8)
        digits = norm_read(s, 64, 8)
        if handle == 0 or (digits != 0 and digits < 640):
            return BAD_ABI
        fill_range(w, 0, 4096, 0)
        put(w, H_MAGIC, STATE_MAGIC)
        put(w, H_NONCE_LO, norm_read(s, 16, 8))
        put(w, H_NONCE_HI, norm_read(s, 24, 8))
        put(w, H_DIGITS, digits)
        put(w, H_PYTHON_NOTES, norm_read(s, 72, 8))
        put(w, H_ROOT_HANDLE, handle)
        put(w, H_NODES, 1)
        norm_node(w, 0, handle, NONE, 0)
        put(w, H_PHASE, 100)
        return norm_issue(w, o, 10, handle, 0, 0)
    if get(w, H_MAGIC) != STATE_MAGIC or get(w, H_PHASE) == 99:
        return BAD_ABI
    if norm_read(s, 16, 8) != get(w, H_NONCE_LO) or norm_read(s, 24, 8) != get(w, H_NONCE_HI):
        return BAD_ABI
    if norm_read(s, 32, 8) != get(w, H_SEQUENCE) or norm_read(s, 40, 8) != get(w, H_ACTION):
        return BAD_ABI
    if event == 1:
        if get(w, H_LAUNCHED) != 0 or length(s) != 128 or norm_read(s, 48, 8) != 0 or norm_read(s, 56, 8) != 0 or norm_read(s, 64, 8) != 0 or norm_read(s, 72, 8) != 0:
            return BAD_ABI
        put(w, H_LAUNCHED, 1)
        return norm_frame(w, o, 0)
    if event != 2 or get(w, H_LAUNCHED) != 1:
        return BAD_ABI
    put(w, H_LAUNCHED, 0)
    result = norm_widen(norm_ack(s, o, w))
    while result == 0:
        result = norm_widen(norm_drive(w, o))
    return result

def norm_widen(value:u32) -> u64:
    return value

def norm_read(s:readbuf, at:u64, count:u64) -> u64:
    value = 0
    i = 0
    while i < count:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def norm_record(node:u64) -> u64:
    return NODE_BASE + node * 128

def norm_node(w:mutbuf, node:u64, handle:u64, parent:u64, key:u64) -> u64:
    at = norm_record(node)
    fill_range(w, at, 128, 0)
    put(w, at + 8, handle)
    put(w, at + 16, parent)
    put(w, at + 24, NONE)
    put(w, at + 32, NONE)
    put(w, at + 40, NONE)
    put(w, at + 48, NONE)
    put(w, at + 64, key)
    return 0

def norm_frame(w:mutbuf, o:mutbuf, payload:u64) -> u32:
    put(o, 0, OUTPUT_MAGIC)
    put(o, 8, get(w, H_SEQUENCE))
    put(o, 16, get(w, H_ACTION))
    put(o, 24, get(w, H_ERROR))
    put(o, 32, get(w, H_REQUEST_HANDLE))
    put(o, 40, get(w, H_REQUEST_A))
    put(o, 48, get(w, H_REQUEST_B))
    put(o, 56, payload)
    return 64 + payload

def norm_issue(w:mutbuf, o:mutbuf, action:u64, handle:u64, a:u64, b:u64) -> u32:
    if get(w, H_SEQUENCE) == NONE:
        return BAD_ABI
    put(w, H_SEQUENCE, get(w, H_SEQUENCE) + 1)
    put(w, H_ACTION, action)
    put(w, H_REQUEST_HANDLE, handle)
    put(w, H_REQUEST_A, a)
    put(w, H_REQUEST_B, b)
    return norm_frame(w, o, 0)

def norm_error(w:mutbuf, o:mutbuf, code:u64) -> u32:
    if get(w, H_STAGE) == 3 and get(w, H_E_SCOPE_CURRENT) != 0:
        return norm_encode_abort(w, o, code)
    return norm_error_final(w, o, code)

def norm_error_final(w:mutbuf, o:mutbuf, code:u64) -> u32:
    put(w, H_PHASE, 99)
    put(w, H_ACTION, 0)
    put(w, H_ERROR, code)
    put(w, H_REQUEST_HANDLE, choose(code == 20, get(w, H_FOREIGN_ERROR), 0))
    put(w, H_REQUEST_A, 0)
    put(w, H_REQUEST_B, 0)
    return norm_frame(w, o, 0)

def norm_done(w:mutbuf, o:mutbuf, size:u64) -> u32:
    put(w, H_PHASE, 99)
    put(w, H_ACTION, 0)
    put(w, H_REQUEST_HANDLE, get(w, H_MAT_ROOT))
    put(w, H_REQUEST_A, get(w, H_MAT_COUNT))
    put(w, H_REQUEST_B, get(w, H_DIGITS))
    return norm_frame(w, o, size)

def norm_schedule(w:mutbuf, phase:u64, node:u64) -> u32:
    put(w, H_PHASE, phase)
    put(w, H_CURRENT, node)
    return 0

def norm_drive(w:mutbuf, o:mutbuf) -> u32:
    phase = get(w, H_PHASE)
    if phase == 30:
        return norm_structure_visit(w, o, get(w, H_CURRENT))
    if phase == 31:
        return norm_structure_advance(w, o, get(w, H_CURRENT))
    if phase == 32:
        return norm_structure_descend(w, o)
    if phase == 33:
        return norm_key_next(w, o)
    if phase == 34:
        put(w, H_PRE_CLEANUP, 6)
        put(w, H_PHASE, 153)
        return norm_issue(w, o, 53, 0, 6, 0)
    if phase == 120:
        return norm_snapshot_resume(w, o)
    if phase == 250:
        return norm_encode_next(w, o)
    if phase == 310:
        return norm_mat_next(w, o)
    return BAD_ABI

def norm_depth(w:mutbuf, node:u64) -> u64:
    depth = 0
    parent = get(w, norm_record(node) + 16)
    while parent != NONE:
        depth = depth + 1
        parent = get(w, norm_record(parent) + 16)
    return depth

def norm_cycle(w:mutbuf, node:u64) -> u64:
    handle = get(w, norm_record(node) + 8)
    parent = get(w, norm_record(node) + 16)
    while parent != NONE:
        if get(w, norm_record(parent) + 8) == handle:
            return 1
        parent = get(w, norm_record(parent) + 16)
    return 0

def norm_snapshot_visit(w:mutbuf, o:mutbuf, node:u64) -> u32:
    put(w, H_CURRENT, node)
    put(w, H_PHASE, 102)
    return norm_issue(w, o, 53, get(w, norm_record(node) + 8), 1, 0)

def norm_snapshot_after_pin(w:mutbuf, o:mutbuf) -> u32:
    node = get(w, H_CURRENT)
    put(w, H_SNAP_COUNT, get(w, H_SNAP_COUNT) + 1)
    put(w, H_SNAP_QUEUED, get(w, H_SNAP_QUEUED) - 1)
    if get(w, H_SNAP_COUNT) > MAX_NODES or norm_depth(w, node) > MAX_DEPTH:
        return norm_error(w, o, 4)
    put(w, H_PHASE, 10)
    return norm_issue(w, o, 10, get(w, norm_record(node) + 8), 1, 0)

def norm_snapshot_kind(s:readbuf, w:mutbuf, o:mutbuf) -> u32:
    node = get(w, H_CURRENT)
    at = norm_record(node)
    container = norm_read(s, 56, 8)
    held_type = norm_read(s, 64, 8)
    kind = norm_read(s, 72, 8)
    if length(s) != 128 or container > 1 or held_type == 0 or kind > 8:
        return BAD_ABI
    put(w, at, kind)
    put(w, H_TYPE_HANDLE, held_type)
    if container != 0:
        # The captured type's equality chooses membership; the dict arm is
        # still an identity test. Every other admitted container is copied as
        # a plain list, exactly as the original snapshot.
        put(w, at, choose(kind == 6, 6, 5))
        put(w, at + 104, 1)
        if norm_cycle(w, node) != 0:
            return norm_error(w, o, 5)
        put(w, H_AVAILABLE, MAX_NODES - get(w, H_SNAP_COUNT) - get(w, H_SNAP_QUEUED))
        return norm_pre_begin(w, o, 103)
    # This second tuple-membership expression is independently observable.
    put(w, H_PHASE, 101)
    return norm_issue(w, o, 11, held_type, 0, 0)

def norm_snapshot_advance(w:mutbuf, o:mutbuf, node:u64) -> u32:
    put(w, H_PRE_NODE, get(w, norm_record(node) + 16))
    put(w, H_PRE_NEXT, get(w, norm_record(node) + 24))
    return norm_schedule(w, 120, node)

def norm_capture_next(w:mutbuf, o:mutbuf) -> u32:
    put(w, H_PHASE, 13)
    return norm_issue(w, o, 4, get(w, H_ITERATOR), get(w, norm_record(get(w, H_CURRENT))), 0)

def norm_capture(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    status = norm_read(s, 48, 8)
    at = norm_record(get(w, H_CURRENT))
    count = get(w, at + 56)
    if length(s) != 128 or status > 2:
        return BAD_ABI
    if status == 2:
        return norm_error(w, o, 10)
    if status == 0:
        put(w, H_SNAP_QUEUED, get(w, H_SNAP_QUEUED) + count)
        put(w, H_PHASE, 104)
        return norm_issue(w, o, 52, get(w, H_ITERATOR), get(w, H_E_SCOPE_CURRENT), 0)
    if get(w, at) == 6 and norm_read(s, 72, 8) != 4:
        return norm_error(w, o, 7)
    if count >= get(w, H_AVAILABLE):
        return norm_error(w, o, choose(get(w, at) == 6, 8, 9))
    child = get(w, H_NODES)
    if child >= MAX_NODES or norm_read(s, 56, 8) == 0:
        return BAD_ABI
    key = 0
    if get(w, at) == 6:
        key = norm_read(s, 64, 8)
        if key == 0:
            return BAD_ABI
    norm_node(w, child, norm_read(s, 56, 8), get(w, H_CURRENT), key)
    previous = get(w, at + 48)
    if previous == NONE:
        put(w, at + 40, child)
    else:
        put(w, norm_record(previous) + 24, child)
    put(w, norm_record(child) + 32, previous)
    put(w, at + 48, child)
    put(w, at + 56, count + 1)
    put(w, H_NODES, child + 1)
    if key != 0:
        put(w, H_PHASE, 106)
        return norm_issue(w, o, 56, key, 0, 0)
    return norm_capture_next(w, o)

def norm_structure_begin(w:mutbuf, o:mutbuf) -> u32:
    put(w, H_STAGE, 2)
    put(w, H_STRUCT_COUNT, 0)
    put(w, H_STRUCT_QUEUED, 1)
    put(w, H_DECLARED, 1)
    return norm_schedule(w, 30, 0)

def norm_structure_visit(w:mutbuf, o:mutbuf, node:u64) -> u32:
    put(w, H_CURRENT, node)
    handle = get(w, norm_record(node) + 8)
    if get(w, norm_record(node) + 104) == 1:
        handle = 0
    put(w, H_PHASE, 147)
    return norm_issue(w, o, 53, handle, 6, 0)

def norm_structure_after_pin(w:mutbuf, o:mutbuf) -> u32:
    node = get(w, H_CURRENT)
    put(w, H_STRUCT_COUNT, get(w, H_STRUCT_COUNT) + 1)
    if get(w, H_STRUCT_COUNT) > MAX_NODES or norm_depth(w, node) > MAX_DEPTH:
        return norm_error(w, o, 12)
    at = norm_record(node)
    kind = get(w, at)
    if get(w, at + 104) != 1 and kind == 8:
        put(w, H_PHASE, 140)
        return norm_issue(w, o, 10, get(w, at + 8), 2, 0)
    put(w, H_PHASE, 148)
    return norm_issue(w, o, 53, 0, 7, 0)

def norm_structure_kind(w:mutbuf, o:mutbuf, kind:u64) -> u32:
    node = get(w, H_CURRENT)
    at = norm_record(node)
    if kind == 5 or kind == 6:
        count = get(w, at + 56)
        if count > MAX_NODES - get(w, H_DECLARED):
            return norm_error(w, o, 13)
        put(w, H_DECLARED, get(w, H_DECLARED) + count)
        put(w, H_SIZE, get(w, H_SIZE) + 2 + choose(count == 0, 0, count - 1))
        if kind == 6:
            put(w, H_SIZE, get(w, H_SIZE) + count)
            put(w, H_KEY_NODE, get(w, at + 40))
            return norm_schedule(w, 33, node)
        return norm_schedule(w, 32, node)
    if kind == 4:
        return norm_string_begin(w, o, node, 0)
    if kind == 3:
        put(w, H_PHASE, 22)
        return norm_issue(w, o, 7, get(w, at + 8), 0, 0)
    if kind > 4:
        return norm_error(w, o, 16)
    put(w, H_SIZE, get(w, H_SIZE) + choose(kind == 1, 5, 4))
    if get(w, H_SIZE) > MAX_BYTES:
        return norm_error(w, o, 18)
    return norm_schedule(w, 31, node)

def norm_structure_descend(w:mutbuf, o:mutbuf) -> u32:
    if get(w, H_SIZE) > MAX_BYTES:
        return norm_error(w, o, 18)
    node = get(w, H_CURRENT)
    at = norm_record(node)
    if get(w, at + 104) == 2:
        remaining = get(w, at + 120)
        if remaining != 0:
            if get(w, H_STRUCT_COUNT) >= MAX_NODES or norm_depth(w, node) >= MAX_DEPTH:
                return norm_error(w, o, 12)
            put(w, at + 120, remaining - 1)
            put(w, H_PHASE, 146)
            return norm_issue(w, o, 21, get(w, at + 112), remaining - 1, 0)
        put(w, H_PHASE, 151)
        return norm_issue(w, o, 53, 0, 6, 0)
    child = get(w, at + 48)
    if child != NONE:
        return norm_schedule(w, 30, child)
    return norm_schedule(w, 31, node)

def norm_structure_advance(w:mutbuf, o:mutbuf, node:u64) -> u32:
    while node != NONE:
        parent = get(w, norm_record(node) + 16)
        if parent != NONE:
            if get(w, norm_record(parent) + 104) == 2:
                return norm_schedule(w, 32, parent)
        previous = get(w, norm_record(node) + 32)
        if previous != NONE:
            return norm_schedule(w, 30, previous)
        node = parent
    return norm_schedule(w, 34, 0)

def norm_key_next(w:mutbuf, o:mutbuf) -> u32:
    key_node = get(w, H_KEY_NODE)
    if key_node == NONE:
        return norm_schedule(w, 32, get(w, H_CURRENT))
    return norm_string_begin(w, o, key_node, 1)

def norm_string_begin(w:mutbuf, o:mutbuf, node:u64, key:u64) -> u32:
    put(w, H_STRING_NODE, node)
    put(w, H_STRING_KEY, key)
    put(w, H_PHASE, 20)
    handle = get(w, norm_record(node) + 8)
    if key == 1:
        handle = get(w, norm_record(node) + 64)
    if key == 2:
        handle = get(w, H_DIRECT_KEY)
    return norm_issue(w, o, 2, handle, 0, 0)

def norm_string_next(w:mutbuf, o:mutbuf) -> u32:
    remaining = get(w, H_STRING_LENGTH) - get(w, H_STRING_OFFSET)
    if remaining == 0:
        return norm_string_done(w, o)
    if remaining > 4096:
        remaining = 4096
    handle = get(w, norm_record(get(w, H_STRING_NODE)) + 8)
    if get(w, H_STRING_KEY) == 1:
        handle = get(w, norm_record(get(w, H_STRING_NODE)) + 64)
    if get(w, H_STRING_KEY) == 2:
        handle = get(w, H_DIRECT_KEY)
    put(w, H_PHASE, 21)
    return norm_issue(w, o, 5, handle, get(w, H_STRING_OFFSET), remaining)

def norm_string_done(w:mutbuf, o:mutbuf) -> u32:
    at = norm_record(get(w, H_STRING_NODE))
    size = get(w, H_POOL_USED) - get(w, H_STRING_START)
    offset = 88
    if get(w, H_STRING_KEY) == 1:
        offset = 72
    if get(w, H_STRING_KEY) != 2:
        put(w, at + offset, POOL_BASE + get(w, H_STRING_START))
        put(w, at + offset + 8, size)
    put(w, H_SIZE, get(w, H_SIZE) + get(w, H_STRING_SIZE))
    if get(w, H_STRING_KEY) == 2:
        return norm_structure_key_request(w, o)
    if get(w, H_STRING_KEY) == 1:
        put(w, H_KEY_NODE, get(w, at + 24))
        return norm_schedule(w, 33, get(w, H_CURRENT))
    return norm_schedule(w, 31, get(w, H_CURRENT))

def norm_structure_cycle(w:mutbuf, node:u64) -> u64:
    identity = get(w, norm_record(node) + 8)
    parent = get(w, norm_record(node) + 16)
    while parent != NONE:
        at = norm_record(parent)
        # Detached snapshot containers have fresh identities. They cannot be
        # the same foreign object as a retained opaque leaf.
        if get(w, at + 104) != 1 and get(w, at + 8) == identity:
            return 1
        parent = get(w, at + 16)
    return 0

def norm_structure_key_request(w:mutbuf, o:mutbuf) -> u32:
    put(w, H_PHASE, 143)
    return norm_issue(w, o, 18, get(w, H_ITERATOR), 0, 0)

def norm_structure_capture_request(w:mutbuf, o:mutbuf) -> u32:
    put(w, H_PHASE, 145)
    at = norm_record(get(w, H_CURRENT))
    return norm_issue(w, o, 20, get(w, at + 8), get(w, at), 0)

def norm_structure_ack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, H_PHASE)
    node = get(w, H_CURRENT)
    at = norm_record(node)
    if length(s) != 128:
        return BAD_ABI
    if phase == 143:
        status = norm_read(s, 48, 8)
        if status == 0:
            return norm_structure_capture_request(w, o)
        if status != 1 or norm_read(s, 56, 8) == 0:
            return BAD_ABI
        if norm_read(s, 64, 8) != 4:
            return norm_error(w, o, 14)
        put(w, H_DIRECT_KEY, norm_read(s, 56, 8))
        return norm_string_begin(w, o, node, 2)
    if norm_read(s, 48, 8) != 0:
        return BAD_ABI
    if phase == 140:
        member = norm_read(s, 56, 8)
        kind = norm_read(s, 72, 8)
        if member > 1 or norm_read(s, 64, 8) == 0 or kind > 8:
            return BAD_ABI
        if member == 0:
            put(w, at, kind)
            return norm_structure_kind(w, o, kind)
        if norm_structure_cycle(w, node) != 0:
            return norm_error(w, o, 19)
        put(w, at, choose(kind == 6, 6, 5))
        put(w, at + 104, 2)
        return norm_pre_begin(w, o, 149)
    if phase == 141:
        count = norm_read(s, 56, 8)
        if count > MAX_NODES - get(w, H_DECLARED):
            return norm_error(w, o, 13)
        put(w, H_DECLARED, get(w, H_DECLARED) + count)
        put(w, at + 56, count)
        put(w, H_SIZE, get(w, H_SIZE) + 2 + choose(count == 0, 0, count - 1))
        if get(w, at) == 6:
            put(w, H_SIZE, get(w, H_SIZE) + count)
            put(w, H_PHASE, 142)
            return norm_issue(w, o, 17, get(w, at + 8), 0, 0)
        return norm_structure_capture_request(w, o)
    if phase == 142:
        if norm_read(s, 56, 8) == 0:
            return BAD_ABI
        put(w, H_ITERATOR, norm_read(s, 56, 8))
        return norm_structure_key_request(w, o)
    if phase == 145:
        if norm_read(s, 56, 8) == 0:
            return BAD_ABI
        put(w, at + 112, norm_read(s, 56, 8))
        put(w, at + 120, norm_read(s, 64, 8))
        return norm_schedule(w, 32, node)
    if phase == 146:
        child = get(w, H_NODES)
        if child >= NODE_CAPACITY or norm_read(s, 56, 8) == 0:
            return BAD_ABI
        norm_node(w, child, norm_read(s, 56, 8), node, 0)
        put(w, norm_record(child), 8)
        put(w, H_NODES, child + 1)
        return norm_schedule(w, 30, child)
    return BAD_ABI

def norm_raw_next(w:mutbuf, o:mutbuf) -> u32:
    remaining = get(w, H_RAW_LENGTH) - get(w, H_RAW_OFFSET)
    if remaining == 0:
        put(w, H_PHASE, 4)
        return norm_issue(w, o, 9, 0, get(w, H_RAW_BYTES), 0)
    if remaining > 4096:
        remaining = 4096
    put(w, H_PHASE, 3)
    return norm_issue(w, o, 6, get(w, H_ROOT_HANDLE), get(w, H_RAW_OFFSET), remaining)

def norm_pre_begin(w:mutbuf, o:mutbuf, phase:u64) -> u32:
    sequence = get(w, H_E_SCOPE_SEQUENCE)
    if sequence == NONE or get(w, H_PRE_DEPTH) > MAX_DEPTH:
        return BAD_ABI
    put(w, H_PHASE, phase)
    return norm_issue(w, o, 50, 0, sequence + 1, get(w, H_E_SCOPE_CURRENT))

def norm_pre_enter(s:readbuf, w:mutbuf) -> u64:
    scope = norm_read(s, 56, 8)
    depth = get(w, H_PRE_DEPTH)
    if scope != get(w, H_E_SCOPE_SEQUENCE) + 1 or scope != get(w, H_REQUEST_A) or depth > MAX_DEPTH:
        return 0
    frame = PRE_STACK_BASE + depth * 32
    put(w, frame, get(w, H_CURRENT))
    put(w, frame + 8, scope)
    put(w, frame + 16, get(w, H_E_SCOPE_CURRENT))
    put(w, frame + 24, 0)
    put(w, H_PRE_DEPTH, depth + 1)
    put(w, H_E_SCOPE_SEQUENCE, scope)
    put(w, H_E_SCOPE_CURRENT, scope)
    return 1

def norm_pre_end(w:mutbuf, o:mutbuf, phase:u64) -> u32:
    depth = get(w, H_PRE_DEPTH)
    if depth == 0:
        return BAD_ABI
    frame = PRE_STACK_BASE + (depth - 1) * 32
    if get(w, frame) != get(w, H_CURRENT) or get(w, frame + 8) != get(w, H_E_SCOPE_CURRENT):
        return BAD_ABI
    put(w, H_PHASE, phase)
    return norm_issue(w, o, 51, 0, get(w, frame + 8), get(w, frame + 16))

def norm_pre_leave(s:readbuf, w:mutbuf) -> u64:
    depth = get(w, H_PRE_DEPTH)
    if depth == 0:
        return 0
    frame = PRE_STACK_BASE + (depth - 1) * 32
    parent = norm_read(s, 56, 8)
    if parent != get(w, H_REQUEST_B) or parent != get(w, frame + 16):
        return 0
    put(w, H_PRE_DEPTH, depth - 1)
    put(w, H_E_SCOPE_CURRENT, parent)
    return 1

def norm_snapshot_resume(w:mutbuf, o:mutbuf) -> u32:
    node = get(w, H_PRE_NODE)
    if node == NONE:
        if get(w, H_PRE_DEPTH) != 0 or get(w, H_E_SCOPE_CURRENT) != 0:
            return BAD_ABI
        put(w, H_PRE_CLEANUP, 1)
        put(w, H_PHASE, 109)
        return norm_issue(w, o, 53, 0, 1, 0)
    put(w, H_CURRENT, node)
    put(w, H_PHASE, 107)
    return norm_issue(w, o, 53, get(w, norm_record(node) + 8), 5, 0)

def norm_pre_snapshot_ack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, H_PHASE)
    node = get(w, H_CURRENT)
    if phase == 102:
        return norm_snapshot_after_pin(w, o)
    if phase == 103:
        if norm_pre_enter(s, w) == 0:
            return BAD_ABI
        put(w, H_PHASE, 11)
        return norm_issue(w, o, 2, get(w, norm_record(node) + 8), 0, 0)
    if phase == 104:
        put(w, H_PRE_NODE, node)
        put(w, H_PRE_NEXT, get(w, norm_record(node) + 40))
        return norm_schedule(w, 120, node)
    if phase == 105:
        return norm_snapshot_advance(w, o, node)
    if phase == 106:
        return norm_capture_next(w, o)
    if phase == 107:
        depth = get(w, H_PRE_DEPTH)
        if depth == 0:
            return BAD_ABI
        put(w, H_PHASE, 111)
        return norm_issue(w, o, 53, get(w, PRE_STACK_BASE + (depth - 1) * 32 + 24), 9, 0)
    if phase == 108:
        if norm_pre_leave(s, w) == 0:
            return BAD_ABI
        return norm_snapshot_advance(w, o, node)
    if phase == 109:
        slot = get(w, H_PRE_CLEANUP)
        if slot < 6:
            put(w, H_PRE_CLEANUP, slot + 1)
            target = slot + 1
            if target == 3:
                target = 9
            else:
                if target > 3:
                    target = target - 1
            return norm_issue(w, o, 53, 0, target, 0)
        if slot == 6:
            put(w, H_PRE_CLEANUP, 7)
            return norm_issue(w, o, 54, get(w, H_ROOT_HANDLE), 0, 0)
        if slot == 7:
            return norm_structure_begin(w, o)
    if phase >= 111 and phase <= 114:
        return norm_snapshot_iterator_ack(s, o, w)
    return BAD_ABI

def norm_snapshot_iterator_ack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, H_PHASE)
    depth = get(w, H_PRE_DEPTH)
    if depth == 0:
        return BAD_ABI
    frame = PRE_STACK_BASE + (depth - 1) * 32
    next_node = get(w, H_PRE_NEXT)
    if phase == 111:
        if next_node == NONE:
            put(w, H_PHASE, 114)
            return norm_issue(w, o, 53, 0, 16 + depth - 1, 0)
        if get(w, norm_record(get(w, H_CURRENT))) != 5:
            return norm_snapshot_visit(w, o, next_node)
        handle = get(w, norm_record(next_node) + 8)
        put(w, frame + 24, handle)
        put(w, H_PHASE, 112)
        return norm_issue(w, o, 53, handle, 16 + depth - 1, 0)
    if phase == 112:
        put(w, H_PHASE, 113)
        return norm_issue(w, o, 53, get(w, frame + 24), 9, 0)
    if phase == 113:
        if next_node == NONE:
            return BAD_ABI
        return norm_snapshot_visit(w, o, next_node)
    if phase == 114:
        return norm_pre_end(w, o, 108)
    return BAD_ABI

def norm_pre_structure_ack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, H_PHASE)
    node = get(w, H_CURRENT)
    if phase == 147:
        return norm_structure_after_pin(w, o)
    if phase == 148:
        return norm_structure_kind(w, o, get(w, norm_record(node)))
    if phase == 149:
        if norm_pre_enter(s, w) == 0:
            return BAD_ABI
        put(w, H_PHASE, 150)
        return norm_issue(w, o, 57, get(w, norm_record(node) + 8), get(w, H_E_SCOPE_CURRENT), 0)
    if phase == 150:
        put(w, H_PHASE, 141)
        return norm_issue(w, o, 2, get(w, norm_record(node) + 8), 0, 0)
    if phase == 151:
        return norm_pre_end(w, o, 152)
    if phase == 152:
        if norm_pre_leave(s, w) == 0:
            return BAD_ABI
        return norm_schedule(w, 31, node)
    if phase == 153:
        slot = get(w, H_PRE_CLEANUP)
        if slot < 8:
            put(w, H_PRE_CLEANUP, slot + 1)
            return norm_issue(w, o, 53, 0, slot + 1, 0)
        if slot == 8 and get(w, H_PRE_DEPTH) == 0 and get(w, H_E_SCOPE_CURRENT) == 0:
            return norm_encode_start(w, o)
    return BAD_ABI

def norm_ack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, H_PHASE)
    if phase == 237:
        return norm_encode_note_ack(s, o, w)
    if norm_read(s, 48, 8) == 3:
        if length(s) != 128 or norm_read(s, 56, 8) == 0 or norm_read(s, 64, 8) != 0 or norm_read(s, 72, 8) != 0:
            return BAD_ABI
        put(w, H_FOREIGN_ERROR, norm_read(s, 56, 8))
        # A transport scope handoff that raised must never be replayed. Its
        # actual foreign custody remains in the context until final cleanup.
        if (phase >= 203 and phase <= 208) or (phase >= 238 and phase <= 241):
            return norm_error_final(w, o, 20)
        return norm_error(w, o, 20)
    if phase >= 140 and phase <= 146:
        return norm_structure_ack(s, o, w)
    if phase >= 300 and phase <= 303:
        return norm_mat_ack(s, o, w)
    if phase >= 200 and phase <= 241:
        return norm_encode_ack(s, o, w)
    if phase == 13:
        return norm_capture(s, o, w)
    if phase == 12 and norm_read(s, 48, 8) == 2 and length(s) == 128:
        return norm_error(w, o, 10)
    if norm_read(s, 48, 8) != 0:
        return BAD_ABI
    if phase >= 102 and phase <= 114:
        if length(s) != 128:
            return BAD_ABI
        return norm_pre_snapshot_ack(s, o, w)
    if phase >= 147 and phase <= 153:
        if length(s) != 128:
            return BAD_ABI
        return norm_pre_structure_ack(s, o, w)
    if phase == 100:
        if length(s) != 128 or norm_read(s, 56, 8) > 1 or norm_read(s, 64, 8) != 0 or norm_read(s, 72, 8) > 8:
            return BAD_ABI
        put(w, H_CALLER, norm_read(s, 56, 8))
        put(w, H_PHASE, 1)
        return norm_issue(w, o, 1, get(w, H_ROOT_HANDLE), 0, 0)
    if phase == 101:
        if length(s) != 128 or norm_read(s, 56, 8) > 1:
            return BAD_ABI
        if norm_read(s, 56, 8) == 0 and get(w, norm_record(get(w, H_CURRENT))) != 0:
            return norm_error(w, o, 11)
        put(w, H_PHASE, 105)
        return norm_issue(w, o, 56, get(w, norm_record(get(w, H_CURRENT)) + 8), 0, 0)
    if phase == 10:
        return norm_snapshot_kind(s, w, o)
    if phase == 1:
        kind = norm_read(s, 56, 8)
        if kind > 8 or length(s) != 128:
            return BAD_ABI
        put(w, NODE_BASE, kind)
        if kind == 7 or kind == 4:
            put(w, H_PHASE, 2)
            return norm_issue(w, o, 2, get(w, H_ROOT_HANDLE), 0, 0)
        if get(w, H_CALLER) != 0:
            put(w, H_STAGE, 1)
            put(w, H_SNAP_COUNT, 0)
            put(w, H_SNAP_QUEUED, 1)
            return norm_snapshot_visit(w, o, 0)
        return norm_structure_begin(w, o)
    if phase == 2:
        size = norm_read(s, 56, 8)
        if length(s) != 128:
            return BAD_ABI
        if size > MAX_BYTES:
            return norm_error(w, o, 1)
        put(w, H_RAW_LENGTH, size)
        if get(w, NODE_BASE) == 7:
            put(w, H_RAW_BYTES, size)
            put(w, H_PHASE, 4)
            return norm_issue(w, o, 9, get(w, H_ROOT_HANDLE), size, 0)
        return norm_raw_next(w, o)
    if phase == 3:
        size = length(s) - 128
        if size > get(w, H_REQUEST_B) * 4:
            return BAD_ABI
        if size > MAX_BYTES - get(w, H_RAW_BYTES):
            return norm_error(w, o, 1)
        norm_copy(s, w, 128, POOL_BASE + get(w, H_RAW_BYTES), size)
        put(w, H_RAW_BYTES, get(w, H_RAW_BYTES) + size)
        put(w, H_RAW_OFFSET, get(w, H_RAW_OFFSET) + get(w, H_REQUEST_B))
        return norm_raw_next(w, o)
    if phase == 4:
        size = length(s) - 128
        count = norm_read(s, 56, 8)
        if size == 0 or size > get(w, H_RAW_BYTES) or count == 0 or count > MAX_NODES:
            return BAD_ABI
        norm_copy(s, o, 128, 64, size)
        put(w, H_EXPECT_COUNT, count)
        return norm_mat_start(w, o, size)
    if phase == 11:
        if length(s) != 128:
            return BAD_ABI
        if norm_read(s, 56, 8) > get(w, H_AVAILABLE):
            return norm_error(w, o, 6)
        put(w, H_PHASE, 12)
        return norm_issue(w, o, 3, get(w, norm_record(get(w, H_CURRENT)) + 8), get(w, norm_record(get(w, H_CURRENT))), 0)
    if phase == 12:
        if length(s) != 128 or norm_read(s, 56, 8) == 0:
            return BAD_ABI
        put(w, H_ITERATOR, norm_read(s, 56, 8))
        return norm_capture_next(w, o)
    if phase == 20:
        size = norm_read(s, 56, 8)
        if length(s) != 128:
            return BAD_ABI
        if get(w, H_SIZE) > MAX_BYTES - 2 or size > MAX_BYTES - get(w, H_SIZE) - 2:
            return norm_error(w, o, 18)
        put(w, H_STRING_LENGTH, size)
        put(w, H_STRING_OFFSET, 0)
        put(w, H_STRING_SIZE, 2)
        put(w, H_STRING_START, get(w, H_POOL_USED))
        return norm_string_next(w, o)
    if phase == 21:
        return norm_string_chunk(s, o, w)
    if phase == 22:
        return norm_integer_bits(s, o, w)
    if phase == 23:
        return norm_integer_bytes(s, o, w)
    if phase == 24:
        return norm_integer_limit(s, o, w)
    return BAD_ABI

def norm_copy(s:readbuf, w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(s, source + i))
        i = i + 1
    return 0
'''


SCALARS = r'''
def norm_pool_byte(w:mutbuf, value:u64) -> u64:
    at = get(w, H_POOL_USED)
    store(w, POOL_BASE + at, value)
    put(w, H_POOL_USED, at + 1)
    return 0

def norm_utf8(w:mutbuf, point:u64) -> u64:
    if point < 128:
        return norm_pool_byte(w, point)
    if point < 2048:
        norm_pool_byte(w, 192 | (point >> 6))
        return norm_pool_byte(w, 128 | (point & 63))
    if point < 65536:
        norm_pool_byte(w, 224 | (point >> 12))
        norm_pool_byte(w, 128 | ((point >> 6) & 63))
        return norm_pool_byte(w, 128 | (point & 63))
    norm_pool_byte(w, 240 | (point >> 18))
    norm_pool_byte(w, 128 | ((point >> 12) & 63))
    norm_pool_byte(w, 128 | ((point >> 6) & 63))
    return norm_pool_byte(w, 128 | (point & 63))

def norm_json_width(point:u64) -> u64:
    if point < 32:
        if point == 8 or point == 9 or point == 10 or point == 12 or point == 13:
            return 2
        return 6
    if point == 34 or point == 92:
        return 2
    if point < 128:
        return 1
    if point < 2048:
        return 2
    if point < 65536:
        return 3
    return 4

def norm_string_chunk(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    count = get(w, H_REQUEST_B)
    if count == 0 or count > 4096 or length(s) != 128 + count * 4:
        return BAD_ABI
    i = 0
    while i < count:
        point = norm_read(s, 128 + i * 4, 4)
        if point > 1114111:
            return BAD_ABI
        if point >= 55296 and point <= 57343:
            return norm_error(w, o, 17)
        size = get(w, H_STRING_SIZE) + norm_json_width(point)
        if size > MAX_BYTES - get(w, H_SIZE):
            return norm_error(w, o, 18)
        put(w, H_STRING_SIZE, size)
        norm_utf8(w, point)
        i = i + 1
    put(w, H_STRING_OFFSET, get(w, H_STRING_OFFSET) + count)
    return norm_string_next(w, o)

def norm_integer_bits(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 128:
        return BAD_ABI
    bits = norm_read(s, 56, 8)
    if bits > MAX_BYTES * 4:
        return norm_error(w, o, 15)
    put(w, H_INT_BITS, bits)
    put(w, H_PHASE, 24)
    return norm_issue(w, o, 34, 0, 0, 0)

def norm_integer_limit(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 128:
        return BAD_ABI
    digits = norm_read(s, 56, 8)
    if digits != 0 and digits < 640:
        return BAD_ABI
    put(w, H_DIGITS, digits)
    bits = get(w, H_INT_BITS)
    # This policy observation belongs to this exact str(integer) position,
    # after its bit-length gate, not to construction or a previous traversal.
    if digits != 0 and digits < MAX_BYTES and bits > digits * 4:
        return norm_error(w, o, 3)
    put(w, H_PHASE, 23)
    return norm_issue(w, o, 8, get(w, norm_record(get(w, H_CURRENT)) + 8), (bits + 8) // 8, 0)

def norm_integer_magnitude(s:readbuf, w:mutbuf, size:u64) -> u64:
    negative = choose(byte(s, 128 + size - 1) >= 128, 1, 0)
    put(w, H_INT_NEGATIVE, negative)
    carry = negative
    i = 0
    while i < size:
        value = byte(s, 128 + i)
        if negative != 0:
            value = (255 ^ value) + carry
            carry = choose(value > 255, 1, 0)
            value = value & 255
        store(w, BINARY_BASE + i, value)
        i = i + 1
    fill_range(w, BINARY_BASE + size, 8, 0)
    while size != 0 and byte(w, BINARY_BASE + size - 1) == 0:
        size = size - 1
    return size

def norm_magnitude_bits(w:mutbuf, size:u64) -> u64:
    if size == 0:
        return 0
    high = byte(w, BINARY_BASE + size - 1)
    bits = (size - 1) * 8
    while high != 0:
        bits = bits + 1
        high = high >> 1
    return bits

def norm_decimal_convert(w:mutbuf, size:u64) -> u64:
    count = 1
    put(w, DECIMAL_BASE, 0)
    words = (size + 3) // 4
    while words != 0:
        words = words - 1
        carry = get(w, BINARY_BASE + words * 4) & 4294967295
        index = 0
        while index < count:
            value = get(w, DECIMAL_BASE + index * 8) * 4294967296 + carry
            put(w, DECIMAL_BASE + index * 8, value % 1000000000)
            carry = value // 1000000000
            index = index + 1
        while carry != 0:
            put(w, DECIMAL_BASE + count * 8, carry % 1000000000)
            carry = carry // 1000000000
            count = count + 1
    put(w, H_DECIMAL_COUNT, count)
    high = get(w, DECIMAL_BASE + (count - 1) * 8)
    digits = 1
    while high >= 10:
        high = high // 10
        digits = digits + 1
    return (count - 1) * 9 + digits

def norm_decimal_emit(w:mutbuf) -> u64:
    if get(w, H_INT_NEGATIVE) != 0:
        norm_pool_byte(w, 45)
    count = get(w, H_DECIMAL_COUNT)
    leading = True
    while count != 0:
        count = count - 1
        value = get(w, DECIMAL_BASE + count * 8)
        divisor = 100000000
        if leading:
            while divisor > 1 and divisor > value:
                divisor = divisor // 10
            leading = False
        while divisor != 0:
            norm_pool_byte(w, 48 + value // divisor)
            value = value % divisor
            divisor = divisor // 10
    return 0

def norm_integer_bytes(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = get(w, H_REQUEST_A)
    if size == 0 or size > MAX_BYTES // 2 + 1 or length(s) != 128 + size:
        return BAD_ABI
    magnitude_size = norm_integer_magnitude(s, w, size)
    if norm_magnitude_bits(w, magnitude_size) != get(w, H_INT_BITS):
        return BAD_ABI
    if magnitude_size == 0 and get(w, H_INT_NEGATIVE) != 0:
        return BAD_ABI
    digits = norm_decimal_convert(w, magnitude_size)
    if get(w, H_DIGITS) != 0 and digits > get(w, H_DIGITS):
        return norm_error(w, o, 3)
    length = digits + get(w, H_INT_NEGATIVE)
    if length > MAX_BYTES - get(w, H_SIZE):
        return norm_error(w, o, 18)
    at = norm_record(get(w, H_CURRENT))
    put(w, at + 88, POOL_BASE + get(w, H_POOL_USED))
    put(w, at + 96, length)
    norm_decimal_emit(w)
    put(w, H_SIZE, get(w, H_SIZE) + length)
    return norm_schedule(w, 31, get(w, H_CURRENT))
'''


SERIALIZE = r'''
def norm_emit_byte(w:mutbuf, o:mutbuf, value:u64) -> u64:
    at = get(w, H_OUT_CURSOR)
    store(o, at, value)
    put(w, H_OUT_CURSOR, at + 1)
    if at >= 64 + MAX_BYTES:
        put(w, H_E_OVERFLOW, 1)
    return 0

def norm_emit_raw(w:mutbuf, o:mutbuf, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        norm_emit_byte(w, o, byte(w, at + index))
        index = index + 1
    return 0

def norm_hex(value:u64) -> u64:
    return choose(value < 10, value + 48, value + 87)

def norm_emit_string(w:mutbuf, o:mutbuf, at:u64, size:u64) -> u64:
    norm_emit_byte(w, o, 34)
    index = 0
    while index < size:
        value = byte(w, at + index)
        if value < 32:
            norm_emit_byte(w, o, 92)
            escape = 0
            if value == 8:
                escape = 98
            if value == 9:
                escape = 116
            if value == 10:
                escape = 110
            if value == 12:
                escape = 102
            if value == 13:
                escape = 114
            if escape != 0:
                norm_emit_byte(w, o, escape)
            else:
                norm_emit_byte(w, o, 117)
                norm_emit_byte(w, o, 48)
                norm_emit_byte(w, o, 48)
                norm_emit_byte(w, o, norm_hex(value >> 4))
                norm_emit_byte(w, o, norm_hex(value & 15))
        else:
            if value == 34 or value == 92:
                norm_emit_byte(w, o, 92)
            norm_emit_byte(w, o, value)
        index = index + 1
    norm_emit_byte(w, o, 34)
    return 0

def norm_key_less(w:mutbuf, left:u64, right:u64) -> u64:
    a = norm_record(left)
    b = norm_record(right)
    x = get(w, a + 72)
    y = get(w, b + 72)
    nx = get(w, a + 80)
    ny = get(w, b + 80)
    index = 0
    while index < nx and index < ny:
        vx = byte(w, x + index)
        vy = byte(w, y + index)
        if vx < vy:
            return 1
        if vx > vy:
            return 0
        index = index + 1
    return choose(nx <= ny, 1, 0)

def norm_next(w:mutbuf, node:u64) -> u64:
    return get(w, norm_record(node) + 24)

def norm_sort(w:mutbuf, node:u64) -> u64:
    record = norm_record(node)
    size = get(w, record + 56)
    head = get(w, record + 40)
    width = 1
    while width < size:
        p = head
        head = NONE
        tail = NONE
        while p != NONE:
            q = p
            left = 0
            while left < width and q != NONE:
                q = norm_next(w, q)
                left = left + 1
            right = width
            element = 0
            while left > 0 or (right > 0 and q != NONE):
                take_left = False
                if left > 0:
                    if right == 0 or q == NONE:
                        take_left = True
                    else:
                        if norm_key_less(w, p, q) == 1:
                            take_left = True
                if take_left:
                    element = p
                    p = norm_next(w, p)
                    left = left - 1
                else:
                    element = q
                    q = norm_next(w, q)
                    right = right - 1
                if tail == NONE:
                    head = element
                else:
                    put(w, norm_record(tail) + 24, element)
                tail = element
            p = q
        put(w, norm_record(tail) + 24, NONE)
        width = width * 2
    put(w, record + 40, head)
    return 0

def norm_literal(w:mutbuf, o:mutbuf, kind:u64) -> u64:
    if kind == 0:
        norm_emit_byte(w, o, 110)
        norm_emit_byte(w, o, 117)
        norm_emit_byte(w, o, 108)
        return norm_emit_byte(w, o, 108)
    if kind == 1:
        norm_emit_byte(w, o, 102)
        norm_emit_byte(w, o, 97)
        norm_emit_byte(w, o, 108)
        norm_emit_byte(w, o, 115)
        return norm_emit_byte(w, o, 101)
    norm_emit_byte(w, o, 116)
    norm_emit_byte(w, o, 114)
    norm_emit_byte(w, o, 117)
    return norm_emit_byte(w, o, 101)

def norm_serialize(w:mutbuf, o:mutbuf) -> u32:
    put(w, H_OUT_CURSOR, 64)
    node = 0
    going = True
    while going:
        record = norm_record(node)
        kind = get(w, record)
        parent = get(w, record + 16)
        if parent != NONE:
            if get(w, norm_record(parent)) == 6:
                norm_emit_string(w, o, get(w, record + 72), get(w, record + 80))
                norm_emit_byte(w, o, 58)
        complete = True
        if kind == 5 or kind == 6:
            if kind == 6:
                norm_sort(w, node)
            norm_emit_byte(w, o, choose(kind == 5, 91, 123))
            if get(w, record + 56) == 0:
                norm_emit_byte(w, o, choose(kind == 5, 93, 125))
            else:
                node = get(w, record + 40)
                complete = False
        else:
            if kind == 4:
                norm_emit_string(w, o, get(w, record + 88), get(w, record + 96))
            else:
                if kind == 3:
                    norm_emit_raw(w, o, get(w, record + 88), get(w, record + 96))
                else:
                    norm_literal(w, o, kind)
        if complete:
            moving = True
            while moving:
                record = norm_record(node)
                sibling = get(w, record + 24)
                if sibling != NONE:
                    norm_emit_byte(w, o, 44)
                    node = sibling
                    moving = False
                else:
                    parent = get(w, record + 16)
                    if parent == NONE:
                        going = False
                        moving = False
                    else:
                        node = parent
                        norm_emit_byte(w, o, choose(get(w, norm_record(node)) == 5, 93, 125))
    size = get(w, H_OUT_CURSOR) - 64
    if size != get(w, H_SIZE) or size == 0 or size > MAX_BYTES:
        return BAD_ABI
    return norm_mat_start(w, o, size)
'''


def source_program():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node
    return [Constants().visit(node) for node in ast.parse(SOURCE + SCALARS + SERIALIZE + ENCODING).body if node.name != 'norm_serialize']


def document():
    nodes = source_program()
    # The independent HIA fragment is inserted where its original eleven
    # functions occurred. New Python-authored functions may move this offset;
    # explicit import/export rebinding preserves the actual call graph.
    insertion = next(index for index, node in enumerate(nodes)
                     if node.name == 'norm_encode_start')
    if len({node.name for node in nodes}) != len(nodes):
        raise ValueError('duplicate normalization authoring function')
    names = {node.name: 'f' + str(index if index < insertion else
                                 index + len(FRAGMENT_FUNCTIONS))
             for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    fragment_names, fragment_signatures = exported_bindings(insertion)
    if set(names) & set(fragment_names):
        raise ValueError('normalization authoring shadows a retained HIA export')
    names.update(fragment_names)
    signatures.update(fragment_signatures)
    retained = fragment_functions(names, signatures, insertion)
    # The fragment's three exports all take buffers. They never enter the
    # finite scalar-only eager-expression set inferred from the actual AST.
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = NormalizationBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    functions[insertion:insertion] = retained
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'program_normalization', 'functions': functions})


def main():
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/program_normalization.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)


if __name__ == '__main__':
    main()
