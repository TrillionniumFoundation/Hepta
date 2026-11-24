"""HIA original engine ScratchOwner selection, adoption and durable receipts."""
from __future__ import annotations
import argparse
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_system_jobctl_record as record
from tools.generate_hia_system_jobctl_scratch_common import compose
ROOT=Path(__file__).resolve().parents[1]
KEYS=('schema','profile','provider','owner','worker_pid','engine','device','inode','job_id','launch_nonce','path')
LITERALS=('rea-static-worker','hepta.rea.static-request.v1','jadx','ghidra','hepta.rea.engine-scratch-claim.v1')
JSON_TEXT=(
 '{"device":',',"inode":',',"job_id":',',"launch_nonce":',',"path":',',"schema":"hepta.rea.engine-scratch-owner.v1"}',
 ',"directory":"engine-scratch","durable":',',"error":',',"original_child_reaped":',',"original_process_group_stopped":',
 ',"removed":',',"schema":"hepta.rea.engine-scratch-cleanup.v1","state":',',"worker_adopted":','true','false','"retained"','"incomplete"','"removed"',
)
POLICY=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 3060 and phase < 3080:
        return scratch_atomic(o, w, phase, result)
    if phase >= 3080 and phase < 3090:
        return scratch_close(o, w, phase)
    if phase >= 3020 and phase < 3050:
        return scratch_finish(o, w, phase, result)
    return scratch_start(o, w, phase, result)

def scratch_start(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 3000:
        operation = get(w, SC_OP)
        if operation == 1 or operation == 2:
            put(w, 0, 3500)
            return 23
        put(w, SC_FAILED, 0)
        put(w, SC_JSON_SIZE, 0)
        put(w, SC_FD, NONE)
        put(w, SC_ATOMIC_FD, NONE)
        put(w, SC_ATOMIC_PARENT, NONE)
        put(w, SC_DIR_FD, NONE)
        put(w, SC_DIR_PARENT, NONE)
        if operation == 3:
            return sc_go(w, 3020)
        if operation == 4:
            size = get(w, SC_ERROR_SIZE)
            if size > 1048576:
                return 0
            copy(w, SC_WORK, get(w, SC_ERROR), size)
            put(w, SC_ORIGINAL_ERROR_SIZE, size)
            put(w, SC_ERROR, SC_WORK)
            put(w, SC_ERROR_SIZE, size)
            put(w, SC_RENDER_STATE, 0)
            put(w, SC_ADOPTED, 0)
            put(w, SC_STOPPED, 0)
            if scratch_receipt(w) == 0:
                return 0
            return scratch_atomic_begin(o, w, 3044, 1, get(w, SC_JSON), get(w, SC_JSON_SIZE))
        if operation != 0 and operation != 5:
            return 0
        put(w, SC_OWN_FD, NONE)
        put(w, SC_PARENT_FD, NONE)
        put(w, SC_SELECTED, 0)
        put(w, SC_ERROR_SIZE, 0)
        if get(w, SC_INTERACTIVE) != 0 or get(w, SC_ARGC) != 1 or get(w, SC_STDIN_PRESENT) == 0:
            return sc_finish(w)
        if scratch_literal(w, get(w, SC_ARG), get(w, SC_ARG_SIZE)) != 1:
            return sc_finish(w)
        return scratch_value(o, w, 3001, get(w, SC_STDIN), get(w, SC_STDIN_SIZE))
    if phase == 3001:
        if result >= 4294967000 or scratch_selected(w) == 0:
            return sc_finish(w)
        put(w, SC_SELECTED, 1)
        if get(w, SC_OP) == 5:
            return sc_finish(w)
        if get(w, SC_STATE_SIZE) >= 1048576:
            sc_error(w, E_EMPTY, 36)
            return sc_finish(w)
        copy(w, SC_NAME, get(w, SC_STATE_ARG), get(w, SC_STATE_SIZE))
        store(w, SC_NAME + get(w, SC_STATE_SIZE), 0)
        return call(o, w, 3002, 257, NEG100, SC_NAME, 2621440, 0, 0, 0, 12)
    if phase == 3002:
        if failed(result):
            sc_result_error(w, E_EMPTY, result)
            return scratch_failure(o, w)
        put(w, SC_FD, result)
        sc_nul(w, decimal(w, sc_text(w, SC_PATH_TEMP, E_PROCFD), result))
        return call(o, w, 3003, 267, NEG100, SC_PATH_TEMP, SC_STATE, 1048576, 0, 0, 60)
    if phase == 3003:
        if failed(result) or result == 0 or result >= 1048560:
            sc_result_error(w, E_EMPTY, result)
            return scratch_failure(o, w)
        put(w, SC_STATE_CANON_SIZE, result)
        store(w, SC_STATE + result, 0)
        if sc_utf8(w, SC_STATE, result) == 0:
            sc_utf_error(w)
            return scratch_failure(o, w)
        copy(w, SC_PATH, SC_STATE, result)
        at = SC_PATH + result
        if byte(w, at - 1) != 47:
            store(w, at, 47)
            at = at + 1
        at = sc_text(w, at, E_SCRATCH)
        store(w, at, 0)
        put(w, SC_PATH_SIZE, at - SC_PATH)
        return call(o, w, 3004, 3, get(w, SC_FD), 0, 0, 0, 0, 0, 0)
    if phase == 3004:
        put(w, SC_FD, NONE)
        return call(o, w, 3005, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 3005:
        put(w, SC_UID, result)
        return scratch_directory(w, 0, 3006)
    if phase == 3006:
        if get(w, SC_DIR_ERROR) != 0:
            return scratch_failure(o, w)
        put(w, SC_OWN_FD, get(w, SC_DIR_FD))
        put(w, SC_PARENT_FD, get(w, SC_DIR_PARENT))
        put(w, SC_DIR_FD, NONE)
        put(w, SC_DIR_PARENT, NONE)
        if scratch_binding(w) == 0:
            sc_error(w, E_EMPTY, 12)
            return scratch_failure(o, w)
        return scratch_atomic_begin(o, w, 3007, 0, SC_BINDING, get(w, SC_BINDING_SIZE))
    if phase == 3007:
        if get(w, SC_FAILED) != 0:
            return scratch_failure(o, w)
        put(w, SC_JSON, SC_BINDING)
        put(w, SC_JSON_SIZE, get(w, SC_BINDING_SIZE))
        return sc_finish(w)
    return 0

def scratch_directory(w:mutbuf, operation:u64, next:u64) -> u32:
    put(w, SC_DIR_OP, operation)
    put(w, SC_DIR_NEXT, next)
    put(w, 0, 3100)
    return 22

def scratch_value(o:mutbuf, w:mutbuf, next:u64, source:u64, size:u64) -> u32:
    put(w, SC_VALUE_SOURCE, source)
    put(w, SC_VALUE_SIZE, size)
    put(w, SC_VALUE_OUTPUT, 1)
    put(w, 0, next)
    put(o, 0, source)
    put(o, 8, size)
    put(o, 16, SC_VALUE_OUTPUT)
    put(o, 24, 8388608)
    put(o, 32, SC_VALUE_WORK)
    put(o, 40, SC_VALUE_BYTES)
    return 14

def scratch_field(w:mutbuf, parent:u64, name:u64) -> u64:
    if parent == NONE or get(w, parent) != 6:
        return NONE
    row = get(w, parent + 24)
    while row != NONE:
        node = SC_VALUE_WORK + 64 + row * 56
        if scratch_key(w, SC_VALUE_WORK + get(w, node + 40), get(w, node + 48)) == name:
            return node
        row = get(w, node + 16)
    return NONE

def scratch_string_is(w:mutbuf, node:u64, literal:u64) -> u64:
    if node == NONE or get(w, node) != 4:
        return 0
    return choose(scratch_literal(w, SC_VALUE_WORK + get(w, node + 24), get(w, node + 32)) == literal, 1, 0)

def scratch_string_equal(w:mutbuf, node:u64, at:u64, size:u64) -> u64:
    if node == NONE or get(w, node) != 4 or get(w, node + 32) != size:
        return 0
    return sc_equal(w, SC_VALUE_WORK + get(w, node + 24), at, size)

def scratch_number_equal(w:mutbuf, node:u64, expected:u64) -> u64:
    if node == NONE or get(w, node) != 3:
        return 0
    at = get(w, SC_VALUE_SOURCE) + get(w, node + 24)
    size = get(w, node + 32)
    if size == 0 or byte(w, at) == 45:
        return 0
    value = sc_unsigned(w, at, size, NONE)
    return choose(get(w, G_INT_ERROR) == 0 and value == expected, 1, 0)

def scratch_selected(w:mutbuf) -> u64:
    root = SC_VALUE_WORK + 64
    if scratch_string_is(w, scratch_field(w, root, 1), 2) == 0:
        return 0
    provider = scratch_field(w, scratch_field(w, root, 2), 3)
    return choose(scratch_string_is(w, provider, 3) == 1 or scratch_string_is(w, provider, 4) == 1, 1, 0)

def scratch_claim(w:mutbuf) -> u64:
    root = SC_VALUE_WORK + 64
    if scratch_string_is(w, scratch_field(w, root, 1), 5) == 0 or scratch_number_equal(w, scratch_field(w, root, 5), get(w, SC_PID)) == 0:
        return 0
    engine = scratch_field(w, root, 6)
    if scratch_string_is(w, engine, 3) == 0 and scratch_string_is(w, engine, 4) == 0:
        return 0
    owner = scratch_field(w, root, 4)
    if owner == NONE or get(w, owner) != 6 or get(w, owner + 32) != 6:
        return 0
    if scratch_number_equal(w, scratch_field(w, owner, 7), get(w, SC_DEV)) == 0 or scratch_number_equal(w, scratch_field(w, owner, 8), get(w, SC_INO)) == 0:
        return 0
    if scratch_string_equal(w, scratch_field(w, owner, 9), get(w, SC_ID), get(w, SC_ID_SIZE)) == 0 or scratch_string_equal(w, scratch_field(w, owner, 10), get(w, SC_NONCE), get(w, SC_NONCE_SIZE)) == 0:
        return 0
    if scratch_string_equal(w, scratch_field(w, owner, 11), SC_PATH, get(w, SC_PATH_SIZE)) == 0:
        return 0
    schema = scratch_field(w, owner, 1)
    if schema == NONE or get(w, schema) != 4:
        return 0
    return owner_schema(w, SC_VALUE_WORK + get(w, schema + 24), get(w, schema + 32))

def scratch_binding(w:mutbuf) -> u64:
    at = scratch_json(w, SC_OUT, 0)
    at = decimal(w, at, get(w, SC_DEV))
    at = decimal(w, scratch_json(w, at, 1), get(w, SC_INO))
    at = quote(w, scratch_json(w, at, 2), get(w, SC_ID), get(w, SC_ID_SIZE))
    at = quote(w, scratch_json(w, at, 3), get(w, SC_NONCE), get(w, SC_NONCE_SIZE))
    at = quote(w, scratch_json(w, at, 4), SC_PATH, get(w, SC_PATH_SIZE))
    at = scratch_json(w, at, 5)
    if at < SC_OUT or at - SC_OUT > 2097152:
        return 0
    copy(w, SC_BINDING, SC_OUT, at - SC_OUT)
    put(w, SC_BINDING_SIZE, at - SC_OUT)
    return 1

def scratch_receipt(w:mutbuf) -> u64:
    state = get(w, SC_RENDER_STATE)
    stopped = get(w, SC_STOPPED)
    at = decimal(w, scratch_json(w, SC_OUT, 0), get(w, SC_DEV))
    at = scratch_json(w, scratch_json(w, at, 6), choose(state == 2, 13, 14))
    if state != 2:
        at = quote(w, scratch_json(w, at, 7), get(w, SC_ERROR), get(w, SC_ERROR_SIZE))
    at = decimal(w, scratch_json(w, at, 1), get(w, SC_INO))
    at = quote(w, scratch_json(w, at, 2), get(w, SC_ID), get(w, SC_ID_SIZE))
    at = quote(w, scratch_json(w, at, 3), get(w, SC_NONCE), get(w, SC_NONCE_SIZE))
    at = scratch_json(w, scratch_json(w, at, 8), choose(stopped == 1, 13, 14))
    at = scratch_json(w, scratch_json(w, at, 9), choose(stopped == 1, 13, 14))
    at = scratch_json(w, scratch_json(w, at, 10), choose(state == 2, 13, 14))
    at = scratch_json(w, scratch_json(w, at, 11), 15 + state)
    at = scratch_json(w, scratch_json(w, at, 12), choose(get(w, SC_ADOPTED) == 1, 13, 14))
    store(w, at, 125)
    if at < SC_OUT or at >= SC_OUT_END:
        return 0
    put(w, SC_JSON, SC_OUT)
    put(w, SC_JSON_SIZE, at + 1 - SC_OUT)
    return 1

def scratch_finish(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 3020:
        put(w, SC_RENDER_STATE, 0)
        put(w, SC_ADOPTED, 0)
        sc_error(w, E_UNCONFIRMED, 0)
        put(w, SC_FAILED, 0)
        if get(w, SC_STOPPED) == 0:
            return scratch_receipt_done(o, w)
        return scratch_directory(w, 1, 3021)
    if phase == 3021:
        if get(w, SC_DIR_ERROR) != 0:
            put(w, SC_FAILED, 0)
            return scratch_receipt_done(o, w)
        sc_nul(w, sc_text(w, SC_NAME, E_CLAIM))
        return call(o, w, 3022, 257, get(w, SC_OWN_FD), SC_NAME, 131072 + 2048 + 524288, 0, 0, 0, 12)
    if phase == 3022:
        if failed(result):
            return scratch_remove(w)
        put(w, SC_FD, result)
        return call(o, w, 3023, 5, result, SC_STAT, 0, 0, 0, 0, 12)
    if phase == 3023:
        if result != 0 or getn(w, SC_STAT + 24, 4) & 61440 != 32768 or get(w, SC_STAT + 16) != 1 or getn(w, SC_STAT + 24, 4) & 511 != 384 or get(w, SC_STAT + 48) > 16384:
            return call(o, w, 3028, 3, get(w, SC_FD), 0, 0, 0, 0, 0, 0)
        return call(o, w, 3024, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 3024:
        if getn(w, SC_STAT + 28, 4) != result:
            return call(o, w, 3028, 3, get(w, SC_FD), 0, 0, 0, 0, 0, 0)
        put(w, SC_USED, 0)
        return scratch_claim_read(o, w)
    if phase == 3025:
        if result == NEG4:
            return scratch_claim_read(o, w)
        if failed(result) or result > 16385 - get(w, SC_USED):
            return call(o, w, 3028, 3, get(w, SC_FD), 0, 0, 0, 0, 0, 0)
        if result == 0:
            return call(o, w, 3026, 3, get(w, SC_FD), 0, 0, 0, 0, 0, 0)
        put(w, SC_USED, get(w, SC_USED) + result)
        return scratch_claim_read(o, w)
    if phase == 3026:
        put(w, SC_FD, NONE)
        if get(w, SC_USED) > 16384:
            return scratch_remove(w)
        return scratch_value(o, w, 3027, SC_CLAIM, get(w, SC_USED))
    if phase == 3027:
        if result < 4294967000:
            put(w, SC_ADOPTED, scratch_claim(w))
        return scratch_remove(w)
    if phase == 3028:
        put(w, SC_FD, NONE)
        return scratch_remove(w)
    if phase == 3030:
        if get(w, SC_DIR_ERROR) == 0:
            put(w, SC_RENDER_STATE, 2)
        put(w, SC_FAILED, 0)
        return scratch_receipt_done(o, w)
    if phase == 3044:
        if get(w, SC_FAILED) != 0:
            size = get(w, SC_ERROR_SIZE)
            copy(w, SC_IO, get(w, SC_ERROR), size)
            at = sc_text(w, SC_ERROR_TEXT, E_RETAINED_PREFIX)
            copy(w, at, SC_WORK, get(w, SC_ORIGINAL_ERROR_SIZE))
            at = at + get(w, SC_ORIGINAL_ERROR_SIZE)
            at = sc_text(w, at, E_COLON)
            copy(w, at, SC_IO, size)
            put(w, SC_ERROR, SC_ERROR_TEXT)
            put(w, SC_ERROR_SIZE, at + size - SC_ERROR_TEXT)
        return scratch_failure(o, w)
    return 0

def scratch_claim_read(o:mutbuf, w:mutbuf) -> u32:
    if get(w, SC_USED) == 16385:
        return call(o, w, 3026, 3, get(w, SC_FD), 0, 0, 0, 0, 0, 0)
    return call(o, w, 3025, 0, get(w, SC_FD), SC_CLAIM + get(w, SC_USED), 16385 - get(w, SC_USED), 0, 0, 0, 12)

def scratch_remove(w:mutbuf) -> u32:
    put(w, SC_RENDER_STATE, 1)
    return scratch_directory(w, 3, 3030)

def scratch_receipt_done(o:mutbuf, w:mutbuf) -> u32:
    if scratch_receipt(w) == 0:
        return 0
    return scratch_failure(o, w)

def scratch_failure(o:mutbuf, w:mutbuf) -> u32:
    put(w, SC_CLOSE_INDEX, 0)
    return scratch_close(o, w, 3080)

def scratch_close_slot(index:u64) -> u64:
    if index == 0:
        return SC_FD
    if index == 1:
        return SC_ATOMIC_FD
    if index == 2:
        return SC_ATOMIC_PARENT
    if index == 3:
        return SC_DIR_FD
    if index == 4:
        return SC_DIR_PARENT
    if index == 5:
        return SC_OWN_FD
    return SC_PARENT_FD

def scratch_close(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    index = get(w, SC_CLOSE_INDEX)
    if phase == 3081:
        put(w, scratch_close_slot(index), NONE)
        index = index + 1
    while index < 7:
        fd = get(w, scratch_close_slot(index))
        if fd != NONE:
            put(w, SC_CLOSE_INDEX, index)
            return call(o, w, 3081, 3, fd, 0, 0, 0, 0, 0, 0)
        index = index + 1
    return sc_finish(w)

def scratch_atomic_begin(o:mutbuf, w:mutbuf, next:u64, kind:u64, source:u64, size:u64) -> u32:
    put(w, SC_ATOMIC_NEXT, next)
    put(w, SC_ATOMIC_KIND, kind)
    put(w, SC_ATOMIC_SOURCE, source)
    put(w, SC_ATOMIC_SIZE, size)
    put(w, SC_ATOMIC_USED, 0)
    put(w, SC_ATOMIC_OWNED, 0)
    put(w, SC_ATOMIC_FD, NONE)
    put(w, SC_ATOMIC_PARENT, NONE)
    put(w, SC_FAILED, 0)
    return call(o, w, 3060, 39, 0, 0, 0, 0, 0, 0, 0)

def scratch_atomic_paths(w:mutbuf) -> u64:
    size = get(w, SC_STATE_SIZE)
    copy(w, SC_PATH_TEMP, get(w, SC_STATE_ARG), size)
    copy(w, SC_NAME, get(w, SC_STATE_ARG), size)
    at = sc_text(w, SC_PATH_TEMP + size, choose(get(w, SC_ATOMIC_KIND) == 0, E_SCRATCH_TMP, E_RETAINED_TMP))
    at = decimal(w, at, get(w, SC_PROCESS_ID))
    store(w, at, 0)
    at = sc_text(w, SC_NAME + size, choose(get(w, SC_ATOMIC_KIND) == 0, E_SCRATCH_FILE, E_RETAINED_FILE))
    store(w, at, 0)
    return 0

def scratch_atomic_bytes(o:mutbuf, w:mutbuf) -> u32:
    used = get(w, SC_ATOMIC_USED)
    size = get(w, SC_ATOMIC_SIZE)
    if used < size:
        return call(o, w, 3062, 1, get(w, SC_ATOMIC_FD), get(w, SC_ATOMIC_SOURCE) + used, size - used, 0, 0, 0, 12)
    store(w, SC_STAT, 10)
    return call(o, w, 3063, 1, get(w, SC_ATOMIC_FD), SC_STAT, 1, 0, 0, 0, 12)

def scratch_atomic(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 3060:
        put(w, SC_PROCESS_ID, result)
        scratch_atomic_paths(w)
        return call(o, w, 3061, 257, NEG100, SC_PATH_TEMP, 524481, 384, 0, 0, 12)
    if phase == 3061:
        if result == NEG4:
            return call(o, w, 3061, 257, NEG100, SC_PATH_TEMP, 524481, 384, 0, 0, 12)
        if failed(result):
            sc_result_error(w, E_EMPTY, result)
            return sc_go(w, get(w, SC_ATOMIC_NEXT))
        put(w, SC_ATOMIC_FD, result)
        put(w, SC_ATOMIC_OWNED, 1)
        return scratch_atomic_bytes(o, w)
    if phase == 3062:
        if result == NEG4:
            return scratch_atomic_bytes(o, w)
        if result == 0:
            sc_error(w, E_WRITE_ZERO, 0)
            return scratch_atomic_fail(o, w)
        if failed(result) or result > get(w, SC_ATOMIC_SIZE) - get(w, SC_ATOMIC_USED):
            sc_result_error(w, E_EMPTY, result)
            return scratch_atomic_fail(o, w)
        put(w, SC_ATOMIC_USED, get(w, SC_ATOMIC_USED) + result)
        return scratch_atomic_bytes(o, w)
    if phase == 3063:
        if result == NEG4:
            return scratch_atomic_bytes(o, w)
        if result == 0:
            sc_error(w, E_WRITE_ZERO, 0)
            return scratch_atomic_fail(o, w)
        if result != 1:
            sc_result_error(w, E_EMPTY, result)
            return scratch_atomic_fail(o, w)
        return call(o, w, 3064, 74, get(w, SC_ATOMIC_FD), 0, 0, 0, 0, 0, 0)
    if phase == 3064:
        if result == NEG4:
            return call(o, w, 3064, 74, get(w, SC_ATOMIC_FD), 0, 0, 0, 0, 0, 0)
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return scratch_atomic_fail(o, w)
        return call(o, w, 3065, 82, SC_PATH_TEMP, SC_NAME, 0, 0, 0, 0, 15)
    if phase == 3065:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return scratch_atomic_fail(o, w)
        copy(w, SC_NAME, get(w, SC_STATE_ARG), get(w, SC_STATE_SIZE))
        store(w, SC_NAME + get(w, SC_STATE_SIZE), 0)
        return call(o, w, 3066, 257, NEG100, SC_NAME, 524288, 0, 0, 0, 12)
    if phase == 3066:
        if result == NEG4:
            return call(o, w, 3066, 257, NEG100, SC_NAME, 524288, 0, 0, 0, 12)
        if failed(result):
            sc_result_error(w, E_EMPTY, result)
            return scratch_atomic_fail(o, w)
        put(w, SC_ATOMIC_PARENT, result)
        return call(o, w, 3067, 74, result, 0, 0, 0, 0, 0, 0)
    if phase == 3067:
        if result == NEG4:
            return call(o, w, 3067, 74, get(w, SC_ATOMIC_PARENT), 0, 0, 0, 0, 0, 0)
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return scratch_atomic_fail(o, w)
        return call(o, w, 3070, 3, get(w, SC_ATOMIC_PARENT), 0, 0, 0, 0, 0, 0)
    if phase == 3070:
        put(w, SC_ATOMIC_PARENT, NONE)
        return call(o, w, 3071, 3, get(w, SC_ATOMIC_FD), 0, 0, 0, 0, 0, 0)
    if phase == 3071:
        put(w, SC_ATOMIC_FD, NONE)
        return sc_go(w, get(w, SC_ATOMIC_NEXT))
    if phase == 3075:
        if get(w, SC_ATOMIC_PARENT) != NONE:
            return call(o, w, 3070, 3, get(w, SC_ATOMIC_PARENT), 0, 0, 0, 0, 0, 0)
        return call(o, w, 3071, 3, get(w, SC_ATOMIC_FD), 0, 0, 0, 0, 0, 0)
    return 0

def scratch_atomic_fail(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 3075, 87, SC_PATH_TEMP, 0, 0, 0, 0, 0, 3)
'''

def source_program():
 source=POLICY
 source+=record.matcher('scratch_key',KEYS)
 source+=record.matcher('scratch_literal',LITERALS)
 source+=record.matcher('owner_schema',('hepta.rea.engine-scratch-owner.v1',))
 source+=record.texts('scratch_json',JSON_TEXT).replace('def scratch_json(w:mutbuf, field:u64, at:u64)', 'def scratch_json(w:mutbuf, at:u64, field:u64)')
 return compose(source)
def main():
 p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args()
 doc=document(source_program(),'system_jobctl_scratch');text=render_assembly(doc);path=ROOT/'examples/hia_bootstrap/system_jobctl_scratch.hepta'
 if a.check:assert path.read_text()==text
 else:path.write_text(text)
 print(path.name,len(text),'functions',len(doc['functions']),'blocks',sum(len(f['blocks'])for f in doc['functions']),'ops',sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
