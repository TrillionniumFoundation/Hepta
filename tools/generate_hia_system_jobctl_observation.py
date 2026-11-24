"""Privileged root jobctl STATUS, READ, CANCEL and invocation binding in HIA."""
from __future__ import annotations
import argparse
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_system_jobctl_observation_common import compose
from tools.generate_hia_system_jobctl_observation_render import SOURCE as RENDER

ROOT=Path(__file__).resolve().parents[1]
POLICY=r'''
def observation(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    action = dispatch(s, o, w)
    if get(w, SUBOP) == 3 and (action == zero_action() or (get(w, 0) >= 2060 and get(w, 0) < 2070)):
        return go(w, 238)
    return action

def zero_action() -> u32:
    return 0

def dispatch(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 600 and phase < 610:
        return recoverable_file(o, w, phase, result)
    if phase >= 450 and phase < 480:
        return terminal_observation(o, w, phase, result)
    if phase >= 400 and phase < 430:
        return properties(o, w, phase, result)
    if phase >= 500 and phase < 510:
        return retained_scratch(o, w, phase, result)
    if phase >= 560 and phase < 580:
        return read_page(o, w, phase, result)
    if phase >= 240 and phase < 260:
        return internal_lock(o, w, phase, result)
    if phase >= 200 and phase < 240:
        return operation(o, w, phase, result)
    if phase >= 680 and phase < 690:
        return output_write(o, w, phase, result)
    return 0

def operation(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 200:
        put(w, PROBE_ERROR, 0)
        put(w, PROBE_ERROR_KIND, 0)
        put(w, PROBE_ERROR_DETAIL, 0)
        put(w, SCRATCH_SIZE, 0)
        put(w, RETAINED, 0)
        put(w, ATOMIC_FAILURE_NEXT, 0)
        put(w, INTERNAL_LOCK, 0)
        return call(o, w, 201, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 201:
        if failed(result):
            return 0
        put(w, PID, result)
        if get(w, SUBOP) == 3:
            put(w, INTERNAL_STEP, 0)
            return internal_mkdir(o, w)
        if get(w, SUBOP) != 0:
            return begin_properties(o, w, 230)
        if get(w, START_REUSED) == 1:
            return record_ready(o, w)
        record_path(w)
        return begin_io(o, w, 202, FILE_RAW, 1048577, 1048576)
    if phase == 202:
        if get(w, IO_ERROR) != 0:
            return io_diagnostic(w, L_ERROR_UNKNOWN_JOB)
        return record_call(o, w, 203, 0, FILE_RAW, get(w, IO_USED))
    if phase == 203:
        if result != 1:
            return typed_diagnostic(o, w, 212, 2, 1, FILE_RAW, get(w, IO_USED), L_ERROR_UNKNOWN_JOB)
        if retained_identity(w) == 0:
            return observation_error(w, L_ERROR_JOB_IDENTITY)
        return record_ready(o, w)
    if phase == 204:
        if get(w, OBS_KIND) != 0:
            return render_status(o, w)
        terminated(w, text_boot(w, PATH))
        return begin_io(o, w, 205, FILE_RAW, 1048577, 1048576)
    if phase == 205:
        if get(w, IO_ERROR) != 0:
            return io_diagnostic(w, NONE)
        if kernel_text(w, FILE_RAW, get(w, IO_USED)) == 0:
            return observation_error(w, L_ERROR_UTF8)
        if equal(w, get(w, RECORD_FIELDS + 48), get(w, RECORD_FIELDS + 56), get(w, SCAN_NEXT), get(w, SCAN_SIZE)) == 0:
            return begin_terminal(o, w, 206)
        return begin_properties(o, w, 207)
    if phase == 206:
        if get(w, OBS_KIND) != 0:
            return render_status(o, w)
        put(w, STATE_CODE, 3)
        put(w, MISSING_REASON, L_TARGET_REBOOT)
        if get(w, RECORD_PROTOCOL) != 0:
            return begin_retained(o, w, 209)
        put(w, RENDER_KIND, 1)
        return render_status(o, w)
    if phase == 207:
        return begin_terminal(o, w, 208)
    if phase == 208:
        if get(w, OBS_KIND) != 0:
            return render_status(o, w)
        if get(w, PROBE_ERROR) != 0:
            return probe_diagnostic(w)
        state = 3
        if record_state(w) == 5:
            state = 4
        elif get(w, PROBE_PRESENT) != 0:
            active = property_state(w)
            if active >= 1 and active <= 3:
                state = 1
            elif active == 4:
                state = 2
        put(w, STATE_CODE, state)
        put(w, RENDER_KIND, 2)
        if get(w, RECORD_PROTOCOL) != 0 and state != 1:
            put(w, STATE_CODE, 7)
            put(w, MISSING_REASON, L_RECEIPT_MISSING)
            return begin_retained(o, w, 209)
        return render_status(o, w)
    if phase == 209:
        put(w, RENDER_KIND, 3)
        return render_status(o, w)
    if phase == 210:
        if get(w, OBS_KIND) == 0:
            return begin_retained(o, w, 211)
        return read_start(o, w)
    if phase == 211:
        return read_start(o, w)
    if phase >= 212 and phase <= 214:
        return typed_diagnostic_ready(w, result)
    if phase == 220:
        if get(w, IO_ERROR) != 0:
            return io_diagnostic(w, NONE)
        if kernel_text(w, FILE_RAW, get(w, IO_USED)) == 0:
            return observation_error(w, L_ERROR_UTF8)
        if equal(w, get(w, RECORD_FIELDS + 48), get(w, RECORD_FIELDS + 56), get(w, SCAN_NEXT), get(w, SCAN_SIZE)) == 0:
            return observation_error(w, L_ERROR_REBOOT_CANCEL)
        return begin_properties(o, w, 221)
    if phase == 221:
        if get(w, PROBE_ERROR) != 0:
            return probe_diagnostic(w)
        active = property_state(w)
        if get(w, PROBE_PRESENT) == 0 or active < 1 or active > 3:
            return cancel_result(o, w, 0)
        if systemctl_command(w, 1) == 0:
            return 0
        put(w, PROCESS_MODE, 0)
        put(w, PROCESS_NEXT, 222)
        put(w, PROCESS_FAILURE_NEXT, 222)
        put(w, 0, 1500)
        return 11
    if phase == 222:
        put(w, PROPERTY_FD, get(w, PROCESS_FDS))
        put(w, PROPERTY_ERROR_FD, get(w, PROCESS_FDS + 8))
        if get(w, SUBOP) != 3 and get(w, PROCESS_FAILURE) == 0 and get(w, PROCESS_ERRNO) == 0 and get(w, PROCESS_STATUS) != 0:
            put(w, STOP_ERROR_FD, get(w, PROPERTY_ERROR_FD))
            put(w, STOP_ERROR_SIZE, get(w, PROCESS_ERR_BYTES))
            put(w, PROPERTY_ERROR_FD, NONE)
            put(w, PROPERTY_CLOSE_NEXT, 226)
            return property_close(o, w)
        put(w, PROPERTY_CLOSE_NEXT, 225)
        return property_close(o, w)
    if phase == 225:
        if get(w, PROCESS_FAILURE) != 0:
            return diagnostic_errno(w, 0 - get(w, PROCESS_FAILURE))
        if get(w, PROCESS_ERRNO) != 0:
            return diagnostic_errno(w, 0 - get(w, PROCESS_ERRNO))
        if get(w, PROCESS_STATUS) != 0:
            return 0
        field(w, 6, 57400, lit(w, L_CANCELLED_RAW, 57400) - 57400)
        return record_call(o, w, 223, 1, FILE_RAW, 0)
    if phase == 226:
        end = lit(w, L_ERROR_STOP_PREFIX, ERROR_TEXT)
        fd = get(w, STOP_ERROR_FD)
        put(w, STOP_ERROR_FD, NONE)
        return diagnostic_stderr(w, fd, get(w, STOP_ERROR_SIZE), ERROR_TEXT, end - ERROR_TEXT)
    if phase == 223:
        if result != 1:
            return 0
        if get(w, SUBOP) == 3:
            put(w, ATOMIC_FAILURE_NEXT, 238)
        return begin_atomic(o, w, 224, 1, RECORD_OUT, get(w, RECORD_SIZE))
    if phase == 224:
        return cancel_result(o, w, 1)
    if phase == 230:
        if get(w, PROBE_ERROR) != 0:
            return probe_diagnostic(w)
        put(w, 0, get(w, SUBOP_NEXT))
        return 8
    if phase == 238:
        if get(w, INTERNAL_LOCK) != 0:
            return call(o, w, 245, 73, get(w, 368), 8, 0, 0, 0, 0, 0)
        return go(w, get(w, SUBOP_NEXT))
    if phase == 239:
        put(w, INTERNAL_LOCK, 0)
        put(w, 368, NONE)
        return go(w, get(w, SUBOP_NEXT))
    return 0

def record_ready(o:mutbuf, w:mutbuf) -> u32:
    if retained_identity(w) == 0:
        return observation_error(w, L_ERROR_JOB_IDENTITY)
    at = lit(w, L_DATA_PREFIX, DATA_DIR)
    copy(w, at, JOB_ID, get(w, 48))
    at = at + get(w, 48)
    put(w, DATA_SIZE, at - DATA_DIR)
    store(w, at, 0)
    put(w, RENDER_KIND, 0)
    if get(w, 40) == 5:
        terminated(w, text_boot(w, PATH))
        return begin_io(o, w, 220, FILE_RAW, 1048577, 1048576)
    return begin_terminal(o, w, choose(get(w, 40) == 4, 210, 204))

def go(w:mutbuf, phase:u64) -> u32:
    put(w, 0, phase)
    return 8

def observation_error(w:mutbuf, reason:u64) -> u32:
    end = lit(w, reason, ERROR_TEXT)
    return diagnostic(w, ERROR_TEXT, end - ERROR_TEXT)

def io_diagnostic(w:mutbuf, context:u64) -> u32:
    at = ERROR_TEXT
    if context != NONE:
        at = lit(w, context, at)
    if get(w, IO_REASON) == 1:
        at = lit(w, L_ERROR_BOUNDED_JSON, at)
        return diagnostic(w, ERROR_TEXT, at - ERROR_TEXT)
    if context == NONE:
        return diagnostic_errno(w, get(w, IO_ERROR))
    return diagnostic_context_errno(w, ERROR_TEXT, at - ERROR_TEXT, get(w, IO_ERROR))

def probe_diagnostic(w:mutbuf) -> u32:
    if get(w, PROBE_ERROR_KIND) == 1:
        return diagnostic_errno(w, get(w, PROBE_ERROR_DETAIL))
    if get(w, PROBE_ERROR_KIND) == 2:
        return observation_error(w, get(w, PROBE_ERROR_DETAIL))
    return 0

def typed_diagnostic(o:mutbuf, w:mutbuf, next:u64, schema:u64, reader:u64, source:u64, size:u64, context:u64) -> u32:
    put(w, TYPE_ERROR_CONTEXT, context)
    put(w, TYPE_ERROR_OUT, schema)
    put(w, TYPE_ERROR_OUT + 8, reader)
    put(w, 0, next)
    put(o, 0, source)
    put(o, 8, size)
    put(o, 16, TYPE_ERROR_OUT)
    put(o, 24, TYPE_ERROR_CAP)
    put(o, 32, TYPE_ERROR_WORK)
    put(o, 40, TYPE_ERROR_WORK_BYTES)
    return 26

def typed_diagnostic_ready(w:mutbuf, result:u64) -> u32:
    if result == 0 or result >= 4294967280 or result > TYPE_ERROR_CAP:
        return 0
    if get(w, 67616) != TYPE_ERROR_OUT or get(w, 67624) != result:
        return 0
    context = get(w, TYPE_ERROR_CONTEXT)
    if context == NONE:
        return diagnostic(w, TYPE_ERROR_OUT, result)
    size = lit(w, context, ERROR_TEXT) - ERROR_TEXT
    start = TYPE_ERROR_OUT - size
    copy(w, start, ERROR_TEXT, size)
    return diagnostic(w, start, size + result)

def internal_mkdir(o:mutbuf, w:mutbuf) -> u32:
    step = get(w, INTERNAL_STEP)
    at = text_var(w, PATH)
    if step == 1:
        at = text_varlib(w, PATH)
    elif step == 2:
        at = text_root(w, PATH)
    store(w, at, 0)
    return call(o, w, 240, 258, NEG100, PATH, 511, 0, 0, 0, 12)

def internal_lock(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 240:
        if result != 0 and result != NEG17:
            return 0
        return call(o, w, 241, 262, NEG100, PATH, STAT, 0, 0, 0, 60)
    if phase == 241:
        if result != 0 or getn(w, STAT + 24, 4) & 61440 != 16384:
            return 0
        put(w, INTERNAL_STEP, get(w, INTERNAL_STEP) + 1)
        if get(w, INTERNAL_STEP) < 3:
            return internal_mkdir(o, w)
        terminated(w, text_root(w, PATH))
        return call(o, w, 242, 90, PATH, 448, 0, 0, 0, 0, 3)
    if phase == 242:
        if result != 0:
            return 0
        terminated(w, text_lock(w, text_root(w, PATH)))
        return call(o, w, 243, 257, NEG100, PATH, 524354, 384, 0, 0, 12)
    if phase == 243:
        if failed(result):
            return 0
        put(w, 368, result)
        put(w, INTERNAL_LOCK, 1)
        return call(o, w, 244, 73, result, 2, 0, 0, 0, 0, 0)
    if phase == 244:
        if result != 0:
            return 0
        record_path(w)
        return begin_io(o, w, 202, FILE_RAW, 1048577, 1048576)
    if phase == 245:
        return call(o, w, 239, 3, get(w, 368), 0, 0, 0, 0, 0, 0)
    return 0

def data_path(w:mutbuf, name:u64) -> u64:
    copy(w, PATH, DATA_DIR, get(w, DATA_SIZE))
    at = lit(w, name, PATH + get(w, DATA_SIZE))
    store(w, at, 0)
    return 0

def begin_terminal(o:mutbuf, w:mutbuf, next:u64) -> u32:
    put(w, TERMINAL_NEXT, next)
    put(w, OBS_KIND, 0)
    put(w, OBS_REASON, 0)
    put(w, OBS_WITNESSED, 0)
    put(w, SCRATCH_SIZE, 0)
    put(w, RETAINED, 0)
    data_path(w, L_EXIT)
    return call(o, w, 450, 262, NEG100, PATH, STAT, 0, 0, 0, 60)

def terminal_done(w:mutbuf, kind:u64, reason:u64) -> u32:
    put(w, OBS_KIND, kind)
    put(w, OBS_REASON, reason)
    return go(w, get(w, TERMINAL_NEXT))

def terminal_invalid(w:mutbuf, reason:u64) -> u32:
    if get(w, RECORD_PROTOCOL) == 0:
        return 0
    return terminal_done(w, 1, reason)

def terminal_call(o:mutbuf, w:mutbuf, next:u64, mode:u64, source:u64, size:u64) -> u32:
    put(w, TERMINAL_MODE, mode)
    put(w, 0, next)
    put(o, 0, source)
    put(o, 8, size)
    return 13

def terminal_observation(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 450:
        if result == NEG2:
            return terminal_done(w, 0, 0)
        if result != 0:
            return diagnostic_errno(w, result)
        return begin_io(o, w, 452, EXIT_RAW, 1048577, 1048576)
    if phase == 452:
        if get(w, IO_ERROR) != 0 or get(w, IO_USED) > 1048576:
            if get(w, RECORD_PROTOCOL) == 0:
                if get(w, IO_ERROR) != 0:
                    return io_diagnostic(w, NONE)
                return observation_error(w, L_ERROR_GROWN_JSON)
            return terminal_invalid(w, 1)
        put(w, EXIT_SIZE, get(w, IO_USED))
        return terminal_call(o, w, 453, 0, EXIT_RAW, get(w, EXIT_SIZE))
    if phase == 453:
        if result != 1:
            if get(w, RECORD_PROTOCOL) == 0:
                return typed_diagnostic(o, w, 213, 4, 0, EXIT_RAW, get(w, EXIT_SIZE), NONE)
            return terminal_invalid(w, 2)
        if get(w, T_SCRATCH) != NONE:
            return canonical_value(o, w, 454, EXIT_RAW + get(w, T_SCRATCH), get(w, T_SCRATCH_SIZE))
        return exit_identity(o, w)
    if phase == 454:
        if result > SCRATCH_CAP:
            if get(w, RECORD_PROTOCOL) == 0:
                return typed_diagnostic(o, w, 213, 4, 0, EXIT_RAW, get(w, EXIT_SIZE), NONE)
            return terminal_invalid(w, 2)
        copy(w, SCRATCH_VALUE, CANON_RESULT, result)
        put(w, SCRATCH_SIZE, result)
        return exit_identity(o, w)
    if phase == 455:
        if result != 1:
            return terminal_done(w, 1, 4)
        if get(w, T_PROTOCOL) == 0:
            return terminal_done(w, 2, 0)
        put(w, HASH_USED, 0)
        return hash_terminal(o, w, 456, 0, 1)
    if phase == 456:
        if result != 0:
            return 0
        return hash_next(o, w)
    if phase == 457:
        if result != 0:
            return 0
        if get(w, HASH_USED) < get(w, EXIT_SIZE):
            return hash_next(o, w)
        return hash_terminal(o, w, 458, 2, 1)
    if phase == 458:
        if result != 32:
            return 0
        index = 0
        while index < 32:
            value = byte(w, SHA_OUT + index)
            store(w, 57500 + index * 2, hexadecimal(value >> 4))
            store(w, 57500 + index * 2 + 1, hexadecimal(value & 15))
            index = index + 1
        data_path(w, L_WITNESS)
        return begin_io(o, w, 459, WITNESS_RAW, 1048577, 1048576)
    if phase == 459:
        if get(w, IO_ERROR) != 0:
            return terminal_done(w, 1, 5)
        return terminal_call(o, w, 460, 1, WITNESS_RAW, get(w, IO_USED))
    if phase == 460:
        if result != 1:
            return terminal_done(w, 1, 5)
        if equal(w, get(w, WITNESS_VALUES), get(w, WITNESS_VALUES + 8), get(w, RECORD_FIELDS), get(w, RECORD_FIELDS + 8)) == 0 or equal(w, get(w, WITNESS_VALUES + 16), get(w, WITNESS_VALUES + 24), get(w, RECORD_FIELDS + 64), get(w, RECORD_FIELDS + 72)) == 0:
            return terminal_done(w, 1, 6)
        if get(w, T_WITNESS_PROTOCOL) != get(w, T_PROTOCOL) or equal(w, get(w, WITNESS_VALUES + 48), get(w, WITNESS_VALUES + 56), 57500, 64) == 0:
            return terminal_done(w, 1, 6)
        put(w, OBS_WITNESSED, 1)
        return terminal_done(w, 2, 0)
    return 0

def exit_identity(o:mutbuf, w:mutbuf) -> u32:
    if equal(w, get(w, EXIT_VALUES), get(w, EXIT_VALUES + 8), get(w, RECORD_FIELDS), get(w, RECORD_FIELDS + 8)) == 0 or equal(w, get(w, EXIT_VALUES + 16), get(w, EXIT_VALUES + 24), get(w, RECORD_FIELDS + 64), get(w, RECORD_FIELDS + 72)) == 0:
        return observation_error(w, L_ERROR_EXIT_IDENTITY)
    if get(w, RECORD_PROTOCOL) != 0 and get(w, RECORD_PROTOCOL) != get(w, T_PROTOCOL):
        return terminal_done(w, 1, 3)
    return terminal_call(o, w, 455, 2, EXIT_RAW, 0)

def hash_terminal(o:mutbuf, w:mutbuf, next:u64, command:u64, size:u64) -> u32:
    store(w, HASH_INPUT, command)
    put(w, 0, next)
    put(o, 0, HASH_INPUT)
    put(o, 8, size)
    put(o, 16, SHA_OUT)
    put(o, 24, SHA_STATE)
    return 10

def hash_next(o:mutbuf, w:mutbuf) -> u32:
    take = get(w, EXIT_SIZE) - get(w, HASH_USED)
    if take > 65536:
        take = 65536
    copy(w, HASH_INPUT + 1, EXIT_RAW + get(w, HASH_USED), take)
    put(w, HASH_USED, get(w, HASH_USED) + take)
    return hash_terminal(o, w, 457, 1, take + 1)

def canonical_value(o:mutbuf, w:mutbuf, next:u64, source:u64, size:u64) -> u32:
    put(w, CANON_RESULT, choose(next == 454, 0, 1))
    put(w, 0, next)
    put(o, 0, source)
    put(o, 8, size)
    put(o, 16, CANON_RESULT)
    put(o, 24, 8388608)
    put(o, 32, CANON_WORK)
    put(o, 40, CANON_BYTES)
    return 14

def begin_io(o:mutbuf, w:mutbuf, next:u64, target:u64, limit:u64, metadata_limit:u64) -> u32:
    put(w, IO_NEXT, next)
    put(w, IO_ERROR, 0)
    put(w, IO_REASON, 0)
    put(w, IO_FD, NONE)
    put(w, IO_TARGET, target)
    put(w, IO_LIMIT, limit)
    put(w, IO_META_LIMIT, metadata_limit)
    put(w, IO_USED, 0)
    return call(o, w, 600, 257, NEG100, PATH, 657408, 0, 0, 0, 12)

def recoverable_file(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 600:
        if result == NEG4:
            return call(o, w, 600, 257, NEG100, PATH, 657408, 0, 0, 0, 12)
        if failed(result):
            put(w, IO_ERROR, result)
            return go(w, get(w, IO_NEXT))
        put(w, IO_FD, result)
        return call(o, w, 601, 5, result, STAT, 0, 0, 0, 0, 12)
    if phase == 601:
        if result != 0 or getn(w, STAT + 24, 4) & 61440 != 32768 or get(w, STAT + 48) > get(w, IO_META_LIMIT):
            if result == 0:
                put(w, IO_REASON, 1)
            put(w, IO_ERROR, choose(result == 0, NEG22, result))
            return io_close(o, w)
        return io_read(o, w)
    if phase == 602:
        if result == NEG4:
            return io_read(o, w)
        if failed(result) or result > get(w, IO_LIMIT) - get(w, IO_USED):
            put(w, IO_ERROR, choose(failed(result), result, NEG22))
            return io_close(o, w)
        put(w, IO_USED, get(w, IO_USED) + result)
        if result == 0 or get(w, IO_USED) == get(w, IO_LIMIT):
            return io_close(o, w)
        return io_read(o, w)
    if phase == 603:
        put(w, IO_FD, NONE)
        return go(w, get(w, IO_NEXT))
    return 0

def io_read(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 602, 0, get(w, IO_FD), get(w, IO_TARGET) + get(w, IO_USED), get(w, IO_LIMIT) - get(w, IO_USED), 0, 0, 0, 12)

def io_close(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 603, 3, get(w, IO_FD), 0, 0, 0, 0, 0, 0)

def begin_retained(o:mutbuf, w:mutbuf, next:u64) -> u32:
    put(w, RETAIN_NEXT, next)
    put(w, SCRATCH_SIZE, 0)
    put(w, RETAINED, 0)
    data_path(w, L_RETAINED_FILE)
    return begin_io(o, w, 500, RETAIN_RAW, 1048577, 1048576)

def retained_scratch(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 500:
        if get(w, IO_ERROR) == NEG2:
            return go(w, get(w, RETAIN_NEXT))
        if get(w, IO_ERROR) != 0:
            return io_diagnostic(w, L_ERROR_RETAINED_CONTEXT)
        return canonical_value(o, w, 501, RETAIN_RAW, get(w, IO_USED))
    if phase == 501:
        if result > SCRATCH_CAP:
            return typed_diagnostic(o, w, 214, 8, 1, RETAIN_RAW, get(w, IO_USED), L_ERROR_RETAINED_CONTEXT)
        copy(w, SCRATCH_VALUE, CANON_RESULT, result)
        put(w, SCRATCH_SIZE, result)
        return terminal_call(o, w, 502, 3, SCRATCH_VALUE, result)
    if phase == 502:
        if result != 1 or retained_valid(w) == 0:
            return observation_error(w, L_ERROR_RETAINED_INVALID)
        put(w, RETAINED, 1)
        return go(w, get(w, RETAIN_NEXT))
    return 0

def retained_valid(w:mutbuf) -> u64:
    index = 0
    while index < 13:
        source = get(w, T_VALUE_FIELDS + index * 16)
        size = get(w, T_VALUE_FIELDS + index * 16 + 8)
        if index < 5 or index == 7:
            if index == 0 and retained_literal(w, source, size, 0) == 0:
                return 0
            if index == 1 and equal(w, source, size, get(w, RECORD_FIELDS), get(w, RECORD_FIELDS + 8)) == 0:
                return 0
            if index == 2 and equal(w, source, size, get(w, RECORD_FIELDS + 64), get(w, RECORD_FIELDS + 72)) == 0:
                return 0
            if (index == 3 or index == 4) and retained_literal(w, source, size, index - 2) == 0:
                return 0
        elif index >= 8 and source != 0:
            return 0
        index = index + 1
    return 1

def uint_text(w:mutbuf, source:u64, size:u64) -> u64:
    if size == 0 or size > 20:
        return 0
    value = 0
    index = 0
    while index < size:
        point = byte(w, source + index)
        if point < 48 or point > 57:
            return 0
        digit = point - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return 0
        value = value * 10 + digit
        index = index + 1
    return 1

def begin_properties(o:mutbuf, w:mutbuf, next:u64) -> u32:
    put(w, PROBE_NEXT, next)
    put(w, PROBE_ERROR, 0)
    put(w, PROBE_ERROR_KIND, 0)
    put(w, PROBE_ERROR_DETAIL, 0)
    put(w, PROBE_PRESENT, 0)
    put(w, INVOCATION_PRESENT, 0)
    put(w, INVOCATION_AT, NONE)
    put(w, INVOCATION_SIZE, 0)
    put(w, PROPERTY_FD, NONE)
    put(w, PROPERTY_ERROR_FD, NONE)
    if systemctl_command(w, 0) == 0:
        return 0
    put(w, PROCESS_MODE, 0)
    put(w, PROCESS_NEXT, 400)
    put(w, PROCESS_FAILURE_NEXT, 400)
    put(w, 0, 1500)
    return 11

def systemctl_command(w:mutbuf, stop:u64) -> u64:
    put(w, COMMAND_COUNT, 0)
    put(w, COMMAND_CURSOR, COMMAND)
    if argument(w, lit(w, L_SYSTEMCTL, get(w, COMMAND_CURSOR))) == 0:
        return 0
    if argument(w, lit(w, choose(stop == 0, L_SHOW, L_STOP), get(w, COMMAND_CURSOR))) == 0:
        return 0
    if stop == 0:
        if argument(w, lit(w, L_NO_PAGER, get(w, COMMAND_CURSOR))) == 0 or argument(w, lit(w, L_PROPERTIES, get(w, COMMAND_CURSOR))) == 0:
            return 0
    if argument(w, lit(w, L_SEPARATOR, get(w, COMMAND_CURSOR))) == 0:
        return 0
    return raw_argument(w, UNIT, get(w, 56))

def property_failure(o:mutbuf, w:mutbuf) -> u32:
    put(w, PROBE_ERROR, 1)
    put(w, PROPERTY_CLOSE_NEXT, get(w, PROBE_NEXT))
    return property_close(o, w)

def property_errno(o:mutbuf, w:mutbuf, raw:u64) -> u32:
    put(w, PROBE_ERROR_KIND, 1)
    put(w, PROBE_ERROR_DETAIL, raw)
    return property_failure(o, w)

def property_error(o:mutbuf, w:mutbuf, reason:u64) -> u32:
    put(w, PROBE_ERROR_KIND, 2)
    put(w, PROBE_ERROR_DETAIL, reason)
    return property_failure(o, w)

def property_close(o:mutbuf, w:mutbuf) -> u32:
    if get(w, PROPERTY_FD) != NONE:
        fd = get(w, PROPERTY_FD)
        put(w, PROPERTY_FD, NONE)
        return call(o, w, 406, 3, fd, 0, 0, 0, 0, 0, 0)
    if get(w, PROPERTY_ERROR_FD) != NONE:
        fd = get(w, PROPERTY_ERROR_FD)
        put(w, PROPERTY_ERROR_FD, NONE)
        return call(o, w, 406, 3, fd, 0, 0, 0, 0, 0, 0)
    return go(w, get(w, PROPERTY_CLOSE_NEXT))

def properties(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 400:
        put(w, PROPERTY_FD, get(w, PROCESS_FDS))
        put(w, PROPERTY_ERROR_FD, get(w, PROCESS_FDS + 8))
        if get(w, PROCESS_FAILURE) != 0:
            return property_errno(o, w, 0 - get(w, PROCESS_FAILURE))
        if get(w, PROCESS_ERRNO) != 0:
            return property_errno(o, w, 0 - get(w, PROCESS_ERRNO))
        put(w, PROPERTY_BYTES, get(w, PROCESS_OUT_BYTES))
        put(w, PROPERTY_READ, 0)
        if get(w, PROPERTY_BYTES) > PROP_CAP:
            return property_failure(o, w)
        return property_read(o, w)
    if phase == 401:
        if result == NEG4:
            return property_read(o, w)
        if failed(result):
            return property_errno(o, w, result)
        if result > get(w, PROPERTY_BYTES) - get(w, PROPERTY_READ) or (result == 0 and get(w, PROPERTY_READ) != get(w, PROPERTY_BYTES)):
            return property_failure(o, w)
        put(w, PROPERTY_READ, get(w, PROPERTY_READ) + result)
        if get(w, PROPERTY_READ) < get(w, PROPERTY_BYTES):
            return property_read(o, w)
        return call(o, w, 402, 3, get(w, PROPERTY_FD), 0, 0, 0, 0, 0, 0)
    if phase == 402:
        put(w, PROPERTY_FD, NONE)
        return call(o, w, 403, 3, get(w, PROPERTY_ERROR_FD), 0, 0, 0, 0, 0, 0)
    if phase == 403:
        put(w, PROPERTY_ERROR_FD, NONE)
        size = bounded_lossy(w, PROP_TEXT, PROP_RAW, get(w, PROPERTY_BYTES), PROP_CAP)
        if size == NONE or parse_properties(w, size) == 0:
            return property_failure(o, w)
        row = property(w, 3)
        if row != NONE:
            put(w, INVOCATION_AT, get(w, row + 16))
            put(w, INVOCATION_SIZE, get(w, row + 24))
            put(w, INVOCATION_PRESENT, choose(get(w, row + 24) != 0, 1, 0))
        if get(w, SUBOP) == 1:
            put(w, PROBE_PRESENT, 1)
            return go(w, get(w, PROBE_NEXT))
        return bind_invocation(o, w)
    if phase == 404:
        if result != 1:
            return property_failure(o, w)
        put(w, ATOMIC_FAILURE_NEXT, 405)
        return begin_atomic(o, w, 405, 1, RECORD_OUT, get(w, RECORD_SIZE))
    if phase == 405:
        if get(w, ATOMIC_ERROR) != 0:
            if get(w, ATOMIC_WRITE_ZERO) != 0:
                return property_error(o, w, L_ERROR_WRITE_ZERO)
            return property_errno(o, w, get(w, ATOMIC_RAW_ERROR))
        put(w, PROBE_PRESENT, 1)
        return go(w, get(w, PROBE_NEXT))
    if phase == 406:
        return property_close(o, w)
    return 0

def property_read(o:mutbuf, w:mutbuf) -> u32:
    if get(w, PROPERTY_READ) == get(w, PROPERTY_BYTES):
        return call(o, w, 402, 3, get(w, PROPERTY_FD), 0, 0, 0, 0, 0, 0)
    return call(o, w, 401, 17, get(w, PROPERTY_FD), PROP_RAW + get(w, PROPERTY_READ), get(w, PROPERTY_BYTES) - get(w, PROPERTY_READ), get(w, PROPERTY_READ), 0, 0, 12)

def parse_properties(w:mutbuf, size:u64) -> u64:
    put(w, PROPERTY_COUNT, 0)
    at = 0
    while at < size:
        start = at
        while at < size and byte(w, PROP_TEXT + at) != 10:
            at = at + 1
        end = at
        if at < size and end > start and byte(w, PROP_TEXT + end - 1) == 13:
            end = end - 1
        separator = start
        while separator < end and byte(w, PROP_TEXT + separator) != 61:
            separator = separator + 1
        if separator < end:
            index = 0
            found = False
            while index < get(w, PROPERTY_COUNT) and found == False:
                row = PROP_TABLE + index * 32
                if equal(w, get(w, row), get(w, row + 8), PROP_TEXT + start, separator - start) == 1:
                    found = True
                else:
                    index = index + 1
            if index == get(w, PROPERTY_COUNT):
                if index >= (PROP_TABLE_END - PROP_TABLE) // 32:
                    return 0
                put(w, PROPERTY_COUNT, index + 1)
            row = PROP_TABLE + index * 32
            put(w, row, PROP_TEXT + start)
            put(w, row + 8, separator - start)
            put(w, row + 16, PROP_TEXT + separator + 1)
            put(w, row + 24, end - separator - 1)
        at = at + 1
    return 1

def property(w:mutbuf, wanted:u64) -> u64:
    index = 0
    while index < get(w, PROPERTY_COUNT):
        row = PROP_TABLE + index * 32
        if property_id(w, get(w, row), get(w, row + 8)) == wanted:
            return row
        index = index + 1
    return NONE

def property_state(w:mutbuf) -> u64:
    row = property(w, 2)
    if row == NONE:
        return 0
    return state_id(w, get(w, row + 16), get(w, row + 24))

def record_state(w:mutbuf) -> u64:
    return state_id(w, get(w, RECORD_FIELDS + 96), get(w, RECORD_FIELDS + 104))

def bind_invocation(o:mutbuf, w:mutbuf) -> u32:
    row = property(w, 1)
    if row != NONE and not_found(w, get(w, row + 16), get(w, row + 24)) == 1:
        return go(w, get(w, PROBE_NEXT))
    row = property(w, 4)
    at = lit(w, L_DESCRIPTION, EXIT_RAW)
    copy(w, at, JOB_ID, get(w, 48))
    at = at + get(w, 48)
    store(w, at, 32)
    copy(w, at + 1, get(w, RECORD_FIELDS + 64), get(w, RECORD_FIELDS + 72))
    at = at + 1 + get(w, RECORD_FIELDS + 72)
    if row == NONE or equal(w, get(w, row + 16), get(w, row + 24), EXIT_RAW, at - EXIT_RAW) == 0:
        return property_error(o, w, L_ERROR_UNIT_OWNER)
    if get(w, INVOCATION_PRESENT) == 0:
        return property_error(o, w, L_ERROR_UNIT_INVOCATION)
    existing = get(w, RECORD_FIELDS + 80)
    if existing != NONE:
        if equal(w, existing, get(w, RECORD_FIELDS + 88), get(w, INVOCATION_AT), get(w, INVOCATION_SIZE)) == 0:
            return property_error(o, w, L_ERROR_UNIT_INCARNATION)
        put(w, PROBE_PRESENT, 1)
        return go(w, get(w, PROBE_NEXT))
    at = RECORD_DATA
    index = 0
    while index < 9:
        source = get(w, RECORD_FIELDS + index * 16)
        size = get(w, RECORD_FIELDS + index * 16 + 8)
        if source >= RECORD_DATA and source < RECORD_DATA + RECORD_CAP and source + size > at:
            at = source + size
        index = index + 1
    if get(w, INVOCATION_SIZE) > RECORD_DATA + RECORD_CAP - at:
        return property_failure(o, w)
    copy(w, at, get(w, INVOCATION_AT), get(w, INVOCATION_SIZE))
    field(w, 5, at, get(w, INVOCATION_SIZE))
    return record_call(o, w, 404, 1, FILE_RAW, 0)

def render_status(o:mutbuf, w:mutbuf) -> u32:
    at = output_start(w)
    kind = get(w, OBS_KIND)
    render = get(w, RENDER_KIND)
    if kind != 0:
        at = metadata_json(w, at, 0)
        if kind == 1:
            at = publication_json(w, at)
        else:
            at = completed_json(w, at)
    elif render == 1:
        at = quote(w, lit(w, L_JOB_OPEN, at), JOB_ID, get(w, 48))
        at = lit(w, L_LOST, key(w, K_STATE, at))
        at = lit(w, L_TARGET_REBOOT, key(w, K_REASON, at))
        at = lit(w, L_SYSTEMD, key(w, K_BACKEND, at))
    elif render == 3:
        at = metadata_json(w, at, 1)
        at = unknown_json(w, at, state_token(get(w, STATE_CODE)), get(w, MISSING_REASON))
        at = scratch_json(w, at)
        if get(w, STATE_CODE) == 7:
            at = properties_json(w, key(w, K_SYSTEMD, at))
            at = record_string(w, key(w, K_LAUNCH_STATE, at), 6)
    else:
        at = quote(w, lit(w, L_JOB_OPEN, at), JOB_ID, get(w, 48))
        at = lit(w, state_token(get(w, STATE_CODE)), key(w, K_STATE, at))
        at = lit(w, L_SYSTEMD, key(w, K_BACKEND, at))
        at = properties_json(w, key(w, K_SYSTEMD, at))
        at = record_string(w, key(w, K_LAUNCH_STATE, at), 6)
    return output_finish(o, w, at)

def read_start(o:mutbuf, w:mutbuf) -> u32:
    at = metadata_json(w, output_start(w), 0)
    if get(w, OBS_KIND) == 1:
        at = publication_json(w, at)
    else:
        at = quote(w, key(w, K_JOB_ID, at), JOB_ID, get(w, 48))
    if get(w, RETAINED) != 0:
        at = scratch_json(w, at)
    put(w, READ_AT, at)
    put(w, READ_SIDE, 0)
    return page_start(o, w)

def page_start(o:mutbuf, w:mutbuf) -> u32:
    side = get(w, READ_SIDE)
    put(w, PAGE_OFFSET, get(w, 72 + side * 8))
    put(w, PAGE_USED, 0)
    put(w, PAGE_SIZE, 0)
    put(w, PAGE_EXPECTED, NONE)
    put(w, PAGE_PRESENT, 0)
    put(w, PAGE_FD, NONE)
    if get(w, OBS_KIND) == 2 and get(w, T_CAPTURE) == 1:
        put(w, PAGE_EXPECTED, get(w, STREAM_VALUES + side * 160 + 16))
    data_path(w, choose(side == 0, L_STDOUT_LOG, L_STDERR_LOG))
    return call(o, w, 560, 257, NEG100, PATH, 657408, 0, 0, 0, 12)

def read_page(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 560:
        if result == NEG2 and get(w, PAGE_EXPECTED) == NONE and get(w, PAGE_OFFSET) == 0:
            return page_ready(o, w)
        if result == NEG4:
            return call(o, w, 560, 257, NEG100, PATH, 657408, 0, 0, 0, 12)
        if result == NEG2:
            return observation_error(w, choose(get(w, PAGE_EXPECTED) != NONE, L_ERROR_LOG_MISSING, L_ERROR_ABSENT_CURSOR))
        if failed(result):
            return diagnostic_errno(w, result)
        put(w, PAGE_PRESENT, 1)
        put(w, PAGE_FD, result)
        return call(o, w, 561, 5, result, STAT, 0, 0, 0, 0, 12)
    if phase == 561:
        if result != 0:
            return page_failure(o, w, 1, result)
        if getn(w, STAT + 24, 4) & 61440 != 32768:
            return page_failure(o, w, 2, L_ERROR_LOG_REGULAR)
        size = get(w, STAT + 48)
        put(w, PAGE_SIZE, size)
        if get(w, PAGE_EXPECTED) != NONE and get(w, PAGE_EXPECTED) != size:
            return page_failure(o, w, 2, L_ERROR_LOG_LENGTH)
        if get(w, PAGE_OFFSET) > size:
            return page_failure(o, w, 2, L_ERROR_LOG_CURSOR)
        return call(o, w, 562, 8, get(w, PAGE_FD), get(w, PAGE_OFFSET), 0, 0, 0, 0, 0)
    if phase == 562:
        if failed(result):
            return page_failure(o, w, 1, result)
        if result != get(w, PAGE_OFFSET):
            return 0
        return page_read(o, w)
    if phase == 563:
        if result == NEG4:
            return page_read(o, w)
        limit = page_limit(w)
        if failed(result):
            return page_failure(o, w, 1, result)
        if result > limit - get(w, PAGE_USED):
            return 0
        put(w, PAGE_USED, get(w, PAGE_USED) + result)
        if result != 0 and get(w, PAGE_USED) < limit:
            return page_read(o, w)
        if get(w, PAGE_EXPECTED) != NONE:
            return call(o, w, 564, 5, get(w, PAGE_FD), STAT, 0, 0, 0, 0, 12)
        return page_close(o, w)
    if phase == 564:
        remaining = get(w, PAGE_SIZE) - get(w, PAGE_OFFSET)
        expected = choose(remaining < page_limit(w), remaining, page_limit(w))
        if result != 0:
            return page_failure(o, w, 1, result)
        if get(w, STAT + 48) != get(w, PAGE_SIZE) or get(w, PAGE_USED) != expected:
            return page_failure(o, w, 2, L_ERROR_LOG_CHANGED)
        return page_close(o, w)
    if phase == 565:
        put(w, PAGE_FD, NONE)
        return page_ready(o, w)
    if phase == 566:
        put(w, PAGE_FD, NONE)
        if get(w, PAGE_ERROR_KIND) == 1:
            return diagnostic_errno(w, get(w, PAGE_ERROR_DETAIL))
        return observation_error(w, get(w, PAGE_ERROR_DETAIL))
    return 0

def page_failure(o:mutbuf, w:mutbuf, kind:u64, detail:u64) -> u32:
    put(w, PAGE_ERROR_KIND, kind)
    put(w, PAGE_ERROR_DETAIL, detail)
    return call(o, w, 566, 3, get(w, PAGE_FD), 0, 0, 0, 0, 0, 0)

def page_limit(w:mutbuf) -> u64:
    value = get(w, 88)
    return choose(value < 1, 1, choose(value > 16384, 16384, value))

def page_read(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 563, 0, get(w, PAGE_FD), LOG_RAW + get(w, PAGE_USED), page_limit(w) - get(w, PAGE_USED), 0, 0, 0, 12)

def page_close(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 565, 3, get(w, PAGE_FD), 0, 0, 0, 0, 0, 0)

def page_ready(o:mutbuf, w:mutbuf) -> u32:
    at = page_json(w, key(w, choose(get(w, READ_SIDE) == 0, K_STDOUT, K_STDERR), get(w, READ_AT)))
    if at == NONE:
        return 0
    put(w, READ_AT, at)
    if get(w, READ_SIDE) == 0:
        put(w, READ_SIDE, 1)
        return page_start(o, w)
    return output_finish(o, w, at)

def cancel_result(o:mutbuf, w:mutbuf, stopped:u64) -> u32:
    if get(w, SUBOP) == 3:
        return go(w, 238)
    at = quote(w, lit(w, L_JOB_OPEN, OUTPUT), JOB_ID, get(w, 48))
    at = lit(w, choose(stopped == 0, L_ALREADY_EXITED, L_STOP_REQUESTED), key(w, K_RESULT, at))
    if stopped != 0:
        at = record_string(w, key(w, K_INVOCATION_ID, at), 5)
    return output_finish(o, w, at)

def output_finish(o:mutbuf, w:mutbuf, at:u64) -> u32:
    if at == NONE or at >= OUTPUT_END - 3:
        return 0
    store(w, at, 125)
    at = at + 1
    if get(w, START_REUSED) == 1:
        store(w, at, 125)
        at = at + 1
    store(w, at, 10)
    put(w, OUT_SIZE, at + 1 - OUTPUT)
    put(w, OUT_USED, 0)
    return output_bytes(o, w)

def output_bytes(o:mutbuf, w:mutbuf) -> u32:
    if get(w, SUBOP) == 0 and get(w, OUT_USED) == 0 and get(w, 368) != NONE:
        put(w, 68500, 684)
        return go(w, 2080)
    return call(o, w, 680, 1, 1, OUTPUT + get(w, OUT_USED), get(w, OUT_SIZE) - get(w, OUT_USED), 0, 0, 0, 12)

def output_write(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 684:
        return output_bytes(o, w)
    if phase == 680:
        if result == NEG4:
            return output_bytes(o, w)
        if result == 0 or failed(result) or result > get(w, OUT_SIZE) - get(w, OUT_USED):
            return 0
        put(w, OUT_USED, get(w, OUT_USED) + result)
        if get(w, OUT_USED) < get(w, OUT_SIZE):
            return output_bytes(o, w)
        return call(o, w, 681, 60, 0, 0, 0, 0, 0, 0, 0)
    return 0
'''

def source_program():
    source=POLICY+RENDER
    source+='\ndef not_found(w:mutbuf, at:u64, size:u64) -> u64:\n'
    raw=b'not-found';source+=f'    return choose(size == {len(raw)} and getn(w, at, 8) == {int.from_bytes(raw[:8],"little")} and byte(w, at + 8) == {raw[8]}, 1, 0)\n'
    source+='\ndef retained_literal(w:mutbuf, at:u64, size:u64, kind:u64) -> u64:\n'
    for index,name in enumerate(('hepta.rea.engine-scratch-cleanup.v1','engine-scratch','retained')):
        raw=name.encode();parts=[f'getn(w, at + {i}, {len(raw[i:i+8])}) ^ {int.from_bytes(raw[i:i+8],"little")}' for i in range(0,len(raw),8)]
        source+=f'    if kind == {index} and size == {len(raw)}:\n        return choose((('+') | ('.join(parts)+')) == 0, 1, 0)\n'
    source+='    return 0\n'
    return compose(source)

def main():
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args()
    doc=document(source_program(),'system_jobctl_observation');text=render_assembly(doc);path=ROOT/'examples/hia_bootstrap/system_jobctl_observation.hepta'
    if a.check:assert path.read_text()==text
    else:path.write_text(text)
    print(path.name,len(text),'functions',len(doc['functions']),'blocks',sum(len(f['blocks']) for f in doc['functions']),'ops',sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
