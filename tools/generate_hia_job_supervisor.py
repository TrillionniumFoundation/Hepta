"""Author the native MCP job owner from the shared HIA process lifecycle."""
import ast
from pathlib import Path
import struct
import subprocess
import tempfile

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_direct_load_plan import LinkerBuilder
from tools.generate_hia_native_filter import LINK_SOURCE
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_subprocess import SOURCE as PROCESS

ROOT = Path(__file__).resolve().parents[1]
PACKER_MAGIC = int.from_bytes(b'HIAJOPK1', 'little')
REQUEST_MAGIC = int.from_bytes(b'HIAJOB01', 'little')

# The first 128 KiB retain the generic process-state layout. Additional state
# belongs to job admission, immutable owner records, and durable publication.
JOB = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 262144:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 1000:
        return job_advance(s, o, w, phase, result)
    if get(w, 131072) == 0:
        if job_request(s) == 0 or admit(s, w) == 0:
            return 0
        return call(o, w, 1000, 107, 0, 0, 0, 0, 0, 0, 0)
    if phase == 19 and get(w, 131080) == 0:
        put(w, 131080, 1)
        put(w, 131088, phase)
        put(w, 131096, result)
        put(w, 131104, 2)
        return job_process_stat(o, w, get(w, 40))
    if phase == 45:
        if failed(result):
            return call(o, w, 999, 60, 74, 0, 0, 0, 0, 0, 0)
        return call(o, w, 1400, 228, 0, 131176, 0, 0, 0, 0, 12)
    return process_advance(s, o, w)

def job_request(s:readbuf) -> u64:
    if length(s) < 227 or length(s) > 65536 or uint(s, 0) != JOB_MAGIC:
        return 0
    directory = uint(s, 128)
    size = uint(s, 136)
    invocation = uint(s, 176)
    if directory < 3 or directory > 2147483647 or size == 0 or size > 128:
        return 0
    if uint(s, 120) != 0 or (invocation != 0 and invocation != 32):
        return 0
    if length(s) < 216 + size + 10:
        return 0
    index = 0
    while index < 6:
        if index != 4 and directory == uint(s, 24 + index * 8):
            return 0
        index = index + 1
    index = 0
    while index < size:
        c = byte(s, 216 + index)
        if (c < 48 or c > 57) and (c < 65 or c > 90) and (c < 97 or c > 122) and c != 45 and c != 46 and c != 95:
            return 0
        index = index + 1
    index = 0
    while index < 32:
        c = byte(s, 144 + index)
        if (c < 48 or c > 57) and (c < 97 or c > 102):
            return 0
        if invocation != 0:
            c = byte(s, 184 + index)
            if (c < 48 or c > 57) and (c < 97 or c > 102):
                return 0
        elif byte(s, 184 + index) != 0:
            return 0
        index = index + 1
    return 1

def job_advance(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 1000:
        put(w, 131192, result)
        return call(o, w, 1001, 5, uint(s, 128), 131584, 0, 0, 0, 0, 12)
    if phase == 1001:
        if failed(result) or getn(w, 131608, 4) & 61440 != 16384 or getn(w, 131612, 4) != get(w, 131192) or getn(w, 131608, 4) & 63 != 0:
            return 0
        at = text_lock(w, 131328)
        store(w, at, 0)
        return call(o, w, 1002, 257, uint(s, 128), 131328, 657474, 384, 0, 0, 12)
    if phase == 1002:
        if failed(result) or result < 3:
            return 0
        put(w, 131256, result)
        return call(o, w, 1003, 5, result, 131584, 0, 0, 0, 0, 12)
    if phase == 1003 or phase == 1005:
        if failed(result) or job_lock_valid(w) == 0:
            return 0
        if phase == 1003:
            put(w, 131264, get(w, 131584))
            put(w, 131272, get(w, 131592))
            return call(o, w, 1004, 73, get(w, 131256), 6, 0, 0, 0, 0, 0)
        if get(w, 131584) != get(w, 131264) or get(w, 131592) != get(w, 131272):
            return 0
        put(w, 131200, 0)
        return job_observe_marker(s, o, w)
    if phase == 1004:
        if failed(result):
            return 0
        return call(o, w, 1005, 262, uint(s, 128), 131328, 131584, 256, 0, 0, 60)
    if phase == 1006:
        if result != 18446744073709551614:
            return 0
        put(w, 131200, get(w, 131200) + 1)
        return job_observe_marker(s, o, w)
    if phase == 1007:
        if failed(result):
            return 0
        put(w, 131136, result)
        return call(o, w, 1008, 0, result, 131744, 38, 0, 0, 0, 12)
    if phase == 1008:
        if result != 37 or byte(w, 131780) != 10:
            return 0
        index = 0
        while index < 36:
            c = byte(w, 131744 + index)
            if index == 8 or index == 13 or index == 18 or index == 23:
                if c != 45:
                    return 0
            elif (c < 48 or c > 57) and (c < 97 or c > 102):
                return 0
            index = index + 1
        return call(o, w, 1009, 3, get(w, 131136), 0, 0, 0, 0, 0, 0)
    if phase == 1009:
        if failed(result):
            return 0
        return call(o, w, 1010, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1010:
        if result < 2 or result > 2147483647:
            return 0
        put(w, 456, result)
        put(w, 131104, 0)
        return job_process_stat(o, w, result)
    if phase >= 1100 and phase <= 1103:
        return job_identity(s, o, w, phase, result)
    if phase >= 1200 and phase <= 1205:
        return job_publish_effect(s, o, w, phase, result)
    if phase >= 1300 and phase <= 1302:
        return job_hash_effect(s, o, w, phase, result)
    if phase == 1400:
        if failed(result):
            return job_fail(o, w)
        job_terminal(s, w)
        put(w, 131104, 3)
        return job_publish(s, o, w)
    return 0

def job_lock_valid(w:mutbuf) -> u64:
    mode = getn(w, 131608, 4)
    return choose(mode & 61440 == 32768 and mode & 63 == 0 and getn(w, 131612, 4) == get(w, 131192) and get(w, 131600) == 1, 1, 0)

def job_observe_marker(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    index = get(w, 131200)
    if index == 10:
        at = text_boot(w, 131456)
        store(w, at, 0)
        return call(o, w, 1007, 257, 18446744073709551516, 131456, 655360, 0, 0, 0, 12)
    at = job_name(w, index // 2, 131328)
    if index & 1 != 0:
        at = text_tmp(w, at)
    store(w, at, 0)
    return call(o, w, 1006, 262, uint(s, 128), 131328, 131584, 256, 0, 0, 60)

def job_process_stat(o:mutbuf, w:mutbuf, pid:u64) -> u32:
    at = text_proc(w, 131456)
    at = job_decimal(w, at, pid)
    at = text_stat(w, at)
    store(w, at, 0)
    return call(o, w, 1100, 257, 18446744073709551516, 131456, 655360, 0, 0, 0, 12)

def job_identity(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if failed(result):
        return job_fail(o, w)
    if phase == 1100:
        put(w, 131136, result)
        return call(o, w, 1101, 0, result, 132096, 4096, 0, 0, 0, 12)
    if phase == 1101:
        if result == 0 or result >= 4096:
            return job_fail(o, w)
        put(w, 131144, result)
        return call(o, w, 1102, 3, get(w, 131136), 0, 0, 0, 0, 0, 0)
    if phase == 1102:
        if job_ticks(w) == 0:
            return job_fail(o, w)
        if get(w, 131104) == 0:
            return call(o, w, 1103, 228, 0, 131176, 0, 0, 0, 0, 12)
        at = text_child_open(w, 147456)
        at = job_identity_text(w, at)
        at = text_child_pid(w, at)
        at = job_decimal(w, at, get(w, 40))
        at = text_end(w, at)
        put(w, 131112, at - 147456)
        return job_publish(s, o, w)
    job_owner(s, w)
    return job_publish(s, o, w)

def job_ticks(w:mutbuf) -> u64:
    end = 132096 + get(w, 131144)
    at = 132096
    floor = 0
    while at + 1 < end:
        if byte(w, at) == 41 and byte(w, at + 1) == 32:
            floor = at + 2
        at = at + 1
    if floor == 0:
        return 0
    at = floor
    field = 0
    while field < 19:
        while at < end and byte(w, at) != 32:
            at = at + 1
        if at >= end:
            return 0
        at = at + 1
        field = field + 1
    first = at
    while at < end and byte(w, at) != 32 and byte(w, at) != 10:
        c = byte(w, at)
        if c < 48 or c > 57:
            return 0
        at = at + 1
    if at == first or at - first > 20 or byte(w, first) == 48:
        return 0
    put(w, 131152, first)
    put(w, 131160, at - first)
    return 1

def job_owner(s:readbuf, w:mutbuf) -> u64:
    at = text_owner_open(w, 147456)
    at = job_decimal(w, at, get(w, 131176) * 1000 + get(w, 131184) // 1000000)
    at = text_invocation(w, at)
    if uint(s, 176) == 0:
        at = text_null(w, at)
    else:
        at = text_quote(w, at)
        at = job_copy_source(s, w, 184, at, 32)
        at = text_quote(w, at)
    at = job_binding(s, w, at)
    at = text_owner_identity(w, at)
    at = job_identity_text(w, at)
    at = text_owner_pid(w, at)
    at = job_decimal(w, at, get(w, 456))
    at = text_owner_uid(w, at)
    at = job_decimal(w, at, get(w, 131192))
    at = text_end(w, at)
    put(w, 131112, at - 147456)
    return 0

def job_identity_text(w:mutbuf, at:u64) -> u64:
    at = job_copy(w, 131744, at, 36)
    store(w, at, 58)
    return job_copy(w, get(w, 131152), at + 1, get(w, 131160))

def job_publish(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = job_name(w, get(w, 131104), 131328)
    store(w, at, 0)
    at = job_name(w, get(w, 131104), 131392)
    at = text_tmp(w, at)
    store(w, at, 0)
    put(w, 131120, 0)
    return call(o, w, 1200, 257, uint(s, 128), 131392, 655553, 384, 0, 0, 12)

def job_publish_effect(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 1201 and result == 18446744073709551612:
        return job_write(s, o, w)
    if failed(result):
        return job_fail(o, w)
    if phase == 1200:
        put(w, 131128, result)
        return job_write(s, o, w)
    if phase == 1201:
        remain = get(w, 131112) - get(w, 131120)
        if result == 0 or result > remain:
            return job_fail(o, w)
        put(w, 131120, get(w, 131120) + result)
        if get(w, 131120) < get(w, 131112):
            return job_write(s, o, w)
        return call(o, w, 1202, 74, get(w, 131128), 0, 0, 0, 0, 0, 0)
    if phase == 1202:
        return call(o, w, 1203, 3, get(w, 131128), 0, 0, 0, 0, 0, 0)
    if phase == 1203:
        return call(o, w, 1204, 316, uint(s, 128), 131392, uint(s, 128), 131328, 1, 0, 204)
    if phase == 1204:
        return call(o, w, 1205, 74, uint(s, 128), 0, 0, 0, 0, 0, 0)
    role = get(w, 131104)
    if role == 0:
        put(w, 131104, 1)
        return job_publish(s, o, w)
    if role == 1:
        put(w, 131072, 1)
        put(w, 0, 0)
        put(w, 8, 0)
        return process_advance(s, o, w)
    if role == 2:
        put(w, 0, get(w, 131088))
        put(w, 8, get(w, 131096))
        return process_advance(s, o, w)
    if role == 3:
        store(w, 163840, 0)
        return job_sha(o, w, 1300, 1)
    return call(o, w, 999, 60, get(w, 131208), 0, 0, 0, 0, 0, 0)

def job_write(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    done = get(w, 131120)
    return call(o, w, 1201, 18, get(w, 131128), 147456 + done, get(w, 131112) - done, done, 0, 0, 12)

def job_fail(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 40) == 0:
        return 0
    if get(w, 448) != 0:
        return call(o, w, 999, 60, 74, 0, 0, 0, 0, 0, 0)
    put(w, 131216, 1)
    put(w, 32, 4)
    put(w, 440, 1)
    return end_group(o, w)

def job_hash_effect(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 1300:
        if result != 0:
            return job_fail(o, w)
        store(w, 163840, 1)
        job_copy(w, 147456, 163841, get(w, 131112))
        return job_sha(o, w, 1301, get(w, 131112) + 1)
    if phase == 1301:
        if result != 0:
            return job_fail(o, w)
        store(w, 163840, 2)
        return job_sha(o, w, 1302, 1)
    if result != 32:
        return job_fail(o, w)
    at = text_witness_open(w, 147456)
    index = 0
    while index < 32:
        value = byte(w, 180224 + index)
        high = value >> 4
        low = value & 15
        store(w, at, choose(high < 10, high + 48, high + 87))
        store(w, at + 1, choose(low < 10, low + 48, low + 87))
        at = at + 2
        index = index + 1
    at = text_quote(w, at)
    at = job_binding(s, w, at)
    at = text_protocol(w, at)
    at = text_end(w, at)
    put(w, 131112, at - 147456)
    put(w, 131104, 4)
    return job_publish(s, o, w)

def job_sha(o:mutbuf, w:mutbuf, phase:u64, size:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, 163840)
    put(o, 8, size)
    put(o, 16, 180224)
    put(o, 24, 182272)
    return 3

def job_terminal(s:readbuf, w:mutbuf) -> u64:
    unknown = get(w, 32) == 4 or get(w, 440) != 0 or get(w, 131216) != 0
    complete = get(w, 4192) != 0 and unknown == False
    durable = complete and get(w, 4200) != 0
    code = get(w, 4104)
    terminal = choose(get(w, 32) == 1, 124, code)
    terminal = choose(unknown, 125, terminal)
    status = terminal
    if status == 0 and durable == False:
        status = 74
    if status > 255:
        status = 1
    put(w, 131208, status)
    at = text_owner_open(w, 147456)
    at = job_decimal(w, at, get(w, 131176) * 1000 + get(w, 131184) // 1000000)
    at = text_cancelled(w, at)
    at = job_bool(w, at, get(w, 32) == 2)
    at = text_exit_code(w, at)
    at = job_signed(w, at, terminal)
    at = job_binding(s, w, at)
    at = text_log_bytes(w, at)
    at = job_decimal(w, at, get(w, 280))
    at = text_stored(w, at)
    at = job_decimal(w, at, get(w, 288))
    at = text_stdout_bytes(w, at)
    at = job_decimal(w, at, get(w, 256))
    at = text_stored(w, at)
    at = job_decimal(w, at, get(w, 264))
    at = text_log_eof(w, at)
    at = job_bool(w, at, get(w, 312) != 0)
    at = text_stdout(w, at)
    at = job_bool(w, at, get(w, 304) != 0)
    at = text_log_errors(w, at)
    at = job_error(w, at, get(w, 296))
    at = text_stdout(w, at)
    at = job_error(w, at, get(w, 272))
    at = text_log_synced(w, at)
    at = job_bool(w, at, get(w, 344) & 2 != 0)
    at = text_stdout(w, at)
    at = job_bool(w, at, get(w, 344) & 1 != 0)
    at = text_log_truncated(w, at)
    at = job_bool(w, at, get(w, 280) != get(w, 288))
    at = text_stdout(w, at)
    at = job_bool(w, at, get(w, 256) != get(w, 264))
    at = text_output_complete(w, at)
    at = job_bool(w, at, complete)
    at = text_output_durable(w, at)
    at = job_bool(w, at, durable)
    at = text_protocol(w, at)
    at = text_timed_out(w, at)
    at = job_bool(w, at, get(w, 32) == 1)
    if get(w, 432) != 0:
        at = text_exec_error(w, at)
        at = job_decimal(w, at, get(w, 432))
    if unknown:
        at = text_unknown(w, at)
        at = text_child_spawned(w, at)
        at = job_bool(w, at, get(w, 40) != 0)
        at = text_child_pid_field(w, at)
        at = job_decimal(w, at, get(w, 40))
        at = text_child_reaped(w, at)
        at = job_bool(w, at, get(w, 448) != 0)
        at = text_child_exit(w, at)
        at = job_signed(w, at, code)
    at = text_end(w, at)
    put(w, 131112, at - 147456)
    return 0

def job_binding(s:readbuf, w:mutbuf, at:u64) -> u64:
    at = text_job_id(w, at)
    at = job_copy_source(s, w, 216, at, uint(s, 136))
    at = text_nonce(w, at)
    at = job_copy_source(s, w, 144, at, 32)
    return text_quote(w, at)

def job_name(w:mutbuf, role:u64, at:u64) -> u64:
    if role == 0:
        return text_intent_name(w, at)
    if role == 1:
        return text_started_name(w, at)
    if role == 2:
        return text_child_name(w, at)
    if role == 3:
        return text_exit_name(w, at)
    return text_witness_name(w, at)

def job_copy_source(s:readbuf, w:mutbuf, source:u64, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, at + index, byte(s, source + index))
        index = index + 1
    return at + size

def job_copy(w:mutbuf, source:u64, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, at + index, byte(w, source + index))
        index = index + 1
    return at + size

def job_decimal(w:mutbuf, at:u64, value:u64) -> u64:
    if value == 0:
        store(w, at, 48)
        return at + 1
    size = 0
    while value != 0:
        store(w, 140000 + size, 48 + value % 10)
        value = value // 10
        size = size + 1
    while size != 0:
        size = size - 1
        store(w, at, byte(w, 140000 + size))
        at = at + 1
    return at

def job_signed(w:mutbuf, at:u64, value:u64) -> u64:
    if value >> 63 != 0:
        store(w, at, 45)
        at = at + 1
        value = 0 - value
    return job_decimal(w, at, value)

def job_bool(w:mutbuf, at:u64, value:bool) -> u64:
    if value:
        return text_true(w, at)
    return text_false(w, at)

def job_error(w:mutbuf, at:u64, value:u64) -> u64:
    if value == 0:
        return text_null(w, at)
    at = text_errno(w, at)
    at = job_decimal(w, at, value)
    return text_quote(w, at)
'''

TEXT = {
    'lock': 'owner.lock', 'boot': '/proc/sys/kernel/random/boot_id',
    'proc': '/proc/', 'stat': '/stat', 'tmp': '.tmp',
    'intent_name': 'owner-intent.json', 'started_name': 'started.json',
    'child_name': 'child.json', 'exit_name': 'exit.json', 'witness_name': 'exit.witness.json',
    'owner_open': '{"at_unix_ms":', 'invocation': ',"invocation_id":',
    'owner_identity': ',"supervisor_identity":{"kind":"proc_start_ticks","value":"',
    'owner_pid': '"},"supervisor_pid":', 'owner_uid': ',"supervisor_uid":',
    'child_open': '{"identity":{"kind":"proc_start_ticks","value":"',
    'child_pid': '"},"pid":', 'end': '}\n', 'null': 'null', 'quote': '"',
    'job_id': ',"job_id":"', 'nonce': '","launch_nonce":"',
    'witness_open': '{"exit_sha256":"', 'protocol': ',"terminal_publication_protocol":1',
    'cancelled': ',"cancelled":', 'exit_code': ',"exit_code":',
    'log_bytes': ',"log_bytes":{"stderr":{"seen":', 'stored': ',"stored":',
    'stdout_bytes': '},"stdout":{"seen":',
    'log_eof': '}},"log_eof":{"stderr":', 'stdout': ',"stdout":',
    'log_errors': '},"log_errors":{"stderr":', 'errno': '"errno ',
    'log_synced': '},"log_synced":{"stderr":',
    'log_truncated': '},"log_truncated":{"stderr":',
    'output_complete': '},"output_complete":', 'output_durable': ',"output_durable":',
    'timed_out': ',"timed_out":', 'true': 'true', 'false': 'false',
    'exec_error': ',"launch_error":"native workload exec failed","exec_errno":',
    'unknown': ',"supervisor_error":"native workload supervision incomplete","effect_outcome":"unknown","status_authoritative":false,"automatic_retry":false',
    'child_spawned': ',"child_spawned":', 'child_pid_field': ',"child_pid":',
    'child_reaped': ',"child_reaped":', 'child_exit': ',"child_exit_code":',
}


def policy_source():
    common = PROCESS.replace('def advance(', 'def process_advance(', 1)
    common = common.replace('length(w) != 131072', 'length(w) != 262144')
    common = common.replace('size < 138', 'size < 227')
    common = common.replace('3544405840977021256', str(REQUEST_MAGIC))
    common = common.replace('    at = 128\n', '    at = 216 + uint(s, 136)\n')
    common = common.replace('if parent < 2 or parent > 2147483647 or uint(s, 16) == 0:',
                            'if (parent != 0 and (parent < 2 or parent > 2147483647)) or uint(s, 16) == 0:')
    common = common.replace('if result != uint(s, 8):', 'if uint(s, 8) != 0 and result != uint(s, 8):')
    common = common.replace('return call(o, w, 10, 157, 1, 15, 0, 0, 0, 0, 0)',
                            'return call(o, w, 10, 157, 1, choose(uint(s, 8) == 0, 0, 15), 0, 0, 0, 0, 0)')
    common = common.replace('selected_fd(s, ', 'selected_fd(s, w, ')
    common = common.replace('def selected_fd(s:readbuf, index:u64)', 'def selected_fd(s:readbuf, w:mutbuf, index:u64)')
    common = common.replace('return uint(s, 120)', 'return get(w, 131256)')
    common = common.replace('uint(s, 120)', 'get(w, 131256)')
    source = JOB.replace('JOB_MAGIC', str(REQUEST_MAGIC)) + common
    for name, value in TEXT.items():
        raw = value.encode()
        source += f'\ndef text_{name}(w:mutbuf, at:u64) -> u64:\n'
        for i, byte in enumerate(raw):
            source += f'    store(w, at + {i}, {byte})\n'
        source += f'    return at + {len(raw)}\n'
    return source


def template():
    with tempfile.TemporaryDirectory(prefix='hia-job-supervisor-author-') as tmp:
        obj, raw = Path(tmp)/'adapter.o', Path(tmp)/'adapter.bin'
        subprocess.run(['as', '--64', str(ROOT/'tools/hia_job_supervisor_syscalls.S'), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)], check=True, capture_output=True)
        symbols = {name: int(address, 16) for address, _, name in (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('job-supervisor adapter has unresolved relocations')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code, {name: 176 + symbols[name] for name in ('job_supervisor_policy_hole', 'job_supervisor_sha_hole')}


def packer_source():
    prefix, holes = template()
    code = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 26 or uint(s, 0, 8) != {PACKER_MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    sha = uint(s, 16, 8)
    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576:
        return 4294967295
    if length(s) != 24 + policy + sha:
        return 4294967295
    size = {len(prefix)} + policy + sha
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at+8]
        code += f'    write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
    code += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, at in holes.items():
        target = str(len(prefix)) + (' + policy' if name.endswith('sha_hole') else '')
        code += f'    write(o, {at}, {target} - {at+4}, 4)\n'
    code += f'    copy_bytes(s, o, 24, {len(prefix)}, policy + sha)\n    return size\n'
    return code + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def document(source, module):
    nodes = ast.parse(source).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(arg) for arg in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': module, 'functions': functions})


def main():
    for module, source in (('job_supervisor', policy_source()), ('job_supervisor_packer', packer_source())):
        path = ROOT/'examples/hia_bootstrap'/(module+'.hepta')
        path.write_text(render_assembly(document(source, module)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
