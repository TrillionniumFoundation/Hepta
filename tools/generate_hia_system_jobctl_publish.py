"""Author durable Exit and matching witness publication entirely in HIA."""
from __future__ import annotations
import argparse
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_system_jobctl_supervisor_common import helpers,literals,substitute
ROOT=Path(__file__).resolve().parents[1]

POLICY=r'''
def publish(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 2500:
        put(w, PUB_FD, NONE)
        put(w, PUB_PARENT, NONE)
        put(w, PUB_CREATED, 0)
        if get(w, PUB_TIME_READY) == 1:
            put(w, 8, 0)
            put(w, 0, 2501)
            return 8
        return call(o, w, 2501, 228, 0, PUB_TIME, 0, 0, 0, 0, 12)
    if phase == 2501:
        if result != 0:
            return 0
        milliseconds(w)
        put(w, PUB_COMPLETE, 0)
        put(w, PUB_DURABLE, 0)
        if get(w, SUP_INTERACTIVE) == 0 and get(w, SPAWN_ERROR) == 0:
            complete = complete_stream(w, 0) & complete_stream(w, 1)
            put(w, PUB_COMPLETE, complete)
            put(w, PUB_DURABLE, complete & get(w, CAP_STREAMS + 88) & get(w, CAP_STREAMS + 256 + 88))
        return call(o, w, 2502, 257, NEG100, SUP_STATE, 524288, 0, 0, 0, 12)
    if phase == 2502:
        if result == NEG4:
            return call(o, w, 2502, 257, NEG100, SUP_STATE, 524288, 0, 0, 0, 12)
        if failed(result):
            return 0
        put(w, PUB_PARENT, result)
        size = render_exit(w)
        if size == NONE or size > 1048576:
            return 0
        put(w, PUB_EXIT_SIZE, size)
        put(w, PUB_STAGE, 0)
        return call(o, w, 2503, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 2503:
        if result == 0 or failed(result):
            return 0
        put(w, PUB_PID, result)
        return begin_atomic(o, w)
    if phase == 2510:
        if result == NEG4:
            return call(o, w, 2510, 257, NEG100, PUB_TEMP, 524481, 384, 0, 0, 12)
        if failed(result):
            return 0
        put(w, PUB_CREATED, 1)
        put(w, PUB_FD, result)
        put(w, PUB_USED, 0)
        return write_bytes(o, w)
    if phase == 2511:
        if result == NEG4:
            return write_bytes(o, w)
        if result == 0 or failed(result) or result > get(w, PUB_SIZE) - get(w, PUB_USED):
            return fail_atomic(o, w)
        put(w, PUB_USED, get(w, PUB_USED) + result)
        return write_bytes(o, w)
    if phase == 2512:
        if result == NEG4:
            return call(o, w, 2512, 74, get(w, PUB_FD), 0, 0, 0, 0, 0, 0)
        if result != 0:
            return fail_atomic(o, w)
        return call(o, w, 2513, 82, PUB_TEMP, PUB_PATH, 0, 0, 0, 0, 15)
    if phase == 2513:
        if result != 0:
            return fail_atomic(o, w)
        return call(o, w, 2514, 74, get(w, PUB_PARENT), 0, 0, 0, 0, 0, 0)
    if phase == 2514:
        if result == NEG4:
            return call(o, w, 2514, 74, get(w, PUB_PARENT), 0, 0, 0, 0, 0, 0)
        if result != 0:
            return fail_atomic(o, w)
        put(w, PUB_CREATED, 0)
        value = get(w, PUB_FD)
        put(w, PUB_FD, NONE)
        return call(o, w, 2515, 3, value, 0, 0, 0, 0, 0, 0)
    if phase == 2515:
        if get(w, PUB_STAGE) == 0:
            return hash_exit(o, w, 2520, 0, 1)
        value = get(w, PUB_PARENT)
        put(w, PUB_PARENT, NONE)
        return call(o, w, 2524, 3, value, 0, 0, 0, 0, 0, 0)
    if phase == 2520:
        if result != 0:
            return 0
        return hash_exit(o, w, 2521, 1, get(w, PUB_EXIT_SIZE) + 1)
    if phase == 2521:
        if result != 0:
            return 0
        return hash_exit(o, w, 2522, 2, 1)
    if phase == 2522:
        if result != 32:
            return 0
        size = render_witness(w)
        if size == NONE:
            return 0
        put(w, PUB_WITNESS_SIZE, size)
        put(w, PUB_STAGE, 1)
        return begin_atomic(o, w)
    if phase == 2524:
        if get(w, SUP_EXIT_CODE) == 0 and get(w, SUP_INTERACTIVE) == 0:
            if get(w, PUB_COMPLETE) != 1 or get(w, PUB_DURABLE) != 1:
                put(w, SUP_RETURN_ERROR, 1)
        put(w, 0, 2070)
        return 8
    if phase == 2580:
        if get(w, PUB_FD) != NONE:
            value = get(w, PUB_FD)
            put(w, PUB_FD, NONE)
            return call(o, w, 2581, 3, value, 0, 0, 0, 0, 0, 0)
        return 0
    if phase == 2581:
        return 0
    return 0

def begin_atomic(o:mutbuf, w:mutbuf) -> u32:
    at = state_prefix(w, PUB_PATH)
    if get(w, PUB_STAGE) == 0:
        at = text_exit_name(w, at)
        put(w, PUB_DATA, PUB_EXIT)
        put(w, PUB_SIZE, get(w, PUB_EXIT_SIZE))
    else:
        at = text_witness_name(w, at)
        put(w, PUB_DATA, PUB_WITNESS)
        put(w, PUB_SIZE, get(w, PUB_WITNESS_SIZE))
    store(w, at, 0)
    at = text_temporary(w, state_prefix(w, PUB_TEMP))
    at = decimal(w, at, get(w, PUB_PID))
    store(w, at, 0)
    put(w, PUB_CREATED, 0)
    return call(o, w, 2510, 257, NEG100, PUB_TEMP, 524481, 384, 0, 0, 12)

def state_prefix(w:mutbuf, target:u64) -> u64:
    size = get(w, SUP_STATE_SIZE)
    copy(w, target, SUP_STATE, size)
    at = target + size
    if size != 0 and byte(w, at - 1) != 47:
        store(w, at, 47)
        at = at + 1
    return at

def write_bytes(o:mutbuf, w:mutbuf) -> u32:
    if get(w, PUB_USED) == get(w, PUB_SIZE):
        return call(o, w, 2512, 74, get(w, PUB_FD), 0, 0, 0, 0, 0, 0)
    return call(o, w, 2511, 1, get(w, PUB_FD), get(w, PUB_DATA) + get(w, PUB_USED), get(w, PUB_SIZE) - get(w, PUB_USED), 0, 0, 0, 12)

def fail_atomic(o:mutbuf, w:mutbuf) -> u32:
    if get(w, PUB_CREATED) != 0:
        return call(o, w, 2580, 263, NEG100, PUB_TEMP, 0, 0, 0, 0, 12)
    return 0

def hash_exit(o:mutbuf, w:mutbuf, next:u64, mode:u64, size:u64) -> u32:
    store(w, PUB_EXIT - 1, mode)
    put(o, 0, PUB_EXIT - 1)
    put(o, 8, size)
    put(o, 16, PUB_HASH_OUT)
    put(o, 24, PUB_SHA_STATE)
    put(w, 0, next)
    return 10

def milliseconds(w:mutbuf) -> u64:
    seconds = get(w, PUB_TIME)
    nanos = get(w, PUB_TIME + 8)
    low = 0
    high = 0
    if seconds >> 63 == 0:
        upper = (seconds >> 32) * 1000
        bottom = (seconds & 4294967295) * 1000 + nanos // 1000000
        low = (upper << 32) + bottom
        high = (upper >> 32) + choose(low < bottom, 1, 0)
    put(w, PUB_MS_LOW, low)
    put(w, PUB_MS_HIGH, high)
    return 0

def complete_stream(w:mutbuf, index:u64) -> u64:
    base = CAP_STREAMS + index * 256
    complete = get(w, base + 16) == 1 and get(w, base + 24) == 0 and get(w, base + 32) == 0
    complete = complete and get(w, base + 48) == 0 and get(w, base + 64) == 0 and get(w, base + 80) == 0
    complete = complete and get(w, base) == get(w, base + 8)
    return choose(complete, 1, 0)

def render_exit(w:mutbuf) -> u64:
    at = text_job(w, PUB_EXIT)
    at = quote(w, at, SUP_JOB, get(w, SUP_JOB_SIZE))
    if at == NONE:
        return NONE
    at = text_nonce(w, at)
    at = quote(w, at, get(w, SPEC_FIELDS + 16), get(w, SPEC_FIELDS + 24))
    if at == NONE:
        return NONE
    at = decimal(w, text_exit_code(w, at), get(w, SUP_EXIT_CODE))
    at = boolean(w, text_timed_out(w, at), get(w, SUP_TIMED_OUT))
    at = boolean(w, text_cancelled(w, at), get(w, SUP_CANCELLED))
    at = decimal128(w, text_timestamp(w, at), get(w, PUB_MS_LOW), get(w, PUB_MS_HIGH))
    at = protocol(w, text_protocol(w, at))
    at = text_complete(w, at)
    if get(w, SUP_INTERACTIVE) == 1:
        at = text_null(w, at)
    else:
        at = boolean(w, at, get(w, PUB_COMPLETE))
    at = text_durable(w, at)
    if get(w, SUP_INTERACTIVE) == 1:
        at = text_null(w, at)
    else:
        at = boolean(w, at, get(w, PUB_DURABLE))
    at = text_capture(w, at)
    if get(w, SUP_INTERACTIVE) == 1:
        at = text_null(w, at)
    else:
        at = text_stdout_capture(w, at)
        at = render_stream(w, at, 0)
        if at == NONE:
            return NONE
        at = text_stderr_capture(w, at)
        at = render_stream(w, at, 1)
        if at == NONE:
            return NONE
        store(w, at, 125)
        at = at + 1
    size = get(w, SUP_CLEANUP_SIZE)
    if size != 0:
        if size > 1048576 or at > PUB_EXIT + 1048576 or size > PUB_EXIT + 1048576 - at:
            return NONE
        at = text_cleanup(w, at)
        copy(w, at, get(w, SUP_CLEANUP), size)
        at = at + size
    if at > PUB_EXIT + 1048574:
        return NONE
    store(w, at, 125)
    store(w, at + 1, 10)
    return at + 2 - PUB_EXIT

def render_stream(w:mutbuf, at:u64, index:u64) -> u64:
    base = CAP_STREAMS + index * 256
    if get(w, SPAWN_ERROR) != 0:
        at = text_not_started(w, at)
        end = text_unavailable(w, SUP_TEMP)
        size = get(w, SUP_ERROR_SIZE)
        if size > 1048576:
            return NONE
        copy(w, end, get(w, SUP_ERROR), size)
        at = quote(w, at, SUP_TEMP, end + size - SUP_TEMP)
        if at == NONE:
            return NONE
        return text_not_started_end(w, at)
    at = decimal(w, text_seen(w, at), get(w, base))
    at = decimal(w, text_saved(w, at), get(w, base + 8))
    at = boolean(w, text_eof(w, at), get(w, base + 16))
    at = boolean(w, text_truncated(w, at), get(w, base + 24))
    at = boolean(w, text_drain(w, at), get(w, base + 32))
    at = maybe_text(w, text_read_error(w, at), get(w, base + 40), get(w, base + 48))
    if at == NONE:
        return NONE
    at = maybe_text(w, text_write_error(w, at), get(w, base + 56), get(w, base + 64))
    if at == NONE:
        return NONE
    at = maybe_text(w, text_sync_error(w, at), get(w, base + 72), get(w, base + 80))
    if at == NONE:
        return NONE
    at = boolean(w, text_synced(w, at), get(w, base + 88))
    store(w, at, 125)
    return at + 1

def render_witness(w:mutbuf) -> u64:
    at = text_job(w, PUB_WITNESS)
    at = quote(w, at, SUP_JOB, get(w, SUP_JOB_SIZE))
    if at == NONE:
        return NONE
    at = text_nonce(w, at)
    at = quote(w, at, get(w, SPEC_FIELDS + 16), get(w, SPEC_FIELDS + 24))
    if at == NONE:
        return NONE
    at = protocol(w, text_protocol(w, at))
    at = text_digest(w, at)
    index = 0
    while index < 32:
        value = byte(w, PUB_HASH_OUT + index)
        store(w, at + index * 2, hexadecimal(value >> 4))
        store(w, at + index * 2 + 1, hexadecimal(value & 15))
        index = index + 1
    at = at + 64
    store(w, at, 34)
    store(w, at + 1, 125)
    store(w, at + 2, 10)
    return at + 3 - PUB_WITNESS

def protocol(w:mutbuf, at:u64) -> u64:
    if get(w, SUP_PROTOCOL) == 1:
        return text_captured(w, at)
    return text_pty(w, at)

def boolean(w:mutbuf, at:u64, value:u64) -> u64:
    if value != 0:
        return text_true(w, at)
    return text_false(w, at)

def maybe_text(w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    if size == 0:
        return text_null(w, at)
    return quote(w, at, source, size)
'''

def source_program():
    text={'exit_name':'exit.json','witness_name':'exit.witness','temporary':'exit.tmp-',
      'job':'{"job_id":','nonce':',"nonce":','exit_code':',"exit_code":','timed_out':',"timed_out":','cancelled':',"cancelled":','timestamp':',"at_unix_ms":','protocol':',"terminal_protocol":','complete':',"output_complete":','durable':',"output_durable":','capture':',"capture":','cleanup':',"scratch_cleanup":',
      'stdout_capture':'{"stdout":','stderr_capture':',"stderr":','captured':'"captured_v1"','pty':'"pty_v1"','true':'true','false':'false','null':'null',
      'seen':'{"seen":','saved':',"saved":','eof':',"eof":','truncated':',"truncated":','drain':',"drain_timeout":','read_error':',"read_error":','write_error':',"write_error":','sync_error':',"sync_error":','synced':',"synced":',
      'digest':',"exit_sha256":"','unavailable':'capture unavailable before workload spawn: ',
      'not_started':'{"seen":0,"saved":0,"eof":false,"truncated":false,"drain_timeout":false,"read_error":',
      'not_started_end':',"write_error":null,"sync_error":null,"synced":false}'}
    return substitute(POLICY+'\n'+helpers(['get','put','putn','call','failed','copy','quote','hexadecimal','decimal','decimal128'])+literals(text))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    doc=document(source_program(),'system_jobctl_publish');text=render_assembly(doc);p=ROOT/'examples/hia_bootstrap/system_jobctl_publish.hepta'
    if args.check:assert p.read_text()==text
    else:p.write_text(text)
    print(p.name,len(doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
