"""Author original-child supervision and bounded output capture in HIA.

The leader is never signalled after its observed reap. Each output turn drains
at most eight 8 KiB reads, retains 16 MiB, and the 200 ms terminal drain deadline
never renews. Both real log fsyncs finish before terminal publication.
"""
from __future__ import annotations
import argparse
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_system_jobctl_errors import error_source
from tools.generate_hia_system_jobctl_supervisor_common import helpers,literals,substitute
ROOT=Path(__file__).resolve().parents[1]

POLICY=r'''
def capture(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 2460:
        return failure_cleanup(o, w, phase, result)
    if phase >= 2400:
        return finish_capture(o, w, phase, result)
    if phase >= 2340:
        return poll_capture(o, w, phase, result)
    if phase == 2300:
        index = 0
        while index < 2:
            offset = 0
            while offset < 96:
                put(w, CAP_STREAMS + index * 256 + offset, 0)
                offset = offset + 8
            index = index + 1
        put(w, SUP_REAPED, 0)
        put(w, SUP_FINISHED, 0)
        put(w, SUP_TIMED_OUT, 0)
        put(w, SUP_CANCELLED, 0)
        put(w, SUP_GROUP_STOPPED, 0)
        put(w, SUP_ERROR_SIZE, 0)
        return clock(o, w, 2301)
    if phase == 2301:
        if result != 0:
            return capture_failure(o, w, result, 0)
        put(w, SUP_BEGIN_SECONDS, get(w, CAP_TIME))
        put(w, SUP_BEGIN_NANOS, get(w, CAP_TIME + 8))
        return observe(o, w)
    if phase == 2304:
        if get(w, 62144) != 0:
            return scratch_failure(o, w)
        put(w, SUP_CANCELLED, get(w, SUP_CANCELLED) | choose(get(w, SUP_STOP) != 0, 1, 0))
        if get(w, 62152) == 1:
            return stop_group(w)
        return clock(o, w, 2306)
    if phase == 2305 or phase == 2308:
        if result == get(w, SUP_PID):
            return reaped(o, w)
        if result != 0:
            return capture_failure(o, w, result, 0)
        if phase == 2308:
            return call(o, w, 2310, 62, get(w, SUP_PID), 9, 0, 0, 0, 0, 0)
        put(w, SUP_CANCELLED, get(w, SUP_CANCELLED) | choose(get(w, SUP_STOP) != 0, 1, 0))
        return clock(o, w, 2306)
    if phase == 2306:
        if result != 0:
            return capture_failure(o, w, result, 0)
        put(w, SUP_TIMED_OUT, timeout_elapsed(w))
        if get(w, SUP_CANCELLED) != 0 or get(w, SUP_TIMED_OUT) != 0:
            if get(w, SUP_SCRATCH) == 1:
                return stop_group(w)
            return wait_child(o, w, 2308, 1)
        return after_observation(o, w)
    if phase == 2310:
        if result != 0:
            put(w, CAP_ERROR_CODE, result)
            return wait_child(o, w, 2309, 1)
        return wait_child(o, w, 2311, 0)
    if phase == 2309:
        if result == get(w, SUP_PID):
            return reaped(o, w)
        if failed(result):
            return capture_failure(o, w, result, 0)
        return capture_failure(o, w, get(w, CAP_ERROR_CODE), 0)
    if phase == 2311 or phase == 2321:
        if result == NEG4 and phase == 2311:
            return wait_child(o, w, phase, 0)
        if result != get(w, SUP_PID):
            if result == 0 and phase == 2321:
                return capture_failure(o, w, 0, 1)
            return capture_failure(o, w, result, 0)
        if phase == 2321:
            put(w, SUP_GROUP_STOPPED, 1)
        return reaped(o, w)
    if phase == 2320:
        if get(w, 62144) != 0:
            return scratch_failure(o, w)
        return wait_child(o, w, 2321, 1)
    if phase == 2322:
        if result != 0:
            return capture_failure(o, w, result, 0)
        seconds = get(w, CAP_TIME)
        nanos = get(w, CAP_TIME + 8) + 200000000
        if nanos >= 1000000000:
            seconds = seconds + 1
            nanos = nanos - 1000000000
        put(w, SUP_DRAIN_SECONDS, seconds)
        put(w, SUP_DRAIN_NANOS, nanos)
        return after_observation(o, w)
    if phase == 2323:
        if result != 0:
            return capture_failure(o, w, result, 0)
        seconds = get(w, CAP_TIME)
        nanos = get(w, CAP_TIME + 8)
        deadline_seconds = get(w, SUP_DRAIN_SECONDS)
        deadline_nanos = get(w, SUP_DRAIN_NANOS)
        if seconds > deadline_seconds or (seconds == deadline_seconds and nanos >= deadline_nanos):
            put(w, CAP_STREAM, 0)
            return expire_streams(o, w)
        remaining = 20000000
        if deadline_seconds == seconds:
            remaining = deadline_nanos - nanos
        elif deadline_seconds == seconds + 1 and nanos > deadline_nanos:
            remaining = 1000000000 - nanos + deadline_nanos
        if remaining > 20000000:
            remaining = 20000000
        put(w, CAP_WAIT_MS, remaining // 1000000)
        return poll_start(o, w)
    if phase == 2324:
        if result == NEG4:
            put(w, CAP_TIME, get(w, CAP_REMAINING))
            put(w, CAP_TIME + 8, get(w, CAP_REMAINING + 8))
            return call(o, w, 2324, 35, CAP_TIME, CAP_REMAINING, 0, 0, 0, 0, 15)
        return observe(o, w)
    if phase == 2325:
        return expire_streams(o, w)
    return 0

def observe(o:mutbuf, w:mutbuf) -> u32:
    if get(w, SUP_FINISHED) != 0:
        return after_observation(o, w)
    if get(w, SUP_SCRATCH) == 1:
        put(w, 62000, 1)
        put(w, 62008, 2304)
        put(w, 62128, get(w, SUP_PID))
        put(w, 0, 3000)
        return 8
    return wait_child(o, w, 2305, 1)

def stop_group(w:mutbuf) -> u32:
    put(w, 62000, 2)
    put(w, 62008, 2320)
    put(w, 62128, get(w, SUP_PID))
    put(w, 0, 3000)
    return 8

def reaped(o:mutbuf, w:mutbuf) -> u32:
    put(w, SUP_REAPED, 1)
    put(w, SUP_FINISHED, 1)
    put(w, SUP_STATUS, getn(w, CAP_WAIT_STATUS, 4))
    return clock(o, w, 2322)

def after_observation(o:mutbuf, w:mutbuf) -> u32:
    if get(w, SUP_FINISHED) != 0:
        if get(w, SUP_INTERACTIVE) == 1 or (capture_fd(w, 2) == NONE and capture_fd(w, 4) == NONE):
            return finish_start(o, w)
        return clock(o, w, 2323)
    put(w, CAP_WAIT_MS, 20)
    return poll_start(o, w)

def timeout_elapsed(w:mutbuf) -> u64:
    seconds = get(w, CAP_TIME)
    nanos = get(w, CAP_TIME + 8)
    first_seconds = get(w, SUP_BEGIN_SECONDS)
    first_nanos = get(w, SUP_BEGIN_NANOS)
    if seconds < first_seconds or (seconds == first_seconds and nanos < first_nanos):
        return choose(get(w, SUP_TIMEOUT) == 0, 1, 0)
    elapsed = seconds - first_seconds
    if nanos < first_nanos:
        elapsed = elapsed - 1
    return choose(elapsed >= get(w, SUP_TIMEOUT), 1, 0)

def poll_start(o:mutbuf, w:mutbuf) -> u32:
    if get(w, SUP_INTERACTIVE) == 1:
        put(w, CAP_TIME, 0)
        put(w, CAP_TIME + 8, get(w, CAP_WAIT_MS) * 1000000)
        return call(o, w, 2324, 35, CAP_TIME, CAP_REMAINING, 0, 0, 0, 0, 15)
    index = 0
    while index < 2:
        at = CAP_POLL + index * 8
        putn(w, at, capture_fd(w, 2 + index * 2), 4)
        putn(w, at + 4, 1, 2)
        putn(w, at + 6, 0, 2)
        index = index + 1
    return call(o, w, 2340, 7, CAP_POLL, 2, get(w, CAP_WAIT_MS), 0, 0, 0, 3)

def poll_capture(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 2340:
        if result == NEG4:
            return observe(o, w)
        put(w, CAP_STREAM, 0)
        if failed(result):
            put(w, CAP_ERROR_CODE, result)
            return failed_poll_stream(o, w)
        return ready_stream(o, w)
    if phase == 2341:
        return failed_poll_stream(o, w)
    if phase == 2342:
        put(w, CAP_STREAM, get(w, CAP_STREAM) + 1)
        return ready_stream(o, w)
    if phase == 2343:
        base = stream_base(w)
        if result == NEG4:
            return next_read(o, w)
        if result == NEG11:
            put(w, CAP_STREAM, get(w, CAP_STREAM) + 1)
            return ready_stream(o, w)
        if result == 0:
            put(w, base + 16, 1)
            return close_reader(o, w, 2342)
        if failed(result) or result > 8192:
            stream_error(w, 0, result, 0)
            return close_reader(o, w, 2342)
        seen = get(w, base)
        if result > NONE - seen:
            stream_error(w, 0, 0, 3)
            return close_reader(o, w, 2342)
        seen = seen + result
        put(w, base, seen)
        if seen > 16777216:
            put(w, base + 24, 1)
        keep = 0
        if get(w, base + 64) == 0:
            keep = 16777216 - get(w, base + 8)
            if keep > result:
                keep = result
        put(w, CAP_KEEP, keep)
        put(w, CAP_WRITTEN, 0)
        return write_kept(o, w)
    if phase == 2344:
        if result == NEG4:
            return write_kept(o, w)
        if result == 0 or failed(result) or result > get(w, CAP_KEEP) - get(w, CAP_WRITTEN):
            stream_error(w, 1, result, choose(result == 0, 4, 0))
            return next_read(o, w)
        put(w, CAP_WRITTEN, get(w, CAP_WRITTEN) + result)
        base = stream_base(w)
        put(w, base + 8, get(w, base + 8) + result)
        return write_kept(o, w)
    return 0

def ready_stream(o:mutbuf, w:mutbuf) -> u32:
    while get(w, CAP_STREAM) < 2:
        index = get(w, CAP_STREAM)
        events = getn(w, CAP_POLL + index * 8 + 6, 2)
        if capture_fd(w, 2 + index * 2) != NONE:
            if events & 32 != 0:
                stream_error(w, 0, 0, 2)
                return close_reader(o, w, 2342)
            if events & 25 != 0:
                put(w, CAP_TURN, 0)
                return next_read(o, w)
        put(w, CAP_STREAM, index + 1)
    return observe(o, w)

def next_read(o:mutbuf, w:mutbuf) -> u32:
    if get(w, CAP_TURN) == 8:
        put(w, CAP_STREAM, get(w, CAP_STREAM) + 1)
        return ready_stream(o, w)
    put(w, CAP_TURN, get(w, CAP_TURN) + 1)
    return call(o, w, 2343, 0, capture_fd(w, 2 + get(w, CAP_STREAM) * 2), CAP_BUFFER, 8192, 0, 0, 0, 12)

def write_kept(o:mutbuf, w:mutbuf) -> u32:
    if get(w, CAP_WRITTEN) == get(w, CAP_KEEP):
        return next_read(o, w)
    return call(o, w, 2344, 1, capture_fd(w, get(w, CAP_STREAM)), CAP_BUFFER + get(w, CAP_WRITTEN), get(w, CAP_KEEP) - get(w, CAP_WRITTEN), 0, 0, 0, 12)

def failed_poll_stream(o:mutbuf, w:mutbuf) -> u32:
    while get(w, CAP_STREAM) < 2:
        index = get(w, CAP_STREAM)
        if capture_fd(w, 2 + index * 2) != NONE:
            stream_error(w, 0, get(w, CAP_ERROR_CODE), 1)
            put(w, CAP_STREAM, index + 1)
            value = capture_fd(w, 2 + index * 2)
            put(w, SPAWN_FDS + (2 + index * 2) * 8, NONE)
            return call(o, w, 2341, 3, value, 0, 0, 0, 0, 0, 0)
        put(w, CAP_STREAM, index + 1)
    return observe(o, w)

def expire_streams(o:mutbuf, w:mutbuf) -> u32:
    while get(w, CAP_STREAM) < 2:
        index = get(w, CAP_STREAM)
        put(w, CAP_STREAM, index + 1)
        value = capture_fd(w, 2 + index * 2)
        if value != NONE:
            put(w, CAP_STREAMS + index * 256 + 32, 1)
            put(w, SPAWN_FDS + (2 + index * 2) * 8, NONE)
            return call(o, w, 2325, 3, value, 0, 0, 0, 0, 0, 0)
    return finish_start(o, w)

def finish_start(o:mutbuf, w:mutbuf) -> u32:
    put(w, SUP_CANCELLED, get(w, SUP_CANCELLED) | choose(get(w, SUP_STOP) != 0, 1, 0))
    status = get(w, SUP_STATUS)
    signal = status & 127
    code = 128
    if signal == 0:
        code = (status >> 8) & 255
    elif signal != 127:
        code = 128 + signal
    if get(w, SUP_TIMED_OUT) != 0:
        code = 124
    put(w, SUP_EXIT_CODE, code)
    put(w, CAP_STREAM, 0)
    return sync_stream(o, w)

def sync_stream(o:mutbuf, w:mutbuf) -> u32:
    if get(w, SUP_INTERACTIVE) == 1 or get(w, CAP_STREAM) == 2:
        put(w, 0, 2050)
        return 8
    return call(o, w, 2400, 74, capture_fd(w, get(w, CAP_STREAM)), 0, 0, 0, 0, 0, 0)

def finish_capture(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 2400:
        if result == NEG4:
            return sync_stream(o, w)
        if result == 0:
            put(w, stream_base(w) + 88, 1)
        else:
            stream_error(w, 2, result, 0)
        index = get(w, CAP_STREAM)
        value = capture_fd(w, index)
        put(w, SPAWN_FDS + index * 8, NONE)
        return call(o, w, 2401, 3, value, 0, 0, 0, 0, 0, 0)
    if phase == 2401:
        put(w, CAP_STREAM, get(w, CAP_STREAM) + 1)
        return sync_stream(o, w)
    return 0

def close_reader(o:mutbuf, w:mutbuf, next:u64) -> u32:
    index = 2 + get(w, CAP_STREAM) * 2
    value = capture_fd(w, index)
    put(w, SPAWN_FDS + index * 8, NONE)
    return call(o, w, next, 3, value, 0, 0, 0, 0, 0, 0)

def stream_error(w:mutbuf, kind:u64, result:u64, label:u64) -> u64:
    base = stream_base(w)
    slot = base + 40 + kind * 16
    if get(w, slot + 8) != 0:
        return 0
    start = SUP_ERROR_TEXT + 1024 + get(w, CAP_STREAM) * 2048 + kind * 512
    at = start
    if label == 1:
        at = text_poll(w, at)
    if label == 2:
        at = text_poll_invalid(w, at)
    elif label == 3:
        at = text_overflow(w, at)
    elif label == 4:
        at = text_no_write(w, at)
    else:
        at = io_error(w, at, choose(failed(result), 0 - result, 5))
    put(w, slot, start)
    put(w, slot + 8, at - start)
    return 0

def capture_failure(o:mutbuf, w:mutbuf, result:u64, label:u64) -> u32:
    at = SUP_ERROR_TEXT
    if label == 1:
        at = text_vanished(w, at)
    else:
        at = io_error(w, at, choose(failed(result), 0 - result, 5))
    put(w, SUP_ERROR, SUP_ERROR_TEXT)
    put(w, SUP_ERROR_SIZE, at - SUP_ERROR_TEXT)
    return failure_start(o, w)

def scratch_failure(o:mutbuf, w:mutbuf) -> u32:
    size = get(w, 62184)
    if size > 1048576:
        return 0
    copy(w, SUP_ERROR_TEXT, get(w, 62176), size)
    put(w, SUP_ERROR, SUP_ERROR_TEXT)
    put(w, SUP_ERROR_SIZE, size)
    return failure_start(o, w)

def failure_start(o:mutbuf, w:mutbuf) -> u32:
    if get(w, SUP_REAPED) == 0:
        return wait_child(o, w, 2460, 1)
    put(w, CAP_CLOSE_CURSOR, 0)
    return failure_close(o, w)

def failure_cleanup(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 2460:
        if result == 0:
            return wait_child(o, w, 2461, 1)
        if result == get(w, SUP_PID):
            put(w, SUP_REAPED, 1)
        put(w, CAP_CLOSE_CURSOR, 0)
        return failure_close(o, w)
    if phase == 2461:
        if result == 0:
            return call(o, w, 2462, 62, get(w, SUP_PID), 9, 0, 0, 0, 0, 0)
        if result == get(w, SUP_PID):
            put(w, SUP_REAPED, 1)
        put(w, CAP_CLOSE_CURSOR, 0)
        return failure_close(o, w)
    if phase == 2462:
        return wait_child(o, w, 2463, choose(result == 0, 0, 1))
    if phase == 2463:
        if result == NEG4 and get(w, CAP_WAIT_FLAGS) == 0:
            return wait_child(o, w, 2463, 0)
        if result == get(w, SUP_PID):
            put(w, SUP_REAPED, 1)
        put(w, CAP_CLOSE_CURSOR, 0)
        return failure_close(o, w)
    if phase == 2464:
        return failure_close(o, w)
    return 0

def failure_close(o:mutbuf, w:mutbuf) -> u32:
    while get(w, CAP_CLOSE_CURSOR) < 9:
        index = get(w, CAP_CLOSE_CURSOR)
        put(w, CAP_CLOSE_CURSOR, index + 1)
        if index != 8 or get(w, SUP_STDIN_PRESENT) != 1:
            value = capture_fd(w, index)
            put(w, SPAWN_FDS + index * 8, NONE)
            if value != NONE:
                return call(o, w, 2464, 3, value, 0, 0, 0, 0, 0, 0)
    put(w, 0, 2050)
    return 8

def wait_child(o:mutbuf, w:mutbuf, next:u64, flags:u64) -> u32:
    put(w, CAP_WAIT_FLAGS, flags)
    return call(o, w, next, 61, get(w, SUP_PID), CAP_WAIT_STATUS, flags, 0, 0, 0, 12)

def clock(o:mutbuf, w:mutbuf, next:u64) -> u32:
    return call(o, w, next, 228, 1, CAP_TIME, 0, 0, 0, 0, 12)

def capture_fd(w:mutbuf, index:u64) -> u64:
    return get(w, SPAWN_FDS + index * 8)

def stream_base(w:mutbuf) -> u64:
    return CAP_STREAMS + get(w, CAP_STREAM) * 256
'''

def source_program():
    text={'poll':'poll: ','poll_invalid':'poll rejected the original output descriptor','overflow':'observed output byte count overflow','no_write':'output write made no progress','vanished':'original engine exit vanished before reap'}
    return substitute(POLICY+'\n'+helpers(['get','getn','put','putn','call','failed','copy'])+literals(text)+error_source())

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    doc=document(source_program(),'system_jobctl_capture');text=render_assembly(doc);p=ROOT/'examples/hia_bootstrap/system_jobctl_capture.hepta'
    if args.check:assert p.read_text()==text
    else:p.write_text(text)
    print(p.name,len(doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
