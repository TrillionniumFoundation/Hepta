"""Author the fixed root systemd process transport in HIA.

The caller supplies only HIA-owned argv, after administrator admission. Captured
stdout and stderr are spooled into original memfds without an invented byte cap.
An exec-error pipe separates failed spawn from a child that really exited.
"""
from __future__ import annotations
import argparse,ast,re
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_system_jobctl_control as control
from tools import generate_hia_system_jobctl_start as start
ROOT=Path(__file__).resolve().parents[1]
CONSTANTS={**start.CONSTANTS,
 'PROCESS_MODE':51200,'PROCESS_NEXT':51208,'PROCESS_PID':51216,'PROCESS_STATUS':51224,
 'PROCESS_ERRNO':51232,'PROCESS_OUT_BYTES':51240,'PROCESS_ERR_BYTES':51248,
 'PROCESS_STEP':51256,'PROCESS_NORMAL_SLOT':51264,'PROCESS_NORMAL_NEXT':51272,
 'PROCESS_NORMAL_RAW':51280,'PROCESS_NORMAL_NEW':51288,'PROCESS_PIPE_OTHER':51296,
 'PROCESS_PIPE_SLOT':51304,'PROCESS_CURSOR':51312,'PROCESS_BARRIER_USED':51320,
 'PROCESS_STREAM':51328,'PROCESS_READ':51336,'PROCESS_WRITTEN':51344,
 'PROCESS_ENV_COUNT':51352,'PROCESS_FAILURE_NEXT':51360,'PROCESS_FAILURE':51368,'PROCESS_FDS':52000,'PROCESS_SIGACTION':52600,
 'PROCESS_PIPE':52640,'PROCESS_POLL':52700,'PROCESS_WAIT':52720,'PROCESS_ERROR':52740,
 'PROCESS_ENV_TEXT':68<<20,'PROCESS_ENV_TEXT_END':72<<20,
 'PROCESS_ENV_OFFSETS':72<<20,'PROCESS_ENV_POINTERS':74<<20,
 'PROCESS_ARG_OFFSETS':76<<20,'PROCESS_ARG_POINTERS':(76<<20)+2048,
 'PROCESS_BUFFER':78<<20,'NEG11':(1<<64)-11}
POLICY=r'''
def process(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 1590 and phase < 1600:
        return process_cleanup(o, w)
    if phase >= 1580 and phase < 1590:
        return normalized_fd(o, w, phase, result)
    if phase >= 1560 and phase < 1580:
        return child_process(o, w, phase, result)
    if phase == 1500:
        if get(w, PROCESS_MODE) > 1 or prepare_vectors(s, w) == 0:
            return 0
        index = 0
        while index < 9:
            put(w, PROCESS_FDS + index * 8, NONE)
            index = index + 1
        put(w, PROCESS_FAILURE, 0)
        put(w, PROCESS_PID, 0)
        put(w, PROCESS_STATUS, 0)
        put(w, PROCESS_ERRNO, 0)
        put(w, PROCESS_OUT_BYTES, 0)
        put(w, PROCESS_ERR_BYTES, 0)
        put(w, PROCESS_BARRIER_USED, 0)
        put(w, PROCESS_STEP, choose(get(w, PROCESS_MODE) == 1, 4, 0))
        return relocate(o, w, 1501, PROCESS_ARG_OFFSETS, get(w, COMMAND_COUNT) + 1, PROCESS_ARG_POINTERS)
    if phase == 1501:
        if result != 0:
            return process_failure(o, w)
        return relocate(o, w, 1510, PROCESS_ENV_OFFSETS, get(w, PROCESS_ENV_COUNT) + 1, PROCESS_ENV_POINTERS)
    if phase == 1510:
        if result != 0:
            return process_failure(o, w)
        step = get(w, PROCESS_STEP)
        if step < 2:
            store(w, PROCESS_BUFFER, 0)
            return call(o, w, 1511, 319, PROCESS_BUFFER, 3, 0, 0, 0, 0, 3)
        if step < 5:
            return call(o, w, 1512, 293, PROCESS_PIPE, 524288, 0, 0, 0, 0, 3)
        if step == 5 and get(w, PROCESS_MODE) == 0:
            path_null(w)
            return call(o, w, 1515, 257, NEG100, PROCESS_BUFFER, 524288, 0, 0, 0, 12)
        if get(w, PROCESS_MODE) == 0:
            put(w, PROCESS_STEP, 0)
            return call(o, w, 1520, 72, fd(w, 2), 3, 0, 0, 0, 0, 0)
        return call(o, w, 1523, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1511:
        if failed(result):
            return process_failure(o, w)
        step = get(w, PROCESS_STEP)
        put(w, PROCESS_STEP, step + 1)
        return normalize(o, w, result, step, 1510)
    if phase == 1512:
        if result != 0:
            return process_failure(o, w)
        slot = (get(w, PROCESS_STEP) - 1) * 2
        put(w, PROCESS_PIPE_SLOT, slot)
        put(w, PROCESS_PIPE_OTHER, getn(w, PROCESS_PIPE + 4, 4))
        put(w, PROCESS_FDS + (slot + 1) * 8, get(w, PROCESS_PIPE_OTHER))
        return normalize(o, w, getn(w, PROCESS_PIPE, 4), slot, 1513)
    if phase == 1513:
        return normalize(o, w, get(w, PROCESS_PIPE_OTHER), get(w, PROCESS_PIPE_SLOT) + 1, 1514)
    if phase == 1514:
        put(w, PROCESS_STEP, get(w, PROCESS_STEP) + 1)
        put(w, 8, 0)
        put(w, 0, 1510)
        return 8
    if phase == 1515:
        if failed(result):
            return process_failure(o, w)
        put(w, PROCESS_STEP, 6)
        return normalize(o, w, result, 8, 1510)
    if phase == 1520:
        if failed(result):
            return process_failure(o, w)
        return call(o, w, 1521, 72, fd(w, 2 + get(w, PROCESS_STEP) * 2), 4, result | 2048, 0, 0, 0, 0)
    if phase == 1521:
        if result != 0:
            return process_failure(o, w)
        if get(w, PROCESS_STEP) == 0:
            put(w, PROCESS_STEP, 1)
            return call(o, w, 1520, 72, fd(w, 4), 3, 0, 0, 0, 0, 0)
        return call(o, w, 1523, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase == 1523:
        if failed(result):
            return process_failure(o, w)
        if result == 0:
            zero(w, PROCESS_SIGACTION, 32)
            return call(o, w, 1560, 13, 13, PROCESS_SIGACTION, 0, 8, 0, 0, 12)
        put(w, PROCESS_PID, result)
        put(w, PROCESS_CURSOR, 0)
        return close_parent(o, w)
    if phase == 1530:
        return close_parent(o, w)
    if phase == 1531:
        if result == NEG4:
            return barrier_read(o, w)
        if failed(result) or result > 4 - get(w, PROCESS_BARRIER_USED):
            return process_failure(o, w)
        if result != 0:
            put(w, PROCESS_BARRIER_USED, get(w, PROCESS_BARRIER_USED) + result)
            if get(w, PROCESS_BARRIER_USED) < 4:
                return barrier_read(o, w)
            put(w, PROCESS_ERRNO, getn(w, PROCESS_ERROR, 4))
        elif get(w, PROCESS_BARRIER_USED) != 0:
            return process_failure(o, w)
        return call(o, w, 1532, 3, fd(w, 6), 0, 0, 0, 0, 0, 0)
    if phase == 1532:
        put(w, PROCESS_FDS + 48, NONE)
        if get(w, PROCESS_ERRNO) != 0:
            return call(o, w, 1550, 61, get(w, PROCESS_PID), PROCESS_WAIT, 0, 0, 0, 0, 12)
        if get(w, PROCESS_MODE) == 1:
            return complete(w)
        return poll_output(o, w)
    if phase == 1540:
        if result == NEG4:
            return poll_output(o, w)
        if failed(result):
            return process_failure(o, w)
        put(w, PROCESS_STREAM, 0)
        return ready_stream(o, w)
    if phase == 1541:
        if result == NEG4:
            return read_stream(o, w)
        if result == NEG11:
            put(w, PROCESS_STREAM, get(w, PROCESS_STREAM) + 1)
            return ready_stream(o, w)
        if failed(result) or result > 65536:
            return process_failure(o, w)
        if result == 0:
            return call(o, w, 1543, 3, fd(w, 2 + get(w, PROCESS_STREAM) * 2), 0, 0, 0, 0, 0, 0)
        put(w, PROCESS_READ, result)
        put(w, PROCESS_WRITTEN, 0)
        return write_stream(o, w)
    if phase == 1542:
        if result == NEG4:
            return write_stream(o, w)
        if result == 0 or failed(result) or result > get(w, PROCESS_READ) - get(w, PROCESS_WRITTEN):
            return process_failure(o, w)
        put(w, PROCESS_WRITTEN, get(w, PROCESS_WRITTEN) + result)
        if get(w, PROCESS_WRITTEN) < get(w, PROCESS_READ):
            return write_stream(o, w)
        at = PROCESS_OUT_BYTES + get(w, PROCESS_STREAM) * 8
        count = get(w, at)
        if get(w, PROCESS_READ) > NONE - count:
            return process_failure(o, w)
        put(w, at, count + get(w, PROCESS_READ))
        put(w, PROCESS_STREAM, get(w, PROCESS_STREAM) + 1)
        return ready_stream(o, w)
    if phase == 1543:
        put(w, PROCESS_FDS + (2 + get(w, PROCESS_STREAM) * 2) * 8, NONE)
        put(w, PROCESS_STREAM, get(w, PROCESS_STREAM) + 1)
        return ready_stream(o, w)
    if phase == 1550:
        if result == NEG4:
            return call(o, w, 1550, 61, get(w, PROCESS_PID), PROCESS_WAIT, 0, 0, 0, 0, 12)
        if result != get(w, PROCESS_PID):
            return process_failure(o, w)
        put(w, PROCESS_STATUS, getn(w, PROCESS_WAIT, 4))
        if get(w, PROCESS_MODE) == 1:
            return complete(w)
        return call(o, w, 1551, 72, fd(w, 0), 1033, 15, 0, 0, 0, 0)
    if phase == 1551:
        if result != 0:
            return process_failure(o, w)
        return call(o, w, 1552, 72, fd(w, 1), 1033, 15, 0, 0, 0, 0)
    if phase == 1552:
        if result != 0:
            return process_failure(o, w)
        return complete(w)
    return 0

def complete(w:mutbuf) -> u32:
    put(w, PROCESS_FAILURE_NEXT, 0)
    put(w, PROCESS_FAILURE, 0)
    put(w, 0, get(w, PROCESS_NEXT))
    return 12

def process_failure(o:mutbuf, w:mutbuf) -> u32:
    error = 5
    result = get(w, 8)
    if failed(result):
        error = 0 - result
    put(w, PROCESS_FAILURE, error)
    put(w, PROCESS_CURSOR, 0)
    return process_cleanup(o, w)

def process_cleanup(o:mutbuf, w:mutbuf) -> u32:
    while get(w, PROCESS_CURSOR) < 9:
        index = get(w, PROCESS_CURSOR)
        put(w, PROCESS_CURSOR, index + 1)
        value = fd(w, index)
        put(w, PROCESS_FDS + index * 8, NONE)
        if value != NONE:
            return call(o, w, 1590, 3, value, 0, 0, 0, 0, 0, 0)
    next = get(w, PROCESS_FAILURE_NEXT)
    put(w, PROCESS_FAILURE_NEXT, 0)
    if next == 0:
        return 0
    put(w, 0, next)
    return 8

def child_process(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 1560:
        if result != 0:
            return child_failure(o, w, result)
        if get(w, PROCESS_MODE) == 1:
            return child_exec(o, w)
        return call(o, w, 1561, 292, fd(w, 8), 0, 0, 0, 0, 0, 0)
    if phase == 1561:
        if result != 0:
            return child_failure(o, w, result)
        return call(o, w, 1562, 292, fd(w, 3), 1, 0, 0, 0, 0, 0)
    if phase == 1562:
        if result != 1:
            return child_failure(o, w, result)
        return call(o, w, 1563, 292, fd(w, 5), 2, 0, 0, 0, 0, 0)
    if phase == 1563:
        if result != 2:
            return child_failure(o, w, result)
        return child_exec(o, w)
    if phase == 1564:
        return child_failure(o, w, result)
    if phase == 1570:
        if result == NEG4:
            return child_error_write(o, w)
        if result == 0 or failed(result) or result > 4 - get(w, PROCESS_CURSOR):
            return call(o, w, 1571, 231, 127, 0, 0, 0, 0, 0, 0)
        put(w, PROCESS_CURSOR, get(w, PROCESS_CURSOR) + result)
        if get(w, PROCESS_CURSOR) < 4:
            return child_error_write(o, w)
        return call(o, w, 1571, 231, 127, 0, 0, 0, 0, 0, 0)
    return 0

def child_exec(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 1564, 59, get(w, ARGV), PROCESS_ARG_POINTERS, PROCESS_ENV_POINTERS, 0, 0, 0, 63)

def child_failure(o:mutbuf, w:mutbuf, result:u64) -> u32:
    if failed(result) == False:
        result = 18446744073709551611
    putn(w, PROCESS_ERROR, 0 - result, 4)
    put(w, PROCESS_CURSOR, 0)
    return child_error_write(o, w)

def child_error_write(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 1570, 1, fd(w, 7), PROCESS_ERROR + get(w, PROCESS_CURSOR), 4 - get(w, PROCESS_CURSOR), 0, 0, 0, 12)

def close_parent(o:mutbuf, w:mutbuf) -> u32:
    while get(w, PROCESS_CURSOR) < 9:
        index = get(w, PROCESS_CURSOR)
        put(w, PROCESS_CURSOR, index + 1)
        if index == 3 or index == 5 or index == 7 or index == 8:
            value = fd(w, index)
            put(w, PROCESS_FDS + index * 8, NONE)
            if value != NONE:
                return call(o, w, 1530, 3, value, 0, 0, 0, 0, 0, 0)
    return barrier_read(o, w)

def barrier_read(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 1531, 0, fd(w, 6), PROCESS_ERROR + get(w, PROCESS_BARRIER_USED), 4 - get(w, PROCESS_BARRIER_USED), 0, 0, 0, 12)

def poll_output(o:mutbuf, w:mutbuf) -> u32:
    if fd(w, 2) == NONE and fd(w, 4) == NONE:
        return call(o, w, 1550, 61, get(w, PROCESS_PID), PROCESS_WAIT, 0, 0, 0, 0, 12)
    index = 0
    while index < 2:
        at = PROCESS_POLL + index * 8
        putn(w, at, fd(w, 2 + index * 2), 4)
        putn(w, at + 4, 1, 2)
        putn(w, at + 6, 0, 2)
        index = index + 1
    return call(o, w, 1540, 7, PROCESS_POLL, 2, NONE, 0, 0, 0, 3)

def ready_stream(o:mutbuf, w:mutbuf) -> u32:
    while get(w, PROCESS_STREAM) < 2:
        index = get(w, PROCESS_STREAM)
        events = getn(w, PROCESS_POLL + index * 8 + 6, 2)
        if fd(w, 2 + index * 2) != NONE:
            if events & 32 != 0:
                return process_failure(o, w)
            if events & 25 != 0:
                return read_stream(o, w)
        put(w, PROCESS_STREAM, index + 1)
    return poll_output(o, w)

def read_stream(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 1541, 0, fd(w, 2 + get(w, PROCESS_STREAM) * 2), PROCESS_BUFFER, 65536, 0, 0, 0, 12)

def write_stream(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 1542, 1, fd(w, get(w, PROCESS_STREAM)), PROCESS_BUFFER + get(w, PROCESS_WRITTEN), get(w, PROCESS_READ) - get(w, PROCESS_WRITTEN), 0, 0, 0, 12)

def fd(w:mutbuf, index:u64) -> u64:
    return get(w, PROCESS_FDS + index * 8)

def normalize(o:mutbuf, w:mutbuf, value:u64, slot:u64, after:u64) -> u32:
    put(w, PROCESS_FDS + slot * 8, value)
    if value >= 3:
        put(w, PROCESS_FDS + slot * 8, value)
        put(w, 8, 0)
        put(w, 0, after)
        return 8
    put(w, PROCESS_NORMAL_RAW, value)
    put(w, PROCESS_NORMAL_SLOT, slot)
    put(w, PROCESS_NORMAL_NEXT, after)
    return call(o, w, 1580, 72, value, 1030, 3, 0, 0, 0, 0)

def normalized_fd(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 1580:
        if failed(result) or result < 3:
            return process_failure(o, w)
        put(w, PROCESS_NORMAL_NEW, result)
        return call(o, w, 1581, 3, get(w, PROCESS_NORMAL_RAW), 0, 0, 0, 0, 0, 0)
    if phase == 1581:
        put(w, PROCESS_FDS + get(w, PROCESS_NORMAL_SLOT) * 8, get(w, PROCESS_NORMAL_NEW))
        put(w, 8, 0)
        put(w, 0, get(w, PROCESS_NORMAL_NEXT))
        return 8
    return 0

def relocate(o:mutbuf, w:mutbuf, next:u64, source:u64, count:u64, target:u64) -> u32:
    put(w, 0, next)
    put(o, 0, source)
    put(o, 8, count)
    put(o, 16, target)
    return 2

def prepare_vectors(s:readbuf, w:mutbuf) -> u64:
    count = get(w, COMMAND_COUNT)
    if count == 0 or count > 128:
        return 0
    index = 0
    while index < count:
        at = get(w, ARGV + index * 16)
        size = get(w, ARGV + index * 16 + 8)
        if at < COMMAND or at >= COMMAND_END or size >= COMMAND_END - at or byte(w, at + size) != 0:
            return 0
        put(w, PROCESS_ARG_OFFSETS + index * 8, at)
        index = index + 1
    put(w, PROCESS_ARG_OFFSETS + count * 8, NONE)
    envcount = uint(s, 16)
    if envcount > 262143:
        return 0
    put(w, PROCESS_ENV_COUNT, envcount)
    index = 0
    at = 32
    while index < uint(s, 8):
        if at > length(s) or length(s) - at < 9:
            return 0
        size = uint(s, at)
        if size >= length(s) - at - 8:
            return 0
        at = at + size + 9
        index = index + 1
    index = 0
    used = PROCESS_ENV_TEXT
    while index < envcount:
        if at > length(s) or length(s) - at < 9:
            return 0
        size = uint(s, at)
        if size >= length(s) - at - 8 or size >= PROCESS_ENV_TEXT_END - used or byte(s, at + 8 + size) != 0:
            return 0
        put(w, PROCESS_ENV_OFFSETS + index * 8, used)
        position = 0
        while position < size:
            value = byte(s, at + 8 + position)
            if value == 0:
                return 0
            store(w, used + position, value)
            position = position + 1
        store(w, used + size, 0)
        used = used + size + 1
        at = at + size + 9
        index = index + 1
    if at != length(s):
        return 0
    put(w, PROCESS_ENV_OFFSETS + envcount * 8, NONE)
    return 1

def path_null(w:mutbuf) -> u64:
    put(w, PROCESS_BUFFER, 0x6c756e2f7665642f)
    putn(w, PROCESS_BUFFER + 8, 108, 2)
    return 0

def zero(w:mutbuf, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, at + index, 0)
        index = index + 1
    return 0
'''
def source_program():
    source=POLICY
    available={n.name:ast.get_source_segment(control.source_program(),n) for n in ast.parse(control.source_program()).body if isinstance(n,ast.FunctionDef)}
    for name in ['call','get','getn','put','putn','failed','uint']:
        source+='\n'+available[name]+'\n'
    for key in sorted(CONSTANTS,key=len,reverse=True):source=re.sub(r'\b'+key+r'\b',str(CONSTANTS[key]),source)
    return source

def main():
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');args=p.parse_args()
    doc=document(source_program(),'system_jobctl_process');path=ROOT/'examples/hia_bootstrap/system_jobctl_process.hepta';text=render_assembly(doc)
    if args.check:assert path.read_text()==text
    else:path.write_text(text)
    print(path.name,len(text),'functions',len(doc['functions']),'blocks',sum(len(f['blocks']) for f in doc['functions']),'ops',sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
