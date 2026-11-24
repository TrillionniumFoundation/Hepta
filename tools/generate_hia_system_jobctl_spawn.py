"""Author the original supervisor's log preparation and fork/exec barrier."""
from __future__ import annotations
import argparse
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_system_jobctl_errors import error_source
from tools.generate_hia_system_jobctl_supervisor_common import helpers,literals,substitute
ROOT=Path(__file__).resolve().parents[1]

POLICY=r'''
def spawn(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 2280 and phase < 2290:
        return normalized(o, w, phase, result)
    if phase >= 2250 and phase < 2280:
        return child(o, w, phase, result)
    if phase == 2200:
        index = 0
        while index < 8:
            put(w, SPAWN_FDS + index * 8, NONE)
            index = index + 1
        put(w, SPAWN_ERROR, 0)
        put(w, SPAWN_ERROR_KIND, 0)
        put(w, SUP_ERROR_SIZE, 0)
        put(w, SUP_PID, 0)
        put(w, SUP_REAPED, 0)
        put(w, SPAWN_BARRIER_USED, 0)
        return relocate(o, w, 2201, SUP_ARG_OFFSETS, get(w, SUP_ARG_COUNT) + 1, SUP_ARG_POINTERS)
    if phase == 2201:
        if result != 0:
            return spawn_failure(o, w, result, 0)
        return relocate(o, w, 2202, SUP_ENV_OFFSETS, get(w, SUP_ENV_COUNT) + 1, SUP_ENV_POINTERS)
    if phase == 2202:
        if result != 0:
            return spawn_failure(o, w, result, 0)
        if get(w, SUP_INTERACTIVE) == 1:
            put(w, 0, 2208)
            return 8
        put(w, SPAWN_STEP, 0)
        if get(w, SUP_STDIN_PRESENT) == 0:
            return log_open(o, w)
        return normalize(o, w, fd(w, 8), 8, 2203)
    if phase == 2203:
        return log_open(o, w)
    if phase == 2204:
        if result == NEG4:
            return log_open(o, w)
        if failed(result):
            return spawn_failure(o, w, result, get(w, SPAWN_STEP) + 1)
        return normalize(o, w, result, get(w, SPAWN_STEP), 2205)
    if phase == 2205:
        put(w, SPAWN_STEP, get(w, SPAWN_STEP) + 1)
        if get(w, SPAWN_STEP) < 2:
            return log_open(o, w)
        put(w, SPAWN_STEP, 0)
        return call(o, w, 2206, 293, SPAWN_PIPE, 524288, 0, 0, 0, 0, 3)
    if phase == 2206:
        if result != 0:
            return spawn_failure(o, w, result, 0)
        slot = 2 + get(w, SPAWN_STEP) * 2
        put(w, SPAWN_PIPE_SLOT, slot)
        put(w, SPAWN_PIPE_OTHER, getn(w, SPAWN_PIPE + 4, 4))
        put(w, SPAWN_FDS + (slot + 1) * 8, get(w, SPAWN_PIPE_OTHER))
        return normalize(o, w, getn(w, SPAWN_PIPE, 4), slot, 2210)
    if phase == 2210:
        return normalize(o, w, get(w, SPAWN_PIPE_OTHER), get(w, SPAWN_PIPE_SLOT) + 1, 2211)
    if phase == 2211:
        return call(o, w, 2212, 72, fd(w, get(w, SPAWN_PIPE_SLOT)), 3, 0, 0, 0, 0, 0)
    if phase == 2212:
        if failed(result):
            return spawn_failure(o, w, result, 0)
        return call(o, w, 2213, 72, fd(w, get(w, SPAWN_PIPE_SLOT)), 4, result | 2048, 0, 0, 0, 0)
    if phase == 2213:
        if result != 0:
            return spawn_failure(o, w, result, 0)
        put(w, SPAWN_STEP, get(w, SPAWN_STEP) + 1)
        if get(w, SPAWN_STEP) < 2:
            return call(o, w, 2206, 293, SPAWN_PIPE, 524288, 0, 0, 0, 0, 3)
        put(w, 0, 2208)
        return 8
    if phase == 2208:
        if get(w, SUP_INVALID) != 0:
            return spawn_failure(o, w, 0, 3)
        if get(w, SUP_INTERACTIVE) == 0 and get(w, SUP_STDIN_PRESENT) == 0:
            end = text_null(w, SUP_PATH)
            store(w, end, 0)
            return call(o, w, 2218, 257, NEG100, SUP_PATH, 524288, 0, 0, 0, 12)
        return call(o, w, 2214, 293, SPAWN_PIPE, 524288, 0, 0, 0, 0, 3)
    if phase == 2218:
        if result == NEG4:
            return call(o, w, 2218, 257, NEG100, SUP_PATH, 524288, 0, 0, 0, 12)
        if failed(result):
            return spawn_failure(o, w, result, 0)
        return normalize(o, w, result, 8, 2219)
    if phase == 2219:
        return call(o, w, 2214, 293, SPAWN_PIPE, 524288, 0, 0, 0, 0, 3)
    if phase == 2214:
        if result != 0:
            return spawn_failure(o, w, result, 0)
        put(w, SPAWN_PIPE_OTHER, getn(w, SPAWN_PIPE + 4, 4))
        put(w, SPAWN_FDS + 56, get(w, SPAWN_PIPE_OTHER))
        return normalize(o, w, getn(w, SPAWN_PIPE, 4), 6, 2215)
    if phase == 2215:
        return normalize(o, w, get(w, SPAWN_PIPE_OTHER), 7, 2216)
    if phase == 2216:
        return call(o, w, 2217, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase == 2217:
        if failed(result):
            return spawn_failure(o, w, result, 0)
        if result == 0:
            zero(w, SPAWN_SIGACTION, 32)
            return call(o, w, 2250, 13, 13, SPAWN_SIGACTION, 0, 8, 0, 0, 12)
        put(w, SUP_PID, result)
        put(w, SPAWN_CURSOR, 0)
        return close_parent(o, w)
    if phase == 2220:
        return close_parent(o, w)
    if phase == 2221:
        if result == NEG4:
            return barrier(o, w)
        if failed(result) or result > 4 - get(w, SPAWN_BARRIER_USED):
            return spawn_failure(o, w, result, 0)
        if result == 0:
            if get(w, SPAWN_BARRIER_USED) != 0:
                return spawn_failure(o, w, 0, 0)
            value = fd(w, 6)
            put(w, SPAWN_FDS + 48, NONE)
            return call(o, w, 2222, 3, value, 0, 0, 0, 0, 0, 0)
        put(w, SPAWN_BARRIER_USED, get(w, SPAWN_BARRIER_USED) + result)
        if get(w, SPAWN_BARRIER_USED) != 4:
            return barrier(o, w)
        put(w, SPAWN_ERROR, getn(w, SPAWN_ERROR_RAW, 4))
        return call(o, w, 2223, 61, get(w, SUP_PID), SPAWN_WAIT, 0, 0, 0, 0, 12)
    if phase == 2222:
        put(w, 0, get(w, SPAWN_NEXT))
        return 8
    if phase == 2223:
        if result == NEG4:
            return call(o, w, 2223, 61, get(w, SUP_PID), SPAWN_WAIT, 0, 0, 0, 0, 12)
        if result == get(w, SUP_PID):
            put(w, SUP_REAPED, 1)
        return spawn_failure(o, w, 0 - get(w, SPAWN_ERROR), 0)
    if phase == 2290:
        return close_failed(o, w)
    return 0

def log_open(o:mutbuf, w:mutbuf) -> u32:
    size = get(w, SUP_STATE_SIZE)
    copy(w, SUP_PATH, SUP_STATE, size)
    at = SUP_PATH + size
    if size != 0 and byte(w, at - 1) != 47:
        store(w, at, 47)
        at = at + 1
    if get(w, SPAWN_STEP) == 0:
        at = text_stdout(w, at)
    else:
        at = text_stderr(w, at)
    store(w, at, 0)
    return call(o, w, 2204, 257, NEG100, SUP_PATH, 655553, 384, 0, 0, 12)

def close_parent(o:mutbuf, w:mutbuf) -> u32:
    while get(w, SPAWN_CURSOR) < 9:
        index = get(w, SPAWN_CURSOR)
        put(w, SPAWN_CURSOR, index + 1)
        if index == 3 or index == 5 or index == 7 or (index == 8 and get(w, SUP_STDIN_PRESENT) == 0):
            value = fd(w, index)
            put(w, SPAWN_FDS + index * 8, NONE)
            if value != NONE:
                return call(o, w, 2220, 3, value, 0, 0, 0, 0, 0, 0)
    return barrier(o, w)

def barrier(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 2221, 0, fd(w, 6), SPAWN_ERROR_RAW + get(w, SPAWN_BARRIER_USED), 4 - get(w, SPAWN_BARRIER_USED), 0, 0, 0, 12)

def child(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 2250:
        if result != 0:
            return child_failure(o, w, result)
        if get(w, SUP_INTERACTIVE) == 1:
            return call(o, w, 2254, 80, get(w, SUP_CWD), 0, 0, 0, 0, 0, 3)
        return call(o, w, 2251, 292, fd(w, 8), 0, 0, 0, 0, 0, 0)
    if phase == 2251:
        if result != 0:
            return child_failure(o, w, result)
        return call(o, w, 2252, 292, fd(w, 3), 1, 0, 0, 0, 0, 0)
    if phase == 2252:
        if result != 1:
            return child_failure(o, w, result)
        return call(o, w, 2253, 292, fd(w, 5), 2, 0, 0, 0, 0, 0)
    if phase == 2253:
        if result != 2:
            return child_failure(o, w, result)
        return call(o, w, 2254, 80, get(w, SUP_CWD), 0, 0, 0, 0, 0, 3)
    if phase == 2254:
        if result != 0:
            return child_failure(o, w, result)
        if get(w, SUP_SCRATCH) == 1:
            return call(o, w, 2255, 109, 0, 0, 0, 0, 0, 0, 0)
        put(w, 0, 2255)
        return 8
    if phase == 2255:
        if result != 0:
            return child_failure(o, w, result)
        put(w, SPAWN_EXEC_SEARCH, 1)
        index = 0
        while index < get(w, SUP_EXE_SIZE):
            if byte(w, get(w, SUP_EXE) + index) == 47:
                put(w, SPAWN_EXEC_SEARCH, 0)
            index = index + 1
        if get(w, SPAWN_EXEC_SEARCH) == 0:
            return call(o, w, 2256, 59, get(w, SUP_EXE), SUP_ARG_POINTERS, SUP_ENV_POINTERS, 0, 0, 0, 63)
        if get(w, SUP_EXE_SIZE) == 0:
            return child_failure(o, w, NEG2)
        put(w, SPAWN_PATH_CURSOR, 0)
        put(w, SPAWN_DENIED, 0)
        return search_next(o, w)
    if phase == 2256:
        return child_failure(o, w, result)
    if phase == 2260:
        if result == 18446744073709551608:
            end = text_shell(w, SUP_TEMP)
            store(w, end, 0)
            put(w, SPAWN_SHELL_OFFSETS, SUP_TEMP)
            put(w, SPAWN_SHELL_OFFSETS + 8, SUP_PATH)
            index = 1
            while index < get(w, SUP_ARG_COUNT):
                put(w, SPAWN_SHELL_OFFSETS + (index + 1) * 8, get(w, SUP_ARG_OFFSETS + index * 8))
                index = index + 1
            put(w, SPAWN_SHELL_OFFSETS + (index + 1) * 8, NONE)
            return relocate(o, w, 2261, SPAWN_SHELL_OFFSETS, index + 2, SPAWN_SHELL_POINTERS)
        return search_result(o, w, result)
    if phase == 2261:
        if result != 0:
            return child_failure(o, w, result)
        return call(o, w, 2262, 59, SUP_TEMP, SPAWN_SHELL_POINTERS, SUP_ENV_POINTERS, 0, 0, 0, 63)
    if phase == 2262:
        return search_result(o, w, result)
    if phase == 2270:
        if result == NEG4:
            return error_write(o, w)
        if result == 0 or failed(result) or result > 4 - get(w, SPAWN_CURSOR):
            return call(o, w, 2271, 231, 127, 0, 0, 0, 0, 0, 0)
        put(w, SPAWN_CURSOR, get(w, SPAWN_CURSOR) + result)
        if get(w, SPAWN_CURSOR) != 4:
            return error_write(o, w)
        return call(o, w, 2271, 231, 127, 0, 0, 0, 0, 0, 0)
    return 0

def search_next(o:mutbuf, w:mutbuf) -> u32:
    start = get(w, SPAWN_PATH_CURSOR)
    stop = start
    size = get(w, SUP_SEARCH_SIZE)
    source = get(w, SUP_SEARCH_PATH)
    while stop < size and byte(w, source + stop) != 58:
        stop = stop + 1
    put(w, SPAWN_SEARCH_DONE, choose(stop == size, 1, 0))
    put(w, SPAWN_PATH_CURSOR, stop + 1)
    at = SUP_PATH
    if stop != start:
        copy(w, at, source + start, stop - start)
        at = at + stop - start
        store(w, at, 47)
        at = at + 1
    copy(w, at, get(w, SUP_EXE), get(w, SUP_EXE_SIZE))
    store(w, at + get(w, SUP_EXE_SIZE), 0)
    return call(o, w, 2260, 59, SUP_PATH, SUP_ARG_POINTERS, SUP_ENV_POINTERS, 0, 0, 0, 63)

def search_result(o:mutbuf, w:mutbuf, result:u64) -> u32:
    code = 0 - result
    if code != 2 and code != 20 and code != 116 and code != 19 and code != 110 and code != 13:
        return child_failure(o, w, result)
    if code == 13:
        put(w, SPAWN_DENIED, 1)
    if get(w, SPAWN_SEARCH_DONE) != 0:
        if get(w, SPAWN_DENIED) != 0:
            result = 18446744073709551603
        return child_failure(o, w, result)
    return search_next(o, w)

def child_failure(o:mutbuf, w:mutbuf, result:u64) -> u32:
    putn(w, SPAWN_ERROR_RAW, choose(failed(result), 0 - result, 5), 4)
    put(w, SPAWN_CURSOR, 0)
    return error_write(o, w)

def error_write(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 2270, 1, fd(w, 7), SPAWN_ERROR_RAW + get(w, SPAWN_CURSOR), 4 - get(w, SPAWN_CURSOR), 0, 0, 0, 12)

def spawn_failure(o:mutbuf, w:mutbuf, result:u64, kind:u64) -> u32:
    put(w, SPAWN_ERROR, choose(failed(result), 0 - result, 5))
    put(w, SPAWN_ERROR_KIND, kind)
    at = SUP_ERROR_TEXT
    if kind == 1:
        at = text_stdout_error(w, at)
    elif kind == 2:
        at = text_stderr_error(w, at)
    if kind == 3:
        at = text_nul(w, at)
    else:
        at = io_error(w, at, get(w, SPAWN_ERROR))
    put(w, SUP_ERROR, SUP_ERROR_TEXT)
    put(w, SUP_ERROR_SIZE, at - SUP_ERROR_TEXT)
    put(w, SPAWN_CURSOR, 0)
    return close_failed(o, w)

def close_failed(o:mutbuf, w:mutbuf) -> u32:
    while get(w, SPAWN_CURSOR) < 9:
        index = get(w, SPAWN_CURSOR)
        put(w, SPAWN_CURSOR, index + 1)
        if index != 8 or get(w, SUP_STDIN_PRESENT) != 1:
            value = fd(w, index)
            put(w, SPAWN_FDS + index * 8, NONE)
            if value != NONE:
                return call(o, w, 2290, 3, value, 0, 0, 0, 0, 0, 0)
    put(w, 0, get(w, SPAWN_NEXT))
    return 8

def normalize(o:mutbuf, w:mutbuf, value:u64, slot:u64, next:u64) -> u32:
    put(w, SPAWN_FDS + slot * 8, value)
    if value >= 3:
        put(w, 8, 0)
        put(w, 0, next)
        return 8
    put(w, SPAWN_NORMAL_RAW, value)
    put(w, SPAWN_NORMAL_SLOT, slot)
    put(w, SPAWN_NORMAL_NEXT, next)
    return call(o, w, 2280, 72, value, 1030, 3, 0, 0, 0, 0)

def normalized(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 2280:
        if failed(result) or result < 3:
            return spawn_failure(o, w, result, 0)
        put(w, SPAWN_NORMAL_NEW, result)
        return call(o, w, 2281, 3, get(w, SPAWN_NORMAL_RAW), 0, 0, 0, 0, 0, 0)
    if phase == 2281:
        put(w, SPAWN_FDS + get(w, SPAWN_NORMAL_SLOT) * 8, get(w, SPAWN_NORMAL_NEW))
        put(w, 8, 0)
        put(w, 0, get(w, SPAWN_NORMAL_NEXT))
        return 8
    return 0

def fd(w:mutbuf, index:u64) -> u64:
    return get(w, SPAWN_FDS + index * 8)

def relocate(o:mutbuf, w:mutbuf, next:u64, source:u64, count:u64, target:u64) -> u32:
    put(w, 0, next)
    put(o, 0, source)
    put(o, 8, count)
    put(o, 16, target)
    return 2

def zero(w:mutbuf, at:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, at + index, 0)
        index = index + 1
    return 0
'''

def source_program():
    text={'stdout':'stdout.log','stderr':'stderr.log','stdout_error':'create original stdout log before spawn: ','stderr_error':'create original stderr log before spawn: ','nul':'nul byte found in provided data','shell':'/bin/sh','null':'/dev/null'}
    return substitute(POLICY+'\n'+helpers(['get','getn','put','putn','call','failed','copy'])+literals(text)+error_source())

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    doc=document(source_program(),'system_jobctl_spawn');text=render_assembly(doc);p=ROOT/'examples/hia_bootstrap/system_jobctl_spawn.hepta'
    if args.check:assert p.read_text()==text
    else:p.write_text(text)
    print(p.name,len(doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
