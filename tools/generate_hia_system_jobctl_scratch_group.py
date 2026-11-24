"""HIA-owned original unreaped-child and complete Linux PGID observation."""
from __future__ import annotations
import argparse
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_system_jobctl_scratch_common import compose
ROOT=Path(__file__).resolve().parents[1]
POLICY=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase >= 3600 and phase < 3610:
        return group_io(o, w, phase, result)
    if phase >= 3590 and phase < 3600:
        return group_close(o, w, phase)
    if phase >= 3510 and phase < 3530:
        return group_scan(o, w, phase, result)
    if phase >= 3530 and phase < 3540:
        return group_stop(o, w, phase, result)
    return group_start(o, w, phase, result)

def group_start(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 3500:
        put(w, G_FD, NONE)
        put(w, G_DIR_FD, NONE)
        put(w, SC_FAILED, 0)
        put(w, SC_EXITED, 0)
        put(w, SC_ERROR_SIZE, 0)
        put(w, G_PID, get(w, SC_PID))
        if get(w, SC_OP) == 1:
            return group_wait(o, w)
        if get(w, SC_OP) != 2:
            return 0
        put(w, SC_STOPPED, 0)
        sc_nul(w, sc_text(w, SC_PATH_TEMP, E_MOUNTINFO))
        put(w, G_IO_KIND, 0)
        return group_open(o, w)
    if phase == 3501:
        if result != 0:
            sc_result_error(w, E_GROUP_CUSTODY, result)
            return group_failed(o, w)
        observed = getn(w, SC_STAT + 16, 4)
        if observed != 0:
            code = getn(w, SC_STAT + 8, 4)
            if observed != get(w, G_PID) or code < 1 or code > 3:
                sc_error(w, E_GROUP_EXIT, 0)
                return group_failed(o, w)
            put(w, SC_EXITED, 1)
        else:
            put(w, SC_EXITED, 0)
        if get(w, SC_OP) == 1:
            return sc_finish(w)
        if observed == 0:
            return group_kill(o, w)
        sc_nul(w, sc_text(w, SC_PATH_TEMP, E_PROC))
        return call(o, w, 3510, 257, NEG100, SC_PATH_TEMP, 65536 + 524288 + 2048, 0, 0, 0, 12)
    if phase == 3504:
        if get(w, G_USED) > 1048576:
            sc_error(w, E_MOUNT_BOUND, 0)
            return group_failed(o, w)
        if group_visibility(w, SC_IO, get(w, G_USED)) == 0:
            return group_failed(o, w)
        if get(w, G_PID) > 2147483647:
            sc_error(w, E_PID_RANGE, 0)
            return group_failed(o, w)
        return call(o, w, 3505, 228, 1, SC_STAT, 0, 0, 0, 0, 12)
    if phase == 3505:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return group_failed(o, w)
        put(w, G_DEADLINE, sc_now(w) + 2000000000)
        return group_wait(o, w)
    return 0

def group_wait(o:mutbuf, w:mutbuf) -> u32:
    index = 0
    while index < 128:
        put(w, SC_STAT + index, 0)
        index = index + 8
    return call(o, w, 3501, 247, 1, get(w, G_PID), SC_STAT, 16777221, 0, 0, 48)

def group_open(o:mutbuf, w:mutbuf) -> u32:
    put(w, G_USED, 0)
    return call(o, w, 3600, 257, NEG100, SC_PATH_TEMP, 524288, 0, 0, 0, 12)

def group_read(o:mutbuf, w:mutbuf) -> u32:
    maximum = choose(get(w, G_IO_KIND) == 0, 1048577, 16385)
    used = get(w, G_USED)
    if used == maximum:
        return call(o, w, 3602, 3, get(w, G_FD), 0, 0, 0, 0, 0, 0)
    return call(o, w, 3601, 0, get(w, G_FD), SC_IO + used, maximum - used, 0, 0, 0, 12)

def group_io(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 3600:
        if result == NEG4:
            return group_open(o, w)
        if failed(result):
            if get(w, G_IO_KIND) == 1 and result == NEG2:
                return group_next(o, w)
            sc_result_error(w, choose(get(w, G_IO_KIND) == 1, E_GROUP_VISIBILITY, E_EMPTY), result)
            return group_failed(o, w)
        put(w, G_FD, result)
        return group_read(o, w)
    if phase == 3601:
        if result == NEG4:
            return group_read(o, w)
        if failed(result):
            sc_result_error(w, E_EMPTY, result)
            return group_failed(o, w)
        maximum = choose(get(w, G_IO_KIND) == 0, 1048577, 16385)
        if result > maximum - get(w, G_USED):
            sc_error(w, E_EMPTY, 5)
            return group_failed(o, w)
        if result == 0:
            return call(o, w, 3602, 3, get(w, G_FD), 0, 0, 0, 0, 0, 0)
        put(w, G_USED, get(w, G_USED) + result)
        return group_read(o, w)
    if phase == 3602:
        put(w, G_FD, NONE)
        if get(w, G_IO_KIND) == 0:
            return sc_go(w, 3504)
        if group_stat(w, SC_IO, get(w, G_USED), get(w, G_PID)) == 0:
            return group_failed(o, w)
        return group_next(o, w)
    return 0

def group_scan(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 3510:
        if failed(result):
            sc_result_error(w, E_EMPTY, result)
            return group_failed(o, w)
        put(w, G_DIR_FD, result)
        put(w, G_COUNT, 0)
        put(w, G_MEMBERS, 0)
        put(w, G_DIR_USED, 0)
        put(w, G_DIR_SIZE, 0)
        return group_next(o, w)
    if phase == 3511:
        if result == 0 or result == NEG2:
            return call(o, w, 3514, 3, get(w, G_DIR_FD), 0, 0, 0, 0, 0, 0)
        if failed(result):
            put(w, G_ERROR_CONTEXT, 0 - result)
            return call(o, w, 3512, 228, 1, SC_STAT, 0, 0, 0, 0, 12)
        if result > 32768:
            sc_error(w, E_EMPTY, 5)
            return group_failed(o, w)
        put(w, G_DIR_USED, 0)
        put(w, G_DIR_SIZE, result)
        return group_next(o, w)
    if phase == 3512:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return group_failed(o, w)
        if get(w, G_COUNT) > 100000 or sc_now(w) >= get(w, G_DEADLINE):
            sc_error(w, E_GROUP_BUDGET, 0)
            return group_failed(o, w)
        put(w, G_COUNT, get(w, G_COUNT) + 1)
        if get(w, G_ERROR_CONTEXT) != 0:
            sc_error(w, E_EMPTY, get(w, G_ERROR_CONTEXT))
            return group_failed(o, w)
        pid = sc_i32(w, SC_NAME, get(w, G_ENTRY_SIZE))
        if get(w, G_INT_ERROR) != 0:
            return group_next(o, w)
        at = sc_text(w, SC_PATH_TEMP, E_PROC)
        store(w, at, 47)
        copy(w, at + 1, SC_NAME, get(w, G_ENTRY_SIZE))
        sc_nul(w, sc_text(w, at + 1 + get(w, G_ENTRY_SIZE), E_SLASH_STAT))
        put(w, G_IO_KIND, 1)
        return group_open(o, w)
    if phase == 3514:
        put(w, G_DIR_FD, NONE)
        if get(w, G_MEMBERS) == 0:
            put(w, SC_STOPPED, 1)
            return sc_finish(w)
        return group_kill(o, w)
    return 0

def group_next(o:mutbuf, w:mutbuf) -> u32:
    used = get(w, G_DIR_USED)
    size = get(w, G_DIR_SIZE)
    while used < size:
        if size - used < 20:
            sc_error(w, E_EMPTY, 5)
            return group_failed(o, w)
        row = SC_DENTS + used
        length = getn(w, row + 16, 2)
        if length < 20 or length > size - used:
            sc_error(w, E_EMPTY, 5)
            return group_failed(o, w)
        name_size = 0
        while name_size < length - 19 and byte(w, row + 19 + name_size) != 0:
            name_size = name_size + 1
        if name_size == length - 19:
            sc_error(w, E_EMPTY, 5)
            return group_failed(o, w)
        used = used + length
        put(w, G_DIR_USED, used)
        dot = name_size == 1 and byte(w, row + 19) == 46
        dotdot = name_size == 2 and getn(w, row + 19, 2) == 11822
        if dot == False and dotdot == False:
            copy(w, SC_NAME, row + 19, name_size)
            store(w, SC_NAME + name_size, 0)
            put(w, G_ENTRY_SIZE, name_size)
            put(w, G_ERROR_CONTEXT, 0)
            return call(o, w, 3512, 228, 1, SC_STAT, 0, 0, 0, 0, 12)
    put(w, G_DIR_SIZE, 0)
    put(w, G_DIR_USED, 0)
    return call(o, w, 3511, 217, get(w, G_DIR_FD), SC_DENTS, 32768, 0, 0, 0, 12)

def group_kill(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 3530, 62, 0 - get(w, G_PID), 9, 0, 0, 0, 0, 0)

def group_stop(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 3530:
        if result != 0 and result != NEG3:
            sc_result_error(w, E_GROUP_STOP, result)
            return group_failed(o, w)
        return call(o, w, 3531, 228, 1, SC_STAT, 0, 0, 0, 0, 12)
    if phase == 3531:
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return group_failed(o, w)
        if sc_now(w) >= get(w, G_DEADLINE):
            sc_error(w, E_GROUP_TIMEOUT, 0)
            return group_failed(o, w)
        put(w, SC_STAT, 0)
        put(w, SC_STAT + 8, 10000000)
        return call(o, w, 3532, 230, 1, 0, SC_STAT, SC_STAT + 16, 0, 0, 240)
    if phase == 3532:
        if result == NEG4:
            copy(w, SC_STAT, SC_STAT + 16, 16)
            return call(o, w, 3532, 230, 1, 0, SC_STAT, SC_STAT + 16, 0, 0, 240)
        if result != 0:
            sc_result_error(w, E_EMPTY, result)
            return group_failed(o, w)
        return group_wait(o, w)
    return 0

def group_failed(o:mutbuf, w:mutbuf) -> u32:
    if get(w, G_FD) != NONE:
        return call(o, w, 3590, 3, get(w, G_FD), 0, 0, 0, 0, 0, 0)
    if get(w, G_DIR_FD) != NONE:
        return call(o, w, 3591, 3, get(w, G_DIR_FD), 0, 0, 0, 0, 0, 0)
    return sc_finish(w)

def group_close(o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 3590:
        put(w, G_FD, NONE)
    elif phase == 3591:
        put(w, G_DIR_FD, NONE)
    return group_failed(o, w)

def group_stat(w:mutbuf, at:u64, size:u64, group:u64) -> u64:
    if size > 16384:
        return sc_error(w, E_STAT_BOUND, 0)
    suffix = size
    while suffix != 0 and byte(w, at + suffix - 1) != 41:
        suffix = suffix - 1
    if suffix == 0:
        return sc_error(w, E_STAT_BAD, 0)
    if sc_utf8(w, at + suffix, size - suffix) == 0:
        return sc_utf_error(w)
    end = at + size
    cursor = sc_word(w, at + suffix, end)
    put(w, G_FIRST_AT, get(w, G_FIELD_AT))
    put(w, G_FIRST_SIZE, get(w, G_FIELD_SIZE))
    cursor = sc_word(w, cursor, end)
    cursor = sc_word(w, cursor, end)
    if get(w, G_FIELD_SIZE) == 0:
        return sc_error(w, E_STAT_ABSENT, 0)
    found = sc_i32(w, get(w, G_FIELD_AT), get(w, G_FIELD_SIZE))
    if get(w, G_INT_ERROR) != 0:
        return sc_error(w, get(w, G_INT_ERROR), 0)
    state = byte(w, get(w, G_FIRST_AT))
    if found == group and (get(w, G_FIRST_SIZE) != 1 or (state != 90 and state != 88)):
        put(w, G_MEMBERS, get(w, G_MEMBERS) + 1)
    return 1

def group_visibility(w:mutbuf, at:u64, size:u64) -> u64:
    if sc_utf8(w, at, size) == 0:
        return sc_utf_error(w)
    end = at + size
    seen = 0
    while at < end:
        line_end = at
        while line_end < end and byte(w, line_end) != 10:
            line_end = line_end + 1
        cursor = at
        field = 0
        is_proc = 0
        while cursor < line_end:
            cursor = sc_word(w, cursor, line_end)
            start = get(w, G_FIELD_AT)
            length = get(w, G_FIELD_SIZE)
            if length == 0:
                cursor = line_end
            if field == 4:
                if length == 5 and getn(w, start, 4) == 1869770799 and byte(w, start + 4) == 99:
                    is_proc = 1
                    seen = 1
            elif field > 4 and is_proc == 1:
                option = start
                while option < start + length:
                    stop = option
                    while stop < start + length and byte(w, stop) != 44:
                        stop = stop + 1
                    count = stop - option
                    if count >= 8 and getn(w, option, 8) == 4423776665443002728:
                        allowed = count == 9 and byte(w, option + 8) == 48
                        if count == 11 and getn(w, option + 8, 3) == 6710895:
                            allowed = True
                        if allowed == False:
                            return sc_error(w, E_RESTRICTED, 0)
                    option = stop + 1
            field = field + 1
        at = line_end + 1
    if seen == 0:
        return sc_error(w, E_NO_PROC, 0)
    return 1
'''

def source_program():return compose(POLICY)
def main():
 p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args()
 doc=document(source_program(),'system_jobctl_scratch_group');text=render_assembly(doc);path=ROOT/'examples/hia_bootstrap/system_jobctl_scratch_group.hepta'
 if a.check:assert path.read_text()==text
 else:path.write_text(text)
 print(path.name,len(text),'functions',len(doc['functions']),'blocks',sum(len(f['blocks'])for f in doc['functions']),'ops',sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
