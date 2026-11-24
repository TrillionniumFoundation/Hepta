"""Author original supervisor path, argv and cleared-environment composition."""
from __future__ import annotations
import argparse
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_system_jobctl_supervisor_common import helpers,literals,substitute
ROOT=Path(__file__).resolve().parents[1]

POLICY=r'''
def vectors(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    put(w, SUP_INVALID, 0)
    prefix = get(w, SPEC_FIELDS + 48)
    prefix_size = get(w, SPEC_FIELDS + 56)
    source = prefix
    size = prefix_size
    if present(w, 4) == 1:
        child = get(w, TABLE + 32)
        source = ARENA + node(w, child, 24)
        size = node(w, child, 32)
    if strip_path(w, source, size, prefix, prefix_size) == 0:
        return 0
    size = mapped_path(w, SUP_CWD_PATH)
    put(w, SUP_CWD, SUP_CWD_PATH)
    put(w, SUP_CWD_SIZE, size)
    mark_nul(w, SUP_CWD_PATH, size)
    source = SUP_TEMP
    size = 0
    child = get(w, TABLE + 16)
    if child != NONE:
        source = ARENA + node(w, child, 24)
        size = node(w, child, 32)
    if strip_path(w, source, size, prefix, prefix_size) == 1:
        size = mapped_path(w, SUP_EXE_PATH)
    else:
        copy(w, SUP_EXE_PATH, source, size)
        store(w, SUP_EXE_PATH + size, 0)
    put(w, SUP_EXE, SUP_EXE_PATH)
    put(w, SUP_EXE_SIZE, size)
    mark_nul(w, SUP_EXE_PATH, size)
    put(w, SUP_ARG_OFFSETS, SUP_EXE_PATH)
    put(w, SUP_ARG_COUNT, 1)
    at = SUP_ARG_TEXT
    child = get(w, TABLE + 24)
    if child != NONE:
        child = node(w, child, 24)
    while child != NONE:
        size = node(w, child, 32)
        source = ARENA + node(w, child, 24)
        if size >= SUP_ARG_END - at or get(w, SUP_ARG_COUNT) >= 524287:
            return 0
        put(w, SUP_ARG_OFFSETS + get(w, SUP_ARG_COUNT) * 8, at)
        put(w, SUP_ARG_COUNT, get(w, SUP_ARG_COUNT) + 1)
        copy(w, at, source, size)
        mark_nul(w, at, size)
        store(w, at + size, 0)
        at = at + size + 1
        child = node(w, child, 16)
    put(w, SUP_ARG_OFFSETS + get(w, SUP_ARG_COUNT) * 8, NONE)
    put(w, SUP_ENV_COUNT, 0)
    put(w, SUP_ENV_CURSOR, 0)
    put(w, SUP_ENV_BASE, 0)
    put(w, SUP_TEXT_CURSOR, SUP_ENV_TEXT)
    while get(w, SUP_ENV_CURSOR) < get(w, ENV_COUNT) or get(w, SUP_ENV_BASE) < 6:
        if env_next(w) == 0:
            return 0
    put(w, SUP_ENV_OFFSETS + get(w, SUP_ENV_COUNT) * 8, NONE)
    return 1

def env_next(w:mutbuf) -> u64:
    base = get(w, SUP_ENV_BASE)
    index = get(w, SUP_ENV_CURSOR)
    if base == 6:
        child = get(w, ENV_INDEX + index * 8)
        put(w, SUP_ENV_CURSOR, index + 1)
        return request_env(w, child)
    key_size = base_key(w, base, SUP_TEMP) - SUP_TEMP
    if index < get(w, ENV_COUNT):
        child = get(w, ENV_INDEX + index * 8)
        order = compare_bytes(w, ARENA + node(w, child, 40), node(w, child, 48), SUP_TEMP, key_size)
        if order == 0:
            put(w, SUP_ENV_CURSOR, index + 1)
            return request_env(w, child)
        if order == 1:
            put(w, SUP_ENV_CURSOR, index + 1)
            if base >= 2:
                put(w, SUP_ENV_BASE, base + 1)
                return request_env(w, child)
    put(w, SUP_ENV_BASE, base + 1)
    if base == 0 and get(w, SUP_SCRATCH) == 0:
        return 1
    source = SUP_JOB
    size = get(w, SUP_JOB_SIZE)
    if base == 0:
        source = get(w, SUP_BINDING)
        size = get(w, SUP_BINDING_SIZE)
    elif base >= 2:
        source = SUP_TEMP + 128
        size = base_value(w, base, source) - source
    return env_emit(w, SUP_TEMP, key_size, source, size)

def request_env(w:mutbuf, child:u64) -> u64:
    size = node(w, child, 48)
    return env_emit(w, ARENA + node(w, child, 40), size, ARENA + node(w, child, 24), node(w, child, 32))

def env_emit(w:mutbuf, key:u64, key_size:u64, source:u64, size:u64) -> u64:
    at = get(w, SUP_TEXT_CURSOR)
    if key_size + size + 2 > SUP_ENV_END - at or get(w, SUP_ENV_COUNT) >= 524287:
        return 0
    put(w, SUP_ENV_OFFSETS + get(w, SUP_ENV_COUNT) * 8, at)
    put(w, SUP_ENV_COUNT, get(w, SUP_ENV_COUNT) + 1)
    copy(w, at, key, key_size)
    mark_nul(w, at, key_size)
    store(w, at + key_size, 61)
    copy(w, at + key_size + 1, source, size)
    mark_nul(w, at + key_size + 1, size)
    store(w, at + key_size + 1 + size, 0)
    if key_size == 4 and byte(w, key) == 80 and byte(w, key + 1) == 65 and byte(w, key + 2) == 84 and byte(w, key + 3) == 72:
        put(w, SUP_SEARCH_PATH, at + key_size + 1)
        put(w, SUP_SEARCH_SIZE, size)
    put(w, SUP_TEXT_CURSOR, at + key_size + size + 2)
    return 1

def base_key(w:mutbuf, index:u64, at:u64) -> u64:
    if index == 0:
        return text_engine_key(w, at)
    if index == 1:
        return text_job_key(w, at)
    if index == 2:
        return text_home_key(w, at)
    if index == 3:
        return text_lang_key(w, at)
    if index == 4:
        return text_path_key(w, at)
    return text_term_key(w, at)

def base_value(w:mutbuf, index:u64, at:u64) -> u64:
    if index == 2:
        return text_home_value(w, at)
    if index == 3:
        return text_lang_value(w, at)
    if index == 4:
        return text_path_value(w, at)
    return text_term_value(w, at)

def mark_nul(w:mutbuf, source:u64, size:u64) -> u64:
    index = 0
    while index < size:
        if byte(w, source + index) == 0:
            put(w, SUP_INVALID, 1)
        index = index + 1
    return 0

def compare_bytes(w:mutbuf, left:u64, left_size:u64, right:u64, right_size:u64) -> u64:
    index = 0
    while index < left_size and index < right_size:
        a = byte(w, left + index)
        b = byte(w, right + index)
        if a < b:
            return 0
        if a > b:
            return 2
        index = index + 1
    if left_size < right_size:
        return 0
    if left_size > right_size:
        return 2
    return 1

def component(w:mutbuf, source:u64, size:u64, cursor:u64) -> u64:
    put(w, SUP_PATH_KIND, 0)
    if cursor == 0 and size != 0:
        if byte(w, source) == 47:
            put(w, SUP_PATH_RESULT, source)
            put(w, SUP_PATH_NEXT, 1)
            put(w, SUP_PATH_KIND, 1)
            return 1
        if byte(w, source) == 46 and (size == 1 or byte(w, source + 1) == 47):
            put(w, SUP_PATH_RESULT, source)
            put(w, SUP_PATH_NEXT, 1)
            put(w, SUP_PATH_KIND, 2)
            return 1
    while cursor < size:
        while cursor < size and byte(w, source + cursor) == 47:
            cursor = cursor + 1
        start = cursor
        while cursor < size and byte(w, source + cursor) != 47:
            cursor = cursor + 1
        if cursor != start and (cursor - start != 1 or byte(w, source + start) != 46):
            put(w, SUP_PATH_RESULT, source + start)
            put(w, SUP_PATH_NEXT, cursor - start)
            put(w, SUP_PATH_KIND, 3)
            return cursor
    return size

def strip_path(w:mutbuf, source:u64, size:u64, prefix:u64, prefix_size:u64) -> u64:
    put(w, PATH_A_CURSOR, 0)
    put(w, PATH_B_CURSOR, 0)
    going = True
    while going:
        next = component(w, prefix, prefix_size, get(w, PATH_B_CURSOR))
        put(w, PATH_B_CURSOR, next)
        if get(w, SUP_PATH_KIND) == 0:
            going = False
        else:
            put(w, PATH_EXPECT_KIND, get(w, SUP_PATH_KIND))
            put(w, PATH_EXPECT_SOURCE, get(w, SUP_PATH_RESULT))
            put(w, PATH_EXPECT_SIZE, get(w, SUP_PATH_NEXT))
            next = component(w, source, size, get(w, PATH_A_CURSOR))
            put(w, PATH_A_CURSOR, next)
            if get(w, SUP_PATH_KIND) != get(w, PATH_EXPECT_KIND):
                return 0
            if compare_bytes(w, get(w, SUP_PATH_RESULT), get(w, SUP_PATH_NEXT), get(w, PATH_EXPECT_SOURCE), get(w, PATH_EXPECT_SIZE)) != 1:
                return 0
    begin = get(w, PATH_A_CURSOR)
    minimum = 0
    if begin == 0:
        if size != 0 and byte(w, source) == 47:
            minimum = 1
        elif size != 0 and byte(w, source) == 46 and (size == 1 or byte(w, source + 1) == 47):
            minimum = 1
    else:
        next = component(w, source, size, begin)
        if get(w, SUP_PATH_KIND) == 0:
            begin = size
        else:
            begin = get(w, SUP_PATH_RESULT) - source
        minimum = begin
    end = size
    going = True
    while going and end > minimum:
        if byte(w, source + end - 1) == 47:
            end = end - 1
        elif byte(w, source + end - 1) == 46 and (end == 1 or byte(w, source + end - 2) == 47):
            end = end - 1
        else:
            going = False
    put(w, SUP_PATH_RESULT, source + begin)
    put(w, SUP_PATH_NEXT, end - begin)
    return 1

def mapped_path(w:mutbuf, target:u64) -> u64:
    source = get(w, SUP_PATH_RESULT)
    size = get(w, SUP_PATH_NEXT)
    at = target
    if size == 0 or byte(w, source) != 47:
        at = text_workspace(w, at)
    copy(w, at, source, size)
    store(w, at + size, 0)
    return at + size - target
'''

def source_program():
    values={'workspace':'/workspace/','engine_key':'HEPTA_RUNTIME_ENGINE_SCRATCH','job_key':'HEPTA_RUNTIME_JOB_ID','home_key':'HOME','lang_key':'LANG','path_key':'PATH','term_key':'TERM','home_value':'/tmp','lang_value':'C.UTF-8','path_value':'/usr/bin:/bin','term_value':'xterm-256color'}
    return substitute(POLICY+'\n'+helpers(['get','put','putn','copy','node','present'])+literals(values))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    doc=document(source_program(),'system_jobctl_supervisor_vectors');text=render_assembly(doc);p=ROOT/'examples/hia_bootstrap/system_jobctl_supervisor_vectors.hepta'
    if args.check:assert p.read_text()==text
    else:p.write_text(text)
    print(p.name,len(doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
