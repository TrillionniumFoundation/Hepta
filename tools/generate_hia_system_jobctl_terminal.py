"""Typed Exit and TerminalWitness decoding for the original privileged jobctl.

Unknown typed fields retain serde IgnoredAny semantics. Known fields preserve
the original integer, Unicode, optional-field and enum forms. No filesystem or
process observation is made by this pure HIA companion.
"""
from __future__ import annotations
import argparse,ast,re
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_system_jobctl_record as record

ROOT=Path(__file__).resolve().parents[1]
EXIT_FIELDS=('job_id','nonce','exit_code','timed_out','cancelled','at_unix_ms',
             'terminal_protocol','output_complete','output_durable','capture','scratch_cleanup')
WITNESS_FIELDS=('job_id','nonce','terminal_protocol','exit_sha256')
STREAM_FIELDS=('seen','saved','eof','truncated','drain_timeout','read_error',
               'write_error','sync_error','synced')
RETAINED_FIELDS=('schema','job_id','launch_nonce','directory','state','device','inode','error',
                 'removed','durable','worker_adopted','original_process_group_stopped','original_child_reaped')
CONSTANTS=dict(STATE_BYTES=128<<20,NONE=(1<<64)-1,TERMINAL_MODE=54000,
 T_PROTOCOL=54024,T_CAPTURE=54032,T_SCRATCH=54056,T_SCRATCH_SIZE=54064,
 T_WITNESS_PROTOCOL=54080,T_ERROR=54088,
 T_VALUE_SPANS=56200,T_VALUE_FIELDS=56416,
 EXIT_SPANS=54272,EXIT_VALUES=54528,CAPTURE_SPANS=54784,
 STREAM_SPANS=54912,STREAM_VALUES=55360,WITNESS_SPANS=55808,WITNESS_VALUES=55936,
 SCAN_NEXT=56064,SCAN_SIZE=56072,T_CURSOR=56080,
 KEY=45056,STACK=68<<20,RECORD_DATA=102<<20,RECORD_CAP=4<<20)

POLICY=r'''
def terminal(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 4194304 or length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    mode = get(w, TERMINAL_MODE)
    if mode != 3 and length(s) > 1048577:
        return 0
    put(w, T_ERROR, 0)
    if mode == 0:
        put(w, T_CURSOR, RECORD_DATA)
        put(w, T_PROTOCOL, 0)
        put(w, T_CAPTURE, 0)
        put(w, T_SCRATCH, NONE)
        put(w, T_SCRATCH_SIZE, 0)
        end = collect(s, w, 0, 0, EXIT_SPANS, 11, 63)
        if end == NONE or whitespace(s, end) != length(s):
            return 0
        return decode_exit(s, w)
    if mode == 1:
        put(w, T_CURSOR, RECORD_DATA + 2097152)
        put(w, T_WITNESS_PROTOCOL, 0)
        end = collect(s, w, 0, 1, WITNESS_SPANS, 4, 15)
        if end == NONE or whitespace(s, end) != length(s):
            return 0
        index = 0
        while index < 4:
            kind = choose(index == 2, 7, 1)
            if primitive(s, w, WITNESS_SPANS + index * 16, WITNESS_VALUES + index * 16, kind) == 0:
                return 0
            index = index + 1
        put(w, T_WITNESS_PROTOCOL, protocol_id(w, get(w, WITNESS_VALUES + 32), get(w, WITNESS_VALUES + 40)))
        return 1
    if mode == 2:
        return validate_capture(w)
    if mode == 3:
        # This mode consumes the already validated/canonicalized whole Value.
        # Unknown fields can then be skipped without reinterpreting their
        # numbers through the independent integer-only Request arena.
        put(w, T_CURSOR, RECORD_DATA)
        end = collect(s, w, 0, 4, T_VALUE_SPANS, 13, 8191)
        if end == NONE or whitespace(s, end) != length(s):
            return 0
        index = 0
        while index < 13:
            kind = choose(index < 5 or index == 7, 1, choose(index < 8, 9, 4))
            if primitive(s, w, T_VALUE_SPANS + index * 16, T_VALUE_FIELDS + index * 16, kind) == 0:
                return 0
            index = index + 1
        return 1
    return 0

def collect(s:readbuf, w:mutbuf, at:u64, kind:u64, table:u64, count:u64, required:u64) -> u64:
    index = 0
    while index < count:
        put(w, table + index * 16, NONE)
        put(w, table + index * 16 + 8, 0)
        index = index + 1
    at = whitespace(s, at)
    if at < length(s) and byte(s, at) == 91 and kind != 4:
        return collect_sequence(s, w, at, table, count, required)
    if at == length(s) or byte(s, at) != 123:
        return NONE
    at = whitespace(s, at + 1)
    mask = 0
    if at < length(s) and byte(s, at) == 125:
        return choose(required == 0, at + 1, NONE)
    while at < length(s):
        field = read_field(s, w, at, kind)
        if field == NONE:
            return NONE
        at = whitespace(s, get(w, SCAN_NEXT))
        if at == length(s) or byte(s, at) != 58:
            return NONE
        at = whitespace(s, at + 1)
        end = skip_value(s, w, at)
        if end == NONE:
            return NONE
        if field != 0:
            if mask & (1 << (field - 1)) != 0:
                return NONE
            mask = mask | (1 << (field - 1))
            put(w, table + (field - 1) * 16, at)
            put(w, table + (field - 1) * 16 + 8, end - at)
        at = whitespace(s, end)
        if at == length(s):
            return NONE
        if byte(s, at) == 125:
            return choose(mask & required == required, at + 1, NONE)
        if byte(s, at) != 44:
            return NONE
        at = whitespace(s, at + 1)
    return NONE

def collect_sequence(s:readbuf, w:mutbuf, at:u64, table:u64, count:u64, required:u64) -> u64:
    # serde derive accepts positional sequences as well as maps. Missing
    # trailing defaults are represented by the already cleared span slots.
    at = whitespace(s, at + 1)
    index = 0
    mask = 0
    if at < length(s) and byte(s, at) == 93:
        return choose(required == 0, at + 1, NONE)
    while at < length(s):
        if index == count:
            return NONE
        end = skip_value(s, w, at)
        if end == NONE:
            return NONE
        put(w, table + index * 16, at)
        put(w, table + index * 16 + 8, end - at)
        mask = mask | (1 << index)
        index = index + 1
        at = whitespace(s, end)
        if at == length(s):
            return NONE
        if byte(s, at) == 93:
            return choose(mask & required == required, at + 1, NONE)
        if byte(s, at) != 44:
            return NONE
        at = whitespace(s, at + 1)
    return NONE

def read_field(s:readbuf, w:mutbuf, at:u64, kind:u64) -> u64:
    if at == length(s) or byte(s, at) != 34:
        return NONE
    at = at + 1
    count = 0
    ascii = 1
    while True:
        unit = decoded(s, at)
        point = unit & 4294967295
        if point == 1114113:
            return NONE
        at = unit >> 32
        if point == 1114112:
            put(w, SCAN_NEXT, at)
            if ascii == 0 or count > 64:
                return 0
            if kind == 0:
                return exit_key(w, KEY, count)
            if kind == 1:
                return witness_key(w, KEY, count)
            if kind == 2:
                return capture_key(w, KEY, count)
            if kind == 4:
                return retained_key(w, KEY, count)
            return stream_key(w, KEY, count)
        if point > 127:
            ascii = 0
        if count < 64:
            store(w, KEY + count, point & 255)
        count = count + 1
    return NONE

def null_span(s:readbuf, w:mutbuf, span:u64) -> bool:
    source = get(w, span)
    return source == NONE or (get(w, span + 8) == 4 and word_null(s, source) == 1)

def primitive(s:readbuf, w:mutbuf, span:u64, target:u64, kind:u64) -> u64:
    source = get(w, span)
    size = get(w, span + 8)
    put(w, target, NONE)
    put(w, target + 8, 0)
    if null_span(s, w, span):
        return choose(kind == 5 or kind == 6 or kind == 8, 1, 0)
    if source == NONE or source > length(s) or size > length(s) - source:
        return 0
    if kind == 1 or kind == 6 or kind == 7 or kind == 8:
        at = get(w, T_CURSOR)
        if (kind == 7 or kind == 8) and byte(s, source) == 123:
            if read_protocol(s, w, source, at) == 0:
                return 0
        elif byte(s, source) != 34 or read_text(s, w, source, at) == 0:
            return 0
        if get(w, SCAN_NEXT) != source + size:
            return 0
        if (kind == 7 or kind == 8) and protocol_id(w, at, get(w, SCAN_SIZE)) == 0:
            return 0
        put(w, target, at)
        put(w, target + 8, get(w, SCAN_SIZE))
        put(w, T_CURSOR, at + get(w, SCAN_SIZE))
        return 1
    if kind == 2:
        if unsigned128(s, source, size) == 0:
            return 0
        at = get(w, T_CURSOR)
        input_copy(s, w, at, source, size)
        put(w, target, at)
        put(w, target + 8, size)
        put(w, T_CURSOR, at + size)
        return 1
    if kind == 3:
        value = signed32(s, w, source, size)
    elif kind == 9:
        value = unsigned64(s, w, source, size)
    else:
        value = NONE
        if size == 4 and byte(s, source) == 116 and byte(s, source + 1) == 114 and byte(s, source + 2) == 117 and byte(s, source + 3) == 101:
            value = 1
        elif size == 5 and byte(s, source) == 102 and byte(s, source + 1) == 97 and byte(s, source + 2) == 108 and byte(s, source + 3) == 115 and byte(s, source + 4) == 101:
            value = 0
        if value == NONE:
            return 0
    put(w, target, value)
    return choose(get(w, T_ERROR) == 0, 1, 0)

def unsigned64(s:readbuf, w:mutbuf, at:u64, size:u64) -> u64:
    if size == 0 or size > 20 or (size > 1 and byte(s, at) == 48):
        put(w, T_ERROR, 1)
        return 0
    value = 0
    index = 0
    while index < size:
        point = byte(s, at + index)
        if point < 48 or point > 57:
            put(w, T_ERROR, 1)
            return 0
        digit = point - 48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            put(w, T_ERROR, 1)
            return 0
        value = value * 10 + digit
        index = index + 1
    return value

def signed32(s:readbuf, w:mutbuf, at:u64, size:u64) -> u64:
    negative = size != 0 and byte(s, at) == 45
    if negative:
        at = at + 1
        size = size - 1
    value = unsigned64(s, w, at, size)
    if get(w, T_ERROR) != 0 or value > choose(negative, 2147483648, 2147483647) or (negative and value == 0):
        put(w, T_ERROR, 1)
        return 0
    return choose(negative, 0 - value, value)

def decode_exit(s:readbuf, w:mutbuf) -> u32:
    index = 0
    while index < 9:
        kind = exit_kind(index)
        if primitive(s, w, EXIT_SPANS + index * 16, EXIT_VALUES + index * 16, kind) == 0:
            return 0
        index = index + 1
    protocol = get(w, EXIT_VALUES + 96)
    if protocol != NONE:
        put(w, T_PROTOCOL, protocol_id(w, protocol, get(w, EXIT_VALUES + 104)))
    if null_span(s, w, EXIT_SPANS + 144) == False:
        source = get(w, EXIT_SPANS + 144)
        end = collect(s, w, source, 2, CAPTURE_SPANS, 2, 3)
        if end == NONE or end != source + get(w, EXIT_SPANS + 152):
            return 0
        side = 0
        while side < 2:
            source = get(w, CAPTURE_SPANS + side * 16)
            end = collect(s, w, source, 3, STREAM_SPANS + side * 160, 9, 287)
            if end == NONE or end != source + get(w, CAPTURE_SPANS + side * 16 + 8):
                return 0
            index = 0
            while index < 9:
                kind = choose(index < 2, 9, choose(index >= 5 and index < 8, 6, 4))
                if primitive(s, w, STREAM_SPANS + side * 160 + index * 16, STREAM_VALUES + side * 160 + index * 16, kind) == 0:
                    return 0
                index = index + 1
            side = side + 1
        put(w, T_CAPTURE, 1)
    if null_span(s, w, EXIT_SPANS + 160) == False:
        put(w, T_SCRATCH, get(w, EXIT_SPANS + 160))
        put(w, T_SCRATCH_SIZE, get(w, EXIT_SPANS + 168))
    return 1

def exit_kind(index:u64) -> u64:
    if index < 2:
        return 1
    if index == 2:
        return 3
    if index < 5:
        return 4
    if index == 5:
        return 2
    if index == 6:
        return 8
    return 5

def stream_complete(w:mutbuf, side:u64) -> u64:
    at = STREAM_VALUES + side * 160
    return choose(get(w, at + 32) == 1 and get(w, at + 48) == 0 and get(w, at + 64) == 0 and get(w, at + 80) == NONE and get(w, at + 96) == NONE and get(w, at + 112) == NONE and get(w, at) == get(w, at + 16), 1, 0)

def validate_capture(w:mutbuf) -> u32:
    if get(w, T_PROTOCOL) == 1:
        if get(w, T_CAPTURE) == 0:
            return 0
        complete = stream_complete(w, 0) == 1 and stream_complete(w, 1) == 1
        durable = complete and get(w, STREAM_VALUES + 128) == 1 and get(w, STREAM_VALUES + 288) == 1
        if get(w, EXIT_VALUES + 112) != choose(complete, 1, 0) or get(w, EXIT_VALUES + 128) != choose(durable, 1, 0):
            return 0
        side = 0
        while side < 2:
            at = STREAM_VALUES + side * 160
            if get(w, at + 16) > 16777216 or get(w, at + 16) > get(w, at):
                return 0
            side = side + 1
        return 1
    return choose(get(w, T_CAPTURE) == 0 and get(w, EXIT_VALUES + 112) == NONE and get(w, EXIT_VALUES + 128) == NONE, 1, 0)
'''

def source_program():
    source=POLICY
    expanded=record.source_program()
    functions={node.name:ast.get_source_segment(expanded,node) for node in ast.parse(expanded).body if isinstance(node,ast.FunctionDef)}
    raw={node.name:ast.get_source_segment(record.POLICY,node) for node in ast.parse(record.POLICY).body if isinstance(node,ast.FunctionDef)}
    for name in ('read_text','read_protocol','ignored_string','skip_value','unsigned128','word_null','input_copy'):
        functions[name]=raw[name]
    defined={node.name for node in ast.parse(source).body if isinstance(node,ast.FunctionDef)}
    while True:
        needed={node.func.id for node in ast.walk(ast.parse(source)) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name)}-defined
        missing=sorted(needed & functions.keys())
        if not missing:break
        for name in missing:source+='\n'+functions[name]+'\n';defined.add(name)
    for name,values in (('exit_key',EXIT_FIELDS),('witness_key',WITNESS_FIELDS),('capture_key',('stdout','stderr')),('stream_key',STREAM_FIELDS),('retained_key',RETAINED_FIELDS)):
        source+=record.matcher(name,values)
    for key in sorted(CONSTANTS,key=len,reverse=True):source=re.sub(r'\b'+key+r'\b',str(CONSTANTS[key]),source)
    return source

def main():
    p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args()
    doc=document(source_program(),'system_jobctl_terminal');text=render_assembly(doc);path=ROOT/'examples/hia_bootstrap/system_jobctl_terminal.hepta'
    if a.check:assert path.read_text()==text
    else:path.write_text(text)
    print(path.name,len(text),'functions',len(doc['functions']),'blocks',sum(len(f['blocks']) for f in doc['functions']),flush=True)
if __name__=='__main__':main()
