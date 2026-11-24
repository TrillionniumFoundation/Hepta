"""Author the original isolated supervisor Spec codec in HIA.

The outer serde struct accepts maps and sequences. Unknown map values follow
IgnoredAny, while the nested Request is passed to the existing strict HIA
Request owner. Both accepted representations render the same struct bytes.
"""
from __future__ import annotations
import argparse,ast,re
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document,POLICY as REQUEST_POLICY
from tools.generate_hia_system_jobctl_record import POLICY as RECORD_POLICY,matcher,texts
from tools.generate_hia_json_preflight import SOURCE as PREFLIGHT_SOURCE
from tools.generate_hia_json_decode import _WIRE_NUMBER_SOURCE

ROOT=Path(__file__).resolve().parents[1]
FIELDS=('request','nonce','boot_id','workspace','terminal_protocol')
CONSTANTS=dict(STATE_BYTES=128<<20,NONE=(1<<64)-1,SPEC_FIELDS=60000,
 SPEC_PROTOCOL=60080,SPEC_MODE=60088,SPEC_SIZE=60096,
 RECORD_DATA=102<<20,RECORD_CAP=2<<20,QUOTE_END=124<<20,
 SPEC_OUT=120<<20,SPEC_CAP=2<<20,RAW=1<<20,REQUEST_OUT=112<<20,
 REQUEST_SIZE=928,SCAN_NEXT=41408,SCAN_SIZE=41416,KEY=45056,STACK=68<<20)

POLICY=r'''
def spec(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != STATE_BYTES or length(o) != 128:
        return 0
    if get(w, SPEC_MODE) == 0:
        if length(s) > 1048577 or decode_spec(s, w) == 0:
            return 0
        return 1
    if get(w, SPEC_MODE) != 1:
        return 0
    at = SPEC_OUT
    store(w, at, 123)
    at = field_text(w, 0, at + 1)
    size = get(w, REQUEST_SIZE)
    if size > 2097152:
        return 0
    copy(w, at, REQUEST_OUT, size)
    at = at + size
    index = 1
    while index < 5:
        source = get(w, SPEC_FIELDS + index * 16)
        if index != 4 or source != NONE:
            store(w, at, 44)
            at = field_text(w, index, at + 1)
            at = quote(w, at, source, get(w, SPEC_FIELDS + index * 16 + 8))
            if at == NONE:
                return 0
        index = index + 1
    if at >= SPEC_OUT + SPEC_CAP:
        return 0
    store(w, at, 125)
    put(w, SPEC_SIZE, at + 1 - SPEC_OUT)
    return 1

def decode_spec(s:readbuf, w:mutbuf) -> u64:
    index = 0
    while index < 5:
        put(w, SPEC_FIELDS + index * 16, NONE)
        put(w, SPEC_FIELDS + index * 16 + 8, 0)
        index = index + 1
    put(w, SPEC_PROTOCOL, 0)
    cursor = whitespace(s, 0)
    if cursor == length(s):
        return 0
    shape = byte(s, cursor)
    if shape != 123 and shape != 91:
        return 0
    closing = choose(shape == 123, 125, 93)
    cursor = whitespace(s, cursor + 1)
    if cursor == length(s) or byte(s, cursor) == closing:
        return 0
    mask = 0
    at = RECORD_DATA
    ordinal = 0
    going = True
    while going:
        ordinal = ordinal + 1
        if shape == 91:
            if ordinal > 5:
                return 0
            field = ordinal
        else:
            if cursor == length(s) or byte(s, cursor) != 34:
                return 0
            field = read_key(s, w, cursor)
            if field == NONE:
                return 0
            cursor = whitespace(s, get(w, SCAN_NEXT))
            if cursor == length(s) or byte(s, cursor) != 58:
                return 0
            cursor = whitespace(s, cursor + 1)
        if cursor == length(s):
            return 0
        if field == 0:
            cursor = skip_value(s, w, cursor)
            if cursor == NONE:
                return 0
        else:
            if mask & (1 << (field - 1)) != 0:
                return 0
            mask = mask | (1 << (field - 1))
            index = field - 1
            if index == 0:
                end = skip_value(s, w, cursor)
                if end == NONE or end - cursor > 1048576:
                    return 0
                input_copy(s, w, RAW, cursor, end - cursor)
                put(w, SPEC_FIELDS, RAW)
                put(w, SPEC_FIELDS + 8, end - cursor)
                cursor = end
            elif index == 4 and cursor + 4 <= length(s) and word_null(s, cursor) == 1:
                cursor = cursor + 4
            else:
                if index == 4 and byte(s, cursor) == 123:
                    if read_protocol(s, w, cursor, at) == 0:
                        return 0
                elif byte(s, cursor) != 34 or read_text(s, w, cursor, at) == 0:
                    return 0
                size = get(w, SCAN_SIZE)
                cursor = get(w, SCAN_NEXT)
                if index == 4:
                    protocol = protocol_id(w, at, size)
                    if protocol == 0:
                        return 0
                    put(w, SPEC_PROTOCOL, protocol)
                put(w, SPEC_FIELDS + index * 16, at)
                put(w, SPEC_FIELDS + index * 16 + 8, size)
                at = at + size
        cursor = whitespace(s, cursor)
        if cursor == length(s):
            return 0
        point = byte(s, cursor)
        if point == closing:
            going = False
        elif point != 44:
            return 0
        cursor = whitespace(s, cursor + 1)
    if cursor != length(s) or mask & 15 != 15:
        return 0
    return 1
'''

def source_program():
    source=POLICY
    for text,names in [(RECORD_POLICY,['word_null','read_key','read_text','read_protocol','ignored_string','skip_value','input_copy','copy']),
                       (REQUEST_POLICY,['get','getn','put','putn','quote','hexadecimal']),
                       (PREFLIGHT_SOURCE,['whitespace','atom','decoded','hex4'])]:
        parts={n.name:ast.get_source_segment(text,n) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
        for name in names:source+='\n'+parts[name].replace('REQUEST_OUT + REQUEST_CAP','QUOTE_END')+'\n'
    source+=_WIRE_NUMBER_SOURCE
    source+=matcher('field_id',FIELDS)+matcher('protocol_id',['captured_v1','pty_v1'])
    source+=texts('field_text',['"'+field+'":' for field in FIELDS])
    for key in sorted(CONSTANTS,key=len,reverse=True):source=re.sub(r'\b'+key+r'\b',str(CONSTANTS[key]),source)
    return source

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    doc=document(source_program(),'system_jobctl_spec');text=render_assembly(doc)
    path=ROOT/'examples/hia_bootstrap/system_jobctl_spec.hepta'
    if args.check:assert path.read_text()==text
    else:path.write_text(text)
    print(path.name,len(text),len(doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)

if __name__=='__main__':main()
