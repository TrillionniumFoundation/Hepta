"""Inspect actual independently admitted canonical compiler call structure."""
import ast
import re
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import document
from tools.generate_hia_cold_qualification_alpha import SOURCE as ALPHA

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''def structure(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 20 or length(s) > 1048576 or length(w) < 32:
        return 4294967295
    if length(o) < 40:
        return 4294967294
    if uint(s, 0, 8) != HEADER or uint(s, 8, 3) != HEADER_TAIL or byte(s, length(s) - 1) != 10:
        return 4294967295
    functions = 0
    blocks = 0
    backward = 0
    tails = 0
    caller = 18446744073709551615
    begin = 0
    while begin < length(s):
        end = begin
        while end < length(s) and byte(s, end) != 10:
            end = end + 1
        if end == length(s):
            return 4294967295
        if end - begin >= 5 and uint(s, begin, 4) == FUNCTION:
            caller = decimal(s, w, begin + 4, end)
            if caller != functions or get(w, 24) == begin + 4 or get(w, 24) >= end or byte(s, get(w, 24)) != 40:
                return 4294967295
            functions = functions + 1
        if end - begin >= 8 and uint(s, begin, 7) == BLOCK:
            blocks = blocks + 1
        pos = begin
        call_at = end
        while pos + 8 <= end:
            if uint(s, pos, 8) == CALL:
                call_at = pos
            pos = pos + 1
        if call_at != end:
            if caller == 18446744073709551615:
                return 4294967295
            pos = call_at + 8
            found = 0
            callee = 0
            while pos + 12 < end:
                if uint(s, pos, 8) == ATTRIBUTE and uint(s, pos + 8, 4) == ATTRIBUTE_TAIL:
                    callee = decimal(s, w, pos + 12, end)
                    if get(w, 24) == pos + 12 or get(w, 24) + 2 != end or uint(s, get(w, 24), 2) != 32034:
                        return 4294967295
                    found = found + 1
                pos = pos + 1
            if found != 1 or callee >= 128:
                return 4294967295
            if callee < caller:
                backward = backward + 1
            if callee == caller and end - begin >= 4 and uint(s, begin, 3) == RESULT:
                value = decimal(s, w, begin + 3, end)
                after = get(w, 24)
                if after < end and after > begin + 3 and byte(s, after) == 58:
                    next = end + 1
                    if length(s) - next >= 9 and uint(s, next, 7) == RETURN:
                        result = decimal(s, w, next + 7, length(s))
                        after = get(w, 24)
                        if result == value and after > next + 7 and after + 2 <= length(s) and uint(s, after, 2) == 2601:
                            tails = tails + 1
        begin = end + 1
    if functions == 0 or functions > 128 or blocks == 0 or backward == 0 or tails == 0:
        return 4294967295
    put(o, 0, RECEIPT)
    put(o, 8, functions)
    put(o, 16, blocks)
    put(o, 24, backward)
    put(o, 32, tails)
    return 40
'''


def source():
    nodes={n.name:ast.get_source_segment(ALPHA,n) for n in ast.parse(ALPHA).body}
    text=SOURCE+'\n'+'\n\n'.join(nodes[n] for n in ('decimal','uint','get','put'))
    tags={'HEADER':b'hia-asm.','HEADER_TAIL':b'v1 ','FUNCTION':b'fn f','BLOCK':b'block b',
        'CALL':b' = call(','ATTRIBUTE':b'"functio','ATTRIBUTE_TAIL':b'n":"f',
        'RESULT':b'  v','RETURN':b'  ret(v','RECEIPT':b'HIAQST01'}
    # The attribute suffix contains five bytes, so retain its exact extent.
    text=text.replace('pos + 12 < end','pos + 13 < end').replace('pos + 8, 4','pos + 8, 5').replace('pos + 12','pos + 13')
    for name,raw in tags.items():text=re.sub(r'\b'+name+r'\b',str(int.from_bytes(raw,'little')),text)
    return text


if __name__=='__main__':
    p=ROOT/'examples/hia_bootstrap/cold_source_structure.hepta'
    p.write_text(render_assembly(document(source(),'cold_source_structure')))
    print(p.name,p.stat().st_size)
