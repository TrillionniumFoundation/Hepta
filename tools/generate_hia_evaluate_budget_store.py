"""Project an authenticated Evaluate budget receipt into the native Store protocol."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_settlement import POLICY as SETTLEMENT
from tools.generate_hia_worker_evaluate_case import source_program as case_source
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/evaluate_budget_store.hepta')
PACKER = SOURCE.with_name('evaluate_budget_store_packer.hepta')
PACK_MAGIC = int.from_bytes(b'HIAEBS01', 'little')

# Input is a private, sealed HIAEBRS1 receipt appended to the expected Store
# request ordinal, Context and owner. Frame zero belongs to Store startup.
POLICY = '''
def command(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 345 or length(s) > 16384 or length(o) < 16384:
        return BAD
    request = read_word(s,8)
    if read_word(s,0) != INPUT or request == 0 or (read_word(s,16) & 4294967295) != CTX:
        return BAD
    if hexadecimal(s,20,32) == False or hexadecimal(s,52,64) == False:
        return BAD
    at = 116
    if read_word(s,at) != RECEIPT or read_word(s,at+8) != 0 or read_word(s,at+56) != 1:
        return BAD
    seq = read_word(s,at+24)
    action = read_word(s,at+16)
    phase = read_word(s,at+40)
    if seq == 0 or seq != read_word(s,at+48) or read_word(s,at+32) > 86400000:
        return BAD
    held = read_word(s,at+104)
    found = read_word(s,at+112)
    if held > 1 or found > 1 or read_word(s,at+120) != 0:
        return BAD
    old = read_word(s,at+72)
    new = read_word(s,at+88)
    charge = read_word(s,at+96)
    if read_word(s,at+64) != 36 or read_word(s,at+80) != 64 or old > 4300 or new > 4300 or charge == 0 or charge > 4300:
        return BAD
    if length(s) != 344+old+new+charge or same(s,16,244,36) == False or same(s,52,280+old,64) == False:
        return BAD
    updated = 344+old
    if (old != 0 and digits(s,280,old) == False) or (new != 0 and digits(s,updated,new) == False) or digits(s,updated+new,charge) == False:
        return BAD
    if new != 0 and sum_matches(s,280,old,updated,new,updated+new,charge) == False:
        return BAD
    if action == 1 and phase == 1:
        return header(o,request,21,0,0)
    if action == 2 and (phase == 2 or phase == 4):
        put(o,48,QUERY)
        put(o,56,1)
        put(o,64,1)
        put(o,72,92)
        append_text(s,o,80,56,16,36)
        return header(o,request,27,17,92)
    if held != 1 or found != 1 or old == 0:
        return BAD
    if action == 6 and phase == 5:
        return header(o,request,2,0,0)
    if phase != 3:
        return BAD
    put(o,48,UPDATE)
    put(o,56,1)
    put(o,72,0)
    if action == 4 and new == 0:
        put(o,64,6)
        put(o,80,3)
        pos = append_text(s,o,88,112,52,64)
        pos = append_text(s,o,112,pos,16,36)
        pos = append_text(s,o,136,pos,280,old)
        return header(o,request,27,1,pos)
    if action == 5 and new != 0:
        put(o,64,7)
        put(o,80,4)
        pos = append_text(s,o,88,136,updated,new)
        pos = append_text(s,o,112,pos,16,36)
        pos = append_text(s,o,136,pos,280,old)
        pos = append_text(s,o,160,pos,52,64)
        return header(o,request,27,1,pos)
    return BAD

def sum_matches(s:readbuf, a:u64, an:u64, b:u64, bn:u64, c:u64, cn:u64) -> bool:
    if an == 0 or an > bn or cn > bn:
        return False
    carry = 0
    i = 0
    while i < bn:
        value = carry
        if i < an:
            value = value+widen(byte(s,a+an-i-1))-48
        if i < cn:
            value = value+widen(byte(s,c+cn-i-1))-48
        carry = choose(value >= 10,1,0)
        if widen(byte(s,b+bn-i-1)) != 48+value-10*carry:
            return False
        i = i+1
    return carry == 0

def append_text(s:readbuf, o:mutbuf, cell:u64, offset:u64, start:u64, size:u64) -> u64:
    put(o,cell,3)
    put(o,cell+8,offset)
    put(o,cell+16,size)
    copy_wire(s,o,start,48+offset,size)
    return offset+size

def header(o:mutbuf, request:u64, kind:u64, target:u64, size:u64) -> u32:
    put(o,0,COMMAND)
    put(o,8,1)
    put(o,16,request)
    put(o,24,kind)
    put(o,32,target)
    put(o,40,size)
    return 48+size
'''


def program():
    tags = {'INPUT': b'HIAEBC01', 'RECEIPT': b'HIAEBRS1', 'CTX': b'ctx-',
            'COMMAND': b'HIATCM01', 'QUERY': b'HIAQPA01', 'UPDATE': b'HIAUPB01'}
    constants = {name: int.from_bytes(value, 'little') for name, value in tags.items()}
    constants['BAD'] = 4294967293
    source = re.sub(r'\b(' + '|'.join(constants) + r')\b', lambda match: str(constants[match[0]]), POLICY)
    helpers = [function(SETTLEMENT, name) for name in ('same', 'hexadecimal', 'digits', 'copy_wire')]
    case = case_source()
    helpers.extend(function(case, name) for name in ('read_word', 'put', 'widen'))
    return '\n'.join([source, *helpers])


def packer_document():
    from tools.generate_hia_native_filter import document as packer
    return packer(magic=PACK_MAGIC, module=PACKER.stem, wire_bytes=16384, output_bytes=16384,
                  workspace_bytes=4096)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)))
    PACKER.write_text(render_assembly(packer_document()))
