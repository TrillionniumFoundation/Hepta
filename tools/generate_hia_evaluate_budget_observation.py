"""Project native Store and paired-run observations into the HIA budget session."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_settlement import program as settlement_source
from tools.generate_hia_worker_evaluate_case import source_program as case_source
from tools.generate_hia_worker_inspection_effect import function


SOURCE = Path('examples/hia_bootstrap/evaluate_budget_observation.hepta')
PACKER = SOURCE.with_name('evaluate_budget_observation_packer.hepta')
PACK_MAGIC = int.from_bytes(b'HIAEOP01', 'little')

# HIAEBO01 has fourteen little-endian words. They bind mode, Store command
# and transaction generation, prior budget sequence, monotonic sample, outer
# deadline, maximum native ms, two retained lifetime identities, and the
# lengths of the original budget receipt and its physical observation. The
# fixed Context and owner precede both payloads. Output is one raw HIAEBRQ1.
POLICY = '''
def observation(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 212 or length(s) > 32768 or length(o) < 4700 or length(w) < 4700:
        return BAD
    if read_word(s,0) != INPUT or (read_word(s,112) & 4294967295) != CTX or hexadecimal(s,116,32) == False or hexadecimal(s,148,64) == False:
        return BAD
    mode = read_word(s,8)
    seq = read_word(s,32)
    receipt = read_word(s,96)
    total = read_word(s,104)
    if receipt > length(s)-212 or total != length(s)-212-receipt or read_word(s,72) == 0 or read_word(s,88) == 0:
        return BAD
    i = 0
    while i < 128:
        put(o,i,0)
        i = i+8
    put(o,0,REQUEST)
    put(o,16,seq)
    copy_wire(s,o,64,96,32)
    if mode == 0:
        start = read_word(s,40)
        ms = read_word(s,56)
        if seq != 0 or receipt != 0 or total != 0 or start == 0 or start >= read_word(s,48) or ms == 0 or ms > 86400000:
            return BAD
        put(o,32,1)
        put(o,40,ms)
        put(o,48,start)
        put(o,56,36)
        put(o,64,64)
        return copy_wire(s,o,112,128,100)
    if receipt < 229 or read_word(s,212) != RECEIPT or read_word(s,220) != 0 or read_word(s,268) != 1:
        return BAD
    if seq == 0 or read_word(s,236) != seq or read_word(s,260) != seq or read_word(s,276) != 36 or read_word(s,292) != 64:
        return BAD
    old = read_word(s,284)
    new = read_word(s,300)
    charged = read_word(s,308)
    if old > 4300 or new > 4300 or charged == 0 or charged > 4300 or receipt != 228+old+new+charged:
        return BAD
    if same(s,112,340,36) == False or same(s,148,376+old,64) == False or read_word(s,332) != 0:
        return BAD
    action = read_word(s,228)
    phase = read_word(s,252)
    at = 212+receipt
    if mode == 1:
        return store_event(s,o,w,at,action,phase)
    if phase != 7 or read_word(s,316) != 1 or read_word(s,324) != 1 or new != 0:
        return BAD
    if mode == 3 and total == 0 and action == 0:
        put(o,8,10)
        return 128
    if mode != 2 or total != 64 or read_word(s,at) != GATE or read_word(s,at+16) > 1 or read_word(s,at+24) != seq:
        return BAD
    operation = read_word(s,at+8)
    now = read_word(s,at+32)
    deadline = read_word(s,at+40)
    elapsed = read_word(s,at+48)
    cumulative = read_word(s,at+56)
    if deadline != read_word(s,48) or now == 0 or now > read_word(s,40) or elapsed > cumulative:
        return BAD
    if decimal_equal(s,440+old,charged,cumulative-elapsed) == False:
        return BAD
    if operation == 5 and action == 0 and elapsed == 0:
        # Zero remaining time is still an observation for the authoritative
        # session. Its refusal never opens an execution arm.
        put(o,8,5)
        put(o,24,now)
        remaining = 0
        if deadline > now:
            remaining = div_million(deadline-now)
        put(o,32,remaining)
        return 128
    if operation == 6 and action == 7:
        put(o,8,6)
        put(o,32,1)
        end = decimal(o,128,elapsed)
        put(o,40,end-128)
        return end
    return BAD

def div_million(value:u64) -> u64:
    result = 0
    shift = 17592186044416
    while shift != 0:
        power = 1000000*shift
        if value >= power:
            value = value-power
            result = result+shift
        shift = shift >> 1
    return result

def store_ack(s:readbuf, at:u64, request:u64, kind:u64, gen:u64) -> bool:
    if at > length(s) or length(s)-at != 80 or read_word(s,at) != ACK or read_word(s,at+8) != 1 or read_word(s,at+16) != request:
        return False
    return read_word(s,at+24) == kind and read_word(s,at+32) == 0 and read_word(s,at+48) == gen and read_word(s,at+72) == 0

def store_event(s:readbuf, o:mutbuf, w:mutbuf, at:u64, action:u64, phase:u64) -> u64:
    request = read_word(s,16)
    gen = read_word(s,24)
    if gen == MAX:
        return BAD
    if action == 1 and phase == 1:
        kind = choose(request == 0,0,21)
        if store_ack(s,at,request,kind,gen) == False or read_word(s,at+40) != 0 or read_word(s,at+56) != 0 or read_word(s,at+64) != 0:
            return BAD
        put(o,8,1)
        put(o,32,1)
        return 128
    if request == 0:
        return BAD
    if action == 2 and (phase == 2 or phase == 4):
        return query_event(s,o,w,at,request,gen,phase)
    if (action == 4 or action == 5) and phase == 3:
        if length(s)-at != 80:
            return BAD
        skipped = read_word(s,at+56)
        if skipped > 1 or store_ack(s,at,request,27,gen+1-skipped) == False or read_word(s,at+40) != 1-skipped:
            return BAD
        if skipped == 0 and read_word(s,at+64) == 0:
            return BAD
        put(o,8,3)
        put(o,32,1-skipped)
        return 128
    if action == 6 and phase == 5:
        if length(s)-at != 336 or read_word(s,at) != WAL or read_word(s,at+8) != 1 or read_word(s,at+16) != gen or read_word(s,at+24) != gen+1:
            return BAD
        if read_word(s,at+128) != ANCHOR or read_word(s,at+136) != 1 or read_word(s,at+144) != gen+1 or store_ack(s,at+256,request,2,gen+1) == False:
            return BAD
        if read_word(s,at+296) != 1 or read_word(s,at+312) != 0 or read_word(s,at+320) != 0:
            return BAD
        put(o,8,4)
        put(o,32,1)
        return 128
    return BAD

def query_event(s:readbuf, o:mutbuf, w:mutbuf, start:u64, request:u64, gen:u64, phase:u64) -> u64:
    at = start
    state = 0
    used = 0
    rowid = 0
    while at <= length(s) and length(s)-at >= 64:
        if read_word(s,at) != FRAME or read_word(s,at+16) != 10 or read_word(s,at+48) != 1 or read_word(s,at+56) != 0:
            return BAD
        kind = read_word(s,at+8)
        identity = read_word(s,at+24)
        offset = read_word(s,at+32)
        size = read_word(s,at+40)
        pos = at+64
        if size > length(s)-pos:
            return BAD
        if state == 0 and kind == 1 and size == 128 and identity != 0 and offset == 0:
            if read_word(s,pos) != LEAF or read_word(s,pos+8) != 1 or read_word(s,pos+16) != identity or read_word(s,pos+32) != 10:
                return BAD
            rowid = identity
            state = 1
        elif state == 1 and kind == 2 and identity == rowid and offset == used and size != 0 and size <= 4504-used:
            copy_wire(s,w,pos,used,size)
            used = used+size
        elif state == 1 and kind == 3 and size == 0 and identity == rowid and offset == used and used >= 141:
            state = 2
        elif (state == 0 or state == 2) and kind == 4 and identity == 0 and offset == used and size == 416:
            rows = choose(state==2,1,0)
            if read_word(s,pos+384) != 14 or read_word(s,pos+392) != 7 or read_word(s,pos+400) != rows or read_word(s,pos+408) != rows:
                return BAD
            ack = pos+416
            changed = choose(phase == 4,1,0)
            if store_ack(s,ack,request,27,gen+changed) == False or read_word(s,ack+40) != changed or read_word(s,ack+56) != 0 or read_word(s,ack+64) != 0:
                return BAD
            put(o,8,2)
            if rows == 0:
                return 128
            return row_event(s,o,w,used)
        else:
            return BAD
        at = pos+size
    return BAD

def row_event(s:readbuf, o:mutbuf, w:mutbuf, size:u64) -> u64:
    if get(w,0) != ROW or get(w,8) != 1 or get(w,16) != 10 or get(w,24) != 3 or get(w,32) != 3 or get(w,40) != 104 or get(w,48) != 36:
        return BAD
    used = get(w,72)
    owner = get(w,96)
    if get(w,56) != 3 or get(w,64) != 140 or used == 0 or used > 4300 or get(w,88) != 140+used or size != 140+used+owner:
        return BAD
    if (owner == 0 and get(w,80) != 0) or (owner != 0 and (owner != 64 or get(w,80) != 3)):
        return BAD
    i = 0
    while i < 36+used+owner:
        c = byte(w,104+i)
        if i < 36:
            if c != byte(s,112+i):
                return BAD
        elif i < 36+used:
            if c < 48 or c > 57 or (i == 36 and used > 1 and c == 48):
                return BAD
        elif (c < 48 or c > 57) and (c < 97 or c > 102):
            return BAD
        store(o,128+i,c)
        i = i+1
    put(o,32,1)
    put(o,40,choose(owner == 0,0,1))
    put(o,48,36)
    put(o,56,used)
    put(o,64,owner)
    return 128+36+used+owner
'''


def program():
    tags = dict(INPUT=b'HIAEBO01', REQUEST=b'HIAEBRQ1', RECEIPT=b'HIAEBRS1',
                GATE=b'HIAEPGT1', CTX=b'ctx-', ACK=b'HIATXR01', FRAME=b'HIAQRF01',
                ROW=b'HIAROW01', LEAF=b'HIAIXLF1', WAL=b'HIAWTA01', ANCHOR=b'HIAWAK01')
    values = {key: int.from_bytes(tag, 'little') for key, tag in tags.items()}
    values.update(BAD=4294967293, MAX=(1 << 64)-1)
    source = re.sub(r'\b(' + '|'.join(values) + r')\b', lambda match: str(values[match[0]]), POLICY)
    settlement = settlement_source()
    shared = [function(settlement, name) for name in
              ('hexadecimal','same','copy_wire','digits','decimal_equal','decimal','next_power')]
    case = case_source()
    shared.extend(function(case, name) for name in ('read_word','get','put','widen'))
    return '\n'.join([source,*shared])


def packer_document():
    from tools.generate_hia_native_filter import document as packer
    return packer(magic=PACK_MAGIC, module=PACKER.stem, wire_bytes=32768, output_bytes=4700,
                  workspace_bytes=8192)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)))
    PACKER.write_text(render_assembly(packer_document()))
