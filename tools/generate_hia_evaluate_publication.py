"""Project the paid report and its Store-confirmed products into publication calls.

HIAEPU01 contains a mode followed by eight little-endian byte lengths and
their payloads: HIAEMF01, canonical call, canonical unsigned worker request,
ledger JSON, measurements ref, ledger ref, receipt JSON, receipt ref. The
normal parent retains all descriptors from one execution. Modes 0, 1 and 3
construct HIAEDU01 for actual Store publication; modes 2 and 4 construct
the input to the independent receipt issuer and terminal checker.
"""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_paired_batch import snapshot_hash
from tools.generate_hia_evaluate_settlement import program as settlement_source
from tools.generate_hia_worker_evaluate_case import source_program as case_source
from tools.generate_hia_worker_inspection_effect import function


SOURCE = Path('examples/hia_bootstrap/evaluate_publication.hepta')
PACKER = SOURCE.with_name('evaluate_publication_packer.hepta')
PACK_MAGIC = int.from_bytes(b'HIAEUP01', 'little')

POLICY = '''
def project(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 120 or length(s) > LIMIT or length(w) < 8192 or read_word(s,0) != REQUEST:
        return BAD
    mode = read_word(s,8)
    if mode > 4:
        return BAD
    at = 80
    i = 0
    while i < 8:
        n = read_word(s,16+8*i)
        if n > length(s)-at:
            return BAD
        put(w,16*i,at)
        put(w,16*i+8,n)
        at = at+n
        i = i+1
    if at != length(s) or get(w,8) < 40 or read_word(s,80) != REPORT:
        return BAD
    at = 120
    stop = 80+get(w,8)
    i = 0
    while i < 4:
        n = read_word(s,88+8*i)
        if n > stop-at:
            return BAD
        put(w,128+16*i,at)
        put(w,136+16*i,n)
        at = at+n
        i = i+1
    if at != stop or claims(s,w) == False:
        return BAD
    if mode == 0:
        return doc(s,o,w,20,176)
    if mode == 1:
        return doc(s,o,w,21,48)
    if mode == 3:
        return doc(s,o,w,22,96)
    if bound_ref(s,w,64,176) == False or bound_ref(s,w,80,48) == False:
        return BAD
    if mode == 4 and bound_ref(s,w,112,96) == False:
        return BAD
    if mode == 2 and (get(w,24) < 2 or get(w,24) > 8388608 or get(w,40) < 2 or get(w,40) > 8388608):
        return BAD
    return settlement(s,o,w,mode)

def claims(s:readbuf,w:mutbuf) -> bool:
    claim = get(w,128)
    n = get(w,136)
    if n < 760 or read_word(s,claim) != CLAIM or read_word(s,claim+8) != n-648:
        return False
    if read_word(s,claim+40) != 512 or read_word(s,claim+48) != 64 or read_word(s,claim+56) != 8 or read_word(s,claim+640) != ACK:
        return False
    t = get(w,144)
    ts = get(w,152)
    decision = get(w,160)
    if ts < 390 or read_word(s,t) != SETTLE or read_word(s,t+56) != 0 or get(w,168) < 73 or read_word(s,decision) != DECISION:
        return False
    pair = read_word(s,t+40)
    if pair < 80 or pair > ts-310 or read_word(s,t+48) != ts-310-pair:
        return False
    if read_word(s,t+64) != read_word(s,decision+48) or read_word(s,t+72) != read_word(s,decision+56):
        return False
    if same(s,claim+192,t+116,64) == False or same(s,claim+192,t+180,64) == False or same(s,claim+256,t+244,66) == False:
        return False
    f = claim+648
    if read_word(s,f) != FRESH or read_word(s,f+8) < 9:
        return False
    req = read_word(s,f+48)
    rows = read_word(s,f+56)
    if req > n-760 or rows > n-760-req:
        return False
    at = f+112+req
    stop = at+rows
    i = 0
    while i < 4:
        if stop-at < 208 or read_word(s,at) != i:
            return False
        kind = choose(i == 0,3,choose(i == 3,5,7))
        if read_word(s,at+8) != kind or checked_ref(s,at+32) == False:
            return False
        meta = read_word(s,at+16)
        size = read_word(s,at+24)
        put(w,208+8*i,at+32)
        at = at+208
        if meta > stop-at or size > stop-at-meta:
            return False
        at = at+meta+size
        i = i+1
    return True

def doc(s:readbuf,o:mutbuf,w:mutbuf,kind:u64,slot:u64) -> u64:
    at = get(w,slot)
    n = get(w,slot+8)
    if n < 2 or n > 8388608 or length(o) < n+96:
        return BAD
    if byte(s,at) != 123 or byte(s,at+n-1) != 125 or widen(pair_hash_sha256(s,w,at,n)) != 32:
        return BAD
    put(o,0,DOCUMENT)
    put(o,8,0)
    put(o,16,kind)
    put(o,24,n)
    i = 0
    while i < 32:
        v = byte(w,length(w)-4096+1088+i)
        store(o,32+2*i,hexchar(v >> 4))
        store(o,33+2*i,hexchar(v & 15))
        i = i+1
    return copy_wire(s,o,at,96,n)

def bound_ref(s:readbuf,w:mutbuf,reference:u64,body:u64) -> bool:
    at = get(w,reference)
    n = get(w,body+8)
    if get(w,reference+8) != 176 or n < 2 or n > 8388608:
        return False
    return checked_ref(s,at) and widen(pair_hash_sha256(s,w,get(w,body),n)) == 32 and digest_matches(s,w,at+53)

def section(s:readbuf,o:mutbuf,w:mutbuf,slot:u64,pos:u64) -> u64:
    n = get(w,slot+8)
    put(o,pos,n)
    return copy_wire(s,o,get(w,slot),pos+8,n)

def settlement(s:readbuf,o:mutbuf,w:mutbuf,mode:u64) -> u64:
    ts = get(w,152)
    need = ts+880+16+get(w,56)+get(w,184)
    if mode == 2:
        need = need+24+get(w,136)+get(w,24)+get(w,40)
    else:
        need = need+8+get(w,104)
    if need > LIMIT or length(o) < need:
        return BAD
    pos = copy_wire(s,o,get(w,144),0,ts)
    put(o,0,choose(mode == 2,ISSUE,SETTLE))
    put(o,56,need-ts)
    pos = copy_wire(s,o,get(w,216),pos,176)
    pos = copy_wire(s,o,get(w,224),pos,176)
    if mode == 2:
        pos = copy_wire(s,o,get(w,232),pos,176)
    else:
        pos = copy_wire(s,o,get(w,112),pos,176)
    pos = copy_wire(s,o,get(w,80),pos,176)
    pos = copy_wire(s,o,get(w,64),pos,176)
    if mode == 4:
        pos = section(s,o,w,96,pos)
    pos = section(s,o,w,48,pos)
    pos = section(s,o,w,176,pos)
    if mode == 2:
        pos = section(s,o,w,128,pos)
        pos = section(s,o,w,16,pos)
        pos = section(s,o,w,32,pos)
    return choose(pos == need,pos,BAD)
'''

def program():
    tags = dict(REQUEST=b'HIAEPU01', REPORT=b'HIAEMF01', CLAIM=b'HIAEJC01', ACK=b'HIASTCP1',
                DOCUMENT=b'HIAEDU01', ISSUE=b'HIAEPR01', SETTLE=b'HIAEST01', FRESH=b'HIAEFI04',
                DECISION=b'HIAESD01')
    values = {key:int.from_bytes(raw,'little') for key,raw in tags.items()}
    values.update(BAD=4294967293, LIMIT=512 << 20)
    src = re.sub(r'\b('+'|'.join(values)+r')\b',lambda m:str(values[m[0]]),POLICY)
    shared = settlement_source()
    parts = [function(shared, name) for name in ('same','copy_wire','checked_ref','ref_prefix',
             'ref_hash_prefix','ref_uri_prefix','literal_read','hexadecimal','digest_matches','hexchar')]
    basic = case_source()
    return '\n'.join([src,*parts,snapshot_hash(),*(function(basic,n) for n in ('read_word','get','put','widen'))])


def packer_document():
    from tools.generate_hia_native_filter import document as packer, template
    image = template(wire_bytes=512<<20, output_bytes=512<<20, workspace_bytes=8192)
    return packer(magic=PACK_MAGIC, module=PACKER.stem, image_template=image)


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(),SOURCE.stem)))
    PACKER.write_text(render_assembly(packer_document()))
