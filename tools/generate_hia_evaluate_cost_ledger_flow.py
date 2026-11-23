"""Use the paid report, a single native Store snapshot, and frozen policy to issue the ledger.

The six inherited arguments are the complete HIAEMF01, the native ledger
application, hia-agent-store, hia-artifact, the state root directory, and its
qualified Store release directory. Explicit arguments may supply the two
directories by descriptor number or by absolute directory name. The four files must be sealed. The exact
canonical ledger bytes are returned only after all three native roles succeed.
"""
from pathlib import Path
import re
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_report_flow import ADAPTER,PORTS,POLICY as FLOW
from tools.generate_hia_worker_evaluate_case import source_program as case_source
from tools.generate_hia_worker_inspection_effect import function

SOURCE=Path('examples/hia_bootstrap/evaluate_cost_ledger_flow.hepta')
PACKER=SOURCE.with_name('evaluate_cost_ledger_flow_packer.hepta')
MAGIC=int.from_bytes(b'HIAELF01','little')

POLICY='''
def ledger_flow(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    stage = get(w,D)
    put(w,D,stage+1)
    if stage == 0:
        if length(s) < 1000 or read_word(s,0) != PAID_REPORT:
            return BAD
        at = 40
        i = 0
        while i < 4:
            n = read_word(s,8+8*i)
            if n < 16 or n > length(s)-at:
                return BAD
            put(w,SECTIONS+16*i,at)
            put(w,SECTIONS+16*i+8,n)
            at = at+n
            i = i+1
        if at != length(s) or read_word(s,40) != CLAIM or get(w,SECTIONS+8) < 760 or read_word(s,48) != get(w,SECTIONS+8)-648 or read_word(s,688) != FRESH:
            return BAD
        if read_word(s,get(w,SECTIONS+16)) != SETTLE or read_word(s,get(w,SECTIONS+32)) != DECISION or read_word(s,get(w,SECTIONS+48)) != MEASURE_START:
            return BAD
        if paid_terms(s,w) == False:
            return BAD
        put(o,1024,QUERY)
        fragment(o,0,0,1024,8)
        fragment(o,1,3,688,get(w,SECTIONS+8)-648)
        return job(o,w,4,13,2,0)
    if stage == 1:
        if length(s) < 256 or read_word(s,176) != COMMAND or read_word(s,0) != REF_START:
            return BAD
        i = 0
        while i < 64:
            c = byte(s,53+i)
            if (c < 48 or c > 57) and (c < 97 or c > 102):
                return BAD
            store(w,D+128+i,c)
            i = i+1
        fragment(o,0,13,176,length(s)-176)
        return job(o,w,5,14,1,0)
    if stage == 2:
        if length(s) < 320 or read_word(s,0) != ACK or read_word(s,length(s)-80) != ACK:
            return BAD
        i = 0
        while i < 64:
            store(o,4096+i,byte(w,D+128+i))
            i = i+1
        store(o,4160,0)
        return job(o,w,6,15,0,0)
    if stage == 3:
        if length(s) < 2 or length(s) > 8388608:
            return BAD
        p = get(w,SECTIONS+8)-648
        d = get(w,SECTIONS+40)
        r = get(w,SIZES+112)
        put(o,1024,RENDER)
        put(o,1032,p)
        put(o,1040,d)
        put(o,1048,r)
        put(o,1056,length(s))
        fragment(o,0,0,1024,40)
        fragment(o,1,3,688,p)
        fragment(o,2,3,get(w,SECTIONS+32),d)
        whole(o,w,3,14)
        whole(o,w,4,15)
        return job(o,w,4,16,5,0)
    if stage != 4 or length(s) < 32 or byte(s,0) != 123 or byte(s,length(s)-1) != 125:
        return BAD
    whole(o,w,0,16)
    put(o,16,1)
    return 3
def paid_terms(s:readbuf,w:mutbuf) -> bool:
    terms = get(w,SECTIONS+16)
    size = get(w,SECTIONS+24)
    decision = get(w,SECTIONS+32)
    width = get(w,SECTIONS+40)
    if size < 622 or width < 73 or read_word(s,terms+56) != 0 or read_word(s,decision+64) != width-72:
        return False
    if read_word(s,terms+64) != read_word(s,decision+48) or read_word(s,terms+72) != read_word(s,decision+56) or read_word(s,terms+64) > read_word(s,terms+72):
        return False
    pair = read_word(s,terms+40)
    budget = read_word(s,terms+48)
    if pair < 80 or pair > size-310 or budget != size-310-pair or budget < 231:
        return False
    at = terms+310+pair
    if read_word(s,at) != BUDGET or read_word(s,at+8) != 0 or read_word(s,at+16) != 0 or read_word(s,at+40) != 8:
        return False
    old = read_word(s,at+72)
    new = read_word(s,at+88)
    cost = read_word(s,at+96)
    if old == 0 or old > 4300 or new == 0 or new > 4300 or cost == 0 or cost > 4300 or budget != 228+old+new+cost or cost != width-72:
        return False
    if same(s,terms+180,232,64) == False or same(s,terms+244,296,66) == False or same(s,terms+116,at+164+old,64) == False:
        return False
    return same(s,terms+80,at+128,36) and same(s,terms+116,232,64) and same(s,decision+72,at+228+old+new,cost)

def same(s:readbuf,a:u64,b:u64,n:u64) -> bool:
    i = 0
    while i < n:
        if byte(s,a+i) != byte(s,b+i):
            return False
        i = i+1
    return True

'''

def program():
    state=34<<20
    names=dict(PAID_REPORT=b'HIAEMF01',CLAIM=b'HIAEJC01',FRESH=b'HIAEFI04',SETTLE=b'HIAEST01',
       DECISION=b'HIAESD01',BUDGET=b'HIAEBRS1',MEASURE_START=b'{"baseli',QUERY=b'HIAELQ01',COMMAND=b'HIATCM01',
       REF_START=b'{"id":"a',ACK=b'HIATXR01',RENDER=b'HIAELR01')
    names={k:int.from_bytes(v,'little') for k,v in names.items()}
    names.update(D=state,SECTIONS=state+32,SIZES=state+512,BAD=0xfffffffd)
    policy='\n'.join((POLICY,*(function(FLOW,n) for n in ('fragment','whole','job'))))
    policy=re.sub(r'\b('+'|'.join(names)+r')\b',lambda m:str(names[m[0]]),policy)
    return '\n'.join((policy,*(function(case_source(),n) for n in ('read_word','get','put','widen'))))

def adapter_source(flow,ports):
    from tools.generate_hia_worker_flow_packer import adapter_source as with_ports
    return with_ports(b'.equ LEDGER_FLOW,1\n'+flow,ports)

def packer_document():
    from tools.build_hia_agent_batch_commit import adapter_layout
    from tools.generate_hia_native_filter import bind_adapter,document as packer,elf_header
    source=adapter_source(Path(ADAPTER).read_bytes(),Path(PORTS).read_bytes())
    with TemporaryDirectory(prefix='hia-evaluate-ledger-flow-') as tmp:
        machine,spots,_=adapter_layout(Path(tmp),ADAPTER,source,{'entry':'report_flow_call_hole'})
    hole=spots['entry'];head=elf_header()
    packed=packer(magic=MAGIC,module=PACKER.stem,image_template=(head+machine,(len(head)+hole,)))
    return bind_adapter(packed,source,machine,(hole,))

if __name__=='__main__':
    SOURCE.write_text(render_assembly(document(program(),SOURCE.stem)),encoding='utf-8')
    PACKER.write_text(render_assembly(packer_document()),encoding='utf-8')
