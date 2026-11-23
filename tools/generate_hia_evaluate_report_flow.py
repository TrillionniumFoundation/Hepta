"""Author the native continuation from a claimed, paid Evaluate to measured documents.

The caller supplies ten sealed descriptors, starting at 3: original HIAEJC01,
physical HIAEMT01, settled HIAEBRS1, owned-reference and direct-call ELFs, four
report roles (reference, native, settlement, measurements), and original
CLOCK_MONOTONIC admission (HIAEMC01 + u64). The stdout HIAEMF01 contains
length-prefixed extents for the original claim, authoritative settlement input,
final decision, and complete public measurements. No Store writes occur here.
"""
import ast
from pathlib import Path
import re
from tempfile import TemporaryDirectory

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_measurements import POLICY as MEASURE
from tools.generate_hia_evaluate_settlement import MATCH, json_slice
from tools.generate_hia_mcp_request import WIRE_HELPERS
from tools.generate_hia_worker_emit_verification import key_table
from tools.generate_hia_worker_evaluate_case import source_program as case_source
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_request import decimal_program

SOURCE = Path('examples/hia_bootstrap/evaluate_report_flow.hepta')
PACKER = SOURCE.with_name('evaluate_report_flow_packer.hepta')
ADAPTER = 'tools/hia_evaluate_report_flow.S'
PORTS = 'tools/hia_worker_descriptor_ports.S'
MAGIC = int.from_bytes(b'HIAEFP01', 'little')
FIELDS = ('metric', 'min_improvement_ratio', 'artifact_bytes', 'latency_ns', 'arguments', 'context', 'id')

POLICY = '''
def flow(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    stage = get(w,D)
    put(w,D,stage+1)
    if stage == 0:
        if length(s) != 16 or read_word(s,0) != CLOCK or read_word(s,8) == 0 or read_word(s,8) > get(w,D+8):
            return BAD
        put(w,D+16,read_word(s,8))
        return select_fd(o,3)
    if stage == 1:
        if claim(s,o,w) == False:
            return BAD
        return select_fd(o,5)
    if stage == 2:
        if length(s) < 231 or read_word(s,0) != PAID or read_word(s,8) != 0 or read_word(s,16) != 0 or read_word(s,40) != 8:
            return BAD
        before = read_word(s,72)
        if before == 0 or before > 4300 or length(s) < 228+before:
            return BAD
        i = 0
        while i < 64:
            if byte(w,OWNER+i) != byte(s,164+before+i):
                return BAD
            i = i+1
        i = 0
        while i < 36:
            if byte(w,CONTEXT+i) != byte(s,128+i):
                return BAD
            i = i+1
        put(w,D+192,164+before)
        return select_fd(o,4)
    if stage == 3:
        if length(s) < 112 or read_word(s,0) != ARCHIVE or read_word(s,32) != PAIR:
            return BAD
        p = read_word(s,8)
        if p < 80 or p > length(s)-32 or read_word(s,16) != length(s)-32-p:
            return BAD
        put(w,D+200,p)
        return reference_job(o,w,0)
    if stage == 4 or stage == 5:
        if length(s) < 12 or read_word(s,0) != REPORT:
            return BAD
        if stage == 4:
            return reference_job(o,w,1)
        return native_job(o,w)
    if stage == 6:
        if length(s) < 24 or read_word(s,0) != NATIVE or read_word(s,8) > length(s)-24 or read_word(s,16) != length(s)-24-read_word(s,8):
            return BAD
        return settle_job(o,w,17,0)
    if stage == 7 or stage == 9:
        if length(s) < 73 or read_word(s,0) != DECISION or read_word(s,64) != length(s)-72:
            return BAD
        if stage == 7:
            return measure_job(o,w)
        return finish(o,w)
    if stage == 8:
        if length(s) < 32 or read_word(s,0) != MEASURE_START or byte(s,length(s)-1) != 125:
            return BAD
        return settle_job(o,w,19,16)
    return BAD

def select_fd(o:mutbuf,id:u64) -> u64:
    put(o,0,id)
    return 1

def fragment(o:mutbuf,i:u64,fd:u64,at:u64,n:u64) -> u64:
    t = 64+24*i
    put(o,t,fd)
    put(o,t+8,at)
    put(o,t+16,n)
    return i+1

def whole(o:mutbuf,w:mutbuf,i:u64,fd:u64) -> u64:
    return fragment(o,i,fd,0,get(w,SIZES+8*fd))

def job(o:mutbuf,w:mutbuf,role:u64,target:u64,count:u64,save:u64) -> u64:
    put(o,0,role)
    put(o,8,target)
    put(o,16,count)
    put(o,24,save)
    put(o,32,get(w,D+8)+10000000000)
    return 2

def claim(s:readbuf,o:mutbuf,w:mutbuf) -> bool:
    if length(s) < 760 or read_word(s,0) != CLAIM or read_word(s,16) != 3 or read_word(s,40) != 512 or read_word(s,48) != 64 or read_word(s,56) != 8 or read_word(s,64) != JOURNAL:
        return False
    if read_word(s,72) != 3 or read_word(s,576) != MUTATION or read_word(s,640) != COMMIT:
        return False
    h = 648
    if read_word(s,8) != length(s)-h or read_word(s,h) != FRESH or byte(s,256) != 114 or byte(s,257) != 45:
        return False
    i = 0
    while i < 64:
        if byte(s,128+i) != byte(s,258+i):
            return False
        store(w,OWNER+i,byte(s,192+i))
        i = i+1
    count = read_word(s,h+8)
    req = read_word(s,h+48)
    extent = read_word(s,h+56)
    at = h+112
    if count < 9 or count > 1024 or req > length(s)-at or extent > length(s)-at-req:
        return False
    if parse(s,o,w,at,req,6) == False:
        return False
    args = node_field(o,64,5)
    ctx = node_field(o,args,6)
    id = node_field(o,ctx,7)
    if id == MAX or get(o,id) != 4 or get(o,id+32) != 36:
        return False
    i = 0
    while i < 36:
        store(w,CONTEXT+i,byte(o,get(o,id+24)+i))
        i = i+1
    at = at+req
    end = at+extent
    i = 0
    while i < count:
        if end-at < 208 or read_word(s,at) != i:
            return False
        m = read_word(s,at+16)
        n = read_word(s,at+24)
        at = at+208
        if m > end-at or n > end-at-m:
            return False
        if i == 1 or i == 2:
            put(w,ART+16*(i-1),at+m)
            put(w,ART+16*(i-1)+8,n)
        elif i == count-5 or i == count-4:
            put(w,CORE+16*(i-(count-5)),at)
            put(w,CORE+16*(i-(count-5))+8,m)
        elif i == count-2:
            if objective(s,o,w,at+m,n) == False:
                return False
        elif i == count-1:
            put(w,WORK,at+m)
            put(w,WORK+8,n)
        at = at+m+n
        i = i+1
    left = read_word(s,h+64)
    right = read_word(s,h+72)
    if at != end or left < 24 or left > length(s)-at or right < 24 or right != length(s)-at-left:
        return False
    put(w,BATCH,at)
    put(w,BATCH+8,left)
    put(w,BATCH+16,at+left)
    put(w,BATCH+24,right)
    first = read_word(s,h+80)
    last = read_word(s,h+104)
    if first < get(w,D+16) or read_word(s,h+88) < first or read_word(s,h+96) < read_word(s,h+88) or last < read_word(s,h+96) or last > get(w,D+8):
        return False
    put(w,D+184,last-first)
    return True

def objective(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64) -> bool:
    if parse(s,o,w,at,n,6) == False:
        return False
    m = node_field(o,64,1)
    r = node_field(o,64,2)
    if m == MAX or r == MAX or get(o,m) != 4 or get(o,r) != 3:
        return False
    metric = key_id(o,get(o,m+24),get(o,m+32))
    if metric != 3 and metric != 4:
        return False
    if widen(decimal_convert(s,w,at+get(o,r+24),get(o,r+32))) != 8:
        return False
    put(w,D+168,metric-2)
    put(w,D+176,get(w,length(w)-192))
    return True

def reference_job(o:mutbuf,w:mutbuf,arm:u64) -> u64:
    store(o,1024,91)
    store(o,1025,44)
    store(o,1026,93)
    base = CORE+16*arm
    snap = BATCH+16*arm
    put(o,1032,REFERENCE_REQUEST)
    put(o,1040,get(w,base+8)+get(w,WORK+8)+3)
    put(o,1048,get(w,snap+8))
    fragment(o,0,0,1024,1)
    fragment(o,1,3,get(w,base),get(w,base+8))
    fragment(o,2,0,1025,1)
    fragment(o,3,3,get(w,WORK),get(w,WORK+8))
    fragment(o,4,0,1026,1)
    fragment(o,5,3,get(w,snap),get(w,snap+8))
    fragment(o,6,3,728+16*arm,16)
    whole(o,w,7,6)
    fragment(o,8,0,1032,24)
    return job(o,w,8,13+arm,9,0)

def native_job(o:mutbuf,w:mutbuf) -> u64:
    put(o,1024,NATIVE_REQUEST)
    put(o,1032,get(w,SIZES+32))
    put(o,1040,get(w,ART+8))
    put(o,1048,get(w,ART+24))
    put(o,1056,get(w,SIZES+56))
    whole(o,w,0,4)
    fragment(o,1,3,get(w,ART),get(w,ART+8))
    fragment(o,2,3,get(w,ART+16),get(w,ART+24))
    whole(o,w,3,7)
    fragment(o,4,0,1024,40)
    return job(o,w,9,15,5,0)

def settle_job(o:mutbuf,w:mutbuf,dest:u64,save:u64) -> u64:
    put(o,1024,SETTLE_REQUEST)
    put(o,1032,get(w,ART+8))
    put(o,1040,get(w,ART+24))
    put(o,1048,get(w,D+168))
    put(o,1056,get(w,D+176))
    put(o,1064,get(w,D+200))
    put(o,1072,get(w,SIZES+40))
    put(o,1080,0)
    put(o,1088,get(w,D+184))
    put(o,1096,get(w,D+8)-get(w,D+16))
    fragment(o,0,0,1024,80)
    fragment(o,1,5,128,36)
    fragment(o,2,5,get(w,D+192),64)
    fragment(o,3,3,192,64)
    fragment(o,4,3,256,66)
    fragment(o,5,4,32,get(w,D+200))
    whole(o,w,6,5)
    return job(o,w,10,dest,7,save)

def measure_job(o:mutbuf,w:mutbuf) -> u64:
    put(o,1024,MEASURE_REQUEST)
    put(o,1032,get(w,SIZES+24)-648)
    put(o,1040,get(w,SIZES+136))
    put(o,1048,get(w,SIZES+120))
    put(o,1056,get(w,SIZES+104))
    put(o,1064,get(w,SIZES+112))
    put(o,1072,get(w,SIZES+32))
    fragment(o,0,0,1024,56)
    fragment(o,1,3,648,get(w,SIZES+24)-648)
    whole(o,w,2,17)
    whole(o,w,3,15)
    whole(o,w,4,13)
    whole(o,w,5,14)
    whole(o,w,6,4)
    return job(o,w,11,18,7,0)

def finish(o:mutbuf,w:mutbuf) -> u64:
    put(o,1024,RESULT)
    put(o,1032,get(w,SIZES+24))
    put(o,1040,get(w,SIZES+128))
    put(o,1048,get(w,SIZES+152))
    put(o,1056,get(w,SIZES+144))
    fragment(o,0,0,1024,40)
    whole(o,w,1,3)
    whole(o,w,2,16)
    whole(o,w,3,19)
    whole(o,w,4,18)
    put(o,16,5)
    return 3
'''

def program():
    state = 34 << 20
    values = {k:int.from_bytes(v,'little') for k,v in dict(CLOCK=b'HIAEMC01',CLAIM=b'HIAEJC01',
        FRESH=b'HIAEFI04',MUTATION=b'HIAJMO01',COMMIT=b'HIASTCP1',PAID=b'HIAEBRS1',JOURNAL=b'HIAJRN02',ARCHIVE=b'HIAEMT01',PAIR=b'HIAEPM01',
        REFERENCE_REQUEST=b'HIAERJ02',NATIVE_REQUEST=b'HIAENJ01',SETTLE_REQUEST=b'HIAEST01',
        MEASURE_REQUEST=b'HIAEMJ01',DECISION=b'HIAESD01',NATIVE=b'HIAENR01',RESULT=b'HIAEMF01',
        REPORT=b'{"report',MEASURE_START=b'{"baseli').items()}
    values.update(D=state,ART=state+32,CORE=state+64,WORK=state+96,BATCH=state+112,
                  OWNER=state+800,CONTEXT=state+864,SIZES=state+512,WINDOW=state+256,MAX=(1<<64)-1,BAD=0xfffffffd)
    policy=POLICY+'\n'+function(MEASURE,'parse')+'\n'+function(MATCH,'node_field')
    policy=re.sub(r'\b('+'|'.join(values)+r')\b',lambda m:str(values[m[0]]),policy)
    decoder='\n'.join(ast.unparse(n) for n in ast.parse(json_slice()).body if n.name.startswith('section_'))
    arithmetic=decimal_program()
    return '\n'.join((policy,*(function(case_source(),n) for n in ('read_word','get','put','widen')),
                    decoder,function(WIRE_HELPERS,'match_word'),key_table(FIELDS),arithmetic))

def adapter_source(flow,ports):
    from tools.generate_hia_worker_flow_packer import adapter_source as bind_ports
    return bind_ports(flow,ports)

def packer_document():
    from tools.build_hia_agent_batch_commit import adapter_layout
    from tools.generate_hia_native_filter import bind_adapter, document as packer, elf_header
    source=adapter_source(Path(ADAPTER).read_bytes(),Path(PORTS).read_bytes())
    with TemporaryDirectory(prefix='hia-paid-reports-') as tmp:
        machine,locations,_=adapter_layout(Path(tmp),ADAPTER,source,{'flow':'report_flow_call_hole'})
    holes=(locations['flow'],)
    head=elf_header()
    image=packer(magic=MAGIC,module=PACKER.stem,image_template=(head+machine,(len(head)+holes[0],)))
    return bind_adapter(image,source,machine,holes)

if __name__=='__main__':
    SOURCE.write_text(render_assembly(document(program(),SOURCE.stem)),encoding='utf-8')
    PACKER.write_text(render_assembly(packer_document()),encoding='utf-8')
