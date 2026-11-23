"""Issue the public measurements JSON from a real fresh, settled Evaluate.

HIAEMJ01 has six little-endian lengths after its magic: HIAEFI04, settled
HIAESD01, HIAENR01, both public physical reference outcomes, and HIAEMT01.
The six sections follow immediately. Output is the canonical Store document.
"""

import ast
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_identity import MEASUREMENT_RECORD
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_paired_batch import snapshot_hash
from tools.generate_hia_evaluate_reference_report import literals
from tools.generate_hia_evaluate_settlement import POLICY as SETTLE, MATCH, OUTCOMES, json_slice
from tools.generate_hia_worker_emit_verification import key_table
from tools.generate_hia_worker_evaluate_case import source_program as case_source
from tools.generate_hia_worker_inspection_effect import function
from tools.generate_hia_worker_request import format_program

SOURCE=Path('examples/hia_bootstrap/evaluate_measurements.hepta')
PACKER=SOURCE.with_name('evaluate_measurements_packer.hepta')
MAGIC=int.from_bytes(b'HIAEMP01','little')
FIELDS=('arguments','baseline_artifact','candidate_artifact','context','objective','workload','metric','cases',
        'function','report','observations','artifact_sha256','completed_cases','planned_cases','status','complete',
        'wall_ns','stdout_sha256','baseline','candidate','normal','traps','total_native_ns',
        'baseline_native','candidate_native','termination_confirmed','artifact_bytes','latency_ns')
POLICY=r'''
def measurements(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 512 or read_word(s,0) != REQUEST:
        return BAD
    cursor = 56
    i = 0
    while i < 6:
        size = read_word(s,8+8*i)
        if size == 0 or size > length(s)-cursor:
            return BAD
        put(w,SECTIONS+16*i,cursor)
        put(w,SECTIONS+16*i+8,size)
        cursor = cursor+size
        i = i+1
    if cursor != length(s) or checks(s,w) == False:
        return BAD
    if fresh(s,o,w) == False:
        return BAD
    if reference(s,o,w,0) == False or reference(s,o,w,1) == False:
        return BAD
    if native(s,o,w) == False:
        return BAD
    return issue(s,o,w)

def checks(s:readbuf,w:mutbuf) -> bool:
    fresh = get(w,SECTIONS)
    decision = get(w,SECTIONS+16)
    paired = get(w,SECTIONS+80)
    if get(w,SECTIONS+8) < 112 or read_word(s,fresh) != FRESH or get(w,SECTIONS+24) < 73 or read_word(s,decision) != DECISION:
        return False
    if get(w,SECTIONS+88) < 112 or read_word(s,paired) != ARCHIVE or read_word(s,paired+32) != PAIR:
        return False
    p = read_word(s,paired+8)
    if p < 80 or 32+p > get(w,SECTIONS+88) or read_word(s,paired+16) != get(w,SECTIONS+88)-32-p:
        return False
    count = read_word(s,paired+48)
    if count == 0 or count > 512 or read_word(s,paired+56) > 2*count or p != 80+64*read_word(s,paired+56):
        return False
    if read_word(s,decision+8) < 1 or read_word(s,decision+8) > 6 or read_word(s,decision+16) > 1:
        return False
    if read_word(s,decision+64) != get(w,SECTIONS+24)-72:
        return False
    if read_word(s,fresh+80) == 0 or read_word(s,fresh+88) < read_word(s,fresh+80) or read_word(s,fresh+96) < read_word(s,fresh+88) or read_word(s,fresh+104) < read_word(s,fresh+96):
        return False
    if read_word(s,fresh+104)-read_word(s,fresh+80) != read_word(s,decision+48) or read_word(s,decision+48) > read_word(s,decision+56):
        return False
    put(w,FACT,count)
    put(w,FACT+8,count)
    return True

def fresh(s:readbuf,o:mutbuf,w:mutbuf) -> bool:
    start = get(w,SECTIONS)
    end = start+get(w,SECTIONS+8)
    at = start+112
    n = read_word(s,start+48)
    row_bytes = read_word(s,start+56)
    count = read_word(s,start+8)
    if count < 9 or count > 1024 or n > end-at or row_bytes > end-at-n:
        return False
    if parse(s,o,w,at,n,6) == False:
        return False
    args = node_field(o,64,K_arguments)
    if args == MAX or keep(o,w,BASE,node_field(o,args,K_baseline_artifact)) == False or keep(o,w,OTHER,node_field(o,args,K_candidate_artifact)) == False or keep(o,w,CONTEXT,node_field(o,args,K_context)) == False:
        return False
    if get(w,BASE+8) != 176 or get(w,OTHER+8) != 176 or get(w,CONTEXT+8) != 121:
        return False
    at = at+n
    stop = at+row_bytes
    i = 0
    while i < count:
        if at > stop or stop-at < 208 or read_word(s,at) != i:
            return False
        m = read_word(s,at+16)
        n = read_word(s,at+24)
        ref = at+32
        at = at+208
        if m > stop-at or n > stop-at-m:
            return False
        if i == 0:
            if parse(s,o,w,at+m,n,6) == False or keep(o,w,OBJECTIVE,node_field(o,64,K_objective)) == False or keep(o,w,WORK,node_field(o,64,K_workload)) == False:
                return False
            if get(w,OBJECTIVE+8) != 176 or get(w,WORK+8) != 176:
                return False
        elif i == 1 or i == 2:
            if same(s,ref,get(w,BASE+16*(i-1)),176) == False:
                return False
            put(w,FACT+32+8*i,n)
        elif i == count-5 or i == count-4:
            put(w,CORE+16*(i-(count-5)),at)
            put(w,CORE+16*(i-(count-5))+8,m)
        elif i == count-2:
            if same(s,ref,get(w,OBJECTIVE),176) == False or parse(s,o,w,at+m,n,6) == False or keep(o,w,METRIC,node_field(o,64,K_metric)) == False:
                return False
            field = node_field(o,64,K_metric)
            if get(o,field) != 4:
                return False
            metric = key_id(o,get(o,field+24),get(o,field+32))
            if metric != K_artifact_bytes and metric != K_latency_ns:
                return False
            put(w,FACT+64,metric)
        elif i == count-1:
            if same(s,ref,get(w,WORK),176) == False or parse(s,o,w,at+m,n,6) == False or case_rows(o,w) == False:
                return False
        at = at+m+n
        i = i+1
    if at != stop:
        return False
    left = read_word(s,start+64)
    right = read_word(s,start+72)
    if left < 24 or left > end-at or right < 24 or right != end-at-left:
        return False
    put(w,BATCHES,at)
    put(w,BATCHES+8,left)
    put(w,BATCHES+16,at+left)
    put(w,BATCHES+24,right)
    return True

def case_rows(o:mutbuf,w:mutbuf) -> bool:
    cases = node_field(o,64,K_cases)
    if cases == MAX or get(o,cases) != 5 or get(o,cases+32) != get(w,FACT):
        return False
    i = 0
    child = get(o,cases+24)
    while child != MAX:
        row = 64+72*child
        slot = ROWS+96*i
        if keep(o,w,slot,node_field(o,row,K_arguments)) == False or keep(o,w,slot+16,node_field(o,row,K_function)) == False:
            return False
        child = get(o,row+16)
        i = i+1
    return i == get(w,FACT)

def reference(s:readbuf,o:mutbuf,w:mutbuf,arm:u64) -> bool:
    q = SECTIONS+48+16*arm
    at = get(w,q)
    n = get(w,q+8)
    if parse(s,o,w,at,n,6) == False:
        return False
    report = node_field(o,64,K_report)
    if report == MAX or get(o,report) != 6:
        return False
    clock = get(w,SECTIONS)+80+16*arm
    wall = read_word(s,clock+8)-read_word(s,clock)
    if field_number(s,o,w,node_field(o,64,K_wall_ns),wall,True) == False or field_number(s,o,w,node_field(o,report,K_planned_cases),get(w,FACT),False) == False:
        return False
    batch = get(w,BATCHES+16*arm)
    done = read_word(s,batch+16)
    if read_word(s,batch) != BATCH or read_word(s,batch+8) != get(w,FACT) or done > get(w,FACT) or field_number(s,o,w,node_field(o,report,K_completed_cases),done,False) == False:
        return False
    if hash_field(s,o,w,node_field(o,64,K_stdout_sha256),batch,get(w,BATCHES+16*arm+8)) == False:
        return False
    if hash_field(s,o,w,node_field(o,report,K_artifact_sha256),get(w,CORE+16*arm),get(w,CORE+16*arm+8)) == False:
        return False
    complete = node_field(o,report,K_complete)
    if complete == MAX or (get(o,complete) != 1 and get(o,complete) != 2):
        return False
    if get(o,complete) == 1:
        put(w,FACT+8,0)
        if arm == 0:
            put(w,FACT+16,1)
    rows = node_field(o,report,K_observations)
    if rows == MAX or get(o,rows) != 5 or get(o,rows+32) != done:
        return False
    i = 0
    child = get(o,rows+24)
    while child != MAX:
        row = 64+72*child
        if get(o,row) != 6 or keep(o,w,ROWS+96*i+32+16*arm,row) == False:
            return False
        child = get(o,row+16)
        i = i+1
    return i == done

def native(s:readbuf,o:mutbuf,w:mutbuf) -> bool:
    at = get(w,SECTIONS+32)
    n = get(w,SECTIONS+40)
    if n <= 24 or read_word(s,at) != NATIVE:
        return False
    width = read_word(s,at+8)
    if width > n-24 or read_word(s,at+16) != n-24-width:
        return False
    at = at+24
    put(w,NATIVE_RUNS,at)
    put(w,NATIVE_RUNS+8,width)
    if parse(s,o,w,at,width,6) == False:
        return False
    if arm_run(s,o,w,0) == False or arm_run(s,o,w,1) == False:
        return False
    if parse(s,o,w,at+width,n-24-width,5) == False or get(o,96) != get(w,FACT):
        return False
    child = get(o,88)
    i = 0
    while child != MAX:
        row = 64+72*child
        baseline = node_field(o,row,K_baseline_native)
        candidate = node_field(o,row,K_candidate_native)
        if baseline != MAX:
            keep(o,w,ROWS+96*i+64,baseline)
        if candidate != MAX:
            keep(o,w,ROWS+96*i+80,candidate)
        child = get(o,row+16)
        i = i+1
    if get(w,FACT+8) != 0:
        paired = get(w,SECTIONS+80)
        if read_word(s,paired+40) == 2 and read_word(s,paired+104) == 2:
            if read_word(s,paired+96) >= get(w,FACT):
                return False
            put(w,FACT+8,read_word(s,paired+96))
    return i == get(w,FACT)

def arm_run(s:readbuf,o:mutbuf,w:mutbuf,arm:u64) -> bool:
    row = node_field(o,64,choose(arm == 0,K_baseline,K_candidate))
    if row == MAX:
        return False
    d = get(w,SECTIONS+16)
    value = read_word(s,d+24+8*arm)
    if get(w,FACT+64) == K_artifact_bytes:
        if value != get(w,FACT+40+8*arm):
            return False
    elif field_number(s,o,w,node_field(o,row,K_total_native_ns),value,True) == False:
        return False
    normal = node_field(o,row,K_normal)
    traps = node_field(o,row,K_traps)
    if normal == MAX or traps == MAX or get(o,traps) != 5:
        return False
    if get(o,traps+32) > 0 or get(o,normal) == 6:
        put(w,FACT+24,1)
    if get(o,normal) == 6:
        report = node_field(o,normal,K_report)
        if report == MAX:
            return False
        if get(o,report) == 6:
            put(w,FACT+32,1)
    return True

def hash_field(s:readbuf,o:mutbuf,w:mutbuf,row:u64,start:u64,n:u64) -> bool:
    if row == MAX or get(o,row) != 4 or get(o,row+32) != 64 or widen(pair_hash_sha256(s,w,start,n)) != 32:
        return False
    at = get(o,row+24)
    i = 0
    while i < 32:
        value = widen(byte(w,length(w)-4096+1088+i))
        if byte(o,at+2*i) != hexchar(value >> 4) or byte(o,at+2*i+1) != hexchar(value & 15):
            return False
        i = i+1
    return True

def field_number(s:readbuf,o:mutbuf,w:mutbuf,row:u64,value:u64,quoted:bool) -> bool:
    if row == MAX or get(o,row) != choose(quoted,4,3):
        return False
    n = get(o,row+32)
    if n == 0 or n > 20:
        return False
    at = get(o,row+24)
    i = 0
    num = 0
    while i < n:
        if quoted:
            c = byte(o,at+i)
        else:
            c = byte(s,get(w,WINDOW)+at+i)
        if c < 48 or c > 57 or num > 1844674407370955161 or (num == 1844674407370955161 and c > 53):
            return False
        num = 10*num+widen(c)-48
        i = i+1
    return num == value

def parse(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64,kind:u64) -> bool:
    if n < 2 or n > 8388608:
        return False
    put(w,WINDOW,at)
    put(w,length(w)-8,(at << 32) | n)
    put(o,length(o)-8,(at << 32) | n)
    put(w,48,262144)
    put(w,56,128)
    return widen(section_decode_json(s,o,w)) < 4294967292 and get(o,64) == kind

def keep(o:mutbuf,w:mutbuf,slot:u64,row:u64) -> bool:
    if row == MAX:
        return False
    offset = choose(get(o,row) < 4,24,56)
    put(w,slot,get(w,WINDOW)+get(o,row+offset))
    put(w,slot+8,get(o,row+offset+8))
    return True

def emit_span(s:readbuf,o:mutbuf,w:mutbuf,at:u64,slot:u64) -> u64:
    return copy_wire(s,o,get(w,slot),at,get(w,slot+8))

def rows_json(s:readbuf,o:mutbuf,w:mutbuf,at:u64) -> u64:
    at = literal('[')
    i = 0
    while i < get(w,FACT+8):
        row = ROWS+96*i
        if i != 0:
            at = literal(',')
        at = literal('{"arguments":')
        at = emit_span(s,o,w,at,row)
        if get(w,row+72) != 0:
            at = literal(',"baseline_native":')
            at = emit_span(s,o,w,at,row+64)
        at = literal(',"baseline_vm":')
        at = emit_span(s,o,w,at,row+32)
        if get(w,row+88) != 0:
            at = literal(',"candidate_native":')
            at = emit_span(s,o,w,at,row+80)
        at = literal(',"candidate_vm":')
        at = emit_span(s,o,w,at,row+48)
        at = literal(',"function":')
        at = emit_span(s,o,w,at,row+16)
        at = literal(',"index":')
        at = decimal(o,at,i)
        at = literal('}')
        i = i+1
    at = literal(']')
    return at

def scope_json(o:mutbuf,w:mutbuf,at:u64) -> u64:
    at = literal('"same host and immutable workload, baseline then candidate; ')
    if get(w,FACT+24) == 0:
        at = literal('call latency includes ctypes FFI overhead; ')
    at = literal('snapshot reset/hash outside call timing is included in subprocess wall cost')
    if get(w,FACT+32) != 0:
        at = literal('; native SysV calls measured inside standalone HIA processes; snapshot reset and hashing outside call timing')
    at = literal('"')
    return at

def refs_json(s:readbuf,o:mutbuf,w:mutbuf,at:u64) -> u64:
    at = literal('{"baseline":')
    at = emit_span(s,o,w,at,SECTIONS+48)
    if get(w,FACT+16) == 0:
        at = literal(',"candidate":')
        at = emit_span(s,o,w,at,SECTIONS+64)
    at = literal('}')
    return at

def ratio_json(o:mutbuf,w:mutbuf,at:u64,bits:u64) -> u64:
    put(w,length(w)-8192+8000,bits)
    n = widen(format_render_binary64(w))
    if n > 32:
        return BAD
    i = 0
    while i < n:
        store(o,at+i,byte(w,length(w)-8192+6144+i))
        i = i+1
    return at+n

def quoted_number(o:mutbuf,at:u64,n:u64) -> u64:
    at = literal('"')
    at = decimal(o,at,n)
    at = literal('"')
    return at
'''

def template():
    parts=MEASUREMENT_RECORD.split('{}')
    expressions=('emit_span(s,o,w,at,BASE)','quoted_number(o,at,read_word(s,d+24))','emit_span(s,o,w,at,OTHER)',
      'quoted_number(o,at,read_word(s,d+32))','emit_span(s,o,w,at,CONTEXT)','ratio_json(o,w,at,read_word(s,d+40))',
      'scope_json(o,w,at)','emit_span(s,o,w,at,METRIC)','emit_span(s,o,w,at,NATIVE_RUNS)','emit_span(s,o,w,at,OBJECTIVE)',
      'rows_json(s,o,w,at)','outcome_json(o,at,read_word(s,d+8))','decimal(o,at,get(w,FACT))',
      'bool_json(o,at,read_word(s,d+16))','refs_json(s,o,w,at)','quoted_number(o,at,read_word(s,d+48))',
      'emit_span(s,o,w,at,WORK)')
    assert len(parts)==len(expressions)+1
    lines=['def issue(s:readbuf,o:mutbuf,w:mutbuf) -> u64:', '    at = 0','    d = get(w,SECTIONS+16)']
    for frag,expr in zip(parts,expressions):
        lines.extend((f'    at = literal({frag!r})',f'    at = {expr}','    if at >= 8388600:','        return BAD'))
    lines.extend((f'    at = literal({parts[-1]!r})','    return at',
                  'def bool_json(o:mutbuf,at:u64,value:u64) -> u64:','    if value == 1:',
                  "        at = literal('true')",'    else:',"        at = literal('false')",'    return at',
                  'def outcome_json(o:mutbuf,at:u64,n:u64) -> u64:'))
    for i,word in enumerate(OUTCOMES,1):
        quoted='"'+word+'"'
        lines.extend((f'    if n == {i}:',f'        at = literal({quoted!r})','        return at'))
    return '\n'.join((*lines,'    return BAD'))

def program():
    from tools.generate_hia_mcp_request import WIRE_HELPERS
    src=case_source()
    helpers=[function(src,x) for x in ('read_word','get','put','widen')]
    tree=ast.parse(json_slice())
    decoder='\n'.join(ast.unparse(f) for f in tree.body if f.name.startswith('section_'))
    constants={k:int.from_bytes(v,'little') for k,v in dict(REQUEST=b'HIAEMJ01',FRESH=b'HIAEFI04',
        DECISION=b'HIAESD01',NATIVE=b'HIAENR01',ARCHIVE=b'HIAEMT01',PAIR=b'HIAEPM01',BATCH=b'HIAEBT01').items()}
    state=34<<20
    constants.update(MAX=(1<<64)-1,BAD=0xfffffffd,SECTIONS=state,FACT=state+256,WINDOW=state+512,
                     BASE=state+640,OTHER=state+656,CONTEXT=state+672,OBJECTIVE=state+688,WORK=state+704,
                     METRIC=state+720,NATIVE_RUNS=state+736,CORE=state+752,BATCHES=state+784,ROWS=state+4096)
    constants.update({f'K_{n}':i for i,n in enumerate(FIELDS,1)})
    policy=literals(POLICY+'\n'+template())+'\n'+function(MATCH,'node_field')
    policy=re.sub(r'\b('+'|'.join(constants)+r')\b',lambda m:str(constants[m[0]]),policy)
    return '\n'.join((policy,*helpers,decoder,function(WIRE_HELPERS,'match_word'),key_table(FIELDS),
                     snapshot_hash(),format_program(),function(SETTLE,'same'),function(SETTLE,'copy_wire'),
                     function(SETTLE,'decimal'),function(SETTLE,'hexchar'),
                     'def next_power(p:u64) -> u64:\n    return (p >> 1) * 14757395258967641293'))

def packer_document():
    from tools.generate_hia_native_filter import document as packer, template
    return packer(magic=MAGIC,module=PACKER.stem,image_template=template(
        wire_bytes=768<<20,output_bytes=32<<20,workspace_bytes=48<<20))

if __name__=='__main__':
    SOURCE.write_text(render_assembly(document(program(),SOURCE.stem)),encoding='utf-8')
    PACKER.write_text(render_assembly(packer_document()),encoding='utf-8')
