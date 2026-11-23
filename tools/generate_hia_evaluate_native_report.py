"""Construct the two public native run records from sealed physical traces.

The input is the HIAEMT01 archive, both artifact ELFs and the supervising
direct-call ELF followed by '<8s4Q' (HIAENJ01 and the four byte lengths).
The output is HIAENR01, two lengths, the canonical native_runs object and
the ordered per-case native observation objects used by measurements.
"""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_paired_batch import snapshot_hash
from tools.generate_hia_evaluate_reference_report import literals
from tools.generate_hia_evaluate_settlement import POLICY as SETTLE
from tools.generate_hia_worker_evaluate_case import source_program as case_source
from tools.generate_hia_worker_inspection_effect import function

SOURCE=Path('examples/hia_bootstrap/evaluate_native_report.hepta')
PACKER=SOURCE.with_name('evaluate_native_report_packer.hepta')
MAGIC=int.from_bytes(b'HIAENP01','little')

# All state is private to one sealed request. The maps are disjoint from the
# SHA kernel's private tail. One row references checked spans of original input.
POLICY=r'''
def native_report(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    n = length(s)
    if n < 232 or read_word(s,n-40) != REQUEST or read_word(s,0) != ARCHIVE:
        return BAD
    if lengths(s,w,n-40) == False:
        return BAD
    pair = read_word(s,8)
    size = read_word(s,16)
    if pair > get(w,8)-32 or size != get(w,8)-32-pair or pair < 80 or read_word(s,32) != PAIR:
        return BAD
    count = read_word(s,48)
    samples = read_word(s,56)
    if count == 0 or count > 512 or samples > count*2 or pair != 80+64*samples:
        return BAD
    i = 0
    while i < samples:
        row = 112+64*i
        index = read_word(s,row)
        arm = read_word(s,row+8)
        if index >= count or arm > 1:
            return BAD
        key = ROWS+96*(512*arm+index)
        if get(w,key+32) != 0:
            return BAD
        put(w,key+32,row)
        i = i+1
    if parse_archive(s,w,32+pair,get(w,8)) == False:
        return BAD
    return render(s,o,w)

def lengths(s:readbuf,w:mutbuf,n:u64) -> bool:
    at = 0
    i = 0
    while i < 4:
        size = read_word(s,n+8+8*i)
        if size < 64 or size > n-at:
            return False
        put(w,8+16*i,size)
        if i != 0:
            if size > 67108864 or (read_word(s,at) & 4294967295) != 1179403647 or widen(pair_hash_sha256(s,w,at,size)) != 32:
                return False
            j = 0
            while j < 32:
                store(w,HASH+32*i+j,byte(w,length(w)-4096+1088+j))
                j = j+1
        at = at+size
        i = i+1
    return at == n

def parse_archive(s:readbuf,w:mutbuf,at:u64,end:u64) -> bool:
    last = 0
    row = 0
    events = 0
    while at < end:
        if end-at < 96 or read_word(s,at) != EVENT:
            return False
        index = read_word(s,at+16)
        arm = read_word(s,at+24)
        time = read_word(s,at+32)
        if arm > 1 or index >= read_word(s,48) or time == 0 or time < last:
            return False
        key = ROWS+96*(arm*512+index)
        kind = read_word(s,at+8)
        after = at+96
        if kind == 1:
            if row != 0 or get(w,key) != 0 or read_word(s,at+40) > 1 or read_word(s,at+64) > 8:
                return False
            role = read_word(s,at+72)
            if role > 12 and role != 256:
                return False
            if read_word(s,at+48) > 100 or read_word(s,at+56) == 0 or read_word(s,at+56) > 10000:
                return False
            put(w,key,at)
            put(w,ORDER+8*get(w,80),key)
            put(w,80,get(w,80)+1)
            row = key
        elif row != key:
            return False
        elif kind == 2:
            if get(w,row+8) != 0 or get(w,row+40) != 0 or read_word(s,at+48) != TERMINAL or read_word(s,at+40) < time:
                return False
            out = read_word(s,at+72)
            err = read_word(s,at+80)
            if out > 2097152 or err > 65536 or out > end-after or err > end-after-out:
                return False
            if read_word(s,at+64) > 1:
                return False
            code = read_word(s,at+56)
            if (code > 255 and code < MAX-63 and code != MAX-255) or (code == MAX-255 and (out != 0 or err != 0 or read_word(s,at+64) != 1)):
                return False
            put(w,row+8,at)
            after = after+out+err
            time = read_word(s,at+40)
        elif kind == 3:
            arg = read_word(s,at+40)
            typ = read_word(s,at+48)
            size = read_word(s,at+56)
            if typ < 1 or typ > 2 or size > 1048576 or size > end-after:
                return False
            roots = get(w,row+40)
            if roots >= 8 or (roots != 0 and arg <= get(w,row+48)):
                return False
            if roots == 0:
                put(w,row+16,at)
            put(w,row+40,roots+1)
            put(w,row+48,arg)
            after = after+size
        elif kind == 4:
            if get(w,row+40) != read_word(s,get(w,row)+64) or read_word(s,at+40) > 1:
                return False
            put(w,row+24,at)
            if bind_sample(s,w,row) == False:
                return False
            row = 0
        else:
            return False
        last = time
        at = after
        events = events+1
    return row == 0 and at == end and events == read_word(s,24) and get(w,88) == read_word(s,56)

def bind_sample(s:readbuf,w:mutbuf,row:u64) -> bool:
    owner = get(w,row+8)
    sample = get(w,row+32)
    if owner == 0:
        put(w,row+56,3)
        return sample == 0
    code = read_word(s,owner+56)
    stopped = read_word(s,owner+64)
    size = read_word(s,owner+72)
    if stopped == 1 or code == MAX-23:
        put(w,row+56,3)
        return sample == 0
    if sample == 0 or read_word(s,sample+24) != code:
        return False
    put(w,88,get(w,88)+1)
    phase = read_word(s,get(w,row)+40)
    if (read_word(s,sample+16) == 0) != (phase == 0):
        return False
    result = 1
    if code == MAX-5:
        result = choose(size == 0,2,5)
    elif code != 0:
        result = choose(code == 65,5,4)
    elif size != 32 or read_word(s,owner+96) != DIRECT:
        result = 5
    else:
        i = 0
        while i < 3:
            if read_word(s,owner+104+8*i) != read_word(s,sample+32+8*i):
                return False
            i = i+1
    put(w,row+56,result)
    return True

def render(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    at = 24
    at = literal('{')
    arm = 0
    seen = 0
    while arm < 2:
        if select_all(s,w,arm) != 0:
            if seen != 0:
                at = literal(',')
            if arm == 0:
                at = literal('"baseline":')
            else:
                at = literal('"candidate":')
            at = render_arm(s,o,w,at,arm)
            if at == BAD:
                return BAD
            seen = seen+1
        arm = arm+1
    at = literal('}')
    width = at-24
    at = literal('[')
    index = 0
    while index < read_word(s,48):
        if index != 0:
            at = literal(',')
        at = case_output(s,o,w,at,index)
        index = index+1
    at = literal(']')
    put(o,0,ANSWER)
    put(o,8,width)
    put(o,16,at-24-width)
    return at

def select_all(s:readbuf,w:mutbuf,arm:u64) -> u64:
    n = 0
    i = 0
    while i < get(w,80):
        row = get(w,ORDER+8*i)
        if read_word(s,get(w,row)+24) == arm:
            put(w,ALL+8*n,row)
            n = n+1
        i = i+1
    put(w,128,n)
    return n

def render_arm(s:readbuf,o:mutbuf,w:mutbuf,at:u64,arm:u64) -> u64:
    at = literal('{"normal":')
    n = 0
    i = 0
    while i < get(w,128):
        row = get(w,ALL+8*i)
        if read_word(s,get(w,row)+40) == 0:
            put(w,GROUP+8*n,row)
            n = n+1
        i = i+1
    normal_ns = 0
    if n == 0:
        at = literal('null')
    else:
        at = outcome(s,o,w,at,n,arm,MAX)
        if at == BAD:
            return BAD
        if get(w,152) == 1:
            normal_ns = get(w,168)
    at = literal(',"total_native_ns":"')
    at = decimal(o,at,normal_ns)
    at = literal('","traps":[')
    i = 0
    n = 0
    while i < get(w,128):
        row = get(w,ALL+8*i)
        if read_word(s,get(w,row)+40) != 0:
            if n != 0:
                at = literal(',')
            put(w,GROUP,row)
            at = outcome(s,o,w,at,1,arm,read_word(s,get(w,row)+16))
            if at == BAD:
                return BAD
            n = n+1
        i = i+1
    at = literal(']}')
    return at

def group_facts(s:readbuf,o:mutbuf,w:mutbuf,n:u64) -> bool:
    put(w,152,1)
    put(w,160,MAX-255)
    put(w,168,0)
    put(w,176,0)
    put(w,184,0)
    put(w,192,0)
    i = 0
    while i < n:
        row = get(w,GROUP+8*i)
        owner = get(w,row+8)
        status = get(w,row+56)
        if status != 1 and i+1 != n:
            return False
        put(w,152,status)
        if get(w,row+40) != 0:
            put(w,176,1)
        if owner != 0:
            code = read_word(s,owner+56)
            if code != MAX-255:
                put(w,160,code)
            stdout = read_word(s,owner+72)
            stderr = read_word(s,owner+80)
            if stdout > 2097152-get(w,184) or stderr > 65536-get(w,192):
                return False
            copy_wire(s,o,owner+96,OUT_CAPTURE+get(w,184),stdout)
            copy_wire(s,o,owner+96+stdout,ERR_CAPTURE+get(w,192),stderr)
            put(w,184,get(w,184)+stdout)
            put(w,192,get(w,192)+stderr)
            if status == 1:
                ticks = read_word(s,owner+112)
                if ticks > MAX-get(w,168):
                    return False
                put(w,168,get(w,168)+ticks)
        i = i+1
    return True

def outcome(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64,arm:u64,index:u64) -> u64:
    if group_facts(s,o,w,n) == False:
        return BAD
    at = literal('{')
    if get(w,176) == 1:
        at = literal('"buffer_snapshots":[')
        i = 0
        while i < n:
            if i != 0:
                at = literal(',')
            at = literal('{"buffers":')
            at = buffer_data(s,o,w,at,get(w,GROUP+8*i))
            at = literal(',"case":')
            at = decimal(o,at,i)
            at = literal('}')
            i = i+1
        at = literal('],')
    at = literal('"direct_call_executable_sha256":"')
    at = hash_hex(o,w,at,HASH+96)
    at = literal('",')
    if index != MAX:
        at = literal('"index":')
        at = decimal(o,at,index)
        at = literal(',')
    at = literal('"report":')
    if get(w,152) == 1:
        at = run_report(s,o,w,at,n,arm)
    else:
        at = literal('null')
    at = literal(',"returncode":')
    code = get(w,160)
    at = exit_json(o,at,code)
    at = literal(',"started":')
    if code == MAX-255:
        at = literal('false')
    else:
        at = literal('true')
    at = literal(',"status":')
    at = status_json(o,at,get(w,152))
    at = literal(',"stderr_sha256":"')
    if widen(out_hash_sha256(o,w,ERR_CAPTURE,get(w,192))) != 32:
        return BAD
    at = hash_hex(o,w,at,length(w)-4096+1088)
    at = literal('","stdout_sha256":"')
    if widen(out_hash_sha256(o,w,OUT_CAPTURE,get(w,184))) != 32:
        return BAD
    at = hash_hex(o,w,at,length(w)-4096+1088)
    at = literal('","termination_confirmed":true,"wall_ns":"')
    last = get(w,GROUP+8*(n-1))
    wall = read_word(s,get(w,last+24)+32)-read_word(s,get(w,get(w,GROUP))+32)
    at = decimal(o,at,wall)
    at = literal('"}')
    return at

def exit_json(o:mutbuf,at:u64,code:u64) -> u64:
    if code == MAX-255:
        at = literal('null')
    elif (code >> 63) != 0:
        at = literal('-')
        at = decimal(o,at,0-code)
    else:
        at = decimal(o,at,code)
    return at

def status_json(o:mutbuf,at:u64,status:u64) -> u64:
    if status == 1:
        at = literal('"returned"')
    elif status == 2:
        at = literal('"trapped"')
    elif status == 3:
        at = literal('"budget_exceeded"')
    elif status == 4:
        at = literal('"faulted"')
    else:
        at = literal('"invalid_report"')
    return at

def run_report(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64,arm:u64) -> u64:
    at = literal('{"artifact_sha256":"')
    at = hash_hex(o,w,at,HASH+32*(arm+1))
    at = literal('","complete":true,"completed_cases":')
    at = decimal(o,at,n)
    at = literal(',"direct_call_executable_sha256":"')
    at = hash_hex(o,w,at,HASH+96)
    at = literal('","measured_calls":')
    first = get(w,get(w,GROUP))
    at = decimal(o,at,n*read_word(s,first+56))
    at = literal(',"observations":[')
    i = 0
    while i < n:
        if i != 0:
            at = literal(',')
        row = get(w,GROUP+8*i)
        at = norm_obs(s,o,w,at,row)
        put(w,row+64,1)
        i = i+1
    at = literal('],"planned_cases":')
    at = decimal(o,at,n)
    at = literal(',"repetitions":')
    at = decimal(o,at,read_word(s,first+56))
    at = literal(',"schema":"hepta.hia.agent.native-observation.v1","timing_scope":"native SysV calls measured inside standalone HIA processes; snapshot reset and hashing outside call timing","total_native_ns":"')
    at = decimal(o,at,get(w,168))
    at = literal('","warmup":')
    at = decimal(o,at,read_word(s,first+48))
    at = literal('}')
    return at

def buffer_data(s:readbuf,o:mutbuf,w:mutbuf,at:u64,row:u64) -> u64:
    n = get(w,row+40)
    ev = get(w,row+16)
    at = literal('[')
    i = 0
    while i < n:
        if i != 0:
            at = literal(',')
        size = read_word(s,ev+56)
        at = literal('{"argument":')
        at = decimal(o,at,read_word(s,ev+40))
        at = literal(',"byte_length":')
        at = decimal(o,at,size)
        if read_word(s,ev+48) == 1:
            at = literal(',"kind":"readbuf"')
        else:
            at = literal(',"kind":"mutbuf"')
        at = literal(',"sha256":"')
        if widen(pair_hash_sha256(s,w,ev+96,size)) != 32:
            return BAD
        at = hash_hex(o,w,at,length(w)-4096+1088)
        at = literal('"}')
        ev = ev+96+size
        i = i+1
    at = literal(']')
    return at

def norm_obs(s:readbuf,o:mutbuf,w:mutbuf,at:u64,row:u64) -> u64:
    owner = get(w,row+8)
    begin = get(w,row)
    role = read_word(s,begin+72)
    value = read_word(s,owner+104)
    at = literal('{')
    if role == 256 and (value >> 32) != 0:
        at = literal('"abi_status":')
        at = decimal(o,at,value >> 32)
        at = literal(',')
    if role == 256:
        at = literal('"buffers":')
        at = buffer_data(s,o,w,at,row)
        at = literal(',')
    at = literal('"elapsed_ns":"')
    at = decimal(o,at,read_word(s,owner+112))
    at = literal('","mismatch":')
    if read_word(s,get(w,row+24)+40) != 0:
        at = literal('true')
    else:
        at = literal('false')
    if role == 256 and (value >> 32) != 0:
        at = literal(',"status":"abi_rejected"}')
    else:
        at = literal(',"status":"returned","values":[')
        at = scalar(o,at,role,value)
        at = literal(']}')
    return at

def scalar(o:mutbuf,at:u64,role:u64,value:u64) -> u64:
    if role == 0:
        return at
    if role == 12:
        at = literal('null')
        return at
    if role == 11:
        if (value & 255) != 0:
            at = literal('true')
        else:
            at = literal('false')
        return at
    bits = scalar_bits(role)
    negative = role < 5 or role == 9
    mask = choose(bits == 64,MAX,(1 << (bits & 63))-1)
    value = value & mask
    if negative and ((value >> (bits-1)) & 1) != 0:
        at = literal('-')
        value = (0-value) & mask
    return decimal(o,at,value)

def scalar_bits(role:u64) -> u64:
    if role == 1 or role == 5:
        return 8
    if role == 2 or role == 6:
        return 16
    if role == 3 or role == 7 or role == 256:
        return 32
    return 64

def case_output(s:readbuf,o:mutbuf,w:mutbuf,at:u64,index:u64) -> u64:
    at = literal('{')
    seen = 0
    arm = 0
    while arm < 2:
        row = ROWS+96*(512*arm+index)
        begin = get(w,row)
        if begin != 0:
            trap = read_word(s,begin+40) != 0
            if trap or get(w,row+64) != 0:
                if seen != 0:
                    at = literal(',')
                if arm == 0:
                    at = literal('"baseline_native":')
                else:
                    at = literal('"candidate_native":')
                if trap:
                    at = trap_obs(s,o,w,at,row)
                else:
                    at = norm_obs(s,o,w,at,row)
                seen = seen+1
        arm = arm+1
    at = literal('}')
    return at

def trap_obs(s:readbuf,o:mutbuf,w:mutbuf,at:u64,row:u64) -> u64:
    at = literal('{')
    if get(w,row+40) != 0:
        at = literal('"buffers":')
        at = buffer_data(s,o,w,at,row)
        at = literal(',')
    owner = get(w,row+8)
    at = literal('"returncode":')
    code = MAX-255
    if owner != 0:
        code = read_word(s,owner+56)
    at = exit_json(o,at,code)
    at = literal(',"status":')
    at = status_json(o,at,get(w,row+56))
    at = literal('}')
    return at
'''

def program():
    from tools.generate_hia_evaluate_reference_report import POLICY as OBS
    src=case_source()
    helpers=[function(src,n) for n in ('read_word','put','get','widen')]
    hashing=snapshot_hash()
    # Both interpreters use the same SHA implementation. For concatenated
    # captures the input buffer is private writable output, read by SHA only.
    second=re.sub(r's:\s*readbuf','s:mutbuf',hashing.replace('pair_hash_','out_hash_'))
    constants={k:int.from_bytes(v,'little') for k,v in dict(REQUEST=b'HIAENJ01',
        ANSWER=b'HIAENR01',ARCHIVE=b'HIAEMT01',PAIR=b'HIAEPM01',EVENT=b'HIAEEV01',
        TERMINAL=b'HIADRT01',DIRECT=b'HIADRR02').items()}
    constants.update(BAD=0xfffffffd,MAX=(1<<64)-1,ROWS=65536,ORDER=16384,ALL=25600,
                     GROUP=30720,HASH=512,OUT_CAPTURE=12<<20,ERR_CAPTURE=15<<20)
    source=re.sub(r'\b('+'|'.join(constants)+r')\b',lambda m:str(constants[m[0]]),literals(POLICY))
    return '\n'.join((source,*helpers,hashing,second,function(SETTLE,'copy_wire'),function(SETTLE,'decimal'),
                       function(SETTLE,'hexchar'),function(OBS,'hash_hex'),
                       'def next_power(p:u64) -> u64:\n    return (p >> 1) * 14757395258967641293'))

def packer_document():
    from tools.generate_hia_native_filter import document as packer, template
    return packer(magic=MAGIC,module=PACKER.stem,image_template=template(
        wire_bytes=512<<20,output_bytes=16<<20,workspace_bytes=1<<20))

if __name__=='__main__':
    SOURCE.write_text(render_assembly(document(program(),SOURCE.stem)),encoding='utf-8')
    PACKER.write_text(render_assembly(packer_document()),encoding='utf-8')
