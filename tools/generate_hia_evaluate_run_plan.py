"""Project an authenticated Evaluate claim and its independently reopened proof into a run plan.

HIAEXQ01 has two little-endian lengths followed by HIAEFH01 and HIAEDP01.
HIAEXI01 contains the original clock and resource limits, seven lengths, the
Context id and owner, followed by data, the two admitted native artifacts,
their reference batches, and the canonical Core for each arm.
"""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_paired_batch import snapshot_hash
from tools.generate_hia_evaluate_settlement import ISSUE, MATCH, POLICY, STATE, hia_literals, json_slice
from tools.generate_hia_worker_evaluate_case import source_program as case_source
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/evaluate_run_plan.hepta')
PACKER = SOURCE.with_name('evaluate_run_plan_packer.hepta')
PACK_MAGIC = int.from_bytes(b'HIAEXK01','little')
KEYS = ('arguments','tool','request_sha256','context','baseline_artifact','candidate_artifact','build_receipt',
        'verification_receipts','request_key','objective','workload','baseline_program','budget','installation',
        'max_native_wall_ms','max_memory_bytes','signatures','candidate','core_sha256','native_artifact',
        'object_artifact','required_claims','id')
# Persistent pointers are into the original immutable input, beyond the parser arena.
POLICY_PLAN = '''
def plan(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 24 or read_word(s,0) != QUERY or length(w) < 100663296:
        return BAD
    half = read_word(s,8)
    ticket = read_word(s,16)
    if half < 800 or half > length(s)-24 or ticket != length(s)-24-half or ticket < 105 or ticket > 169:
        return BAD
    if read_word(s,24) != HALF or read_word(s,32) == 0:
        return BAD
    cl = read_word(s,40)
    en = read_word(s,48)
    cn = read_word(s,56)
    if cl < 760 or cl > half-40 or en < 2 or en > 8388608 or en > half-40-cl or cn < 2 or cn > 8388608 or cn != half-40-cl-en:
        return BAD
    proof = 24+half
    if read_word(s,proof) != PROVED or read_word(s,proof+8) != ticket-80 or read_word(s,proof+80) != SCHEDULE:
        return BAD
    checks = read_word(s,proof+96)
    if read_word(s,proof+88) > 4 or checks > 64 or ticket != 105+checks or byte(s,proof+104+checks) != 4:
        return BAD
    if journal(s,64,cl) == False:
        return BAD
    if request(s,o,w,64+cl,en,cn,proof+16) == False or fresh(s,o,w,64+648,cl-648,proof) == False:
        return BAD
    return publish(s,o,w)

def journal(s:readbuf,a:u64,n:u64) -> bool:
    if read_word(s,a) != CLAIM or read_word(s,a+8) != n-648 or read_word(s,a+16) != 3 or read_word(s,a+24) == 0 or read_word(s,a+32) == 0:
        return False
    if read_word(s,a+40) != 512 or read_word(s,a+48) != 64 or read_word(s,a+56) != 8:
        return False
    j = a+64
    if read_word(s,j) != JOURNAL or read_word(s,j+8) != 3 or read_word(s,j+16) != 9 or read_word(s,j+24) != 1 or read_word(s,j+32) != 0 or read_word(s,j+40) != 1:
        return False
    if byte(s,j+192) != 114 or byte(s,j+193) != 45 or same(s,j+64,j+194,64) == False:
        return False
    k = a+576
    if read_word(s,k) != MUTATION or read_word(s,k+8) != 2 or read_word(s,k+16) != 11 or read_word(s,k+24) != 0 or read_word(s,k+32) != 48 or read_word(s,k+40) != 0 or read_word(s,k+48) != 48 or read_word(s,k+56) != 512:
        return False
    return read_word(s,a+640)==COMMIT

def request(s:readbuf,o:mutbuf,w:mutbuf,en:u64,n:u64,m:u64,proof_id:u64) -> bool:
    if hash_equal(s,w,en,n,proof_id) == False or fields(s,o,w,en,n) == False or get(o,96) != 5 or tool(s,w) == False or width(w,K_request_sha256) != 0:
        return False
    used = get(o,24)
    if used > 32*1048576:
        return False
    i = 0
    while i < used:
        store(w,ADMITTED+i,byte(o,i))
        i = i+1
    put(w,P+152,en)
    args = offset(w,K_arguments)
    arg_n = width(w,K_arguments)
    call = en+n
    if hash_equal(s,w,call,m,192) == False or fields(s,o,w,call,m) == False or get(o,96) != 2 or tool(s,w) == False:
        return False
    if arg_n < 2 or arg_n != width(w,K_arguments) or same(s,args,offset(w,K_arguments),arg_n) == False or fields(s,o,w,args,arg_n) == False:
        return False
    if width(w,K_context) != 121 or width(w,K_baseline_artifact) != 176 or width(w,K_candidate_artifact) != 176 or width(w,K_build_receipt) != 176:
        return False
    ctx = offset(w,K_context)
    if hexadecimal(s,ctx+11,32) == False or hexadecimal(s,ctx+55,64) == False or (read_word(s,ctx+7) & 4294967295) != CTX:
        return False
    put(w,P,ctx)
    put(w,P+8,offset(w,K_baseline_artifact))
    put(w,P+16,offset(w,K_candidate_artifact))
    put(w,P+24,offset(w,K_build_receipt))
    put(w,P+32,offset(w,K_verification_receipts))
    put(w,P+40,width(w,K_verification_receipts))
    key = offset(w,K_request_key)
    key_n = width(w,K_request_key)
    if key_n < 2 or key_n+64 > length(o) or byte(s,key) != 34:
        return False
    a = owner_prefix(o,0)
    a = copy_wire(s,o,key,a,key_n)
    a = owner_suffix(o,a)
    return widen(mutable_hash_sha256(o,w,0,a)) == 32 and digest_matches(s,w,256)

def tool(s:readbuf,w:mutbuf) -> bool:
    return width(w,K_tool)==14 and evaluate_tool_literal(s,offset(w,K_tool))

def fresh(s:readbuf,o:mutbuf,w:mutbuf,f:u64,n:u64,proof:u64) -> bool:
    if n < 112 or read_word(s,f) != FRESH:
        return False
    count = read_word(s,f+8)
    if count < 9 or count > 1024 or get(w,P+40) != choose(count==9,2,1+(count-9)*177):
        return False
    k = 0
    while k < read_word(s,proof+96):
        if widen(byte(s,proof+104+k)) >= count-9:
            return False
        k = k+1
    if read_word(s,f+16) >= read_word(s,f+24) or read_word(s,32) > read_word(s,f+80) or read_word(s,f+80) > read_word(s,f+88) or read_word(s,f+88) > read_word(s,f+96) or read_word(s,f+96) > read_word(s,f+104):
        return False
    req = read_word(s,f+48)
    rows = read_word(s,f+56)
    left = read_word(s,f+64)
    right = read_word(s,f+72)
    if req < 2 or req > n-112 or rows > n-112-req or left > n-112-req-rows or right != n-112-req-rows-left or left < 24 or right < 24:
        return False
    a = f+112
    if fields(s,o,w,a,req) == False or get(o,96) != 6 or tool(s,w) == False or width(w,K_request_sha256) != 66 or same(s,offset(w,K_request_sha256)+1,proof+16,64) == False:
        return False
    if same_envelope(s,o,w,a) == False:
        return False
    a = a+req
    end = a+rows
    if read_word(s,end) != BATCH or read_word(s,end+left) != BATCH or read_word(s,end+8) == 0 or read_word(s,end+8) != read_word(s,end+left+8):
        return False
    save(w,3,end,left)
    save(w,4,end+left,right)
    i = 0
    while i < count:
        if a > end or end-a < 208 or read_word(s,a) != i:
            return False
        kind = read_word(s,a+8)
        m = read_word(s,a+16)
        b = read_word(s,a+24)
        ref = a+32
        a = a+208
        if m > end-a or b > end-a-m or checked_ref(s,ref) == False or hash_equal(s,w,a+m,b,ref+53) == False:
            return False
        if item(s,o,w,i,count,kind,ref,a,m,b,proof) == False:
            return False
        a = a+m+b
        i = i+1
    return a==end

def same_envelope(s:readbuf,o:mutbuf,w:mutbuf,raw:u64) -> bool:
    # The five-field canonical admission and the original signed envelope
    # have independently decoded arenas. Compare objects by decoded key and
    # arrays in order. The root's single additional member is request_sha256.
    put(w,STACK,0)
    put(w,STACK+8,0)
    queued = 1
    while queued != 0:
        queued = queued-1
        l = ADMITTED+64+72*get(w,STACK+16*queued)
        r = 64+72*get(w,STACK+16*queued+8)
        kind = get(w,l)
        if kind != get(o,r):
            return False
        ln = get(w,l+32)
        rn = get(o,r+32)
        if kind >= 5:
            if ln+choose(r==64,1,0) != rn:
                return False
            left = get(w,l+24)
            right = get(o,r+24)
            while left != MAX:
                if kind == 6:
                    right = find_member(o,w,ADMITTED+64+72*left,get(o,r+24))
                if right == MAX or queued >= 262144:
                    return False
                put(w,STACK+16*queued,left)
                put(w,STACK+16*queued+8,right)
                queued = queued+1
                left = get(w,ADMITTED+64+72*left+16)
                right = get(o,64+72*right+16)
        elif kind == 4:
            if ln != rn or arena_equal(o,w,get(o,r+24),ADMITTED+get(w,l+24),ln) == False:
                return False
        elif kind == 3:
            if ln != rn or same(s,get(w,P+152)+get(w,l+24),raw+get(o,r+24),ln) == False:
                return False
    return True

def find_member(o:mutbuf,w:mutbuf,left:u64,right:u64) -> u64:
    n = get(w,left+48)
    key = ADMITTED+get(w,left+40)
    while right != MAX:
        r = 64+72*right
        if get(o,r+48) == n and arena_equal(o,w,get(o,r+40),key,n):
            return right
        right = get(o,r+16)
    return MAX

def arena_equal(o:mutbuf,w:mutbuf,a:u64,b:u64,n:u64) -> bool:
    i = 0
    while i < n:
        if byte(o,a+i) != byte(w,b+i):
            return False
        i = i+1
    return True

def item(s:readbuf,o:mutbuf,w:mutbuf,i:u64,count:u64,kind:u64,ref:u64,a:u64,m:u64,b:u64,proof:u64) -> bool:
    body = a+m
    if i == 0:
        if kind != 3 or same(s,ref+53,get(w,P)+55,64) == False or fields(s,o,w,body,b) == False:
            return False
        if save_ref(w,K_objective,P+48) == False or save_ref(w,K_workload,P+56) == False or save_ref(w,K_baseline_program,P+64) == False:
            return False
        put(w,P+72,offset(w,K_installation))
        put(w,P+80,width(w,K_installation))
        start = offset(w,K_budget)
        size = width(w,K_budget)
        if size < 2 or fields(s,o,w,start,size) == False:
            return False
        return decimal_equal(s,offset(w,K_max_native_wall_ms),width(w,K_max_native_wall_ms),read_word(s,744)) and policy_memory(s,w)
    if i <= 2:
        if kind != 7 or same(s,ref,get(w,P+8*i),176) == False or b < 64 or (read_word(s,body) & 4294967295) != ELF:
            return False
        if fields(s,o,w,a,m) == False or match_field(s,w,K_context,get(w,P),121) == False or match_field(s,w,K_installation,get(w,P+72),get(w,P+80)) == False:
            return False
        if width(w,K_core_sha256) != 66 or save_ref(w,K_candidate,P+88+8*(i-1)) == False:
            return False
        put(w,P+104+8*(i-1),offset(w,K_core_sha256)+1)
        if i == 1:
            if same(s,offset(w,K_candidate),get(w,P+64),176) == False or width(w,K_signatures) < 2:
                return False
            put(w,P+120,offset(w,K_signatures))
            put(w,P+128,width(w,K_signatures))
        save(w,i,body,b)
        return True
    if i == 3:
        if kind != 5 or same(s,ref,get(w,P+24),176) == False or fields(s,o,w,body,b) == False:
            return False
        if match_field(s,w,K_native_artifact,get(w,P+16),176) == False or match_field(s,w,K_candidate,get(w,P+96),176) == False or match_field(s,w,K_context,get(w,P),121) == False:
            return False
        return save_ref(w,K_object_artifact,P+144)
    if i < count-5:
        return kind==8 and same(s,ref,get(w,P+32)+1+177*(i-4),176)
    if i < count-3:
        arm = i-(count-5)
        if kind != 0 or same(s,ref,get(w,P+88+8*arm),176) == False or hash_equal(s,w,a,m,get(w,P+104+8*arm)) == False:
            return False
        save(w,5+arm,a,m)
        return True
    if i == count-3:
        return kind==6 and same(s,ref,get(w,P+144),176)
    if i == count-2:
        if kind != 0 or same(s,ref,get(w,P+48),176) == False or fields(s,o,w,body,b) == False:
            return False
        row = field_node(o,K_required_claims)
        return row != MAX and get(o,row)==5 and get(o,row+32)==read_word(s,proof+88)
    if kind != 0 or same(s,ref,get(w,P+56),176) == False:
        return False
    save(w,0,body,b)
    return True

def policy_memory(s:readbuf,w:mutbuf) -> bool:
    a = offset(w,K_max_memory_bytes)
    n = width(w,K_max_memory_bytes)
    return n > 2 and byte(s,a)==34 and decimal_equal(s,a+1,n-2,read_word(s,752))

def field_node(o:mutbuf,key:u64) -> u64:
    i = get(o,88)
    while i != MAX:
        row = 64+72*i
        if key_id(o,get(o,row+40),get(o,row+48)) == key:
            return row
        i = get(o,row+16)
    return MAX

def offset(w:mutbuf,key:u64) -> u64:
    return get(w,FIELDS_AT+16*key)

def width(w:mutbuf,key:u64) -> u64:
    return get(w,FIELDS_AT+8+16*key)

def match_field(s:readbuf,w:mutbuf,key:u64,a:u64,n:u64) -> bool:
    return n != 0 and width(w,key)==n and same(s,offset(w,key),a,n)

def save_ref(w:mutbuf,key:u64,slot:u64) -> bool:
    put(w,slot,offset(w,key))
    return width(w,key)==176

def hash_equal(s:readbuf,w:mutbuf,a:u64,n:u64,expected:u64) -> bool:
    return widen(pair_hash_sha256(s,w,a,n))==32 and digest_matches(s,w,expected)

def save(w:mutbuf,k:u64,a:u64,n:u64) -> u64:
    put(w,SECTIONS+16*k,a)
    put(w,SECTIONS+16*k+8,n)
    return 0

def publish(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    sig_n = get(w,P+128)
    data_n = get(w,SECTIONS+8)+sig_n+3
    size = 196+data_n
    i = 1
    while i < 7:
        size = size+get(w,SECTIONS+16*i+8)
        i = i+1
    if size > length(o):
        return BAD
    put(o,0,PLAN)
    put(o,8,read_word(s,32))
    put(o,16,read_word(s,736))
    put(o,24,read_word(s,744))
    put(o,32,read_word(s,752))
    put(o,40,data_n)
    p = copy_wire(s,o,get(w,P)+7,96,36)
    p = copy_wire(s,o,256,p,64)
    store(o,p,91)
    p = copy_wire(s,o,get(w,P+120),p+1,sig_n)
    store(o,p,44)
    p = copy_wire(s,o,get(w,SECTIONS),p+1,get(w,SECTIONS+8))
    store(o,p,93)
    p = p+1
    i = 1
    while i < 7:
        n = get(w,SECTIONS+16*i+8)
        put(o,40+8*i,n)
        p = copy_wire(s,o,get(w,SECTIONS+16*i),p,n)
        i = i+1
    return p
'''

def write_literal(name, text):
    lines = [f'def {name}(o:mutbuf,p:u64) -> u64:']
    for i in range(0,len(text),8):
        chunk = text[i:i+8]
        if len(chunk)==8:
            lines.append(f'    put(o,p+{i},{int.from_bytes(chunk,"little")})')
        else:
            lines.extend(f'    store(o,p+{i+j},{v})' for j,v in enumerate(chunk))
    lines.append(f'    return p+{len(text)}')
    return '\n'.join(lines)

def program():
    tags=dict(QUERY=b'HIAEXQ01', HALF=b'HIAEFH01', PLAN=b'HIAEXI01', CLAIM=b'HIAEJC01', FRESH=b'HIAEFI04',
              JOURNAL=b'HIAJRN02', MUTATION=b'HIAJMO01', COMMIT=b'HIASTCP1', PROVED=b'HIAEDP01',
              SCHEDULE=b'HIAADK02', BATCH=b'HIAEBT01', CTX=b'ctx-', ELF=b'\x7fELF')
    constants={k:int.from_bytes(v,'little') for k,v in tags.items()}
    constants.update(MAX=(1<<64)-1,BAD=4294967293,P=STATE+65536,SECTIONS=STATE+66048,FIELDS_AT=STATE+2048,ADMITTED=48<<20,STACK=80<<20)
    constants.update({'K_'+k:i for i,k in enumerate(KEYS,1)})
    body=re.sub(r'\b('+'|'.join(constants)+r')\b',lambda m:str(constants[m[0]]),POLICY_PLAN)
    decoder=json_slice(KEYS)
    base=POLICY+'\n'+MATCH+'\n'+ISSUE
    helpers=[function(base,k) for k in ('same','hexadecimal','digits','decimal_equal','checked_ref','digest_matches','hexchar','copy_wire')]
    literals=hia_literals()
    helpers.extend(function(literals,k) for k in ('ref_prefix','ref_hash_prefix','ref_uri_prefix','evaluate_tool_literal'))
    case=case_source()
    helpers.extend(function(case,k) for k in ('read_word','get','put','widen'))
    digest=snapshot_hash()
    mutable=digest.replace('pair_hash_', 'mutable_hash_').replace('s: readbuf','s: mutbuf').replace('s:readbuf','s:mutbuf')
    return '\n'.join((body,*helpers,write_literal('owner_prefix',b'{"key":'),
                      write_literal('owner_suffix',b',"tool":"hia_evaluate"}'),decoder,digest,mutable))

def packer_document():
    from tools.generate_hia_native_filter import document as packer, template
    frame=template(wire_bytes=128<<20,output_bytes=64<<20,workspace_bytes=96<<20,
                   canonical_section=(196,40))
    return packer(magic=PACK_MAGIC,module=PACKER.stem,image_template=frame,separate_sections=True)

if __name__=='__main__':
    SOURCE.write_text(render_assembly(document(program(),SOURCE.stem)))
    PACKER.write_text(render_assembly(packer_document()))
