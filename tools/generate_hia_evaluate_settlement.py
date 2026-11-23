"""Author the native Evaluate judgment and its checked terminal publication.

HIAEST01 takes original artifact lengths, the admitted numeric objective, the
paired measurement record and the execution-budget owner's HIAEBRS1 terminal
receipt. It binds the official Context and request owner, checks exact decimal
settlement, and applies the existing HIA measurement policy. Optional issuance
material is five Store-issued refs followed by read-back measurement, cost and
evaluation documents. Their SHA-256 and relevant public fields are checked
before emitting the public response, Journal command or cost sideband.

HIAEPR01 uses the same settled header with five refs (baseline, candidate,
build receipt, ledger, measurements), and length-prefixed ledger, measurements,
and the committed HIAEJC01 claim plus the canonical call and unsigned envelope.
It issues original public evaluation-receipt JSON.
"""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_identity import source_program as identity
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_paired_batch import snapshot_hash
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/evaluate_settlement.hepta')
PACKER = SOURCE.with_name('evaluate_settlement_packer.hepta')
MAGIC = int.from_bytes(b'HIAESP01', 'little')

# Fixed header: magic, baseline/candidate ELF sizes, metric (1 bytes/2 ns),
# binary64 threshold, paired report length, budget receipt length, issuance
# material length, reference wall ns, elapsed evaluation wall ns.
# The following ASCII fields identify Context, budget owner, Journal row and
# public request, at 36/64/64/66 bytes. Remaining sections are length-delimited.
POLICY = '''
def settle(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 390 or (read_word(s,0) != REQUEST and read_word(s,0) != ISSUE):
        return BAD
    if read_word(s,8) == 0 or read_word(s,8) > 67108864 or read_word(s,16) == 0 or read_word(s,16) > 67108864:
        return BAD
    metric = read_word(s,24)
    threshold = read_word(s,32)
    if threshold == 9223372036854775808:
        threshold = 0
    if metric < 1 or metric > 2 or threshold > 4607182418800017408 or read_word(s,64) > read_word(s,72):
        return BAD
    if read_word(s,80) & 4294967295 != CTX or hexadecimal(s,84,32) == False or hexadecimal(s,116,128) == False:
        return BAD
    if byte(s,244) != 114 or byte(s,245) != 45 or hexadecimal(s,246,64) == False:
        return BAD
    n = read_word(s,40)
    budget = read_word(s,48)
    issued = read_word(s,56)
    if n < 80 or n > 65616 or budget > 13312 or n > length(s)-310 or budget > length(s)-310-n or issued != length(s)-310-n-budget:
        return BAD
    sample = 310
    if check_pair(s,w,sample,n) == False:
        return BAD
    status = read_word(s,sample+8)
    if status == 5:
        if budget != 0 or issued != 0 or read_word(s,0) != REQUEST:
            return BAD
        return refused(s,o,w,read_word(s,sample+64))
    if budget < 128 or closed_budget(s,w,sample+n,budget) == False:
        return BAD
    before = choose(metric == 1,read_word(s,8),read_word(s,sample+32))
    after = choose(metric == 1,read_word(s,16),read_word(s,sample+40))
    complete = get(w,16) != 0
    traps = get(w,24) != 0
    flags = choose(status == 2,1,0) | choose(status == 0,2,0) | choose(complete,4,0)
    flags = flags | choose(metric == 2,8,0) | choose(traps,16,0)
    put(w,128,0)
    put(w,136,0)
    put(w,144,before)
    put(w,152,after)
    put(w,160,threshold)
    put(w,168,flags)
    if widen(judge(w,o)) != 24:
        return BAD
    decision = get(o,8)
    ratio = get(o,16)
    put(w,32,decision)
    put(w,40,ratio)
    put(w,48,before)
    put(w,56,after)
    if read_word(s,0) == ISSUE:
        return issue_receipt(s,o,w,sample+n+budget,issued)
    if issued == 0:
        return decision_record(s,o,w)
    return publish(s,o,w,sample+n+budget,issued)

def check_pair(s:readbuf, w:mutbuf, at:u64, size:u64) -> bool:
    if read_word(s,at) != PAIR:
        return False
    status = read_word(s,at+8)
    count = read_word(s,at+16)
    rows = read_word(s,at+24)
    if status > 5 or count == 0 or count > 512 or rows > 2*count or size != 80+64*rows:
        return False
    if status == 5 and (rows != 0 or read_word(s,at+72) != 2 or read_word(s,at+64) >= count):
        return False
    if status != 0 and (read_word(s,at+64) >= count or read_word(s,at+72) > 2):
        return False
    totals = 1024
    normal_reports_returned = True
    i = 0
    while i < rows:
        row = at+80+64*i
        index = read_word(s,row)
        arm = read_word(s,row+8)
        expected = read_word(s,row+16)
        code = read_word(s,row+24)
        if index >= count or arm > 1 or expected > 19 or (expected >= 12 and expected <= 14):
            return False
        slot = 4096+8*(arm*512+index)
        if get(w,slot) != 0:
            return False
        put(w,slot,row)
        if arm == 1 and get(w,4096+8*index) == 0:
            return False
        if read_word(s,row+48) > 1 or read_word(s,row+56) > 8388608:
            return False
        if expected != 0:
            put(w,24,1)
        if expected == 0 and code != 0:
            normal_reports_returned = False
        if expected == 0 and code == 0:
            duration = read_word(s,row+40)
            if duration > MAX-get(w,totals+8*arm):
                return False
            put(w,totals+8*arm,get(w,totals+8*arm)+duration)
        i = i+1
    if get(w,totals) != read_word(s,at+32) or get(w,totals+8) != read_word(s,at+40):
        return False
    complete = (status == 0 or status == 1) and rows == 2*count and normal_reports_returned
    if status == 0 and complete == False:
        return False
    put(w,16,choose(complete,1,0))
    return True

def closed_budget(s:readbuf, w:mutbuf, at:u64, n:u64) -> bool:
    if read_word(s,at) != BUDGET or read_word(s,at+8) != 0 or read_word(s,at+16) != 0:
        return False
    sequence = read_word(s,at+24)
    if sequence == 0 or read_word(s,at+40) != 8 or read_word(s,at+48) != sequence or read_word(s,at+56) != 1:
        return False
    if read_word(s,at+32) > 86400000 or read_word(s,at+104) != 1 or read_word(s,at+64) != 36 or read_word(s,at+80) != 64 or read_word(s,at+112) != 1 or read_word(s,at+120) != 0:
        return False
    old = read_word(s,at+72)
    new = read_word(s,at+88)
    cost = read_word(s,at+96)
    if old == 0 or old > 4300 or new == 0 or new > 4300 or cost == 0 or cost > 4300 or n != 228+old+new+cost:
        return False
    if same(s,80,at+128,36) == False or same(s,116,at+164+old,64) == False:
        return False
    before = at+164
    updated = at+228+old
    charged = updated+new
    if digits(s,before,old) == False or digits(s,updated,new) == False or digits(s,charged,cost) == False:
        return False
    i = 0
    carry = 0
    while i < new:
        value = carry
        if i < old:
            value = value + widen(byte(s,before+old-i-1))-48
        if i < cost:
            value = value + widen(byte(s,charged+cost-i-1))-48
        carry = choose(value >= 10,1,0)
        if byte(s,updated+new-i-1) != 48+value-10*carry:
            return False
        i = i+1
    if carry != 0 or old > new or cost > new:
        return False
    put(w,64,charged)
    put(w,72,cost)
    return True

def decision_record(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    put(o,0,DECISION)
    put(o,8,get(w,32))
    put(o,16,get(w,16))
    put(o,24,get(w,48))
    put(o,32,get(w,56))
    put(o,40,get(w,40))
    put(o,48,read_word(s,64))
    put(o,56,read_word(s,72))
    put(o,64,get(w,72))
    return copy_wire(s,o,get(w,64),72,get(w,72))

def digits(s:readbuf, at:u64, size:u64) -> bool:
    if size == 0 or (size > 1 and byte(s,at) == 48):
        return False
    i = 0
    while i < size:
        c = byte(s,at+i)
        if c < 48 or c > 57:
            return False
        i = i+1
    return True

def hexadecimal(s:readbuf, at:u64, size:u64) -> bool:
    i = 0
    while i < size:
        c = byte(s,at+i)
        if (c < 48 or c > 57) and (c < 97 or c > 102):
            return False
        i = i+1
    return True

def same(s:readbuf, a:u64, b:u64, size:u64) -> bool:
    i = 0
    while i < size:
        if byte(s,a+i) != byte(s,b+i):
            return False
        i = i+1
    return True

def copy_wire(s:readbuf, o:mutbuf, start:u64, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o,at+i,byte(s,start+i))
        i = i+1
    return at+size

def local_copy(o:mutbuf, src:u64, at:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o,at+i,byte(o,src+i))
        i = i+1
    return at+size

def decimal(o:mutbuf, at:u64, value:u64) -> u64:
    power = 10000000000000000000
    digits = 0
    while power > 0:
        digit = 0
        while value >= power:
            digit = digit+1
            value = value-power
        if digit != 0 or digits != 0 or power == 1:
            store(o,at,digit+48)
            at = at+1
            digits = digits+1
        power = next_power(power)
    return at

def checked_ref(s:readbuf, at:u64) -> bool:
    return ref_prefix(s,at) and hexadecimal(s,at+9,32) and ref_hash_prefix(s,at+41) and hexadecimal(s,at+53,64) and ref_uri_prefix(s,at+117) and hexadecimal(s,at+142,32) and byte(s,at+174) == 34 and byte(s,at+175) == 125

def publish(s:readbuf, o:mutbuf, w:mutbuf, start:u64, size:u64) -> u64:
    if size < 904:
        return BAD
    i = 0
    while i < 5:
        if checked_ref(s,start+176*i) == False:
            return BAD
        i = i+1
    # Every linked document is independently read back from its issued role.
    # Verify actual bytes against refs before exposing any public result.
    at = start+880
    i = 0
    while i < 3:
        if at > length(s) or length(s)-at < 8:
            return BAD
        width = read_word(s,at)
        at = at+8
        if width < 2 or width > 8388608 or width > length(s)-at:
            return BAD
        ref = start+176*(2+i)
        if widen(pair_hash_sha256(s,w,at,width)) != 32 or digest_matches(s,w,ref+53) == False:
            return BAD
        if fields(s,w,at,width) == False or document_matches(s,o,w,start,i) == False:
            return BAD
        at = at+width
        i = i+1
    if at != length(s):
        return BAD
    cursor = result_first(o,16384)
    cursor = copy_wire(s,o,start,cursor,176)
    cursor = result_candidate(o,cursor)
    cursor = copy_wire(s,o,start+176,cursor,176)
    cursor = result_receipt(o,cursor)
    cursor = copy_wire(s,o,start+352,cursor,176)
    cursor = result_ledger(o,cursor)
    cursor = copy_wire(s,o,start+528,cursor,176)
    cursor = result_measurement(o,cursor)
    cursor = copy_wire(s,o,start+704,cursor,176)
    cursor = result_outcome(o,cursor)
    cursor = outcome_name(o,cursor,get(w,32))
    cursor = result_complete(o,cursor)
    cursor = boolean(o,cursor,get(w,16))
    cursor = result_end(o,cursor)
    return terminal(s,o,1,cursor-16384)

def refused(s:readbuf, o:mutbuf, w:mutbuf, index:u64) -> u64:
    at = refused_prefix(o,16384)
    at = decimal(o,at,index)
    at = refused_suffix(o,at)
    return terminal(s,o,2,at-16384)

def terminal(s:readbuf, o:mutbuf, status:u64, payload:u64) -> u64:
    at = envelope_begin(o,32768)
    if status == 1:
        at = envelope_success(o,at)
        at = copy_wire(s,o,244,at,66)
        at = envelope_result(o,at)
        at = local_copy(o,16384,at,payload)
        at = envelope_complete(o,at)
    else:
        at = envelope_error(o,at)
        at = local_copy(o,16384,at,payload)
        at = envelope_request(o,at)
        at = copy_wire(s,o,244,at,66)
        at = envelope_rejected(o,at)
    n = at-32768
    # Keep contiguous output sections separate from immutable construction areas.
    begin = 48
    side = begin+n
    command = side+68+payload
    if command+88+n+64 > 16384:
        return BAD
    put(o,0,TERMINAL)
    put(o,8,status)
    put(o,16,n)
    put(o,24,68+payload)
    put(o,32,88+n+64)
    put(o,40,0)
    local_copy(o,32768,begin,n)
    put(o,side,SIDEBAND)
    put(o,side+8,status)
    put(o,side+16,36)
    put(o,side+24,payload)
    copy_wire(s,o,80,side+32,36)
    local_copy(o,16384,side+68,payload)
    put(o,command,UPDATE)
    put(o,command+8,1)
    put(o,command+16,1)
    put(o,command+24,0)
    put(o,command+32,2)
    put(o,command+40,3)
    put(o,command+48,88)
    put(o,command+56,n)
    put(o,command+64,3)
    put(o,command+72,88+n)
    put(o,command+80,64)
    local_copy(o,32768,command+88,n)
    return copy_wire(s,o,180,command+88+n,64)

def digest_matches(s:readbuf, w:mutbuf, at:u64) -> bool:
    i = 0
    while i < 32:
        word = widen(byte(w,length(w)-4096+1088+i))
        if byte(s,at+2*i) != hexchar(word >> 4) or byte(s,at+2*i+1) != hexchar(word & 15):
            return False
        i = i+1
    return True

def hexchar(x:u64) -> u64:
    return choose(x < 10,x+48,x+87)
'''

ISSUE = '''
# The private issue input replaces the evaluation receipt ref with the
# original build receipt ref. Two issued Store documents and the original
# HIAEFI04 then follow, each with an unsigned word length.
def issue_receipt(s:readbuf,o:mutbuf,w:mutbuf,refs:u64,n:u64) -> u64:
    if n < 1020:
        return BAD
    i = 0
    while i < 5:
        if checked_ref(s,refs+176*i) == False:
            return BAD
        i = i+1
    cursor = refs+880
    i = 1
    while i <= 2:
        if length(s)-cursor < 8:
            return BAD
        width = read_word(s,cursor)
        cursor = cursor+8
        if width < 2 or width > 8388608 or width > length(s)-cursor:
            return BAD
        ref = refs+176*(2+i)
        if widen(pair_hash_sha256(s,w,cursor,width)) != 32 or digest_matches(s,w,ref+53) == False:
            return BAD
        if fields(s,o,w,cursor,width) == False:
            return BAD
        if i == 1:
            # All documents must bind precisely the same typed Context.
            put(w,256,get(w,2048+16*K_context))
        if document_matches(s,o,w,refs,i) == False:
            return BAD
        if i == 2:
            if get(w,2056+16*K_workload) != 176 or get(w,2056+16*K_objective) != 176:
                return BAD
            put(w,20048,get(w,2048+16*K_objective))
            put(w,20056,get(w,2048+16*K_workload))
        cursor = cursor+width
        i = i+1
    put(w,20768,refs)
    if claimed_inputs(s,o,w,cursor) == False:
        return BAD
    return issue_json(s,o,w,refs)

# Only the immutable unique-Store acknowledgement and its original two admitted
# canonical projections can authorize new receipt issuance.
def claimed_inputs(s:readbuf,o:mutbuf,w:mutbuf,cursor:u64) -> bool:
    if length(s)-cursor < 8:
        return False
    size = read_word(s,cursor)
    at = cursor+8
    if size < 760 or size > length(s)-at or read_word(s,at) != CLAIM:
        return False
    if read_word(s,at+8) != size-648 or read_word(s,at+16) < 1 or read_word(s,at+24) < 1 or read_word(s,at+32) == 0:
        return False
    if ((read_word(s,at+40)^512) | (read_word(s,at+48)^64) | (read_word(s,at+56)^8)) != 0:
        return False
    state = at+64
    state_tag = (read_word(s,state)^JOURNAL) | (read_word(s,state+8)^3) | (read_word(s,state+16)^9)
    state_flags = (read_word(s,state+24)^1) | read_word(s,state+32) | (read_word(s,state+40)^1)
    if (state_tag | state_flags) != 0:
        return False
    if same(s,state+128,116,64) == False or same(s,state+64,246,64) == False or same(s,state+128,180,64) == False or same(s,state+192,244,66) == False:
        return False
    route = at+576
    route_tag = (read_word(s,route)^ROUTE) | (read_word(s,route+8)^2) | (read_word(s,route+16)^11)
    route_sizes = read_word(s,route+24) | (read_word(s,route+32)^48) | read_word(s,route+40) | (read_word(s,route+48)^48)
    if (route_tag | route_sizes | (read_word(s,route+56)^512) | (read_word(s,at+640)^COMMIT_ACK)) != 0:
        return False
    stop = at+size
    if length(s)-stop < 8:
        return False
    call_size = read_word(s,stop)
    call = stop+8
    if call_size < 2 or call_size > 8388608 or call_size > length(s)-call:
        return False
    if widen(pair_hash_sha256(s,w,call,call_size)) != 32 or digest_matches(s,w,246) == False:
        return False
    if fields(s,o,w,call,call_size) == False or get(o,96) != 2 or evaluate_tool(s,w) == False:
        return False
    args = get(w,2048+16*K_arguments)
    width = get(w,2056+16*K_arguments)
    put(w,20736,args)
    put(w,20744,width)
    pos = call+call_size
    if length(s)-pos < 8:
        return False
    unsigned = pos+8
    extent = read_word(s,pos)
    if extent < 2 or extent > 8388608 or extent != length(s)-unsigned:
        return False
    if fields(s,o,w,unsigned,extent) == False or get(o,96) != 5 or evaluate_tool(s,w) == False:
        return False
    if width == 0 or width != get(w,2056+16*K_arguments) or same(s,args,get(w,2048+16*K_arguments),width) == False:
        return False
    if get(w,2056+16*K_request_sha256) != 0:
        return False
    put(w,20752,unsigned)
    put(w,20760,extent)
    return fresh_facts(s,o,w,get(w,20768),at+648,stop)

def evaluate_tool(s:readbuf,w:mutbuf) -> bool:
    at = get(w,2048+16*K_tool)
    return get(w,2056+16*K_tool) == 14 and evaluate_tool_literal(s,at)

def fresh_facts(s:readbuf,o:mutbuf,w:mutbuf,refs:u64,start:u64,end:u64) -> bool:
    if read_word(s,start) != FRESH:
        return False
    count = read_word(s,start+8)
    if count < 9 or count > 1024:
        return False
    first = read_word(s,start+80)
    last = read_word(s,start+104)
    if first == 0 or read_word(s,start+88) < first or read_word(s,start+96) < read_word(s,start+88) or last < read_word(s,start+96) or last-first != read_word(s,64):
        return False
    req = read_word(s,start+48)
    rows = read_word(s,start+56)
    left = read_word(s,start+64)
    right = read_word(s,start+72)
    at = start+112
    if req < 2 or req > end-at or rows > end-at-req:
        return False
    if left > end-at-req-rows or right != end-at-req-rows-left or left < 24 or right < 24:
        return False
    if read_word(s,at+req+rows) != BATCH or read_word(s,at+req+rows+left) != BATCH:
        return False
    if read_word(s,at+req+rows+8) != read_word(s,326) or read_word(s,at+req+rows+left+8) != read_word(s,326):
        return False
    if fields(s,o,w,at,req) == False:
        return False
    id = get(w,2048+16*K_request_sha256)
    if get(w,2056+16*K_request_sha256) != 66 or widen(pair_hash_sha256(s,w,get(w,20752),get(w,20760))) != 32 or digest_matches(s,w,id+1) == False:
        return False
    arg = get(w,20736)
    width = get(w,20744)
    if width == 0 or fields(s,o,w,arg,width) == False:
        return False
    if ref_field(s,w,K_baseline_artifact,refs) == False or ref_field(s,w,K_candidate_artifact,refs+176) == False or ref_field(s,w,K_build_receipt,refs+352) == False or ref_field_len(s,w,K_context,get(w,256),121) == False:
        return False
    vr = get(w,2048+16*K_verification_receipts)
    num = count-9
    if get(w,2056+16*K_verification_receipts) != choose(num==0,2,1+177*num) or byte(s,vr) != 91:
        return False
    put(w,20000,vr)
    put(w,20008,get(w,2056+16*K_verification_receipts))
    at = at+req
    stop = at+rows
    i = 0
    while i < count:
        if at > stop or stop-at < 208 or read_word(s,at) != i:
            return False
        kind = read_word(s,at+8)
        meta = read_word(s,at+16)
        size = read_word(s,at+24)
        ref = at+32
        at = at+208
        if meta > stop-at or size > stop-at-meta or checked_ref(s,ref) == False:
            return False
        if i == 0:
            if kind != 3 or same(s,ref+53,get(w,256)+55,64) == False or fields(s,o,w,at+meta,size) == False:
                return False
            if ref_field(s,w,K_objective,get(w,20048)) == False or ref_field(s,w,K_workload,get(w,20056)) == False:
                return False
            install = get(w,2048+16*K_installation)
            install_width = get(w,2056+16*K_installation)
            if install_width < 2 or byte(s,install) != 123:
                return False
            put(w,20016,install)
            put(w,20024,install_width)
        elif i <= 2:
            if kind != 7 or same(s,ref,refs+176*(i-1),176) == False or size != read_word(s,8*i):
                return False
            if fields(s,o,w,at,meta) == False or ref_field_len(s,w,K_installation,get(w,20016),get(w,20024)) == False or ref_field_len(s,w,K_context,get(w,256),121) == False:
                return False
            digest = get(w,2048+16*K_core_sha256)
            if get(w,2056+16*K_core_sha256) != 66 or hexadecimal(s,digest+1,64) == False:
                return False
            put(w,20032+8*(i-1),digest)
        elif i == 3:
            if kind != 5 or same(s,ref,refs+352,176) == False:
                return False
        elif i < count-5:
            if kind != 8 or same(s,ref,vr+1+177*(i-4),176) == False:
                return False
        elif i < count-3:
            digest = get(w,20032+8*(i-(count-5)))
            if kind != 0 or widen(pair_hash_sha256(s,w,at,meta)) != 32 or digest_matches(s,w,digest+1) == False:
                return False
        elif (i == count-3 and kind != 6) or (i > count-3 and kind != 0):
            return False
        if i == count-2:
            if same(s,ref,get(w,20048),176) == False or fields(s,o,w,at+meta,size) == False or string_field(s,w,K_metric,choose(read_word(s,24)==1,S_BYTES,S_LATENCY)) == False:
                return False
            threshold = get(w,2048+16*K_min_improvement_ratio)
            width = get(w,2056+16*K_min_improvement_ratio)
            if width == 0 or widen(decimal_convert(s,w,threshold,width)) != 8 or exact_ratio(w) != read_word(s,32):
                return False
        if i == count-1 and same(s,ref,get(w,20056),176) == False:
            return False
        if widen(pair_hash_sha256(s,w,at+meta,size)) != 32 or digest_matches(s,w,ref+53) == False:
            return False
        at = at+meta+size
        i = i+1
    return at == stop

def ref_field_len(s:readbuf,w:mutbuf,key:u64,at:u64,n:u64) -> bool:
    return get(w,2056+16*key) == n and same(s,get(w,2048+16*key),at,n)
'''

MATCH = '''
def document_matches(s:readbuf, o:mutbuf, w:mutbuf, refs:u64, order:u64) -> bool:
    context = get(w,2048+16*K_context)
    if get(w,2056+16*K_context) != 121 or context_prefix(s,context) == False or same(s,context+7,80,36) == False or ref_hash_prefix(s,context+43) == False or hexadecimal(s,context+55,64) == False:
        return False
    if order == 0:
        put(w,256,context)
    elif same(s,context,get(w,256),121) == False:
        return False
    if order == 1:
        return string_field(s,w,K_schema,S_LEDGER) and quoted_span(s,w,K_native_child_wall_ns,get(w,64),get(w,72)) and decimal_field(s,w,K_evaluation_wall_ns_through_report,read_word(s,72))
    if ref_field(s,w,K_baseline_artifact,refs) == False or ref_field(s,w,K_candidate_artifact,refs+176) == False:
        return False
    if string_field(s,w,K_outcome,get(w,32)) == False or bool_field(s,w,K_planned_workload_complete,get(w,16)) == False:
        return False
    if order == 0:
        return string_field(s,w,K_schema,S_RECEIPT) and ref_field(s,w,K_measurements,refs+704) and ref_field(s,w,K_full_cost_ledger,refs+528) and bool_field(s,w,K_report_complete,1) and bool_field(s,w,K_termination_confirmed,1) and bool_field(s,w,K_adopted,0)
    rat = get(w,2048+16*K_improvement_ratio)
    size = get(w,2056+16*K_improvement_ratio)
    if size == 0 or widen(decimal_convert(s,w,rat,size)) != 8 or exact_ratio(w) != get(w,40):
        return False
    if observations_match(s,o,w) == False:
        return False
    return string_field(s,w,K_schema,S_MEASURE) and string_field(s,w,K_metric,choose(read_word(s,24)==1,S_BYTES,S_LATENCY)) and decimal_field(s,w,K_baseline_value,get(w,48)) and decimal_field(s,w,K_candidate_value,get(w,56)) and decimal_field(s,w,K_reference_wall_ns,read_word(s,64)) and numeric_field(s,w,K_planned_cases,read_word(s,326))

def node_field(o:mutbuf, parent:u64, key:u64) -> u64:
    if parent == MAX or get(o,parent) != 6:
        return MAX
    idx = get(o,parent+24)
    while idx != MAX:
        row = 64+72*idx
        if key_id(o,get(o,row+40),get(o,row+48)) == key:
            return row
        idx = get(o,row+16)
    return MAX

def observations_match(s:readbuf, o:mutbuf, w:mutbuf) -> bool:
    observations = node_field(o,64,K_observations)
    native = node_field(o,64,K_native_runs)
    refs = node_field(o,64,K_reference_runs)
    if observations == MAX or get(o,observations) != 5 or native == MAX or get(o,native) != 6 or refs == MAX or get(o,refs) != 6:
        return False
    complete = get(w,16)
    count = read_word(s,326)
    rows = get(o,observations+32)
    if rows > count or (complete == 1 and rows != count):
        return False
    arm = 0
    while arm < 2:
        name = choose(arm == 0,K_baseline,K_candidate)
        nr = node_field(o,native,name)
        rr = node_field(o,refs,name)
        if complete == 1 and (nr == MAX or rr == MAX or get(o,nr) != 6 or get(o,rr) != 6):
            return False
        if nr != MAX and complete == 1:
            node = node_field(o,nr,K_total_native_ns)
            if node == MAX or get(o,node) != 4 or arena_decimal(o,node,read_word(s,342+8*arm)) == False:
                return False
        arm = arm+1
    child = get(o,observations+24)
    i = 0
    while i < rows:
        row = 64+72*child
        id = node_field(o,row,K_index)
        if id == MAX or get(o,id) != 3 or decimal_equal(s,get(w,264)+get(o,id+24),get(o,id+32),i) == False:
            return False
        arm = 0
        while arm < 2:
            vm = node_field(o,row,choose(arm == 0,K_baseline_vm,K_candidate_vm))
            observed = node_field(o,row,choose(arm == 0,K_baseline_native,K_candidate_native))
            if complete == 1 and (vm == MAX or get(o,vm) != 6 or observed == MAX or get(o,observed) != 6):
                return False
            sample = get(w,4096+8*(512*arm+i))
            if observed != MAX and sample == 0:
                return False
            if observed != MAX and sample != 0 and read_word(s,sample+16) == 0 and read_word(s,sample+24) == 0:
                elapsed = node_field(o,observed,K_elapsed_ns)
                if elapsed == MAX or get(o,elapsed) != 4 or arena_decimal(o,elapsed,read_word(s,sample+40)) == False:
                    return False
            arm = arm+1
        child = get(o,row+16)
        i = i+1
    return True

def arena_decimal(o:mutbuf, row:u64, expected:u64) -> bool:
    size = get(o,row+32)
    at = get(o,row+24)
    if size == 0 or size > 20 or (size > 1 and byte(o,at) == 48):
        return False
    value = 0
    i = 0
    while i < size:
        ch = widen(byte(o,at+i))
        if ch < 48 or ch > 57 or value > 1844674407370955161 or (value == 1844674407370955161 and ch > 53):
            return False
        value = value*10+ch-48
        i = i+1
    return value == expected

def ref_field(s:readbuf, w:mutbuf, key:u64, at:u64) -> bool:
    return get(w,2048+16*key+8) == 176 and same(s,get(w,2048+16*key),at,176)

def quoted_span(s:readbuf, w:mutbuf, key:u64, expected:u64, width:u64) -> bool:
    at = get(w,2048+16*key)
    return get(w,2048+16*key+8) == width+2 and byte(s,at) == 34 and byte(s,at+width+1) == 34 and same(s,at+1,expected,width)

def bool_field(s:readbuf, w:mutbuf, key:u64, value:u64) -> bool:
    at = get(w,2048+16*key)
    size = get(w,2048+16*key+8)
    if value == 1:
        return size == 4 and true_text(s,at)
    return size == 5 and false_text(s,at)

def decimal_field(s:readbuf, w:mutbuf, key:u64, expected:u64) -> bool:
    at = get(w,2048+16*key)
    size = get(w,2048+16*key+8)
    if size < 3 or size > 22 or byte(s,at) != 34 or byte(s,at+size-1) != 34:
        return False
    return decimal_equal(s,at+1,size-2,expected)

def numeric_field(s:readbuf, w:mutbuf, key:u64, expected:u64) -> bool:
    return decimal_equal(s,get(w,2048+16*key),get(w,2048+16*key+8),expected)

def decimal_equal(s:readbuf, at:u64, size:u64, expected:u64) -> bool:
    if size == 0 or size > 20 or digits(s,at,size) == False:
        return False
    value = 0
    i = 0
    while i < size:
        digit = widen(byte(s,at+i))-48
        if value > 1844674407370955161 or (value == 1844674407370955161 and digit > 5):
            return False
        value = value*10+digit
        i = i+1
    return value == expected
'''

FIELDS = ('schema','outcome','baseline_artifact','candidate_artifact','full_cost_ledger','measurements',
          'metric','baseline_value','candidate_value','planned_cases','planned_workload_complete','report_complete',
          'termination_confirmed','adopted','reference_wall_ns','native_child_wall_ns','evaluation_wall_ns_through_report','context','improvement_ratio','observations','native_runs',
          'reference_runs','baseline','candidate','index','elapsed_ns','baseline_vm','candidate_vm','baseline_native',
          'candidate_native','total_native_ns','arguments','request_sha256','build_receipt','verification_receipts','installation','core_sha256','objective','workload','min_improvement_ratio','tool')
OUTCOMES = ('budget_exceeded','incorrect','inconclusive','improved','regressed','unchanged')
NAMES = (*OUTCOMES, 'hepta.hia.agent.evaluation.v1','hepta.hia.agent.cost-ledger.v1',
         'hepta.hia.agent.measurements.v1','artifact_bytes','latency_ns')
LITERALS = {
    'result_first':'{"adopted":false,"baseline_artifact":',
    'result_candidate':',"candidate_artifact":', 'result_receipt':',"evaluation_receipt":',
    'result_ledger':',"full_cost_ledger":','result_measurement':',"measurements":',
    'result_outcome':',"outcome":','result_complete':',"planned_workload_complete":',
    'result_end':',"report_complete":true,"termination_confirmed":true}',
    'refused_prefix':'{"code":"E_HIA_WORKLOAD_EXPECTATION","details_artifact":null,"message":"declared case expectation differs from baseline Core at index ',
    'refused_suffix':'","phase":"execution","retry_action":"correct_input"}',
    'envelope_begin':'{"contract_version":"hepta.hia.agent-native.v1",',
    'envelope_success':'"request_id":"', 'envelope_result':'","result":',
    'envelope_complete':',"status":"completed"}','envelope_error':'"error":',
    'envelope_request':',"request_id":"','envelope_rejected':'","status":"rejected"}',
    'write_true':'true','write_false':'false',
}
CHECKS = {'evaluate_tool_literal':'"hia_evaluate"', 'context_prefix':'{"id":"', 'ref_prefix':'{"id":"a-', 'ref_hash_prefix':'","sha256":"',
          'ref_uri_prefix':'","uri":"hia://artifacts/', 'true_text':'true','false_text':'false'}
STATE = 32 << 20


def hia_literals():
    lines = []
    def write(name, value):
        raw = value.encode()
        lines.append(f'def {name}(o:mutbuf, at:u64) -> u64:')
        for i in range(0,len(raw),8):
            part = raw[i:i+8]
            if len(part) == 8:
                lines.append(f'    put(o,at+{i},{int.from_bytes(part,"little")})')
            else:
                lines.extend(f'    store(o,at+{i+j},{ch})' for j,ch in enumerate(part))
        lines.append(f'    return at+{len(raw)}')
    def check(name, raw):
        parts = []
        for i in range(0,len(raw),8):
            block = raw[i:i+8]
            if len(block) == 8:
                parts.append(f'(read_word(s,at+{i}) ^ {int.from_bytes(block,"little")})')
            else:
                parts.extend(f'(byte(s,at+{i+j}) ^ {ch})' for j,ch in enumerate(block))
        lines.extend((f'def {name}(s:readbuf, at:u64) -> bool:', '    return ('+' | '.join(parts)+') == 0'))
    from tools.generate_hia_agent_identity import EVALUATION_RECORD
    parts = EVALUATION_RECORD.split('{}')
    assert len(parts) == 13
    def insert_part(i):
        raw=parts[i].encode()
        for j in range(0,len(raw),8):
            cell=raw[j:j+8]
            if len(cell)==8:
                lines.append(f'    put(o,p+{j},{int.from_bytes(cell,"little")})')
            else:
                lines.extend(f'    store(o,p+{j+k},{v})' for k,v in enumerate(cell))
        lines.append(f'    p = p+{len(raw)}')
    # Invoke the exact published identity template with spans derived from
    # the admitted Store rows and the settled decision.
    lines += ['def issue_json(s:readbuf,o:mutbuf,w:mutbuf,refs:u64) -> u64:', '    p = 0']
    spans = (('refs','176'),(f'get(w,{STATE+20032})','66'),('refs+352','176'),
             ('refs+176','176'),(f'get(w,{STATE+20040})','66'),(f'get(w,{STATE+256})','121'),
             ('refs+528','176'),(f'get(w,{STATE+20016})',f'get(w,{STATE+20024})'),('refs+704','176'))
    for i,(at,width) in enumerate(spans):
        insert_part(i)
        lines.append(f'    p = copy_wire(s,o,{at},p,{width})')
    insert_part(9)
    lines.append(f'    p = outcome_name(o,p,get(w,{STATE+32}))')
    insert_part(10)
    lines.append(f'    p = boolean(o,p,get(w,{STATE+16}))')
    insert_part(11)
    lines.append(f'    p = copy_wire(s,o,get(w,{STATE+20000}),p,get(w,{STATE+20008}))')
    insert_part(12)
    lines.append('    return p')
    for name, value in LITERALS.items():
        write(name,value)
    for name, value in CHECKS.items():
        check(name,value.encode())
    for i,value in enumerate(NAMES,1):
        check(f'match_{i}',('"'+value+'"').encode())
        if i <= len(OUTCOMES):
            write(f'outcome_{i}','"'+value+'"')
    lines.append('def outcome_name(o:mutbuf, at:u64, n:u64) -> u64:')
    lines.extend(f'    if n == {i}:\n        return outcome_{i}(o,at)' for i in range(1,7))
    lines += ['    return at','def boolean(o:mutbuf, at:u64, flag:u64) -> u64:',
              '    if flag == 1:\n        return write_true(o,at)','    return write_false(o,at)',
              'def string_field(s:readbuf, w:mutbuf, key:u64, value:u64) -> bool:',
              f'    at = get(w,{STATE+2048}+16*key)', f'    size = get(w,{STATE+2056}+16*key)']
    lines.extend(f'    if value == {i}:\n        return size == {len(name)+2} and match_{i}(s,at)' for i,name in enumerate(NAMES,1))
    lines += ['    return False','def next_power(value:u64) -> u64:']
    lines.extend(f'    if value == {10**i}:\n        return {10**(i-1)}' for i in range(19,0,-1))
    return '\n'.join((*lines,'    return 0'))


def relocated(source):
    import ast
    tree = ast.parse(source)
    class Memory(ast.NodeTransformer):
        def visit_Call(self,n):
            self.generic_visit(n)
            if isinstance(n.func,ast.Name) and n.func.id in ('put','get') and isinstance(n.args[0],ast.Name) and n.args[0].id=='w':
                n.args[1]=ast.BinOp(ast.Constant(STATE),ast.Add(),n.args[1])
            return n
    return ast.unparse(ast.fix_missing_locations(Memory().visit(tree)))


def settlement_keys(names):
    """Match each complete JSON key with one branch per encoded length."""
    lines = ['def key_id(w:mutbuf, at:u64, extent:u64) -> u64:']
    encoded = [(i, name.encode('ascii')) for i, name in enumerate(names, 1)]
    for width in sorted({len(name) for _, name in encoded}):
        lines.append(f'    if extent == {width}:')
        for off in range(0, width, 8):
            lines.append(f'        word{off} = match_word(w, at + {off}, {min(8, width-off)})')
        lines.append('        result = 0')
        for ordinal, name in encoded:
            if len(name) != width:
                continue
            comparisons = [f'(word{off} ^ {int.from_bytes(name[off:off+8], "little")})'
                           for off in range(0, width, 8)]
            lines.append(f'        result = result | choose(({" | ".join(comparisons)}) == 0, {ordinal}, 0)')
        lines.append('        return result')
    return '\n'.join((*lines, '    return 0', ''))


def json_slice():
    import ast
    from tools.generate_hia_json_decode import source_program
    from tools.generate_hia_mcp_request import WIRE_HELPERS
    tree = ast.parse(source_program(wire_spans=True))
    names = {n.name for n in tree.body}
    explicit = {n.name for n in tree.body if 's' in {x.arg for x in n.args.args}
                and not any(x.annotation.id == 'mutbuf' for x in n.args.args)}
    class Span(ast.NodeTransformer):
        def visit_FunctionDef(self,n):
            buffers=[x.arg for x in n.args.args if x.annotation.id=='mutbuf']
            self.span=(f'get({buffers[0]},length({buffers[0]})-8)' if buffers else 'window')
            if n.name in explicit:
                n.args.args.append(ast.arg(arg='window',annotation=ast.Name('u64',ast.Load())))
            self.generic_visit(n)
            n.name='section_'+n.name
            return n
        def visit_Call(self,n):
            self.generic_visit(n)
            if not isinstance(n.func,ast.Name):
                return n
            if n.func.id in names:
                if n.func.id in explicit:
                    n.args.append(ast.parse(self.span,mode='eval').body)
                n.func.id='section_'+n.func.id
            elif n.args and isinstance(n.args[0],ast.Name) and n.args[0].id=='s':
                if n.func.id=='length':
                    return ast.parse('('+self.span+' & 4294967295)',mode='eval').body
                if n.func.id=='byte':
                    n.args[1]=ast.BinOp(ast.parse('('+self.span+' >> 32)',mode='eval').body,ast.Add(),n.args[1])
            return n
    decoder=ast.unparse(ast.fix_missing_locations(Span().visit(tree)))
    helpers=function(WIRE_HELPERS,'match_word')+'\n'+settlement_keys(FIELDS)
    body=f'''
def fields(s:readbuf, o:mutbuf, w:mutbuf, at:u64, width:u64) -> bool:
    put(w,{STATE+264},at)
    put(w,48,262144)
    put(w,56,128)
    put(w,length(w)-8,(at << 32) | width)
    put(o,length(o)-8,(at << 32) | width)
    if widen(section_decode_json(s,o,w)) >= 4294967292 or get(o,64) != 6:
        return False
    i = 0
    while i <= {len(FIELDS)}:
        put(w,{STATE+2048}+16*i,0)
        put(w,{STATE+2056}+16*i,0)
        i = i+1
    i = get(o,88)
    while i != 18446744073709551615:
        row = 64+72*i
        key = key_id(o,get(o,row+40),get(o,row+48))
        if key != 0:
            off = choose(get(o,row) < 4,24,56)
            put(w,{STATE+2048}+16*key,at+get(o,row+off))
            put(w,{STATE+2056}+16*key,get(o,row+off+8))
        i = get(o,row+16)
    return True
'''
    return '\n'.join((decoder,helpers,body))


def program():
    from tools.generate_hia_mcp_request import WIRE_HELPERS
    from tools.generate_hia_worker_evaluate_case import source_program as case_source
    src=identity()
    judge=function(src,'measurement_policy')
    judge=judge.replace('def measurement_policy(s:readbuf, o:mutbuf)', 'def judge(w:mutbuf, o:mutbuf)')
    judge=judge.replace('if length(s) != 48:',f'if length(w) < {STATE+176}:')
    judge=re.sub(r'read_word\(s, (\d+)\)',lambda m:f'get(w,{STATE+128+int(m[1])})',judge)
    constants={name:int.from_bytes(raw,'little') for name,raw in dict(
        REQUEST=b'HIAEST01',ISSUE=b'HIAEPR01',FRESH=b'HIAEFI04',BATCH=b'HIAEBT01',PAIR=b'HIAEPM01',BUDGET=b'HIAEBRS1',DECISION=b'HIAESD01',
        CLAIM=b'HIAEJC01',JOURNAL=b'HIAJRN02',ROUTE=b'HIAJMO01',COMMIT_ACK=b'HIASTCP1',
        TERMINAL=b'HIAESTR1',SIDEBAND=b'HIAIND01',UPDATE=b'HIAUPB01',CTX=b'ctx-').items()}
    constants.update(MAX=(1<<64)-1,BAD=4294967293,S_RECEIPT=7,S_LEDGER=8,S_MEASURE=9,S_BYTES=10,S_LATENCY=11)
    constants.update({'K_'+k:i for i,k in enumerate(FIELDS,1)})
    policy=POLICY.replace('fields(s,w,at,width)', 'fields(s,o,w,at,width)')
    policy=relocated(policy+'\n'+MATCH+'\n'+ISSUE)
    policy=re.sub(r'\b('+'|'.join(constants)+r')\b',lambda m:str(constants[m[0]]),policy)
    from tools.generate_hia_worker_request import decimal_program
    case=case_source()
    ratio_source='def exact_ratio(w:mutbuf) -> u64:\n    return get(w,length(w)-192)'

    return '\n'.join((policy,judge,function(src,'rational_bits'),hia_literals(),json_slice(),snapshot_hash(),decimal_program(),ratio_source,
                      *(function(case,name) for name in ('read_word','put','get','widen'))))



def settlement_document():
    """Fold fixed wire offsets before emitting the bounded self-host source."""
    import ast
    import operator

    operators = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
                 ast.BitAnd: operator.and_, ast.BitOr: operator.or_, ast.BitXor: operator.xor}

    class FixedOffsets(ast.NodeTransformer):
        def visit_BinOp(self, node):
            node = self.generic_visit(node)
            operation = operators.get(type(node.op))
            if (operation is not None and isinstance(node.left, ast.Constant)
                    and isinstance(node.right, ast.Constant)
                    and type(node.left.value) is int and type(node.right.value) is int):
                value = operation(node.left.value, node.right.value) & ((1 << 64) - 1)
                return ast.copy_location(ast.Constant(value), node)
            return node

    source = ast.unparse(FixedOffsets().visit(ast.parse(program())))
    return document(source, SOURCE.stem)


def packer_document():
    from tools.generate_hia_native_filter import document as packer, elf_header, template
    frame=template(wire_bytes=512<<20,output_bytes=32<<20,workspace_bytes=48<<20)
    return packer(magic=MAGIC,module=PACKER.stem,image_template=frame)


if __name__=='__main__':
    SOURCE.write_text(render_assembly(settlement_document()),encoding='utf-8')
    PACKER.write_text(render_assembly(packer_document()),encoding='utf-8')
