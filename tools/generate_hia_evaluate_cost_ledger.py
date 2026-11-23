"""Author the settled Evaluate ledger over a real read-only Store transaction.

HIAELQ01 + fresh returns frozen artifact ref (176 bytes) followed by two
Store SELECTs and ROLLBACK. HIAELR01 + four little-endian lengths followed by
fresh, decision, entire Store reply, and frozen policy body returns public JSON.
"""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_identity import source_program as identity
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_evaluate_paired_batch import snapshot_hash
from tools.generate_hia_evaluate_settlement import ISSUE, MATCH, POLICY, STATE, hia_literals, json_slice
from tools.generate_hia_worker_evaluate_case import source_program as case_source
from tools.generate_hia_worker_inspection_effect import function

SOURCE = Path('examples/hia_bootstrap/evaluate_cost_ledger.hepta')
PACKER = SOURCE.with_name('evaluate_cost_ledger_packer.hepta')
PACK_MAGIC = int.from_bytes(b'HIAELP01', 'little')
KEYS = ('arguments','context','budget','cost_policy','external_costs_complete','external_costs',
        'expected_invocations','discovery_wall_ns','model_wall_ns','model_tokens','tool')
# w[0:8MiB] holds the published identity frame only after all decode operations.
# The three persistent windows store the working typed row, positional entries
# and query state outside the decoder's 32 MiB arena.
BODY = '''
def ledger(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 120 or length(o) != 8388608 or length(w) < 50331648:
        return BAD
    if read_word(s,0) == QUERY:
        if fresh_context(s,o,w,8,length(s)-8) == False:
            return BAD
        ref = get(w,MEM+8)
        ctx = get(w,MEM)
        copy_wire(s,o,ref,0,176)
        p = select_command(s,o,176,1,8,ctx+7,36)
        p = select_command(s,o,p,2,5,ref+7,34)
        return command(o,p,3,3,0,0)
    if read_word(s,0) != RENDER:
        return BAD
    f = read_word(s,8)
    d = read_word(s,16)
    r = read_word(s,24)
    p = read_word(s,32)
    if f > length(s)-40 or d > length(s)-40-f or r > length(s)-40-f-d or p != length(s)-40-f-d-r:
        return BAD
    if fresh_context(s,o,w,40,f) == False or policy(s,o,w,40+f+d+r,p) == False:
        return BAD
    pos = 40+f
    if d < 73 or read_word(s,pos) != DECISION or read_word(s,pos+64) != d-72 or digits(s,pos+72,d-72) == False:
        return BAD
    start = read_word(s,120)
    end = read_word(s,144)
    if start == 0 or end < start or end-start != read_word(s,pos+48):
        return BAD
    put(w,MEM+72,pos)
    if transaction(s,o,w,pos+d,r) == False:
        return BAD
    return emit_ledger(s,o,w)

def fresh_context(s:readbuf,o:mutbuf,w:mutbuf,at:u64,size:u64) -> bool:
    if size < 112 or read_word(s,at) != FRESH or read_word(s,at+8) < 9 or read_word(s,at+8) > 1024:
        return False
    req = read_word(s,at+48)
    rows = read_word(s,at+56)
    left = read_word(s,at+64)
    right = read_word(s,at+72)
    if req > size-112 or rows > size-112-req or left > size-112-req-rows or right != size-112-req-rows-left:
        return False
    if left < 24 or right < 24 or read_word(s,at+80) == 0 or read_word(s,at+88) < read_word(s,at+80) or read_word(s,at+96) < read_word(s,at+88) or read_word(s,at+104) < read_word(s,at+96):
        return False
    batch = at+112+req+rows
    if read_word(s,batch) != BATCH or read_word(s,batch+left) != BATCH or read_word(s,batch+8) != read_word(s,batch+left+8):
        return False
    if row_inventory(s,at+112+req,rows,read_word(s,at+8)) == False:
        return False
    at = at+112
    if fields(s,o,w,at,req) == False:
        return False
    if field_n(w,K_tool) != 14 or is_evaluate(s,field_at(w,K_tool)) == False:
        return False
    a = field_at(w,K_arguments)
    n = field_n(w,K_arguments)
    if n < 2 or fields(s,o,w,a,n) == False:
        return False
    ctx = field_at(w,K_context)
    if field_n(w,K_context) != 121 or (read_word(s,ctx+7) & 4294967295) != CTX or hexadecimal(s,ctx+11,32) == False or hexadecimal(s,ctx+55,64) == False:
        return False
    put(w,MEM,ctx)
    at = at+req
    if rows < 208 or read_word(s,at) != 0 or read_word(s,at+8) != 3 or checked_ref(s,at+32) == False:
        return False
    meta = read_word(s,at+16)
    n = read_word(s,at+24)
    if meta > rows-208 or n > rows-208-meta or same(s,at+85,ctx+55,64) == False:
        return False
    at = at+208+meta
    if widen(pair_hash_sha256(s,w,at,n)) != 32 or digest_matches(s,w,ctx+55) == False or fields(s,o,w,at,n) == False:
        return False
    a = field_at(w,K_budget)
    n = field_n(w,K_budget)
    if n < 2 or fields(s,o,w,a,n) == False:
        return False
    ref = field_at(w,K_cost_policy)
    if field_n(w,K_cost_policy) != 176 or checked_ref(s,ref) == False:
        return False
    put(w,MEM+8,ref)
    return True

def row_inventory(s:readbuf,at:u64,width:u64,count:u64) -> bool:
    stop = at+width
    i = 0
    while i < count:
        if at > stop or stop-at < 208 or read_word(s,at) != i or checked_ref(s,at+32) == False:
            return False
        meta = read_word(s,at+16)
        n = read_word(s,at+24)
        if meta > stop-at-208 or n > stop-at-208-meta:
            return False
        at = at+208+meta+n
        i = i+1
    return at == stop

def policy(s:readbuf,o:mutbuf,w:mutbuf,a:u64,n:u64) -> bool:
    if widen(pair_hash_sha256(s,w,a,n)) != 32 or digest_matches(s,w,get(w,MEM+8)+53) == False or fields(s,o,w,a,n) == False:
        return False
    f = field_at(w,K_external_costs_complete)
    z = field_n(w,K_external_costs_complete)
    if z == 4 and (read_word(s,f) & 4294967295) == 1702195828:
        put(w,MEM+16,1)
    elif z == 5 and (read_word(s,f) & 1099511627775) == 435728179558:
        put(w,MEM+16,0)
    else:
        return False
    if save_field(w,K_expected_invocations,0) == False:
        return False
    a = field_at(w,K_external_costs)
    n = field_n(w,K_external_costs)
    if n < 2 or fields(s,o,w,a,n) == False:
        return False
    return save_field(w,K_discovery_wall_ns,1) and save_field(w,K_model_tokens,2) and save_field(w,K_model_wall_ns,3)

def field_at(w:mutbuf,key:u64) -> u64:
    return get(w,FIELD_AT+key*16)

def field_n(w:mutbuf,key:u64) -> u64:
    return get(w,FIELD_AT+8+key*16)

def save_field(w:mutbuf,key:u64,index:u64) -> bool:
    put(w,MEM+128+16*index,field_at(w,key))
    put(w,MEM+136+16*index,field_n(w,key))
    return field_n(w,key) != 0

def command(o:mutbuf,p:u64,ordinal:u64,kind:u64,target:u64,size:u64) -> u64:
    put(o,p,COMMAND)
    put(o,p+8,1)
    put(o,p+16,ordinal)
    put(o,p+24,kind)
    put(o,p+32,target)
    put(o,p+40,size)
    return p+48

def select_command(s:readbuf,o:mutbuf,p:u64,ordinal:u64,target:u64,a:u64,n:u64) -> u64:
    p = command(o,p,ordinal,27,target,56+n)
    put(o,p,PARAMS)
    put(o,p+8,1)
    put(o,p+16,1)
    put(o,p+24,56+n)
    put(o,p+32,3)
    put(o,p+40,56)
    put(o,p+48,n)
    return copy_wire(s,o,a,p+56,n)

def ack(s:readbuf,w:mutbuf,a:u64,end:u64,ordinal:u64,kind:u64) -> bool:
    if a > end or end-a < 80 or read_word(s,a) != ACK or read_word(s,a+8) != 1 or read_word(s,a+16) != ordinal or read_word(s,a+24) != kind or read_word(s,a+32) != 0 or read_word(s,a+40) != 0:
        return False
    if ordinal == 0:
        put(w,MEM+32,read_word(s,a+48))
    return read_word(s,a+48) == get(w,MEM+32) and read_word(s,a+56) == 0 and read_word(s,a+64) == 0 and read_word(s,a+72) == 0

def transaction(s:readbuf,o:mutbuf,w:mutbuf,a:u64,n:u64) -> bool:
    end = a+n
    if ack(s,w,a,end,0,0) == False:
        return False
    put(w,MEM+40,0)
    put(w,MEM+48,0)
    put(w,MEM+56,0)
    put(w,MEM+64,0)
    put(w,MEM+80,0)
    put(w,MEM+88,0)
    put(w,MEM+96,0)
    put(w,MEM+104,0)
    put(w,MEM+112,0)
    a = query_result(s,o,w,a+80,end,5)
    if a == 0 or ack(s,w,a,end,1,27) == False:
        return False
    a = query_result(s,o,w,a+80,end,1)
    if a == 0 or ack(s,w,a,end,2,27) == False or ack(s,w,a+80,end,3,3) == False:
        return False
    return a+160 == end

def query_result(s:readbuf,o:mutbuf,w:mutbuf,a:u64,end:u64,table:u64) -> u64:
    count = 0
    size = 0
    row = 0
    total = 0
    while a <= end and end-a >= 64:
        kind = read_word(s,a+8)
        id = read_word(s,a+24)
        off = read_word(s,a+32)
        n = read_word(s,a+40)
        index = read_word(s,a+48)
        if read_word(s,a) != FRAME or read_word(s,a+16) != table or read_word(s,a+56) != 0 or n > end-a-64:
            return 0
        a = a+64
        if kind == 4:
            if row != 0 or id != 0 or index != count or n != 416 or off != total:
                return 0
            if read_word(s,a+384) != choose(table==5,5,2) or read_word(s,a+392) != choose(table==5,127,63) or read_word(s,a+400) != count or read_word(s,a+408) != count:
                return 0
            if table == 5:
                put(w,MEM+40,count)
            elif count != 1:
                return 0
            return a+n
        if index != count+1 or id == 0:
            return 0
        if kind == 1:
            if row != 0 or off != 0 or n != 128 or read_word(s,a) != INDEX:
                return 0
            if read_word(s,a+8) != 1 or read_word(s,a+16) != 2 or read_word(s,a+32) != table or read_word(s,a+88) != 0 or read_word(s,a+96) != ROW_ID or read_word(s,a+104) != 1 or read_word(s,a+112) != table or read_word(s,a+120) != id:
                return 0
            put(w,MEM+216,read_word(s,a+80))
            row = id
            size = 0
        elif kind == 2:
            if row != id or off != size or n == 0 or n > ROW_LIMIT-size:
                return 0
            copy_wire(s,w,a,ROW+size,n)
            size = size+n
        elif kind == 3:
            if id != row or off != size or n != 0 or size < 32 or size != get(w,MEM+216):
                return 0
            count = count+1
            if count > choose(table==5,10001,1) or row_cells(w,table,size) == False:
                return 0
            if table == 1:
                if artifact(s,w) == False:
                    return 0
            elif cost_row_data(s,w,count) == False:
                return 0
            total = total+size
            row = 0
        else:
            return 0
        a = a+n
    return 0

def row_cells(w:mutbuf,table:u64,n:u64) -> bool:
    k = choose(table==5,7,6)
    if get(w,ROW) != ROWMAG or get(w,ROW+8) != 1 or get(w,ROW+16) != table or get(w,ROW+24) != k:
        return False
    off = 32+24*k
    i = 0
    while i < k:
        if cell(w,i,1) != off or off > n or cell(w,i,2) > n-off:
            return False
        off = off+cell(w,i,2)
        i = i+1
    return off == n

def cell(w:mutbuf,i:u64,j:u64) -> u64:
    return get(w,ROW+32+24*i+8*j)

def cell_matches(s:readbuf,w:mutbuf,i:u64,at:u64,n:u64) -> bool:
    if cell(w,i,0) != 3 or cell(w,i,2) != n:
        return False
    j = 0
    while j < n:
        if byte(w,ROW+cell(w,i,1)+j) != byte(s,at+j):
            return False
        j = j+1
    return True

def artifact(s:readbuf,w:mutbuf) -> bool:
    r = get(w,MEM+8)
    return cell_matches(s,w,0,r+7,34) and cell_matches(s,w,1,r+53,64) and cell_matches(s,w,2,r+126,48)
'''
ROWS = '''
def cost_row_data(s:readbuf,w:mutbuf,i:u64) -> bool:
    if cell(w,0,0) != 1 or cell(w,0,2) != 8:
        return False
    seq = get(w,ROW+cell(w,0,1))
    prev = get(w,MEM+112)
    if i > 1 and (seq ^ 9223372036854775808) <= (prev ^ 9223372036854775808):
        return False
    put(w,MEM+112,seq)
    scoped = cell(w,1,0) != 0
    if scoped and cell_matches(s,w,1,get(w,MEM)+7,36) == False:
        return False
    if scoped == False and cell(w,1,2) != 0:
        return False
    if i > 10000:
        return True
    if cell(w,2,0) != 3 or cell(w,3,0) != 3 or cell(w,4,0) != 3 or cell(w,5,0) != 3 or (cell(w,6,0) != 3 and cell(w,6,0) != 4):
        return False
    if add_cost(w,choose(scoped,0,2),ROW+cell(w,4,1),cell(w,4,2)) == False:
        return False
    p = ENTRIES+get(w,MEM+48)
    if p+64+quoted_width(w,1)+quoted_width(w,2)+quoted_width(w,3)+quoted_width(w,4)+quoted_width(w,5)+cell(w,6,2) > ENTRIES+8388608:
        return False
    if i > 1:
        store(w,p,44)
        p = p+1
    store(w,p,91)
    p = p+1
    if scoped:
        p = quoted(w,p,1)
    else:
        put(w,p,1819047278)
        p = p+4
    store(w,p,44)
    p = p+1
    p = local_copy(w,ROW+cell(w,6,1),p,cell(w,6,2))
    store(w,p,44)
    p = quoted(w,p+1,3)
    store(w,p,44)
    p = p+1
    if seq >= 9223372036854775808:
        store(w,p,45)
        p = p+1
        seq = 0-seq
    p = decimal(w,p,seq)
    store(w,p,44)
    p = quoted(w,p+1,5)
    store(w,p,44)
    p = quoted(w,p+1,2)
    store(w,p,44)
    p = quoted(w,p+1,4)
    store(w,p,93)
    put(w,MEM+48,p+1-ENTRIES)
    return True

def quoted_width(w:mutbuf,k:u64) -> u64:
    a = ROW+cell(w,k,1)
    n = cell(w,k,2)
    i = 0
    size = n+2
    while i < n:
        ch = widen(byte(w,a+i))
        if ch < 32:
            size = size+choose(ch==8 or ch==9 or ch==10 or ch==12 or ch==13,1,5)
        elif ch == 34 or ch == 92:
            size = size+1
        i = i+1
    return size

def quoted(w:mutbuf,p:u64,k:u64) -> u64:
    a = ROW+cell(w,k,1)
    n = cell(w,k,2)
    store(w,p,34)
    p = p+1
    i = 0
    while i < n:
        v = widen(byte(w,a+i))
        if v == 34 or v == 92:
            store(w,p,92)
            store(w,p+1,v)
            p = p+2
        elif v < 32:
            e = 0
            if v == 8:
                e = 98
            elif v == 9:
                e = 116
            elif v == 10:
                e = 110
            elif v == 12:
                e = 102
            elif v == 13:
                e = 114
            store(w,p,92)
            if e != 0:
                store(w,p+1,e)
                p = p+2
            else:
                put(w,p+1,3158133)
                store(w,p+4,hexchar(v >> 4))
                store(w,p+5,hexchar(v & 15))
                p = p+6
        else:
            store(w,p,v)
            p = p+1
        i = i+1
    store(w,p,34)
    return p+1

def add_cost(w:mutbuf,scope:u64,a:u64,n:u64) -> bool:
    while n > 0 and whitespace(widen(byte(w,a))):
        a = a+1
        n = n-1
    while n > 0 and whitespace(widen(byte(w,a+n-1))):
        n = n-1
    if n == 0:
        return False
    if byte(w,a) == 45 or byte(w,a) == 43:
        scope = scope+choose(byte(w,a)==45,1,0)
        a = a+1
        n = n-1
    if n == 0 or n > 65528:
        return False
    base = SUMS+65536*scope
    slot = MEM+80+8*scope
    old = get(w,slot)
    carry = 0
    i = 0
    j = 0
    while j < n or i < old or carry != 0:
        digit = 0
        if j < n:
            ch = widen(byte(w,a+n-j-1))
            if ch == 95 and j != 0 and j+1 < n:
                j = j+1
                ch = widen(byte(w,a+n-j-1))
                if byte(w,a+n-j+1) < 48 or byte(w,a+n-j+1) > 57:
                    return False
            if ch < 48 or ch > 57:
                return False
            digit = ch-48
            j = j+1
        if i < old:
            digit = digit+widen(byte(w,base+i))
        digit = digit+carry
        carry = choose(digit >= 10,1,0)
        store(w,base+i,digit-10*carry)
        i = i+1
    while i > 0 and byte(w,base+i-1) == 0:
        i = i-1
    put(w,slot,i)
    return True

def whitespace(ch:u64) -> bool:
    return ch == 32 or (ch >= 9 and ch <= 13)

def emit_total(w:mutbuf,o:mutbuf,p:u64,scope:u64) -> u64:
    a = SUMS+65536*scope
    b = a+65536
    an = get(w,MEM+80+scope*8)
    bn = get(w,MEM+88+scope*8)
    sign = choose(an < bn,1,0)
    if an == bn:
        i = an
        while i > 0 and byte(w,a+i-1) == byte(w,b+i-1):
            i = i-1
        if i != 0 and byte(w,a+i-1) < byte(w,b+i-1):
            sign = 1
    store(o,p,34)
    p = p+1
    if sign == 1:
        a = a+65536
        b = b-65536
        i = an
        an = bn
        bn = i
        store(o,p,45)
        p = p+1
    borrow = 0
    i = 0
    while i < an:
        x = widen(byte(w,a+i))+10
        if i < bn:
            x = x-widen(byte(w,b+i))
        x = x-borrow
        borrow = choose(x < 10,1,0)
        store(w,a+i,x-10+10*borrow)
        i = i+1
    while i > 0 and byte(w,a+i-1) == 0:
        i = i-1
    if i == 0:
        store(o,p,48)
        p = p+1
    while i > 0:
        i = i-1
        store(o,p,48+widen(byte(w,a+i)))
        p = p+1
    store(o,p,34)
    return p+1

def policy_value(s:readbuf,o:mutbuf,w:mutbuf,p:u64,i:u64) -> u64:
    return copy_wire(s,o,get(w,MEM+128+16*i),p,get(w,MEM+136+16*i))

def emit_ledger(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    en = get(w,MEM+48)
    d = get(w,MEM+72)
    limits = en+get(w,MEM+80)+get(w,MEM+88)+get(w,MEM+96)+get(w,MEM+104)+read_word(s,d+64)+512
    i = 0
    while i < 4:
        limits = limits+get(w,MEM+136+16*i)
        i = i+1
    if limits > length(o):
        return BAD
    put(o,16,get(w,MEM+40))
    put(o,24,get(w,MEM+16))
    store(o,32,91)
    p = copy_wire(s,o,get(w,MEM),33,121)
    store(o,p,44)
    p = emit_total(w,o,p+1,0)
    store(o,p,44)
    store(o,p+1,91)
    p = p+2
    i = 0
    while i < en:
        store(o,p+i,byte(w,ENTRIES+i))
        i = i+1
    p = p+en
    store(o,p,93)
    store(o,p+1,44)
    store(o,p+2,34)
    p = decimal(o,p+3,read_word(s,d+56))
    store(o,p,34)
    store(o,p+1,44)
    store(o,p+2,91)
    p = p+3
    i = 1
    while i < 4:
        if i > 1:
            store(o,p,44)
            p = p+1
        p = policy_value(s,o,w,p,i)
        i = i+1
    store(o,p,93)
    store(o,p+1,44)
    p = policy_value(s,o,w,p+2,0)
    store(o,p,44)
    store(o,p+1,34)
    p = copy_wire(s,o,d+72,p+2,read_word(s,d+64))
    store(o,p,34)
    store(o,p+1,44)
    p = emit_total(w,o,p+2,2)
    i = 0
    while i < 9:
        store(o,p,44)
        store(o,p+1,48)
        p = p+2
        i = i+1
    store(o,p,93)
    p = p+1
    i = 0
    while i < p:
        store(w,i,byte(o,i))
        i = i+1
    put(w,MEM+200,p)
    return cost_receipt(w,o,1)
'''

def program():
    tags = dict(QUERY=b'HIAELQ01', RENDER=b'HIAELR01', FRESH=b'HIAEFI04', DECISION=b'HIAESD01',
                COMMAND=b'HIATCM01', PARAMS=b'HIAQPA01', ACK=b'HIATXR01', FRAME=b'HIAQRF01',
                ROWMAG=b'HIAROW01', INDEX=b'HIAIXLF1', ROW_ID=b'HIARID01', CTX=b'ctx-', BATCH=b'HIAEBT01')
    constants = {k:int.from_bytes(v,'little') for k,v in tags.items()}
    constants.update(BAD=4294967293, MEM=STATE+65536,FIELD_AT=STATE+2048,
                     ROW=8<<20, ROW_LIMIT=8<<20,ENTRIES=16<<20,SUMS=24<<20)
    constants.update({'K_'+k:i for i,k in enumerate(KEYS,1)})
    def expand(source):
        return re.sub(r'\b('+'|'.join(constants)+r')\b',lambda m:str(constants[m[0]]),source)
    from tools.generate_hia_worker_request import decimal_program
    case = case_source()
    original = identity()
    helpers = [function(POLICY+'\n'+MATCH+'\n'+ISSUE,k) for k in
               ('same','hexadecimal','digits','checked_ref','copy_wire','local_copy','decimal','hexchar','digest_matches')]
    token = b'"hia_evaluate"'
    helpers += ['def is_evaluate(s:readbuf,a:u64) -> bool:\n    return ' +
                ' and '.join(f'byte(s,a+{i}) == {v}' for i,v in enumerate(token))]
    fixed = hia_literals()
    helpers += [function(fixed,k) for k in ('ref_prefix','ref_hash_prefix','ref_uri_prefix')]
    helpers += [function(decimal_program(),'next_power')] if 'def next_power(' in decimal_program() else []
    if not any('def next_power(' in s for s in helpers):
        from tools.generate_hia_evaluate_settlement import program as settlement
        helpers += [function(settlement(),'next_power')]
    helpers += [function(case,k) for k in ('read_word','put','get','widen')]
    decode = json_slice(KEYS)
    template = ('cost_receipt','cost_receipt_pass','cost_rows','cost_row','receipt_literal',
                'receipt_fragment','receipt_delimited_fragment','receipt_fragment_size')
    emit = '\n'.join(function(original,k) for k in template)
    emit = emit.replace('s: readbuf','s: mutbuf').replace('s:readbuf','s:mutbuf')
    emit = emit.replace('length(s)', 'get(s,MEM+200)').replace('read_word(s,','get(s,')
    return '\n'.join((expand(BODY+'\n'+ROWS),*helpers,decode,snapshot_hash(),expand(emit)))

def packer_document():
    from tools.generate_hia_native_filter import document as packer, template
    frame = template(wire_bytes=512<<20, output_bytes=8<<20, workspace_bytes=48<<20,
                     canonical_render_tag=int.from_bytes(b'HIAELR01', 'little'))
    return packer(magic=PACK_MAGIC, module=PACKER.stem, image_template=frame, separate_sections=True)

if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(),SOURCE.stem)))
    PACKER.write_text(render_assembly(packer_document()))
