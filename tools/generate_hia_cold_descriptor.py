"""Native cold descriptor and CLI binding construction from captured relative sources.

The fixed recipe owns topology and policy. Captured manifests own actual sizes and
hashes. Fresh native plan inventories own syntax, imports, and publication facts.
No target image or successful cold observation is synthesized here.
"""
from pathlib import Path
from hashlib import sha256
import ast,copy,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_allocator_witness import document
from tools.generate_hia_sha256 import source_program as sha_source
from tools.generate_hia_native_filter import source_program as filter_source

ROOT=Path(__file__).resolve().parents[1]
U64=(1<<64)-1
COMMON=r'''
def uint(s:readbuf,at:u64,n:u64) -> u64:
    value = 0
    i = 0
    while i < n:
        value = value | (byte(s,at+i) << (i*8))
        i = i+1
    return value

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i = 0
    while i < 8:
        store(w,at+i,(value >> (i*8)) & 255)
        i = i+1
    return 0

def copy_input(s:readbuf,o:mutbuf,target:u64,source:u64,n:u64) -> u64:
    i = 0
    while i < n:
        store(o,target+i,byte(s,source+i))
        i = i+1
    return 0

def same(s:readbuf,a:u64,b:u64,n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s,a+i) != byte(s,b+i):
            return 0
        i = i+1
    return 1

def same_output(s:readbuf,o:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s,a+i) != byte(o,b+i):
            return 0
        i = i+1
    return 1

def zero(s:readbuf,at:u64,n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s,at+i) != 0:
            return 0
        i = i+1
    return 1

def nonzero(s:readbuf,at:u64) -> u64:
    return choose(uint(s,at,8) | uint(s,at+8,8) | uint(s,at+16,8) | uint(s,at+24,8) != 0,1,0)

def flat_name(s:readbuf,at:u64,n:u64,cap:u64) -> u64:
    if n == 0 or n >= cap or byte(s,at) == 46:
        return 0
    i = 0
    while i < cap:
        c = byte(s,at+i)
        if i < n:
            if (c < 48 or c > 57) and (c < 65 or c > 90) and (c < 97 or c > 122) and c != 45 and c != 46 and c != 95:
                return 0
        elif c != 0:
            return 0
        i = i+1
    return 1

def raw_name(s:readbuf,at:u64,n:u64) -> u64:
    if n == 0 or n > 127 or byte(s,at) == 46:
        return 0
    i = 0
    while i < n:
        c = byte(s,at+i)
        if (c < 48 or c > 57) and (c < 65 or c > 90) and (c < 97 or c > 122) and c != 45 and c != 46 and c != 95:
            return 0
        i = i+1
    return 1

def forbidden(s:readbuf,at:u64,n:u64) -> u64:
    if n == 0 or (n == 1 and byte(s,at) == 46) or (n == 2 and uint(s,at,2) == 11822):
        return 1
    if n == 4 and uint(s,at,4) == 1953064750:
        return 1
    if n == 11 and uint(s,at,8) == 7521962882505924447 and uint(s,at+8,3) == 6250341:
        return 1
    return 0

def relative(s:readbuf,at:u64,n:u64,cap:u64) -> u64:
    if n == 0 or n > 4095 or n >= cap:
        return 0
    start = 0
    i = 0
    while i < cap:
        c = byte(s,at+i)
        if i < n:
            if c == 47:
                if forbidden(s,at+start,i-start) != 0:
                    return 0
                start = i+1
            elif (c < 48 or c > 57) and (c < 65 or c > 90) and (c < 97 or c > 122) and c != 45 and c != 46 and c != 95:
                return 0
        elif c != 0:
            return 0
        i = i+1
    return choose(forbidden(s,at+start,n-start) == 0,1,0)

def raw_relative(s:readbuf,at:u64,n:u64) -> u64:
    if n == 0 or n > 4095:
        return 0
    start = 0
    i = 0
    while i < n:
        c = byte(s,at+i)
        if c == 47:
            if forbidden(s,at+start,i-start) != 0:
                return 0
            start = i+1
        elif (c < 48 or c > 57) and (c < 65 or c > 90) and (c < 97 or c > 122) and c != 45 and c != 46 and c != 95:
            return 0
        i = i+1
    return choose(forbidden(s,at+start,n-start) == 0,1,0)

def order(s:readbuf,a:u64,an:u64,b:u64,bn:u64) -> u64:
    i = 0
    while i < an and i < bn:
        x = byte(s,a+i)
        y = byte(s,b+i)
        if x != y:
            return choose(x < y,1,0)
        i = i+1
    return choose(an < bn,1,0)

def manifest(s:readbuf,at:u64,n:u64) -> u64:
    if n < 32 or n > 1048576 or at > length(s) or n > length(s)-at:
        return 0
    count = uint(s,at+8,8)
    if uint(s,at,8) != @MANIFEST@ or count == 0 or count > 16384 or uint(s,at+16,8) != 1 or uint(s,at+24,8) != 0:
        return 0
    end = at+n
    cursor = at+32
    previous = 0
    previous_n = 0
    i = 0
    while i < count:
        if cursor > end or end-cursor < 49:
            return 0
        size = uint(s,cursor,8)
        if size == 0 or size > end-cursor-48 or uint(s,cursor+8,8) > 67108864 or nonzero(s,cursor+16) == 0 or raw_relative(s,cursor+48,size) == 0:
            return 0
        if i != 0 and order(s,previous,previous_n,cursor+48,size) == 0:
            return 0
        previous = cursor+48
        previous_n = size
        cursor = cursor+48+size
        i = i+1
    return choose(cursor == end,count,0)

def member(s:readbuf,at:u64,path:u64,n:u64) -> u64:
    count = uint(s,at+8,8)
    i = 0
    cursor = at+32
    while i < count:
        size = uint(s,cursor,8)
        if size == n and same(s,path,cursor+48,n) != 0:
            return cursor
        cursor = cursor+48+size
        i = i+1
    return 0

def list_has(s:readbuf,at:u64,count:u64,name:u64,n:u64) -> u64:
    i = 0
    while i < count:
        size = uint(s,at,8)
        if size == n and same(s,at+8,name,n) != 0:
            return 1
        at = at+8+size
        i = i+1
    return 0

def q_widen(n:u32) -> u64:
    return n
'''

PLAN=r'''
def inventory(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 32 or length(s) > 67108864 or length(o) != 8388608 or length(w) < 2097152:
        return 4294967293
    nodes = uint(s,8,8)
    if uint(s,0,8) != @PLAN@ or nodes == 0 or nodes > 65536 or uint(s,16,8) != 0 or uint(s,24,8) != 0:
        return 4294967295
    cursor = 32
    i = 0
    imports = 0
    publications = 0
    needed = 80
    while i < nodes:
        if cursor > length(s) or length(s)-cursor < 32:
            return 4294967295
        op = uint(s,cursor,8)
        identifier = uint(s,cursor+8,8)
        argc = uint(s,cursor+16,8)
        n = uint(s,cursor+24,8)
        if op == 0 or op > 17 or identifier > 4096 or argc > 128 or n > 1048576 or argc*8 > length(s)-cursor-32:
            return 4294967295
        data = cursor+32+argc*8
        if n > length(s)-data:
            return 4294967295
        if op == 1 or op == 12:
            if raw_name(s,data,n) == 0:
                return 4294967295
            count = choose(op == 1,imports,publications)
            base = choose(op == 1,16384,32768)
            found = 0
            j = 0
            while j < count:
                old = get(w,base+j*16)
                oldn = get(w,base+j*16+8)
                if oldn == n and same(s,old,data,n) != 0:
                    found = 1
                j = j+1
            if op == 12 and found != 0:
                return 4294967295
            if found == 0:
                if (op == 1 and count >= 64) or (op == 12 and count >= 4096):
                    return 4294967295
                put(w,base+count*16,data)
                put(w,base+count*16+8,n)
                needed = needed+8+n
                if op == 1:
                    imports = imports+1
                else:
                    publications = publications+1
        cursor = data+n
        i = i+1
    if cursor != length(s) or needed > 8388608:
        return 4294967295
    fill_range(o,0,80,0)
    put(o,0,@PLAN_INVENTORY@)
    put(o,8,length(s))
    put(o,16,nodes)
    put(o,24,imports)
    put(o,32,publications)
    put(o,40,needed)
    if q_widen(q_sha256(s,o,w,0,length(s),48)) != 32:
        return 4294967295
    out = 80
    i = 0
    while i < imports+publications:
        base = choose(i < imports,16384,32768)
        index = choose(i < imports,i,i-imports)
        at = get(w,base+index*16)
        n = get(w,base+index*16+8)
        put(o,out,n)
        copy_input(s,o,out+8,at,n)
        out = out+8+n
        i = i+1
    return choose(out == needed,out,4294967295)
'''

TABLES=r'''
def droot(s:readbuf,base:u64,i:u64) -> u64:
    return base+256+i*384

def dphase(s:readbuf,base:u64,i:u64) -> u64:
    return base+256+uint(s,base+16,8)*384+i*384

def dbinding(s:readbuf,base:u64,i:u64) -> u64:
    return base+256+(uint(s,base+16,8)+uint(s,base+24,8))*384+i*288

def infrastructure(s:readbuf,at:u64,n:u64) -> u64:
    if n == 4 and uint(s,at,4) == @FAST@:
        return 1
    if n == 4 and uint(s,at,4) == @COLD@:
        return 2
    return 0

def tables(s:readbuf,w:mutbuf,base:u64,n:u64,filled:u64) -> u64:
    if n < 256 or n > 2097152 or base > length(s) or n > length(s)-base:
        return 0
    if uint(s,base,8) != choose(filled == 0,@RECIPE@,@DESCRIPTOR@) or uint(s,base+8,8) != 1:
        return 0
    roots = uint(s,base+16,8)
    phases = uint(s,base+24,8)
    bindings = uint(s,base+32,8)
    if roots < 4 or roots > 512 or phases < 40 or phases > 64 or bindings == 0 or bindings > 2048:
        return 0
    end = 256+(roots+phases)*384+bindings*288
    if end > n or uint(s,base+96,8) != end or uint(s,base+104,8) != n or uint(s,base+112,8) != 0 or uint(s,base+120,8) != 0:
        return 0
    if filled == 0:
        if n != end or uint(s,base+40,8) != 0 or uint(s,base+48,8) != 0 or zero(s,base+128,32) == 0:
            return 0
    else:
        count = uint(s,base+48,8)
        if count == 0 or count > 16384 or uint(s,base+40,8) != n-end or manifest(s,base+end,n-end) != count or nonzero(s,base+128) == 0:
            return 0
    plen = uint(s,base+56,8)
    if plen == 0 or plen > 95:
        return 0
    i = 0
    while i < 96:
        c = byte(s,base+160+i)
        if i < plen:
            if c < 32 or c > 126:
                return 0
        elif c != 0:
            return 0
        i = i+1
    i = 64
    while i < 96:
        if uint(s,base+i,8) >= roots:
            return 0
        j = 64
        while j < i:
            if uint(s,base+i,8) == uint(s,base+j,8):
                return 0
            j = j+8
        if uint(s,droot(s,base,uint(s,base+i,8))+24,8) != 0:
            return 0
        i = i+8
    if root_tables(s,w,base,n,filled) == 0 or phase_tables(s,w,base,n,filled) == 0:
        return 0
    return 1

def root_tables(s:readbuf,w:mutbuf,base:u64,n:u64,filled:u64) -> u64:
    roots = uint(s,base+16,8)
    i = 0
    while i < roots:
        row = droot(s,base,i)
        if uint(s,row+24,8) > 1 or flat_name(s,row+64,uint(s,row+8,8),128) == 0 or relative(s,row+192,uint(s,row+16,8),192) == 0:
            return 0
        if filled == 0:
            if uint(s,row,8) != 0 or zero(s,row+32,32) == 0:
                return 0
        else:
            if uint(s,row,8) > 67108864 or nonzero(s,row+32) == 0:
                return 0
            if uint(s,row+24,8) == 1:
                item = member(s,base+uint(s,base+96,8),row+192,uint(s,row+16,8))
                if item == 0 or uint(s,item+8,8) != uint(s,row,8) or same(s,item+16,row+32,32) == 0:
                    return 0
        j = 0
        while j < i:
            old = droot(s,base,j)
            if same(s,row+64,old+64,128) != 0:
                return 0
            j = j+1
        i = i+1
    return 1

def phase_tables(s:readbuf,w:mutbuf,base:u64,n:u64,filled:u64) -> u64:
    phases = uint(s,base+24,8)
    bindings = uint(s,base+32,8)
    base_index = 18446744073709551615
    cursor = 0
    qualified = 0
    i = 0
    while i < phases:
        row = dphase(s,base,i)
        kind = uint(s,row+64,8)
        family = uint(s,row+72,8)
        label = uint(s,row+80,8)
        count = uint(s,row+152,8)
        deps = uint(s,row+160,8)
        if flat_name(s,row,uint(s,row+168,8),64) == 0 or uint(s,row+88,8) != 0 or relative(s,row+256,uint(s,row+176,8),128) == 0:
            return 0
        if uint(s,row+104,8) == 0 or uint(s,row+104,8) > 65536 or uint(s,row+144,8) != cursor or count < 2 or count > 64 or count > bindings-cursor or deps >> i != 0 or zero(s,row+184,72) == 0:
            return 0
        if filled == 0:
            if uint(s,row+96,8) != 0 or zero(s,row+112,32) == 0:
                return 0
        else:
            item = member(s,base+uint(s,base+96,8),row+256,uint(s,row+176,8))
            if item == 0 or uint(s,item+8,8) < 32 or uint(s,item+8,8) != uint(s,row+96,8) or same(s,item+16,row+112,32) == 0:
                return 0
        j = 0
        while j < i:
            if same(s,row,dphase(s,base,j),64) != 0:
                return 0
            j = j+1
        if kind == 1:
            if base_index != 18446744073709551615 or family != 18446744073709551615 or label != 0:
                return 0
        elif kind == 2:
            if i == 0 or base_index != 18446744073709551615 or family != 18446744073709551615 or label != 0 or deps != (1 << i)-1:
                return 0
            base_index = i
        elif kind == 3:
            if base_index == 18446744073709551615 or family >= 19 or label == 0 or label > 2 or deps & (1 << base_index) == 0:
                return 0
            bit = 1 << (family*2+label-1)
            if qualified & bit != 0:
                return 0
            qualified = qualified | bit
        else:
            return 0
        if bindings_valid(s,base,row,i,base_index) == 0:
            return 0
        cursor = cursor+count
        i = i+1
    if base_index == 18446744073709551615 or qualified != 274877906943 or cursor != bindings:
        return 0
    put(w,4000,base_index)
    return 1

def bindings_valid(s:readbuf,base:u64,row:u64,index:u64,base_index:u64) -> u64:
    start = uint(s,row+144,8)
    count = uint(s,row+152,8)
    kind = uint(s,row+64,8)
    label = uint(s,row+80,8)
    fast = 0
    cold = 0
    compiler = 0
    j = 0
    while j < count:
        b = dbinding(s,base,start+j)
        typ = uint(s,b,8)
        source = uint(s,b+8,8)
        n = uint(s,b+24,8)
        if flat_name(s,b+160,n,128) == 0:
            return 0
        k = 0
        while k < j:
            if same(s,b+160,dbinding(s,base,start+k)+160,128) != 0:
                return 0
            k = k+1
        infra = infrastructure(s,b+160,n)
        if infra != 0:
            if typ != 0 or source != uint(s,base+choose(infra == 1,80,88),8):
                return 0
            if infra == 1:
                fast = fast+1
            else:
                cold = cold+1
        if typ == 0:
            if source >= uint(s,base+16,8) or uint(s,b+16,8) != 0 or zero(s,b+32,128) == 0:
                return 0
        elif typ == 1:
            if kind == 1 or source >= index or uint(s,row+160,8) & (1 << source) == 0 or flat_name(s,b+32,uint(s,b+16,8),128) == 0:
                return 0
        else:
            return 0
        if kind == 3 and n == 8 and uint(s,b+160,8) == @COMPILER@:
            if typ != 1 or source != base_index or uint(s,b+16,8) != 7 or uint(s,b+32,8) != choose(label == 1,@B3@,@M3@):
                return 0
            compiler = compiler+1
        j = j+1
    return choose(fast == 1 and cold == 1 and (kind != 3 or compiler == 1),1,0)

def receipt(s:readbuf,w:mutbuf,at:u64,n:u64) -> u64:
    if n < 80 or at > length(s) or n > length(s)-at or uint(s,at,8) != @PLAN_INVENTORY@ or uint(s,at+40,8) != n:
        return 0
    if uint(s,at+8,8) < 32 or uint(s,at+8,8) > 67108864 or uint(s,at+16,8) == 0 or uint(s,at+16,8) > 65536 or uint(s,at+24,8) > 64 or uint(s,at+32,8) > 4096 or nonzero(s,at+48) == 0:
        return 0
    imports = uint(s,at+24,8)
    pubs = uint(s,at+32,8)
    cursor = at+80
    put(w,2000,cursor)
    i = 0
    while i < imports+pubs:
        if i == imports:
            put(w,2000,cursor)
        if cursor > at+n or at+n-cursor < 9:
            return 0
        size = uint(s,cursor,8)
        if size > at+n-cursor-8 or raw_name(s,cursor+8,size) == 0:
            return 0
        j = choose(i < imports,0,imports)
        while j < i:
            old = get(w,65536+j*16)
            if get(w,65536+j*16+8) == size and same(s,old,cursor+8,size) != 0:
                return 0
            j = j+1
        put(w,65536+i*16,cursor+8)
        put(w,65536+i*16+8,size)
        cursor = cursor+8+size
        i = i+1
    if pubs == 0:
        put(w,2000,cursor)
    return choose(cursor == at+n,1,0)

def receipt_bundle(s:readbuf,w:mutbuf,at:u64,n:u64,phases:u64) -> u64:
    if n < 16 or at > length(s) or n > length(s)-at or uint(s,at,8) != @PLAN_BUNDLE@ or uint(s,at+8,8) != phases:
        return 0
    cursor = at+16
    i = 0
    while i < phases:
        if cursor > at+n or at+n-cursor < 8:
            return 0
        size = uint(s,cursor,8)
        if size > at+n-cursor-8 or receipt(s,w,cursor+8,size) == 0:
            return 0
        put(w,16384+i*32,cursor+8)
        put(w,16384+i*32+8,cursor+88)
        put(w,16384+i*32+16,get(w,2000))
        cursor = cursor+8+size
        i = i+1
    return choose(cursor == at+n,1,0)

def plan_bindings(s:readbuf,w:mutbuf,base:u64,phase:u64) -> u64:
    row = dphase(s,base,phase)
    inv = get(w,16384+phase*32)
    imports_at = get(w,16384+phase*32+8)
    imports = uint(s,inv+24,8)
    count = uint(s,row+152,8)
    start = uint(s,row+144,8)
    cursor = imports_at
    i = 0
    while i < imports:
        n = uint(s,cursor,8)
        found = 0
        j = 0
        while j < count:
            b = dbinding(s,base,start+j)
            if uint(s,b+24,8) == n and same(s,b+160,cursor+8,n) != 0:
                found = 1
            j = j+1
        if found == 0:
            return 0
        cursor = cursor+8+n
        i = i+1
    j = 0
    while j < count:
        b = dbinding(s,base,start+j)
        n = uint(s,b+24,8)
        if infrastructure(s,b+160,n) == 0 and list_has(s,imports_at,imports,b+160,n) == 0:
            return 0
        if uint(s,b,8) == 1:
            source = uint(s,b+8,8)
            other = get(w,16384+source*32)
            if list_has(s,get(w,16384+source*32+16),uint(s,other+32,8),b+32,uint(s,b+16,8)) == 0:
                return 0
        j = j+1
    return 1
'''

COMPOSE=r'''
def compose(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 64 or length(s) > 67108864 or length(o) != 8388608 or length(w) < 2097152:
        return 4294967293
    if uint(s,0,8) != @COMPOSE@ or zero(s,40,24) == 0:
        return 4294967295
    recipe_n = uint(s,8,8)
    source_n = uint(s,16,8)
    tool_n = uint(s,24,8)
    bundle_n = uint(s,32,8)
    if recipe_n > length(s)-64:
        return 4294967295
    source = 64+recipe_n
    if source_n > length(s)-source:
        return 4294967295
    tools = source+source_n
    if tool_n > length(s)-tools:
        return 4294967295
    bundle = tools+tool_n
    if bundle_n != length(s)-bundle or tables(s,w,64,recipe_n,0) == 0:
        return 4294967295
    source_count = manifest(s,source,source_n)
    if source_count == 0 or manifest(s,tools,tool_n) == 0 or recipe_n+source_n > 2097152:
        return 4294967295
    phases = uint(s,64+24,8)
    if receipt_bundle(s,w,bundle,bundle_n,phases) == 0:
        return 4294967295
    copy_input(s,o,0,64,recipe_n)
    copy_input(s,o,recipe_n,source,source_n)
    put(o,0,@DESCRIPTOR@)
    put(o,40,source_n)
    put(o,48,source_count)
    put(o,104,recipe_n+source_n)
    roots = uint(s,64+16,8)
    i = 0
    while i < roots:
        row = droot(s,64,i)
        origin = choose(uint(s,row+24,8) == 0,tools,source)
        item = member(s,origin,row+192,uint(s,row+16,8))
        if item == 0:
            return 4294967295
        put(o,row-64,uint(s,item+8,8))
        copy_input(s,o,row-64+32,item+16,32)
        i = i+1
    i = 0
    while i < phases:
        row = dphase(s,64,i)
        item = member(s,source,row+256,uint(s,row+176,8))
        inv = get(w,16384+i*32)
        if item == 0 or uint(s,item+8,8) != uint(s,inv+8,8) or uint(s,inv+16,8) != uint(s,row+104,8) or same(s,item+16,inv+48,32) == 0 or plan_bindings(s,w,64,i) == 0:
            return 4294967295
        put(o,row-64+96,uint(s,item+8,8))
        copy_input(s,o,row-64+112,item+16,32)
        i = i+1
    if q_widen(q_sha256(s,o,w,source,source_n,128)) != 32:
        return 4294967295
    return recipe_n+source_n
'''

BIND=r'''
def bind(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 64 or length(s) > 8388608 or length(o) != 8388608 or length(w) < 2097152:
        return 4294967293
    if uint(s,0,8) != @BIND@ or uint(s,56,8) != 0:
        return 4294967295
    descriptor_n = uint(s,8,8)
    master_n = uint(s,16,8)
    owner_n = uint(s,24,8)
    exporter_n = uint(s,32,8)
    policy_n = uint(s,40,8)
    sha_n = uint(s,48,8)
    if descriptor_n > 2097152 or master_n > 1048576 or owner_n > 1048576 or exporter_n > 1048576 or policy_n == 0 or policy_n > 1048576 or sha_n == 0 or sha_n > 1048576 or policy_n+sha_n+@CLI_PREFIX@ > 1048576:
        return 4294967295
    if 64+descriptor_n+master_n+owner_n+exporter_n+policy_n+sha_n != length(s) or tables(s,w,64,descriptor_n,1) == 0:
        return 4294967295
    master = 64+descriptor_n
    owner = master+master_n
    exporter = owner+owner_n
    if elf(s,master,master_n) == 0 or elf(s,owner,owner_n) == 0 or elf(s,exporter,exporter_n) == 0:
        return 4294967295
    manifest_at = 64+uint(s,64+96,8)
    manifest_n = uint(s,64+40,8)
    if q_widen(q_sha256(s,o,w,manifest_at,manifest_n,7340032)) != 32 or same_output(s,o,64+128,7340032,32) == 0:
        return 4294967295
    put(o,0,@CLI_PACKET@)
    put(o,8,policy_n)
    put(o,16,sha_n)
    if q_widen(q_sha256(s,o,w,64,descriptor_n,24)) != 32 or q_widen(q_sha256(s,o,w,master,master_n,56)) != 32 or q_widen(q_sha256(s,o,w,owner,owner_n,88)) != 32 or q_widen(q_sha256(s,o,w,exporter,exporter_n,120)) != 32:
        return 4294967295
    cold = droot(s,64,uint(s,64+88,8))
    if same_output(s,o,cold+32,88,32) == 0:
        return 4294967295
    copy_input(s,o,152,exporter+exporter_n,policy_n+sha_n)
    return 152+policy_n+sha_n

def elf(s:readbuf,at:u64,n:u64) -> u64:
    if n < 64 or uint(s,at,4) != 1179403647 or byte(s,at+4) != 2 or byte(s,at+5) != 1 or uint(s,at+16,2) != 2 or uint(s,at+18,2) != 62:
        return 0
    return 1
'''

def hash_span():
    source=sha_source()
    source=source.replace('def sha256(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
        'def sha256(s:readbuf, o:mutbuf, w:mutbuf, start:u64, size:u64, out:u64) -> u32:')
    source=source.replace('    if length(s) > 8388608 or length(o) < 32 or length(w) < 1088:',
        '    if start > length(s) or size > length(s)-start or size > 67108864 or out > length(o) or length(o)-out < 32 or length(w) < 1088:')
    source=source.replace('(length(s) + 72)','(size + 72)')
    source=source.replace('padded_byte(s, block + i * 4 + j, padded)','padded_byte(s, start, size, block + i * 4 + j, padded)')
    source=source.replace('store(o, i * 4 + j,','store(o, out + i * 4 + j,')
    source=source.replace('def padded_byte(s:readbuf, index:u64, total:u64) -> u64:',
        'def padded_byte(s:readbuf, start:u64, size:u64, index:u64, total:u64) -> u64:')
    a=source.index('def padded_byte(');b=source.index('def rotate(')
    tail=source[a:b].replace('length(s)','size').replace('byte(s, index)','byte(s, start + index)')
    source=source[:a]+tail+source[b:]
    tree=ast.parse(source)
    names={n.name:'q_'+n.name for n in tree.body if isinstance(n,ast.FunctionDef)}
    class Rename(ast.NodeTransformer):
        def visit_FunctionDef(self,node):
            node.name=names[node.name];return self.generic_visit(node)
        def visit_Name(self,node):
            if node.id in names:node.id=names[node.id]
            return node
    tree=Rename().visit(tree)
    source=ast.unparse(ast.fix_missing_locations(tree))
    nodes=ast.parse(source).body
    old=next(n for n in nodes if n.name=='q_get')
    source=source.replace(ast.get_source_segment(source,old),'def q_get(w:mutbuf,index:u64) -> u64:\n    return word_load(w,index)')
    return source

MAGICS={'PLAN':b'HIAQPL01','PLAN_INVENTORY':b'HIAQPS01','MANIFEST':b'HIASXM01','RECIPE':b'HIAQBT01','COMPOSE':b'HIAQCA01','PLAN_BUNDLE':b'HIAQPB01','DESCRIPTOR':b'HIAQBD01','BIND':b'HIAQBC01','CLI_PACKET':b'HIAQCP01','FAST':b'fast','COLD':b'cold','COMPILER':b'compiler','B3':b'B3.flat\0','M3':b'M3.flat\0'}
def resolve(source):
    for name,raw in MAGICS.items():source=source.replace('@'+name+'@',str(int.from_bytes(raw,'little')))
    from tools.generate_hia_cold_cli import template
    return source.replace('@CLI_PREFIX@',str(len(template()[0])))

def emit(name,body):
    text=resolve(body+'\n'+COMMON+'\n'+hash_span())
    doc=document(text);raw=render_assembly(doc).encode()
    p=ROOT/'examples/hia_bootstrap'/(name+'.hepta');p.write_bytes(raw)
    print(name,len(raw),len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),sha256(raw).hexdigest(),flush=True)

if __name__=='__main__':
    emit('cold_plan_inventory',PLAN)
    emit('cold_descriptor_compose',COMPOSE+'\n'+TABLES)
    emit('cold_cli_bind',BIND+'\n'+TABLES)
    text=filter_source(wire_bytes=67108864,output_bytes=8388608,workspace_bytes=16777216,magic=int.from_bytes(b'HIAQPF01','little'))
    doc=document(text);raw=render_assembly(doc).encode();(ROOT/'examples/hia_bootstrap/cold_descriptor_filter_packer.hepta').write_bytes(raw)
    print('cold_descriptor_filter_packer',len(raw),sha256(raw).hexdigest(),flush=True)
