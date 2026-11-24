"""Native bounded cold replay scheduler. No runtime Python or target compiler."""
from pathlib import Path
from hashlib import sha256
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_allocator_witness import document
from tools.generate_hia_cold_master_common import helpers,packer
ROOT=Path(__file__).resolve().parents[1]
FAMILIES=('capacity','cfg','elf','chain','owned','bulk','loan','resource','tail','select','effects','multi','keyword','signed','scalar-casts','explicit-traps','cli','names','exports')
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 4194304:
        return 0
    p = get(w,0)
    r = get(w,8)
    if p >= 200 and p < 250:
        return transfer(s,o,w,p,r)
    if p >= 250 and p < 300:
        return hashing(s,o,w,p,r)
    if p < 200:
        return admission(s,o,w,p,r)
    if p < 400:
        return schedule(s,o,w,p,r)
    if p < 500:
        return prepare_phase(s,o,w,p,r)
    if p < 600:
        return collect_phase(s,o,w,p,r)
    if p < 700:
        return prepare_archive(s,o,w,p,r)
    if p < 800:
        return collect_archive(s,o,w,p,r)
    if p < 900:
        return extract(s,o,w,p,r)
    if p < 1000:
        return complete(s,o,w,p,r)
    return child(s,o,w,p,r)

def rootrow(s:readbuf,i:u64) -> u64:
    return 128+i*192

def phaserow(s:readbuf,i:u64) -> u64:
    return 128+uint(s,32,8)*192+i*256

def bindingrow(s:readbuf,i:u64) -> u64:
    return 128+uint(s,32,8)*192+uint(s,40,8)*256+i*288

def state(i:u64) -> u64:
    return 200000+i*384

def cache(i:u64) -> u64:
    return 300000+i*48

def active(w:mutbuf) -> u64:
    return state(get(w,2024))

def text_ok(s:readbuf,at:u64,n:u64,cap:u64) -> u64:
    if n == 0 or n >= cap or byte(s,at) == 46:
        return 0
    i = 0
    while i < cap:
        c = byte(s,at+i)
        if i < n:
            if c != 45 and c != 46 and c != 95 and (c < 48 or c > 57) and (c < 65 or c > 90) and (c < 97 or c > 122):
                return 0
        elif c != 0:
            return 0
        i = i+1
    return 1

def same_source(s:readbuf,a:u64,b:u64,n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s,a+i) != byte(s,b+i):
            return 0
        i = i+1
    return 1

def copy_input(s:readbuf,w:mutbuf,target:u64,source:u64,n:u64) -> u64:
    i = 0
    while i < n:
        store(w,target+i,byte(s,source+i))
        i = i+1
    return 0

def nonzero(s:readbuf,at:u64) -> u64:
    return choose(uint(s,at,8) | uint(s,at+8,8) | uint(s,at+16,8) | uint(s,at+24,8) != 0,1,0)

def validate(s:readbuf,w:mutbuf) -> u64:
    roots = uint(s,32,8)
    phases = uint(s,40,8)
    bindings = uint(s,48,8)
    if roots < 4 or roots > 512 or phases < 40 or phases > 64 or bindings == 0 or bindings > 2048:
        return 0
    if length(s) != 128+roots*192+phases*256+bindings*288 or uint(s,96,8) != 1 or uint(s,104,8) != 0 or uint(s,112,8) != 0 or uint(s,120,8) != 0:
        return 0
    if uint(s,16,8) <= uint(s,88,8) or uint(s,16,8)-uint(s,88,8) != 180000000000:
        return 0
    i = 7
    while i < 11:
        if uint(s,i*8,8) >= roots:
            return 0
        j = 7
        while j < i:
            if uint(s,i*8,8) == uint(s,j*8,8):
                return 0
            j = j+1
        i = i+1
    i = 0
    while i < roots:
        at = rootrow(s,i)
        if uint(s,at,8) < 3 or uint(s,at,8) > 2147483647 or uint(s,at+8,8) > 67108864 or nonzero(s,at+32) == 0 or text_ok(s,at+64,uint(s,at+16,8),128) == 0:
            return 0
        j = 0
        while j < i:
            if same_source(s,at+64,rootrow(s,j)+64,128) != 0:
                return 0
            j = j+1
        i = i+1
    base = 18446744073709551615
    next_binding = 0
    qualified = 0
    i = 0
    while i < phases:
        at = phaserow(s,i)
        kind = uint(s,at+64,8)
        family = uint(s,at+72,8)
        label = uint(s,at+80,8)
        if text_ok(s,at,uint(s,at+168,8),64) == 0 or uint(s,at+88,8) < 3 or uint(s,at+88,8) > 2147483647 or uint(s,at+96,8) < 32 or uint(s,at+96,8) > 67108864 or uint(s,at+104,8) == 0 or uint(s,at+104,8) > 65536 or nonzero(s,at+112) == 0:
            return 0
        if uint(s,at+144,8) != next_binding or uint(s,at+152,8) < 2 or uint(s,at+152,8) > 64 or uint(s,at+152,8) > bindings-next_binding or uint(s,at+160,8) >> i != 0:
            return 0
        j = 184
        while j < 256:
            if uint(s,at+j,8) != 0:
                return 0
            j = j+8
        j = 0
        while j < i:
            old = phaserow(s,j)
            if same_source(s,at,old,64) != 0:
                return 0
            j = j+1
        if kind == 1:
            if base != 18446744073709551615 or family != 18446744073709551615 or label != 0:
                return 0
        elif kind == 2:
            if i == 0 or base != 18446744073709551615 or family != 18446744073709551615 or label != 0:
                return 0
            base = i
        elif kind == 3:
            if base == 18446744073709551615 or family >= 19 or label == 0 or label > 2:
                return 0
            bit = 1 << (family*2+label-1)
            if qualified & bit != 0:
                return 0
            qualified = qualified | bit
        else:
            return 0
        fast = 0
        cold = 0
        compiler = 0
        j = 0
        while j < uint(s,at+152,8):
            b = bindingrow(s,next_binding+j)
            typ = uint(s,b,8)
            source = uint(s,b+8,8)
            if text_ok(s,b+160,uint(s,b+24,8),128) == 0:
                return 0
            k = 0
            while k < j:
                old = bindingrow(s,next_binding+k)
                if same_source(s,b+160,old+160,128) != 0:
                    return 0
                k = k+1
            if typ == 0:
                if source >= roots or uint(s,b+16,8) != 0:
                    return 0
                k = 32
                while k < 160:
                    if uint(s,b+k,8) != 0:
                        return 0
                    k = k+8
                if source == uint(s,72,8):
                    fast = fast+1
                if source == uint(s,80,8):
                    cold = cold+1
            elif typ == 1:
                if source >= i or uint(s,at+160,8) & (1 << source) == 0 or text_ok(s,b+32,uint(s,b+16,8),128) == 0:
                    return 0
                if kind == 3 and source == base and uint(s,b+16,8) == 7:
                    if label == 1 and uint(s,b+32,8) == @B3@:
                        compiler = compiler+1
                    if label == 2 and uint(s,b+32,8) == @M3@:
                        compiler = compiler+1
            else:
                return 0
            j = j+1
        if fast != 1 or cold != 1 or (kind == 3 and compiler == 0):
            return 0
        next_binding = next_binding+uint(s,at+152,8)
        i = i+1
    if base == 18446744073709551615 or qualified != 274877906943 or next_binding != bindings:
        return 0
    put(w,2016,base)
    return 1

def admission(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p == 0:
        if length(s) < 128 or uint(s,0,8) != @REQUEST@ or uint(s,8,8) < 2 or uint(s,8,8) > 2147483647 or uint(s,24,8) < 3 or uint(s,24,8) > 2147483647 or validate(s,w) == 0:
            return finish(o,w,65)
        initialize(w)
        return call(o,w,1,110,0,0,0,0,0,0,0)
    if failed(r):
        return finish(o,w,74)
    if p == 1:
        if r != uint(s,8,8):
            return finish(o,w,65)
        return call(o,w,2,157,1,9,0,0,0,0,0)
    if p == 2:
        return call(o,w,6,110,0,0,0,0,0,0,0)
    if p == 6:
        if r != get(w,2280):
            return finish(o,w,65)
        return call(o,w,3,39,0,0,0,0,0,0,0)
    if p == 3:
        put(w,2008,r)
        return call(o,w,4,107,0,0,0,0,0,0,0)
    if p == 4:
        put(w,2000,r)
        return call(o,w,5,5,uint(s,24,8),1200,0,0,0,0,12)
    if p == 5:
        if getn(w,1224,4) & 61440 != 16384 or getn(w,1224,4) & 63 != 0 or getn(w,1228,4) != get(w,2000):
            return finish(o,w,65)
        put(w,2032,0)
        return resume(s,o,w,10)
    if p == 10:
        if get(w,2032) == uint(s,32,8):
            put(w,2032,0)
            return resume(s,o,w,20)
        at = rootrow(s,get(w,2032))
        return call(o,w,11,5,uint(s,at,8),1200,0,0,0,0,12)
    if p == 11:
        at = rootrow(s,get(w,2032))
        if getn(w,1224,4) & 61440 != 32768 or get(w,1248) > 2147483648 or uint(s,at+24,8) > get(w,1248) or uint(s,at+8,8) > get(w,1248)-uint(s,at+24,8):
            return finish(o,w,65)
        return call(o,w,12,72,uint(s,at,8),1034,0,0,0,0,0)
    if p == 12:
        if r & 15 != 15:
            return finish(o,w,65)
        return call(o,w,13,319,61000,3,0,0,0,0,3)
    if p == 13:
        if r < 3:
            return finish(o,w,74)
        put(w,400000+get(w,2032)*8,r)
        at = rootrow(s,get(w,2032))
        return copying(o,w,uint(s,at,8),r,uint(s,at+24,8),uint(s,at+8,8),14)
    if p == 14:
        at = rootrow(s,get(w,2032))
        return hash_view(o,w,get(w,400000+get(w,2032)*8),0,uint(s,at+8,8),15)
    if p == 15:
        if same_input(s,w,rootrow(s,get(w,2032))+32,4096,32) == 0:
            return finish(o,w,65)
        return call(o,w,16,91,get(w,400000+get(w,2032)*8),320,0,0,0,0,0)
    if p == 16:
        return call(o,w,17,72,get(w,400000+get(w,2032)*8),1033,15,0,0,0,0)
    if p == 17:
        put(w,2032,get(w,2032)+1)
        return resume(s,o,w,10)
    if p == 20:
        if get(w,2032) == uint(s,40,8):
            return resume(s,o,w,300)
        at = phaserow(s,get(w,2032))
        return call(o,w,21,5,uint(s,at+88,8),1200,0,0,0,0,12)
    if p == 21:
        at = phaserow(s,get(w,2032))
        if getn(w,1224,4) & 61440 != 32768 or get(w,1248) > 2147483648 or uint(s,at+176,8) > get(w,1248) or uint(s,at+96,8) > get(w,1248)-uint(s,at+176,8):
            return finish(o,w,65)
        return call(o,w,22,72,uint(s,at+88,8),1034,0,0,0,0,0)
    if p == 22:
        if r & 15 != 15:
            return finish(o,w,65)
        return call(o,w,23,319,61000,3,0,0,0,0,3)
    if p == 23:
        if r < 3:
            return finish(o,w,74)
        put(w,state(get(w,2032))+320,r)
        at = phaserow(s,get(w,2032))
        return copying(o,w,uint(s,at+88,8),r,uint(s,at+176,8),uint(s,at+96,8),25)
    if p == 25:
        at = phaserow(s,get(w,2032))
        return hash_view(o,w,get(w,state(get(w,2032))+320),0,uint(s,at+96,8),26)
    if p == 26:
        at = phaserow(s,get(w,2032))
        if same_input(s,w,at+112,4096,32) == 0:
            return finish(o,w,65)
        return call(o,w,27,72,get(w,state(get(w,2032))+320),1033,15,0,0,0,0)
    if p == 27:
        return reading(o,w,get(w,state(get(w,2032))+320),62000,32,0,24)
    if p == 24:
        at = phaserow(s,get(w,2032))
        if get(w,62000) != @PLAN@ or get(w,62008) != uint(s,at+104,8) or get(w,62016) != 0 or get(w,62024) != 0:
            return finish(o,w,65)
        put(w,2032,get(w,2032)+1)
        return resume(s,o,w,20)
    return finish(o,w,65)
'''
SOURCE+=r'''
def counts(s:readbuf,w:mutbuf) -> u64:
    running = 0
    pending = 0
    unsealed = 0
    archived = 0
    sealed = 0
    i = 0
    while i < uint(s,40,8):
        row = state(i)
        status = get(w,row)
        if status == 1 or status == 2:
            running = running+1
        if status == 3 or status == 5:
            pending = pending+1
        if (status >= 1 and status <= 3) or status == 5:
            unsealed = unsealed+1
        if status == 3 and get(w,row+88) != 0:
            archived = archived+1
        if status == 4:
            sealed = sealed+1
        i = i+1
    if running > 2 or pending > 2 or unsealed > 4 or archived > 1:
        return 0
    put(w,2040,running)
    put(w,2048,pending)
    put(w,2056,unsealed)
    put(w,2064,archived)
    put(w,2072,sealed)
    put(w,2080,choose(running > get(w,2080),running,get(w,2080)))
    put(w,2088,choose(pending > get(w,2088),pending,get(w,2088)))
    put(w,2096,choose(unsealed > get(w,2096),unsealed,get(w,2096)))
    put(w,2104,choose(archived > get(w,2104),archived,get(w,2104)))
    return 1

def ready(s:readbuf,w:mutbuf,i:u64) -> u64:
    if get(w,state(i)) != 0:
        return 0
    at = phaserow(s,i)
    kind = uint(s,at+64,8)
    if kind == 2:
        j = 0
        while j < get(w,2016):
            if get(w,state(j)) != 4:
                return 0
            j = j+1
    if kind == 3 and get(w,state(get(w,2016))) != 4:
        return 0
    j = 0
    mask = uint(s,at+160,8)
    while j < i:
        if mask & (1 << j) != 0 and get(w,state(j)) != 4:
            return 0
        j = j+1
    return 1

def schedule(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p == 300:
        return call(o,w,301,228,1,1400,0,0,0,0,12)
    if p == 301:
        if failed(r):
            return finish(o,w,74)
        now = get(w,1400)*1000000000+get(w,1408)
        if now >= uint(s,16,8) or now < uint(s,88,8):
            return finish(o,w,124)
        put(w,2120,now)
        return call(o,w,302,61,18446744073709551615,1440,1,0,0,0,12)
    if p == 302:
        if r == 18446744073709551612:
            return resume(s,o,w,300)
        if failed(r) and r != 18446744073709551606:
            return finish(o,w,74)
        if r != 0 and not failed(r):
            if getn(w,1440,4) != 0:
                return finish(o,w,1)
            i = 0
            while i < uint(s,40,8):
                row = state(i)
                if get(w,row) == 1 and get(w,row+8) == r:
                    put(w,2024,i)
                    put(w,row+104,get(w,2120))
                    return resume(s,o,w,500)
                if get(w,row) == 3 and get(w,row+88) == r:
                    put(w,2024,i)
                    put(w,row+112,get(w,2120))
                    put(w,row+88,0)
                    put(w,row,5)
                    return resume(s,o,w,700)
                i = i+1
            return finish(o,w,74)
        if counts(s,w) == 0:
            return finish(o,w,74)
        if get(w,2072) == uint(s,40,8):
            return resume(s,o,w,900)
        if get(w,2048) < 2:
            i = 0
            while i < uint(s,40,8):
                if get(w,state(i)) == 2:
                    put(w,state(i),3)
                    if counts(s,w) == 0:
                        return finish(o,w,74)
                    return resume(s,o,w,303)
                i = i+1
        return resume(s,o,w,303)
    if p == 303:
        if get(w,2064) == 0:
            i = 0
            while i < uint(s,40,8):
                if get(w,state(i)) == 3 and get(w,state(i)+88) == 0:
                    put(w,2024,i)
                    return resume(s,o,w,600)
                i = i+1
        if get(w,2040) < 2:
            i = 0
            while i < uint(s,40,8):
                if ready(s,w,i) != 0:
                    put(w,2024,i)
                    return resume(s,o,w,400)
                i = i+1
        if get(w,2040) == 0 and get(w,2048) == 0:
            return finish(o,w,65)
        put(w,1500,0)
        put(w,1508,1000000)
        return call(o,w,304,35,1500,0,0,0,0,0,3)
    if p == 304:
        if failed(r) and r != 18446744073709551612:
            return finish(o,w,74)
        return resume(s,o,w,300)
    return finish(o,w,65)

def phase_name(s:readbuf,w:mutbuf,archive:u64) -> u64:
    at = phaserow(s,get(w,2024))
    n = uint(s,at+168,8)
    fill_range(w,62000,128,0)
    copy_input(s,w,62000,at,n)
    if archive != 0:
        copyw(w,62000+n,61100,7)
    return 0

def rootfd(w:mutbuf,index:u64) -> u64:
    return get(w,400000+index*8)

def prepare_phase(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    row = active(w)
    at = phaserow(s,get(w,2024))
    if p == 400:
        phase_name(s,w,0)
        return call(o,w,401,258,uint(s,24,8),62000,448,0,0,0,12)
    if failed(r):
        return finish(o,w,74)
    if p == 401:
        return call(o,w,402,257,uint(s,24,8),62000,720896,0,0,0,12)
    if p == 402:
        if r < 3:
            return finish(o,w,74)
        put(w,row+16,r)
        return call(o,w,403,257,r,61120,655554,384,0,0,12)
    if p == 403:
        if r < 3:
            return finish(o,w,74)
        put(w,row+24,r)
        return call(o,w,404,319,61000,3,0,0,0,0,3)
    if p == 404:
        if r < 3:
            return finish(o,w,74)
        put(w,row+32,r)
        return call(o,w,405,319,61000,3,0,0,0,0,3)
    if p == 405:
        if r < 3:
            return finish(o,w,74)
        put(w,row+40,r)
        fill_range(w,500000,12416,0)
        put(w,500000,@DRIVER_REQUEST@)
        put(w,500008,get(w,2008))
        put(w,500016,uint(s,16,8))
        put(w,500024,get(w,row+16))
        put(w,500032,rootfd(w,uint(s,72,8)))
        put(w,500040,rootfd(w,uint(s,80,8)))
        put(w,500048,get(w,row+320))
        put(w,500056,get(w,row+24))
        put(w,500064,uint(s,at+152,8))
        put(w,500072,uint(s,at+96,8))
        put(w,500080,uint(s,at+104,8))
        copy_input(s,w,500088,at+112,32)
        j = 0
        while j < uint(s,at+152,8):
            bi = uint(s,at+144,8)+j
            b = bindingrow(s,bi)
            target = 500128+j*192
            if uint(s,b,8) == 0:
                source = rootrow(s,uint(s,b+8,8))
                put(w,target,rootfd(w,uint(s,b+8,8)))
                put(w,target+8,uint(s,source+8,8))
                copy_input(s,w,target+32,source+32,32)
            else:
                c = cache(bi)
                if get(w,c) < 3:
                    return finish(o,w,74)
                put(w,target,get(w,c))
                put(w,target+8,get(w,c+8))
                copyw(w,target+32,c+16,32)
            put(w,target+16,uint(s,b+24,8))
            copy_input(s,w,target+64,b+160,128)
            j = j+1
        put(w,2136,128+uint(s,at+152,8)*192)
        put(w,2296,0)
        return resume(s,o,w,420)
    if p == 406:
        if r < 3:
            return finish(o,w,74)
        put(w,row+48,r)
        return writing(o,w,r,500000,get(w,2136),407)
    if p == 407:
        return call(o,w,408,72,get(w,row+48),1033,15,0,0,0,0)
    if p == 408:
        put(w,2144,0)
        put(w,2152,rootfd(w,uint(s,56,8)))
        put(w,2160,get(w,row+48))
        put(w,2168,get(w,row+32))
        put(w,2176,get(w,row+40))
        put(w,row+96,get(w,2120))
        return call(o,w,409,57,0,0,0,0,0,0,0)
    if p == 409:
        if r == 0:
            return resume(s,o,w,1000)
        put(w,row+8,r)
        put(w,row,1)
        if counts(s,w) == 0:
            return finish(o,w,74)
        return resume(s,o,w,300)
    if p == 420:
        i = get(w,2296)
        if i == uint(s,at+152,8):
            return call(o,w,406,319,61000,3,0,0,0,0,3)
        fd = get(w,500128+i*192)
        j = 0
        while j < i:
            if get(w,500128+j*192) == fd:
                return call(o,w,421,72,fd,1030,3,0,0,0,0)
            j = j+1
        put(w,2296,i+1)
        return resume(s,o,w,420)
    if p == 421:
        if r < 3:
            return finish(o,w,74)
        i = get(w,2296)
        put(w,500128+i*192,r)
        put(w,600000+get(w,2024)*512+i*8,r)
        put(w,2296,i+1)
        return resume(s,o,w,420)
    return finish(o,w,65)

def collect_phase(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    row = active(w)
    if failed(r):
        return finish(o,w,74)
    if p == 500:
        return call(o,w,501,5,get(w,row+40),1200,0,0,0,0,12)
    if p == 501:
        if get(w,1248) != 0:
            return finish(o,w,74)
        return call(o,w,502,5,get(w,row+32),1200,0,0,0,0,12)
    if p == 502:
        if get(w,1248) != 64:
            return finish(o,w,74)
        return call(o,w,503,72,get(w,row+32),1033,15,0,0,0,0)
    if p == 503:
        return reading(o,w,get(w,row+32),row+128,64,0,504)
    if p == 504:
        at = phaserow(s,get(w,2024))
        if get(w,row+128) != @DRIVER_OK@ or get(w,row+136) != uint(s,at+104,8) or get(w,row+144) != uint(s,at+96,8) or get(w,row+152) == 0:
            return finish(o,w,74)
        put(w,2296,0)
        return resume(s,o,w,505)
    if p == 505:
        if get(w,2296) == uint(s,phaserow(s,get(w,2024))+152,8):
            put(w,row,2)
            return resume(s,o,w,300)
        where = 600000+get(w,2024)*512+get(w,2296)*8
        fd = get(w,where)
        put(w,where,0)
        put(w,2296,get(w,2296)+1)
        if fd != 0:
            return call(o,w,506,3,fd,0,0,0,0,0,0)
        return resume(s,o,w,505)
    if p == 506:
        return resume(s,o,w,505)
    return finish(o,w,65)
'''
SOURCE+=r'''
def prepare_archive(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    row = active(w)
    at = phaserow(s,get(w,2024))
    if p == 600:
        phase_name(s,w,1)
        return call(o,w,601,257,uint(s,24,8),62000,655554,384,0,0,12)
    if failed(r):
        return finish(o,w,74)
    if p == 601:
        if r < 3:
            return finish(o,w,74)
        put(w,row+56,r)
        return call(o,w,602,319,61000,3,0,0,0,0,3)
    if p == 602:
        if r < 3:
            return finish(o,w,74)
        put(w,row+72,r)
        return call(o,w,603,319,61000,3,0,0,0,0,3)
    if p == 603:
        if r < 3:
            return finish(o,w,74)
        put(w,row+80,r)
        fill_range(w,500000,128,0)
        put(w,500000,@ARCHIVE_REQUEST@)
        put(w,500008,get(w,2008))
        put(w,500016,uint(s,16,8))
        put(w,500024,get(w,row+16))
        put(w,500032,get(w,row+24))
        put(w,500040,get(w,row+32))
        put(w,500048,get(w,row+320))
        put(w,500056,uint(s,at+96,8))
        put(w,500064,uint(s,at+104,8))
        put(w,500072,get(w,row+56))
        copy_input(s,w,500080,at+112,32)
        return call(o,w,604,319,61000,3,0,0,0,0,3)
    if p == 604:
        if r < 3:
            return finish(o,w,74)
        put(w,row+64,r)
        return writing(o,w,r,500000,128,605)
    if p == 605:
        return call(o,w,606,72,get(w,row+64),1033,15,0,0,0,0)
    if p == 606:
        put(w,2144,1)
        put(w,2152,rootfd(w,uint(s,64,8)))
        put(w,2160,get(w,row+64))
        put(w,2168,get(w,row+72))
        put(w,2176,get(w,row+80))
        return call(o,w,607,57,0,0,0,0,0,0,0)
    if p == 607:
        if r == 0:
            return resume(s,o,w,1000)
        put(w,row+88,r)
        if counts(s,w) == 0:
            return finish(o,w,74)
        if get(w,2304) != 0:
            put(w,2024,get(w,2304)-1)
            put(w,2304,0)
            previous = active(w)
            if get(w,previous) != 5 or get(w,previous+88) != 0:
                return finish(o,w,74)
            return hash_view(o,w,get(w,previous+56),0,get(w,previous+208),706)
        return resume(s,o,w,300)
    return finish(o,w,65)

def collect_archive(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    row = active(w)
    if failed(r):
        return finish(o,w,74)
    if p == 700:
        return call(o,w,701,5,get(w,row+80),1200,0,0,0,0,12)
    if p == 701:
        if get(w,1248) != 0:
            return finish(o,w,74)
        return call(o,w,702,5,get(w,row+72),1200,0,0,0,0,12)
    if p == 702:
        if get(w,1248) != 128:
            return finish(o,w,74)
        return call(o,w,703,72,get(w,row+72),1033,15,0,0,0,0)
    if p == 703:
        return reading(o,w,get(w,row+72),row+192,128,0,704)
    if p == 704:
        at = phaserow(s,get(w,2024))
        if get(w,row+192) != @ARCHIVE_OK@ or get(w,row+200) == 0 or get(w,row+200) > 4096 or get(w,row+208) < 240 or get(w,row+216) != uint(s,at+104,8) or same_input(s,w,at+112,row+224,32) == 0 or same(w,row+160,row+256,32) == 0:
            return finish(o,w,74)
        return call(o,w,705,5,get(w,row+56),1200,0,0,0,0,12)
    if p == 705:
        if getn(w,1224,4) & 61440 != 32768 or getn(w,1224,4) & 511 != 256 or get(w,1248) != get(w,row+208):
            return finish(o,w,74)
        if get(w,row) != 5 or get(w,row+88) != 0 or get(w,2304) != 0 or counts(s,w) == 0 or get(w,2064) != 0:
            return finish(o,w,74)
        if get(w,2048) < 2:
            i = 0
            queued = 0
            while i < uint(s,40,8) and queued == 0:
                if get(w,state(i)) == 2:
                    put(w,state(i),3)
                    queued = 1
                i = i+1
        if counts(s,w) == 0:
            return finish(o,w,74)
        i = 0
        while i < uint(s,40,8):
            if get(w,state(i)) == 3 and get(w,state(i)+88) == 0:
                put(w,2304,get(w,2024)+1)
                put(w,2024,i)
                return resume(s,o,w,600)
            i = i+1
        return hash_view(o,w,get(w,row+56),0,get(w,row+208),706)
    if p == 706:
        if same(w,4096,row+288,32) == 0:
            return finish(o,w,74)
        put(w,2184,0)
        return resume(s,o,w,800)
    if p == 710:
        if same(w,4096,row+288,32) == 0:
            return finish(o,w,74)
        put(w,2224,16)
        return resume(s,o,w,711)
    if p == 711:
        if get(w,2224) >= 88:
            return call(o,w,713,3,get(w,row+320),0,0,0,0,0,0)
        return call(o,w,712,3,get(w,row+get(w,2224)),0,0,0,0,0,0)
    if p == 712:
        put(w,2224,get(w,2224)+8)
        return resume(s,o,w,711)
    if p == 713:
        put(w,row,4)
        put(w,row+88,0)
        return resume(s,o,w,300)
    return finish(o,w,65)

def extract(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    row = active(w)
    b = bindingrow(s,get(w,2184))
    if failed(r):
        return finish(o,w,74)
    if p == 800:
        if get(w,2184) == uint(s,48,8):
            return hash_view(o,w,get(w,row+56),0,get(w,row+208),710)
        if uint(s,b,8) != 1 or uint(s,b+8,8) != get(w,2024):
            put(w,2184,get(w,2184)+1)
            return resume(s,o,w,800)
        j = 0
        while j < get(w,2184):
            old = bindingrow(s,j)
            if uint(s,old,8) == 1 and uint(s,old+8,8) == get(w,2024) and same_source(s,old+32,b+32,128) != 0 and get(w,cache(j)) >= 3:
                copyw(w,cache(get(w,2184)),cache(j),48)
                put(w,2184,get(w,2184)+1)
                return resume(s,o,w,800)
            j = j+1
        put(w,2192,64)
        put(w,2200,0)
        return reading(o,w,get(w,row+56),62000,64,0,801)
    if p == 801:
        at = phaserow(s,get(w,2024))
        if get(w,62000) != @ARCHIVE@ or get(w,62008) != get(w,row+200) or get(w,62016) != uint(s,at+104,8) or get(w,62024) != uint(s,at+96,8) or same_input(s,w,at+112,62032,32) == 0:
            return finish(o,w,74)
        return resume(s,o,w,802)
    if p == 802:
        if get(w,2200) >= get(w,row+200) or get(w,2192) > get(w,row+208) or get(w,row+208)-get(w,2192) < 176:
            return finish(o,w,74)
        return reading(o,w,get(w,row+56),62000,176,get(w,2192),803)
    if p == 803:
        n = get(w,62000)
        size = get(w,62008)
        if n == 0 or n > 127 or size > get(w,row+208)-get(w,2192)-176:
            return finish(o,w,74)
        if n == uint(s,b+16,8) and same_input(s,w,b+32,62048,128) != 0:
            if size > 67108864:
                return finish(o,w,65)
            put(w,2208,size)
            copyw(w,2232,62016,32)
            return call(o,w,804,319,61000,3,0,0,0,0,3)
        put(w,2192,get(w,2192)+176+size)
        put(w,2200,get(w,2200)+1)
        return resume(s,o,w,802)
    if p == 804:
        if r < 3:
            return finish(o,w,74)
        put(w,2216,r)
        return copying(o,w,get(w,row+56),r,get(w,2192)+176,get(w,2208),805)
    if p == 805:
        return hash_view(o,w,get(w,2216),0,get(w,2208),806)
    if p == 806:
        if same(w,4096,2232,32) == 0:
            return finish(o,w,74)
        return call(o,w,807,91,get(w,2216),320,0,0,0,0,0)
    if p == 807:
        return call(o,w,808,72,get(w,2216),1033,15,0,0,0,0)
    if p == 808:
        c = cache(get(w,2184))
        put(w,c,get(w,2216))
        put(w,c+8,get(w,2208))
        copyw(w,c+16,2232,32)
        put(w,2184,get(w,2184)+1)
        return resume(s,o,w,800)
    return finish(o,w,65)
'''
SOURCE+=r'''
def child(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    row = active(w)
    if failed(r):
        return finish(o,w,127)
    if p == 1000:
        return call(o,w,1001,157,1,9,0,0,0,0,0)
    if p == 1001:
        return call(o,w,1002,110,0,0,0,0,0,0,0)
    if p == 1002:
        if r != get(w,2008):
            return finish(o,w,127)
        return call(o,w,1003,436,3,4294967295,4,0,0,0,0)
    if p == 1003:
        return call(o,w,1004,33,get(w,2160),0,0,0,0,0,0)
    if p == 1004:
        return call(o,w,1005,33,get(w,2168),1,0,0,0,0,0)
    if p == 1005:
        return call(o,w,1006,33,get(w,2176),2,0,0,0,0,0)
    if p == 1006:
        return call(o,w,1007,81,get(w,row+16),0,0,0,0,0,0)
    if p == 1007:
        put(w,540000,get(w,row+16))
        put(w,540008,get(w,row+24))
        put(w,540016,get(w,row+320))
        n = 3
        if get(w,2144) == 0:
            i = 0
            while i < get(w,500064):
                put(w,540000+n*8,get(w,500128+i*192))
                n = n+1
                i = i+1
        else:
            put(w,540024,get(w,row+32))
            put(w,540032,get(w,row+56))
            n = 5
        put(w,2264,n)
        put(w,2256,0)
        return resume(s,o,w,1008)
    if p == 1008:
        if get(w,2256) == get(w,2264):
            put(w,60000,61000)
            put(w,60008,18446744073709551615)
            put(w,60016,61200)
            put(w,60024,61216)
            put(w,60032,61232)
            put(w,60040,61248)
            put(w,60048,18446744073709551615)
            put(w,0,1010)
            put(o,0,60000)
            put(o,8,7)
            put(o,16,60200)
            return 2
        return call(o,w,1009,72,get(w,540000+get(w,2256)*8),2,0,0,0,0,0)
    if p == 1009:
        put(w,2256,get(w,2256)+1)
        return resume(s,o,w,1008)
    if p == 1010:
        return call(o,w,1011,322,get(w,2152),61264,60200,60216,4096,0,252)
    return finish(o,w,127)

def complete(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p == 900:
        fill_range(w,500000,128+uint(s,40,8)*192,0)
        put(w,500000,@MASTER_OK@)
        put(w,500008,uint(s,40,8))
        put(w,500016,uint(s,88,8))
        put(w,500024,get(w,2120))
        put(w,500032,get(w,2080))
        put(w,500040,get(w,2104))
        put(w,500048,get(w,2088))
        put(w,500056,get(w,2096))
        put(w,500064,get(w,2016))
        put(w,500072,uint(s,32,8))
        put(w,500080,uint(s,48,8))
        put(w,500088,get(w,2008))
        put(w,500096,get(w,2280))
        i = 0
        while i < uint(s,40,8):
            row = state(i)
            at = phaserow(s,i)
            out = 500128+i*192
            put(w,out,i)
            put(w,out+8,uint(s,at+64,8))
            put(w,out+16,uint(s,at+72,8))
            put(w,out+24,uint(s,at+80,8))
            put(w,out+32,uint(s,at+104,8))
            put(w,out+40,uint(s,at+96,8))
            put(w,out+48,get(w,row+96))
            put(w,out+56,get(w,row+104))
            put(w,out+64,get(w,row+112))
            put(w,out+72,get(w,row+208))
            put(w,out+80,get(w,row+200))
            copy_input(s,w,out+96,at+112,32)
            copyw(w,out+128,row+160,32)
            copyw(w,out+160,row+288,32)
            i = i+1
        put(w,2272,0)
        return resume(s,o,w,901)
    if p == 901:
        if get(w,2272) == 128+uint(s,40,8)*192:
            return finish(o,w,0)
        return call(o,w,902,1,1,500000+get(w,2272),128+uint(s,40,8)*192-get(w,2272),0,0,0,12)
    if p == 902:
        if r == 18446744073709551612:
            return resume(s,o,w,901)
        if failed(r) or r == 0 or r > 128+uint(s,40,8)*192-get(w,2272):
            return finish(o,w,74)
        put(w,2272,get(w,2272)+r)
        return resume(s,o,w,901)
    return finish(o,w,65)
'''

def source():
    text=SOURCE.replace('and not failed(r)','and r >> 63 == 0')
    # Parent zero is admitted only as the explicit outer owner relationship;
    # actual parent is recorded and death-signal custody is retained.
    text=text.replace('uint(s,8,8) < 2 or uint(s,8,8) > 2147483647','(uint(s,8,8) != 0 and uint(s,8,8) < 2) or uint(s,8,8) > 2147483647')
    text=text.replace('if r != uint(s,8,8):','if uint(s,8,8) != 0 and r != uint(s,8,8):')
    text=text.replace('return call(o,w,2,157,1,9,0,0,0,0,0)','put(w,2280,r)\n        return call(o,w,2,157,1,9,0,0,0,0,0)')
    for key,value in {'REQUEST':b'HIAQMS01','PLAN':b'HIAQPL01','DRIVER_REQUEST':b'HIAQDR01','DRIVER_OK':b'HIAQOK01','ARCHIVE_REQUEST':b'HIAQARQ1','ARCHIVE_OK':b'HIAQAS01','ARCHIVE':b'HIAQAR01','MASTER_OK':b'HIAQMR01','B3':b'B3.flat\0','M3':b'M3.flat\0'}.items():
        text=text.replace('@'+key+'@',str(int.from_bytes(value,'little')))
    text+='\ndef initialize(w:mutbuf) -> u64:\n'
    for at,value in [(61000,b'hia-cold-master\0'),(61100,b'.hiaqar\0'),(61120,b'evidence.hiaqj\0'),(61200,b'PATH=\0'),(61216,b'LANG=C\0'),(61232,b'LC_ALL=C\0'),(61248,b'TZ=UTC\0'),(61264,b'\0')]:
        for i in range(0,len(value),8):text+=f'    put(w,{at+i},{int.from_bytes(value[i:i+8],"little")})\n'
    return text+'    return 0\n'+helpers()

if __name__=='__main__':
    for name,text in [('cold_master',source()),('cold_master_packer',packer(b'HIAQMP01'))]:
        doc=document(text);raw=render_assembly(doc).encode();path=ROOT/'examples/hia_bootstrap'/(name+'.hepta');path.write_bytes(raw)
        print(name,len(raw),len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),sha256(raw).hexdigest(),flush=True)
