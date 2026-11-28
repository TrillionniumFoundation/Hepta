"""Author the independent native cold-toolchain bootstrap/capture entry.

Development author only. The emitted HIA and its native packer are the public
construction implementation; no author is used by the finished entry.
"""
from pathlib import Path
from hashlib import sha256
import ast, struct, subprocess, tempfile
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_cli import source as cli_source
from tools.generate_hia_cold_master_common import helpers
from tools.generate_hia_cold_document import bulk_document
from tools.hia_cold_byte_loops import accelerate
from tools.hia_cold_guarded_read import guarded_u64_read
from tools.generate_hia_native_filter import LINK_SOURCE

ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) != 65536 or length(o) != 128 or length(w) != 8388608:
        return 0
    p = get(w,0)
    r = get(w,8)
    if p >= 200 and p < 250:
        return transfer(s,o,w,p,r)
    if p >= 250 and p < 300:
        return hashing(s,o,w,p,r)
    if p < 100:
        return startup(s,o,w,p,r)
    if p < 200:
        return metadata_input(s,o,w,p,r)
    if p == 399:
        return capture(s,o,w,p,r)
    if p < 400:
        return paths(s,o,w,p,r)
    if p < 450:
        return capture(s,o,w,p,r)
    if p < 480:
        return extract_asset(s,o,w,p,r)
    if p < 500:
        return sealing(s,o,w,p,r)
    if p < 600:
        return capture_all(s,o,w,p,r)
    if p < 700:
        return outer_owner(s,o,w,p,r)
    if p < 800:
        return postverify(s,o,w,p,r)
    if p < 900:
        return inner_start(s,o,w,p,r)
    if p < 1000:
        return run_stage(s,o,w,p,r)
    if p < 1100:
        return publication(s,o,w,p,r)
    if p < 1200:
        return manifests(s,o,w,p,r)
    if p < 1300:
        return launching(s,o,w,p,r)
    if p < 1400:
        return child(s,o,w,p,r)
    if p < 1500:
        return inner_complete(s,o,w,p,r)
    if p < 1600:
        return outer_complete(s,o,w,p,r)
    return install_path(s,o,w,p,r)

def asset_row(i:u64) -> u64:
    return 6291456+i*128

def pub_state(i:u64) -> u64:
    return 6816768+i*64

def source_path(w:mutbuf,i:u64) -> u64:
    return get(w,7078912+i*16)

def source_length(w:mutbuf,i:u64) -> u64:
    return get(w,7078920+i*16)

def recipe(w:mutbuf,at:u64) -> u64:
    return get(w,2097152+at)

def stage_row(w:mutbuf,i:u64) -> u64:
    return 2097280+i*64

def binding_row(w:mutbuf,i:u64) -> u64:
    return 2097152+recipe(w,56)+i*128

def publication_row(w:mutbuf,i:u64) -> u64:
    return 2097152+recipe(w,64)+i*320

def lexical(w:mutbuf,a:u64,an:u64,b:u64,bn:u64) -> u64:
    i = 0
    while i < minimum(an,bn):
        av = byte(w,a+i)
        bv = byte(w,b+i)
        if av != bv:
            return choose(av < bv,1,0)
        i = i+1
    return choose(an < bn,1,0)

def zeros(w:mutbuf,at:u64,n:u64) -> u64:
    i = 0
    while i < n:
        if byte(w,at+i) != 0:
            return 0
        i = i+1
    return 1

def path_valid(w:mutbuf,at:u64,n:u64,flat:u64) -> u64:
    if n == 0 or n > 4095 or byte(w,at) == 47 or byte(w,at+n-1) == 47:
        return 0
    if flat != 0 and byte(w,at) == 46:
        return 0
    i = 0
    start = 0
    while i <= n:
        if i == n or byte(w,at+i) == 47:
            size = i-start
            if size == 0 or size > 255 or (flat != 0 and i != n):
                return 0
            if size == 1 and byte(w,at+start) == 46:
                return 0
            if size == 2 and byte(w,at+start) == 46 and byte(w,at+start+1) == 46:
                return 0
            if size == 4 and same(w,at+start,61360,4) != 0:
                return 0
            if size == 11 and same(w,at+start,61376,11) != 0:
                return 0
            start = i+1
        else:
            c = byte(w,at+i)
            if c < 33 or c > 126:
                return 0
        i = i+1
    return 1

def reserved_output(w:mutbuf,at:u64,n:u64) -> u64:
    i = 0
    while i < 7:
        size = get(w,62528+i*64)
        if n >= size and same(w,at,62536+i*64,size) != 0:
            if n == size or byte(w,at+size) == 47:
                return 1
        i = i+1
    return 0

def valid_authority(w:mutbuf) -> u64:
    n = get(w,2080)
    if n < 40 or n > 1048576 or get(w,1048576) != @AUTHORITY@ or get(w,1048584) != 1 or get(w,1048600) != 0:
        return 0
    count = get(w,1048592)
    if count == 0 or count > 4096:
        return 0
    put(w,2096,count)
    at = 1048608
    end = 1048576+n
    i = 0
    found = 0
    while i < count:
        if at > end or end-at < 9:
            return 0
        size = get(w,at)
        if size == 0 or size > 4095 or size > end-at-8:
            return 0
        path = at+8
        if path_valid(w,path,size,0) == 0:
            return 0
        if i != 0 and lexical(w,source_path(w,i-1),source_length(w,i-1),path,size) == 0:
            return 0
        put(w,7078912+i*16,path)
        put(w,7078920+i*16,size)
        if size == @AUTHORITY_PATH_SIZE@ and same(w,path,61504,size) != 0:
            found = found | 1
            put(w,2880,i)
        if size == @RECIPE_PATH_SIZE@ and same(w,path,61632,size) != 0:
            found = found | 2
            put(w,2888,i)
        after = at+8+((size+7) & 18446744073709551608)
        if after > end or zeros(w,path+size,after-path-size) == 0:
            return 0
        at = after
        i = i+1
    return choose(at == end and found == 3,1,0)

def valid_publications(w:mutbuf) -> u64:
    i = 0
    while i < get(w,2152):
        row = publication_row(w,i)
        name = get(w,row)
        path = get(w,row+8)
        mode = get(w,row+16)
        flag = get(w,row+24)
        if name == 0 or name > 63 or path > 191 or (mode != 256 and mode != 320) or flag > 1 or get(w,row+32) > 67108864 or zeros(w,row+40,24) == 0:
            return 0
        if path_valid(w,row+64,name,1) == 0 or zeros(w,row+64+name,64-name) == 0 or zeros(w,row+128+path,192-path) == 0:
            return 0
        if flag == 0:
            if path != 0:
                return 0
        else:
            if path_valid(w,row+128,path,0) == 0 or reserved_output(w,row+128,path) != 0:
                return 0
            j = 0
            while j < i:
                previous = publication_row(w,j)
                if get(w,previous+24) == 1 and get(w,previous+8) == path and same(w,previous+128,row+128,path) != 0:
                    return 0
                j = j+1
        i = i+1
    return 1

def valid_stage(w:mutbuf,i:u64,bind_start:u64,pub_start:u64) -> u64:
    row = stage_row(w,i)
    if get(w,row) != i or get(w,row+8) >= get(w,2096) or get(w,row+16) != bind_start or get(w,row+32) != pub_start or get(w,row+48) != 0 or get(w,row+56) != 0:
        return 0
    nb = get(w,row+24)
    np = get(w,row+40)
    if nb < 2 or nb > 64 or nb > get(w,2144)-bind_start or np == 0 or np > get(w,2152)-pub_start:
        return 0
    j = 0
    special = 0
    while j < nb:
        b = binding_row(w,bind_start+j)
        n = get(w,b)
        kind = get(w,b+8)
        index = get(w,b+16)
        if n == 0 or n > 95 or kind > 5 or get(w,b+24) != 0 or path_valid(w,b+32,n,1) == 0 or zeros(w,b+32+n,96-n) == 0:
            return 0
        if (kind == 0 and index >= 7) or (kind == 1 and index >= get(w,2096)) or (kind == 2 and index >= pub_start) or (kind >= 3 and index != 0):
            return 0
        if kind == 4 and installed_count(w,pub_start) == 0:
            return 0
        k = 0
        while k < j:
            other = binding_row(w,bind_start+k)
            if get(w,other) == n and same(w,other+32,b+32,n) != 0:
                return 0
            k = k+1
        if n == 4 and same(w,b+32,62400,4) != 0:
            special = special | 1
        if n == 4 and same(w,b+32,62416,4) != 0:
            special = special | 2
        j = j+1
    if special != 3:
        return 0
    j = 0
    while j < np:
        p = publication_row(w,pub_start+j)
        k = 0
        while k < j:
            previous = publication_row(w,pub_start+k)
            if get(w,previous) == get(w,p) and same(w,previous+64,p+64,get(w,p)) != 0:
                return 0
            k = k+1
        j = j+1
    return 1

def valid_recipe(w:mutbuf) -> u64:
    n = get(w,2088)
    if n < 128 or n > 2097152 or recipe(w,0) != @RECIPE@ or recipe(w,8) != 1 or recipe(w,40) != get(w,2096) or recipe(w,48) != 128 or recipe(w,72) != n or zeros(w,2097232,48) == 0:
        return 0
    stages = recipe(w,16)
    bindings = recipe(w,24)
    pubs = recipe(w,32)
    if stages == 0 or stages > 64 or bindings < stages*2 or bindings > 4096 or pubs == 0 or pubs > 4096:
        return 0
    if recipe(w,56) != 128+stages*64 or recipe(w,64) != 128+stages*64+bindings*128 or n != 128+stages*64+bindings*128+pubs*320:
        return 0
    put(w,2136,stages)
    put(w,2144,bindings)
    put(w,2152,pubs)
    if valid_publications(w) == 0 or installed_count(w,pubs) == 0:
        return 0
    b = 0
    p = 0
    i = 0
    while i < stages:
        if valid_stage(w,i,b,p) == 0:
            return 0
        row = stage_row(w,i)
        b = b+get(w,row+24)
        p = p+get(w,row+40)
        i = i+1
    return choose(b == bindings and p == pubs,1,0)
'''

SOURCE+=r'''
def decimal_input(s:readbuf,at:u64,n:u64) -> u64:
    if n == 0 or n > 7:
        return 0
    v = 0
    i = 0
    while i < n:
        c = byte(s,at+i)
        if c < 48 or c > 57:
            return 0
        v = v*10+c-48
        i = i+1
    return choose(v >= 3 and v <= 1048575,v,0)

def arguments(s:readbuf,w:mutbuf) -> u64:
    argc = uint(s,8,8)
    if argc != 7 and argc != 4:
        return 0
    put(w,2016,choose(argc == 4,1,0))
    at = 304
    i = 0
    while i < argc:
        if at > 65536-9:
            return 0
        n = uint(s,at,8)
        if n == 0 or n > 8191 or n > 65536-at-9 or byte(s,at+8+n) != 0:
            return 0
        if i != 0:
            if argc == 4:
                if i == 1:
                    if n != 10 or same_input(s,w,at+8,61424,10) == 0:
                        return 0
                else:
                    fd = decimal_input(s,at+8,n)
                    if fd == 0:
                        return 0
                    put(w,choose(i == 2,2064,2056),fd)
            elif i & 1 != 0:
                index = i >> 1
                size = choose(index == 1,11,8)
                if n != size or same_input(s,w,at+8,62000+index*16,size) == 0:
                    return 0
            else:
                index = (i >> 1)-1
                if n < 2 or byte(s,at+8) != 47:
                    return 0
                copy_input(s,w,320000+index*8192,at+8,n+1)
                put(w,2800+index*8,n)
        at = at+9+n
        i = i+1
    return 1

def startup(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p == 0:
        constants(w)
        if uint(s,0,8) != @ARGV@ or arguments(s,w) == 0:
            return finish(o,w,64)
        copy_input(s,w,20000,16,288)
        return call(o,w,1,107,0,0,0,0,0,0,0)
    if failed(r):
        return finish(o,w,74)
    if p == 1:
        put(w,2000,r)
        return call(o,w,2,39,0,0,0,0,0,0,0)
    if p == 2:
        put(w,2008,r)
        if get(w,2016) != 0:
            if get(w,2064) == get(w,2056):
                return finish(o,w,65)
            return resume(s,o,w,800)
        return open_path(s,o,w,320000,get(w,2800),18446744073709551516,0,3)
    if p == 3:
        put(w,2040,get(w,2592))
        return open_path(s,o,w,328192,get(w,2808),18446744073709551516,0,4)
    if p == 4:
        put(w,2048,get(w,2592))
        return open_path(s,o,w,336384,get(w,2816),18446744073709551516,2,5)
    if p == 5:
        put(w,2056,get(w,2592))
        return call(o,w,6,5,get(w,2056),1200,0,0,0,0,12)
    if p == 6:
        if private_directory(w) == 0:
            return finish(o,w,65)
        return call(o,w,7,319,61000,3,0,0,0,0,3)
    if p == 7:
        if r < 3:
            return finish(o,w,74)
        put(w,2064,r)
        return call(o,w,8,77,r,8388608,0,0,0,0,0)
    if p == 8:
        put(w,2072,8388608)
        return start_capture(s,o,w,61504,@AUTHORITY_PATH_SIZE@,get(w,2040),1048576,256,20000,0,100)
    return finish(o,w,65)

def private_directory(w:mutbuf) -> u64:
    return choose(getn(w,1224,4) & 65535 == 16832 and getn(w,1228,4) == get(w,2000),1,0)

def regular_capture(w:mutbuf) -> u64:
    links = get(w,1216)
    if getn(w,1224,4) & 61440 != 32768 or (links != 1 and (get(w,2424) == 0 or links != 0)):
        return 0
    return choose(get(w,1248) <= get(w,2352),1,0)

def capture_stable(w:mutbuf) -> u64:
    if same(w,1200,18000,56) == 0 or same(w,1288,18088,32) == 0:
        return 0
    return regular_capture(w)

def start_capture(s:readbuf,o:mutbuf,w:mutbuf,path:u64,n:u64,base:u64,maximum:u64,mode:u64,pin:u64,self:u64,after:u64) -> u32:
    put(w,2328,pin)
    put(w,2344,after)
    put(w,2352,maximum)
    put(w,2416,mode)
    put(w,2424,self)
    if self != 0:
        return call(o,w,399,257,18446744073709551516,61400,526336,0,0,0,12)
    return open_path(s,o,w,path,n,base,1,400)

def capture(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 399:
        put(w,2592,r)
        return resume(s,o,w,400)
    if p == 400:
        if get(w,2592) < 3:
            return finish(o,w,74)
        put(w,2304,get(w,2592))
        return call(o,w,401,5,get(w,2304),1200,0,0,0,0,12)
    if p == 401:
        if regular_capture(w) == 0:
            return finish(o,w,65)
        put(w,2312,get(w,1248))
        copyw(w,18000,1200,160)
        return call(o,w,402,319,61000,3,0,0,0,0,3)
    if p == 402:
        if r < 3:
            return finish(o,w,74)
        put(w,2320,r)
        return call(o,w,403,91,r,get(w,2416),0,0,0,0,0)
    if p == 403:
        return copying(o,w,get(w,2304),get(w,2320),0,get(w,2312),404)
    if p == 404:
        return call(o,w,405,5,get(w,2304),1200,0,0,0,0,12)
    if p == 405:
        if capture_stable(w) == 0:
            return finish(o,w,74)
        return call(o,w,406,72,get(w,2320),1033,15,0,0,0,0)
    if p == 406:
        return call(o,w,407,72,get(w,2320),1034,0,0,0,0,0)
    if p == 407:
        if r != 15:
            return finish(o,w,74)
        return hash_view(o,w,get(w,2320),0,get(w,2312),408)
    if p == 408:
        copyw(w,19000,4096,32)
        if get(w,2328) != 0 and same(w,19000,get(w,2328),32) == 0:
            return finish(o,w,65)
        return hash_view(o,w,get(w,2304),0,get(w,2312),409)
    if p == 409:
        if same(w,4096,19000,32) == 0:
            return finish(o,w,74)
        return call(o,w,410,5,get(w,2304),1200,0,0,0,0,12)
    if p == 410:
        if capture_stable(w) == 0:
            return finish(o,w,74)
        return call(o,w,411,3,get(w,2304),0,0,0,0,0,0)
    if p == 411:
        return resume(s,o,w,get(w,2344))
    return finish(o,w,65)

def metadata_input(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 100:
        if get(w,2312) < 40:
            return finish(o,w,65)
        put(w,2080,get(w,2312))
        return reading(o,w,get(w,2320),1048576,get(w,2080),0,101)
    if p == 101:
        if valid_authority(w) == 0:
            return finish(o,w,65)
        return call(o,w,102,3,get(w,2320),0,0,0,0,0,0)
    if p == 102:
        return start_capture(s,o,w,61632,@RECIPE_PATH_SIZE@,get(w,2040),2097152,256,20032,0,103)
    if p == 103:
        if get(w,2312) < 128:
            return finish(o,w,65)
        put(w,2088,get(w,2312))
        return reading(o,w,get(w,2320),2097152,get(w,2088),0,104)
    if p == 104:
        if valid_recipe(w) == 0:
            return finish(o,w,65)
        return call(o,w,105,3,get(w,2320),0,0,0,0,0,0)
    if p == 105:
        put(w,2400,0)
        return resume(s,o,w,500)
    return finish(o,w,65)
'''

SOURCE+=r'''
def zlength(w:mutbuf,at:u64,maximum:u64) -> u64:
    i = 0
    while i < maximum:
        if byte(w,at+i) == 0:
            return i
        i = i+1
    return 0

def save_asset(w:mutbuf,i:u64) -> u64:
    row = asset_row(i)
    fill_range(w,row,128,0)
    put(w,row,get(w,2072))
    put(w,row+8,get(w,2312))
    copyw(w,row+16,19000,32)
    copyw(w,row+48,18000,40)
    copyw(w,row+88,18088,32)
    return 0

def source_manifest_add(w:mutbuf,i:u64) -> u64:
    n = source_length(w,i)
    at = get(w,2104)
    if at > 1048576 or n+48 > 1048576-at:
        return 0
    row = asset_row(i+8)
    put(w,4194304+at,n)
    put(w,4194312+at,get(w,row+8))
    copyw(w,4194320+at,row+16,32)
    copyw(w,4194352+at,source_path(w,i),n)
    put(w,2104,at+48+n)
    return 1

def begin_source_capture(s:readbuf,o:mutbuf,w:mutbuf,i:u64,after:u64) -> u32:
    if i < 7:
        path = 62100+i*40
        return start_capture(s,o,w,path,zlength(w,path,40),get(w,2048),67108864,320,20064+i*32,0,after)
    if i == 7:
        return start_capture(s,o,w,0,0,0,1048576,320,0,1,after)
    index = i-8
    return start_capture(s,o,w,source_path(w,index),source_length(w,index),get(w,2040),67108864,256,0,0,after)

def capture_all(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 500:
        if get(w,2400) == 0:
            put(w,4194304,@MANIFEST@)
            put(w,4194312,get(w,2096))
            put(w,4194320,1)
            put(w,4194328,0)
            put(w,2104,32)
        if get(w,2400) == get(w,2096)+8:
            return writing_at(o,w,get(w,2064),1048576,get(w,2080),1048576,510)
        return begin_source_capture(s,o,w,get(w,2400),501)
    if p == 501:
        if get(w,2072) > 2147483648-get(w,2312):
            return finish(o,w,65)
        save_asset(w,get(w,2400))
        if get(w,2400) < 8:
            put(w,16000+get(w,2400)*8,get(w,2320))
        else:
            if source_manifest_add(w,get(w,2400)-8) == 0:
                return finish(o,w,65)
            if get(w,2400)-8 == get(w,2880) and (get(w,2312) != get(w,2080) or same(w,19000,20000,32) == 0):
                return finish(o,w,74)
            if get(w,2400)-8 == get(w,2888) and (get(w,2312) != get(w,2088) or same(w,19000,20032,32) == 0):
                return finish(o,w,74)
        return call(o,w,502,8,get(w,2064),get(w,2072),0,0,0,0,0)
    if p == 502:
        if r != get(w,2072):
            return finish(o,w,74)
        return copying(o,w,get(w,2320),get(w,2064),0,get(w,2312),503)
    if p == 503:
        put(w,2072,get(w,2072)+get(w,2312))
        if get(w,2400) >= 8:
            return call(o,w,504,3,get(w,2320),0,0,0,0,0,0)
        return resume(s,o,w,504)
    if p == 504:
        put(w,2400,get(w,2400)+1)
        return resume(s,o,w,500)
    if p == 510:
        return writing_at(o,w,get(w,2064),2097152,get(w,2088),2097152,511)
    if p == 511:
        return writing_at(o,w,get(w,2064),4194304,get(w,2104),4194304,512)
    if p == 512:
        return writing_at(o,w,get(w,2064),6291456,(get(w,2096)+8)*128,8192,513)
    if p == 513:
        fill_range(w,400000,128,0)
        put(w,400000,@TRANSPORT@)
        put(w,400008,1)
        put(w,400016,get(w,2096))
        put(w,400024,get(w,2136))
        put(w,400032,get(w,2080))
        put(w,400040,get(w,2088))
        put(w,400048,get(w,2104))
        put(w,400056,get(w,2072))
        put(w,400064,get(w,2000))
        return writing(o,w,get(w,2064),400000,128,514)
    if p == 514:
        return call(o,w,515,72,get(w,2064),1033,15,0,0,0,0)
    if p == 515:
        return call(o,w,516,72,get(w,2064),1034,0,0,0,0,0)
    if p == 516:
        if r != 15:
            return finish(o,w,74)
        return reading(o,w,get(w,2064),7200000,128,0,517)
    if p == 517:
        if same(w,400000,7200000,128) == 0:
            return finish(o,w,74)
        return reading(o,w,get(w,2064),7200000,(get(w,2096)+8)*128,8192,518)
    if p == 518:
        if same(w,6291456,7200000,(get(w,2096)+8)*128) == 0:
            return finish(o,w,74)
        return reading(o,w,get(w,2064),7200000,get(w,2104),4194304,519)
    if p == 519:
        if same(w,4194304,7200000,get(w,2104)) == 0:
            return finish(o,w,74)
        return hash_view(o,w,get(w,2064),1048576,get(w,2080),520)
    if p == 520:
        if same(w,4096,20000,32) == 0:
            return finish(o,w,74)
        return hash_view(o,w,get(w,2064),2097152,get(w,2088),521)
    if p == 521:
        if same(w,4096,20032,32) == 0:
            return finish(o,w,74)
        return hash_view(o,w,get(w,2064),4194304,get(w,2104),522)
    if p == 522:
        copyw(w,21000,4096,32)
        put(w,2400,0)
        return resume(s,o,w,523)
    if p == 523:
        if get(w,2400) == get(w,2096)+8:
            return resume(s,o,w,600)
        row = asset_row(get(w,2400))
        return hash_view(o,w,get(w,2064),get(w,row),get(w,row+8),524)
    if p == 524:
        if same(w,4096,asset_row(get(w,2400))+16,32) == 0:
            return finish(o,w,74)
        put(w,2400,get(w,2400)+1)
        return resume(s,o,w,523)
    return finish(o,w,65)

def start_extract(o:mutbuf,w:mutbuf,fd:u64,offset:u64,size:u64,pin:u64,after:u64) -> u32:
    if size > 67108864:
        return finish(o,w,65)
    put(w,2450,fd)
    put(w,2458,offset)
    put(w,2466,size)
    put(w,2474,pin)
    put(w,2482,after)
    return call(o,w,450,319,61000,3,0,0,0,0,3)

def extract_asset(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 450:
        if r < 3:
            return finish(o,w,74)
        put(w,2442,r)
        return call(o,w,451,91,r,320,0,0,0,0,0)
    if p == 451:
        return copying(o,w,get(w,2450),get(w,2442),get(w,2458),get(w,2466),452)
    if p == 452:
        return call(o,w,453,72,get(w,2442),1033,15,0,0,0,0)
    if p == 453:
        return call(o,w,454,72,get(w,2442),1034,0,0,0,0,0)
    if p == 454:
        if r != 15:
            return finish(o,w,74)
        return hash_view(o,w,get(w,2442),0,get(w,2466),455)
    if p == 455:
        if same(w,4096,get(w,2474),32) == 0:
            return finish(o,w,74)
        return resume(s,o,w,get(w,2482))
    return finish(o,w,65)
'''

SOURCE+=r'''
def quotient_ten(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit != 0:
        bit = bit-1
        remainder = (remainder << 1) | ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder-10
            quotient = quotient | (1 << bit)
    return quotient

def decimal_text(w:mutbuf,at:u64,value:u64) -> u64:
    n = 0
    if value == 0:
        store(w,at,48)
        return 1
    while value != 0:
        following = quotient_ten(value)
        store(w,350000+n,48+value-following*10)
        value = following
        n = n+1
    i = 0
    while i < n:
        store(w,at+i,byte(w,350000+n-i-1))
        i = i+1
    return n

def owner_request(w:mutbuf) -> u64:
    fill_range(w,400000,128,0)
    put(w,400000,@OWNER_REQUEST@)
    put(w,400008,get(w,2008))
    put(w,400016,get(w,2168))
    put(w,400024,get(w,2176))
    put(w,400032,180)
    put(w,400040,get(w,16056))
    put(w,400048,get(w,2272))
    put(w,400056,get(w,2256))
    put(w,400064,get(w,2264))
    put(w,400072,get(w,2248))
    put(w,400080,get(w,2056))
    put(w,400088,4)
    put(w,400096,6)
    put(w,400104,2)
    at = argument(w,400128,61000,14)
    at = argument(w,at,61424,10)
    n = decimal_text(w,351000,get(w,2064))
    at = argument(w,at,351000,n)
    n = decimal_text(w,351000,get(w,2856))
    at = argument(w,at,351000,n)
    at = argument(w,at,61200,5)
    at = argument(w,at,61216,6)
    at = argument(w,at,61232,8)
    at = argument(w,at,61248,6)
    copyw(w,360000,61264,5)
    copyw(w,360005,336384,get(w,2816))
    copyw(w,360005+get(w,2816),61280,5)
    at = argument(w,at,360000,10+get(w,2816))
    copyw(w,360000,61296,7)
    copyw(w,360007,336384,get(w,2816))
    copyw(w,360007+get(w,2816),61312,4)
    at = argument(w,at,360000,11+get(w,2816))
    put(w,at,get(w,2064))
    put(w,at+8,get(w,2856))
    return at+16-400000

def outer_owner(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 600:
        if get(w,2816) > 8180:
            return finish(o,w,65)
        return call(o,w,601,258,get(w,2056),61132,448,0,0,0,12)
    if p == 601:
        return call(o,w,602,258,get(w,2056),61148,448,0,0,0,12)
    if p == 602:
        return call(o,w,603,258,get(w,2056),61100,448,0,0,0,12)
    if p == 603:
        return call(o,w,604,319,61000,3,0,0,0,0,3)
    if p == 604:
        if r < 3:
            return finish(o,w,74)
        put(w,2272,r)
        return call(o,w,605,72,r,1033,15,0,0,0,0)
    if p == 605:
        return call(o,w,606,319,61000,3,0,0,0,0,3)
    if p == 606:
        if r < 3:
            return finish(o,w,74)
        put(w,2256,r)
        return call(o,w,607,91,r,384,0,0,0,0,0)
    if p == 607:
        return call(o,w,608,319,61000,3,0,0,0,0,3)
    if p == 608:
        if r < 3:
            return finish(o,w,74)
        put(w,2264,r)
        return call(o,w,609,91,r,384,0,0,0,0,0)
    if p == 609:
        return call(o,w,610,257,get(w,2056),61328,655554,384,0,0,12)
    if p == 610:
        if r < 3:
            return finish(o,w,74)
        put(w,2248,r)
        return call(o,w,611,72,get(w,2056),1030,3,0,0,0,0)
    if p == 611:
        if r < 3:
            return finish(o,w,74)
        put(w,2856,r)
        return call(o,w,612,228,1,1400,0,0,0,0,12)
    if p == 612:
        start = get(w,1400)*1000000000+get(w,1408)
        put(w,2168,start)
        put(w,2176,start+180000000000)
        n = owner_request(w)
        return seal_request(o,w,400000,n,613)
    if p == 613:
        put(w,2280,get(w,2368))
        i = 0
        while i < 6:
            put(w,540000+i*8,get(w,400040+i*8))
            i = i+1
        put(w,540048,get(w,2064))
        put(w,540056,get(w,2856))
        return launch(o,w,get(w,16048),get(w,2280),0,8,614)
    if p == 614:
        put(w,2288,get(w,2728))
        return call(o,w,615,5,get(w,2248),1200,0,0,0,0,12)
    if p == 615:
        if get(w,1248) < 256 or get(w,1248) > 1048576:
            return finish(o,w,74)
        put(w,2840,get(w,1248))
        return reading(o,w,get(w,2248),7200000,256,0,616)
    if p == 616:
        if valid_owner_receipt(w) == 0:
            return finish(o,w,74)
        return call(o,w,617,5,get(w,2264),1200,0,0,0,0,12)
    if p == 617:
        if get(w,1248) != 0:
            return finish(o,w,74)
        return call(o,w,618,5,get(w,2256),1200,0,0,0,0,12)
    if p == 618:
        if get(w,1248) != 128:
            return finish(o,w,74)
        return call(o,w,619,72,get(w,2256),1033,15,0,0,0,0)
    if p == 619:
        return reading(o,w,get(w,2256),390000,128,0,620)
    if p == 620:
        if get(w,390000) != @INNER_OK@ or get(w,390008) != 1 or get(w,390016) != get(w,2136) or get(w,390024) != get(w,2096) or get(w,390032) != installed_count(w,get(w,2152)) or get(w,390040) != get(w,2104) or get(w,390048) < 32 or get(w,390048) > 1048576 or get(w,390056) != 0 or same(w,390064,21000,32) == 0:
            return finish(o,w,74)
        put(w,2112,get(w,390048))
        copyw(w,21032,390096,32)
        put(w,2400,0)
        return resume(s,o,w,700)
    return finish(o,w,65)

def valid_owner_receipt(w:mutbuf) -> u64:
    at = 7200000
    if get(w,at) != @OWNER_OK@ or get(w,at+8) != 0 or get(w,at+16) != get(w,2288) or get(w,at+24) != get(w,2008) or get(w,at+32) != get(w,2168) or get(w,at+40) != get(w,2176) or get(w,at+48) != 180 or get(w,at+56) != 3000000000:
        return 0
    if get(w,at+64) < 2 or get(w,at+72) != 0 or get(w,at+80) != 0 or get(w,at+88) != 1 or get(w,at+96) != 1 or get(w,at+104) != 1 or get(w,at+112) != 0 or get(w,at+120) != 0 or get(w,at+136) != 0 or get(w,at+168) != 0 or get(w,at+176) != 1 or get(w,at+192) != 0:
        return 0
    if get(w,at+128) > 16384 or get(w,at+144) > 4096 or get(w,at+200) != 4096 or get(w,at+208) != 16384 or get(w,at+216) != 65536 or get(w,at+224) != 1 or get(w,at+232) != 0 or get(w,at+240) != 0 or get(w,at+248) != 0:
        return 0
    if get(w,at+152) < get(w,2168) or get(w,at+152) > get(w,2176) or get(w,at+160) != get(w,at+152)+3000000000 or get(w,at+184) < get(w,at+152) or get(w,at+184) > get(w,at+160):
        return 0
    return choose(get(w,2840) == 256+get(w,at+128)*40+get(w,at+144)*48,1,0)

def original_unchanged(w:mutbuf,row:u64) -> u64:
    if get(w,2312) != get(w,row+8) or same(w,19000,row+16,32) == 0 or same(w,18000,row+48,40) == 0 or same(w,18088,row+88,32) == 0:
        return 0
    return 1

def postverify(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 700:
        if get(w,2400) == get(w,2096)+8:
            return start_capture(s,o,w,61760,zlength(w,61760,32),get(w,2056),1048576,256,21000,0,710)
        return begin_source_capture(s,o,w,get(w,2400),701)
    if p == 701:
        if original_unchanged(w,asset_row(get(w,2400))) == 0:
            return finish(o,w,74)
        return call(o,w,702,3,get(w,2320),0,0,0,0,0,0)
    if p == 702:
        put(w,2400,get(w,2400)+1)
        return resume(s,o,w,700)
    if p == 710:
        if get(w,2312) != get(w,2104):
            return finish(o,w,74)
        return call(o,w,711,3,get(w,2320),0,0,0,0,0,0)
    if p == 711:
        return start_capture(s,o,w,61792,zlength(w,61792,32),get(w,2056),1048576,256,21032,0,712)
    if p == 712:
        if get(w,2312) != get(w,2112):
            return finish(o,w,74)
        return reading(o,w,get(w,2320),5242880,get(w,2112),0,713)
    if p == 713:
        if valid_tool_manifest(w) == 0:
            return finish(o,w,74)
        return call(o,w,714,3,get(w,2320),0,0,0,0,0,0)
    if p == 714:
        put(w,2400,0)
        put(w,2824,5242912)
        return resume(s,o,w,715)
    if p == 715:
        if get(w,2400) == installed_count(w,get(w,2152)):
            return resume(s,o,w,1500)
        at = get(w,2824)
        return start_capture(s,o,w,at+48,get(w,at),get(w,2056),67108864,256,at+16,0,716)
    if p == 716:
        at = get(w,2824)
        pub = publication_row(w,get(w,7144448+get(w,2400)*8))
        if get(w,2312) != get(w,at+8) or getn(w,18024,4) & 4095 != get(w,pub+16) or getn(w,18028,4) != get(w,2000):
            return finish(o,w,74)
        return call(o,w,717,3,get(w,2320),0,0,0,0,0,0)
    if p == 717:
        put(w,2824,get(w,2824)+48+get(w,get(w,2824)))
        put(w,2400,get(w,2400)+1)
        return resume(s,o,w,715)
    return finish(o,w,65)
'''

SOURCE+=r'''
def nonzero_pin(w:mutbuf,at:u64) -> u64:
    return choose(get(w,at) | get(w,at+8) | get(w,at+16) | get(w,at+24) != 0,1,0)

def valid_transport(w:mutbuf) -> u64:
    at = 8388608
    i = 0
    while i < get(w,2096)+8:
        row = asset_row(i)
        n = get(w,row+8)
        if get(w,row) != at or n > 67108864 or n > get(w,2072)-at or nonzero_pin(w,row+16) == 0 or get(w,row+120) != 0:
            return 0
        if i < 7 and same(w,row+16,20064+i*32,32) == 0:
            return 0
        if i == 7 and (n == 0 or n > 1048576):
            return 0
        at = at+n
        i = i+1
    if at != get(w,2072):
        return 0
    row = asset_row(get(w,2880)+8)
    if get(w,row+8) != get(w,2080) or same(w,row+16,20000,32) == 0:
        return 0
    row = asset_row(get(w,2888)+8)
    if get(w,row+8) != get(w,2088) or same(w,row+16,20032,32) == 0:
        return 0
    return 1

def valid_source_manifest(w:mutbuf) -> u64:
    if get(w,4194304) != @MANIFEST@ or get(w,4194312) != get(w,2096) or get(w,4194320) != 1 or get(w,4194328) != 0:
        return 0
    at = 4194336
    end = 4194304+get(w,2104)
    i = 0
    while i < get(w,2096):
        n = source_length(w,i)
        if at > end or n+48 > end-at:
            return 0
        row = asset_row(i+8)
        if get(w,at) != n or get(w,at+8) != get(w,row+8) or same(w,at+16,row+16,32) == 0 or same(w,at+48,source_path(w,i),n) == 0:
            return 0
        at = at+48+n
        i = i+1
    return choose(at == end,1,0)

def inner_start(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 800:
        return call(o,w,801,110,0,0,0,0,0,0,0)
    if p == 801:
        if r < 2:
            return finish(o,w,65)
        put(w,2832,r)
        return call(o,w,802,157,1,9,0,0,0,0,0)
    if p == 802:
        return call(o,w,803,110,0,0,0,0,0,0,0)
    if p == 803:
        if r != get(w,2832):
            return finish(o,w,74)
        return call(o,w,804,5,get(w,2056),1200,0,0,0,0,12)
    if p == 804:
        if private_directory(w) == 0:
            return finish(o,w,65)
        return call(o,w,805,72,get(w,2064),1034,0,0,0,0,0)
    if p == 805:
        if r != 15:
            return finish(o,w,65)
        return call(o,w,806,5,get(w,2064),1200,0,0,0,0,12)
    if p == 806:
        if getn(w,1224,4) & 61440 != 32768 or get(w,1248) < 8388608 or get(w,1248) > 2147483648:
            return finish(o,w,65)
        put(w,2072,get(w,1248))
        return reading(o,w,get(w,2064),400000,128,0,807)
    if p == 807:
        if get(w,400000) != @TRANSPORT@ or get(w,400008) != 1 or get(w,400016) == 0 or get(w,400016) > 4096 or get(w,400024) == 0 or get(w,400024) > 64 or get(w,400032) < 40 or get(w,400032) > 1048576 or get(w,400040) < 128 or get(w,400040) > 2097152 or get(w,400048) < 32 or get(w,400048) > 1048576 or get(w,400056) != get(w,2072) or get(w,400064) != get(w,2000) or zeros(w,400072,56) == 0:
            return finish(o,w,65)
        put(w,2080,get(w,400032))
        put(w,2088,get(w,400040))
        put(w,2104,get(w,400048))
        return hash_view(o,w,get(w,2064),1048576,get(w,2080),808)
    if p == 808:
        if same(w,4096,20000,32) == 0:
            return finish(o,w,65)
        return reading(o,w,get(w,2064),1048576,get(w,2080),1048576,809)
    if p == 809:
        if valid_authority(w) == 0 or get(w,2096) != get(w,400016):
            return finish(o,w,65)
        return hash_view(o,w,get(w,2064),2097152,get(w,2088),810)
    if p == 810:
        if same(w,4096,20032,32) == 0:
            return finish(o,w,65)
        return reading(o,w,get(w,2064),2097152,get(w,2088),2097152,811)
    if p == 811:
        if valid_recipe(w) == 0 or get(w,2136) != get(w,400024):
            return finish(o,w,65)
        return reading(o,w,get(w,2064),6291456,(get(w,2096)+8)*128,8192,812)
    if p == 812:
        if valid_transport(w) == 0:
            return finish(o,w,65)
        return reading(o,w,get(w,2064),4194304,get(w,2104),4194304,813)
    if p == 813:
        if valid_source_manifest(w) == 0:
            return finish(o,w,65)
        return hash_view(o,w,get(w,2064),4194304,get(w,2104),814)
    if p == 814:
        copyw(w,21000,4096,32)
        return start_extract(o,w,get(w,2064),4194304,get(w,2104),21000,815)
    if p == 815:
        put(w,2224,get(w,2442))
        put(w,2400,0)
        return resume(s,o,w,816)
    if p == 816:
        if get(w,2400) == 8:
            return call(o,w,818,257,get(w,2056),61100,720896,0,0,0,12)
        row = asset_row(get(w,2400))
        return start_extract(o,w,get(w,2064),get(w,row),get(w,row+8),row+16,817)
    if p == 817:
        put(w,16000+get(w,2400)*8,get(w,2442))
        put(w,2400,get(w,2400)+1)
        return resume(s,o,w,816)
    if p == 818:
        if r < 3:
            return finish(o,w,74)
        put(w,2184,r)
        return call(o,w,819,5,r,1200,0,0,0,0,12)
    if p == 819:
        if private_directory(w) == 0:
            return finish(o,w,65)
        return call(o,w,820,228,1,1400,0,0,0,0,12)
    if p == 820:
        start = get(w,1400)*1000000000+get(w,1408)
        put(w,2168,start)
        put(w,2176,start+180000000000)
        put(w,2128,0)
        put(w,2160,0)
        return resume(s,o,w,900)
    return finish(o,w,65)

def stage_name(w:mutbuf) -> u64:
    store(w,350100,115)
    n = decimal_text(w,350101,get(w,2128))
    store(w,350101+n,0)
    return n+1

def driver_frame(w:mutbuf) -> u64:
    fill_range(w,200000,128,0)
    put(w,200000,@DRIVER_REQUEST@)
    put(w,200008,get(w,2008))
    put(w,200016,get(w,2176))
    put(w,200024,get(w,2192))
    put(w,200032,get(w,2864))
    put(w,200040,get(w,2872))
    put(w,200048,get(w,2200))
    put(w,200056,get(w,2208))
    row = stage_row(w,get(w,2128))
    put(w,200064,get(w,row+24))
    plan = asset_row(get(w,row+8)+8)
    put(w,200072,get(w,plan+8))
    put(w,200080,get(w,2904))
    copyw(w,200088,plan+16,32)
    return 128+get(w,row+24)*192

def begin_binding(s:readbuf,o:mutbuf,w:mutbuf,b:u64,after:u64) -> u32:
    kind = get(w,b+8)
    index = get(w,b+16)
    if kind == 0 or kind == 1 or kind == 5:
        row = asset_row(choose(kind == 0,index,choose(kind == 5,7,index+8)))
        return start_extract(o,w,get(w,2064),get(w,row),get(w,row+8),row+16,after)
    if kind == 2:
        row = pub_state(index)
        return start_extract(o,w,get(w,row),0,get(w,row+8),row+16,after)
    if kind == 3:
        return start_extract(o,w,get(w,2224),0,get(w,2104),21000,after)
    if kind == 4:
        if get(w,2232) < 3:
            return finish(o,w,65)
        return start_extract(o,w,get(w,2232),0,get(w,2112),21032,after)
    return finish(o,w,65)

def run_stage(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 900:
        if get(w,2128) == get(w,2136):
            return resume(s,o,w,1400)
        return call(o,w,901,228,1,1400,0,0,0,0,12)
    if p == 901:
        if get(w,1400)*1000000000+get(w,1408) >= get(w,2176):
            return finish(o,w,124)
        stage_name(w)
        return call(o,w,902,258,get(w,2184),350100,448,0,0,0,12)
    if p == 902:
        return call(o,w,903,257,get(w,2184),350100,720896,0,0,0,12)
    if p == 903:
        if r < 3:
            return finish(o,w,74)
        put(w,2192,r)
        return call(o,w,904,5,r,1200,0,0,0,0,12)
    if p == 904:
        if private_directory(w) == 0:
            return finish(o,w,65)
        return call(o,w,905,257,get(w,2192),61448,655554,384,0,0,12)
    if p == 905:
        if r < 3:
            return finish(o,w,74)
        put(w,2208,r)
        row = stage_row(w,get(w,2128))
        plan = asset_row(get(w,row+8)+8)
        if get(w,plan+8) < 32:
            return finish(o,w,65)
        return start_extract(o,w,get(w,2064),get(w,plan),get(w,plan+8),plan+16,906)
    if p == 906:
        put(w,2200,get(w,2442))
        return reading(o,w,get(w,2200),380000,32,0,907)
    if p == 907:
        if get(w,380000) != @PLAN@ or get(w,380008) == 0 or get(w,380008) > 65536 or get(w,380016) != 0 or get(w,380024) != 0:
            return finish(o,w,65)
        put(w,2904,get(w,380008))
        put(w,2400,0)
        put(w,2864,0)
        put(w,2872,0)
        return resume(s,o,w,908)
    if p == 908:
        row = stage_row(w,get(w,2128))
        if get(w,2400) == get(w,row+24):
            if get(w,2864) < 3 or get(w,2872) < 3:
                return finish(o,w,65)
            n = driver_frame(w)
            return seal_request(o,w,200000,n,910)
        b = binding_row(w,get(w,row+16)+get(w,2400))
        return begin_binding(s,o,w,b,909)
    if p == 909:
        row = stage_row(w,get(w,2128))
        b = binding_row(w,get(w,row+16)+get(w,2400))
        target = 200128+get(w,2400)*192
        fill_range(w,target,192,0)
        put(w,target,get(w,2442))
        put(w,target+8,get(w,2466))
        put(w,target+16,get(w,b))
        copyw(w,target+32,4096,32)
        copyw(w,target+64,b+32,get(w,b))
        put(w,540000+get(w,2400)*8,get(w,2442))
        if get(w,b) == 4 and same(w,b+32,62400,4) != 0:
            if same(w,4096,20224,32) == 0:
                return finish(o,w,65)
            put(w,2864,get(w,2442))
        if get(w,b) == 4 and same(w,b+32,62416,4) != 0:
            if same(w,4096,20256,32) == 0:
                return finish(o,w,65)
            put(w,2872,get(w,2442))
        put(w,2400,get(w,2400)+1)
        return resume(s,o,w,908)
    if p == 910:
        put(w,2216,get(w,2368))
        n = get(w,stage_row(w,get(w,2128))+24)
        put(w,540000+n*8,get(w,2192))
        put(w,540008+n*8,get(w,2200))
        put(w,540016+n*8,get(w,2208))
        return launch(o,w,get(w,16032),get(w,2216),64,n+3,911)
    if p == 911:
        return reading(o,w,get(w,2712),380000,64,0,912)
    if p == 912:
        row = stage_row(w,get(w,2128))
        plan = asset_row(get(w,row+8)+8)
        if get(w,380000) != @DRIVER_OK@ or get(w,380008) != get(w,2904) or get(w,380016) != get(w,plan+8) or nonzero_pin(w,380032) == 0:
            return finish(o,w,74)
        return call(o,w,913,5,get(w,2208),1200,0,0,0,0,12)
    if p == 913:
        if getn(w,1224,4) & 61440 != 32768 or get(w,1216) != 1 or get(w,1248) != get(w,380024):
            return finish(o,w,74)
        return hash_view(o,w,get(w,2208),0,get(w,1248),914)
    if p == 914:
        if same(w,4096,380032,32) == 0:
            return finish(o,w,74)
        put(w,2400,0)
        return resume(s,o,w,1000)
    return finish(o,w,65)
'''

SOURCE+=r'''
def current_pub(w:mutbuf) -> u64:
    return get(w,stage_row(w,get(w,2128))+32)+get(w,2400)

def publication(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 1000:
        return call(o,w,1001,257,get(w,2192),61856,655554,384,0,0,12)
    if p == 1001:
        if r < 3:
            return finish(o,w,74)
        put(w,2920,r)
        return writing(o,w,r,380000,64,1002)
    if p == 1002:
        return call(o,w,1003,91,get(w,2920),256,0,0,0,0,0)
    if p == 1003:
        return call(o,w,1004,74,get(w,2920),0,0,0,0,0,0)
    if p == 1004:
        return call(o,w,1005,3,get(w,2920),0,0,0,0,0,0)
    if p == 1005:
        row = stage_row(w,get(w,2128))
        if get(w,2400) == get(w,row+40):
            return call(o,w,1040,91,get(w,2208),256,0,0,0,0,0)
        pub = publication_row(w,current_pub(w))
        return start_capture(s,o,w,pub+64,get(w,pub),get(w,2192),get(w,pub+32),get(w,pub+16),0,0,1006)
    if p == 1006:
        index = current_pub(w)
        row = pub_state(index)
        put(w,row,get(w,2320))
        put(w,row+8,get(w,2312))
        copyw(w,row+16,19000,32)
        put(w,row+48,1)
        pub = publication_row(w,index)
        if get(w,pub+24) == 0:
            return resume(s,o,w,1020)
        return start_install_path(s,o,w,pub+128,get(w,pub+8),1010)
    if p == 1010:
        return call(o,w,1011,257,get(w,2976),360000,655554,384,0,0,12)
    if p == 1011:
        if r < 3:
            return finish(o,w,74)
        put(w,2920,r)
        row = pub_state(current_pub(w))
        return copying(o,w,get(w,row),r,0,get(w,row+8),1012)
    if p == 1012:
        row = pub_state(current_pub(w))
        return hash_view(o,w,get(w,2920),0,get(w,row+8),1013)
    if p == 1013:
        if same(w,4096,pub_state(current_pub(w))+16,32) == 0:
            return finish(o,w,74)
        return call(o,w,1014,5,get(w,2920),1200,0,0,0,0,12)
    if p == 1014:
        row = pub_state(current_pub(w))
        if getn(w,1224,4) & 61440 != 32768 or get(w,1216) != 1 or getn(w,1228,4) != get(w,2000) or get(w,1248) != get(w,row+8):
            return finish(o,w,74)
        pub = publication_row(w,current_pub(w))
        return call(o,w,1015,91,get(w,2920),get(w,pub+16),0,0,0,0,0)
    if p == 1015:
        return call(o,w,1016,74,get(w,2920),0,0,0,0,0,0)
    if p == 1016:
        return call(o,w,1017,3,get(w,2920),0,0,0,0,0,0)
    if p == 1017:
        return call(o,w,1018,74,get(w,2976),0,0,0,0,0,0)
    if p == 1018:
        if get(w,2984) != 0:
            return call(o,w,1020,3,get(w,2976),0,0,0,0,0,0)
        return resume(s,o,w,1020)
    if p == 1020:
        pub = publication_row(w,current_pub(w))
        return call(o,w,1021,263,get(w,2192),pub+64,0,0,0,0,12)
    if p == 1021:
        put(w,2160,current_pub(w)+1)
        put(w,2400,get(w,2400)+1)
        return resume(s,o,w,1005)
    if p == 1040:
        return call(o,w,1041,74,get(w,2208),0,0,0,0,0,0)
    if p == 1041:
        return call(o,w,1042,74,get(w,2192),0,0,0,0,0,0)
    if p == 1042:
        return call(o,w,1043,91,get(w,2192),320,0,0,0,0,0)
    if p == 1043:
        put(w,2400,0)
        return resume(s,o,w,1044)
    if p == 1044:
        n = get(w,stage_row(w,get(w,2128))+24)+3
        if get(w,2400) == n:
            return call(o,w,1046,3,get(w,2216),0,0,0,0,0,0)
        return call(o,w,1045,3,get(w,540000+get(w,2400)*8),0,0,0,0,0,0)
    if p == 1045:
        put(w,2400,get(w,2400)+1)
        return resume(s,o,w,1044)
    if p == 1046:
        return call(o,w,1047,3,get(w,2712),0,0,0,0,0,0)
    if p == 1047:
        return call(o,w,1048,3,get(w,2720),0,0,0,0,0,0)
    if p == 1048:
        if get(w,2232) >= 3:
            return call(o,w,1049,3,get(w,2232),0,0,0,0,0,0)
        return resume(s,o,w,1049)
    if p == 1049:
        put(w,2232,0)
        put(w,2128,get(w,2128)+1)
        return resume(s,o,w,1100)
    return finish(o,w,65)

def start_install_path(s:readbuf,o:mutbuf,w:mutbuf,path:u64,n:u64,after:u64) -> u32:
    put(w,2952,path)
    put(w,2960,n)
    put(w,2968,0)
    put(w,2976,get(w,2056))
    put(w,2984,0)
    put(w,2992,after)
    return resume(s,o,w,1600)

def install_path(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r) and (p != 1601 or r != 18446744073709551599):
        return finish(o,w,74)
    if p == 1600:
        begin = get(w,2968)
        end = begin
        while end < get(w,2960) and byte(w,get(w,2952)+end) != 47:
            end = end+1
        if end == begin or end-begin > 255:
            return finish(o,w,65)
        copyw(w,360000,get(w,2952)+begin,end-begin)
        store(w,360000+end-begin,0)
        if end == get(w,2960):
            return resume(s,o,w,get(w,2992))
        put(w,3000,end+1)
        return call(o,w,1601,258,get(w,2976),360000,448,0,0,0,12)
    if p == 1601:
        return call(o,w,1602,257,get(w,2976),360000,720896,0,0,0,12)
    if p == 1602:
        if r < 3:
            return finish(o,w,74)
        put(w,3008,r)
        return call(o,w,1603,5,r,1200,0,0,0,0,12)
    if p == 1603:
        if private_directory(w) == 0:
            return finish(o,w,65)
        if get(w,2984) != 0:
            return call(o,w,1604,3,get(w,2976),0,0,0,0,0,0)
        return resume(s,o,w,1604)
    if p == 1604:
        put(w,2976,get(w,3008))
        put(w,2984,1)
        put(w,2968,get(w,3000))
        return resume(s,o,w,1600)
    return finish(o,w,65)

def installed_count(w:mutbuf,through:u64) -> u64:
    n = 0
    i = 0
    while i < through:
        if get(w,publication_row(w,i)+24) == 1:
            n = n+1
        i = i+1
    return n

def sort_installed(w:mutbuf,through:u64) -> u64:
    n = 0
    i = 0
    while i < through:
        row = publication_row(w,i)
        if get(w,row+24) == 1:
            j = n
            while j != 0 and pub_less(w,get(w,7144448+(j-1)*8),i) == 0:
                old_index = get(w,7144448+(j-1)*8)
                put(w,7144448+j*8,old_index)
                j = j-1
            put(w,7144448+j*8,i)
            n = n+1
        i = i+1
    return n

def pub_less(w:mutbuf,a:u64,b:u64) -> u64:
    first = publication_row(w,a)
    second = publication_row(w,b)
    return lexical(w,first+128,get(w,first+8),second+128,get(w,second+8))

def render_tool_manifest(w:mutbuf) -> u64:
    count = sort_installed(w,get(w,2160))
    if count == 0:
        return 0
    put(w,5242880,@MANIFEST@)
    put(w,5242888,count)
    put(w,5242896,1)
    put(w,5242904,0)
    at = 32
    i = 0
    while i < count:
        index = get(w,7144448+i*8)
        pub = publication_row(w,index)
        state = pub_state(index)
        n = get(w,pub+8)
        if get(w,state+48) != 1 or at > 1048576 or n+48 > 1048576-at:
            return 0
        put(w,5242880+at,n)
        put(w,5242888+at,get(w,state+8))
        copyw(w,5242896+at,state+16,32)
        copyw(w,5242928+at,pub+128,n)
        at = at+48+n
        i = i+1
    put(w,2112,at)
    return 1

def valid_tool_manifest(w:mutbuf) -> u64:
    count = sort_installed(w,get(w,2152))
    if get(w,5242880) != @MANIFEST@ or get(w,5242888) != count or get(w,5242896) != 1 or get(w,5242904) != 0:
        return 0
    at = 5242912
    end = 5242880+get(w,2112)
    i = 0
    while i < count:
        pub = publication_row(w,get(w,7144448+i*8))
        n = get(w,pub+8)
        if at > end or n+48 > end-at:
            return 0
        if get(w,at) != n or get(w,at+8) > get(w,pub+32) or nonzero_pin(w,at+16) == 0 or same(w,at+48,pub+128,n) == 0:
            return 0
        at = at+48+n
        i = i+1
    return choose(at == end,1,0)

def manifests(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 1100:
        if installed_count(w,get(w,2160)) == 0:
            put(w,2112,0)
            return resume(s,o,w,900)
        if render_tool_manifest(w) == 0:
            return finish(o,w,65)
        return seal_request(o,w,5242880,get(w,2112),1101)
    if p == 1101:
        put(w,2232,get(w,2368))
        return hash_view(o,w,get(w,2232),0,get(w,2112),1102)
    if p == 1102:
        copyw(w,21032,4096,32)
        return resume(s,o,w,900)
    return finish(o,w,65)
'''

SOURCE+=r'''
def start_manifest_publish(o:mutbuf,w:mutbuf,fd:u64,size:u64,name:u64,pin:u64,after:u64) -> u32:
    put(w,3032,fd)
    put(w,3040,size)
    put(w,3048,name)
    put(w,3056,after)
    put(w,3064,pin)
    return call(o,w,1440,257,get(w,2056),name,655554,384,0,0,12)

def build_receipt(w:mutbuf,inner:u64) -> u64:
    fill_range(w,390000,128,0)
    put(w,390000,choose(inner != 0,@INNER_OK@,@BUILD_OK@))
    put(w,390008,1)
    put(w,390016,get(w,2136))
    put(w,390024,get(w,2096))
    put(w,390032,installed_count(w,get(w,2152)))
    put(w,390040,get(w,2104))
    put(w,390048,get(w,2112))
    copyw(w,390064,21000,32)
    copyw(w,390096,21032,32)
    return 0

def emit_receipt(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if r == 18446744073709551612:
        return call(o,w,phase,1,1,390000+get(w,3024),128-get(w,3024),0,0,0,12)
    if failed(r) or r == 0 or r > 128-get(w,3024):
        return finish(o,w,74)
    put(w,3024,get(w,3024)+r)
    if get(w,3024) == 128:
        return finish(o,w,0)
    return call(o,w,phase,1,1,390000+get(w,3024),128-get(w,3024),0,0,0,12)

def inner_complete(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p == 1490:
        return emit_receipt(s,o,w,p,r)
    if failed(r):
        return finish(o,w,74)
    if p == 1400:
        if get(w,2160) != get(w,2152) or get(w,2232) < 3:
            return finish(o,w,65)
        return start_manifest_publish(o,w,get(w,2224),get(w,2104),61760,21000,1401)
    if p == 1401:
        return start_manifest_publish(o,w,get(w,2232),get(w,2112),61792,21032,1402)
    if p == 1402:
        return call(o,w,1403,74,get(w,2184),0,0,0,0,0,0)
    if p == 1403:
        return call(o,w,1404,91,get(w,2184),320,0,0,0,0,0)
    if p == 1404:
        return call(o,w,1405,74,get(w,2056),0,0,0,0,0,0)
    if p == 1405:
        build_receipt(w,1)
        put(w,3024,0)
        return call(o,w,1490,1,1,390000,128,0,0,0,12)
    if p == 1440:
        if r < 3:
            return finish(o,w,74)
        put(w,2920,r)
        return copying(o,w,get(w,3032),r,0,get(w,3040),1441)
    if p == 1441:
        return hash_view(o,w,get(w,2920),0,get(w,3040),1442)
    if p == 1442:
        if same(w,4096,get(w,3064),32) == 0:
            return finish(o,w,74)
        return call(o,w,1443,91,get(w,2920),256,0,0,0,0,0)
    if p == 1443:
        return call(o,w,1444,74,get(w,2920),0,0,0,0,0,0)
    if p == 1444:
        return call(o,w,1445,3,get(w,2920),0,0,0,0,0,0)
    if p == 1445:
        return resume(s,o,w,get(w,3056))
    return finish(o,w,65)

def outer_complete(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p == 1590:
        return emit_receipt(s,o,w,p,r)
    if failed(r):
        return finish(o,w,74)
    if p == 1500:
        build_receipt(w,0)
        return call(o,w,1501,257,get(w,2056),61472,655554,384,0,0,12)
    if p == 1501:
        if r < 3:
            return finish(o,w,74)
        put(w,2920,r)
        return writing(o,w,r,390000,128,1502)
    if p == 1502:
        return call(o,w,1503,74,get(w,2920),0,0,0,0,0,0)
    if p == 1503:
        return reading(o,w,get(w,2920),391000,128,0,1504)
    if p == 1504:
        if same(w,390000,391000,128) == 0:
            return finish(o,w,74)
        return call(o,w,1505,91,get(w,2920),256,0,0,0,0,0)
    if p == 1505:
        return call(o,w,1506,3,get(w,2920),0,0,0,0,0,0)
    if p == 1506:
        return call(o,w,1507,74,get(w,2056),0,0,0,0,0,0)
    if p == 1507:
        return call(o,w,1508,91,get(w,2248),256,0,0,0,0,0)
    if p == 1508:
        put(w,3024,0)
        return call(o,w,1590,1,1,390000,128,0,0,0,12)
    return finish(o,w,65)
'''

AUTHORITY_PATH=b'examples/hia_bootstrap/cold_build_sources.hiadat'
RECIPE_PATH=b'examples/hia_bootstrap/cold_build_recipe.hiadat'

def template():
    with tempfile.TemporaryDirectory(prefix='hia-cold-build-author-') as tmp:
        obj=Path(tmp)/'entry.o';raw=Path(tmp)/'entry.bin'
        subprocess.run(['as','--64',str(ROOT/'tools/hia_cold_build_entry_syscalls.S'),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={name:int(addr,16) for addr,_,name in (line.split() for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
        assert symbols['_start']==0 and 'R_X86_64' not in subprocess.check_output(['objdump','-r',str(obj)],text=True)
        code=raw.read_bytes()
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)+struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    return header+code,{name:176+symbols[name] for name in ('policy_hole','sha_hole','entry_pins')}

def packer():
    prefix,holes=template()
    text=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 314 or uint(s,0,8) != {int.from_bytes(b'HIAQBE01','little')}:
        return 4294967295
    policy = uint(s,8,8)
    sha = uint(s,16,8)
    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576 or length(s) != 312+policy+sha:
        return 4294967295
    i = 24
    while i < 312:
        if uint(s,i,8) | uint(s,i+8,8) | uint(s,i+16,8) | uint(s,i+24,8) == 0:
            return 4294967295
        i = i+32
    size = {len(prefix)}+policy+sha
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0,len(prefix),8):
        raw=prefix[at:at+8];text+=f'    write(o,{at},{int.from_bytes(raw,"little")},{len(raw)})\n'
    text+=f'''    write(o,96,size,8)
    write(o,104,size,8)
    write(o,{holes['policy_hole']},{len(prefix)-holes['policy_hole']-4},4)
    write(o,{holes['sha_hole']},{len(prefix)-holes['sha_hole']-4}+policy,4)
    copy_bytes(s,o,24,{holes['entry_pins']},288)
    copy_bytes(s,o,312,{len(prefix)},policy+sha)
    return size
'''
    return text+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]

def source():
    original=cli_source()
    nodes={n.name:ast.get_source_segment(original,n) for n in ast.parse(original).body if isinstance(n,ast.FunctionDef)}
    selected=('copy_input','open_path','paths','seal_request','sealing','launch','launching','child','argument')
    text=SOURCE+'\n\n'+'\n\n'.join(nodes[name] for name in selected)+'\n'+helpers()
    # All operands in these receipt guards are pure reads at fixed, already
    # bounded private-workspace addresses. Eager u64 predicates preserve their
    # result while avoiding a separate CFG diamond for every OR operand.
    parsed=ast.parse(text.replace('@',''))
    class ReceiptPredicates(ast.NodeTransformer):
        def __init__(self,minimum_terms):self.minimum_terms=minimum_terms
        def visit_BoolOp(self,node):
            node=self.generic_visit(node)
            if not isinstance(node.op,ast.Or) or len(node.values)<self.minimum_terms:return node
            terms=[ast.Call(func=ast.Name(id='choose',ctx=ast.Load()),args=[v,ast.Constant(1),ast.Constant(0)],keywords=[]) for v in node.values]
            value=terms[0]
            for term in terms[1:]:value=ast.BinOp(left=value,op=ast.BitOr(),right=term)
            return ast.Compare(left=value,ops=[ast.NotEq()],comparators=[ast.Constant(0)])
    # Parse the selected function only after replacing its magic token with a
    # valid placeholder name, then restore that token in the emitted author text.
    original_lines=text.splitlines()
    for guard in parsed.body:
        if not isinstance(guard,ast.FunctionDef) or guard.name not in ('valid_owner_receipt','inner_start','outer_owner'):continue
        original_guard='\n'.join(original_lines[guard.lineno-1:guard.end_lineno])
        # The two large transport/inner-receipt predicates also read only fixed
        # offsets; smaller guards retain their original short-circuit semantics.
        minimum_terms=2 if guard.name=='valid_owner_receipt' else 10
        compact=ast.unparse(ast.fix_missing_locations(ReceiptPredicates(minimum_terms).visit(guard)))
        for token in ('OWNER_OK','INNER_OK','TRANSPORT'):
            compact=compact.replace(token,'@'+token+'@')
        text=text.replace(original_guard,compact)
    values={'ARGV':b'HIAARG01','AUTHORITY':b'HIATBS01','RECIPE':b'HIATBR01','MANIFEST':b'HIASXM01','TRANSPORT':b'HIATBX01','DRIVER_REQUEST':b'HIAQDR01','DRIVER_OK':b'HIAQOK01','OWNER_REQUEST':b'HIACOW01','OWNER_OK':b'HIACOR01','BUILD_OK':b'HIATBOK1','INNER_OK':b'HIATBIK1','PLAN':b'HIAQPL01'}
    for key,value in values.items():text=text.replace('@'+key+'@',str(int.from_bytes(value,'little')))
    text=text.replace('@AUTHORITY_PATH_SIZE@',str(len(AUTHORITY_PATH))).replace('@RECIPE_PATH_SIZE@',str(len(RECIPE_PATH)))
    items=[(61000,b'hia-cold-build\0'),(61032,b'/\0'),(61040,b'\0'),(61100,b'build-evidence\0'),(61132,b'home\0'),(61148,b'tmp\0'),(61200,b'PATH=\0'),(61216,b'LANG=C\0'),(61232,b'LC_ALL=C\0'),(61248,b'TZ=UTC\0'),(61264,b'HOME=\0'),(61280,b'/home\0'),(61296,b'TMPDIR=\0'),(61312,b'/tmp\0'),(61328,b'process-owner.receipt\0'),(61360,b'.git\0'),(61376,b'__pycache__\0'),(61400,b'/proc/self/exe\0'),(61424,b'--internal\0'),(61448,b'evidence.hiaqj\0'),(61472,b'build.receipt\0'),(61504,AUTHORITY_PATH+b'\0'),(61632,RECIPE_PATH+b'\0'),(61760,b'source.manifest.hiasxm\0'),(61792,b'toolchain.manifest.hiasxm\0'),(62000,b'--source\0'),(62016,b'--bootstrap\0'),(62032,b'--output\0'),(62400,b'fast\0'),(62416,b'cold\0')]
    items.append((61856,b'driver.receipt\0'))
    roots=['hia-seed-assembly','hia-seed-projector','hia-seed-backend','hia-seed-filter-pack','hia-cold-qualification-driver','hia-independent-subprocess','hia-cold-process-owner']
    for i,name in enumerate(roots):items.append((62100+i*40,name.encode()+b'\0'))
    reserved=['build-evidence','home','tmp','source.manifest.hiasxm','toolchain.manifest.hiasxm','process-owner.receipt','build.receipt']
    for i,name in enumerate(reserved):items.append((62528+i*64,struct.pack('<Q',len(name))+name.encode()+b'\0'))
    stores=[]
    for at,value in items:
        for i in range(0,len(value),8):stores.append(f'    put(w,{at+i},{int.from_bytes(value[i:i+8],"little")})')
    count=(len(stores)+63)//64
    text+='\ndef constants(w:mutbuf) -> u64:\n'+''.join(f'    constants_{i}(w)\n' for i in range(count))+'    return 0\n'
    for i in range(count):text+=f'\ndef constants_{i}(w:mutbuf) -> u64:\n'+'\n'.join(stores[i*64:(i+1)*64])+'\n    return 0\n'
    return guarded_u64_read(accelerate(text,bulk=True))

if __name__=='__main__':
    for name,text in [('cold_build_entry',source()),('cold_build_entry_packer',packer())]:
        doc=bulk_document(text,name);raw=render_assembly(doc).encode();(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).write_bytes(raw)
        print(name,len(raw),len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),sha256(raw).hexdigest(),flush=True)
