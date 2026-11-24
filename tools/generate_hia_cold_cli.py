"""Native cold CLI: pinned descriptor, source-only custody, owned replay and v2 report."""
from pathlib import Path
from hashlib import sha256
import struct,subprocess,tempfile
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_allocator_witness import document
from tools.generate_hia_cold_master_common import helpers
from tools.generate_hia_native_filter import LINK_SOURCE
from tools.generate_hia_native_observer import reference_image
ROOT=Path(__file__).resolve().parents[1]
FAMILIES=('capacity','cfg','elf','chain','owned','bulk','loan','resource','tail','select','effects','multi','keyword','signed','scalar-casts','explicit-traps','cli','names','exports')
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
        return roles(s,o,w,p,r)
    if p < 400:
        return paths(s,o,w,p,r)
    if p < 450:
        return descriptor(s,o,w,p,r)
    if p < 500:
        return asset(s,o,w,p,r)
    if p < 600:
        return exporting(s,o,w,p,r)
    if p < 700:
        return bundle(s,o,w,p,r)
    if p < 800:
        return prepare_owner(s,o,w,p,r)
    if p < 900:
        return owner_result(s,o,w,p,r)
    if p < 1000:
        return generations(s,o,w,p,r)
    if p < 1200:
        return reporting(s,o,w,p,r)
    if p < 1300:
        return launching(s,o,w,p,r)
    return child(s,o,w,p,r)

def copy_input(s:readbuf,w:mutbuf,target:u64,source:u64,n:u64) -> u64:
    i = 0
    while i < n:
        store(w,target+i,byte(s,source+i))
        i = i+1
    return 0

def startup(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p == 0:
        constants(w)
        if uint(s,0,8) != @ARGV@ or uint(s,8,8) != 9 or arguments(s,w) == 0:
            return finish(o,w,64)
        return call(o,w,1,39,0,0,0,0,0,0,0)
    if failed(r):
        return finish(o,w,74)
    if p == 1:
        put(w,2008,r)
        return call(o,w,2,107,0,0,0,0,0,0,0)
    if p == 2:
        put(w,2000,r)
        return call(o,w,3,228,1,1400,0,0,0,0,12)
    if p == 3:
        put(w,2016,get(w,1400)*1000000000+get(w,1408))
        return open_path(s,o,w,200000,get(w,2400),18446744073709551516,0,4)
    if p == 4:
        put(w,2040,get(w,2592))
        return open_path(s,o,w,208192,get(w,2408),18446744073709551516,2,5)
    if p == 5:
        put(w,2048,get(w,2592))
        return open_path(s,o,w,216384,get(w,2416),18446744073709551516,0,6)
    if p == 6:
        put(w,2056,get(w,2592))
        return call(o,w,7,319,61000,3,0,0,0,0,3)
    if p == 7:
        if r < 3:
            return finish(o,w,74)
        put(w,2080,r)
        copy_input(s,w,24000,16,32)
        return load_asset(s,o,w,224576,get(w,2424),18446744073709551516,18446744073709551615,2097152,r,0,8)
    if p == 8:
        put(w,2072,get(w,2308))
        return call(o,w,9,72,get(w,2080),1033,15,0,0,0,0)
    if p == 9:
        return reading(o,w,get(w,2080),1048576,get(w,2072),0,400)
    return finish(o,w,65)

def arguments(s:readbuf,w:mutbuf) -> u64:
    at = 144
    i = 0
    while i < 9:
        if at > 65536-9:
            return 0
        n = uint(s,at,8)
        if n > 8191 or n == 0 or at+9+n > 65536 or byte(s,at+8+n) != 0:
            return 0
        if i != 0:
            if i & 1 != 0:
                expected = choose(i == 1,62000,choose(i == 3,62016,choose(i == 5,62032,62048)))
                size = choose(i == 5,11,8)
                if n != size or same_input(s,w,at+8,expected,size) == 0:
                    return 0
            else:
                index = i // 2-1
                if n < 2 or byte(s,at+8) != 47:
                    return 0
                copy_input(s,w,200000+index*8192,at+8,n+1)
                put(w,2400+index*8,n)
        at = at+9+n
        i = i+1
    return 1

def open_path(s:readbuf,o:mutbuf,w:mutbuf,path:u64,n:u64,base:u64,mode:u64,after:u64) -> u32:
    if n == 0 or n > 8191:
        return finish(o,w,65)
    put(w,2500,path)
    put(w,2508,n)
    put(w,2516,base)
    put(w,2524,mode)
    put(w,2532,after)
    put(w,2540,0)
    put(w,2548,base)
    put(w,2556,0)
    if byte(w,path) == 47:
        put(w,2540,1)
        return call(o,w,300,257,18446744073709551516,61032,720896,0,0,0,12)
    return resume(s,o,w,301)

def paths(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,65)
    if p == 300:
        if r < 3:
            return finish(o,w,74)
        put(w,2548,r)
        put(w,2556,1)
        return resume(s,o,w,301)
    if p == 301:
        start = get(w,2540)
        end = start
        while end < get(w,2508) and byte(w,get(w,2500)+end) != 47:
            c = byte(w,get(w,2500)+end)
            if c < 32 or c == 127:
                return finish(o,w,65)
            end = end+1
        n = end-start
        if n == 0 or n > 255 or (n == 1 and byte(w,get(w,2500)+start) == 46) or (n == 2 and byte(w,get(w,2500)+start) == 46 and byte(w,get(w,2500)+start+1) == 46):
            return finish(o,w,65)
        copyw(w,26000,get(w,2500)+start,n)
        store(w,26000+n,0)
        put(w,2564,end)
        if end == get(w,2508) and get(w,2524) == 2:
            return call(o,w,302,258,get(w,2548),26000,448,0,0,0,12)
        return resume(s,o,w,303)
    if p == 302:
        return resume(s,o,w,303)
    if p == 303:
        flags = 720896
        if get(w,2564) == get(w,2508) and get(w,2524) == 1:
            flags = 655360
        return call(o,w,304,257,get(w,2548),26000,flags,0,0,0,12)
    if p == 304:
        if r < 3:
            return finish(o,w,74)
        put(w,2572,r)
        if get(w,2556) != 0:
            return call(o,w,305,3,get(w,2548),0,0,0,0,0,0)
        return resume(s,o,w,305)
    if p == 305:
        put(w,2548,get(w,2572))
        put(w,2556,1)
        if get(w,2564) == get(w,2508):
            put(w,2592,get(w,2572))
            return resume(s,o,w,get(w,2532))
        put(w,2540,get(w,2564)+1)
        return resume(s,o,w,301)
    return finish(o,w,65)

def load_asset(s:readbuf,o:mutbuf,w:mutbuf,path:u64,n:u64,base:u64,expected:u64,maximum:u64,target:u64,offset:u64,after:u64) -> u32:
    put(w,2316,target)
    put(w,2324,expected)
    put(w,2332,offset)
    put(w,2340,after)
    put(w,2348,maximum)
    return open_path(s,o,w,path,n,base,1,450)

def asset(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 450:
        put(w,2300,get(w,2592))
        return call(o,w,451,5,get(w,2300),1200,0,0,0,0,12)
    if p == 451:
        size = get(w,1248)
        if getn(w,1224,4) & 61440 != 32768 or get(w,1216) != 1 or size > get(w,2348) or (get(w,2324) != 18446744073709551615 and size != get(w,2324)):
            return finish(o,w,65)
        put(w,2308,size)
        return call(o,w,452,8,get(w,2316),get(w,2332),0,0,0,0,0)
    if p == 452:
        if r != get(w,2332):
            return finish(o,w,74)
        return copying(o,w,get(w,2300),get(w,2316),0,get(w,2308),453)
    if p == 453:
        return hash_view(o,w,get(w,2316),get(w,2332),get(w,2308),454)
    if p == 454:
        if same(w,4096,24000,32) == 0:
            return finish(o,w,65)
        return call(o,w,455,3,get(w,2300),0,0,0,0,0,0)
    if p == 455:
        return resume(s,o,w,get(w,2340))
    return finish(o,w,65)
'''
SOURCE+=r'''
def desc(w:mutbuf,offset:u64) -> u64:
    return get(w,1048576+offset)

def droot(w:mutbuf,i:u64) -> u64:
    return 1048832+i*384

def dphase(w:mutbuf,i:u64) -> u64:
    return 1048832+desc(w,16)*384+i*384

def dbinding(w:mutbuf,i:u64) -> u64:
    return 1048832+(desc(w,16)+desc(w,24))*384+i*288

def path_valid(w:mutbuf,at:u64,n:u64,cap:u64,flat:u64) -> u64:
    if n == 0 or n >= cap or byte(w,at) == 47 or byte(w,at+n-1) == 47:
        return 0
    i = 0
    start = 0
    while i < cap:
        c = byte(w,at+i)
        if i >= n:
            if c != 0:
                return 0
        elif c == 47:
            if flat != 0 or i == start or (i-start == 1 and byte(w,at+start) == 46) or (i-start == 2 and byte(w,at+start) == 46 and byte(w,at+start+1) == 46):
                return 0
            start = i+1
        elif c < 32 or c > 126:
            return 0
        i = i+1
    if n-start == 1 and byte(w,at+start) == 46:
        return 0
    if n-start == 2 and byte(w,at+start) == 46 and byte(w,at+start+1) == 46:
        return 0
    return 1

def manifest_member(w:mutbuf,path:u64,n:u64,size:u64,pin:u64) -> u64:
    at = 1048576+desc(w,96)+32
    end = 1048576+get(w,2072)
    i = 0
    while i < desc(w,48):
        if at > end or end-at < 49:
            return 0
        count = get(w,at)
        if count == 0 or count > 4095 or count > end-at-48:
            return 0
        if count == n and same(w,at+48,path,n) != 0:
            return choose(get(w,at+8) == size and same(w,at+16,pin,32) != 0,1,0)
        at = at+48+count
        i = i+1
    return 0

def descriptor_valid(w:mutbuf) -> u64:
    if get(w,2072) < 256 or desc(w,0) != @DESCRIPTOR@ or desc(w,8) != 1 or desc(w,16) < 4 or desc(w,16) > 512 or desc(w,24) < 40 or desc(w,24) > 64 or desc(w,32) == 0 or desc(w,32) > 2048:
        return 0
    if desc(w,40) < 32 or desc(w,40) > 1048576 or desc(w,48) == 0 or desc(w,48) > 16384 or desc(w,56) == 0 or desc(w,56) > 95:
        return 0
    tables = 256+(desc(w,16)+desc(w,24))*384+desc(w,32)*288
    if desc(w,96) != tables or desc(w,104) != get(w,2072) or tables+desc(w,40) != get(w,2072) or desc(w,112) != 0 or desc(w,120) != 0:
        return 0
    i = 64
    while i < 96:
        if desc(w,i) >= desc(w,16):
            return 0
        j = 64
        while j < i:
            if desc(w,j) == desc(w,i):
                return 0
            j = j+8
        i = i+8
    i = 0
    while i < 96:
        c = byte(w,1048736+i)
        if i < desc(w,56):
            if c < 32 or c > 126:
                return 0
        elif c != 0:
            return 0
        i = i+1
    m = 1048576+tables
    if get(w,m) != @MANIFEST@ or get(w,m+8) != desc(w,48) or get(w,m+16) != 1 or get(w,m+24) != 0:
        return 0
    i = 0
    while i < desc(w,16):
        row = droot(w,i)
        if get(w,row) > 67108864 or get(w,row+24) > 1 or path_valid(w,row+64,get(w,row+8),128,1) == 0 or path_valid(w,row+192,get(w,row+16),192,0) == 0:
            return 0
        if get(w,row+24) == 1 and manifest_member(w,row+192,get(w,row+16),get(w,row),row+32) == 0:
            return 0
        i = i+1
    i = 0
    while i < desc(w,24):
        row = dphase(w,i)
        if get(w,row+88) != 0 or path_valid(w,row+256,get(w,row+176),128,0) == 0 or manifest_member(w,row+256,get(w,row+176),get(w,row+96),row+112) == 0:
            return 0
        j = 184
        while j < 256:
            if get(w,row+j) != 0:
                return 0
            j = j+8
        i = i+1
    return 1

def descriptor(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 400:
        if descriptor_valid(w) == 0:
            return finish(o,w,65)
        if same_input(s,w,80,droot(w,desc(w,88))+32,32) == 0:
            return finish(o,w,65)
        put(w,2360,0)
        return resume(s,o,w,100)
    if p == 401:
        if r < 3:
            return finish(o,w,74)
        put(w,2136,r)
        return writing(o,w,r,1048576+desc(w,96),desc(w,40),402)
    if p == 402:
        return call(o,w,403,72,get(w,2136),1033,15,0,0,0,0)
    if p == 403:
        return resume(s,o,w,500)
    return finish(o,w,65)

def roles(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 100:
        if get(w,2360) == 3:
            return call(o,w,401,319,61000,3,0,0,0,0,3)
        return call(o,w,101,319,61000,3,0,0,0,0,3)
    if p == 101:
        if r < 3:
            return finish(o,w,74)
        put(w,2096+get(w,2360)*8,r)
        copy_input(s,w,24000,48+get(w,2360)*32,32)
        return load_asset(s,o,w,62100+get(w,2360)*64,choose(get(w,2360) == 0,15,22),get(w,2056),18446744073709551615,67108864,r,0,102)
    if p == 102:
        if get(w,2308) < 64:
            return finish(o,w,65)
        return reading(o,w,get(w,2096+get(w,2360)*8),63000,64,0,103)
    if p == 103:
        if getn(w,63000,4) != 1179403647 or byte(w,63004) != 2 or byte(w,63005) != 1 or getn(w,63016,2) != 2 or getn(w,63018,2) != 62:
            return finish(o,w,65)
        return call(o,w,104,91,get(w,2096+get(w,2360)*8),320,0,0,0,0,0)
    if p == 104:
        return call(o,w,105,72,get(w,2096+get(w,2360)*8),1033,15,0,0,0,0)
    if p == 105:
        put(w,2360,get(w,2360)+1)
        return resume(s,o,w,100)
    return finish(o,w,65)

def seal_request(o:mutbuf,w:mutbuf,buffer:u64,size:u64,after:u64) -> u32:
    if size == 0 or size > 1048576 or buffer > 8388608-size:
        return finish(o,w,65)
    put(w,2376,buffer)
    put(w,2384,size)
    put(w,2392,after)
    return call(o,w,480,319,61000,3,0,0,0,0,3)

def sealing(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 480:
        if r < 3:
            return finish(o,w,74)
        put(w,2370,r)
        return writing(o,w,r,get(w,2376),get(w,2384),481)
    if p == 481:
        return call(o,w,482,72,get(w,2370),1033,15,0,0,0,0)
    if p == 482:
        return resume(s,o,w,get(w,2392))
    return finish(o,w,65)

def launch(o:mutbuf,w:mutbuf,image:u64,request:u64,out_size:u64,keep:u64,after:u64) -> u32:
    put(w,2688,image)
    put(w,2696,request)
    put(w,2704,out_size)
    put(w,2736,after)
    put(w,2744,keep)
    return call(o,w,1200,319,61000,3,0,0,0,0,3)

def launching(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p == 1204 and r == 18446744073709551612:
        return call(o,w,1204,61,get(w,2728),1440,0,0,0,0,12)
    if failed(r):
        return finish(o,w,74)
    if p == 1200:
        if r < 3:
            return finish(o,w,74)
        put(w,2712,r)
        return call(o,w,1201,319,61000,3,0,0,0,0,3)
    if p == 1201:
        if r < 3:
            return finish(o,w,74)
        put(w,2720,r)
        return call(o,w,1202,57,0,0,0,0,0,0,0)
    if p == 1202:
        if r == 0:
            return resume(s,o,w,1300)
        put(w,2728,r)
        return call(o,w,1204,61,r,1440,0,0,0,0,12)
    if p == 1204:
        if r != get(w,2728) or getn(w,1440,4) != 0:
            return finish(o,w,1)
        return call(o,w,1205,5,get(w,2720),1200,0,0,0,0,12)
    if p == 1205:
        if get(w,1248) != 0:
            return finish(o,w,74)
        return call(o,w,1206,5,get(w,2712),1200,0,0,0,0,12)
    if p == 1206:
        if get(w,1248) != get(w,2704):
            return finish(o,w,74)
        return call(o,w,1207,72,get(w,2712),1033,15,0,0,0,0)
    if p == 1207:
        return resume(s,o,w,get(w,2736))
    return finish(o,w,65)

def child(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,127)
    if p == 1300:
        return call(o,w,1301,157,1,15,0,0,0,0,0)
    if p == 1301:
        return call(o,w,1302,110,0,0,0,0,0,0,0)
    if p == 1302:
        if r != get(w,2008):
            return finish(o,w,127)
        return call(o,w,1303,436,3,4294967295,4,0,0,0,0)
    if p == 1303:
        return call(o,w,1304,33,get(w,2696),0,0,0,0,0,0)
    if p == 1304:
        return call(o,w,1305,33,get(w,2712),1,0,0,0,0,0)
    if p == 1305:
        return call(o,w,1306,33,get(w,2720),2,0,0,0,0,0)
    if p == 1306:
        put(w,2752,0)
        return resume(s,o,w,1307)
    if p == 1307:
        if get(w,2752) == get(w,2744):
            put(w,60000,61000)
            put(w,60008,18446744073709551615)
            put(w,60016,18446744073709551615)
            put(w,0,1309)
            put(o,0,60000)
            put(o,8,3)
            put(o,16,60200)
            return 2
        return call(o,w,1308,72,get(w,540000+get(w,2752)*8),2,0,0,0,0,0)
    if p == 1308:
        put(w,2752,get(w,2752)+1)
        return resume(s,o,w,1307)
    if p == 1309:
        return call(o,w,1310,322,get(w,2688),61040,60200,60216,4096,0,252)
    return finish(o,w,127)
'''
SOURCE+=r'''
def export_request(w:mutbuf,mode:u64) -> u64:
    fill_range(w,500000,128,0)
    put(w,500000,@EXPORT_REQUEST@)
    put(w,500008,mode)
    put(w,500016,get(w,2040))
    put(w,500024,get(w,2048))
    put(w,500032,get(w,2136))
    put(w,500040,desc(w,40))
    put(w,500048,desc(w,48))
    copyw(w,500064,1048704,32)
    return 0

def export_receipt(w:mutbuf,at:u64,mode:u64) -> u64:
    if get(w,at) != @EXPORT_OK@ or get(w,at+8) != mode or get(w,at+16) != desc(w,48) or same(w,at+32,1048704,32) == 0:
        return 0
    if get(w,at+64) != 1 or get(w,at+72) != 1 or get(w,at+80) != 1 or get(w,at+88) != 1 or get(w,at+96) != 16384 or get(w,at+104) != 4095 or get(w,at+112) != 256 or get(w,at+120) != 67108864:
        return 0
    return 1

def exporting(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 500 or p == 550:
        export_request(w,choose(p == 500,0,1))
        return seal_request(o,w,500000,128,p+1)
    if p == 501 or p == 551:
        put(w,540000,get(w,2040))
        put(w,540008,get(w,2048))
        put(w,540016,get(w,2136))
        return launch(o,w,get(w,2112),get(w,2368),128,3,p+1)
    if p == 502:
        put(w,2160,get(w,2712))
        return reading(o,w,get(w,2712),550000,128,0,503)
    if p == 503:
        if export_receipt(w,550000,0) == 0:
            return finish(o,w,74)
        return call(o,w,504,228,1,1400,0,0,0,0,12)
    if p == 504:
        put(w,2024,get(w,1400)*1000000000+get(w,1408))
        put(w,2032,get(w,2024)+180000000000)
        return open_path(s,o,w,61100,6,get(w,2048),0,505)
    if p == 505:
        put(w,2168,get(w,2592))
        return open_path(s,o,w,61116,13,get(w,2048),2,506)
    if p == 506:
        put(w,2176,get(w,2592))
        return call(o,w,507,72,get(w,2176),1030,3,0,0,0,0)
    if p == 507:
        if r < 3:
            return finish(o,w,74)
        put(w,2800,r)
        return call(o,w,508,319,61000,3,0,0,0,0,3)
    if p == 508:
        if r < 3:
            return finish(o,w,74)
        put(w,2120,r)
        put(w,2128,0)
        put(w,2808,0)
        put(w,2816,0)
        runtime_header(w)
        return resume(s,o,w,600)
    if p == 552:
        put(w,2240,get(w,2712))
        return reading(o,w,get(w,2712),550128,128,0,553)
    if p == 553:
        if export_receipt(w,550128,1) == 0:
            return finish(o,w,74)
        return resume(s,o,w,900)
    return finish(o,w,65)

def runtime_header(w:mutbuf) -> u64:
    size = 128+desc(w,16)*192+desc(w,24)*256+desc(w,32)*288
    fill_range(w,4194304,size,0)
    put(w,2824,size)
    put(w,4194304,@MASTER_REQUEST@)
    put(w,4194320,get(w,2032))
    put(w,4194328,get(w,2800))
    put(w,4194336,desc(w,16))
    put(w,4194344,desc(w,24))
    put(w,4194352,desc(w,32))
    put(w,4194360,desc(w,64))
    put(w,4194368,desc(w,72))
    put(w,4194376,desc(w,80))
    put(w,4194384,desc(w,88))
    put(w,4194392,get(w,2024))
    put(w,4194400,1)
    copyw(w,4194432+desc(w,16)*192+desc(w,24)*256,dbinding(w,0),desc(w,32)*288)
    return 0

def bundle(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 600 or p == 630:
        put(w,2832,p)
        return call(o,w,625,228,1,1400,0,0,0,0,12)
    if p == 625:
        if get(w,1400)*1000000000+get(w,1408) >= get(w,2032):
            return finish(o,w,124)
        return resume(s,o,w,get(w,2832)+1)
    if p == 601:
        if get(w,2808) == desc(w,16):
            return resume(s,o,w,630)
        row = droot(w,get(w,2808))
        size = get(w,row)
        if get(w,2128) > 2147483648 or size > 2147483648-get(w,2128):
            return finish(o,w,65)
        out = 4194432+get(w,2808)*192
        put(w,out,get(w,2120))
        put(w,out+8,size)
        put(w,out+16,get(w,row+8))
        put(w,out+24,get(w,2128))
        copyw(w,out+32,row+32,160)
        copyw(w,24000,row+32,32)
        directory = choose(get(w,row+24) == 0,get(w,2056),get(w,2168))
        return load_asset(s,o,w,row+192,get(w,row+16),directory,size,67108864,get(w,2120),get(w,2128),602)
    if p == 602:
        put(w,2128,get(w,2128)+get(w,2308))
        put(w,2808,get(w,2808)+1)
        return resume(s,o,w,600)
    if p == 631:
        if get(w,2816) == desc(w,24):
            return call(o,w,640,72,get(w,2120),1033,15,0,0,0,0)
        row = dphase(w,get(w,2816))
        size = get(w,row+96)
        if get(w,2128) > 2147483648 or size > 2147483648-get(w,2128):
            return finish(o,w,65)
        out = 4194432+desc(w,16)*192+get(w,2816)*256
        copyw(w,out,row,256)
        put(w,out+88,get(w,2120))
        put(w,out+176,get(w,2128))
        copyw(w,24000,row+112,32)
        return load_asset(s,o,w,row+256,get(w,row+176),get(w,2168),size,67108864,get(w,2120),get(w,2128),632)
    if p == 632:
        put(w,2128,get(w,2128)+get(w,2308))
        put(w,2816,get(w,2816)+1)
        return resume(s,o,w,630)
    if p == 640:
        return seal_request(o,w,4194304,get(w,2824),641)
    if p == 641:
        put(w,2184,get(w,2368))
        return resume(s,o,w,700)
    return finish(o,w,65)

def argument(w:mutbuf,at:u64,source:u64,n:u64) -> u64:
    put(w,at,n)
    copyw(w,at+8,source,n)
    store(w,at+8+n,0)
    return at+9+n

def owner_request(w:mutbuf) -> u64:
    fill_range(w,800000,128,0)
    put(w,800000,@OWNER_REQUEST@)
    put(w,800008,get(w,2008))
    put(w,800016,get(w,2024))
    put(w,800024,get(w,2032))
    put(w,800032,180)
    put(w,800040,get(w,2096))
    put(w,800048,get(w,2184))
    put(w,800056,get(w,2192))
    put(w,800064,get(w,2200))
    put(w,800072,get(w,2208))
    put(w,800080,get(w,2176))
    put(w,800088,1)
    put(w,800096,6)
    put(w,800104,2)
    at = argument(w,800128,62100,15)
    at = argument(w,at,61200,5)
    at = argument(w,at,61216,6)
    at = argument(w,at,61232,8)
    at = argument(w,at,61248,6)
    copyw(w,26000,61264,5)
    copyw(w,26005,208192,get(w,2408))
    copyw(w,26005+get(w,2408),61280,5)
    at = argument(w,at,26000,10+get(w,2408))
    copyw(w,26000,61296,7)
    copyw(w,26007,208192,get(w,2408))
    copyw(w,26007+get(w,2408),61312,4)
    at = argument(w,at,26000,11+get(w,2408))
    put(w,at,get(w,2120))
    put(w,at+8,get(w,2800))
    return at+16-800000

def prepare_owner(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 700:
        return call(o,w,701,319,61000,3,0,0,0,0,3)
    if p == 701:
        if r < 3:
            return finish(o,w,74)
        put(w,2192,r)
        return call(o,w,702,91,r,384,0,0,0,0,0)
    if p == 702:
        return call(o,w,703,319,61000,3,0,0,0,0,3)
    if p == 703:
        if r < 3:
            return finish(o,w,74)
        put(w,2200,r)
        return call(o,w,704,91,r,384,0,0,0,0,0)
    if p == 704:
        return call(o,w,705,257,get(w,2048),61328,655554,384,0,0,12)
    if p == 705:
        if r < 3:
            return finish(o,w,74)
        put(w,2208,r)
        n = owner_request(w)
        return seal_request(o,w,800000,n,706)
    if p == 706:
        put(w,2216,get(w,2368))
        i = 0
        while i < 6:
            put(w,540000+i*8,get(w,800040+i*8))
            i = i+1
        put(w,540048,get(w,2120))
        put(w,540056,get(w,2800))
        return launch(o,w,get(w,2104),get(w,2216),0,8,800)
    return finish(o,w,65)
'''
SOURCE+=r'''
def owner_header(w:mutbuf) -> u64:
    at = 5020000
    if get(w,at) != @OWNER_OK@ or get(w,at+8) != 0 or get(w,at+16) != get(w,2224) or get(w,at+24) != get(w,2008) or get(w,at+32) != get(w,2024) or get(w,at+40) != get(w,2032) or get(w,at+48) != 180 or get(w,at+56) != 3000000000:
        return 0
    if get(w,at+64) < 2 or get(w,at+72) != 0 or get(w,at+80) != 0 or get(w,at+88) != 1 or get(w,at+96) != 1 or get(w,at+104) != 1 or get(w,at+112) != 0 or get(w,at+120) != 0 or get(w,at+136) != 0 or get(w,at+168) != 0 or get(w,at+176) != 1 or get(w,at+192) != 0:
        return 0
    if get(w,at+128) > 16384 or get(w,at+144) > 4096 or get(w,at+200) != 4096 or get(w,at+208) != 16384 or get(w,at+216) != 65536 or get(w,at+224) != 1 or get(w,at+232) != 0 or get(w,at+240) != 0 or get(w,at+248) != 0:
        return 0
    if get(w,at+152) < get(w,2024) or get(w,at+152) > get(w,2032) or get(w,at+160) != get(w,at+152)+3000000000 or get(w,at+184) < get(w,at+152) or get(w,at+184) > get(w,at+160):
        return 0
    return choose(get(w,2840) == 256+get(w,at+128)*40+get(w,at+144)*48,1,0)

def master_header(w:mutbuf) -> u64:
    at = 5000000
    if get(w,at) != @MASTER_OK@ or get(w,at+8) != desc(w,24) or get(w,at+16) != get(w,2024) or get(w,at+24) < get(w,2024) or get(w,at+24) > get(w,5020152):
        return 0
    if get(w,at+32) == 0 or get(w,at+32) > 2 or get(w,at+40) != 1 or get(w,at+48) == 0 or get(w,at+48) > 2 or get(w,at+56) == 0 or get(w,at+56) > 4:
        return 0
    if get(w,at+64) >= desc(w,24) or get(w,at+72) != desc(w,16) or get(w,at+80) != desc(w,32) or get(w,at+88) != get(w,5020064) or get(w,at+96) != get(w,2224) or get(w,at+104) != 0 or get(w,at+112) != 0 or get(w,at+120) != 0:
        return 0
    base = 5000128+get(w,at+64)*192
    i = 0
    while i < desc(w,24):
        row = 5000128+i*192
        meta = dphase(w,i)
        if get(w,row) != i or get(w,row+8) != get(w,meta+64) or get(w,row+16) != get(w,meta+72) or get(w,row+24) != get(w,meta+80) or get(w,row+32) != get(w,meta+104) or get(w,row+40) != get(w,meta+96) or same(w,row+96,meta+112,32) == 0:
            return 0
        if get(w,row+48) < get(w,2024) or get(w,row+56) < get(w,row+48) or get(w,row+64) < get(w,row+56) or get(w,row+64) > get(w,at+24) or get(w,row+72) < 240 or get(w,row+80) == 0 or get(w,row+80) > 4096 or get(w,row+88) != 0:
            return 0
        if get(w,row+8) == 1 and get(w,row+64) > get(w,base+48):
            return 0
        if get(w,row+8) == 3 and get(w,row+48) < get(w,base+64):
            return 0
        i = i+1
    return choose(get(w,dphase(w,get(w,at+64))+64) == 2,1,0)

def owner_result(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 800:
        put(w,2224,get(w,2728))
        return call(o,w,801,5,get(w,2208),1200,0,0,0,0,12)
    if p == 801:
        if get(w,1248) < 256 or get(w,1248) > 1048576:
            return finish(o,w,74)
        put(w,2840,get(w,1248))
        return reading(o,w,get(w,2208),5020000,256,0,802)
    if p == 802:
        if owner_header(w) == 0:
            return finish(o,w,74)
        return call(o,w,803,5,get(w,2200),1200,0,0,0,0,12)
    if p == 803:
        if get(w,1248) != 0:
            return finish(o,w,74)
        return call(o,w,804,5,get(w,2192),1200,0,0,0,0,12)
    if p == 804:
        if get(w,1248) != 128+desc(w,24)*192:
            return finish(o,w,74)
        put(w,2232,get(w,1248))
        return call(o,w,805,72,get(w,2192),1033,15,0,0,0,0)
    if p == 805:
        return reading(o,w,get(w,2192),5000000,get(w,2232),0,806)
    if p == 806:
        if master_header(w) == 0:
            return finish(o,w,74)
        return call(o,w,807,91,get(w,2208),256,0,0,0,0,0)
    if p == 807:
        return resume(s,o,w,550)
    return finish(o,w,65)

def generation_name(w:mutbuf,at:u64,n:u64) -> u64:
    i = 0
    while i < 8:
        size = choose(i == 7,19,7)
        if n == size and same(w,at,64000+i*32,size) != 0:
            return i
        i = i+1
    return 18446744073709551615

def generations(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 900:
        base = get(w,5000064)
        meta = dphase(w,base)
        n = get(w,meta+168)
        copyw(w,26000,meta,n)
        copyw(w,26000+n,61140,8)
        return open_path(s,o,w,26000,n+7,get(w,2176),1,901)
    if p == 901:
        put(w,2856,get(w,2592))
        return call(o,w,902,5,get(w,2856),1200,0,0,0,0,12)
    if p == 902:
        row = 5000128+get(w,5000064)*192
        if getn(w,1224,4) & 65535 != 33024 or getn(w,1228,4) != get(w,2000) or get(w,1216) != 1 or get(w,1248) != get(w,row+72):
            return finish(o,w,74)
        put(w,2864,get(w,1248))
        return hash_view(o,w,get(w,2856),0,get(w,2864),903)
    if p == 903:
        row = 5000128+get(w,5000064)*192
        if same(w,4096,row+160,32) == 0:
            return finish(o,w,74)
        return reading(o,w,get(w,2856),63000,64,0,904)
    if p == 904:
        row = 5000128+get(w,5000064)*192
        if get(w,63000) != @ARCHIVE@ or get(w,63008) != get(w,row+80) or get(w,63016) != get(w,row+32) or get(w,63024) != get(w,row+40) or same(w,63032,row+96,32) == 0:
            return finish(o,w,74)
        put(w,2872,64)
        put(w,2880,0)
        put(w,2888,0)
        return resume(s,o,w,905)
    if p == 905:
        row = 5000128+get(w,5000064)*192
        if get(w,2880) == get(w,row+80):
            if get(w,2872) != get(w,2864) or get(w,2888) != 255:
                return finish(o,w,74)
            return resume(s,o,w,920)
        if get(w,2872) > get(w,2864) or get(w,2864)-get(w,2872) < 176:
            return finish(o,w,74)
        return reading(o,w,get(w,2856),63000,176,get(w,2872),906)
    if p == 906:
        n = get(w,63000)
        size = get(w,63008)
        if n == 0 or n > 127 or size > get(w,2864)-get(w,2872)-176:
            return finish(o,w,74)
        put(w,2896,size)
        found = generation_name(w,63048,n)
        put(w,2904,found)
        if found == 18446744073709551615:
            return resume(s,o,w,910)
        if get(w,2888) & (1 << found) != 0 or size == 0 or size > 67108864 or (found == 7 and size != 1107):
            return finish(o,w,74)
        copyw(w,2912,63016,32)
        return hash_view(o,w,get(w,2856),get(w,2872)+176,size,907)
    if p == 907:
        if same(w,4096,2912,32) == 0:
            return finish(o,w,74)
        if get(w,2904) == 7:
            return reading(o,w,get(w,2856),5050000,1107,get(w,2872)+176,908)
        copyw(w,5040000+get(w,2904)*32,4096,32)
        return resume(s,o,w,909)
    if p == 908:
        if same(w,5050000,700000,1107) == 0:
            return finish(o,w,74)
        return resume(s,o,w,909)
    if p == 909:
        put(w,2888,get(w,2888) | (1 << get(w,2904)))
        return resume(s,o,w,910)
    if p == 910:
        put(w,2872,get(w,2872)+176+get(w,2896))
        put(w,2880,get(w,2880)+1)
        return resume(s,o,w,905)
    if p == 920:
        if same(w,5040032,5040064,32) == 0 or same(w,5040064,5040096,32) == 0 or same(w,5040128,5040160,32) != 0 or same(w,5040160,5040192,32) == 0 or same(w,5040096,5040192,32) != 0:
            return finish(o,w,74)
        return call(o,w,921,3,get(w,2856),0,0,0,0,0,0)
    if p == 921:
        return resume(s,o,w,1000)
    return finish(o,w,65)
'''
CHECKS=('export_manifest_matches_qualification','native_hia_toolchain_only','nested_full_qualification_pass','nested_process_exit_zero','no_ancestor_git_identity','no_bytecode_cache_created','fresh_home_and_tmp','no_inherited_target_or_successor_images','origin_hashes_preserved','owned_process_tree_cleanup_confirmed','source_export_hashes_preserved','all_independent_references_before_B0','lossless_phase_archives_verified','all_19_families_both_compilers')
LITERALS=[
'{"schema":"hepta.hia.selfhost-cold-replay.v2","status":"NATIVE_COLD_SELFHOST_REPLAY_PASS","profile":',
',"returncode":0,"source_manifest":{',',',':','},"generation_sha256":[','],"modified_generation_sha256":[','],"seed_sha256":',',"native_flat_observer_hex":',
',"qualification_wall_limit_seconds":180,"cleanup_wall_limit_seconds":3,"nested_wall_elapsed_ns":',',"cleanup_wall_elapsed_ns":',',"wall_elapsed_ns":',
',"checks":{'+','.join('"'+x+'":true' for x in CHECKS)+'}',
',"scheduler":{"phase_workers":2,"archive_workers":1,"max_pending_archives":2,"max_unsealed_phases":4,"peak_phase_workers":',',"peak_archive_workers":',',"peak_pending_archives":',',"peak_unsealed_phases":',
'},"qualification_families":{',':{"original":true,"modified":true}','},"phases":[','{"id":',',"kind":','"reference"','"base"','"qualification"',',"family":',',"label":','"original"','"modified"','""',',"plan_sha256":',',"journal_sha256":',',"archive_sha256":',',"node_count":',',"nodes_retained":',',"returncode":0,"cleanup_complete":true,"sealed":true}',']}\n']
SOURCE+=r'''
def jbyte(w:mutbuf,value:u64) -> u64:
    if get(w,2264) >= 2097152:
        put(w,2272,1)
        return 0
    store(w,5500000+get(w,2264),value)
    put(w,2264,get(w,2264)+1)
    return 0

def jraw(w:mutbuf,at:u64,n:u64) -> u64:
    if n > 2097152-get(w,2264):
        put(w,2272,1)
        return 0
    copyw(w,5500000+get(w,2264),at,n)
    put(w,2264,get(w,2264)+n)
    return 0

def hex_digit(n:u64) -> u64:
    return choose(n < 10,n+48,n+87)

def jstring(w:mutbuf,at:u64,n:u64) -> u64:
    jbyte(w,34)
    i = 0
    while i < n:
        c = byte(w,at+i)
        if c == 34 or c == 92:
            jbyte(w,92)
            jbyte(w,c)
        elif c < 32:
            jbyte(w,92)
            jbyte(w,117)
            jbyte(w,48)
            jbyte(w,48)
            jbyte(w,hex_digit(c >> 4))
            jbyte(w,hex_digit(c & 15))
        else:
            jbyte(w,c)
        i = i+1
    jbyte(w,34)
    return 0

def jhex(w:mutbuf,at:u64,n:u64) -> u64:
    jbyte(w,34)
    i = 0
    while i < n:
        c = byte(w,at+i)
        jbyte(w,hex_digit(c >> 4))
        jbyte(w,hex_digit(c & 15))
        i = i+1
    jbyte(w,34)
    return 0

def jnumber(w:mutbuf,n:u64) -> u64:
    if n == 0:
        jbyte(w,48)
        return 0
    count = 0
    while n != 0:
        store(w,30000+count,n % 10+48)
        n = n // 10
        count = count+1
    while count != 0:
        count = count-1
        jbyte(w,byte(w,30000+count))
    return 0

def json_manifest(w:mutbuf) -> u64:
    at = 1048576+desc(w,96)+32
    i = 0
    while i < desc(w,48):
        n = get(w,at)
        if i != 0:
            literal(w,2)
        jstring(w,at+48,n)
        literal(w,3)
        jhex(w,at+16,32)
        at = at+48+n
        i = i+1
    return 0

def json_generations(w:mutbuf) -> u64:
    literal(w,4)
    i = 1
    while i < 4:
        if i != 1:
            literal(w,2)
        jhex(w,5040000+i*32,32)
        i = i+1
    literal(w,5)
    i = 4
    while i < 7:
        if i != 4:
            literal(w,2)
        jhex(w,5040000+i*32,32)
        i = i+1
    literal(w,6)
    jhex(w,5040000,32)
    literal(w,7)
    jhex(w,5050000,1107)
    return 0

def json_scheduler(w:mutbuf) -> u64:
    literal(w,8)
    jnumber(w,get(w,5020152)-get(w,2024))
    literal(w,9)
    jnumber(w,get(w,5020184)-get(w,5020152))
    literal(w,10)
    jnumber(w,get(w,3048)-get(w,2016))
    literal(w,11)
    literal(w,12)
    jnumber(w,get(w,5000032))
    literal(w,13)
    jnumber(w,get(w,5000040))
    literal(w,14)
    jnumber(w,get(w,5000048))
    literal(w,15)
    jnumber(w,get(w,5000056))
    literal(w,16)
    i = 0
    while i < 19:
        if i != 0:
            literal(w,2)
        jstring(w,720000+i*32,family_length(i))
        literal(w,17)
        i = i+1
    return 0

def json_phase(w:mutbuf,i:u64) -> u64:
    meta = dphase(w,i)
    row = 5000128+i*192
    if i != 0:
        literal(w,2)
    literal(w,19)
    jstring(w,meta,get(w,meta+168))
    literal(w,20)
    literal(w,20+get(w,meta+64))
    literal(w,24)
    if get(w,meta+64) == 3:
        family = get(w,meta+72)
        jstring(w,720000+family*32,family_length(family))
    else:
        literal(w,28)
    literal(w,25)
    literal(w,choose(get(w,meta+80) == 0,28,25+get(w,meta+80)))
    literal(w,29)
    jhex(w,row+96,32)
    literal(w,30)
    jhex(w,row+128,32)
    literal(w,31)
    jhex(w,row+160,32)
    literal(w,32)
    jnumber(w,get(w,row+32))
    literal(w,33)
    jnumber(w,get(w,row+32))
    literal(w,34)
    return 0

def render_report(w:mutbuf) -> u64:
    put(w,2264,0)
    put(w,2272,0)
    literal(w,0)
    jstring(w,1048736,desc(w,56))
    literal(w,1)
    json_manifest(w)
    json_generations(w)
    json_scheduler(w)
    literal(w,18)
    i = 0
    while i < desc(w,24):
        json_phase(w,i)
        i = i+1
    literal(w,35)
    return choose(get(w,2272) == 0,get(w,2264),0)

def publish_fd(o:mutbuf,w:mutbuf,source:u64,size:u64,name:u64,after:u64) -> u32:
    put(w,3000,source)
    put(w,3008,size)
    put(w,3016,name)
    put(w,3024,after)
    return call(o,w,1100,257,get(w,2048),name,655554,384,0,0,12)

def reporting(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p == 1020 and r == 18446744073709551612:
        return resume(s,o,w,1019)
    if failed(r):
        return finish(o,w,74)
    if p == 1000:
        return publish_fd(o,w,get(w,2192),get(w,2232),61376,1001)
    if p == 1001:
        return publish_fd(o,w,get(w,2160),128,61408,1002)
    if p == 1002:
        return publish_fd(o,w,get(w,2240),128,61440,1003)
    if p == 1003:
        return publish_fd(o,w,get(w,2080),get(w,2072),61472,1004)
    if p == 1004:
        return call(o,w,1005,228,1,1400,0,0,0,0,12)
    if p == 1005:
        put(w,3048,get(w,1400)*1000000000+get(w,1408))
        n = render_report(w)
        if n == 0:
            return finish(o,w,65)
        put(w,2256,n)
        return call(o,w,1010,257,get(w,2048),61536,655554,384,0,0,12)
    if p == 1010:
        if r < 3:
            return finish(o,w,74)
        put(w,2248,r)
        return writing(o,w,r,5500000,get(w,2256),1011)
    if p == 1011:
        return call(o,w,1012,74,get(w,2248),0,0,0,0,0,0)
    if p == 1012:
        return call(o,w,1013,91,get(w,2248),256,0,0,0,0,0)
    if p == 1013:
        return call(o,w,1014,316,get(w,2048),61536,get(w,2048),61504,1,0,204)
    if p == 1014:
        return call(o,w,1015,74,get(w,2048),0,0,0,0,0,0)
    if p == 1015:
        put(w,3040,0)
        return resume(s,o,w,1019)
    if p == 1019:
        if get(w,3040) == get(w,2256):
            return finish(o,w,0)
        return call(o,w,1020,1,1,5500000+get(w,3040),get(w,2256)-get(w,3040),0,0,0,12)
    if p == 1020:
        if r == 0 or r > get(w,2256)-get(w,3040):
            return finish(o,w,74)
        put(w,3040,get(w,3040)+r)
        return resume(s,o,w,1019)
    if p == 1100:
        if r < 3:
            return finish(o,w,74)
        put(w,3032,r)
        return copying(o,w,get(w,3000),r,0,get(w,3008),1101)
    if p == 1101:
        return call(o,w,1102,74,get(w,3032),0,0,0,0,0,0)
    if p == 1102:
        return call(o,w,1103,91,get(w,3032),256,0,0,0,0,0)
    if p == 1103:
        return call(o,w,1104,3,get(w,3032),0,0,0,0,0,0)
    if p == 1104:
        return resume(s,o,w,get(w,3024))
    return finish(o,w,65)
'''

def source():
    text=SOURCE.replace('put(w,2370,','put(w,2368,').replace('get(w,2370)','get(w,2368)')
    text=text.replace('if p < 500:\n        return asset(s,o,w,p,r)','if p >= 480 and p < 500:\n        return sealing(s,o,w,p,r)\n    if p < 500:\n        return asset(s,o,w,p,r)')
    text=text.replace('flags = 655360','flags = 657408')
    a=text.index('def paths(');b=text.index('\ndef load_asset(',a);part=text[a:b]
    part=part.replace('if failed(r):','if failed(r) and (p != 306 or r != 18446744073709551614):',1)
    part=part.replace('''        put(w,2556,1)
        return resume(s,o,w,301)''','''        put(w,2556,1)
        if get(w,2524) == 2:
            put(w,2580,301)
            return call(o,w,306,262,r,61360,1200,256,0,0,60)
        return resume(s,o,w,301)''',1)
    part=part.replace('''        put(w,2556,1)
        if get(w,2564) == get(w,2508):''','''        put(w,2556,1)
        if get(w,2524) == 2:
            put(w,2580,307)
            return call(o,w,306,262,get(w,2548),61360,1200,256,0,0,60)
        return resume(s,o,w,307)
    if p == 306:
        if r != 18446744073709551614:
            return finish(o,w,65)
        return resume(s,o,w,get(w,2580))
    if p == 307:
        if get(w,2564) == get(w,2508):''',1)
    text=text[:a]+part+text[b:]
    values={'ARGV':b'HIAARG01','DESCRIPTOR':b'HIAQBD01','MANIFEST':b'HIASXM01','EXPORT_REQUEST':b'HIASXQ01','EXPORT_OK':b'HIASXR01','MASTER_REQUEST':b'HIAQMS01','MASTER_OK':b'HIAQMR01','OWNER_REQUEST':b'HIACOW01','OWNER_OK':b'HIACOR01','ARCHIVE':b'HIAQAR01'}
    for key,value in values.items():text=text.replace('@'+key+'@',str(int.from_bytes(value,'little')))
    items=[(61000,b'hia-cold-cli\0'),(61032,b'/\0'),(61040,b'\0'),(61100,b'source\0'),(61116,b'qualification\0'),(61140,b'.hiaqar\0'),(61200,b'PATH=\0'),(61216,b'LANG=C\0'),(61232,b'LC_ALL=C\0'),(61248,b'TZ=UTC\0'),(61264,b'HOME=\0'),(61280,b'/home\0'),(61296,b'TMPDIR=\0'),(61312,b'/tmp\0'),(61328,b'process-owner.receipt\0'),(61360,b'.git\0'),(61376,b'master.receipt\0'),(61408,b'source-export-before.receipt\0'),(61440,b'source-export-after.receipt\0'),(61472,b'bundle.descriptor\0'),(61504,b'final-cold.json\0'),(61536,b'cold-report.pending\0'),(62000,b'--source\0'),(62016,b'--output\0'),(62032,b'--toolchain\0'),(62048,b'--bundle\0')]
    for i,name in enumerate(['hia-cold-master','hia-cold-process-owner','hia-cold-source-export']):items.append((62100+i*64,name.encode()+b'\0'))
    for i,name in enumerate(['B0.flat','B1.flat','B2.flat','B3.flat','M1.flat','M2.flat','M3.flat','native-observer.elf']):items.append((64000+i*32,name.encode()+b'\0'))
    observer=reference_image();assert len(observer)==1107;items.append((700000,observer))
    for i,name in enumerate(FAMILIES):items.append((720000+i*32,name.encode()+b'\0'))
    at=740000;literal_spans=[]
    for value in LITERALS:
        raw=value.encode();items.append((at,raw));literal_spans.append((at,len(raw)));at+=len(raw)
    stores=[]
    for at,value in items:
        for i in range(0,len(value),8):stores.append(f'    put(w,{at+i},{int.from_bytes(value[i:i+8],"little")})')
    count=(len(stores)+63)//64
    text+='\ndef constants(w:mutbuf) -> u64:\n'+''.join(f'    constants_{i}(w)\n' for i in range(count))+'    return 0\n'
    for i in range(count):text+=f'\ndef constants_{i}(w:mutbuf) -> u64:\n'+'\n'.join(stores[i*64:(i+1)*64])+'\n    return 0\n'
    text+='\ndef literal(w:mutbuf,i:u64) -> u64:\n'
    for i,(at,n) in enumerate(literal_spans):text+=f'    if i == {i}:\n        return jraw(w,{at},{n})\n'
    text+='    return 0\n\ndef family_length(i:u64) -> u64:\n'
    for i,name in enumerate(FAMILIES):text+=f'    if i == {i}:\n        return {len(name)}\n'
    return text+'    return 0\n'+helpers()

def template():
    with tempfile.TemporaryDirectory(prefix='hia-cold-cli-author-') as tmp:
        obj=Path(tmp)/'cli.o';raw=Path(tmp)/'cli.bin'
        subprocess.run(['as','--64',str(ROOT/'tools/hia_cold_cli_syscalls.S'),'-o',str(obj)],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
        symbols={name:int(addr,16) for addr,_,name in (line.split() for line in subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines())}
        assert symbols['_start']==0 and 'R_X86_64' not in subprocess.check_output(['objdump','-r',str(obj)],text=True)
        code=raw.read_bytes()
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)+struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)+struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    return header+code,{name:176+symbols[name] for name in ('policy_hole','sha_hole','entry_pins')}

def packer():
    prefix,holes=template()
    text=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s) < 154 or uint(s,0,8) != {int.from_bytes(b'HIAQCP01','little')}:
        return 4294967295
    policy = uint(s,8,8)
    sha = uint(s,16,8)
    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576 or length(s) != 152+policy+sha:
        return 4294967295
    i = 24
    while i < 152:
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
    copy_bytes(s,o,24,{holes['entry_pins']},128)
    copy_bytes(s,o,152,{len(prefix)},policy+sha)
    return size
'''
    return text+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]

if __name__=='__main__':
    for name,text in [('cold_cli',source()),('cold_cli_packer',packer())]:
        doc=document(text);raw=render_assembly(doc).encode();(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).write_bytes(raw)
        print(name,len(raw),len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),sha256(raw).hexdigest(),flush=True)
