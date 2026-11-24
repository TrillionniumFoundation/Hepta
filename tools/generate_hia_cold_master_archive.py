"""Native stopped-phase archive: complete journal replay, file custody and sealing."""
from pathlib import Path
from hashlib import sha256
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import bulk_document as document
from tools.hia_cold_byte_loops import accelerate
from tools.generate_hia_cold_master_common import helpers,packer,DECODER
ROOT=Path(__file__).resolve().parents[1]
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != 4194304:
        return 0
    phase = get(w,0)
    r = get(w,8)
    if phase >= 200 and phase < 250:
        return transfer(s,o,w,phase,r)
    if phase >= 250 and phase < 300:
        return hashing(s,o,w,phase,r)
    if phase < 200:
        return admission(s,o,w,phase,r)
    if phase < 500:
        return inventory(s,o,w,phase,r)
    if phase < 700:
        return journal_scan(s,o,w,phase,r)
    if phase < 900:
        return archiving(s,o,w,phase,r)
    return sealing(s,o,w,phase,r)

def admission(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if p == 0:
        if length(s) != 128 or uint(s,0,8) != @REQUEST@ or uint(s,112,8) != 0 or uint(s,120,8) != 0:
            return finish(o,w,65)
        if uint(s,8,8) < 2 or uint(s,8,8) > 2147483647 or uint(s,16,8) == 0 or uint(s,56,8) < 32 or uint(s,56,8) > 67108864 or uint(s,64,8) == 0 or uint(s,64,8) > 65536:
            return finish(o,w,65)
        i = 3
        while i < 10:
            if i != 7 and i != 8:
                fd = uint(s,i*8,8)
                if fd < 3 or fd > 2147483647:
                    return finish(o,w,65)
                j = 3
                while j < i:
                    if j != 7 and j != 8 and fd == uint(s,j*8,8):
                        return finish(o,w,65)
                    j = j + 1
            i = i + 1
        put(w,61000,46)
        return call(o,w,1,110,0,0,0,0,0,0,0)
    if failed(r):
        return finish(o,w,74)
    if p == 1:
        if r != uint(s,8,8):
            return finish(o,w,65)
        return call(o,w,2,157,1,15,0,0,0,0,0)
    if p == 2:
        return call(o,w,3,107,0,0,0,0,0,0,0)
    if p == 3:
        put(w,2000,r)
        return call(o,w,4,5,uint(s,24,8),1200,0,0,0,0,12)
    if p == 4:
        if getn(w,1224,4) & 61440 != 16384 or getn(w,1224,4) & 63 != 0 or getn(w,1228,4) != get(w,2000):
            return finish(o,w,65)
        return call(o,w,5,5,uint(s,72,8),1200,0,0,0,0,12)
    if p == 5:
        if regular(w) == 0 or get(w,1248) != 0:
            return finish(o,w,65)
        return call(o,w,6,5,uint(s,40,8),1200,0,0,0,0,12)
    if p == 6:
        if getn(w,1224,4) & 61440 != 32768 or get(w,1248) != 64:
            return finish(o,w,65)
        return call(o,w,7,72,uint(s,40,8),1034,0,0,0,0,0)
    if p == 7:
        if r & 15 != 15:
            return finish(o,w,65)
        return reading(o,w,uint(s,40,8),10000,64,0,8)
    if p == 8:
        if get(w,10000) != @DRIVER_OK@ or get(w,10008) != uint(s,64,8) or get(w,10016) != uint(s,56,8) or get(w,10024) == 0:
            return finish(o,w,65)
        return call(o,w,9,5,uint(s,48,8),1200,0,0,0,0,12)
    if p == 9:
        if getn(w,1224,4) & 61440 != 32768 or get(w,1248) != uint(s,56,8):
            return finish(o,w,65)
        return call(o,w,10,72,uint(s,48,8),1034,0,0,0,0,0)
    if p == 10:
        if r & 15 != 15:
            return finish(o,w,65)
        return hash_view(o,w,uint(s,48,8),0,uint(s,56,8),11)
    if p == 11:
        if same_input(s,w,80,4096,32) == 0:
            return finish(o,w,65)
        return call(o,w,12,5,uint(s,32,8),1200,0,0,0,0,12)
    if p == 12:
        if regular(w) == 0 or get(w,1248) != get(w,10024):
            return finish(o,w,65)
        put(w,2016,get(w,1200))
        put(w,2024,get(w,1208))
        return hash_view(o,w,uint(s,32,8),0,get(w,10024),13)
    if p == 13:
        if same(w,4096,10032,32) == 0:
            return finish(o,w,74)
        put(w,2032,0)
        put(w,2040,0)
        put(w,2048,0)
        put(w,2056,0)
        return resume(s,o,w,500)
    if p == 190:
        if get(w,1400)*1000000000 + get(w,1408) >= uint(s,16,8):
            return finish(o,w,124)
        return resume(s,o,w,get(w,2096))
    return finish(o,w,65)

def regular(w:mutbuf) -> u64:
    if getn(w,1224,4) & 61440 != 32768 or getn(w,1224,4) & 63 != 0 or getn(w,1228,4) != get(w,2000) or get(w,1216) != 1 or get(w,1248) >> 63 != 0:
        return 0
    return 1

def deadline(s:readbuf,o:mutbuf,w:mutbuf,after:u64) -> u32:
    put(w,2096,after)
    return call(o,w,190,228,1,1400,0,0,0,0,12)

def journal_scan(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 500:
        if get(w,2032) == get(w,10024):
            if get(w,2040) != uint(s,64,8) or get(w,2048) != 0 or get(w,2056) != 0:
                return finish(o,w,74)
            return call(o,w,300,257,uint(s,24,8),61000,720896,0,0,0,12)
        if get(w,2032) > get(w,10024) or get(w,10024)-get(w,2032) < 33:
            return finish(o,w,74)
        return deadline(s,o,w,501)
    if p == 501:
        return reading(o,w,uint(s,32,8),800000,32,get(w,2032),502)
    if p == 502:
        size = get(w,800016)
        if size == 0 or size > 65504 or size > get(w,10024)-get(w,2032)-32:
            return finish(o,w,74)
        return reading(o,w,uint(s,32,8),800032,size,get(w,2032)+32,503)
    if p == 503:
        size = unpack_chunk(w,get(w,800016)+32)
        if size == 0 or journal_bytes(w,size) == 0:
            return finish(o,w,74)
        put(w,2032,get(w,2032)+get(w,800016)+32)
        return resume(s,o,w,500)
    return finish(o,w,65)

def journal_bytes(w:mutbuf,size:u64) -> u64:
    at = 0
    while at < size:
        if get(w,2056) != 0:
            n = minimum(size-at,get(w,2056))
            at = at+n
            put(w,2056,get(w,2056)-n)
        else:
            n = minimum(size-at,64-get(w,2048))
            copyw(w,12000+get(w,2048),940000+at,n)
            at = at+n
            put(w,2048,get(w,2048)+n)
            if get(w,2048) == 64:
                if get(w,12000) != @JOURNAL@ or get(w,12008) != get(w,2040) or get(w,12016) == 0 or get(w,12016) > 17 or get(w,12024) > 4096 or get(w,12032) > 128 or get(w,12040) > 1048576 or get(w,12048) > 9223372036853726207 or get(w,12056) != 0:
                    return 0
                put(w,2056,get(w,12032)*8+get(w,12040)+get(w,12048))
                put(w,2048,0)
                put(w,2040,get(w,2040)+1)
    return 1

def inventory(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 300:
        if r < 3:
            return finish(o,w,74)
        put(w,2064,r)
        put(w,2072,0)
        put(w,2080,0)
        return call(o,w,301,217,r,500000,65536,0,0,0,12)
    if p == 301:
        if r == 0:
            if get(w,2072) == 0 or get(w,2080) != 1:
                return finish(o,w,74)
            sort_files(w)
            return sha(o,w,700,0,1)
        if r > 65536:
            return finish(o,w,74)
        put(w,2104,r)
        put(w,2112,0)
        return resume(s,o,w,302)
    if p == 302:
        at = get(w,2112)
        if at == get(w,2104):
            return call(o,w,301,217,get(w,2064),500000,65536,0,0,0,12)
        if at > get(w,2104) or get(w,2104)-at < 20:
            return finish(o,w,74)
        n = getn(w,500016+at,2)
        if n < 20 or n > get(w,2104)-at:
            return finish(o,w,74)
        put(w,2112,at+n)
        count = 0
        while count < n-19 and byte(w,500019+at+count) != 0:
            count = count+1
        if count == n-19:
            return finish(o,w,74)
        if (count == 1 and byte(w,500019+at) == 46) or (count == 2 and getn(w,500019+at,2) == 11822):
            return resume(s,o,w,302)
        if count == 0 or count > 127 or byte(w,500019+at) == 46 or get(w,2072) == 4096:
            return finish(o,w,65)
        i = 0
        while i < count:
            c = byte(w,500019+at+i)
            if (c < 48 or c > 57) and (c < 65 or c > 90) and (c < 97 or c > 122) and c != 45 and c != 46 and c != 95:
                return finish(o,w,65)
            i = i+1
        row = 1500000+get(w,2072)*192
        zero_range(w,row,192)
        copyw(w,row,500019+at,count)
        put(w,row+128,count)
        return call(o,w,303,257,uint(s,24,8),row,657408,0,0,0,12)
    if p == 303:
        if r < 3:
            return finish(o,w,74)
        put(w,2120,r)
        return call(o,w,304,5,r,1200,0,0,0,0,12)
    if p == 304:
        if regular(w) == 0:
            return finish(o,w,65)
        row = 1500000+get(w,2072)*192
        put(w,row+136,get(w,1248))
        put(w,row+144,get(w,1200))
        put(w,row+152,get(w,1208))
        if get(w,1200) == get(w,2016) and get(w,1208) == get(w,2024):
            if get(w,1248) != get(w,10024):
                return finish(o,w,74)
            put(w,2080,get(w,2080)+1)
        return deadline(s,o,w,307)
    if p == 307:
        return hash_view(o,w,get(w,2120),0,get(w,1500136+get(w,2072)*192),305)
    if p == 305:
        row = 1500000+get(w,2072)*192
        if get(w,row+144) == get(w,2016) and get(w,row+152) == get(w,2024) and same(w,4096,10032,32) == 0:
            return finish(o,w,74)
        copyw(w,1500160+get(w,2072)*192,4096,32)
        return call(o,w,306,3,get(w,2120),0,0,0,0,0,0)
    if p == 306:
        put(w,2072,get(w,2072)+1)
        return resume(s,o,w,302)
    return finish(o,w,65)

def sort_files(w:mutbuf) -> u64:
    i = 1
    while i < get(w,2072):
        j = i
        while j != 0 and name_less(w,1500000+j*192,1500000+(j-1)*192) == 1:
            copyw(w,13000,1500000+j*192,192)
            copyw(w,1500000+j*192,1500000+(j-1)*192,192)
            copyw(w,1500000+(j-1)*192,13000,192)
            j = j-1
        i = i+1
    return 0

def name_less(w:mutbuf,a:u64,b:u64) -> u64:
    i = 0
    while i < minimum(get(w,a+128),get(w,b+128)):
        x = byte(w,a+i)
        y = byte(w,b+i)
        if x != y:
            return choose(x < y,1,0)
        i = i+1
    return choose(get(w,a+128) < get(w,b+128),1,0)

def zero_range(w:mutbuf,at:u64,n:u64) -> u64:
    i = 0
    while i < n:
        store(w,at+i,0)
        i = i+1
    return 0
'''
SOURCE+=r'''
def archiving(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 700:
        if r != 0:
            return finish(o,w,74)
        copyw(w,1008000,4160,1184)
        put(w,2136,0)
        put(w,2144,0)
        put(w,62000,@ARCHIVE@)
        put(w,62008,get(w,2072))
        put(w,62016,uint(s,64,8))
        put(w,62024,uint(s,56,8))
        copy_input(s,w,80,62032,32)
        return append(s,o,w,62000,64,701)
    if p == 701:
        if get(w,2144) == get(w,2072):
            copyw(w,4160,1008000,1184)
            return sha(o,w,900,2,1)
        row = 1500000+get(w,2144)*192
        return call(o,w,702,257,uint(s,24,8),row,657408,0,0,0,12)
    if p == 702:
        if r < 3:
            return finish(o,w,74)
        put(w,2152,r)
        return call(o,w,703,5,r,1200,0,0,0,0,12)
    if p == 703:
        if same_file(w) == 0:
            return finish(o,w,74)
        put(w,2160,0)
        return sha(o,w,704,0,1)
    if p == 704:
        if r != 0:
            return finish(o,w,74)
        copyw(w,1009200,4160,1184)
        row = 1500000+get(w,2144)*192
        put(w,62000,get(w,row+128))
        put(w,62008,get(w,row+136))
        copyw(w,62016,row+160,32)
        copyw(w,62048,row,128)
        return append(s,o,w,62000,176,705)
    if p == 705:
        row = 1500000+get(w,2144)*192
        if get(w,2160) == get(w,row+136):
            copyw(w,4160,1009200,1184)
            return sha(o,w,710,2,1)
        put(w,2168,minimum(65536,get(w,row+136)-get(w,2160)))
        return deadline(s,o,w,706)
    if p == 706:
        return reading(o,w,get(w,2152),700000,get(w,2168),get(w,2160),707)
    if p == 707:
        copyw(w,4160,1009200,1184)
        copyw(w,65537,700000,get(w,2168))
        return sha(o,w,708,1,get(w,2168)+1)
    if p == 708:
        if r != 0:
            return finish(o,w,74)
        copyw(w,1009200,4160,1184)
        return append(s,o,w,700000,get(w,2168),709)
    if p == 709:
        put(w,2160,get(w,2160)+get(w,2168))
        return resume(s,o,w,705)
    if p == 710:
        if r != 32 or same(w,4096,1500160+get(w,2144)*192,32) == 0:
            return finish(o,w,74)
        return call(o,w,711,5,get(w,2152),1200,0,0,0,0,12)
    if p == 711:
        if same_file(w) == 0:
            return finish(o,w,74)
        return call(o,w,712,91,get(w,2152),256,0,0,0,0,0)
    if p == 712:
        return call(o,w,713,74,get(w,2152),0,0,0,0,0,0)
    if p == 713:
        return call(o,w,714,3,get(w,2152),0,0,0,0,0,0)
    if p == 714:
        put(w,2144,get(w,2144)+1)
        return resume(s,o,w,701)
    if p == 880:
        if r != 0:
            return finish(o,w,74)
        copyw(w,1008000,4160,1184)
        return writing_at(o,w,uint(s,72,8),get(w,2200),get(w,2208),get(w,2136),881)
    if p == 881:
        put(w,2136,get(w,2136)+get(w,2208))
        return resume(s,o,w,get(w,2216))
    return finish(o,w,65)

def append(s:readbuf,o:mutbuf,w:mutbuf,at:u64,size:u64,after:u64) -> u32:
    if size == 0 or size > 65536 or get(w,2136) > 9223372036854775807-size:
        return finish(o,w,65)
    put(w,2200,at)
    put(w,2208,size)
    put(w,2216,after)
    copyw(w,4160,1008000,1184)
    copyw(w,65537,at,size)
    return sha(o,w,880,1,size+1)

def same_file(w:mutbuf) -> u64:
    row = 1500000+get(w,2144)*192
    if regular(w) == 0 or get(w,1248) != get(w,row+136) or get(w,1200) != get(w,row+144) or get(w,1208) != get(w,row+152):
        return 0
    return 1

def sealing(s:readbuf,o:mutbuf,w:mutbuf,p:u64,r:u64) -> u32:
    if failed(r):
        return finish(o,w,74)
    if p == 900:
        if r != 32:
            return finish(o,w,74)
        copyw(w,1010500,4096,32)
        return call(o,w,901,74,uint(s,72,8),0,0,0,0,0,0)
    if p == 901:
        return hash_view(o,w,uint(s,72,8),0,get(w,2136),902)
    if p == 902:
        if same(w,4096,1010500,32) == 0:
            return finish(o,w,74)
        return call(o,w,903,5,uint(s,72,8),1200,0,0,0,0,12)
    if p == 903:
        if regular(w) == 0 or get(w,1248) != get(w,2136):
            return finish(o,w,74)
        return call(o,w,904,8,get(w,2064),0,0,0,0,0,0)
    if p == 904:
        if r != 0:
            return finish(o,w,74)
        put(w,2224,0)
        zero_range(w,2300000,32768)
        return call(o,w,905,217,get(w,2064),500000,65536,0,0,0,12)
    if p == 905:
        if r == 0:
            if get(w,2224) != get(w,2072):
                return finish(o,w,74)
            return call(o,w,910,91,uint(s,24,8),320,0,0,0,0,0)
        if r > 65536:
            return finish(o,w,74)
        if verify_names(w,r) == 0:
            return finish(o,w,74)
        return call(o,w,905,217,get(w,2064),500000,65536,0,0,0,12)
    if p == 910:
        return call(o,w,911,74,uint(s,24,8),0,0,0,0,0,0)
    if p == 911:
        return call(o,w,912,91,uint(s,72,8),256,0,0,0,0,0)
    if p == 912:
        return call(o,w,913,74,uint(s,72,8),0,0,0,0,0,0)
    if p == 913:
        return call(o,w,914,3,get(w,2064),0,0,0,0,0,0)
    if p == 914:
        put(w,62000,@SUCCESS@)
        put(w,62008,get(w,2072))
        put(w,62016,get(w,2136))
        put(w,62024,get(w,2040))
        copy_input(s,w,80,62032,32)
        copyw(w,62064,10032,32)
        copyw(w,62096,1010500,32)
        put(w,2232,0)
        return call(o,w,915,1,1,62000,128,0,0,0,12)
    if p == 915:
        if r == 0 or r > 128-get(w,2232):
            return finish(o,w,74)
        put(w,2232,get(w,2232)+r)
        if get(w,2232) != 128:
            return call(o,w,915,1,1,62000+get(w,2232),128-get(w,2232),0,0,0,12)
        return finish(o,w,0)
    return finish(o,w,65)

def verify_names(w:mutbuf,size:u64) -> u64:
    at = 0
    while at < size:
        if size-at < 20:
            return 0
        n = getn(w,500016+at,2)
        if n < 20 or n > size-at:
            return 0
        count = 0
        while count < n-19 and byte(w,500019+at+count) != 0:
            count = count+1
        if count == n-19:
            return 0
        if (count == 1 and byte(w,500019+at) == 46) or (count == 2 and getn(w,500019+at,2) == 11822):
            at = at+n
        else:
            index = 0
            found = 0
            while index < get(w,2072) and found == 0:
                row = 1500000+index*192
                if get(w,row+128) == count and same(w,row,500019+at,count) == 1:
                    found = 1
                else:
                    index = index+1
            if index == get(w,2072) or get(w,2300000+index*8) != 0:
                return 0
            put(w,2300000+index*8,1)
            put(w,2224,get(w,2224)+1)
            at = at+n
    return 1

def copy_input(s:readbuf,w:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i = 0
    while i < n:
        store(w,b+i,byte(s,a+i))
        i = i+1
    return 0
'''
def source():
 text=SOURCE+'\n'+DECODER+'\n'+helpers()
 for key,raw in [('REQUEST',b'HIAQARQ1'),('DRIVER_OK',b'HIAQOK01'),('JOURNAL',b'HIAQJL01'),('ARCHIVE',b'HIAQAR01'),('SUCCESS',b'HIAQAS01')]:text=text.replace('@'+key+'@',str(int.from_bytes(raw,'little')))
 return accelerate(text,bulk=True)

def main():
 for name,text in [('cold_master_archive',source()),('cold_master_archive_packer',packer(b'HIAQAP01'))]:
  d=document(text,module=name);out=render_assembly(d).encode();(ROOT/('examples/hia_bootstrap/'+name+'.hepta')).write_bytes(out);print(name,len(out),len(d['functions']),sum(len(f['blocks']) for f in d['functions']),sum(len(b['ops']) for f in d['functions'] for b in f['blocks']),sha256(out).hexdigest())
if __name__=='__main__':main()

