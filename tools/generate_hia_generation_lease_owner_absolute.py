"""Native lexical Path.absolute after actual Path/string admission.

HIAGPAQ1 accepts an already captured WTF-8 path. It preserves '..' and a
two-slash POSIX root, never follows input symlinks, and obtains the actual
working directory through getcwd or the native parent-walk fallback.
HIAGPAN1 is a separate private posixpath.abspath profile for tempfile's
normalized candidates; it collapses '..' lexically without following links.
The successful result is an owned, fully sealed WTF-8 memfd. Failed private
FD cleanup remains in the same context until the explicit abort retry.
This private component does not stand in for public __fspath__ or gettempdir.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
from tools import generate_hia_native_path_resolve as original
ROOT=Path(__file__).resolve().parents[1]
C=dict(original.C,MAGIC=int.from_bytes(b'HIAGPAQ1','little'),
       REPLY=int.from_bytes(b'HIAGPAR1','little'),
       CONTEXT=int.from_bytes(b'HIAGPAC1','little'),NORM_MAGIC=int.from_bytes(b'HIAGPAN1','little'),BAD=4294967293)
SOURCE=r'''
def absolute(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<128 or length(w)<200704:
        return BAD
    phase=get(w,0)
    if phase==0:
        return begin(s,o,w)
    if get(w,304)!=CONTEXT or get(w,320)!=get(w,16):
        return BAD
    r=get(w,8)
    if phase==98:
        if get(w,400)!=0:
            return BAD
        if length(s)!=32 or word_load(s,0)!=MAGIC or word_load(s,8)!=1 or word_load(s,16)!=0 or word_load(s,24)!=0:
            return BAD
        return call(o,w,99,39,0,0,0,0,0,0,0)
    if phase==99:
        if r!=get(w,312):
            return BAD
        put(w,24,0)
        put(w,32,0)
        put(w,40,0)
        put(w,200,0)
        put(w,328,1)
        put(w,336,0)
        put(w,368,0)
        put(w,392,0)
        return close_next(o,w)
    if phase<20:
        return initialize(s,o,w,phase,r)
    if phase==20 or phase==21 or phase==22 or phase==25 or phase==26:
        return lexical(s,o,w,phase)
    if phase>=90 and phase<=96:
        return closing(o,w,phase,r)
    if phase>=100 and phase<=118:
        return cwd_phase(o,w,phase,r)
    if phase>=800 and phase<810:
        return io_step(o,w,phase,r)
    return BAD

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<32 or (word_load(s,0)!=MAGIC and word_load(s,0)!=NORM_MAGIC) or word_load(s,8)!=0 or word_load(s,16)!=length(s)-32 or word_load(s,24)!=0:
        return BAD
    if valid_wtf8(s)==False:
        return BAD
    i=24
    while i<1024:
        if get(w,i)!=0:
            return BAD
        i=i+8
    zero(w,24,2024)
    put(w,48,length(s)-32)
    put(w,64,32)
    put(w,304,CONTEXT)
    put(w,320,get(w,16))
    put(w,360,1)
    put(w,376,choose(word_load(s,0)==NORM_MAGIC,1,0))
    put(w,2048,0)
    i=0
    while i<6:
        put(w,256+i*8,NONE)
        i=i+1
    return call(o,w,1,39,0,0,0,0,0,0,0)

def valid_wtf8(s:readbuf) -> bool:
    i=32
    while i<length(s):
        first=byte(s,i)
        if first<128:
            i=i+1
        else:
            width=0
            if first>=194 and first<=223:
                width=2
            elif first>=224 and first<=239:
                width=3
            elif first>=240 and first<=244:
                width=4
            if width==0 or width>length(s)-i:
                return False
            second=byte(s,i+1)
            if second<128 or second>191:
                return False
            if (first==224 and second<160) or (first==240 and second<144) or (first==244 and second>=144):
                return False
            j=2
            while j<width:
                value=byte(s,i+j)
                if value<128 or value>191:
                    return False
                j=j+1
            i=i+width
    return True

def initialize(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==1:
        if r<2 or r>2147483647:
            return stop(o,w,4,r,1)
        put(w,312,r)
        put(w,200,0)
        return call(o,w,2,319,3,2048,3,0,0,0,0)
    if phase==2:
        if failed(r):
            return stop(o,w,4,r,2)
        i=get(w,200)
        put(w,256+i*8,r)
        put(w,200,i+1)
        if i<2:
            return call(o,w,2,319,3,2048,3,0,0,0,0)
        n=get(w,48)
        lead=0
        while lead<n and byte(s,32+lead)==47:
            lead=lead+1
        if lead!=0:
            amount=1
            if lead==2:
                amount=2
            store(w,PATH,47)
            store(w,PATH+1,47)
            put(w,96,amount)
            put(w,360,amount)
            return io(o,w,1,get(w,264),PATH,amount,0,20)
        return call(o,w,5,79,3,PATH,4096,0,0,0,0)
    if phase==5:
        if r==18446744073709551582 or r==18446744073709551580:
            return cwd_begin(o,w)
        if failed(r):
            return stop(o,w,4,r,5)
        if r==0 or r>4096 or byte(w,PATH+r-1)!=0:
            return stop(o,w,5,0,5)
        if byte(w,PATH)!=47:
            return stop(o,w,4,18446744073709551614,5)
        n=fs_decode(w,PATH,r-1,IO)
        put(w,96,n)
        return io(o,w,1,get(w,264),IO,n,0,20)
    return BAD

def lexical(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==20:
        at=get(w,64)
        end=32+get(w,48)
        while at<end and byte(s,at)==47:
            at=at+1
        if at==end:
            return call(o,w,90,72,0,get(w,264),1033,15,0,0,0)
        first=at
        while at<end and byte(s,at)!=47:
            at=at+1
        put(w,64,at)
        if at-first==1 and byte(s,first)==46:
            put(w,0,20)
            return 3
        if get(w,376)==1 and at-first==2 and byte(s,first)==46 and byte(s,first+1)==46:
            if get(w,96)==get(w,360):
                put(w,0,20)
                return 3
            put(w,152,get(w,96))
            return parent_scan(o,w)
        put(w,72,first)
        put(w,88,at-first)
        put(w,112,0)
        return write_part(s,o,w)
    if phase==25:
        size=get(w,816)
        i=size
        while i!=0:
            i=i-1
            if byte(w,IO+i)==47:
                n=get(w,152)-size+i
                put(w,96,choose(n<get(w,360),get(w,360),n))
                return call(o,w,26,77,0,get(w,264),get(w,96),0,0,0,0)
        put(w,152,get(w,152)-size)
        if get(w,152)==0:
            return stop(o,w,5,0,25)
        return parent_scan(o,w)
    if phase==26:
        if get(w,8)!=0:
            return stop(o,w,4,get(w,8),26)
        put(w,0,20)
        return 3
    if phase==22:
        put(w,112,get(w,112)+get(w,128))
        put(w,96,get(w,96)+get(w,120))
        if get(w,112)<get(w,88):
            return write_part(s,o,w)
        put(w,0,20)
        return 3
    return BAD

def write_part(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    prefix=0
    if get(w,112)==0 and get(w,96)!=get(w,360):
        prefix=1
        store(w,IO,47)
    amount=minimum(CAP-prefix,get(w,88)-get(w,112))
    i=0
    at=get(w,72)+get(w,112)
    while i<amount:
        store(w,IO+prefix+i,byte(s,at+i))
        i=i+1
    put(w,128,amount)
    put(w,120,prefix+amount)
    return io(o,w,1,get(w,264),IO,prefix+amount,get(w,96),22)

def fs_decode(w:mutbuf,at:u64,n:u64,to:u64) -> u64:
    i=0
    count=0
    while i<n:
        first=byte(w,at+i)
        width=fs_width(w,at+i,n-i)
        if width==0:
            store(w,to+count,237)
            store(w,to+count+1,176+(first>>6))
            store(w,to+count+2,128+(first&63))
            count=count+3
            i=i+1
        else:
            j=0
            while j<width:
                store(w,to+count,byte(w,at+i+j))
                count=count+1
                j=j+1
            i=i+width
    return count

def fs_width(w:mutbuf,at:u64,n:u64) -> u64:
    first=byte(w,at)
    if first<128:
        return 1
    width=0
    if first>=194 and first<=223:
        width=2
    elif first>=224 and first<=239:
        width=3
    elif first>=240 and first<=244:
        width=4
    if width==0 or width>n:
        return 0
    second=byte(w,at+1)
    if second<128 or second>191:
        return 0
    if (first==224 and second<160) or (first==237 and second>=160) or (first==240 and second<144) or (first==244 and second>=144):
        return 0
    j=2
    while j<width:
        value=byte(w,at+j)
        if value<128 or value>191:
            return 0
        j=j+1
    return width

def cwd_phase(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==100:
        if failed(r):
            return stop(o,w,4,r,100)
        put(w,288,r)
        return call(o,w,101,5,12,r,STAT,0,0,0,0)
    if phase==101:
        if failed(r):
            return stop(o,w,4,r,101)
        put(w,600,get(w,STAT))
        put(w,608,get(w,STAT+8))
        return cwd_parent(o,w)
    if phase==102:
        if failed(r):
            return stop(o,w,4,r,102)
        put(w,296,r)
        return call(o,w,103,5,12,r,CWD_STAT,0,0,0,0)
    if phase==103:
        if failed(r):
            return stop(o,w,4,r,103)
        put(w,616,get(w,CWD_STAT))
        put(w,624,get(w,CWD_STAT+8))
        if get(w,600)==get(w,616) and get(w,608)==get(w,624):
            store(w,PATH,47)
            put(w,96,1)
            return io(o,w,1,get(w,264),PATH,1,0,112)
        return call(o,w,104,217,12,get(w,296),IO,CAP,0,0,0)
    if phase==104:
        if r==EINTR:
            return call(o,w,104,217,12,get(w,296),IO,CAP,0,0,0)
        if failed(r):
            return stop(o,w,4,r,104)
        if r==0:
            return stop(o,w,4,18446744073709551614,104)
        if r>CAP:
            return stop(o,w,5,0,104)
        put(w,640,r)
        put(w,648,0)
        return cwd_scan(o,w)
    if phase==105:
        if r==EINTR:
            return call(o,w,105,262,60,get(w,296),PATH,STAT,256,0,0)
        if failed(r):
            if r==18446744073709551614:
                return cwd_scan(o,w)
            return stop(o,w,4,r,105)
        if get(w,STAT)!=get(w,600) or get(w,STAT+8)!=get(w,608):
            return cwd_scan(o,w)
        if get(w,656)>NONE-get(w,680) or get(w,632)>NONE//40-1:
            return stop(o,w,5,0,105)
        zero(w,FRAME,40)
        put(w,FRAME,get(w,680))
        put(w,FRAME+8,get(w,656))
        return io(o,w,1,get(w,256),PATH,get(w,656),get(w,680),106)
    if phase==106:
        return io(o,w,1,get(w,272),FRAME,40,get(w,632)*40,107)
    if phase==107:
        put(w,680,get(w,680)+get(w,656))
        put(w,632,get(w,632)+1)
        return call(o,w,108,436,0,get(w,288),get(w,288),0,0,0,0)
    if phase==108:
        if failed(r):
            return stop(o,w,4,r,108)
        put(w,288,get(w,296))
        put(w,296,NONE)
        put(w,600,get(w,616))
        put(w,608,get(w,624))
        return cwd_parent(o,w)
    if phase==112:
        if get(w,632)==0:
            return call(o,w,115,436,0,get(w,296),get(w,296),0,0,0,0)
        return io(o,w,0,get(w,272),FRAME,40,(get(w,632)-1)*40,113)
    if phase==113:
        put(w,688,get(w,FRAME))
        put(w,696,get(w,FRAME+8))
        if get(w,696)==0 or get(w,696)>=4096:
            return stop(o,w,5,0,113)
        return io(o,w,0,get(w,256),PATH,get(w,696),get(w,688),118)
    if phase==118:
        prefix=0
        if get(w,96)!=1:
            prefix=1
            store(w,IO,47)
        n=fs_decode(w,PATH,get(w,696),IO+prefix)+prefix
        put(w,712,n)
        return io(o,w,1,get(w,264),IO,n,get(w,96),117)
    if phase==117:
        put(w,96,get(w,96)+get(w,712))
        put(w,632,get(w,632)-1)
        put(w,0,112)
        return 3
    if phase==115:
        if failed(r):
            return stop(o,w,4,r,115)
        put(w,296,NONE)
        return call(o,w,116,436,0,get(w,288),get(w,288),0,0,0,0)
    if phase==116:
        if failed(r):
            return stop(o,w,4,r,116)
        put(w,288,NONE)
        put(w,0,20)
        return 3
    return BAD

def stop(o:mutbuf,w:mutbuf,status:u64,raw:u64,where:u64) -> u32:
    if get(w,24)==0:
        put(w,24,status)
        put(w,32,raw)
        put(w,40,where)
    put(w,200,0)
    put(w,336,0)
    put(w,368,0)
    return close_next(o,w)

def close_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,200)
    while i<6:
        fd=get(w,256+i*8)
        put(w,200,i+1)
        keep=i==1 and get(w,24)==0 and get(w,328)==0
        if fd!=NONE and keep==False and (get(w,400)&(1<<i))==0:
            put(w,384,i)
            if i==1:
                put(w,368,1)
            return call(o,w,94,436,0,fd,fd,0,0,0,0)
        i=i+1
    if get(w,24)!=0 and get(w,264)!=NONE and get(w,368)==0 and (get(w,400)&2)==0:
        put(w,368,1)
        put(w,384,1)
        return call(o,w,94,436,0,get(w,264),get(w,264),0,0,0,0)
    return result(o,w)

def closing(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==90:
        if failed(r):
            return stop(o,w,4,r,90)
        return call(o,w,91,72,0,get(w,264),1034,0,0,0,0)
    if phase==91:
        if r!=15:
            return stop(o,w,5,r,91)
        return call(o,w,92,5,12,get(w,264),STAT,0,0,0,0)
    if phase==92:
        if failed(r) or get(w,STAT+48)!=get(w,96):
            return stop(o,w,5,r,92)
        put(w,200,0)
        return close_next(o,w)
    if phase==94 or phase==95:
        if phase==94 and r==18446744073709551578:
            return call(o,w,95,3,0,get(w,256+get(w,384)*8),0,0,0,0,0)
        if phase==95 and r!=0:
            put(w,400,get(w,400)|(1<<get(w,384)))
        if r!=0:
            put(w,336,1)
            if get(w,392)==0:
                put(w,392,r)
            if get(w,24)==0:
                put(w,24,4)
                put(w,32,r)
                put(w,40,94)
        else:
            put(w,256+get(w,384)*8,NONE)
        return close_next(o,w)
    return BAD

def result(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,get(w,24))
    put(o,16,get(w,32))
    put(o,24,get(w,40))
    put(o,32,NONE)
    pending=get(w,336)
    if get(w,400)!=0:
        pending=1
    put(o,56,pending)
    put(o,72,get(w,400))
    put(o,88,get(w,392))
    if pending!=0:
        put(w,0,98)
        return 0
    if get(w,24)==0 and get(w,328)==0:
        put(o,32,get(w,264))
        put(o,40,get(w,96))
        put(o,48,15)
        put(w,264,NONE)
    put(w,0,97)
    return 0
'''
def source_program():
    names={'cwd_begin','cwd_parent','cwd_scan','copy_bytes','io','io_more',
           'io_step','call','get','put','zero','minimum','failed','parent_scan'}
    helpers='\n\n'.join(ast.get_source_segment(original.SOURCE,n) for n in ast.parse(original.SOURCE).body
                        if isinstance(n,ast.FunctionDef) and n.name in names)
    source=SOURCE+'\n'+helpers
    for key,value in sorted(C.items(),key=lambda item:-len(item[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    tree=document(source_program(),'generation_lease_owner_absolute')
    target=ROOT/'examples/hia_bootstrap/generation_lease_owner_absolute.hepta'
    target.write_text(render_assembly(tree))
    print(target.name,target.stat().st_size,len(tree['functions']),
          sum(len(f['blocks']) for f in tree['functions']),
          sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
