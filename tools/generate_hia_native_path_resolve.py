"""Strict=False POSIX path resolution in HIA with unbounded private memfd records.

No fixed symlink-count limit. Stack, seen targets and the current path are owned
memfd objects; bounded buffers only transfer actual record bytes.
"""
from pathlib import Path
import re
from tools.generate_hia_ndu_evaluator import document
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
C={'NONE':2**64-1,'EINTR':2**64-4,'AT_FDCWD':2**64-100,'MAGIC':int.from_bytes(b'HIAPTH01','little'),'REPLY':int.from_bytes(b'HIAPTR01','little'),
'BORROW_MAGIC':int.from_bytes(b'HIAPTB01','little'),'CWD_STAT':1536,'FRAME':1024,'SEEN':1088,'STAT':1152,'PATH':4096,'LINK':196608,'IO':131072,'CAP':65536}
SOURCE=r'''
def resolve(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<128 or length(w)<200704:
        return 4294967293
    phase=get(w,0)
    r=get(w,8)
    if phase!=0 and phase!=1 and (phase<90 or (phase>=101 and phase<130 and phase!=102) or (phase>=140 and phase<150) or phase>=800) and get(w,544)!=0:
        return stop(o,w,6,0,0)
    if phase==0:
        return begin(s,o,w)
    if phase<20:
        return initialize(s,o,w,phase,r)
    if phase<40:
        return parts(o,w,phase,r)
    if phase<60:
        return links(o,w,phase,r)
    if phase<80:
        return transitions(o,w,phase,r)
    if phase>=140 and phase<150:
        return unicode_phase(o,w,phase)
    if phase>=100 and phase<130:
        return cwd_phase(o,w,phase,r)
    if phase>=90 and phase<100:
        return closing(o,w,phase,r)
    if phase>=800 and phase<810:
        return io_step(o,w,phase,r)
    if phase>=820 and phase<830:
        return copy_step(o,w,phase,r)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    mode=0
    at=0
    n=0
    if get(w,512)==BORROW_MAGIC:
        mode=get(w,520)
        at=get(w,528)
        n=get(w,536)
        if mode>1 or at>length(s) or n>length(s)-at:
            return 4294967293
    else:
        if length(s)<32 or word_load(s,0)!=MAGIC or word_load(s,8)>1 or word_load(s,16)!=length(s)-32 or word_load(s,24)!=0:
            return 4294967293
        mode=word_load(s,8)
        at=32
        n=length(s)-32
    if mode==1 and (n<2 or byte(s,at)!=34 or byte(s,at+n-1)!=34):
        return 4294967293
    base=get(w,16)
    cancel=get(w,544)
    zero(w,24,2024)
    put(w,16,base)
    put(w,544,cancel)
    put(w,2048,0)
    put(w,2056,7310238724270485551)
    put(w,2064,110463927936620)
    put(w,48,mode)
    put(w,56,n)
    put(w,64,at+mode)
    put(w,72,at+n-mode)
    put(w,176,NONE)
    put(w,184,NONE)
    i=0
    while i<6:
        put(w,256+i*8,NONE)
        i=i+1
    put(w,200,0)
    return call(o,w,1,319,3,2048,3,0,0,0,0)

def initialize(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==1:
        if failed(r):
            return stop(o,w,4,r,1)
        i=get(w,200)
        put(w,256+i*8,r)
        put(w,200,i+1)
        if i<3:
            return call(o,w,1,319,3,2048,3,0,0,0,0)
        put(w,0,2)
        return 3
    if phase==2:
        return decode(s,o,w)
    if phase==3:
        put(w,80,get(w,80)+get(w,88))
        put(w,88,0)
        put(w,0,2)
        return 3
    if phase==4:
        put(w,80,get(w,80)+get(w,88))
        put(w,88,0)
        if get(w,168)!=0:
            store(w,PATH,47)
            put(w,96,1)
            return io(o,w,1,get(w,264),PATH,1,0,7)
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
        put(w,96,r-1)
        return io(o,w,1,get(w,264),PATH,r-1,0,7)
    if phase==7:
        zero(w,FRAME,40)
        put(w,FRAME+8,0)
        put(w,FRAME+16,get(w,80))
        put(w,FRAME+24,0)
        put(w,104,1)
        return io(o,w,1,get(w,272),FRAME,40,0,20)
    return 4294967293

def cwd_begin(o:mutbuf,w:mutbuf) -> u32:
    put(w,2072,46)
    put(w,2080,11822)
    put(w,632,0)
    put(w,680,get(w,80))
    return call(o,w,100,257,12,AT_FDCWD,2072,2686976,0,0,0)

def cwd_parent(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,102,257,12,get(w,288),2080,589824,0,0,0)

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
        fd=get(w,288)
        put(w,288,NONE)
        return call(o,w,108,3,0,fd,0,0,0,0,0)
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
            fd=get(w,296)
            put(w,296,NONE)
            return call(o,w,115,3,0,fd,0,0,0,0,0)
        return io(o,w,0,get(w,272),FRAME,40,(get(w,632)-1)*40,113)
    if phase==113:
        put(w,688,get(w,FRAME))
        put(w,696,get(w,FRAME+8))
        if get(w,96)!=1:
            store(w,IO,47)
            at=get(w,96)
            put(w,96,at+1)
            return io(o,w,1,get(w,264),IO,1,at,114)
        put(w,0,114)
        return 3
    if phase==114:
        return copy_file(o,w,get(w,256),get(w,688),get(w,264),get(w,96),get(w,696),117)
    if phase==117:
        put(w,96,get(w,96)+get(w,696))
        put(w,632,get(w,632)-1)
        put(w,0,112)
        return 3
    if phase==115:
        if failed(r):
            return stop(o,w,4,r,115)
        fd=get(w,288)
        put(w,288,NONE)
        return call(o,w,116,3,0,fd,0,0,0,0,0)
    if phase==116:
        if failed(r):
            return stop(o,w,4,r,116)
        put(w,0,7)
        return 3
    return 4294967293

def cwd_scan(o:mutbuf,w:mutbuf) -> u32:
    pos=get(w,648)
    n=get(w,640)
    while pos<n:
        if n-pos<20:
            return stop(o,w,5,0,104)
        record=byte(w,IO+pos+16)|(byte(w,IO+pos+17)<<8)
        if record<20 or record>n-pos:
            return stop(o,w,5,0,104)
        name=IO+pos+19
        count=0
        while count<record-19 and byte(w,name+count)!=0:
            if byte(w,name+count)==47:
                return stop(o,w,5,0,104)
            count=count+1
        if count==record-19 or count==0 or count>=4096:
            return stop(o,w,5,0,104)
        pos=pos+record
        put(w,648,pos)
        dot=count==1 and byte(w,name)==46
        dotdot=count==2 and byte(w,name)==46 and byte(w,name+1)==46
        if dot==False and dotdot==False:
            put(w,656,count)
            copy_bytes(w,name,PATH,count)
            store(w,PATH+count,0)
            return call(o,w,105,262,60,get(w,296),PATH,STAT,256,0,0)
    return call(o,w,104,217,12,get(w,296),IO,CAP,0,0,0)

def copy_bytes(w:mutbuf,at:u64,to:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        word_store(w,to+i,word_load(w,at+i))
        i=i+8
    while i<n:
        store(w,to+i,byte(w,at+i))
        i=i+1
    return 0

def decode(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    at=get(w,64)
    end=get(w,72)
    n=get(w,88)
    while at<end and n<65520:
        cp=byte(s,at)
        at=at+1
        if get(w,48)==1 and cp==92:
            if at>=end:
                return stop(o,w,1,0,2)
            cp=byte(s,at)
            at=at+1
            if cp==117:
                if end-at<4:
                    return stop(o,w,1,0,2)
                cp=hex4(s,at)
                if cp==NONE:
                    return stop(o,w,1,0,2)
                at=at+4
                if cp>=55296 and cp<56320:
                    if end-at>=6 and byte(s,at)==92 and byte(s,at+1)==117:
                        low=hex4(s,at+2)
                        if low>=56320 and low<=57343:
                            cp=65536+((cp-55296)<<10)+low-56320
                            at=at+6
                    if cp>=55296 and cp<56320:
                        if get(w,184)==NONE:
                            put(w,184,get(w,80)+n)
                elif cp>=56320 and cp<=57343:
                    if cp>=56448 and cp<=56575:
                        cp=cp-56320
                        store(w,IO+n,cp)
                        n=n+1
                        cp=NONE
                    else:
                        if get(w,184)==NONE:
                            put(w,184,get(w,80)+n)
                if cp!=NONE:
                    if cp==0 and get(w,176)==NONE:
                        put(w,176,get(w,80)+n)
                    if get(w,80)+n==0 and cp==47:
                        put(w,168,1)
                    n=utf8(w,IO,n,cp)
                cp=NONE
            elif cp==98:
                cp=8
            elif cp==102:
                cp=12
            elif cp==110:
                cp=10
            elif cp==114:
                cp=13
            elif cp==116:
                cp=9
            elif cp!=34 and cp!=47 and cp!=92:
                return stop(o,w,1,0,2)
        if get(w,48)==1 and cp!=NONE and cp>=128:
            if cp<194 or cp>244:
                return stop(o,w,1,0,2)
            first=cp
            need=choose(cp<224,2,choose(cp<240,3,4))
            if need-1>end-at:
                return stop(o,w,1,0,2)
            cp=cp&choose(need==2,31,choose(need==3,15,7))
            k=1
            while k<need:
                c=byte(s,at)
                if c<128 or c>191 or (k==1 and ((first==224 and c<160) or (first==240 and c<144) or (first==244 and c>=144))):
                    return stop(o,w,1,0,2)
                cp=(cp<<6)|(c&63)
                at=at+1
                k=k+1
            if cp>=55296 and cp<=57343:
                if cp>=56448 and cp<=56575:
                    store(w,IO+n,cp-56320)
                    n=n+1
                    cp=NONE
                elif get(w,184)==NONE:
                    put(w,184,get(w,80)+n)
            if cp!=NONE:
                n=utf8(w,IO,n,cp)
                cp=NONE
        if cp!=NONE:
            if cp==0 and get(w,176)==NONE:
                put(w,176,get(w,80)+n)
            if get(w,80)+n==0 and cp==47:
                put(w,168,1)
            store(w,IO+n,cp)
            n=n+1
    put(w,64,at)
    put(w,88,n)
    return io(o,w,1,get(w,256),IO,n,get(w,80),choose(at<end,3,4))

def parts(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==20:
        if get(w,104)==0:
            return call(o,w,90,72,0,get(w,264),1033,15,0,0,0)
        return io(o,w,0,get(w,272),FRAME,40,(get(w,104)-1)*40,21)
    if phase==21:
        if get(w,FRAME)==1:
            put(w,104,get(w,104)-1)
            put(w,136,get(w,FRAME+32))
            put(w,144,get(w,80))
            return copy_file(o,w,get(w,264),0,get(w,256),get(w,80),get(w,96),60)
        if get(w,FRAME+24)>=get(w,FRAME+16):
            put(w,104,get(w,104)-1)
            put(w,0,20)
            return 3
        put(w,112,get(w,FRAME+8)+get(w,FRAME+24))
        put(w,120,0)
        return scan_part(o,w)
    if phase==22:
        size=get(w,816)
        i=0
        while i<size:
            if byte(w,IO+i)==47:
                put(w,120,get(w,120)+i)
                put(w,FRAME+24,get(w,FRAME+24)+i+1)
                return io(o,w,1,get(w,272),FRAME,40,(get(w,104)-1)*40,23)
            i=i+1
        put(w,120,get(w,120)+size)
        put(w,FRAME+24,get(w,FRAME+24)+size)
        if get(w,FRAME+24)<get(w,FRAME+16):
            return scan_part(o,w)
        return io(o,w,1,get(w,272),FRAME,40,(get(w,104)-1)*40,23)
    if phase==23:
        if get(w,120)==0:
            put(w,0,20)
            return 3
        bad=get(w,184)
        if get(w,112)<=bad and bad-get(w,112)<get(w,120):
            return unicode_begin(o,w)
        bad=get(w,176)
        if get(w,112)<=bad and bad-get(w,112)<get(w,120):
            return stop(o,w,2,0,23)
        if get(w,120)<=2:
            return io(o,w,0,get(w,256),IO,get(w,120),get(w,112),24)
        return candidate(o,w)
    if phase==24:
        if get(w,120)==1 and byte(w,IO)==46:
            put(w,0,20)
            return 3
        if get(w,120)==2 and byte(w,IO)==46 and byte(w,IO+1)==46:
            if get(w,96)==1:
                put(w,0,20)
                return 3
            put(w,152,get(w,96))
            return parent_scan(o,w)
        return candidate(o,w)
    if phase==25:
        size=get(w,816)
        i=size
        while i!=0:
            i=i-1
            if byte(w,IO+i)==47:
                n=get(w,152)-size+i
                put(w,96,choose(n==0,1,n))
                return call(o,w,26,77,0,get(w,264),get(w,96),0,0,0,0)
        put(w,152,get(w,152)-size)
        if get(w,152)==0:
            return stop(o,w,5,0,25)
        return parent_scan(o,w)
    if phase==26:
        if failed(r):
            return stop(o,w,4,r,26)
        put(w,0,20)
        return 3
    if phase==27:
        prefix=get(w,96)
        if prefix!=1:
            store(w,PATH+prefix,47)
            prefix=prefix+1
        return io(o,w,0,get(w,256),PATH+prefix,get(w,120),get(w,112),28)
    if phase==28:
        store(w,PATH+get(w,128),0)
        return call(o,w,29,262,60,AT_FDCWD,PATH,STAT,256,0,0)
    if phase==29:
        if failed(r) or (word_load(w,STAT+24)&61440)!=40960:
            return append_part(o,w)
        put(w,136,0)
        put(w,0,40)
        return 3
    return 4294967293


def unicode_begin(o:mutbuf,w:mutbuf) -> u32:
    put(w,560,0)
    put(w,568,0)
    put(w,576,0)
    put(w,584,0)
    put(w,744,0)
    put(w,760,0)
    return unicode_count(o,w,get(w,264),0,get(w,96),142)

def unicode_count(o:mutbuf,w:mutbuf,fd:u64,at:u64,n:u64,after:u64) -> u32:
    put(w,720,fd)
    put(w,728,at)
    put(w,736,n)
    put(w,752,after)
    return unicode_more(o,w)

def unicode_more(o:mutbuf,w:mutbuf) -> u32:
    if get(w,736)==0:
        put(w,0,get(w,752))
        return 3
    return io(o,w,0,get(w,720),IO,minimum(CAP,get(w,736)),get(w,728),141)

def utf8_count_width(w:mutbuf,at:u64,n:u64,last:u64) -> u64:
    ch=byte(w,at)
    if ch<194 or ch>244:
        return 1
    need=2
    if ch>=224:
        need=3
    if ch>=240:
        need=4
    if n<need:
        if last==0:
            return 0
        return 1
    c=byte(w,at+1)
    if c<128 or c>191 or (ch==224 and c<160) or (ch==237 and c>=160) or (ch==240 and c<144) or (ch==244 and c>=144):
        return 1
    i=2
    while i<need:
        c=byte(w,at+i)
        if c<128 or c>191:
            return 1
        i=i+1
    return need

def unicode_run(o:mutbuf,w:mutbuf) -> u32:
    if get(w,736)<3:
        return unicode_done(o,w)
    return io(o,w,0,get(w,256),IO,minimum(CAP,get(w,736)),get(w,728),143)

def unicode_done(o:mutbuf,w:mutbuf) -> u32:
    put(w,584,1)
    return stop(o,w,3,0,23)

def unicode_phase(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==141:
        n=get(w,816)
        last=choose(n==get(w,736),1,0)
        i=0
        while i<n:
            amount=utf8_count_width(w,IO+i,n-i,last)
            if amount==0:
                put(w,728,get(w,728)+i)
                put(w,736,get(w,736)-i)
                return unicode_more(o,w)
            put(w,744,get(w,744)+1)
            i=i+amount
        put(w,728,get(w,728)+i)
        put(w,736,get(w,736)-i)
        return unicode_more(o,w)
    if phase==142:
        if get(w,760)==0:
            put(w,760,1)
            if get(w,96)!=1:
                put(w,744,get(w,744)+1)
            return unicode_count(o,w,get(w,256),get(w,112),get(w,184)-get(w,112),142)
        put(w,568,get(w,744))
        put(w,576,get(w,744))
        put(w,728,get(w,184))
        put(w,736,get(w,120)-(get(w,184)-get(w,112)))
        return unicode_run(o,w)
    if phase==143:
        n=get(w,816)
        i=0
        while i+3<=n:
            a=byte(w,IO+i)
            b=byte(w,IO+i+1)
            c=byte(w,IO+i+2)
            if a!=237 or b<160 or b>191 or c<128 or c>191:
                return unicode_done(o,w)
            cp=((a&15)<<12)|((b&63)<<6)|(c&63)
            if cp>=56448 and cp<=56575:
                return unicode_done(o,w)
            if get(w,576)==get(w,568):
                put(w,560,cp)
            put(w,576,get(w,576)+1)
            i=i+3
        put(w,728,get(w,728)+i)
        put(w,736,get(w,736)-i)
        return unicode_run(o,w)
    return 4294967293

def scan_part(o:mutbuf,w:mutbuf) -> u32:
    size=minimum(CAP,get(w,FRAME+16)-get(w,FRAME+24))
    return io(o,w,0,get(w,256),IO,size,get(w,FRAME+8)+get(w,FRAME+24),22)

def parent_scan(o:mutbuf,w:mutbuf) -> u32:
    size=minimum(CAP,get(w,152))
    return io(o,w,0,get(w,264),IO,size,get(w,152)-size,25)

def candidate(o:mutbuf,w:mutbuf) -> u32:
    prefix=get(w,96)+choose(get(w,96)==1,0,1)
    if get(w,120)>NONE-prefix:
        return stop(o,w,5,0,27)
    put(w,128,prefix+get(w,120))
    if get(w,128)>4095:
        return append_part(o,w)
    return io(o,w,0,get(w,264),PATH,get(w,96),0,27)

def links(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==40:
        if get(w,136)==get(w,192):
            put(w,224,4096)
            return read_target(o,w)
        return io(o,w,0,get(w,280),SEEN,40,get(w,136)*40,41)
    if phase==41:
        if get(w,SEEN+8)!=get(w,128):
            put(w,136,get(w,136)+1)
            put(w,0,40)
            return 3
        return io(o,w,0,get(w,256),IO,get(w,128),get(w,SEEN),42)
    if phase==42:
        if equal(w,PATH,IO,get(w,128))==0:
            put(w,136,get(w,136)+1)
            put(w,0,40)
            return 3
        if get(w,SEEN+32)==0:
            return append_part(o,w)
        put(w,144,get(w,SEEN+16))
        put(w,152,get(w,SEEN+24))
        return call(o,w,43,77,0,get(w,264),0,0,0,0,0)
    if phase==43:
        if failed(r):
            return stop(o,w,4,r,43)
        return copy_file(o,w,get(w,256),get(w,144),get(w,264),0,get(w,152),44)
    if phase==44:
        put(w,96,get(w,152))
        put(w,0,20)
        return 3
    if phase==45:
        if failed(r):
            return append_part(o,w)
        if r==get(w,224):
            if get(w,224)>(length(w)-LINK)//2:
                return stop(o,w,5,0,45)
            put(w,224,get(w,224)*2)
            return read_target(o,w)
        put(w,232,r)
        put(w,240,get(w,80))
        return io(o,w,1,get(w,256),PATH,get(w,128),get(w,80),46)
    if phase==46:
        put(w,80,get(w,80)+get(w,128))
        put(w,248,get(w,80))
        return io(o,w,1,get(w,256),LINK,get(w,232),get(w,80),47)
    if phase==47:
        put(w,80,get(w,80)+get(w,232))
        put(w,SEEN,get(w,240))
        put(w,SEEN+8,get(w,128))
        put(w,SEEN+16,0)
        put(w,SEEN+24,0)
        put(w,SEEN+32,0)
        return io(o,w,1,get(w,280),SEEN,40,get(w,192)*40,48)
    if phase==48:
        zero(w,FRAME,40)
        put(w,FRAME,1)
        put(w,FRAME+32,get(w,192))
        put(w,192,get(w,192)+1)
        return io(o,w,1,get(w,272),FRAME,40,get(w,104)*40,49)
    if phase==49:
        put(w,104,get(w,104)+1)
        zero(w,FRAME,40)
        put(w,FRAME+8,get(w,248))
        put(w,FRAME+16,get(w,232))
        return io(o,w,1,get(w,272),FRAME,40,get(w,104)*40,50)
    if phase==50:
        put(w,104,get(w,104)+1)
        if get(w,232)!=0 and byte(w,LINK)==47:
            return call(o,w,51,77,0,get(w,264),1,0,0,0,0)
        put(w,0,20)
        return 3
    if phase==51:
        if failed(r):
            return stop(o,w,4,r,51)
        put(w,96,1)
        put(w,0,20)
        return 3
    return 4294967293

def read_target(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,45,267,60,AT_FDCWD,PATH,LINK,get(w,224),0,0)

def transitions(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==60:
        put(w,80,get(w,80)+get(w,96))
        return io(o,w,0,get(w,280),SEEN,40,get(w,136)*40,61)
    if phase==61:
        put(w,SEEN+16,get(w,144))
        put(w,SEEN+24,get(w,96))
        put(w,SEEN+32,1)
        return io(o,w,1,get(w,280),SEEN,40,get(w,136)*40,20)
    if phase==62:
        return copy_file(o,w,get(w,256),get(w,112),get(w,264),get(w,96)+choose(get(w,96)==1,0,1),get(w,120),63)
    if phase==63:
        put(w,96,get(w,128))
        put(w,0,20)
        return 3
    return 4294967293

def append_part(o:mutbuf,w:mutbuf) -> u32:
    if get(w,96)!=1:
        store(w,IO,47)
        return io(o,w,1,get(w,264),IO,1,get(w,96),62)
    put(w,0,62)
    return 3

def io(o:mutbuf,w:mutbuf,write:u64,fd:u64,buffer:u64,n:u64,offset:u64,next:u64) -> u32:
    put(w,800,write)
    put(w,808,fd)
    put(w,816,n)
    put(w,824,buffer)
    put(w,832,offset)
    put(w,840,next)
    put(w,848,0)
    return io_more(o,w)

def io_more(o:mutbuf,w:mutbuf) -> u32:
    if get(w,848)==get(w,816):
        put(w,0,get(w,840))
        put(w,8,0)
        return 3
    return call(o,w,800,choose(get(w,800)==0,17,18),12,get(w,808),get(w,824)+get(w,848),get(w,816)-get(w,848),get(w,832)+get(w,848),0,0)

def io_step(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if r==EINTR:
        return io_more(o,w)
    if failed(r) or r==0 or r>get(w,816)-get(w,848):
        return stop(o,w,4,r,800)
    put(w,848,get(w,848)+r)
    return io_more(o,w)

def copy_file(o:mutbuf,w:mutbuf,src:u64,si:u64,dst:u64,di:u64,n:u64,next:u64) -> u32:
    put(w,864,src)
    put(w,872,si)
    put(w,880,dst)
    put(w,888,di)
    put(w,896,n)
    put(w,904,0)
    put(w,912,next)
    return copy_more(o,w)

def copy_more(o:mutbuf,w:mutbuf) -> u32:
    if get(w,904)==get(w,896):
        put(w,0,get(w,912))
        put(w,8,0)
        return 3
    n=minimum(CAP,get(w,896)-get(w,904))
    put(w,920,n)
    return io(o,w,0,get(w,864),IO,n,get(w,872)+get(w,904),820)

def copy_step(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==820:
        return io(o,w,1,get(w,880),IO,get(w,920),get(w,888)+get(w,904),821)
    put(w,904,get(w,904)+get(w,920))
    return copy_more(o,w)

def stop(o:mutbuf,w:mutbuf,status:u64,raw:u64,where:u64) -> u32:
    if get(w,24)==0:
        put(w,24,status)
        put(w,32,raw)
        put(w,40,where)
    put(w,200,0)
    return close_next(o,w)

def close_next(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,200)
    while i<6:
        fd=get(w,256+i*8)
        put(w,200,i+1)
        if fd!=NONE and (i!=1 or get(w,24)!=0):
            put(w,256+i*8,NONE)
            return call(o,w,94,3,0,fd,0,0,0,0,0)
        i=i+1
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,get(w,24))
    put(o,16,get(w,32))
    put(o,24,get(w,40))
    put(o,32,NONE)
    if get(w,24)==3 and get(w,584)==1:
        put(o,56,get(w,560))
        put(o,64,get(w,568))
        put(o,72,get(w,576))
        put(o,80,1)
    if get(w,24)==0:
        put(o,32,get(w,264))
        put(o,40,get(w,96))
        put(o,48,15)
        put(w,264,NONE)
    return 0

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
    if phase==94:
        if failed(r):
            put(w,24,4)
            put(w,32,r)
            put(w,40,94)
            put(w,200,0)
        return close_next(o,w)
    return 4294967293

def hex4(s:readbuf,at:u64) -> u64:
    i=0
    v=0
    while i<4:
        d=byte(s,at+i)
        if d>=48 and d<=57:
            d=d-48
        elif d>=65 and d<=70:
            d=d-55
        elif d>=97 and d<=102:
            d=d-87
        else:
            return NONE
        v=v*16+d
        i=i+1
    return v

def utf8(w:mutbuf,base:u64,n:u64,cp:u64) -> u64:
    if cp<128:
        store(w,base+n,cp)
        return n+1
    if cp<2048:
        store(w,base+n,192|(cp>>6))
        store(w,base+n+1,128|(cp&63))
        return n+2
    if cp<65536:
        store(w,base+n,224|(cp>>12))
        store(w,base+n+1,128|((cp>>6)&63))
        store(w,base+n+2,128|(cp&63))
        return n+3
    store(w,base+n,240|(cp>>18))
    store(w,base+n+1,128|((cp>>12)&63))
    store(w,base+n+2,128|((cp>>6)&63))
    store(w,base+n+3,128|(cp&63))
    return n+4

def equal(w:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        if word_load(w,a+i)!=word_load(w,b+i):
            return 0
        i=i+8
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return 0
        i=i+1
    return 1

def call(o:mutbuf,w:mutbuf,next:u64,nr:u64,flags:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(w,0,next)
    put(o,0,nr)
    put(o,8,a)
    put(o,16,b)
    put(o,24,c)
    put(o,32,d)
    put(o,40,e)
    put(o,48,f)
    put(o,56,flags)
    return 1

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,value:u64) -> u64:
    word_store(w,at,value)
    return 0

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        word_store(w,at+i,0)
        i=i+8
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0

def minimum(a:u64,b:u64) -> u64:
    return choose(a<b,a,b)

def failed(value:u64) -> bool:
    return value>=18446744073709547520
'''
def program():
    s=SOURCE
    for n,v in C.items():s=re.sub(r'\b'+n+r'\b',str(v),s)
    return s
def main():
    d=document(program(),'native_path_resolve');p=ROOT/'examples/hia_bootstrap/native_path_resolve.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']))
if __name__=='__main__':main()
