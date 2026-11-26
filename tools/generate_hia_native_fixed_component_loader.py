"""Fixed installation-relative native component custody; development author only.

Product identity, symbol selection, admission and retirement are HIA policies.
The bridge supplies only real syscalls, fixed native roles and libc loader calls.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(Q=int.from_bytes(b'HIANLCQ1','little'),R=int.from_bytes(b'HIANLCR1','little'),
 TAG=int.from_bytes(b'HIANLCW1','little'),CATQ=int.from_bytes(b'HIANCAQ1','little'),CATR=int.from_bytes(b'HIANLCA1','little'),
 FSQ=int.from_bytes(b'HIASFL01','little'),FSR=int.from_bytes(b'HIASFR01','little'),
 MAPQ=int.from_bytes(b'HIAMAP01','little'),MAPR=int.from_bytes(b'HIAMPR01','little'),
 NODETAG=int.from_bytes(b'HIANLCN1','little'),BAD=4294967293,NONE=(1<<64)-1,
 WORK=25<<20,OUT=131072,PH=128,FB=136,OP=144,STATUS=152,DETAIL=160,KNOWN=168,
 CONSUMED=176,PENDING=184,DELIVERED=192,CAP=208,PID=240,HELD=248,
 SELFARG=512,ENTRYARG=520,NODEBUF=8192,RANDOM=8320,SMALL=8448,
 SAVE_NEXT=256,SAVE_PREV=264,CURSOR=272,RESULT_PTR=280,AFTER=288,
 SNAP_STATE=544,SNAP_COUNT=552,SNAP_EXPORT_N=560,SNAP_SOURCEFD=568,SNAP_EXPORTS=16384,
 CLOSE_SLOT=296,CLOSE_NEXT=304,ERROR_RETURN=312,
 LIB=72,MEMFD=80,ORIGINFD=88,SOURCEFD=96,MAPSFD=104,
 PATHMAP=112,PATHCAP=120,PATHLEN=128,FNAME=136,FNAME_N=144,DIR_N=152,
 FS_ACTIVE=160,HEAD=176,COUNT=184,PENDING_HEAD=192,ERROR=200,ERRNO=208,UNKNOWN=216,
 WRITE_AT=224,READ_AT=232,EXPORT_INDEX=240,EXPORT_AT=248,MAPS_N=256,
 PRODUCT_N=264,SOURCE_N=272,SOURCE_AT=280,ORIGIN_CLOSE=288,POST_CLOSE=296,
 PARSE_VALUE=6000,PARSE_FIELDS=6016,PARSE_MAJOR=6112,PARSE_MINOR=6120,
 EXPORTS=1024,EXPECTED=2048,FILE_N=2080,CAT_N=2088,EXPORT_N=2096,
 DLINFO=3200,STAT=3264,DIGEST=4096,SHAWORK=4224,FDPATH=8192,MAPSPATH=8448,
 MEMNAME=8512,NAME=16384,FSOUT=32768,MAPOUT=33792,MAPWORK=655360,
 CATALOG=65536,FRAME=131072,FSWORK=1048576,FSWORK_N=1056768,
 HASHINPUT=(6<<20)-1,HASHBUF=6<<20,MAPSDATA=8<<20,MAPSMAX=16<<20)
SOURCE=r'''
def loader(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PH)
    r=get(o,FB)
    if phase==0:
        return begin(s,o,w)
    if phase<10:
        return locking(s,o,w,phase,r)
    if phase<100:
        return loading(s,o,w,phase,r)
    if phase<200:
        return sealing(o,w,phase,r)
    if phase<300:
        return symbols(o,w,phase,r)
    if phase>=500 and phase<600:
        return capabilities(s,o,w,phase,r)
    if phase>=700 and phase<800:
        return retirement(o,w,phase,r)
    if phase==800 or phase==801:
        return closed_fd(o,w,phase,r)
    if phase==900:
        return system(o,901,202,1,40,129,2147483647,0,0,0)
    if phase==901:
        return reply(o,w)
    return BAD

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word(s,0)!=Q or word(s,8)>4 or length(o)<OUT or length(w)!=WORK:
        return BAD
    op=word(s,8)
    i=16
    while i<128:
        used=False
        if op==0 and i==16:
            used=True
        if op==3 and i>=24 and i<=40:
            used=True
        if used==False and word(s,i)!=0:
            return BAD
        i=i+8
    if op==0 and word(s,16)==0:
        return BAD
    clear(o,128,384)
    put(o,OP,op)
    put(o,KNOWN,1)
    return system(o,1,39,0,0,0,0,0,0,0)

def locking(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==1:
        if r==0 or failed(r):
            return fail_unlocked(o,w,1,r)
        put(o,PID,r)
        return atom(o,2)
    if phase==2:
        if r==0:
            put(o,HELD,1)
            return locked(s,o,w)
        if r!=1:
            return fail_unlocked(o,w,5,r)
        put(o,SMALL,0)
        put(o,SMALL+8,10000000)
        return system(o,3,202,193,40,128,1,SMALL,0,0)
    if phase==3:
        if failed(r) and r!=18446744073709551612 and r!=18446744073709551605 and r!=18446744073709551506:
            return fail_unlocked(o,w,1,r)
        return atom(o,2)
    return BAD

def locked(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    op=get(o,OP)
    if get(w,0)==0:
        if op!=0:
            return finish(o,w,8,0)
        i=0
        while i<4096:
            if i!=40 and get(w,i)!=0:
                return finish(o,w,8,i)
            i=i+8
        put(w,0,TAG)
        put(w,8,get(o,SELFARG))
        put(w,16,get(o,PID))
        put(w,24,get(o,ENTRYARG))
        put(w,32,1)
        put(w,56,word(s,16))
        put(w,MEMFD,NONE)
        put(w,ORIGINFD,NONE)
        put(w,SOURCEFD,NONE)
        put(w,MAPSFD,NONE)
        clear(w,FRAME,128)
        put(w,FRAME,CATQ)
        put(w,FRAME+8,word(s,16))
        return role(o,10,10,FRAME,128,CATALOG,65536,SMALL,128)
    if get(w,0)!=TAG or get(w,8)!=get(o,SELFARG) or get(w,16)!=get(o,PID) or get(w,24)!=get(o,ENTRYARG):
        return finish(o,w,8,0)
    if op==0:
        return finish(o,w,8,0)
    if get(w,UNKNOWN)!=0 or get(w,32)==5:
        put(o,KNOWN,0)
        put(o,PENDING,1)
        return finish(o,w,5,get(w,ERRNO))
    if op==1:
        if get(w,COUNT)!=0:
            return finish(o,w,6,get(w,COUNT))
        put(w,32,3)
        return cleanup(o,w)
    if op==4:
        if get(w,32)==4:
            return finish(o,w,0,0)
        if get(w,32)==2:
            return retry_nodes(o,w)
        if get(w,32)==3:
            return cleanup(o,w)
        return finish(o,w,8,0)
    if get(w,32)!=2:
        return finish(o,w,8,0)
    if op==2:
        return system(o,500,9,0,0,4096,3,34,NONE,0)
    put(o,CURSOR,get(w,HEAD))
    return lookup_cap(o,w)

def loading(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==10:
        if r<128 or r>65536 or get(w,CATALOG)!=CATR or get(w,CATALOG+8)!=get(w,56):
            return fail(o,w,3,r)
        put(w,CAT_N,r)
        n=get(w,CATALOG+16)
        pn=get(w,CATALOG+24)
        sn=get(w,CATALOG+32)
        count=get(w,CATALOG+40)
        if n<64 or n>67108864 or pn==0 or sn==0 or count==0 or count>128:
            return fail(o,w,3,10)
        if pn>r-128 or sn>r-128-pn or get(w,CATALOG+48)!=r-128 or get(w,CATALOG+56)!=0:
            return fail(o,w,3,11)
        i=96
        while i<128:
            if get(w,CATALOG+i)!=0:
                return fail(o,w,3,i)
            i=i+8
        if byte(w,CATALOG+128)==47 or byte(w,CATALOG+128+pn)==47:
            return fail(o,w,3,12)
        i=0
        while i<pn+sn:
            if byte(w,CATALOG+128+i)==0:
                return fail(o,w,3,13)
            i=i+1
        put(w,FILE_N,n)
        put(w,PRODUCT_N,pn)
        put(w,SOURCE_N,sn)
        put(w,SOURCE_AT,CATALOG+128+pn)
        put(w,EXPORT_N,count)
        put(w,EXPORT_AT,CATALOG+128+pn+sn)
        within(w,EXPECTED,CATALOG+64,32)
        put(o,PH,11)
        return 5
    if phase==11:
        if r!=1 or get(w,DLINFO)==0:
            return fail(o,w,1,11)
        put(w,FNAME,get(w,DLINFO))
        put(w,FNAME_N,0)
        put(w,DIR_N,0)
        return peek(o,12,get(w,FNAME))
    if phase==12:
        n=get(w,FNAME_N)
        if r==0:
            if n==0:
                return fail(o,w,1,12)
            dn=get(w,DIR_N)
            if dn==0:
                dn=1
            if dn>9223372036854771712:
                return fail(o,w,9,12)
            put(w,PATHCAP,(dn+4096)&18446744073709547520)
            return system(o,13,9,0,0,get(w,PATHCAP),3,34,NONE,0)
        if r==47:
            put(w,DIR_N,n+1)
        if n>=9223372036854771712 or get(w,FNAME)>NONE-n-1:
            return fail(o,w,9,12)
        put(w,FNAME_N,n+1)
        return peek(o,12,get(w,FNAME)+n+1)
    if phase==13:
        if failed(r):
            put(w,PATHCAP,0)
            return fail(o,w,9,r)
        put(w,PATHMAP,r)
        n=get(w,DIR_N)
        if n==0:
            store(o,SMALL,46)
            store(o,SMALL+1,0)
            put(w,PATHLEN,1)
            return memory(o,14,3,SMALL,0,r,2)
        put(w,PATHLEN,n)
        return memory(o,14,0,get(w,FNAME),0,r,n)
    if phase==14:
        if r!=0:
            return quarantine(o,w,14)
        store(o,SMALL,0)
        return memory(o,15,3,SMALL,0,get(w,PATHMAP)+get(w,PATHLEN),1)
    if phase==15:
        if r!=0:
            return quarantine(o,w,15)
        return system(o,16,257,0,18446744073709551516,get(w,PATHMAP),2686976,0,0,0)
    if phase==16:
        if failed(r):
            return fail(o,w,1,r)
        put(w,ORIGINFD,r)
        return system(o,17,5,4,r,STAT,0,0,0,0)
    if phase==17:
        if failed(r) or (get(w,STAT+24)&61440)!=16384:
            return fail(o,w,1,r)
        return system(o,18,11,0,get(w,PATHMAP),get(w,PATHCAP),0,0,0,0)
    if phase==18:
        if failed(r):
            return fail(o,w,1,r)
        put(w,PATHMAP,0)
        put(w,PATHCAP,0)
        n=get(w,SOURCE_N)
        if n>=65536:
            return fail(o,w,3,18)
        within(w,FRAME,get(w,SOURCE_AT),n)
        store(w,FRAME+n,0)
        return system(o,19,257,4,get(w,ORIGINFD),FRAME,2686976,0,0,0)
    if phase==19:
        if failed(r):
            return fail(o,w,1,r)
        put(w,SOURCEFD,r)
        return system(o,20,5,4,r,STAT,0,0,0,0)
    if phase==20:
        if failed(r) or (get(w,STAT+24)&61440)!=16384:
            return fail(o,w,1,r)
        n=fd_path(w,FRAME+192,get(w,ORIGINFD))
        store(w,FRAME+192+n,47)
        n=n+1
        within(w,FRAME+192+n,CATALOG+128,get(w,PRODUCT_N))
        n=n+get(w,PRODUCT_N)
        store(w,FRAME+192+n,0)
        clear(w,FRAME,192)
        put(w,FRAME,FSQ)
        put(w,FRAME+8,1)
        put(w,FRAME+16,67108864)
        put(w,FRAME+32,n)
        put(w,FS_ACTIVE,1)
        clear(w,FSWORK,8192)
        return role(o,21,11,FRAME,193+n,FSOUT,256,FSWORK,FSWORK_N)
    if phase==21:
        if r!=0 or get(w,FSOUT)!=FSR or get(w,FSOUT+168)!=1 or get(w,FSOUT+184)!=0:
            return quarantine(o,w,21)
        if get(w,FSOUT+8)!=0:
            return fail(o,w,1,get(w,FSOUT+16))
        if get(w,FSOUT+32)!=get(w,FILE_N) or get(w,FSOUT+40)==0 or get(w,FSOUT+48)<get(w,FILE_N):
            return fail(o,w,2,21)
        if equal(w,FSOUT+128,EXPECTED,32)==0:
            return fail(o,w,2,22)
        mem_name(w)
        return system(o,100,319,1,MEMNAME,3,0,0,0,0)
    return BAD

def sealing(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==100:
        if failed(r):
            return fail(o,w,1,r)
        put(w,MEMFD,r)
        put(w,WRITE_AT,0)
        return write_image(o,w)
    if phase==101:
        if r==18446744073709551612:
            return write_image(o,w)
        left=get(w,FILE_N)-get(w,WRITE_AT)
        if failed(r) or r==0 or r>left:
            return fail(o,w,1,r)
        put(w,WRITE_AT,get(w,WRITE_AT)+r)
        return write_image(o,w)
    if phase==102:
        if r!=0:
            return fail(o,w,1,r)
        return system(o,103,72,0,get(w,MEMFD),1034,0,0,0,0)
    if phase==103:
        if r!=15:
            return fail(o,w,2,r)
        return system(o,104,5,4,get(w,MEMFD),STAT,0,0,0,0)
    if phase==104:
        if failed(r) or (get(w,STAT+24)&61440)!=32768 or get(w,STAT+16)!=0 or get(w,STAT+48)!=get(w,FILE_N):
            return fail(o,w,2,r)
        clear(w,SHAWORK,1184)
        put(w,READ_AT,0)
        store(w,HASHINPUT,0)
        return role(o,105,12,HASHINPUT,1,DIGEST,32,SHAWORK,1184)
    if phase==105:
        if r!=0:
            return fail(o,w,2,r)
        return read_sealed(o,w)
    if phase==106:
        if r==18446744073709551612:
            return read_sealed(o,w)
        n=get(w,FILE_N)-get(w,READ_AT)
        if n>1048576:
            n=1048576
        if failed(r) or r==0 or r>n:
            return fail(o,w,1,r)
        put(w,WRITE_AT,r)
        store(w,HASHINPUT,1)
        return role(o,107,12,HASHINPUT,1+r,DIGEST,32,SHAWORK,1184)
    if phase==107:
        if r!=0:
            return fail(o,w,2,r)
        put(w,READ_AT,get(w,READ_AT)+get(w,WRITE_AT))
        return read_sealed(o,w)
    if phase==108:
        if r!=32 or equal(w,DIGEST,EXPECTED,32)==0:
            return fail(o,w,2,r)
        n=fd_path(w,FDPATH,get(w,MEMFD))
        store(w,FDPATH+n,0)
        put(o,PH,109)
        return 8
    if phase==109:
        if r==0:
            return fail(o,w,4,109)
        put(w,LIB,r)
        put(w,EXPORT_INDEX,0)
        return next_symbol(o,w)
    return BAD

def write_image(o:mutbuf,w:mutbuf) -> u32:
    at=get(w,WRITE_AT)
    n=get(w,FILE_N)
    if at==n:
        return system(o,102,72,0,get(w,MEMFD),1033,15,0,0,0)
    return system(o,101,1,0,get(w,MEMFD),get(w,FSOUT+40)+at,n-at,0,0,0)

def read_sealed(o:mutbuf,w:mutbuf) -> u32:
    at=get(w,READ_AT)
    n=get(w,FILE_N)-at
    if n==0:
        store(w,HASHINPUT,2)
        return role(o,108,12,HASHINPUT,1,DIGEST,32,SHAWORK,1184)
    if n>1048576:
        n=1048576
    return system(o,106,17,4,get(w,MEMFD),HASHBUF,n,at,0,0)

def next_symbol(o:mutbuf,w:mutbuf) -> u32:
    i=get(w,EXPORT_INDEX)
    at=get(w,EXPORT_AT)
    end=CATALOG+get(w,CAT_N)
    if i==get(w,EXPORT_N):
        if at!=end:
            return fail(o,w,3,200)
        maps_path(w)
        return system(o,201,257,4,18446744073709551516,MAPSPATH,524288,0,0,0)
    if at>end or end-at<8:
        return fail(o,w,3,201)
    n=get(w,at)
    if n==0 or n>128 or n>end-at-8:
        return fail(o,w,3,202)
    j=0
    while j<n:
        ch=byte(w,at+8+j)
        if ch==0 or ch>127:
            return fail(o,w,3,203)
        store(w,NAME+j,ch)
        j=j+1
    store(w,NAME+n,0)
    put(w,EXPORT_AT,at+8+n)
    put(o,PH,200)
    return 9

def symbols(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==200:
        if r==0:
            return fail(o,w,4,200)
        put(w,EXPORTS+get(w,EXPORT_INDEX)*8,r)
        put(w,EXPORT_INDEX,get(w,EXPORT_INDEX)+1)
        return next_symbol(o,w)
    if phase==201:
        if failed(r):
            return fail(o,w,1,r)
        put(w,MAPSFD,r)
        put(w,MAPS_N,0)
        return read_maps(o,w)
    if phase==202:
        if r==18446744073709551612:
            return read_maps(o,w)
        if failed(r) or r>MAPSMAX+1-get(w,MAPS_N):
            return fail(o,w,1,r)
        if r==0:
            return close_fd(o,w,203,MAPSFD)
        put(w,MAPS_N,get(w,MAPS_N)+r)
        if get(w,MAPS_N)>MAPSMAX:
            return fail(o,w,4,202)
        return read_maps(o,w)
    if phase==203:
        clear(w,MAPWORK,8192)
        put(w,MAPWORK,MAPQ)
        put(w,MAPWORK+8,get(w,EXPORT_N))
        dev=get(w,STAT)
        put(w,MAPWORK+16,((dev&1048320)>>8)|((dev&18446726481523507200)>>32))
        put(w,MAPWORK+24,(dev&255)|((dev&17592184995840)>>12))
        put(w,MAPWORK+32,get(w,STAT+8))
        put(w,MAPWORK+40,get(w,FILE_N))
        put(w,MAPWORK+48,4300)
        within(w,MAPWORK+64,EXPORTS,get(w,EXPORT_N)*8)
        return role(o,204,13,MAPSDATA,get(w,MAPS_N),MAPOUT,16+get(w,EXPORT_N)*8,MAPWORK,8192)
    if phase==204:
        if r!=0 or get(w,MAPOUT)!=MAPR or get(w,MAPOUT+8)!=get(w,EXPORT_N):
            return fail(o,w,4,r)
        return retire_capture(o,w,205)
    if phase==205:
        if stable_retired(o,w,r)==0:
            return finish(o,w,1,get(w,ERRNO))
        put(w,32,2)
        return finish(o,w,0,0)
    return BAD

def read_maps(o:mutbuf,w:mutbuf) -> u32:
    n=get(w,MAPS_N)
    return system(o,202,0,4,get(w,MAPSFD),MAPSDATA+n,MAPSMAX+1-n,0,0,0)

def capabilities(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==500:
        if failed(r):
            return finish(o,w,9,r)
        put(o,RESULT_PTR,r)
        clear(o,NODEBUF,128)
        put(o,NODEBUF,NODETAG)
        put(o,NODEBUF+8,get(w,HEAD))
        put(o,NODEBUF+16,0)
        put(o,NODEBUF+40,get(w,8))
        put(o,NODEBUF+48,get(w,16))
        return system(o,501,318,3,RANDOM,16,0,0,0,0)
    if phase==501:
        if r!=16 or (get(o,RANDOM)==0 and get(o,RANDOM+8)==0):
            put(o,STATUS,1)
            put(o,DETAIL,r)
            put(o,NODEBUF+8,get(w,PENDING_HEAD))
            put(o,NODEBUF+56,1)
            return memory(o,509,3,NODEBUF,0,get(o,RESULT_PTR),128)
        put(o,NODEBUF+24,get(o,RANDOM))
        put(o,NODEBUF+32,get(o,RANDOM+8))
        return memory(o,502,3,NODEBUF,0,get(o,RESULT_PTR),128)
    if phase==502:
        if r!=0:
            return quarantine(o,w,502)
        if get(w,HEAD)!=0:
            put(o,SMALL,get(o,RESULT_PTR))
            return memory(o,503,3,SMALL,0,get(w,HEAD)+16,8)
        return again(o,503)
    if phase==503:
        if r!=0:
            return quarantine(o,w,503)
        put(w,HEAD,get(o,RESULT_PTR))
        put(w,COUNT,get(w,COUNT)+1)
        put(o,CAP,get(o,RESULT_PTR))
        put(o,CAP+8,get(o,NODEBUF+24))
        put(o,CAP+16,get(o,NODEBUF+32))
        put(o,DELIVERED,1)
        put(o,CONSUMED,1)
        return finish(o,w,0,0)
    if phase==509:
        if r!=0:
            return quarantine(o,w,509)
        put(w,PENDING_HEAD,get(o,RESULT_PTR))
        return retry_nodes(o,w)
    if phase==510:
        if r!=0 or get(o,NODEBUF)!=NODETAG or get(o,NODEBUF+40)!=get(w,8) or get(o,NODEBUF+48)!=get(w,16) or get(o,NODEBUF+56)!=0:
            return quarantine(o,w,510)
        if get(o,CURSOR)!=word(s,24):
            put(o,CURSOR,get(o,NODEBUF+8))
            return lookup_cap(o,w)
        if get(o,NODEBUF+24)!=word(s,32) or get(o,NODEBUF+32)!=word(s,40):
            return finish(o,w,7,0)
        put(o,SAVE_NEXT,get(o,NODEBUF+8))
        put(o,SAVE_PREV,get(o,NODEBUF+16))
        if get(o,SAVE_PREV)!=0:
            put(o,SMALL,get(o,SAVE_NEXT))
            return memory(o,511,3,SMALL,0,get(o,SAVE_PREV)+8,8)
        put(w,HEAD,get(o,SAVE_NEXT))
        return again(o,511)
    if phase==511:
        if r!=0:
            return quarantine(o,w,511)
        if get(o,SAVE_NEXT)!=0:
            put(o,SMALL,get(o,SAVE_PREV))
            return memory(o,512,3,SMALL,0,get(o,SAVE_NEXT)+16,8)
        return again(o,512)
    if phase==512:
        if r!=0 or get(w,COUNT)==0:
            return quarantine(o,w,512)
        put(w,COUNT,get(w,COUNT)-1)
        put(o,CONSUMED,1)
        put(o,NODEBUF+8,get(w,PENDING_HEAD))
        put(o,NODEBUF+16,0)
        put(o,NODEBUF+56,1)
        return memory(o,513,3,NODEBUF,0,get(o,CURSOR),128)
    if phase==513:
        if r!=0:
            return quarantine(o,w,513)
        put(w,PENDING_HEAD,get(o,CURSOR))
        return retry_nodes(o,w)
    if phase==520:
        if r!=0 or get(o,NODEBUF)!=NODETAG or get(o,NODEBUF+40)!=get(w,8) or get(o,NODEBUF+48)!=get(w,16) or get(o,NODEBUF+56)!=1:
            return quarantine(o,w,520)
        put(o,SAVE_NEXT,get(o,NODEBUF+8))
        return system(o,521,11,0,get(w,PENDING_HEAD),4096,0,0,0,0)
    if phase==521:
        if failed(r):
            put(o,PENDING,1)
            return finish(o,w,1,r)
        put(w,PENDING_HEAD,get(o,SAVE_NEXT))
        return retry_nodes(o,w)
    return BAD

def lookup_cap(o:mutbuf,w:mutbuf) -> u32:
    if get(o,CURSOR)==0:
        return finish(o,w,7,0)
    return memory(o,510,0,get(o,CURSOR),3,NODEBUF,128)

def retry_nodes(o:mutbuf,w:mutbuf) -> u32:
    if get(w,PENDING_HEAD)!=0:
        return memory(o,520,0,get(w,PENDING_HEAD),3,NODEBUF,128)
    if get(w,32)==3:
        return cleanup(o,w)
    return finish(o,w,get(o,STATUS),get(o,DETAIL))

def retirement(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==700:
        if r!=0:
            return quarantine(o,w,700)
        put(w,LIB,0)
        clear(w,EXPORTS,1024)
        put(w,POST_CLOSE,1)
        return cleanup(o,w)
    if phase==701:
        return cleanup(o,w)
    if phase==702:
        if failed(r):
            put(o,PENDING,1)
            return finish(o,w,1,r)
        put(w,PATHMAP,0)
        put(w,PATHCAP,0)
        return cleanup(o,w)
    if phase==703:
        if stable_retired(o,w,r)==0:
            return finish(o,w,1,get(w,ERRNO))
        return cleanup(o,w)
    if phase==710:
        if failed(r):
            put(o,PENDING,1)
            return finish(o,w,1,r)
        put(w,MAPSFD,r)
        put(w,MAPS_N,0)
        return read_post_close_maps(o,w)
    if phase==711:
        if r==18446744073709551612:
            return read_post_close_maps(o,w)
        if failed(r) or r>MAPSMAX+1-get(w,MAPS_N):
            put(o,PENDING,1)
            return finish(o,w,1,r)
        if r==0:
            return close_fd(o,w,712,MAPSFD)
        put(w,MAPS_N,get(w,MAPS_N)+r)
        if get(w,MAPS_N)>MAPSMAX:
            put(o,PENDING,1)
            return finish(o,w,1,711)
        return read_post_close_maps(o,w)
    if phase==712:
        found=mapping_present(w)
        if found==1:
            return quarantine(o,w,712)
        if found!=0:
            put(o,PENDING,1)
            return finish(o,w,1,712)
        put(w,POST_CLOSE,0)
        return cleanup(o,w)
    return BAD

def cleanup(o:mutbuf,w:mutbuf) -> u32:
    if get(w,UNKNOWN)!=0:
        return quarantine(o,w,get(w,ERRNO))
    if get(w,PENDING_HEAD)!=0:
        return retry_nodes(o,w)
    if get(w,LIB)!=0:
        put(o,PH,700)
        return 14
    if get(w,POST_CLOSE)!=0:
        if get(w,MAPSFD)!=NONE:
            return close_fd(o,w,701,MAPSFD)
        maps_path(w)
        return system(o,710,257,4,18446744073709551516,MAPSPATH,524288,0,0,0)
    if get(w,FS_ACTIVE)!=0:
        return retire_capture(o,w,703)
    if get(w,MAPSFD)!=NONE:
        return close_fd(o,w,701,MAPSFD)
    if get(w,MEMFD)!=NONE:
        return close_fd(o,w,701,MEMFD)
    if get(w,SOURCEFD)!=NONE:
        return close_fd(o,w,701,SOURCEFD)
    if get(w,ORIGINFD)!=NONE:
        return close_fd(o,w,701,ORIGINFD)
    if get(w,PATHMAP)!=0:
        return system(o,702,11,0,get(w,PATHMAP),get(w,PATHCAP),0,0,0,0)
    put(w,32,4)
    if get(o,OP)==1:
        put(o,CONSUMED,1)
    put(o,PENDING,0)
    return finish(o,w,get(o,STATUS),get(o,DETAIL))


def read_post_close_maps(o:mutbuf,w:mutbuf) -> u32:
    n=get(w,MAPS_N)
    return system(o,711,0,4,get(w,MAPSFD),MAPSDATA+n,MAPSMAX+1-n,0,0,0)

def mapping_present(w:mutbuf) -> u64:
    at=0
    end=get(w,MAPS_N)
    while at<end:
        first=at
        while at<end and byte(w,MAPSDATA+at)!=10 and byte(w,MAPSDATA+at)!=13:
            at=at+1
        last=at
        if at<end:
            sep=byte(w,MAPSDATA+at)
            at=at+1
            if sep==13 and at<end and byte(w,MAPSDATA+at)==10:
                at=at+1
        if first==last:
            return 2
        p=first
        field=0
        while field<5:
            while p<last and maps_space(byte(w,MAPSDATA+p))==1:
                p=p+1
            if p==last:
                return 2
            start=p
            while p<last and maps_space(byte(w,MAPSDATA+p))==0:
                p=p+1
            put(w,PARSE_FIELDS+field*16,start)
            put(w,PARSE_FIELDS+field*16+8,p)
            field=field+1
        p=get(w,PARSE_FIELDS+48)
        stop=get(w,PARSE_FIELDS+56)
        colon=NONE
        i=p
        while i<stop:
            if byte(w,MAPSDATA+i)==58:
                if colon!=NONE:
                    return 2
                colon=i
            i=i+1
        if colon==NONE:
            return 2
        if maps_uint(w,p,colon,16)!=0:
            return 2
        put(w,PARSE_MAJOR,get(w,PARSE_VALUE))
        if maps_uint(w,colon+1,stop,16)!=0:
            return 2
        put(w,PARSE_MINOR,get(w,PARSE_VALUE))
        if maps_uint(w,get(w,PARSE_FIELDS+64),get(w,PARSE_FIELDS+72),10)!=0:
            return 2
        dev=get(w,STAT)
        major=((dev&1048320)>>8)|((dev&18446726481523507200)>>32)
        minor=(dev&255)|((dev&17592184995840)>>12)
        if get(w,PARSE_MAJOR)==major and get(w,PARSE_MINOR)==minor and get(w,PARSE_VALUE)==get(w,STAT+8):
            return 1
    return 0

def maps_space(value:u64) -> u64:
    if value==32 or value==9 or value==11 or value==12:
        return 1
    return 0

def maps_uint(w:mutbuf,first:u64,last:u64,base:u64) -> u64:
    if first==last:
        return 1
    value=0
    max=1844674407370955161
    tail=5
    if base==16:
        max=1152921504606846975
        tail=15
    while first<last:
        ch=byte(w,MAPSDATA+first)
        digit=16
        if ch>=48 and ch<=57:
            digit=ch-48
        if ch>=65 and ch<=70:
            digit=ch-55
        if ch>=97 and ch<=102:
            digit=ch-87
        if digit>=base or value>max or (value==max and digit>tail):
            return 1
        value=value*base+digit
        first=first+1
    put(w,PARSE_VALUE,value)
    return 0

def retire_capture(o:mutbuf,w:mutbuf,next:u64) -> u32:
    clear(w,FRAME,192)
    put(w,FRAME,FSQ)
    put(w,FRAME+8,3)
    return role(o,next,11,FRAME,192,FSOUT,256,FSWORK,FSWORK_N)

def stable_retired(o:mutbuf,w:mutbuf,r:u64) -> u64:
    if r!=0 or get(w,FSOUT)!=FSR or get(w,FSOUT+168)!=1 or get(w,FSOUT+184)!=0:
        put(w,UNKNOWN,1)
        put(w,32,5)
        put(o,KNOWN,0)
        put(o,PENDING,1)
        put(w,ERRNO,703)
        return 0
    if get(w,FSOUT+160)!=0 or get(w,FSOUT+176)!=1:
        put(o,PENDING,1)
        put(w,ERRNO,get(w,FSOUT+208))
        put(w,32,3)
        return 0
    put(w,FS_ACTIVE,0)
    return 1

def close_fd(o:mutbuf,w:mutbuf,next:u64,slot:u64) -> u32:
    put(o,CLOSE_SLOT,slot)
    put(o,CLOSE_NEXT,next)
    return system(o,800,436,0,get(w,slot),get(w,slot),0,0,0,0)

def closed_fd(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    slot=get(o,CLOSE_SLOT)
    if phase==800 and r==18446744073709551578:
        return system(o,801,3,0,get(w,slot),0,0,0,0,0)
    if r!=0:
        put(o,PENDING,1)
        if phase==801:
            put(w,slot,NONE)
            return quarantine(o,w,r)
        put(w,32,3)
        return finish(o,w,1,r)
    put(w,slot,NONE)
    return again(o,get(o,CLOSE_NEXT))

def fail(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    if get(o,STATUS)==0:
        put(o,STATUS,status)
        put(o,DETAIL,detail)
    if get(w,ERROR)==0:
        put(w,ERROR,status)
        put(w,ERRNO,detail)
    put(w,32,3)
    return cleanup(o,w)

def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(w,UNKNOWN,1)
    put(w,32,5)
    put(w,ERRNO,detail)
    put(o,KNOWN,0)
    put(o,PENDING,1)
    return finish(o,w,5,detail)

def fail_unlocked(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(o,STATUS,status)
    put(o,DETAIL,detail)
    snapshot(o,w)
    return reply(o,w)

def finish(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    if get(o,STATUS)==0:
        put(o,STATUS,status)
        put(o,DETAIL,detail)
    if get(w,32)==3 or get(w,32)==5 or get(w,PENDING_HEAD)!=0:
        put(o,PENDING,1)
    snapshot(o,w)
    put(o,PH,900)
    return 3

def snapshot(o:mutbuf,w:mutbuf) -> u64:
    put(o,SNAP_STATE,get(w,32))
    put(o,SNAP_COUNT,get(w,COUNT))
    put(o,SNAP_EXPORT_N,0)
    put(o,SNAP_SOURCEFD,NONE)
    if get(o,DELIVERED)==1:
        put(o,SNAP_EXPORT_N,get(w,EXPORT_N))
        put(o,SNAP_SOURCEFD,get(w,SOURCEFD))
        i=0
        while i<get(w,EXPORT_N):
            put(o,SNAP_EXPORTS+i*8,get(w,EXPORTS+i*8))
            i=i+1
    return 0

def reply(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,128)
    put(o,0,R)
    put(o,8,get(o,STATUS))
    put(o,16,get(o,SNAP_STATE))
    put(o,80,get(o,PENDING))
    put(o,88,get(o,KNOWN))
    put(o,96,get(o,CONSUMED))
    put(o,104,choose(get(o,SNAP_STATE)==4,1,0))
    put(o,112,get(o,DETAIL))
    put(o,120,get(o,SNAP_COUNT))
    if get(o,DELIVERED)==1:
        put(o,24,get(o,CAP))
        put(o,32,get(o,CAP+8))
        put(o,40,get(o,CAP+16))
        put(o,48,get(o,SNAP_EXPORT_N))
        put(o,56,get(o,SNAP_SOURCEFD))
        i=0
        n=get(o,SNAP_EXPORT_N)
        while i<n:
            put(o,128+i*8,get(o,SNAP_EXPORTS+i*8))
            i=i+1
    return 0

def atom(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    return 2

def again(o:mutbuf,next:u64) -> u32:
    put(o,PH,next)
    put(o,FB,0)
    return 15

def peek(o:mutbuf,next:u64,pointer:u64) -> u32:
    put(o,PH,next)
    put(o,0,pointer)
    return 6

def memory(o:mutbuf,next:u64,sk:u64,sa:u64,dk:u64,da:u64,n:u64) -> u32:
    put(o,PH,next)
    put(o,0,sk)
    put(o,8,sa)
    put(o,16,dk)
    put(o,24,da)
    put(o,32,n)
    return 7

def role(o:mutbuf,next:u64,action:u64,si:u64,sn:u64,oi:u64,on:u64,wi:u64,wn:u64) -> u32:
    put(o,PH,next)
    put(o,0,si)
    put(o,8,sn)
    put(o,16,oi)
    put(o,24,on)
    put(o,32,wi)
    put(o,40,wn)
    return action

def system(o:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PH,next)
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def fd_path(w:mutbuf,at:u64,fd:u64) -> u64:
    store(w,at,47)
    store(w,at+1,112)
    store(w,at+2,114)
    store(w,at+3,111)
    store(w,at+4,99)
    store(w,at+5,47)
    store(w,at+6,115)
    store(w,at+7,101)
    store(w,at+8,108)
    store(w,at+9,102)
    store(w,at+10,47)
    store(w,at+11,102)
    store(w,at+12,100)
    store(w,at+13,47)
    n=0
    x=fd
    while x>=10:
        n=n+1
        x=(x*3435973837)>>35
    size=15+n
    while n>0:
        store(w,at+14+n,48+fd-((fd*3435973837)>>35)*10)
        fd=(fd*3435973837)>>35
        n=n-1
    store(w,at+14,48+fd)
    return size

def maps_path(w:mutbuf) -> u64:
    put(w,MAPSPATH,0x65732f636f72702f)
    put(w,MAPSPATH+8,0x007370616d2f666c)
    return 0

def mem_name(w:mutbuf) -> u64:
    put(w,MEMNAME,0x656c75646f6d6169)
    store(w,MEMNAME+8,0)
    return 0

def failed(value:u64) -> bool:
    return value>=18446744073709547521

def equal(w:mutbuf,a:u64,b:u64,n:u64) -> u64:
    i=0
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return 0
        i=i+1
    return 1

def within(w:mutbuf,to:u64,from_at:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        put(w,to+i,get(w,from_at+i))
        i=i+8
    while i<n:
        store(w,to+i,byte(w,from_at+i))
        i=i+1
    return 0

def clear(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0

def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value

def word(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
'''
def source_program():
    source=SOURCE
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    tree=document(source_program(),'native_fixed_component_loader')
    path=ROOT/'examples/hia_bootstrap/native_fixed_component_loader.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
