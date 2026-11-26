"""HIA POSIX shutil.which semantics over libc's live environment.

Only platform environment reads, fixed buffer views and syscalls cross the
mechanical boundary. Candidate construction, duplicate PATH entries, access
checks and real mapping custody are HIA decisions.
"""
from tools.generate_hia_clang_capture_common import C,write_module
C.update(WH_REQUEST=int.from_bytes(b'HIACWH01','little'),WH_REPLY=int.from_bytes(b'HIACWR01','little'),
 WH_CONTEXT=int.from_bytes(b'HIACWW01','little'),WSELF=32,WPID=40,WTAG=48,WEXTENT=56,WBASE=64,
 NAME_N=72,DIRECT=80,ENV_PTR=88,ENV_IDX=96,ENV_ELEM=104,ENV_MATCH=112,ENV_CHAR=120,
 PATH_PTR=128,PATH_N=136,SCAN=144,SEGMAX=152,SEGLEN=160,SEGCOUNT=168,
 PATH_MAP=176,PATH_CAP=184,TABLE_SLOTS=200,TABLE_OFF=208,
 CAND_MAP=216,CAND_CAP=224,CAND_N=232,CURSOR=240,START=248,NEXT=256,
 W_PENDING=280,RETIRING=288,W_UNKNOWN=296,CLEAN_INDEX=304,W_CLEAN_ERR=312,
 BORROW_S=320,BORROW_SN=328,BORROW_O=336,BORROW_ON=344,DONE=352,
 W_STAT=512,DEFAULT=1024,DEFAULT_LO=int.from_bytes(b'/bin:/us','little'),DEFAULT_HI=int.from_bytes(b'r/bin','little'))
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        put(w,WPID,r)
        if get(w,DIRECT)==2:
            return finish(o,w)
        if get(w,DIRECT)!=0:
            put(w,CAND_CAP,(get(w,NAME_N)+4096)&18446744073709547520)
            return allocate_candidate(o,w)
        return environment(w)
    if phase>=2 and phase<=12:
        return scan_environment(s,o,w,phase,r)
    if phase>=20 and phase<=40:
        return prepare_candidate(s,o,w,phase,r)
    if phase>=41 and phase<=44:
        return check_candidate(o,w,phase,r)
    if phase==900 or phase==901:
        return retire(o,w,phase,r)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<32 or length(o)<128 or length(w)<4096:
        return 4294967293
    if word(s,0)!=WH_REQUEST or word(s,8)!=0 or word(s,16)!=length(s)-32 or word(s,24)!=0:
        return 4294967293
    put(w,WSELF,get(w,WBASE))
    put(w,WTAG,WH_CONTEXT)
    put(w,NAME_N,length(s)-32)
    put(w,ERROR,1)
    i=32
    while i<length(s) and get(w,DIRECT)!=2:
        c=byte(s,i)
        if c==0:
            put(w,DIRECT,2)
        if c==47:
            put(w,DIRECT,1)
        i=i+1
    return call(o,w,1,39,0,0,0,0,0,0,0)

def environment(w:mutbuf) -> u32:
    put(w,PHASE,2)
    return 5

def peek(o:mutbuf,w:mutbuf,next:u64,address:u64,n:u64) -> u32:
    put(w,PHASE,next)
    put(o,0,address)
    put(o,8,n)
    return 6

def scan_environment(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==2:
        put(w,ENV_PTR,r)
        if r==0:
            return default_path(o,w)
        return peek(o,w,3,r,8)
    if phase==3:
        if r==0:
            return default_path(o,w)
        put(w,ENV_ELEM,r)
        put(w,ENV_CHAR,0)
        put(w,ENV_MATCH,1)
        return peek(o,w,4,r,1)
    if phase==4:
        i=get(w,ENV_CHAR)
        expected=80
        if i==1:
            expected=65
        elif i==2:
            expected=84
        elif i==3:
            expected=72
        elif i==4:
            expected=61
        if r!=expected:
            put(w,ENV_IDX,get(w,ENV_IDX)+1)
            return peek(o,w,3,get(w,ENV_PTR)+get(w,ENV_IDX)*8,8)
        if i<4:
            put(w,ENV_CHAR,i+1)
            return peek(o,w,4,get(w,ENV_ELEM)+i+1,1)
        put(w,PATH_PTR,get(w,ENV_ELEM)+5)
        put(w,SEGCOUNT,1)
        return peek(o,w,5,get(w,PATH_PTR),1)
    if phase==5:
        if r==0:
            if get(w,SCAN)==0:
                return finish(o,w)
            if get(w,SEGLEN)>get(w,SEGMAX):
                put(w,SEGMAX,get(w,SEGLEN))
            put(w,PATH_N,get(w,SCAN))
            return allocate_path(o,w)
        if r==58:
            put(w,SEGCOUNT,get(w,SEGCOUNT)+1)
            if get(w,SEGLEN)>get(w,SEGMAX):
                put(w,SEGMAX,get(w,SEGLEN))
            put(w,SEGLEN,0)
        else:
            put(w,SEGLEN,get(w,SEGLEN)+1)
        put(w,SCAN,get(w,SCAN)+1)
        return peek(o,w,5,get(w,PATH_PTR)+get(w,SCAN),1)
    if phase==6:
        if failed(r):
            return fail(o,w,3,errno(r))
        put(w,PATH_MAP,r)
        return borrowed(w,7,get(w,PATH_PTR),get(w,PATH_N),r,get(w,PATH_CAP))
    if phase==7:
        n=get(w,PATH_N)
        if n>length(s) or n>=length(o):
            return 4294967293
        copy_view(s,0,o,0,n)
        store(o,n,0)
        return jump(w,8)
    if phase==8:
        total=get(w,SEGMAX)+get(w,NAME_N)+2
        if total<get(w,NAME_N) or total>9223372036854771712:
            return fail(o,w,3,12)
        put(w,CAND_CAP,(total+4095)&18446744073709547520)
        return allocate_candidate(o,w)
    return 4294967293

def default_path(o:mutbuf,w:mutbuf) -> u32:
    put(w,DEFAULT,DEFAULT_LO)
    put(w,DEFAULT+8,DEFAULT_HI)
    put(w,PATH_PTR,get(w,WBASE)+DEFAULT)
    put(w,PATH_N,13)
    put(w,SEGCOUNT,2)
    put(w,SEGMAX,8)
    return allocate_path(o,w)

def allocate_path(o:mutbuf,w:mutbuf) -> u32:
    slots=2
    if get(w,SEGCOUNT)>72057594037927936:
        return fail(o,w,3,12)
    while slots<get(w,SEGCOUNT)*2:
        slots=slots*2
    put(w,TABLE_SLOTS,slots)
    at=(get(w,PATH_N)+8)&18446744073709551608
    if at<get(w,PATH_N) or at>9223372036854771712-slots*32:
        return fail(o,w,3,12)
    put(w,TABLE_OFF,at)
    put(w,PATH_CAP,(at+slots*32+4095)&18446744073709547520)
    return call(o,w,6,9,0,get(w,PATH_CAP),3,34,NONE,0,0)

def allocate_candidate(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,20,9,0,get(w,CAND_CAP),3,34,NONE,0,0)

def borrowed(w:mutbuf,next:u64,source:u64,n:u64,dest:u64,cap:u64) -> u32:
    put(w,PHASE,next)
    put(w,BORROW_S,source)
    put(w,BORROW_SN,n)
    put(w,BORROW_O,dest)
    put(w,BORROW_ON,cap)
    return 14

def prepare_candidate(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==20:
        if failed(r):
            return fail(o,w,3,errno(r))
        put(w,CAND_MAP,r)
        if get(w,DIRECT)!=0:
            put(w,CAND_N,0)
            return append_name(w)
        return candidate_next(o,w)
    if phase==21:
        return seen_candidate(s,o,w)
    if phase==22:
        if get(w,DONE)!=0:
            return finish(o,w)
        return borrowed(w,23,get(w,PATH_MAP)+get(w,START),get(w,SEGLEN),get(w,CAND_MAP),get(w,CAND_CAP))
    if phase==23:
        n=get(w,SEGLEN)
        if n>length(s) or n+1>=length(o):
            return 4294967293
        copy_view(s,0,o,0,n)
        if n!=0 and byte(s,n-1)!=47:
            store(o,n,47)
            n=n+1
        put(w,CAND_N,n)
        return jump(w,24)
    if phase==24:
        return append_name(w)
    if phase==25:
        n=get(w,NAME_N)
        at=get(w,CAND_N)
        if length(s)!=32+n or at>length(o) or n>=length(o)-at:
            return 4294967293
        copy_view(s,32,o,at,n)
        store(o,at+n,0)
        put(w,CAND_N,at+n)
        return jump(w,40)
    if phase==40:
        return call(o,w,41,4,get(w,CAND_MAP),W_STAT,0,0,0,0,12)
    return 4294967293

def append_name(w:mutbuf) -> u32:
    put(w,PHASE,25)
    return 15

def candidate_next(o:mutbuf,w:mutbuf) -> u32:
    if get(w,DIRECT)!=0:
        return finish(o,w)
    return borrowed(w,21,get(w,PATH_MAP),get(w,PATH_N),get(w,PATH_MAP)+get(w,TABLE_OFF),get(w,TABLE_SLOTS)*32)

def seen_candidate(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    cursor=get(w,CURSOR)
    n=get(w,PATH_N)
    if n!=length(s) or length(o)!=get(w,TABLE_SLOTS)*32:
        return 4294967293
    while cursor<=n:
        start=cursor
        while cursor<n and byte(s,cursor)!=58:
            cursor=cursor+1
        count=cursor-start
        put(w,CURSOR,cursor+1)
        slots=get(w,TABLE_SLOTS)
        slot=0
        i=0
        while i<count:
            slot=(slot*131+byte(s,start+i))&(slots-1)
            i=i+1
        duplicate=0
        while get(o,slot*32)!=0 and duplicate==0:
            other=get(o,slot*32)-1
            size=get(o,slot*32+8)
            if size==count:
                i=0
                while i<count and byte(s,start+i)==byte(s,other+i):
                    i=i+1
                if i==count:
                    duplicate=1
            if duplicate==0:
                slot=(slot+1)&(slots-1)
        if duplicate==0:
            put(o,slot*32,start+1)
            put(o,slot*32+8,count)
            put(w,START,start)
            put(w,SEGLEN,count)
            return jump(w,22)
        cursor=get(w,CURSOR)
    put(w,DONE,1)
    return jump(w,22)

def check_candidate(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==41:
        if failed(r):
            return candidate_next(o,w)
        return call(o,w,42,21,get(w,CAND_MAP),1,0,0,0,0,0)
    if phase==42:
        if r!=0:
            return candidate_next(o,w)
        return call(o,w,43,4,get(w,CAND_MAP),W_STAT,0,0,0,0,12)
    if phase==43:
        if failed(r) or (get(w,W_STAT+24)&61440)!=16384:
            put(w,ERROR,0)
            return finish(o,w)
        return candidate_next(o,w)
    return 4294967293

def fail(o:mutbuf,w:mutbuf,error:u64,number:u64) -> u32:
    put(w,ERROR,error)
    put(w,ERROR_NO,number)
    return finish(o,w)

def retire(o:mutbuf,w:mutbuf,phase:u64,r:u64) -> u32:
    if phase==901:
        at=choose(get(w,CLEAN_INDEX)==0,PATH_MAP,CAND_MAP)
        if failed(r):
            if get(w,W_CLEAN_ERR)==0:
                put(w,W_CLEAN_ERR,errno(r))
        else:
            put(w,at,0)
            put(w,at+8,0)
        put(w,CLEAN_INDEX,get(w,CLEAN_INDEX)+1)
    while get(w,CLEAN_INDEX)<2:
        at=choose(get(w,CLEAN_INDEX)==0,PATH_MAP,CAND_MAP)
        if get(w,at)!=0:
            return call(o,w,901,11,get(w,at),get(w,at+8),0,0,0,0,0)
        put(w,CLEAN_INDEX,get(w,CLEAN_INDEX)+1)
    return finish(o,w)

def finish(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,128)
    put(o,0,WH_REPLY)
    pending=choose(get(w,PATH_MAP)!=0,1,0)+choose(get(w,CAND_MAP)!=0,1,0)
    put(o,8,get(w,ERROR))
    put(o,16,get(w,ERROR_NO))
    if get(w,RETIRING)!=0:
        put(o,8,choose(get(w,W_CLEAN_ERR)!=0,4,0))
        put(o,16,get(w,W_CLEAN_ERR))
    elif get(w,ERROR)==0:
        put(o,24,get(w,CAND_N))
        put(o,32,get(w,CAND_MAP))
        put(o,40,get(w,CAND_CAP))
    put(o,48,get(w,WPID))
    put(o,56,pending)
    put(o,64,1)
    retired=get(w,RETIRING)!=0 and pending==0
    put(o,72,choose(retired,1,0))
    put(w,DONE,1)
    if retired:
        clear(w,0,4096)
    return 0

def copy_view(s:readbuf,source:u64,o:mutbuf,dest:u64,n:u64) -> u64:
    i=0
    while n-i>=8:
        put(o,dest+i,word(s,source+i))
        i=i+8
    while i<n:
        store(o,dest+i,byte(s,source+i))
        i=i+1
    return 0
'''
if __name__=='__main__':write_module('clang_which',SOURCE,'advance')
