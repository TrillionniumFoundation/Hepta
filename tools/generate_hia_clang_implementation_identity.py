"""HIA source-catalog identity from actual stable regular file bytes.

The digest commits to a sequence of logical source names, actual sizes and
actual SHA-256 content digests. Production supplies the catalog from its fixed
native image. The private frame itself grants no code or execution authority.
"""
from tools.generate_hia_clang_capture_common import C,write_module
C.update(I_REQUEST=int.from_bytes(b'HIAIDQ01','little'),I_REPLY=int.from_bytes(b'HIAIDR01','little'),
 I_CONTEXT=int.from_bytes(b'HIAIDW01','little'),I_FILE_MAGIC=int.from_bytes(b'HIASFL01','little'),I_FILE_REPLY=int.from_bytes(b'HIASFR01','little'),
 I_SELF=32,I_PID=40,I_TAG=48,I_BASE=56,I_EXTENT=64,I_SOURCE=72,I_FILE_ACTIVE=80,I_FILE_AT=88,I_FILE_N=96,
 I_INDEX=104,I_COUNT=112,I_CURSOR=120,I_NAME_AT=128,I_NAME_N=136,I_NAME_CURSOR=144,I_NEXT=152,
 I_HASH_N=160,I_RETIRING=168,I_UNKNOWN=176,I_FILE_OP=184,I_CLEAN_ERROR=192,I_CLEAN_ERRNO=200,
 I_DIGEST=256,I_RETIRE=512,I_FILE_OUT=1024,I_HASH_INPUT=8191,I_CHUNK=8192,I_HASH_WORK=32768,I_FILE_WORK=65536)
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    r=get(w,RESULT)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        put(w,I_PID,r)
        store(w,I_HASH_INPUT,0)
        return hashing(w,2,1)
    if phase==2:
        if r!=0:
            return fail(o,w,4,r)
        return record(s,o,w)
    if phase==3:
        if r!=0:
            return fail(o,w,4,r)
        return name_chunk(s,w)
    if phase==4:
        if r!=0:
            return fail(o,w,4,r)
        put(w,I_NAME_CURSOR,get(w,I_NAME_CURSOR)+get(w,I_HASH_N)-1)
        return name_chunk(s,w)
    if phase==5:
        put(w,I_FILE_ACTIVE,1)
        put(w,I_FILE_OP,0)
        put(w,PHASE,6)
        return 2
    if phase==6:
        if r!=0 or get(w,I_FILE_OUT)!=I_FILE_REPLY:
            put(w,I_UNKNOWN,1)
            return fail(o,w,3,6)
        if get(w,I_FILE_OUT+8)!=0:
            put(w,ERROR,2)
            put(w,ERROR_NO,get(w,I_FILE_OUT+16))
        else:
            store(w,I_HASH_INPUT,1)
            put(w,I_CHUNK,get(w,I_FILE_OUT+32))
            i=0
            while i<32:
                store(w,I_CHUNK+8+i,byte(w,I_FILE_OUT+128+i))
                i=i+1
        if get(w,I_FILE_OUT+168)!=1:
            put(w,I_UNKNOWN,1)
            return fail(o,w,3,7)
        return file_retire(w,7)
    if phase==7:
        if file_retired(w)==False:
            return finish(o,w)
        if get(w,ERROR)!=0:
            return finish(o,w)
        return hashing(w,8,41)
    if phase==8:
        if r!=0:
            return fail(o,w,4,r)
        put(w,I_INDEX,get(w,I_INDEX)+1)
        put(w,I_CURSOR,get(w,I_NEXT))
        return record(s,o,w)
    if phase==9:
        if r!=32:
            return fail(o,w,4,r)
        return finish(o,w)
    if phase==900:
        if get(w,I_UNKNOWN)!=0:
            return finish(o,w)
        if get(w,I_FILE_ACTIVE)!=0:
            return file_retire(w,901)
        return finish(o,w)
    if phase==901:
        file_retired(w)
        return finish(o,w)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<32 or length(o)<128 or length(w)<2097152:
        return 4294967293
    if word(s,0)!=I_REQUEST or word(s,8)!=0 or word(s,24)!=length(s):
        return 4294967293
    count=word(s,16)
    if count==0 or count>(length(s)-32)//211:
        return 4294967293
    at=32
    i=0
    while i<count:
        if at>length(s) or length(s)-at<16:
            return 4294967293
        n=word(s,at)
        size=word(s,at+8)
        if n==0 or n>length(s)-at-16 or size>length(s)-at-16-n or size<194:
            return 4294967293
        file=at+16+n
        if word(s,file)!=I_FILE_MAGIC or word(s,file+8)!=0 or word(s,file+16)!=1073741824 or word(s,file+24)!=1:
            return 4294967293
        pn=word(s,file+32)
        if pn==0 or pn!=size-193:
            return 4294967293
        j=40
        while j<192:
            if word(s,file+j)!=0:
                return 4294967293
            j=j+8
        j=0
        while j<pn:
            if byte(s,file+192+j)==0:
                return 4294967293
            j=j+1
        if byte(s,file+192+pn)!=0:
            return 4294967293
        at=file+size
        i=i+1
    if at!=length(s):
        return 4294967293
    put(w,I_SELF,get(w,I_BASE))
    put(w,I_TAG,I_CONTEXT)
    put(w,I_COUNT,count)
    put(w,I_CURSOR,32)
    return call(o,w,1,39,0,0,0,0,0,0,0)

def record(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,I_INDEX)==get(w,I_COUNT):
        store(w,I_HASH_INPUT,2)
        return hashing(w,9,1)
    at=get(w,I_CURSOR)
    n=word(s,at)
    size=word(s,at+8)
    put(w,I_NAME_AT,at+16)
    put(w,I_NAME_N,n)
    put(w,I_NAME_CURSOR,0)
    put(w,I_FILE_AT,at+16+n)
    put(w,I_FILE_N,size)
    put(w,I_NEXT,at+16+n+size)
    store(w,I_HASH_INPUT,1)
    put(w,I_CHUNK,n)
    return hashing(w,3,9)

def name_chunk(s:readbuf,w:mutbuf) -> u32:
    at=get(w,I_NAME_CURSOR)
    n=get(w,I_NAME_N)
    if at==n:
        return jump(w,5)
    size=n-at
    if size>16384:
        size=16384
    store(w,I_HASH_INPUT,1)
    i=0
    while i<size:
        store(w,I_CHUNK+i,byte(s,get(w,I_NAME_AT)+at+i))
        i=i+1
    return hashing(w,4,1+size)

def hashing(w:mutbuf,next:u64,n:u64) -> u32:
    put(w,PHASE,next)
    put(w,I_HASH_N,n)
    return 3

def file_retire(w:mutbuf,next:u64) -> u32:
    clear(w,I_RETIRE,192)
    put(w,I_RETIRE,I_FILE_MAGIC)
    put(w,I_RETIRE+8,3)
    put(w,I_FILE_OP,1)
    put(w,PHASE,next)
    return 2

def file_retired(w:mutbuf) -> bool:
    if get(w,RESULT)!=0 or get(w,I_FILE_OUT)!=I_FILE_REPLY:
        put(w,I_UNKNOWN,1)
        put(w,I_CLEAN_ERROR,3)
        return False
    if get(w,I_FILE_OUT+168)!=1:
        put(w,I_UNKNOWN,1)
        put(w,I_CLEAN_ERROR,3)
        return False
    if get(w,I_FILE_OUT+8)!=0 or get(w,I_FILE_OUT+160)!=0 or get(w,I_FILE_OUT+176)!=1:
        put(w,I_CLEAN_ERROR,5)
        put(w,I_CLEAN_ERRNO,get(w,I_FILE_OUT+16))
        return False
    put(w,I_FILE_ACTIVE,0)
    return True

def fail(o:mutbuf,w:mutbuf,error:u64,number:u64) -> u32:
    put(w,ERROR,error)
    put(w,ERROR_NO,number)
    return finish(o,w)

def finish(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,128)
    put(o,0,I_REPLY)
    error=get(w,ERROR)
    number=get(w,ERROR_NO)
    pending=get(w,I_FILE_ACTIVE)!=0 or get(w,I_UNKNOWN)!=0
    if get(w,I_RETIRING)!=0:
        error=0
        number=0
    if get(w,I_CLEAN_ERROR)!=0:
        error=get(w,I_CLEAN_ERROR)
        number=get(w,I_CLEAN_ERRNO)
    if get(w,I_UNKNOWN)!=0:
        error=3
    put(o,8,error)
    put(o,16,number)
    put(o,24,get(w,I_INDEX))
    if error==0 and get(w,I_RETIRING)==0:
        i=0
        while i<32:
            store(o,32+i,byte(w,I_DIGEST+i))
            i=i+1
    put(o,64,choose(pending,1,0))
    put(o,72,choose(get(w,I_UNKNOWN)==0,1,0))
    retired=get(w,I_RETIRING)!=0 and pending==False
    put(o,80,choose(retired,1,0))
    if retired:
        clear(w,0,65536)
    return 0
'''
if __name__=='__main__':write_module('clang_implementation_identity',SOURCE,'advance')
