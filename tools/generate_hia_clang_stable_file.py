"""Native bounded regular-file capture and stable streaming identity.

This is development authoring. All file identity, size, exact-byte comparison,
hash streaming and resource retirement decisions execute in HIA.
"""
from tools.generate_hia_clang_capture_common import C,write_module
C.update(FS_MAGIC=int.from_bytes(b'HIASFL01','little'),FS_REPLY=int.from_bytes(b'HIASFR01','little'),
 FS_CONTEXT=int.from_bytes(b'HIASFW01','little'),FS_ERROR=16,FS_ERRNO=24,FS_SELF=32,FS_PID=40,FS_TAG=48,
 FS_OP=56,FS_PATH_N=64,FS_EXPECT_N=72,FS_COMPARE=80,FS_MAX=88,FS_EMPTY=96,
 FS_FD=104,FS_DATA=112,FS_CAP=120,FS_TOTAL=128,FS_SIZE=136,FS_ERROR_PHASE=144,
 FS_RETIRED=152,FS_UNKNOWN=160,FS_CLOSE_METHOD=168,FS_RETIRING=176,FS_HASH_N=184,
 FS_READ_N=192,FS_CLOSE_RESULT=200,FS_CLEAN_ERROR=208,FS_CLEAN_ERRNO=216,
 FS_BEFORE=256,FS_AFTER=400,FS_DIGEST=560,FS_BASE=608,FS_EXTENT=616,
 FS_HASH_WORK=1024,FS_HASH_INPUT=8191,FS_CHUNK=8192,FS_CHUNK_N=1048576)
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    result=get(w,RESULT)
    if phase==0:
        return begin_file(s,o,w)
    if phase==1:
        put(w,FS_PID,result)
        return call(o,w,20,6,192,FS_BEFORE,0,0,0,0,13)
    if phase==20:
        if failed(result):
            return fs_fail(o,w,2,errno(result),phase)
        if regular(w,FS_BEFORE)==0:
            return fs_fail(o,w,3,0,phase)
        n=get(w,FS_BEFORE+48)
        if n>get(w,FS_MAX) or n==0 and get(w,FS_EMPTY)==0:
            return fs_fail(o,w,3,0,phase)
        put(w,FS_SIZE,n)
        if get(w,FS_OP)==2 and n!=get(w,FS_EXPECT_N):
            return fs_fail(o,w,4,0,phase)
        if get(w,FS_COMPARE)!=0 and expected_identity(s,w)==0:
            return fs_fail(o,w,4,0,phase)
        return call(o,w,22,2,192,657408,0,0,0,0,1)
    if phase==22:
        if failed(result):
            return fs_fail(o,w,2,errno(result),phase)
        put(w,FS_FD,result)
        return call(o,w,23,5,result,FS_AFTER,0,0,0,0,12)
    if phase==23:
        if failed(result):
            return fs_fail(o,w,2,errno(result),phase)
        if regular(w,FS_AFTER)==0 or stable_identity(w)==0:
            return fs_fail(o,w,4,0,phase)
        if get(w,FS_OP)==1:
            cap=(get(w,FS_SIZE)+4096)&18446744073709547520
            put(w,FS_CAP,cap)
            return call(o,w,24,9,0,cap,3,34,NONE,0,0)
        return hash_begin(w)
    if phase==24:
        if failed(result):
            put(w,FS_CAP,0)
            return fs_fail(o,w,7,errno(result),phase)
        put(w,FS_DATA,result)
        return hash_begin(w)
    if phase==25:
        if result!=0:
            return fs_fail(o,w,8,result,phase)
        return read_file(o,w)
    if phase==26:
        if failed(result):
            if errno(result)==4:
                return read_file(o,w)
            return fs_fail(o,w,2,errno(result),phase)
        if result==0:
            if get(w,FS_TOTAL)!=get(w,FS_SIZE):
                return fs_fail(o,w,4,0,phase)
            return call(o,w,40,5,get(w,FS_FD),FS_AFTER,0,0,0,0,12)
        if result>get(w,FS_READ_N) or get(w,FS_TOTAL)>get(w,FS_SIZE) or result>get(w,FS_SIZE)-get(w,FS_TOTAL):
            return fs_fail(o,w,4,0,phase)
        put(w,FS_READ_N,result)
        if get(w,FS_OP)==2:
            at=193+get(w,FS_PATH_N)+get(w,FS_TOTAL)
            i=0
            while i<result:
                if byte(s,at+i)!=byte(w,FS_CHUNK+i):
                    return fs_fail(o,w,4,0,phase)
                i=i+1
        if get(w,FS_OP)==1:
            put(w,PHASE,27)
            return 3
        return hash_update(w)
    if phase==27:
        n=get(w,FS_READ_N)
        if n>length(s) or n>length(o):
            return 4294967293
        i=0
        while n-i>=8:
            put(o,i,word(s,i))
            i=i+8
        while i<n:
            store(o,i,byte(s,i))
            i=i+1
        return hash_update(w)
    if phase==28:
        if result!=0:
            return fs_fail(o,w,8,result,phase)
        put(w,FS_TOTAL,get(w,FS_TOTAL)+get(w,FS_READ_N))
        return read_file(o,w)
    if phase==40:
        if failed(result):
            return fs_fail(o,w,2,errno(result),phase)
        if stable_identity(w)==0:
            return fs_fail(o,w,4,0,phase)
        return fs_close(o,w,41)
    if phase==41:
        if failed(result) and errno(result)==38:
            put(w,FS_CLOSE_METHOD,1)
            return call(o,w,42,3,get(w,FS_FD),0,0,0,0,0,0)
        if failed(result):
            fs_cleanup_error(w,6,errno(result))
            return fs_fail_without_close(o,w,6,errno(result),phase)
        put(w,FS_FD,NONE)
        return call(o,w,43,6,192,FS_AFTER,0,0,0,0,13)
    if phase==42:
        put(w,FS_FD,NONE)
        if failed(result):
            put(w,FS_UNKNOWN,1)
            fs_cleanup_error(w,6,errno(result))
            return fs_fail_without_close(o,w,6,errno(result),phase)
        return call(o,w,43,6,192,FS_AFTER,0,0,0,0,13)
    if phase==43:
        if failed(result):
            return fs_fail(o,w,2,errno(result),phase)
        if regular(w,FS_AFTER)==0 or stable_identity(w)==0:
            return fs_fail(o,w,4,0,phase)
        store(w,FS_HASH_INPUT,2)
        put(w,FS_HASH_N,1)
        put(w,PHASE,44)
        return 2
    if phase==44:
        if result!=32:
            return fs_fail(o,w,8,result,phase)
        return finish_file(o,w)
    if phase>=900 and phase<=906:
        return retirement(o,w,phase,result)
    return 4294967293

def begin_file(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<193 or word(s,0)!=FS_MAGIC or word(s,8)>2 or length(w)<FS_CHUNK+FS_CHUNK_N or length(o)<256:
        return 4294967293
    op=word(s,8)
    n=word(s,32)
    expected=word(s,40)
    maximum=word(s,16)
    compare=word(s,48)
    if maximum==0 or maximum>1073741824 or word(s,24)>1 or compare>3 or word(s,56)!=0:
        return 4294967293
    if n>length(s)-193 or expected!=length(s)-193-n:
        return 4294967293
    if op!=2 and expected!=0:
        return 4294967293
    if op==1 and maximum>67108864:
        return 4294967293
    if op==2 and expected>maximum:
        return 4294967293
    i=128
    while i<192:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
    if compare==0:
        i=64
        while i<128:
            if word(s,i)!=0:
                return 4294967293
            i=i+8
    i=0
    while i<n:
        if byte(s,192+i)==0:
            return 4294967293
        i=i+1
    if byte(s,192+n)!=0:
        return 4294967293
    put(w,FS_SELF,get(w,FS_BASE))
    put(w,FS_TAG,FS_CONTEXT)
    put(w,FS_OP,op)
    put(w,FS_PATH_N,n)
    put(w,FS_EXPECT_N,expected)
    put(w,FS_COMPARE,compare)
    put(w,FS_MAX,maximum)
    put(w,FS_EMPTY,word(s,24))
    put(w,FS_FD,NONE)
    return call(o,w,1,39,0,0,0,0,0,0,0)

def regular(w:mutbuf,at:u64) -> u64:
    return choose((get(w,at+24)&61440)==32768,1,0)

def stable_identity(w:mutbuf) -> u64:
    a=FS_BEFORE
    b=FS_AFTER
    if get(w,a)!=get(w,b) or get(w,a+8)!=get(w,b+8) or get(w,a+48)!=get(w,b+48):
        return 0
    if get(w,FS_OP)==2 and (get(w,a+24)&4294967295)!=(get(w,b+24)&4294967295):
        return 0
    if get(w,a+88)!=get(w,b+88) or get(w,a+96)!=get(w,b+96):
        return 0
    if get(w,a+104)!=get(w,b+104) or get(w,a+112)!=get(w,b+112):
        return 0
    return 1

def identity_field(w:mutbuf,index:u64) -> u64:
    if index==0:
        return get(w,FS_BEFORE)
    if index==1:
        return get(w,FS_BEFORE+8)
    if index==2:
        return get(w,FS_BEFORE+24)&4294967295
    if index==3:
        return get(w,FS_BEFORE+48)
    return get(w,FS_BEFORE+88+(index-4)*8)

def expected_identity(s:readbuf,w:mutbuf) -> u64:
    count=8
    if get(w,FS_COMPARE)==2:
        count=6
    if get(w,FS_COMPARE)==3:
        count=2
    i=0
    while i<count:
        if word(s,64+i*8)!=identity_field(w,i):
            return 0
        i=i+1
    return 1

def hash_begin(w:mutbuf) -> u32:
    store(w,FS_HASH_INPUT,0)
    put(w,FS_HASH_N,1)
    put(w,PHASE,25)
    return 2

def hash_update(w:mutbuf) -> u32:
    store(w,FS_HASH_INPUT,1)
    put(w,FS_HASH_N,1+get(w,FS_READ_N))
    put(w,PHASE,28)
    return 2

def read_file(o:mutbuf,w:mutbuf) -> u32:
    n=get(w,FS_SIZE)+1-get(w,FS_TOTAL)
    n=choose(n>FS_CHUNK_N,FS_CHUNK_N,n)
    put(w,FS_READ_N,n)
    return call(o,w,26,0,get(w,FS_FD),FS_CHUNK,n,0,0,0,12)

def fs_close(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if get(w,FS_CLOSE_METHOD)==1:
        return call(o,w,phase+1,3,get(w,FS_FD),0,0,0,0,0,0)
    return call(o,w,phase,436,get(w,FS_FD),get(w,FS_FD),0,0,0,0,0)

def fs_cleanup_error(w:mutbuf,code:u64,number:u64) -> u64:
    if get(w,FS_CLEAN_ERROR)==0:
        put(w,FS_CLEAN_ERROR,code)
        put(w,FS_CLEAN_ERRNO,number)
    return 0

def fs_set_error(w:mutbuf,code:u64,number:u64,phase:u64) -> u64:
    if get(w,FS_ERROR)==0:
        put(w,FS_ERROR,code)
        put(w,FS_ERRNO,number)
        put(w,FS_ERROR_PHASE,phase)
    return 0

def fs_fail(o:mutbuf,w:mutbuf,code:u64,number:u64,phase:u64) -> u32:
    fs_set_error(w,code,number,phase)
    return jump(w,900)

def fs_fail_without_close(o:mutbuf,w:mutbuf,code:u64,number:u64,phase:u64) -> u32:
    fs_set_error(w,code,number,phase)
    return jump(w,904)

def retirement(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==900:
        if get(w,FS_FD)!=NONE:
            return fs_close(o,w,901)
        return jump(w,904)
    if phase==901:
        if failed(result) and errno(result)==38:
            put(w,FS_CLOSE_METHOD,1)
            return call(o,w,902,3,get(w,FS_FD),0,0,0,0,0,0)
        if failed(result):
            fs_cleanup_error(w,6,errno(result))
            fs_set_error(w,6,errno(result),phase)
        else:
            put(w,FS_FD,NONE)
        return jump(w,904)
    if phase==902:
        put(w,FS_FD,NONE)
        if failed(result):
            put(w,FS_UNKNOWN,1)
            fs_cleanup_error(w,6,errno(result))
            fs_set_error(w,6,errno(result),phase)
        return jump(w,904)
    if phase==904:
        if get(w,FS_DATA)!=0:
            return call(o,w,905,11,get(w,FS_DATA),get(w,FS_CAP),0,0,0,0,0)
        return jump(w,906)
    if phase==905:
        if failed(result):
            fs_cleanup_error(w,6,errno(result))
            fs_set_error(w,6,errno(result),phase)
        else:
            put(w,FS_DATA,0)
            put(w,FS_CAP,0)
        return jump(w,906)
    if phase==906:
        if get(w,FS_RETIRING)==1 and get(w,FS_DATA)==0 and get(w,FS_FD)==NONE and get(w,FS_UNKNOWN)==0:
            put(w,FS_RETIRED,1)
        answer=finish_file(o,w)
        if get(w,FS_RETIRED)==1:
            clear(w,0,8192)
        return answer
    return 4294967293

def finish_file(o:mutbuf,w:mutbuf) -> u32:
    clear(o,0,256)
    put(o,0,FS_REPLY)
    put(o,8,get(w,FS_ERROR))
    put(o,16,get(w,FS_ERRNO))
    put(o,24,get(w,FS_ERROR_PHASE))
    put(o,32,get(w,FS_SIZE))
    put(o,40,get(w,FS_DATA))
    put(o,48,get(w,FS_CAP))
    put(o,56,get(w,FS_FD))
    i=0
    while i<8:
        put(o,64+i*8,identity_field(w,i))
        i=i+1
    i=0
    while i<32:
        store(o,128+i,byte(w,FS_DIGEST+i))
        i=i+1
    pending=get(w,FS_DATA)!=0 or get(w,FS_FD)!=NONE or get(w,FS_UNKNOWN)!=0
    put(o,160,choose(pending,1,0))
    put(o,168,choose(get(w,FS_UNKNOWN)==0,1,0))
    put(o,176,get(w,FS_RETIRED))
    put(o,184,get(w,FS_UNKNOWN))
    put(o,192,get(w,FS_TOTAL))
    put(o,200,get(w,FS_CLEAN_ERROR))
    put(o,208,get(w,FS_CLEAN_ERRNO))
    return 0
'''
if __name__=='__main__':write_module('clang_stable_file',SOURCE,'advance')
