"""Pure copies of internally captured byte frames; no authority from callers."""
from tools.generate_hia_clang_value_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,640)==0:
        if length(o)<128+get(w,A_RAW_N):
            return 4294967293
        clear(o,0,128)
        put(o,0,A_CODEC_REQUEST)
        put(o,8,1)
        put(o,16,get(w,A_RAW_N))
        return 0
    if get(w,640)==4:
        return diagnostic_prefix(s,o)
    if get(w,640)==3:
        clear(o,0,32)
        put(o,0,0x3130485743414948)
        put(o,16,length(s))
        i=0
        direct=0
        while i<length(s):
            if byte(s,i)==47:
                direct=1
            i=i+1
        put(w,A_WHICH_DIRECT,direct)
        if get(w,A_BYTE_ORIGIN)==0 and direct==0:
            put(o,16,0)
        return 0
    if get(w,640)==2:
        return normalize_posix(s,o)
    if get(w,640)!=1 or length(s)!=get(w,A_SOURCE_N) or length(o)<get(w,A_FRAME_N):
        return 4294967293
    clear(o,0,256)
    put(o,0,choose(get(w,A_ORIGIN_HELD)==1,A_RAW_ORIGIN_REQUEST,A_RAW_REQUEST))
    put(o,16,get(w,A_TARGET))
    put(o,24,get(w,A_COMPILE_KIND))
    put(o,32,get(w,A_LAYOUT))
    if get(w,A_ORIGIN_HELD)==1:
        put(o,72,get(w,A_ORIGIN_FD))
    put(o,40,get(w,A_CORE_N))
    put(o,48,get(w,A_FS_N))
    put(o,56,get(w,A_PATH_N))
    put(o,64,get(w,A_ABI_N))
    copied(s,o,256,256,get(w,A_CORE_N))
    copied(s,o,256+get(w,A_CORE_N),get(w,A_FRAME_ABI),get(w,A_ABI_N))
    copied(s,o,256+get(w,A_CORE_N)+get(w,A_ABI_N),get(w,A_FRAME_PATH),get(w,A_PATH_N))
    return 0

def diagnostic_prefix(s:readbuf,o:mutbuf) -> u32:
    at=0
    chars=0
    while at<length(s) and chars<3000:
        b=byte(s,at)
        size=1
        if b>=194 and b<=223:
            size=2
        elif b>=224 and b<=239:
            size=3
        elif b>=240 and b<=244:
            size=4
        elif b>=128:
            return 4294967293
        if size>length(s)-at:
            return 4294967293
        if size>length(o)-at:
            return 4294967294
        i=0
        while i<size:
            store(o,at+i,byte(s,at+i))
            i=i+1
        at=at+size
        chars=chars+1
    return at

def normalize_posix(s:readbuf,o:mutbuf) -> u32:
    n=length(s)
    if length(o)<n or length(o)==0:
        return 4294967294
    root=0
    if n!=0 and byte(s,0)==47:
        root=1
        if n>=2 and byte(s,1)==47 and (n==2 or byte(s,2)!=47):
            root=2
    pos=0
    while pos<root:
        store(o,pos,47)
        pos=pos+1
    at=0
    while at<n:
        while at<n and byte(s,at)==47:
            at=at+1
        start=at
        while at<n and byte(s,at)!=47:
            at=at+1
        count=at-start
        if count!=0 and (count!=1 or byte(s,start)!=46):
            if pos>root:
                store(o,pos,47)
                pos=pos+1
            copied(s,o,start,pos,count)
            pos=pos+count
    if pos==0:
        store(o,0,46)
        pos=1
    return pos

def copied(s:readbuf,o:mutbuf,source:u64,destination:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,destination+i,byte(s,source+i))
        i=i+1
    return 0
'''
if __name__=='__main__':write_module('clang_value_buffers',SOURCE)
