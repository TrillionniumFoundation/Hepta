"""Strict UTF-8 and universal-newline decoding of actual captured file bytes."""
from tools.generate_hia_clang_capture_common import write_module
SOURCE=r'''
def decode(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    put(w,STREAM_N,0)
    if utf8(s,0,length(s))==0:
        put(w,STREAM_RESULT,E_ENCODING)
        return 10
    if length(o)<length(s):
        put(w,STREAM_RESULT,E_MEMORY)
        return 10
    i=0
    n=0
    while i<length(s):
        ch=byte(s,i)
        if ch==13:
            store(o,n,10)
            if i+1<length(s) and byte(s,i+1)==10:
                i=i+1
        else:
            store(o,n,ch)
        i=i+1
        n=n+1
    put(w,STREAM_N,n)
    put(w,STREAM_RESULT,0)
    return 10
'''
if __name__=='__main__':write_module('clang_capture_streams',SOURCE,'decode')
