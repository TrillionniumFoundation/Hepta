"""Pure strict UTF-8 first-error bounds for actual UnicodeDecodeError slots."""
from tools.generate_hia_clang_capture_common import C,write_module
C.update(U_REPLY=int.from_bytes(b'HIAU8ER1','little'))
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<64:
        return 4294967294
    clear(o,0,64)
    put(o,0,U_REPLY)
    put(o,40,length(s))
    at=0
    while at<length(s):
        a=byte(s,at)
        need=1
        if a>=194 and a<=223:
            need=2
        elif a>=224 and a<=239:
            need=3
        elif a>=240 and a<=244:
            need=4
        elif a>=128:
            return reject(o,at,at+1,1)
        j=1
        while j<need:
            if j>=length(s)-at:
                return reject(o,at,length(s),3)
            b=byte(s,at+j)
            if b<128 or b>191:
                return reject(o,at,at+j,2)
            if j==1:
                if a==224 and b<160 or a==237 and b>=160 or a==240 and b<144 or a==244 and b>=144:
                    return reject(o,at,at+j,2)
            j=j+1
        at=at+need
    return 0

def reject(o:mutbuf,start:u64,end:u64,reason:u64) -> u32:
    put(o,8,1)
    put(o,16,start)
    put(o,24,end)
    put(o,32,reason)
    return 0
'''
if __name__=='__main__':write_module('native_utf8_error',SOURCE,'advance')
