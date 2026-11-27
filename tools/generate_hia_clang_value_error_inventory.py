"""Typed inventory exceptions from actual artifact and native inventory bytes."""
from tools.generate_hia_clang_value_error_plan_common import C,write_module
C.update(E_INV_REPLY=3744,E_INV_N=3872,E_INV_ART=3880,E_INV_RAW=3888,E_INV_EXPECT=3896,E_INV_RETURN=3904,E_INV_NEED=3912,
 E_INV_REQUEST=52428800,E_INV_WORK=6291456,E_INV_WORK_N=1048704)
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(w,PHASE)
    result=get(w,RESULT)
    if phase==1900:
        return begin(w)
    if phase==1901:
        if result!=0:
            return a_unknown(w,phase)
        return a_copy(w,1902,a_at(w,A_INNER_WORK+285212672),a_at(w,E_INV_REQUEST+128+get(w,E_INV_ART)),get(w,E_INV_RAW))
    if phase==1902:
        if result!=0:
            return a_unknown(w,phase)
        return a_copy(w,1903,a_at(w,A_INNER_WORK+291504128+64),a_at(w,E_INV_REQUEST+128+get(w,E_INV_ART)+get(w,E_INV_RAW)),get(w,E_INV_EXPECT))
    if phase==1903:
        if result!=0:
            return a_unknown(w,phase)
        if get(w,A_XMAP)!=0:
            if get(w,A_XCAP)<8192:
                return a_unknown(w,phase)
            return invoke_text(w)
        if get(w,A_XCAP)!=0:
            return a_unknown(w,phase)
        put(w,E_INV_NEED,8192)
        return a_newmap(o,w,1904,8192)
    if phase==1904:
        if failed(result):
            return a_fail(w,18,errno(result))
        put(w,A_XMAP,result)
        put(w,A_XCAP,get(w,E_INV_NEED))
        return invoke_text(w)
    if phase==1905:
        if result==4294967294:
            n=get(w,E_INV_WORK+56)
            if n<=get(w,A_XCAP) or n>134217856:
                return a_unknown(w,phase)
            n=(n+4095)&18446744073709547520
            put(w,E_INV_NEED,n)
            return call(o,w,1904,25,get(w,A_XMAP),get(w,A_XCAP),n,1,0,0,0)
        if result<128 or result>get(w,A_XCAP):
            return a_unknown(w,phase)
        put(w,E_INV_RETURN,result)
        return a_copy(w,1906,get(w,A_XMAP),a_at(w,E_INV_REPLY),128)
    if phase==1906:
        if result!=0 or get(w,E_INV_REPLY)!=0x3153524943414948:
            return a_unknown(w,phase)
        return construct(w)
    return 4294967293

def begin(w:mutbuf) -> u32:
    if get(w,ERROR)!=9 or get(w,A_INNER_ACTIVE)!=1:
        return a_unknown(w,1900)
    phase=get(w,A_INNER_WORK+696)
    kind=get(w,A_INNER_WORK+296)
    if kind>1 or kind==0 and phase!=411 or kind==1 and phase!=448:
        return a_unknown(w,1900)
    art=get(w,A_INNER_WORK+984)
    meta=get(w,A_INNER_WORK+336)
    count=get(w,A_INNER_WORK+291504128+32)
    inv=A_INNER_WORK+285212672
    if art==0 or art>67108864 or get(w,A_INNER_WORK+992)==0 or meta<64 or meta>65536 or count>128:
        return a_unknown(w,1900)
    n=64
    if kind==0 and get(w,inv)==0:
        if get(w,inv+16)!=2 or get(w,inv+8)>65536:
            return a_unknown(w,1900)
        n=2112+get(w,inv+8)*24
    put(w,E_INV_ART,art)
    put(w,E_INV_RAW,n)
    put(w,E_INV_EXPECT,meta-64)
    put(w,E_INV_N,128+art+n+meta-64)
    clear(w,E_INV_REQUEST,128)
    put(w,E_INV_REQUEST,0x3152454943414948)
    put(w,E_INV_REQUEST+8,kind)
    put(w,E_INV_REQUEST+16,art)
    put(w,E_INV_REQUEST+24,n)
    put(w,E_INV_REQUEST+32,count)
    put(w,E_INV_REQUEST+40,meta-64)
    return a_copy(w,1901,get(w,A_INNER_WORK+992),a_at(w,E_INV_REQUEST+128),art)

def invoke_text(w:mutbuf) -> u32:
    return a_invoke(w,1905,11,a_at(w,E_INV_REQUEST),get(w,E_INV_N),get(w,A_XMAP),get(w,A_XCAP),a_at(w,E_INV_WORK),E_INV_WORK_N)

def construct(w:mutbuf) -> u32:
    cls=get(w,E_INV_REPLY+8)
    n=get(w,E_INV_REPLY+16)
    unicode=get(w,E_INV_REPLY+24)
    if (cls!=45 and cls!=51 and cls!=52) or n==0 or get(w,E_INV_RETURN)!=128+n or get(w,E_INV_REPLY+56)!=128+n or unicode>1:
        return a_unknown(w,1906)
    if unicode==1:
        at=get(w,E_INV_REPLY+32)
        size=get(w,E_INV_REPLY+40)
        pos=get(w,E_INV_REPLY+48)
        if size==0 or at>get(w,E_INV_ART) or size>get(w,E_INV_ART)-at or pos>=size or cls==45:
            return a_unknown(w,1906)
    e_row(w,20,33,n,0,0,0,0,0)
    e_class(w,32,cls)
    e_list(w,34)
    e_append(w,34,33)
    e_tuple(w,35,34)
    e_exception(w,15,32,35,NONE)
    if unicode==1:
        start=get(w,E_TEXT_N)
        put(w,E_TEXT+start,452739691361)
        put(w,E_TEXT_N,start+5)
        e_scalar(w,36,4,a_at(w,E_TEXT+start),5,0)
        e_scalar(w,37,7,get(w,A_INNER_WORK+992)+get(w,E_INV_REPLY+32),get(w,E_INV_REPLY+40),0)
        e_number(w,38,get(w,E_INV_REPLY+48),0)
        e_number(w,39,get(w,E_INV_REPLY+48)+1,0)
        start=get(w,E_TEXT_N)
        text_ascii_reason(w)
        e_scalar(w,40,4,a_at(w,E_TEXT+start),get(w,E_TEXT_N)-start,0)
        e_list(w,53)
        e_append(w,53,36)
        e_append(w,53,37)
        e_append(w,53,38)
        e_append(w,53,39)
        e_append(w,53,40)
        e_tuple(w,54,53)
        e_row(w,17,42,54,NONE,0,0,0,0)
        e_chain(w,15,42,1)
        e_chain(w,15,42,0)
    return jump(w,1600)
'''
def source():
 raw=b'ordinal not in range(128)';text=SOURCE+'\ndef text_ascii_reason(w:mutbuf) -> u64:\n    at=E_TEXT+get(w,E_TEXT_N)\n'
 i=0
 while len(raw)-i>=8:
  text+='    put(w,at+'+str(i)+','+str(int.from_bytes(raw[i:i+8],'little'))+')\n';i+=8
 for j in range(i,len(raw)):text+='    store(w,at+'+str(j)+','+str(raw[j])+')\n'
 text+='    put(w,E_TEXT_N,get(w,E_TEXT_N)+'+str(len(raw))+')\n    return 0\n'
 return text
if __name__=='__main__':write_module('clang_value_error_inventory',source())
