"""Pure native str/bytes repr using a fixed Unicode 16.0.0 printable table.

Python is only the source author and comparison oracle. The generated HIA
performs decoding, quotation selection, escaping and rendering itself.
"""
from tools.generate_hia_clang_capture_common import C,write_module
import unicodedata
assert unicodedata.unidata_version=='16.0.0'
RANGES=[]
at=0
while at<0x110000:
 if not chr(at).isprintable():
  at+=1
  continue
 end=at+1
 while end<0x110000 and chr(end).isprintable():end+=1
 RANGES.append(at|((end-1)<<21))
 at=end
assert 64+len(RANGES)*8<=8192
C.update(R_MAGIC=int.from_bytes(b'HIAREPR1','little'),R_TABLE=64,R_RANGES=len(RANGES),R_MASK=2097151)
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<16 or word(s,0)!=R_MAGIC or word(s,8)>2:
        return 4294967293
    if length(w)<8192:
        return 4294967294
    mode=word(s,8)
    single=False
    double=False
    at=16
    while at<length(s):
        b=byte(s,at)
        if b==39:
            single=True
        elif b==34:
            double=True
        at=at+1
    quote=39
    if single and double==False:
        quote=34
    tables(w)
    size=measure(s,w,mode,quote)
    if size==NONE:
        return 4294967293
    if size>=4294967292:
        return 4294967292
    if length(o)<size:
        return 4294967294
    pos=0
    if mode==1:
        store(o,0,98)
        pos=1
    store(o,pos,quote)
    pos=pos+1
    at=16
    while at<length(s):
        cp=byte(s,at)
        width=1
        if mode!=1:
            info=decode(s,at,length(s))
            cp=info&R_MASK
            width=info>>32
        count=escape_size(w,cp,width,mode,quote)
        if cp==92 or cp==quote:
            store(o,pos,92)
            store(o,pos+1,cp)
        elif cp==9 or cp==10 or cp==13:
            store(o,pos,92)
            marker=116
            if cp==10:
                marker=110
            elif cp==13:
                marker=114
            store(o,pos+1,marker)
        elif escaped(w,cp,mode):
            hex_escape(o,pos,cp,count)
        else:
            i=0
            while i<width:
                store(o,pos+i,byte(s,at+i))
                i=i+1
        pos=pos+count
        at=at+width
    store(o,pos,quote)
    return size

def measure(s:readbuf,w:mutbuf,mode:u64,quote:u64) -> u64:
    size=2
    if mode==1:
        size=3
    at=16
    while at<length(s):
        cp=byte(s,at)
        width=1
        if mode!=1:
            info=decode(s,at,length(s))
            width=info>>32
            if width==0:
                return NONE
            cp=info&R_MASK
        add=escape_size(w,cp,width,mode,quote)
        if size>=4294967292-add:
            return 4294967292
        size=size+add
        at=at+width
    return size

def escaped(w:mutbuf,cp:u64,mode:u64) -> bool:
    if mode==1:
        return cp<32 or cp>126
    if mode==2 and cp>127:
        return True
    return printable(w,cp)==False

def escape_size(w:mutbuf,cp:u64,width:u64,mode:u64,quote:u64) -> u64:
    if cp==92 or cp==quote or cp==9 or cp==10 or cp==13:
        return 2
    if escaped(w,cp,mode):
        if cp<256:
            return 4
        if cp<65536:
            return 6
        return 10
    return width

def hex_escape(o:mutbuf,at:u64,cp:u64,n:u64) -> u64:
    store(o,at,92)
    marker=120
    if n==6:
        marker=117
    elif n==10:
        marker=85
    store(o,at+1,marker)
    i=n-2
    while i!=0:
        i=i-1
        digit=cp&15
        if digit<10:
            store(o,at+2+i,48+digit)
        else:
            store(o,at+2+i,87+digit)
        cp=cp>>4
    return 0

def printable(w:mutbuf,cp:u64) -> bool:
    lo=0
    hi=R_RANGES
    while lo<hi:
        mid=(lo+hi)//2
        row=get(w,R_TABLE+mid*8)
        if row>>21<cp:
            lo=mid+1
        else:
            hi=mid
    if lo<R_RANGES:
        return (get(w,R_TABLE+lo*8)&R_MASK)<=cp
    return False

def decode(s:readbuf,at:u64,end:u64) -> u64:
    if at>=end:
        return 0
    a=byte(s,at)
    if a<128:
        return a|4294967296
    need=0
    value=0
    if a>=194 and a<=223:
        need=2
        value=a&31
    elif a>=224 and a<=239:
        need=3
        value=a&15
    elif a>=240 and a<=244:
        need=4
        value=a&7
    if need==0 or need>end-at:
        return 0
    i=1
    while i<need:
        b=byte(s,at+i)
        if b<128 or b>191:
            return 0
        value=(value<<6)|(b&63)
        i=i+1
    if need==3 and value<2048 or need==4 and (value<65536 or value>1114111):
        return 0
    return value|(need<<32)
'''
CHUNKS=[RANGES[i:i+128]for i in range(0,len(RANGES),128)]
SOURCE+='\ndef tables(w:mutbuf) -> u64:\n'
for i in range(len(CHUNKS)):SOURCE+=f'    table_{i}(w)\n'
SOURCE+='    return 0\n'
for i,chunk in enumerate(CHUNKS):
 SOURCE+=f'\ndef table_{i}(w:mutbuf) -> u64:\n'
 for j,row in enumerate(chunk):SOURCE+=f'    put(w,{64+(i*128+j)*8},{row})\n'
 SOURCE+='    return 0\n'
if __name__=='__main__':
 print('PINNED_UNICODE',unicodedata.unidata_version,'PRINTABLE_RANGES',len(RANGES),flush=True)
 write_module('native_string_repr',SOURCE,'advance')
