"""Exact native subprocess.TimeoutExpired text for an actual Clang argv frame."""
from tools import generate_hia_native_string_repr as representation
from tools.generate_hia_clang_capture_common import write_module
SOURCE=r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or word(s,0)!=0x3130504143414948 or word(s,8)!=0:
        return 4294967293
    if length(w)<8192:
        return 4294967294
    count=word(s,16)
    if count==0 or count>(length(s)-128)//10:
        return 4294967293
    tables(w)
    total=38
    at=128
    i=0
    while i<count:
        if at>length(s) or length(s)-at<8:
            return 4294967293
        n=word(s,at)
        at=at+8
        if n==0 or at>=length(s) or n>=length(s)-at:
            return 4294967293
        if byte(s,at+n)!=0:
            return 4294967293
        quote=choose_quote(s,at,n)
        amount=measure_arg(s,w,at,n,quote)
        if amount==NONE or total>=4294967292-amount:
            return 4294967292
        total=total+amount
        if i!=0:
            if total>=4294967290:
                return 4294967292
            total=total+2
        at=at+n+1
        i=i+1
    if length(o)<total:
        return 4294967294
    prefix(o)
    pos=10
    at=128
    i=0
    while i<count:
        n=word(s,at)
        at=at+8
        if i!=0:
            store(o,pos,44)
            store(o,pos+1,32)
            pos=pos+2
        quote=choose_quote(s,at,n)
        pos=render_arg(s,o,w,at,n,quote,pos)
        at=at+n+1
        i=i+1
    store(o,pos,93)
    pos=pos+1
    suffix(o,pos)
    return total

def choose_quote(s:readbuf,at:u64,n:u64) -> u64:
    single=False
    double=False
    i=0
    while i<n:
        b=byte(s,at+i)
        if b==39:
            single=True
        elif b==34:
            double=True
        i=i+1
    if single and double==False:
        return 34
    return 39

def fs_decode(s:readbuf,at:u64,end:u64) -> u64:
    raw=decode(s,at,end)
    cp=raw&R_MASK
    if raw>>32==0 or cp>=55296 and cp<=57343:
        return (56320+byte(s,at))|4294967296
    return raw

def measure_arg(s:readbuf,w:mutbuf,at:u64,n:u64,quote:u64) -> u64:
    end=at+n
    amount=2
    while at<end:
        if byte(s,at)==0:
            return NONE
        raw=fs_decode(s,at,end)
        cp=raw&R_MASK
        width=raw>>32
        add=escape_size(w,cp,width,0,quote)
        if amount>=4294967292-add:
            return NONE
        amount=amount+add
        at=at+width
    return amount

def render_arg(s:readbuf,o:mutbuf,w:mutbuf,at:u64,n:u64,quote:u64,pos:u64) -> u64:
    store(o,pos,quote)
    pos=pos+1
    end=at+n
    while at<end:
        raw=fs_decode(s,at,end)
        cp=raw&R_MASK
        width=raw>>32
        count=escape_size(w,cp,width,0,quote)
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
        elif escaped(w,cp,0):
            hex_escape(o,pos,cp,count)
        else:
            i=0
            while i<width:
                store(o,pos+i,byte(s,at+i))
                i=i+1
        pos=pos+count
        at=at+width
    store(o,pos,quote)
    return pos+1
'''
SOURCE+=representation.SOURCE[representation.SOURCE.index('\ndef escaped('):]
def literal(name,raw,offset):
 text='\ndef '+name+'(o:mutbuf'+(',at:u64'if offset=='at'else '')+') -> u64:\n'
 for i,value in enumerate(raw):text+='    store(o,'+('at+'if offset=='at'else '')+str(i)+','+str(value)+')\n'
 return text+'    return 0\n'
assert len(b"Command '[")+len(b"]' timed out after 3 seconds")==38
SOURCE+=literal('prefix',b"Command '[",0)+literal('suffix',b"' timed out after 3 seconds",'at')
if __name__=='__main__':write_module('native_reap_timeout_text',SOURCE,'advance')
