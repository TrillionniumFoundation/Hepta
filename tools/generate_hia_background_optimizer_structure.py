"""Preserve hia_program._structure budgets for a freshly captured JSON tree.

The caller owns the matching raw bytes and dynamic 72-byte arena. This leaf
does not create authority from a caller-supplied arena or a threshold hash.
The fixed decimal threshold is separately captured from the named source data.
Foreign object/cycle admission remains in the public typed ingress.
"""
from pathlib import Path
import re, json
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={
 'INPUT':int.from_bytes(b'HIABST01','little'),'OUTPUT':int.from_bytes(b'HIABSR01','little'),
 'ARENA':5208772604367785521,'NONE':(1<<64)-1,'BAD':4294967293,
 'MAX_BYTES':8388608,'MAX_NODES':262144,'MAX_DEPTH':64,'THRESHOLD_N':10100891,
 'STACK':4096,'SEEN':4202496,
}
ERRORS={
 1:'E_HIA_LIMIT: program exceeds structural budget',
 2:'E_HIA_LIMIT: program exceeds queued-node budget',
 3:'E_HIA_FORMAT: cyclic HIA JSON structure',
 4:'E_HIA_FORMAT: non-string JSON key',
 5:'E_HIA_FORMAT: only bounded integer JSON values are supported',
 6:'E_HIA_FORMAT: unpaired Unicode surrogate',
 7:'E_HIA_LIMIT: program exceeds byte budget before encoding',
 8:'E_HIA_LIMIT: integer exceeds JSON byte budget',
}
SOURCE=r'''
def background_optimizer_structure(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(o)<512 or length(w)<SEEN:
        return BAD
    if read64(s,0)!=INPUT:
        return BAD
    root=read64(s,8)
    raw_n=read64(s,16)
    arena_n=read64(s,24)
    threshold_n=read64(s,32)
    conversion_limit=read64(s,40)
    if conversion_limit!=0 and (conversion_limit<640 or conversion_limit>2147483647):
        return BAD
    at=48
    while at<128:
        if read64(s,at)!=0:
            return BAD
        at=at+8
    remaining=length(s)-128
    if raw_n>remaining:
        return BAD
    remaining=remaining-raw_n
    if arena_n>remaining:
        return BAD
    remaining=remaining-arena_n
    if threshold_n!=THRESHOLD_N or remaining!=threshold_n:
        return BAD
    arena_at=128+raw_n
    if arena_n<64:
        return BAD
    count=read64(s,arena_at+8)
    if count==0 or count>length(w)-SEEN or root>=count:
        return BAD
    if arena_valid(s,w,arena_at,arena_n,raw_n)==False:
        return BAD
    zero(w,0,128)
    put(w,0,arena_at)
    put(w,8,arena_at+arena_n)
    put(w,16,raw_n)
    put(w,64,conversion_limit)
    put(w,24,1)
    put(w,32,1)
    put(w,STACK,root)
    put(w,STACK+8,0)
    return walk(s,o,w)

def walk(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    while get(w,24)!=0:
        pending=get(w,24)-1
        put(w,24,pending)
        put(w,32,get(w,32)-1)
        node=get(w,STACK+pending*16)
        depth=get(w,STACK+pending*16+8)
        put(w,40,get(w,40)+1)
        put(w,56,depth)
        if get(w,40)>MAX_NODES or depth>MAX_DEPTH:
            return finish(o,w,1)
        row=get(w,0)+64+node*72
        kind=read64(s,row)
        if kind==5 or kind==6:
            error=container(s,w,node,depth,kind)
            if error!=0:
                return finish(o,w,error)
        elif kind==4:
            error=string_bytes(s,w,get(w,0)+read64(s,row+24),read64(s,row+32))
            if error!=0:
                return finish(o,w,error)
        elif kind==3:
            error=integer_bytes(s,w,128+read64(s,row+24),read64(s,row+32))
            if error!=0:
                return finish(o,w,error)
        elif kind==0 or kind==2:
            put(w,48,get(w,48)+4)
        elif kind==1:
            put(w,48,get(w,48)+5)
        else:
            return BAD
        if get(w,48)>MAX_BYTES:
            return finish(o,w,7)
    return finish(o,w,0)

def container(s:readbuf,w:mutbuf,node:u64,depth:u64,kind:u64) -> u64:
    base=get(w,0)
    count=nodeword(s,base,node,32)
    if count>MAX_NODES-get(w,40)-get(w,32):
        return 2
    put(w,32,get(w,32)+count)
    size=get(w,48)+2
    if count!=0:
        size=size+count-1
    if kind==6:
        size=size+count
    put(w,48,size)
    if size>MAX_BYTES:
        return 7
    if kind==6:
        child=nodeword(s,base,node,24)
        i=0
        while i<count:
            error=string_bytes(s,w,base+nodeword(s,base,child,40),nodeword(s,base,child,48))
            if error!=0:
                return error
            child=nodeword(s,base,child,16)
            i=i+1
    child=nodeword(s,base,node,24)
    i=0
    pending=get(w,24)
    while i<count:
        put(w,STACK+(pending+i)*16,child)
        put(w,STACK+(pending+i)*16+8,depth+1)
        child=nodeword(s,base,child,16)
        i=i+1
    put(w,24,pending+count)
    return 0

def string_bytes(s:readbuf,w:mutbuf,at:u64,n:u64) -> u64:
    used=get(w,48)
    if used>MAX_BYTES:
        return 7
    remaining=MAX_BYTES-used
    chars=0
    i=0
    while i<n:
        if n-i>=8:
            value=read64(s,at+i)
            if (value&9259542123273814144)==0:
                chars=chars+8
                i=i+8
            else:
                width=utf8_width(s,at+i,n-i)
                if width==0:
                    return 64
                chars=chars+1
                i=i+width
        else:
            width=utf8_width(s,at+i,n-i)
            if width==0:
                return 64
            chars=chars+1
            i=i+width
    if chars+2>remaining:
        return 7
    total=2
    i=0
    while i<n:
        ch=byte(s,at+i)
        width=utf8_width(s,at+i,n-i)
        if width==0:
            return 64
        if ch<32:
            if ch==8 or ch==9 or ch==10 or ch==12 or ch==13:
                total=total+2
            else:
                total=total+6
        elif ch==34 or ch==92:
            total=total+2
        elif width==3 and ch==237 and byte(s,at+i+1)>=160:
            return 6
        else:
            total=total+width
        if total>remaining:
            return 7
        i=i+width
    put(w,48,used+total)
    return 0

def utf8_width(s:readbuf,at:u64,n:u64) -> u64:
    if n==0:
        return 0
    first=byte(s,at)
    if first<128:
        return 1
    if first>=194 and first<=223 and n>=2:
        b=byte(s,at+1)
        if b>=128 and b<=191:
            return 2
        return 0
    if first>=224 and first<=239 and n>=3:
        b=byte(s,at+1)
        c=byte(s,at+2)
        if b<128 or b>191 or c<128 or c>191:
            return 0
        if first==224 and b<160:
            return 0
        return 3
    if first>=240 and first<=244 and n>=4:
        b=byte(s,at+1)
        c=byte(s,at+2)
        d=byte(s,at+3)
        if b<128 or b>191 or c<128 or c>191 or d<128 or d>191:
            return 0
        if first==240 and b<144:
            return 0
        if first==244 and b>143:
            return 0
        return 4
    return 0

def integer_bytes(s:readbuf,w:mutbuf,at:u64,n:u64) -> u64:
    if n==0:
        return 64
    skip=0
    if byte(s,at)==45:
        skip=1
    if skip==n:
        return 64
    i=skip
    while i<n:
        ch=byte(s,at+i)
        if ch<48 or ch>57:
            return 5
        i=i+1
    digits=n-skip
    if digits>THRESHOLD_N:
        return 8
    if digits==THRESHOLD_N:
        i=0
        decided=0
        threshold=get(w,8)
        while i<digits and decided==0:
            a=byte(s,at+skip+i)
            b=byte(s,threshold+i)
            if a>b:
                return 8
            if a<b:
                decided=1
            i=i+1
        if decided==0:
            return 8
    limit=get(w,64)
    if limit!=0 and digits>limit:
        return 9
    amount=n
    if n==2 and skip==1 and byte(s,at+1)==48:
        amount=1
    put(w,48,get(w,48)+amount)
    return 0

def arena_valid(s:readbuf,w:mutbuf,base:u64,size:u64,wire:u64) -> bool:
    if size<64 or read64(s,base)!=ARENA:
        return False
    count=read64(s,base+8)
    if count==0 or count>(size-64)//72 or count>length(w)-SEEN:
        return False
    first=64+72*count
    if read64(s,base+16)!=first or read64(s,base+24)!=size or read64(s,base+32)!=size or read64(s,base+40)!=wire or read64(s,base+48)!=1 or read64(s,base+56)!=0:
        return False
    i=0
    while i<count:
        store(w,SEEN+i,0)
        i=i+1
    store(w,SEEN,1)
    i=0
    while i<count:
        row=base+64+i*72
        kind=read64(s,row)
        parent=read64(s,row+8)
        following=read64(s,row+16)
        start=read64(s,row+24)
        extent=read64(s,row+32)
        key=read64(s,row+40)
        kn=read64(s,row+48)
        if kind>6 or (i==0 and (parent!=NONE or following!=NONE)) or (i!=0 and parent>=i):
            return False
        if following!=NONE and (following<=i or following>=count):
            return False
        if i!=0 and nodeword(s,base,parent,0)==6:
            if key<first or key>size or kn>size-key:
                return False
        elif key!=0 or kn!=0:
            return False
        if kind==4:
            if start<first or start>size or extent>size-start:
                return False
        elif kind<4:
            if start>wire or extent==0 or extent>wire-start:
                return False
        if kind>=4:
            raw=read64(s,row+56)
            rn=read64(s,row+64)
            if raw>wire or rn==0 or rn>wire-raw:
                return False
        if kind==5 or kind==6:
            if extent>count:
                return False
            child=start
            j=0
            while j<extent:
                if child<=i or child>=count or byte(w,SEEN+child)!=0 or nodeword(s,base,child,8)!=i:
                    return False
                store(w,SEEN+child,1)
                child=nodeword(s,base,child,16)
                j=j+1
            if child!=NONE:
                return False
        i=i+1
    i=0
    while i<count:
        if byte(w,SEEN+i)!=1:
            return False
        i=i+1
    return True

def finish(o:mutbuf,w:mutbuf,error:u64) -> u32:
    if error==64:
        return BAD
    zero(o,0,128)
    put(o,0,OUTPUT)
    put(o,8,choose(error==0,0,1))
    put(o,16,error)
    put(o,24,get(w,40))
    put(o,32,get(w,48))
    put(o,48,get(w,56))
    put(o,56,get(w,24))
    if error==9:
        put(o,40,limit_error(o,get(w,64)))
    elif error!=0:
        put(o,40,error_json(o,error))
    return 0

def limit_error(o:mutbuf,limit:u64) -> u64:
    at=128+limit_prefix(o,128)
    at=decimal(o,at,limit)
    return at+limit_suffix(o,at)-128

def decimal(o:mutbuf,at:u64,value:u64) -> u64:
    divisor=1
    while value//divisor>=10:
        divisor=divisor*10
    while divisor!=0:
        store(o,at,48+(value//divisor)%10)
        at=at+1
        divisor=divisor//10
    return at

def nodeword(s:readbuf,base:u64,node:u64,slot:u64) -> u64:
    if node==NONE or node>=read64(s,base+8):
        return NONE
    return read64(s,base+64+node*72+slot)
def read64(s:readbuf,at:u64) -> u64:
    return word_load(s,at)
def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)
def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(8*i))&255)
        i=i+1
    return 0
def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0
def choose(condition:bool,a:u64,b:u64) -> u64:
    if condition:
        return a
    return b
'''
def source_program():
 text=SOURCE
 lines=['def error_json(o:mutbuf,which:u64) -> u64:']
 for number in ERRORS:
  lines += [f'    if which=={number}:',f'        return error_{number}(o)']
 lines += ['    return 0']
 text+='\n'+'\n'.join(lines)+'\n'
 for number,message in ERRORS.items():
  raw=json.dumps({'type':'HIAProgramRejected','message':message},sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
  lines=[f'def error_{number}(o:mutbuf) -> u64:']
  for i,byte in enumerate(raw):lines.append(f'    store(o,{128+i},{byte})')
  lines.append(f'    return {len(raw)}')
  text+='\n'+'\n'.join(lines)+'\n'
 for name,raw in [('limit_prefix',b'{"message":"Exceeds the limit ('),('limit_suffix',b' digits) for integer string conversion; use sys.set_int_max_str_digits() to increase the limit","type":"ValueError"}')]:
  lines=[f'def {name}(o:mutbuf,at:u64) -> u64:']
  for i,byte in enumerate(raw):lines.append(f'    store(o,at+{i},{byte})')
  lines.append(f'    return {len(raw)}')
  text+='\n'+'\n'.join(lines)+'\n'
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
  text=re.sub(r'\b'+key+r'\b',str(value),text)
 return text
def main():
 doc=document(source_program(),'background_optimizer_structure')
 path=ROOT/'examples/hia_bootstrap/background_optimizer_structure.hepta'
 path.write_text(render_assembly(doc))
 print(path.name,path.stat().st_size,len(doc['functions']),sum(len(f['blocks']) for f in doc['functions']),flush=True)
if __name__=='__main__':main()
