"""Original NDU receipt JSON decoding and ordered strict diagnostics, in HIA.
The author is development-only; the generated HIA executes all byte decoding,
grammar, duplicate-key and non-finite decisions. No host JSON callback is used.
"""
from pathlib import Path
import ast
import re
from tools.generate_hia_ndu_evaluator import document
from hepta.hia_agent_assembly import render_assembly
ROOT=Path(__file__).resolve().parents[1]
C={'NONE':2**64-1,'MAGIC':int.from_bytes(b'HIANJD01','little'),'INPUT_CAP':4<<20,'OUTPUT_CAP':8<<20,'WORK_CAP':128<<20,'STACK':1<<20,'KEYS':66<<20,'TABLE':100<<20}
SOURCE=r'''
def diagnose(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)>INPUT_CAP or length(o)<OUTPUT_CAP or length(w)<WORK_CAP:
        return 4294967293
    digits=4300
    if get(w,2240)==3544411265436830024:
        digits=get(w,2248)
        if digits!=0 and (digits<640 or digits>2147483647):
            return 4294967293
    zero(o,0,128)
    zero(w,0,4096)
    put(w,2248,digits)
    put(o,96,digits)
    put(o,0,MAGIC)
    n=decode(s,o,w)
    if n==NONE:
        return 128
    put(o,16,n)
    put(w,8,n)
    buckets=16
    while buckets<length(s)//4+1:
        buckets=buckets*2
    if buckets>1048576:
        buckets=1048576
    put(w,16,buckets)
    zero(w,TABLE,buckets*8)
    parse(o,w)
    if get(o,8)==1:
        location(o,get(o,32))
    return 128+n

def decode(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    kind=1
    at=0
    n=length(s)
    if n>=4 and byte(s,0)==0 and byte(s,1)==0 and byte(s,2)==254 and byte(s,3)==255:
        kind=5
        at=4
    elif n>=4 and byte(s,0)==255 and byte(s,1)==254 and byte(s,2)==0 and byte(s,3)==0:
        kind=4
        at=4
    elif n>=2 and byte(s,0)==254 and byte(s,1)==255:
        kind=3
        at=2
    elif n>=2 and byte(s,0)==255 and byte(s,1)==254:
        kind=2
        at=2
    elif n>=3 and byte(s,0)==239 and byte(s,1)==187 and byte(s,2)==191:
        at=3
        put(w,24,3)
    elif n>=4:
        if byte(s,0)==0:
            kind=choose(byte(s,1)==0,5,3)
        elif byte(s,1)==0:
            kind=choose(byte(s,2)==0 and byte(s,3)==0,4,2)
    elif n==2:
        if byte(s,0)==0:
            kind=3
        elif byte(s,1)==0:
            kind=2
    put(o,64,kind)
    out=128
    while at<n:
        cp=0
        width=1
        if kind==1:
            a=byte(s,at)
            if a<128:
                cp=a
            else:
                width=2
                if a>=224:
                    width=3
                if a>=240:
                    width=4
                if a<194 or a>244:
                    return decode_error(s,o,w,kind,1,at,at+1)
                k=1
                while k<width:
                    if at+k>=n:
                        return decode_error(s,o,w,kind,2,at,n)
                    b=byte(s,at+k)
                    if b<128 or b>191 or (k==1 and ((a==224 and b<160) or (a==240 and b<144) or (a==244 and b>=144))):
                        return decode_error(s,o,w,kind,3,at,at+k)
                    k=k+1
                cp=a&choose(width==2,31,choose(width==3,15,7))
                k=1
                while k<width:
                    cp=(cp<<6)|(byte(s,at+k)&63)
                    k=k+1
        elif kind==2 or kind==3:
            if n-at<2:
                return decode_error(s,o,w,kind,4,at,n)
            cp=pair(s,at,kind==3)
            width=2
            if cp>=55296 and cp<56320 and n-at>=4:
                low=pair(s,at+2,kind==3)
                if low>=56320 and low<=57343:
                    cp=65536+((cp-55296)<<10)+low-56320
                    width=4
        else:
            if n-at<4:
                return decode_error(s,o,w,kind,4,at,n)
            cp=pair(s,at,kind==5)
            low=pair(s,at+2,kind==5)
            if kind==5:
                cp=(cp<<16)|low
            else:
                cp=cp|(low<<16)
            width=4
            if cp>1114111:
                return decode_error(s,o,w,kind,5,at,at+4)
        out=emit_utf8(o,out,cp)
        at=at+width
    return out-128

def pair(s:readbuf,at:u64,big:bool) -> u64:
    if big:
        return (byte(s,at)<<8)|byte(s,at+1)
    return byte(s,at)|(byte(s,at+1)<<8)

def decode_error(s:readbuf,o:mutbuf,w:mutbuf,kind:u64,reason:u64,start:u64,end:u64) -> u64:
    put(o,8,2)
    put(o,24,reason)
    put(o,64,kind)
    put(o,72,start-get(w,24))
    put(o,80,end-get(w,24))
    put(o,88,byte(s,start))
    put(o,112,get(w,24))
    return NONE

def parse(o:mutbuf,w:mutbuf) -> u64:
    at=white(o,0)
    depth=0
    need=1
    while True:
        if need==1:
            if at>=get(w,8):
                return error(o,1,at)
            ch=byte(o,128+at)
            if ch==123 or ch==91:
                row=STACK+depth*16
                if row>KEYS-16:
                    put(o,8,6)
                    return 0
                put(w,row,0)
                frame_put(w,row,0,choose(ch==123,1,2))
                frame_put(w,row,8,choose(ch==123,1,5))
                put(w,64,get(w,64)+1)
                frame_put(w,row,16,get(w,64))
                frame_put(w,row,24,0)
                depth=depth+1
                at=white(o,at+1)
            else:
                at=primitive(o,w,at)
                if at==NONE:
                    return 0
            need=0
        elif depth==0:
            if at!=get(w,8):
                return error(o,2,at)
            return 0
        else:
            row=STACK+(depth-1)*16
            kind=frame_get(w,row,0)
            stage=frame_get(w,row,8)
            ch=choose(at<get(w,8),byte(o,128+minimum(at,get(w,8))),0)
            if kind==1:
                if stage==1 or stage==2:
                    if ch==125:
                        if stage==2:
                            return error(o,9,get(w,72))
                        if frame_get(w,row,24)!=0:
                            put(o,8,3)
                            return 0
                        depth=depth-1
                        at=white(o,at+1)
                    else:
                        if ch!=34:
                            return error(o,3,at)
                        end=scan_string(o,at)
                        if end==NONE:
                            return 0
                        remember(o,w,row,at)
                        at=white(o,end)
                        if at>=get(w,8) or byte(o,128+at)!=58:
                            return error(o,4,at)
                        at=white(o,at+1)
                        frame_put(w,row,8,4)
                        need=1
                elif ch==125:
                    if frame_get(w,row,24)!=0:
                        put(o,8,3)
                        return 0
                    depth=depth-1
                    at=white(o,at+1)
                elif ch==44:
                    put(w,72,at)
                    frame_put(w,row,8,2)
                    at=white(o,at+1)
                else:
                    return error(o,5,at)
            else:
                if stage==5 or stage==6:
                    if ch==93:
                        if stage==6:
                            return error(o,10,get(w,72))
                        depth=depth-1
                        at=white(o,at+1)
                    else:
                        frame_put(w,row,8,7)
                        need=1
                elif ch==93:
                    depth=depth-1
                    at=white(o,at+1)
                elif ch==44:
                    put(w,72,at)
                    frame_put(w,row,8,6)
                    at=white(o,at+1)
                else:
                    return error(o,5,at)
    return 0

def frame_get(w:mutbuf,row:u64,index:u64) -> u64:
    if index==16:
        return get(w,row+8)
    shift=choose(index==0,0,choose(index==8,8,16))
    return (get(w,row)>>shift)&255

def frame_put(w:mutbuf,row:u64,index:u64,value:u64) -> unit:
    if index==16:
        put(w,row+8,value)
    else:
        shift=choose(index==0,0,choose(index==8,8,16))
        old=get(w,row)
        put(w,row,(old^(old&(255<<shift)))|(value<<shift))

def primitive(o:mutbuf,w:mutbuf,at:u64) -> u64:
    ch=byte(o,128+at)
    end=NONE
    if ch==34:
        end=scan_string(o,at)
    elif same(o,at,1819047278,4):
        end=at+4
    elif same(o,at,1702195828,4):
        end=at+4
    elif same(o,at,435728179558,5):
        end=at+5
    elif same(o,at,5136718,3) or same(o,at,8751735898823355977,8) or (ch==45 and same(o,at+1,8751735898823355977,8)):
        put(o,8,4)
        return NONE
    elif ch==45 or (ch>=48 and ch<=57):
        end=number(o,w,at)
    if end==NONE:
        if get(o,8)==0:
            error(o,1,at)
        return NONE
    return white(o,end)

def same(o:mutbuf,at:u64,value:u64,n:u64) -> bool:
    if at>get(o,16) or n>get(o,16)-at:
        return False
    i=0
    while i<n:
        if byte(o,128+at+i)!=((value>>(8*i))&255):
            return False
        i=i+1
    return True

def number(o:mutbuf,w:mutbuf,at:u64) -> u64:
    n=get(w,8)
    p=at
    if byte(o,128+p)==45:
        p=p+1
    if p>=n:
        return NONE
    digits=0
    ch=byte(o,128+p)
    if ch==48:
        digits=1
        p=p+1
    elif ch>=49 and ch<=57:
        while p<n and digit(byte(o,128+p)):
            digits=digits+1
            p=p+1
    else:
        return NONE
    floating=0
    if p+1<n and byte(o,128+p)==46 and digit(byte(o,128+p+1)):
        floating=1
        p=p+2
        while p<n and digit(byte(o,128+p)):
            p=p+1
    if p<n and (byte(o,128+p)==101 or byte(o,128+p)==69):
        e=p+1
        if e<n and (byte(o,128+e)==43 or byte(o,128+e)==45):
            e=e+1
        if e<n and digit(byte(o,128+e)):
            floating=1
            p=e+1
            while p<n and digit(byte(o,128+p)):
                p=p+1
    if floating==0 and get(w,2248)!=0 and digits>get(w,2248):
        put(o,8,5)
        put(o,112,digits)
        return NONE
    return p

def scan_string(o:mutbuf,start:u64) -> u64:
    n=get(o,16)
    p=start+1
    while p<n:
        ch=byte(o,128+p)
        if ch==34:
            return p+1
        if ch<32:
            error(o,7,p)
            return NONE
        if ch==92:
            old=p
            p=p+1
            if p>=n:
                error(o,6,start)
                return NONE
            ch=byte(o,128+p)
            if ch==117:
                if n-p<=5:
                    error(o,8,p)
                    return NONE
                i=1
                while i<=4:
                    if hexval(byte(o,128+p+i))==NONE:
                        error(o,8,p)
                        return NONE
                    i=i+1
                p=p+4
            elif ch!=34 and ch!=47 and ch!=92 and ch!=98 and ch!=102 and ch!=110 and ch!=114 and ch!=116:
                error(o,11,old)
                return NONE
        p=p+1
    error(o,6,start)
    return NONE

def remember(o:mutbuf,w:mutbuf,frame:u64,start:u64) -> u64:
    at=start+1
    h=14695981039346656037
    while byte(o,128+at)!=34:
        cp=key_char(o,w,at)
        at=get(w,136)
        h=(h^cp)*1099511628211
    owner=frame_get(w,frame,16)
    slot=(h^(owner*1099511628211))&(get(w,16)-1)
    head=get(w,TABLE+slot*8)
    cursor=head
    while cursor!=0:
        r=KEYS+(cursor-1)*32
        if get(w,r)==h and get(w,r+8)==owner and key_same(o,w,get(w,r+16),start):
            frame_put(w,frame,24,1)
            return 0
        cursor=get(w,r+24)
    count=get(w,80)
    r=KEYS+count*32
    put(w,r,h)
    put(w,r+8,owner)
    put(w,r+16,start)
    put(w,r+24,head)
    put(w,80,count+1)
    put(w,TABLE+slot*8,count+1)
    return 0

def key_same(o:mutbuf,w:mutbuf,a:u64,b:u64) -> bool:
    a=a+1
    b=b+1
    while True:
        ca=byte(o,128+a)
        cb=byte(o,128+b)
        if ca==34 or cb==34:
            return ca==cb
        x=key_char(o,w,a)
        a=get(w,136)
        y=key_char(o,w,b)
        b=get(w,136)
        if x!=y:
            return False
    return False

def key_char(o:mutbuf,w:mutbuf,at:u64) -> u64:
    cp=byte(o,128+at)
    at=at+1
    if cp==92:
        cp=byte(o,128+at)
        at=at+1
        if cp==117:
            cp=hex4(o,at)
            at=at+4
            if cp>=55296 and cp<56320 and at+6<=get(o,16) and byte(o,128+at)==92 and byte(o,128+at+1)==117:
                low=hex4(o,at+2)
                if low>=56320 and low<=57343:
                    cp=65536+((cp-55296)<<10)+low-56320
                    at=at+6
        elif cp==98:
            cp=8
        elif cp==102:
            cp=12
        elif cp==110:
            cp=10
        elif cp==114:
            cp=13
        elif cp==116:
            cp=9
    elif cp>=192:
        need=choose(cp<224,2,choose(cp<240,3,4))
        cp=cp&choose(need==2,31,choose(need==3,15,7))
        i=1
        while i<need:
            cp=(cp<<6)|(byte(o,128+at)&63)
            at=at+1
            i=i+1
    put(w,136,at)
    return cp

def location(o:mutbuf,position:u64) -> u64:
    p=0
    chars=0
    line=1
    col=1
    while p<position:
        cp=byte(o,128+p)
        width=1
        if cp>=192:
            width=choose(cp<224,2,choose(cp<240,3,4))
        if cp==10:
            line=line+1
            col=1
        else:
            col=col+1
        chars=chars+1
        p=p+width
    put(o,40,chars)
    put(o,48,line)
    put(o,56,col)
    return 0

def error(o:mutbuf,code:u64,at:u64) -> u64:
    put(o,8,1)
    put(o,24,code)
    put(o,32,at)
    return 0

def emit_utf8(o:mutbuf,at:u64,cp:u64) -> u64:
    if cp<128:
        store(o,at,cp)
        return at+1
    if cp<2048:
        store(o,at,192|(cp>>6))
        store(o,at+1,128|(cp&63))
        return at+2
    if cp<65536:
        store(o,at,224|(cp>>12))
        store(o,at+1,128|((cp>>6)&63))
        store(o,at+2,128|(cp&63))
        return at+3
    store(o,at,240|(cp>>18))
    store(o,at+1,128|((cp>>12)&63))
    store(o,at+2,128|((cp>>6)&63))
    store(o,at+3,128|(cp&63))
    return at+4

def white(o:mutbuf,p:u64) -> u64:
    while p<get(o,16):
        ch=byte(o,128+p)
        if ch!=32 and ch!=9 and ch!=10 and ch!=13:
            return p
        p=p+1
    return p

def hex4(o:mutbuf,p:u64) -> u64:
    value=0
    i=0
    while i<4:
        value=(value<<4)|hexval(byte(o,128+p+i))
        i=i+1
    return value

def hexval(c:u64) -> u64:
    if c>=48 and c<=57:
        return c-48
    if c>=65 and c<=70:
        return c-55
    if c>=97 and c<=102:
        return c-87
    return NONE

def digit(c:u64) -> bool:
    return c>=48 and c<=57

def minimum(a:u64,b:u64) -> u64:
    return choose(a<b,a,b)

def get(w:mutbuf,at:u64) -> u64:
    return word_load(w,at)

def put(w:mutbuf,at:u64,value:u64) -> unit:
    word_store(w,at,value)

def zero(w:mutbuf,at:u64,n:u64) -> unit:
    while n>=8:
        word_store(w,at,0)
        at=at+8
        n=n-8
    while n!=0:
        store(w,at,0)
        at=at+1
        n=n-1
'''
def program():
    out=SOURCE
    for name,value in C.items():out=re.sub(r'\b'+name+r'\b',str(value),out)
    tree=ast.parse(out)
    for fn in tree.body:
        if fn.returns.id=="unit":
            fn.returns=ast.Name(id="u64",ctx=ast.Load())
            fn.body.append(ast.Return(value=ast.Constant(value=0)))
    return ast.unparse(ast.fix_missing_locations(tree))
def main():
    d=document(program(),'ndu_rank_native_owner_json')
    p=ROOT/'examples/hia_bootstrap/ndu_rank_native_owner_json.hepta';p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']))
if __name__=='__main__':main()
