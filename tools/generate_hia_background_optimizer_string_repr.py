"""CPython 3.14 string repr for native BG errors and shared result values.

The printable ranges and quote/escape algorithm come from the existing native
CLI formatter. This separately qualified leaf embeds the observed fixed table
in its HIA source; no Python, table file, or Rust policy is used at runtime.
"""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_structure import SOURCE as structure_source
ROOT=Path(__file__).resolve().parents[1]
C={'REQUEST':int.from_bytes(b'HIABRP01','little'),'REPLY':int.from_bytes(b'HIABRR01','little'),'BAD':4294967293,'SHORT':4294967294,'NONE':(1<<64)-1}
SOURCE=r'''
def background_optimizer_string_repr(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or length(w)<16384 or read64(s,0)!=REQUEST or read64(s,8)>1 or read64(s,16)>2 or read64(s,24)!=length(s)-64:
        return BAD
    i=32
    while i<64:
        if read64(s,i)!=0:
            return BAD
        i=i+8
    if length(o)<64:
        return SHORT
    zero(w,0,128)
    constants(w)
    if scan(s,w)==False:
        return BAD
    render(s,o,w)
    needed=get(w,0)
    if get(w,48)!=0:
        return BAD
    if read64(s,8)==1:
        if needed>length(o)-64:
            return SHORT
        put(w,24,1)
        put(w,0,0)
        render(s,o,w)
    zero(o,0,64)
    put(o,0,REPLY)
    put(o,8,read64(s,16))
    put(o,16,needed)
    put(o,24,get(w,40))
    put(o,32,get(w,32))
    return 0

def scan(s:readbuf,w:mutbuf) -> bool:
    at=64
    single=False
    double=False
    count=0
    while at<length(s):
        cp=decode(s,w,at)
        if get(w,48)!=0:
            return False
        if cp==39:
            single=True
        if cp==34:
            double=True
        count=count+1
        at=at+get(w,56)
    put(w,32,choose(single and double==False,34,39))
    put(w,40,count)
    return True

def render(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    kind=read64(s,16)
    put(w,8,0)
    if kind==2:
        prefix(o,w)
    if kind!=0:
        emit(o,w,34)
        put(w,8,1)
    quote=get(w,32)
    emit(o,w,quote)
    at=64
    while at<length(s):
        cp=decode(s,w,at)
        if cp==quote or cp==92:
            emit(o,w,92)
            emit(o,w,cp)
        elif cp==9 or cp==10 or cp==13:
            emit(o,w,92)
            emit(o,w,choose(cp==9,116,choose(cp==10,110,114)))
        elif printable(w,cp):
            point(o,w,cp)
        else:
            emit(o,w,92)
            if cp<256:
                emit(o,w,120)
                hex_digits(o,w,cp,2)
            elif cp<65536:
                emit(o,w,117)
                hex_digits(o,w,cp,4)
            else:
                emit(o,w,85)
                hex_digits(o,w,cp,8)
        at=at+get(w,56)
    emit(o,w,quote)
    put(w,8,0)
    if kind!=0:
        emit(o,w,34)
    if kind==2:
        suffix(o,w)
    return 0

def emit(o:mutbuf,w:mutbuf,value:u64) -> u64:
    if get(w,8)!=0 and (value==34 or value==92):
        raw(o,w,92)
    return raw(o,w,value)

def raw(o:mutbuf,w:mutbuf,value:u64) -> u64:
    at=get(w,0)
    if at==NONE:
        put(w,48,1)
        return 0
    if get(w,24)!=0:
        store(o,64+at,value)
    put(w,0,at+1)
    return 0

def point(o:mutbuf,w:mutbuf,cp:u64) -> u64:
    if cp<128:
        emit(o,w,cp)
    elif cp<2048:
        emit(o,w,192|(cp>>6))
        emit(o,w,128|(cp&63))
    elif cp<65536:
        emit(o,w,224|(cp>>12))
        emit(o,w,128|((cp>>6)&63))
        emit(o,w,128|(cp&63))
    else:
        emit(o,w,240|(cp>>18))
        emit(o,w,128|((cp>>12)&63))
        emit(o,w,128|((cp>>6)&63))
        emit(o,w,128|(cp&63))
    return 0

def decode(s:readbuf,w:mutbuf,at:u64) -> u64:
    cp=byte(s,at)
    width=1
    if cp>=128:
        if cp<194 or cp>244:
            put(w,48,1)
            return 0
        width=choose(cp<224,2,choose(cp<240,3,4))
        if width>length(s)-at:
            put(w,48,1)
            return 0
        first=cp
        cp=cp&choose(width==2,31,choose(width==3,15,7))
        i=1
        while i<width:
            b=byte(s,at+i)
            if b<128 or b>191:
                put(w,48,1)
                return 0
            if i==1 and ((first==224 and b<160) or (first==240 and b<144) or (first==244 and b>143)):
                put(w,48,1)
                return 0
            cp=(cp<<6)|(b&63)
            i=i+1
    put(w,56,width)
    return cp

def printable(w:mutbuf,cp:u64) -> bool:
    lo=0
    hi=RANGE_COUNT
    while lo<hi:
        middle=(lo+hi)>>1
        value=get(w,8192+middle*8)
        lower=value&2097151
        upper=value>>21
        if cp<lower:
            hi=middle
        elif cp>upper:
            lo=middle+1
        else:
            return True
    return False

def hex_digits(o:mutbuf,w:mutbuf,value:u64,count:u64) -> u64:
    index=count
    while index>0:
        index=index-1
        digit=(value>>(index*4))&15
        emit(o,w,choose(digit<10,48+digit,87+digit))
    return 0
'''
def source_program():
    tables=json.loads((ROOT/'tools/hia_cli_unicode_tables.json').read_text())
    ranges=tables['profiles']['314']['printable_ranges']
    assert len(ranges)==736 and tables['profiles']['314']['printable_count']==154810
    helpers=[ast.unparse(n).replace('SEEN','0')for n in ast.parse(structure_source).body if n.name in {'read64','get','put','zero','choose'}]
    text=SOURCE+'\n'+'\n'.join(helpers)+'\n'
    chunks=[ranges[i:i+96]for i in range(0,len(ranges),96)]
    text+='\ndef constants(w:mutbuf) -> u64:\n'+'\n'.join('    constants_'+str(i)+'(w)'for i in range(len(chunks)))+'\n    return 0\n'
    cursor=0
    for i,chunk in enumerate(chunks):
        text+='\ndef constants_'+str(i)+'(w:mutbuf) -> u64:\n'
        for low,high in chunk:
            text+=f'    put(w,{8192+cursor*8},{low|(high<<21)})\n';cursor+=1
        text+='    return 0\n'
    for name,raw in [('prefix',b'{"message":'),('suffix',b',"type":"KeyError"}')]:
        text+='\ndef '+name+'(o:mutbuf,w:mutbuf) -> u64:\n'+'\n'.join(f'    emit(o,w,{b})'for b in raw)+'\n    return 0\n'
    values={**C,'RANGE_COUNT':len(ranges)}
    for key,value in sorted(values.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'background_optimizer_string_repr')
def main():
    tree=program();target=ROOT/'examples/hia_bootstrap/background_optimizer_string_repr.hepta';target.write_text(render_assembly(tree))
    print(target.name,target.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
