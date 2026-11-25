"""Bounded-window JSON quoting and POSIX surrogateescape path decoding."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT = Path(__file__).resolve().parents[1]
C = {'MAGIC': int.from_bytes(b'HIAPCDQ1', 'little'),
     'REPLY': int.from_bytes(b'HIAPCDR1', 'little'),
     'BAD': 4294967293, 'MAX': (1 << 64) - 1}
SOURCE = r'''
def path_string_codec(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(o)<128 or length(w)<32:
        return BAD
    if word_load(s,0)!=MAGIC or word_load(s,8)>1:
        return BAD
    n=word_load(s,16)
    limit=word_load(s,24)
    final=word_load(s,32)
    mode=word_load(s,8)
    if n!=length(s)-128 or limit>n or final>1 or n>3074457345618258581:
        return BAD
    if mode==0 and (limit!=n or final!=0):
        return BAD
    if mode==1 and final==0 and (n<3 or limit>n-3):
        return BAD
    i=40
    while i<128:
        if word_load(s,i)!=0:
            return BAD
        i=i+8
    count=convert(s,o,w,False)
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,word_load(w,0))
    put(o,16,count)
    put(o,24,128+count)
    if count>length(o)-128:
        return 1
    convert(s,o,w,True)
    return 0

def convert(s:readbuf,o:mutbuf,w:mutbuf,writing:bool) -> u64:
    mode=word_load(s,8)
    n=word_load(s,16)
    limit=word_load(s,24)
    i=0
    out=0
    while i<limit:
        value=byte(s,128+i)
        if mode==0:
            if value==34 or value==92:
                output(o,out,92,writing)
                output(o,out+1,value,writing)
                out=out+2
            elif value<32:
                output(o,out,92,writing)
                output(o,out+1,117,writing)
                output(o,out+2,48,writing)
                output(o,out+3,48,writing)
                output(o,out+4,hex(value>>4),writing)
                output(o,out+5,hex(value&15),writing)
                out=out+6
            else:
                output(o,out,value,writing)
                out=out+1
            i=i+1
        else:
            width=utf8_width(s,128+i,n-i)
            if width==0:
                output(o,out,237,writing)
                output(o,out+1,176+(value>>6),writing)
                output(o,out+2,128+(value&63),writing)
                out=out+3
                i=i+1
            else:
                j=0
                while j<width:
                    output(o,out,byte(s,128+i+j),writing)
                    out=out+1
                    j=j+1
                i=i+width
    put(w,0,i)
    put(w,8,out)
    return out

def utf8_width(s:readbuf,at:u64,n:u64) -> u64:
    first=byte(s,at)
    if first<128:
        return 1
    width=0
    if first>=194 and first<=223:
        width=2
    elif first>=224 and first<=239:
        width=3
    elif first>=240 and first<=244:
        width=4
    if width==0 or n<width:
        return 0
    second=byte(s,at+1)
    if second<128 or second>191:
        return 0
    if (first==224 and second<160) or (first==237 and second>=160) or (first==240 and second<144) or (first==244 and second>=144):
        return 0
    j=2
    while j<width:
        value=byte(s,at+j)
        if value<128 or value>191:
            return 0
        j=j+1
    return width

def output(o:mutbuf,at:u64,value:u64,writing:bool) -> u64:
    if writing:
        store(o,128+at,value)
    return 0

def hex(value:u64) -> u64:
    if value<10:
        return value+48
    return value+87

def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0

def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0
'''

def source_program():
    source = SOURCE
    for key, value in sorted(C.items(), key=lambda item: -len(item[0])):
        source = re.sub(r'\b' + key + r'\b', str(value), source)
    return source

def program():
    return document(source_program(), 'native_path_string_codec')

if __name__ == '__main__':
    tree = program()
    path = ROOT / 'examples/hia_bootstrap/native_path_string_codec.hepta'
    path.write_text(render_assembly(tree))
    print(path.name, path.stat().st_size, len(tree['functions']),
          sum(len(f['blocks']) for f in tree['functions']),
          sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']), flush=True)
