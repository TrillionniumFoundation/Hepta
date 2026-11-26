"""Private native filesystem-byte/WTF-8 conversion for owned tempdir buffers."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(MAGIC=int.from_bytes(b'HIAGTCQ1','little'),REPLY=int.from_bytes(b'HIAGTCR1','little'),BAD=4294967293)
SOURCE=r'''
def tempdir_codec(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or length(o)<128 or length(w)<32:
        return BAD
    if word_load(s,0)!=MAGIC or word_load(s,8)>1 or word_load(s,16)!=length(s)-128:
        return BAD
    i=24
    while i<128:
        if word_load(s,i)!=0:
            return BAD
        i=i+8
    n=word_load(s,16)
    if n>3074457345618258559:
        return BAD
    count=convert(s,o,w,False)
    if word_load(w,0)!=0:
        zero(o,0,128)
        word_store(o,0,REPLY)
        word_store(o,8,2)
        return 0
    if count>length(o)-128:
        return BAD
    zero(o,0,128)
    word_store(o,0,REPLY)
    word_store(o,16,count)
    convert(s,o,w,True)
    return 0

def convert(s:readbuf,o:mutbuf,w:mutbuf,writing:bool) -> u64:
    i=0
    n=word_load(s,16)
    out=0
    word_store(w,0,0)
    while i<n:
        first=byte(s,128+i)
        width=utf8_width(s,128+i,n-i)
        if word_load(s,8)==0:
            if width==0:
                emit(o,out,237,writing)
                emit(o,out+1,176+(first>>6),writing)
                emit(o,out+2,128+(first&63),writing)
                out=out+3
                i=i+1
            else:
                j=0
                while j<width:
                    emit(o,out,byte(s,128+i+j),writing)
                    out=out+1
                    j=j+1
                i=i+width
        else:
            special=False
            if n-i>=3 and first==237:
                second=byte(s,129+i)
                third=byte(s,130+i)
                if (second==178 or second==179) and third>=128 and third<=191:
                    emit(o,out,((second&3)<<6)|(third&63),writing)
                    out=out+1
                    i=i+3
                    special=True
            if special==False:
                if width==0:
                    word_store(w,0,2)
                    return 0
                j=0
                while j<width:
                    emit(o,out,byte(s,128+i+j),writing)
                    out=out+1
                    j=j+1
                i=i+width
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
    if width==0 or width>n:
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

def emit(o:mutbuf,at:u64,value:u64,writing:bool) -> u64:
    if writing:
        store(o,128+at,value)
    return 0

def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0
'''
def source_program():
    source=SOURCE
    for key,value in sorted(C.items(),key=lambda row:-len(row[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    doc=document(source_program(),'generation_lease_owner_tempdir_codec')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_tempdir_codec.hepta'
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,len(doc['functions']),sum(len(f['blocks'])for f in doc['functions']),sum(len(b['ops'])for f in doc['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
