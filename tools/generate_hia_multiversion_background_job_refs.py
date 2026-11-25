"""Fixed native queue reference provider for actual strongly owned Jobs."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={'INPUT':int.from_bytes(b'HIABJRF1','little'),'OUTPUT':int.from_bytes(b'HIABJRO1','little'),'CONTEXT':int.from_bytes(b'HIABJRC1','little'),'JOB_INPUT':int.from_bytes(b'HIABJO01','little'),'JOB_OUTPUT':int.from_bytes(b'HIABJOR1','little'),'PHASE':128,'FEEDBACK':136,'RQ':256,'RP':512}
SOURCE=r'''
def job_refs(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=64 or length(o)<4096 or length(w)<64:
        return 4294967293
    if word_load(s,0)!=INPUT or word_load(s,8)<1 or word_load(s,8)>2:
        return 4294967293
    if word_load(s,40)!=0 or word_load(s,48)!=0 or word_load(s,56)!=0:
        return 4294967293
    if word_load(w,0)!=CONTEXT or word_load(w,8)==0 or word_load(w,16)==0 or word_load(w,24)<256:
        return 4294967293
    if word_load(w,32)!=0 or word_load(w,40)!=0 or word_load(w,48)!=0 or word_load(w,56)!=0:
        return 4294967293
    phase=word_load(o,PHASE)
    if phase==0:
        zero(o,RQ,128)
        put(o,RQ,JOB_INPUT)
        put(o,RQ+8,word_load(s,8)+1)
        put(o,RQ+24,word_load(s,16))
        put(o,RQ+32,word_load(s,24))
        put(o,RQ+40,word_load(s,32))
        put(o,PHASE,1)
        put(o,0,word_load(w,8))
        put(o,8,51)
        put(o,16,RQ)
        put(o,24,128)
        put(o,32,RP)
        put(o,40,2048)
        put(o,48,word_load(w,16))
        put(o,56,word_load(w,24))
        return 4
    if phase==1:
        if word_load(o,FEEDBACK)!=0 or word_load(o,RP)!=JOB_OUTPUT:
            return finish(o,9,0,0,0)
        status=word_load(o,RP+8)
        if status!=0:
            return finish(o,status,0,0,0)
        if word_load(s,8)==2:
            return finish(o,0,0,0,0)
        if word_load(o,RP+16)==0:
            return finish(o,9,0,0,0)
        return finish(o,0,word_load(o,RP+16),word_load(o,RP+24),word_load(o,RP+32))
    return 4294967293

def finish(o:mutbuf,status:u64,node:u64,a:u64,b:u64) -> u32:
    zero(o,0,128)
    put(o,0,OUTPUT)
    put(o,8,status)
    put(o,16,node)
    put(o,24,a)
    put(o,32,b)
    return 0

def put(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(n>>(i*8))&255)
        i=i+1
    return 0

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0
'''
def source_program():
    result=SOURCE
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        result=re.sub(r'\b'+key+r'\b',str(value),result)
    return result
def main():
    result=document(source_program(),'multiversion_background_job_refs')
    p=ROOT/'examples/hia_bootstrap/multiversion_background_job_refs.hepta'
    p.write_text(render_assembly(result))
    print(p.name,p.stat().st_size,len(result['functions']),sum(len(f['blocks'])for f in result['functions']),flush=True)
if __name__=='__main__':main()
