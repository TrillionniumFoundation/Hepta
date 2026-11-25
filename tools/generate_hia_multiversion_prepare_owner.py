"""Native build -> pinned artifact/receipt -> loader/VM -> owned retirement."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_multiversion_intake import SOURCE as HELPERS
from tools.generate_hia_multiversion_prepare_proof import SOURCE as PROOF
ROOT=Path(__file__).resolve().parents[1]
C={'REQUEST':int.from_bytes(b'HIAMVGF1','little'),'REPLY':int.from_bytes(b'HIAMVGR1','little'),'STATE':int.from_bytes(b'HIAMVGS1','little'),
   'BUILD_REQUEST':int.from_bytes(b'HIAMVBF1','little'),'BUILD_REPLY':int.from_bytes(b'HIAMVBR1','little'),
   'IMAGE_REQUEST':int.from_bytes(b'HIAMVI02','little'),'IMAGE_REPLY':int.from_bytes(b'HIAMVIR1','little'),'IMAGE_STATE':int.from_bytes(b'HIAMVIS1','little'),
   'PROBE_REPLY':int.from_bytes(b'HIAMVPR1','little'),'RETIRE_REQUEST':int.from_bytes(b'HIAMVRT1','little'),'ABI_MAGIC':int.from_bytes(b'HIAMVAB1','little'),
   'WORK':192<<20,'HOLDER':160<<20,'CORE':160<<20,'ABI':168<<20,'PATH':169<<20,'PIN':170<<20,'BOUT':180<<20,
   'IOUT':182<<20,'PROUT':(182<<20)+512,'ROUT':(182<<20)+1024,'RREQ':(182<<20)+2048,
   'CTRL':186<<20,'NONE':(1<<64)-1,'NEGATIVE':(1<<64)-4095}
SOURCE=r'''
def prepare_owner(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<WORK or length(o)<2048:
        return 4294967293
    phase=get(w,CTRL)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        return after_build(o,w)
    if phase==2:
        return after_image(o,w)
    if phase==3:
        return after_probe(o,w)
    if phase==4:
        put(w,CTRL+64,get(w,CTRL+8))
        if get(w,CTRL+24)!=2:
            put(w,CTRL+48,0)
        return finish(o,w)
    if phase==10:
        return empty_holder(o,w)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<256 or readword(s,0)!=REQUEST or readword(s,8)>2:
        return 4294967293
    op=readword(s,8)
    if op!=0:
        if length(s)!=256 or get(w,CTRL+16)!=STATE:
            return 4294967293
        i=16
        while i<256:
            if readword(s,i)!=0:
                return 4294967293
            i=i+8
        put(w,CTRL+24,op)
        return retirement(o,w,op)
    if length(o)<1050624 or get(w,CTRL+16)!=0:
        return 4294967293
    fd=readword(s,16)
    deadline=readword(s,24)
    cancel=readword(s,32)
    n=readword(s,40)
    ab=readword(s,48)
    pn=readword(s,56)
    if fd<3 or fd>2147483647 or deadline==0 or (cancel!=0 and (cancel&7)!=0):
        return 4294967293
    if n==0 or n>8388608 or n>length(s)-256 or ab>length(s)-256-n or pn!=length(s)-256-n-ab:
        return 4294967293
    if ab<336 or ab>5136 or readword(s,256+n)!=ABI_MAGIC or pn==0 or pn>4095:
        return 4294967293
    count=readword(s,264+n)
    if count==0 or count>16 or ab!=16+320*count or abi_valid(s,256+n,count)==False:
        return 4294967293
    if byte(s,256+n+ab)!=47:
        return 4294967293
    i=0
    while i<pn:
        if byte(s,256+n+ab+i)==0:
            return 4294967293
        i=i+1
    i=64
    while i<128:
        if readword(s,i)!=0:
            return 4294967293
        i=i+8
    i=160
    while i<256:
        if readword(s,i)!=0:
            return 4294967293
        i=i+8
    zero(w,CTRL,4096)
    put(w,CTRL+16,STATE)
    put(w,CTRL+64,NONE)
    put(w,CTRL+88,n)
    put(w,CTRL+96,ab)
    put(w,CTRL+104,pn)
    copy_input(s,256,w,CORE,n)
    copy_input(s,256+n,w,ABI,ab)
    copy_input(s,256+n+ab,w,PATH,pn)
    store(w,PATH+pn,0)
    copy_input(s,0,w,PIN,length(s))
    put(w,PIN,BUILD_REQUEST)
    put(w,PIN+8,1)
    zero(w,BOUT,512)
    put(w,BOUT+88,NONE)
    put(w,BOUT+96,NONE)
    zero(w,IOUT,2048)
    return role(o,w,1,2,PIN,length(s),BOUT,1049088,0,134217728)

def after_build(o:mutbuf,w:mutbuf) -> u32:
    raw=get(w,CTRL+8)
    if raw!=0 or get(w,BOUT)!=BUILD_REPLY or get(w,BOUT+8)!=0:
        put(w,CTRL+32,1)
        put(w,CTRL+40,raw)
        put(w,CTRL+56,get(w,BOUT+16))
        return call(o,w,10,39,0,0,0,0,0,0,0)
    n=get(w,BOUT+80)
    if n==0 or n>1048576 or get(w,BOUT+88)!=NONE or get(w,BOUT+96)!=NONE:
        put(w,CTRL+32,1)
        put(w,CTRL+40,4294967293)
        return call(o,w,10,39,0,0,0,0,0,0,0)
    put(w,CTRL+72,n)
    zero(w,PIN,128)
    put(w,PIN,IMAGE_REQUEST)
    put(w,PIN+8,get(w,CTRL+104))
    put(w,PIN+16,get(w,CTRL+96))
    put(w,PIN+24,n)
    copy(w,BOUT+160,PIN+32,32)
    pn=get(w,CTRL+104)
    ab=get(w,CTRL+96)
    copy(w,PATH,PIN+128,pn)
    copy(w,ABI,PIN+128+pn,ab)
    copy(w,BOUT+512,PIN+128+pn+ab,n)
    zero(w,0,8192)
    return role(o,w,2,3,PIN,128+pn+ab+n,IOUT,512,0,HOLDER)

def after_image(o:mutbuf,w:mutbuf) -> u32:
    raw=get(w,CTRL+8)
    if raw!=0 or get(w,IOUT)!=IMAGE_REPLY or get(w,IOUT+8)!=0:
        put(w,CTRL+32,2)
        put(w,CTRL+40,raw)
        put(w,CTRL+56,get(w,IOUT+16))
        if get(w,16)!=IMAGE_STATE or (get(w,0)!=902 and get(w,0)!=999):
            return call(o,w,10,39,0,0,0,0,0,0,0)
        return retirement(o,w,1)
    copy(w,1872,CTRL+512,32)
    copy(w,1904,CTRL+544,32)
    put(w,CTRL+576,get(w,248))
    return role(o,w,3,4,CORE,get(w,CTRL+88),PROUT,128,0,HOLDER)

def after_probe(o:mutbuf,w:mutbuf) -> u32:
    raw=get(w,CTRL+8)
    if raw!=0 or get(w,PROUT)!=PROBE_REPLY or get(w,PROUT+8)!=0:
        put(w,CTRL+32,3)
        put(w,CTRL+40,raw)
        put(w,CTRL+56,get(w,PROUT+16))
        return retirement(o,w,1)
    put(w,CTRL+48,1)
    return finish(o,w)

def empty_holder(o:mutbuf,w:mutbuf) -> u32:
    pid=get(w,CTRL+8)
    if pid==0 or pid>=NEGATIVE:
        put(w,CTRL+64,65)
        return finish(o,w)
    zero(w,0,8192)
    put(w,0,902)
    put(w,16,IMAGE_STATE)
    put(w,24,pid)
    put(w,32,NONE)
    put(w,40,NONE)
    put(w,48,NONE)
    copy(w,PATH,8192,get(w,CTRL+104))
    store(w,8192+get(w,CTRL+104),0)
    return retirement(o,w,1)

def retirement(o:mutbuf,w:mutbuf,op:u64) -> u32:
    put(w,RREQ,RETIRE_REQUEST)
    put(w,RREQ+8,op)
    put(w,RREQ+16,0)
    return role(o,w,4,5,RREQ,24,ROUT,768,0,HOLDER)

def finish(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,2048)
    put(o,0,REPLY)
    status=get(w,CTRL+32)
    if get(w,CTRL+24)!=0:
        status=get(w,CTRL+64)
    put(o,8,status)
    put(o,16,get(w,CTRL+40))
    put(o,24,get(w,CTRL+56))
    put(o,32,get(w,CTRL+64))
    put(o,40,get(w,CTRL+48))
    put(o,48,get(w,CTRL+88))
    put(o,56,get(w,CTRL+96))
    put(o,64,get(w,CTRL+104))
    put(o,80,get(w,BOUT+48))
    put(o,88,get(w,PROUT+56))
    put(o,96,get(w,PROUT+64))
    put(o,104,get(w,BOUT+88))
    put(o,112,get(w,BOUT+96))
    put(w,BOUT+88,NONE)
    put(w,BOUT+96,NONE)
    put(o,120,get(w,BOUT+24))
    copy_output(w,BOUT+128,o,128,96)
    copy_output(w,IOUT+64,o,224,32)
    copy_output(w,CTRL+512,o,256,64)
    put(o,320,get(w,CTRL+576))
    put(o,328,get(w,IOUT+48))
    copy_output(w,IOUT,o,512,512)
    copy_output(w,PROUT,o,1024,128)
    copy_output(w,ROUT,o,1152,768)
    if get(w,CTRL+48)==0:
        zero(o,768,256)
    if get(w,CTRL+24)==0:
        n=get(w,CTRL+72)
        put(o,72,n)
        copy_output(w,BOUT+512,o,2048,n)
    return 0

def role(o:mutbuf,w:mutbuf,next:u64,action:u64,si:u64,sn:u64,oi:u64,on:u64,wi:u64,wn:u64) -> u32:
    put(w,CTRL,next)
    put(o,0,si)
    put(o,8,sn)
    put(o,16,oi)
    put(o,24,on)
    put(o,32,wi)
    put(o,40,wn)
    return action

def call(o:mutbuf,w:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(w,CTRL,next)
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1
'''
SOURCE+='\n'+PROOF[PROOF.index('def abi_valid('):PROOF.index('def capture(')]
SOURCE+='\n'+HELPERS[HELPERS.index('def zero('):]
def source_program():
    s=SOURCE
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s

def main():
    t=document(source_program(),'multiversion_prepare_owner');p=ROOT/'examples/hia_bootstrap/multiversion_prepare_owner.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
