"""HIA outer normalization, exact Core identities, and scalar intake owner.

The normalizer is an actual captured process. No verified caller flag or raw
composite shortcut is accepted. This stage does not prove or publish code.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
ROOT=Path(__file__).resolve().parents[1]
C=dict(REQUEST=int.from_bytes(b'HIAMVNQ1','little'),REPLY=int.from_bytes(b'HIAMVNP1','little'),
 NORM=int.from_bytes(b'HIAVCF01','little'),PREQUEST=int.from_bytes(b'HIAMVPS1','little'),PREPLY=int.from_bytes(b'HIAMVPO1','little'),
 IREQUEST=int.from_bytes(b'HIAMVIT1','little'),IREPLY=int.from_bytes(b'HIAMVIP1','little'),ABIMAGIC=int.from_bytes(b'HIAMVAB1','little'),
 NONE=(1<<64)-1,NEG4=(1<<64)-4,WORK=256<<20,RAW=1<<20,PIN=10<<20,NORMAL=20<<20,IIN=37<<20,IOUT=46<<20,PWORK=56<<20,IWORK=80<<20,
 POUT=65536,HASHWORK=131072,CLOCK=98304,RAW_SHA=512,ORIGINAL_SHA=544,CORE_SHA=576,ABI_SHA=608)
SOURCE=r'''
def prepare(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<320 or length(w)<WORK:
        return 4294967293
    phase=get(w,0)
    result=get(w,8)
    if phase==0:
        return begin(s,o,w)
    if phase<20:
        return normalized(o,w,phase,result)
    if phase>=20 and phase<40:
        return identified(o,w,phase,result)
    if phase>=50 and phase<60:
        return diagnostics(o,w,phase,result)
    if phase>=70 and phase<80:
        return closing(o,w,phase,result)
    if phase>=90 and phase<100:
        return guarded(o,w,phase,result)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or readword(s,0)!=REQUEST or readword(s,8)>1:
        return 4294967293
    if readword(s,16)<3 or readword(s,16)>2147483647 or readword(s,24)==0:
        return 4294967293
    if readword(s,32)!=0 and (readword(s,32)&7)!=0:
        return 4294967293
    n=readword(s,40)
    if n>8388608 or length(s)-128!=n:
        return 4294967293
    i=48
    while i<128:
        if readword(s,i)!=0:
            return 4294967293
        i=i+8
    zero(w,128,64000)
    put(w,72,readword(s,32))
    put(w,80,readword(s,24))
    put(w,88,NONE)
    put(w,144,n)
    put(w,184,readword(s,8))
    put(w,256,NONE)
    put(w,264,NONE)
    put(w,312,NONE)
    put(w,320,NONE)
    copy_input(s,128,w,RAW,n)
    put(w,360,readword(s,16))
    return guard(o,w,1)

def normalized(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==1:
        zero(w,HASHWORK,1184)
        return role(w,2,4,RAW,get(w,144),RAW_SHA,32,HASHWORK,1184)
    if phase==2:
        if result!=32:
            return fail(o,w,5,result)
        put(w,224,2)
        return call(o,w,3,72,0,get(w,360),1030,3,0,0,0)
    if phase==3:
        if failed(result):
            return fail(o,w,7,result)
        put(w,88,result)
        return guard(o,w,4)
    if phase==4:
        return process(w,5,1)
    if phase==5:
        if process_reply(w,result)==False:
            return fail(o,w,8,0)
        if result!=0:
            return fail(o,w,7,result)
        put(w,256,get(w,POUT+48))
        put(w,264,get(w,POUT+56))
        put(w,200,get(w,POUT+24))
        if get(w,200)!=0:
            if get(w,200)!=512 and get(w,200)!=768:
                return fail(o,w,7,get(w,200))
            return close_streams(o,w,50)
        size=get(w,POUT+64)
        if size<64 or size>16777280 or get(w,POUT+72)!=0:
            return fail(o,w,8,size)
        put(w,248,size)
        put(w,272,0)
        return read_normal(o,w)
    if phase==6:
        if result==NEG4:
            return guard(o,w,7)
        if failed(result) or result==0 or result>get(w,248)-get(w,272):
            return fail(o,w,7,result)
        put(w,272,get(w,272)+result)
        if get(w,272)<get(w,248):
            return guard(o,w,7)
        return close_streams(o,w,8)
    if phase==7:
        return read_normal(o,w)
    if phase==8:
        size=get(w,248)
        if get(w,NORMAL)!=NORM or get(w,NORMAL+8)!=0 or get(w,NORMAL+16)!=0 or get(w,NORMAL+48)!=0 or get(w,NORMAL+56)!=0:
            return fail(o,w,8,0)
        profile=get(w,NORMAL+24)
        original=get(w,NORMAL+32)
        core=get(w,NORMAL+40)
        if profile>4 or original==0 or core==0 or original>8388608 or core>8388608:
            return fail(o,w,8,1)
        if original>size-64 or core!=size-64-original:
            return fail(o,w,8,2)
        put(w,192,profile)
        put(w,152,original)
        put(w,160,core)
        put(w,224,get(w,224)|1)
        return guard(o,w,20)
    return 4294967293

def identified(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==20:
        zero(w,HASHWORK,1184)
        return role(w,21,4,NORMAL+64,get(w,152),ORIGINAL_SHA,32,HASHWORK,1184)
    if phase==21:
        if result!=32:
            return fail(o,w,5,result)
        put(w,224,get(w,224)|4)
        return guard(o,w,22)
    if phase==22:
        zero(w,HASHWORK,1184)
        return role(w,23,4,NORMAL+64+get(w,152),get(w,160),CORE_SHA,32,HASHWORK,1184)
    if phase==23:
        if result!=32:
            return fail(o,w,5,result)
        put(w,224,get(w,224)|8)
        if get(w,192)!=0:
            return fail(o,w,3,1)
        if get(w,152)!=get(w,160) or equal(w,NORMAL+64,NORMAL+64+get(w,152),get(w,152))==False:
            return fail(o,w,8,3)
        zero(w,IIN,64)
        put(w,IIN,IREQUEST)
        put(w,IIN+8,get(w,184))
        put(w,IIN+16,get(w,160))
        copy(w,NORMAL+64+get(w,152),IIN+64,get(w,160))
        return guard(o,w,24)
    if phase==24:
        return role(w,25,3,IIN,64+get(w,160),IOUT,8396800,IWORK,167772160)
    if phase==25:
        if get(w,IOUT)!=IREPLY or get(w,IOUT+8)!=result:
            return fail(o,w,8,4)
        if result!=0:
            return fail(o,w,result,get(w,IOUT+16))
        if get(w,IOUT+24)!=get(w,160) or get(w,IOUT+32)!=get(w,160) or get(w,IOUT+56)!=get(w,184):
            return fail(o,w,8,5)
        if equal(w,IOUT+64,CORE_SHA,32)==False or equal(w,IOUT+96,CORE_SHA,32)==False or equal(w,IOUT+128,CORE_SHA,32)==False:
            return fail(o,w,8,6)
        if get(w,IOUT+192)!=7 or equal(w,IOUT+256,NORMAL+64+get(w,152),get(w,160))==False:
            return fail(o,w,8,7)
        exports=get(w,IOUT+48)
        abi=get(w,IOUT+40)
        if exports==0 or exports>16 or abi!=16+exports*320:
            return fail(o,w,8,8)
        put(w,176,exports)
        put(w,168,abi)
        copy(w,IOUT+160,ABI_SHA,32)
        put(w,224,get(w,224)|48)
        needed=320+get(w,152)+get(w,160)+abi
        if needed>length(o):
            return fail(o,w,6,needed)
        return guard(o,w,26)
    if phase==26:
        return final_close(o,w)
    return 4294967293

def diagnostics(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==50:
        return guard(o,w,51)
    if phase==51:
        return process(w,52,4)
    if phase==52:
        if process_reply(w,result)==False:
            return fail(o,w,8,9)
        if result!=0:
            return fail(o,w,7,result)
        put(w,256,get(w,POUT+48))
        put(w,264,get(w,POUT+56))
        put(w,208,get(w,POUT+24))
        if get(w,208)!=512:
            return fail(o,w,8,10)
        put(w,296,get(w,POUT+64))
        put(w,304,get(w,POUT+72))
        return guard(o,w,53)
    if phase==53:
        put(w,312,get(w,256))
        put(w,320,get(w,264))
        put(w,256,NONE)
        put(w,264,NONE)
        put(w,128,1)
        put(w,136,0)
        return final_close(o,w)
    return 4294967293

def process(w:mutbuf,next:u64,which:u64) -> u32:
    zero(w,PIN,128)
    put(w,PIN,PREQUEST)
    put(w,PIN+8,which)
    put(w,PIN+16,get(w,88))
    put(w,PIN+24,get(w,80))
    put(w,PIN+32,get(w,144))
    put(w,PIN+40,16777280)
    put(w,PIN+48,67108864)
    put(w,PIN+64,get(w,72))
    copy(w,RAW,PIN+128,get(w,144))
    zero(w,POUT,128)
    return role(w,next,2,PIN,128+get(w,144),POUT,128,PWORK,20971520)

def process_reply(w:mutbuf,result:u64) -> bool:
    if get(w,POUT)!=PREPLY or get(w,POUT+8)!=result or get(w,POUT+120)!=0:
        return False
    put(w,216,result)
    if result==0:
        a=get(w,POUT+48)
        b=get(w,POUT+56)
        if a<3 or a>2147483647 or b<3 or b>2147483647 or a==b:
            return False
        if get(w,POUT+96)!=1 or get(w,POUT+104)!=7 or get(w,POUT+112)!=15:
            return False
        if get(w,POUT+64)>16777280 or get(w,POUT+72)>67108864:
            return False
    return True

def read_normal(o:mutbuf,w:mutbuf) -> u32:
    count=get(w,248)-get(w,272)
    if count>65536:
        count=65536
    return call(o,w,6,17,4,get(w,256),NORMAL+get(w,272),count,get(w,272),0,0)

def close_streams(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(w,280,next)
    fd=get(w,256)
    put(w,256,NONE)
    if fd!=NONE:
        return call(o,w,70,3,0,fd,0,0,0,0,0)
    return closing(o,w,70,0)

def closing(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==70:
        fd=get(w,264)
        put(w,264,NONE)
        if fd!=NONE:
            return call(o,w,71,3,0,fd,0,0,0,0,0)
        phase=71
    if phase==71:
        next=get(w,280)
        if next!=0:
            put(w,0,next)
            put(w,8,0)
            return 6
        fd=get(w,88)
        put(w,88,NONE)
        if fd!=NONE:
            return call(o,w,72,3,0,fd,0,0,0,0,0)
        phase=72
    if phase==72:
        return finish(o,w)
    return 4294967293

def fail(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(w,128,status)
    put(w,136,detail)
    return final_close(o,w)

def final_close(o:mutbuf,w:mutbuf) -> u32:
    return close_streams(o,w,0)

def guard(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(w,344,next)
    return call(o,w,90,228,4,1,CLOCK,0,0,0,0)

def guarded(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==90:
        if failed(result):
            return fail(o,w,7,result)
        now=get(w,CLOCK)*1000000000+get(w,CLOCK+8)
        if now>=get(w,80):
            put(w,216,1)
            return fail(o,w,7,1)
        put(w,0,91)
        return 5
    if phase==91:
        if result==1:
            put(w,216,2)
            return fail(o,w,7,2)
        put(w,0,get(w,344))
        put(w,8,0)
        return 6
    return 4294967293

def role(w:mutbuf,next:u64,action:u64,si:u64,sn:u64,oi:u64,on:u64,wi:u64,wn:u64) -> u32:
    put(w,0,next)
    put(w,16,si)
    put(w,24,sn)
    put(w,32,oi)
    put(w,40,on)
    put(w,48,wi)
    put(w,56,wn)
    return action

def call(o:mutbuf,w:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(w,0,next)
    put(o,0,nr)
    put(o,8,mask)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def finish(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,320)
    put(o,0,REPLY)
    put(o,8,get(w,128))
    put(o,16,get(w,136))
    put(o,24,get(w,144))
    put(o,32,get(w,152))
    put(o,40,get(w,160))
    put(o,48,get(w,168))
    put(o,56,get(w,176))
    put(o,64,get(w,184))
    put(o,72,get(w,192))
    copy_output(w,RAW_SHA,o,80,32)
    copy_output(w,ORIGINAL_SHA,o,112,32)
    copy_output(w,CORE_SHA,o,144,32)
    copy_output(w,ABI_SHA,o,176,32)
    put(o,208,get(w,200))
    put(o,216,get(w,208))
    put(o,224,get(w,216))
    put(o,232,get(w,296))
    put(o,240,get(w,304))
    put(o,248,get(w,224))
    put(o,256,get(w,312))
    put(o,264,get(w,320))
    if get(w,128)==0:
        copy_output(w,NORMAL+64,o,320,get(w,152)+get(w,160))
        copy_output(w,IOUT+256+get(w,160),o,320+get(w,152)+get(w,160),get(w,168))
    return 0

def failed(value:u64) -> bool:
    return value>=18446744073709547520

def equal(w:mutbuf,a:u64,b:u64,n:u64) -> bool:
    i=0
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return False
        i=i+1
    return True
'''
from tools.generate_hia_multiversion_intake import SOURCE as INTAKE_SOURCE
SOURCE += INTAKE_SOURCE[INTAKE_SOURCE.index('def zero('):]
def source_program():
    text=SOURCE
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+name+r'\b',str(value),text)
    return text
def main():
    t=document(source_program(),'multiversion_prepare_intake');p=ROOT/'examples/hia_bootstrap/multiversion_prepare_intake.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
