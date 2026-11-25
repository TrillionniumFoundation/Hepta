"""HIA fixed-proof preparation over actual admitted Core and sealed proof code.

This is a private runtime stage, not a public serialized-proof admission API.
The enclosing native runtime owns normalization/profile/ABI and the image pin.
Every export is reverified by the actual captured primitive proof process.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_multiversion_intake import SOURCE as INTAKE
ROOT=Path(__file__).resolve().parents[1]
C=dict(REQUEST=int.from_bytes(b'HIAMVPF1','little'),REPLY=int.from_bytes(b'HIAMVFR2','little'),
 ABI_MAGIC=int.from_bytes(b'HIAMVAB1','little'),PROCESS=int.from_bytes(b'HIAMVPS1','little'),
 PROCESS_REPLY=int.from_bytes(b'HIAMVPO1','little'),PROOF=int.from_bytes(b'HIAMVP02','little'),
 PROOF_REPLY=int.from_bytes(b'HIAMVR01','little'),RECEIPT=int.from_bytes(b'HIAJPR01','little'),
 NONE=(1<<64)-1,NEG4=(1<<64)-4,WORK=128<<20,
 CORE1=1<<20,CORE2=9<<20,ABI=17<<20,PIN=18<<20,PROCWORK=36<<20,
 JSON=56<<20,ARENA=58<<20,JSONWORK=74<<20,RI=82<<20,RO=100<<20,RW=102<<20,
 IMAGE=112<<20,HASHWORK=131072,CLOCK=32768,STAT=32896,POUT=65536,
 EXPECTED=512,ACTUAL=544,SHA1=576,SHA2=608,INVENTORY_SHA=640,ABI_SHA=672,INVENTORY=4096)
LABELS={1:'claims',2:'canonical_core_reverified',3:'all_inputs_return_normally_proved',
4:'all_input_behavior_equivalence_proved',5:'first_trap_code_preserved',6:'structural_verification',
7:'before',8:'after',9:'scope',10:'selected_public_scalar_function',11:'counterexample',
12:'execution_authority',13:'checker',14:'kind',15:'trusted_executable_hia_scalar_checker',
16:'runtime',17:'implementation',18:'HIA-native',19:'version',20:'1',21:'solver',22:'result',23:'unsat',24:'source_identity_sha256',25:'source_identity',26:'native-closure.image.bin',27:'identity',28:'native_closure_sha256'}
SOURCE=r'''
def prepare_proof(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<512 or length(w)<WORK:
        return 4294967293
    phase=get(w,0)
    result=get(w,8)
    if phase==0:
        return begin(s,o,w)
    if phase<20:
        return capture(o,w,phase,result)
    if phase<40:
        return proofs(o,w,phase,result)
    if phase>=70 and phase<80:
        return close_owned(o,w,phase,result)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<256 or readword(s,0)!=REQUEST:
        return 4294967293
    mode=readword(s,8)
    timeout=readword(s,16)
    fd=readword(s,24)
    cancel=readword(s,32)
    a=readword(s,40)
    b=readword(s,48)
    ab=readword(s,56)
    if mode<1 or mode>2 or timeout==0 or timeout>30000 or fd<3 or fd>2147483647:
        return 4294967293
    if cancel!=0 and (cancel&7)!=0:
        return 4294967293
    if a==0 or a>8388608 or b>8388608 or (mode==1 and b!=0) or (mode==2 and b==0):
        return 4294967293
    if a>length(s)-256 or b>length(s)-256-a or ab!=length(s)-256-a-b:
        return 4294967293
    if ab<336 or readword(s,256+a+b)!=ABI_MAGIC:
        return 4294967293
    count=readword(s,264+a+b)
    if count==0 or count>16 or ab!=16+count*320:
        return 4294967293
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
    if abi_valid(s,256+a+b,count)==False:
        return 4294967293
    zero(w,72,32000)
    put(w,72,cancel)
    put(w,80,NONE)
    put(w,104,mode)
    put(w,112,timeout)
    put(w,120,count)
    put(w,144,a)
    put(w,152,b)
    put(w,160,ab)
    put(w,168,512)
    put(w,208,NONE)
    put(w,216,NONE)
    copy_input(s,128,w,EXPECTED,32)
    copy_input(s,256,w,CORE1,a)
    copy_input(s,256+a,w,CORE2,b)
    copy_input(s,256+a+b,w,ABI,ab)
    put(w,360,fd)
    return call(o,w,1,228,4,1,CLOCK,0,0,0,0)

def abi_valid(s:readbuf,base:u64,count:u64) -> bool:
    seen=0
    i=0
    while i<count:
        at=base+16+i*320
        original=readword(s,at)
        if original>=count:
            return False
        bit=1<<original
        if (seen&bit)!=0 or abi_record_valid(s,at)==False:
            return False
        seen=seen|bit
        i=i+1
    return True

def abi_record_valid(s:readbuf,at:u64) -> bool:
    name=readword(s,at+8)
    argc=readword(s,at+16)
    typ=readword(s,at+24)
    if name==0 or name>128 or argc>16 or typ==0 or typ>11:
        return False
    j=0
    while j<128:
        c=byte(s,at+32+j)
        if j<name:
            if ((c>=65 and c<=90) or (c>=97 and c<=122) or c==95 or (j!=0 and c>=48 and c<=57))==False:
                return False
        elif c!=0:
            return False
        j=j+1
    j=0
    while j<16:
        v=readword(s,at+160+j*8)
        if (j<argc and (v==0 or v>11)) or (j>=argc and v!=0):
            return False
        j=j+1
    j=288
    while j<320:
        if readword(s,at+j)!=0:
            return False
        j=j+8
    return True

def capture(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==1:
        if failed(result):
            return fail(o,w,4,result)
        put(w,304,now(w))
        return call(o,w,2,72,0,get(w,360),1030,3,0,0,0)
    if phase==2:
        if failed(result):
            return fail(o,w,4,result)
        put(w,80,result)
        return call(o,w,3,5,4,result,STAT,0,0,0,0)
    if phase==3:
        if failed(result):
            return fail(o,w,4,result)
        mode=get(w,STAT+24)&65535
        n=get(w,STAT+48)
        if (mode&61440)!=32768 or (mode&4095)!=320 or get(w,STAT+16)!=0 or n<64 or n>8388608:
            return fail(o,w,5,1)
        put(w,88,n)
        return call(o,w,4,72,0,get(w,80),1034,0,0,0,0)
    if phase==4:
        if result!=15:
            return fail(o,w,5,2)
        put(w,96,0)
        return image_read(o,w,5)
    if phase==5:
        if result==NEG4:
            return image_read(o,w,5)
        if failed(result) or result==0 or result>get(w,88)-get(w,96):
            return fail(o,w,4,result)
        put(w,96,get(w,96)+result)
        if get(w,96)<get(w,88):
            return image_read(o,w,5)
        zero(w,HASHWORK,1184)
        return role(w,6,3,IMAGE,get(w,88),ACTUAL,32,HASHWORK,1184)
    if phase==6:
        if result!=32 or equal(w,EXPECTED,ACTUAL,32)==False:
            return fail(o,w,5,3)
        zero(w,HASHWORK,1184)
        return role(w,7,3,CORE1,get(w,144),SHA1,32,HASHWORK,1184)
    if phase==7:
        if result!=32:
            return fail(o,w,5,4)
        zero(w,HASHWORK,1184)
        return role(w,8,3,CORE2,get(w,152),SHA2,32,HASHWORK,1184)
    if phase==8:
        if result!=32:
            return fail(o,w,5,5)
        n=inventory(w)
        zero(w,HASHWORK,1184)
        return role(w,9,3,INVENTORY,n,INVENTORY_SHA,32,HASHWORK,1184)
    if phase==9:
        if result!=32:
            return fail(o,w,5,6)
        zero(w,HASHWORK,1184)
        return role(w,10,3,ABI,get(w,160),ABI_SHA,32,HASHWORK,1184)
    if phase==10:
        if result!=32:
            return fail(o,w,5,7)
        return call(o,w,20,228,4,1,CLOCK,0,0,0,0)
    return 4294967293

def proofs(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==20:
        if failed(result):
            return fail(o,w,4,result)
        started=now(w)
        delta=get(w,112)*1000000
        if started>18446744073709551615-delta-60000000000:
            return fail(o,w,4,8)
        put(w,176,started)
        put(w,184,started+delta)
        return launch(w)
    if phase==21:
        if result!=0 or get(w,POUT)!=PROCESS_REPLY or get(w,POUT+8)!=result:
            return fail(o,w,4,result)
        a=get(w,POUT+48)
        b=get(w,POUT+56)
        put(w,208,a)
        put(w,216,b)
        put(w,200,get(w,POUT+24))
        put(w,224,get(w,POUT+64))
        put(w,232,get(w,POUT+72))
        if a<3 or a>2147483647 or b<3 or b>2147483647 or a==b:
            return fail(o,w,5,9)
        if get(w,POUT+96)!=1 or get(w,POUT+104)!=7 or get(w,POUT+112)!=15 or get(w,POUT+120)!=0:
            return fail(o,w,5,10)
        if get(w,200)!=0 or get(w,232)!=0 or get(w,224)<64 or get(w,224)>1048576:
            return fail(o,w,3,get(w,200))
        put(w,240,0)
        return proof_read(o,w)
    if phase==22:
        if result==NEG4:
            return proof_read(o,w)
        if failed(result) or result==0 or result>get(w,224)-get(w,240):
            return fail(o,w,4,result)
        put(w,240,get(w,240)+result)
        if get(w,240)<get(w,224):
            return proof_read(o,w)
        return close_streams(o,w,23)
    if phase==23:
        if get(w,JSON)!=PROOF_REPLY or get(w,JSON+8)!=get(w,104) or get(w,JSON+16)>2 or get(w,JSON+24)!=get(w,224)-64:
            return fail(o,w,5,11)
        if get(w,JSON+40)!=0 or get(w,JSON+48)!=0 or get(w,JSON+56)!=0:
            return fail(o,w,5,12)
        put(w,256,get(w,JSON+16))
        put(w,312,get(w,JSON+32))
        put(w,272,get(w,224)-64)
        zero(w,JSONWORK,128)
        put(w,JSONWORK+48,131073)
        put(w,JSONWORK+56,128)
        return role(w,24,4,JSON+64,get(w,272),ARENA,16777216,JSONWORK,8388608)
    if phase==24:
        if result<64 or result>16777216:
            return fail(o,w,5,13)
        put(w,280,result)
        return patch(w)
    if phase==25:
        if result<64 or result>1048576 or get(w,RO)!=PROOF_REPLY or get(w,RO+8)!=get(w,104) or get(w,RO+16)!=get(w,256) or get(w,RO+24)!=result-64:
            return fail(o,w,5,14)
        put(w,328,result)
        if get(w,256)!=1:
            put(w,248,1)
            return append_receipt(o,w)
        if claims(w)==False:
            return fail(o,w,5,15)
        return call(o,w,26,228,4,1,CLOCK,0,0,0,0)
    if phase==26:
        if failed(result):
            return fail(o,w,4,result)
        if now(w)>get(w,184):
            return fail(o,w,2,12)
        put(w,136,get(w,136)+1)
        return append_receipt(o,w)
    if phase==27:
        if get(w,248)!=0:
            return final_close(o,w)
        put(w,128,get(w,128)+1)
        if get(w,128)<get(w,120):
            return call(o,w,20,228,4,1,CLOCK,0,0,0,0)
        put(w,96,0)
        return image_read(o,w,28)
    if phase==28:
        if result==NEG4:
            return image_read(o,w,28)
        if failed(result) or result==0 or result>get(w,88)-get(w,96):
            return fail(o,w,4,result)
        put(w,96,get(w,96)+result)
        if get(w,96)<get(w,88):
            return image_read(o,w,28)
        zero(w,HASHWORK,1184)
        return role(w,29,3,IMAGE,get(w,88),EXPECTED,32,HASHWORK,1184)
    if phase==29:
        if result!=32 or equal(w,EXPECTED,ACTUAL,32)==False:
            return fail(o,w,5,16)
        return final_close(o,w)
    return 4294967293

def launch(w:mutbuf) -> u32:
    at=ABI+16+get(w,128)*320
    n=get(w,at+8)
    size=64+n+get(w,144)+get(w,152)
    zero(w,PIN,192)
    put(w,PIN,PROCESS)
    put(w,PIN+8,2)
    put(w,PIN+16,get(w,80))
    put(w,PIN+24,get(w,184)+60000000000)
    put(w,PIN+32,size)
    put(w,PIN+40,1048576)
    put(w,PIN+48,67108864)
    put(w,PIN+64,get(w,72))
    put(w,PIN+128,PROOF)
    put(w,PIN+136,get(w,104))
    put(w,PIN+144,get(w,112))
    put(w,PIN+152,n)
    put(w,PIN+160,get(w,144))
    put(w,PIN+168,get(w,152))
    put(w,PIN+184,get(w,184))
    copy(w,at+32,PIN+192,n)
    copy(w,CORE1,PIN+192+n,get(w,144))
    copy(w,CORE2,PIN+192+n+get(w,144),get(w,152))
    zero(w,POUT,128)
    return role(w,21,2,PIN,128+size,POUT,128,PROCWORK,20971520)

def patch(w:mutbuf) -> u32:
    at=ABI+16+get(w,128)*320
    n=get(w,at+8)
    zero(w,RI,768)
    put(w,RI,RECEIPT)
    put(w,RI+16,get(w,104))
    put(w,RI+32,get(w,312))
    put(w,RI+40,get(w,112))
    put(w,RI+48,n)
    put(w,RI+56,choose(get(w,104)==1,51,63))
    copy(w,SHA1,RI+64,32)
    copy(w,SHA2,RI+96,32)
    copy(w,SHA1,RI+128,32)
    copy(w,SHA2,RI+160,32)
    copy(w,SHA1,RI+192,32)
    copy(w,SHA2,RI+224,32)
    copy(w,ACTUAL,RI+256,32)
    copy(w,ACTUAL,RI+288,32)
    copy(w,INVENTORY_SHA,RI+320,32)
    put(w,RI+352,get(w,272))
    put(w,RI+360,get(w,280))
    put(w,RI+408,get(w,256))
    copy(w,at+32,RI+512,n)
    copy(w,JSON+64,RI+768,get(w,272))
    copy(w,ARENA,RI+768+get(w,272),get(w,280))
    return role(w,25,5,RI,768+get(w,272)+get(w,280),RO,1048576,RW,8388608)

def claims(w:mutbuf) -> bool:
    if node(w,0,0)!=6:
        return False
    c=field(w,0,1)
    if node(w,field(w,c,2),0)!=2:
        return False
    if node(w,field(w,c,choose(get(w,104)==1,3,4)),0)!=2:
        return False
    if get(w,104)==2 and node(w,field(w,c,5),0)!=2:
        return False
    v=field(w,0,6)
    if get(w,104)==1:
        if node(w,v,0)!=2:
            return False
    else:
        if node(w,field(w,v,7),0)!=2 or node(w,field(w,v,8),0)!=2:
            return False
    if string_id(w,field(w,0,9))!=10 or node(w,field(w,0,11),0)!=0 or node(w,field(w,0,12),0)!=1:
        return False
    checker=field(w,0,13)
    if string_id(w,field(w,checker,14))!=15:
        return False
    runtime=field(w,checker,16)
    if string_id(w,field(w,runtime,17))!=18 or string_id(w,field(w,runtime,19))!=20:
        return False
    if digest(w,field(w,checker,24),INVENTORY_SHA)==False:
        return False
    identity=field(w,checker,25)
    if node(w,identity,0)!=6 or node(w,identity,32)!=1 or digest(w,field(w,identity,26),ACTUAL)==False:
        return False
    solver=field(w,0,21)
    solver_identity=field(w,solver,27)
    if digest(w,field(w,solver_identity,28),ACTUAL)==False:
        return False
    return string_id(w,field(w,solver,22))==23


def digest(w:mutbuf,n:u64,expected:u64) -> bool:
    if node(w,n,0)!=4 or node(w,n,32)!=64:
        return False
    at=ARENA+node(w,n,24)
    i=0
    while i<32:
        value=byte(w,expected+i)
        high=value>>4
        low=value&15
        if byte(w,at+i*2)!=high+choose(high<10,48,87) or byte(w,at+i*2+1)!=low+choose(low<10,48,87):
            return False
        i=i+1
    return True

def node(w:mutbuf,n:u64,slot:u64) -> u64:
    if n>=get(w,ARENA+8):
        return NONE
    return get(w,ARENA+64+n*72+slot)

def field(w:mutbuf,n:u64,key:u64) -> u64:
    if node(w,n,0)!=6:
        return NONE
    child=node(w,n,24)
    while child!=NONE:
        if label(w,ARENA+node(w,child,40),node(w,child,48))==key:
            return child
        child=node(w,child,16)
    return NONE

def string_id(w:mutbuf,n:u64) -> u64:
    if node(w,n,0)!=4:
        return 0
    return label(w,ARENA+node(w,n,24),node(w,n,32))

def append_receipt(o:mutbuf,w:mutbuf) -> u32:
    n=get(w,328)-64
    at=get(w,168)
    if at>length(o) or length(o)-at<8 or n>length(o)-at-8:
        return fail(o,w,6,at+8+n)
    put(o,at,n)
    copy_output(w,RO+64,o,at+8,n)
    put(w,168,at+8+n)
    put(w,0,27)
    put(w,8,0)
    return 6

def image_read(o:mutbuf,w:mutbuf,next:u64) -> u32:
    n=get(w,88)-get(w,96)
    if n>65536:
        n=65536
    return call(o,w,next,17,4,get(w,80),IMAGE+get(w,96),n,get(w,96),0,0)

def proof_read(o:mutbuf,w:mutbuf) -> u32:
    n=get(w,224)-get(w,240)
    if n>65536:
        n=65536
    return call(o,w,22,17,4,get(w,208),JSON+get(w,240),n,get(w,240),0,0)

def close_streams(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(w,320,next)
    fd=get(w,208)
    put(w,208,NONE)
    if fd!=NONE:
        return call(o,w,70,3,0,fd,0,0,0,0,0)
    return close_owned(o,w,70,0)

def close_owned(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==70:
        fd=get(w,216)
        put(w,216,NONE)
        if fd!=NONE:
            return call(o,w,71,3,0,fd,0,0,0,0,0)
        phase=71
    if phase==71:
        next=get(w,320)
        if next!=0:
            put(w,0,next)
            put(w,8,0)
            return 6
        fd=get(w,80)
        put(w,80,NONE)
        if fd!=NONE:
            return call(o,w,72,3,0,fd,0,0,0,0,0)
        phase=72
    if phase==72:
        return call(o,w,73,228,4,1,CLOCK,0,0,0,0)
    if phase==73:
        if failed(result):
            put(w,248,4)
            put(w,264,result)
        return finish(o,w)
    return 4294967293

def fail(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(w,248,status)
    put(w,264,detail)
    return final_close(o,w)

def final_close(o:mutbuf,w:mutbuf) -> u32:
    return close_streams(o,w,0)

def finish(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,512)
    put(o,0,REPLY)
    put(o,8,get(w,248))
    put(o,16,get(w,264))
    put(o,24,get(w,104))
    put(o,32,get(w,120))
    put(o,40,get(w,136))
    put(o,48,get(w,128))
    put(o,56,get(w,256))
    put(o,64,get(w,168))
    put(o,72,get(w,200))
    put(o,80,choose(now(w)>=get(w,304),now(w)-get(w,304),0))
    copy_output(w,ACTUAL,o,96,32)
    copy_output(w,SHA1,o,128,32)
    copy_output(w,SHA2,o,160,32)
    copy_output(w,ABI_SHA,o,192,32)
    return 0

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

def now(w:mutbuf) -> u64:
    return get(w,CLOCK)*1000000000+get(w,CLOCK+8)

def failed(value:u64) -> bool:
    return value>=18446744073709547520

def equal(w:mutbuf,a:u64,b:u64,n:u64) -> bool:
    i=0
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return False
        i=i+1
    return True

def loadn(w:mutbuf,at:u64,n:u64) -> u64:
    v=0
    i=0
    while i<n:
        v=v|(byte(w,at+i)<<(8*i))
        i=i+1
    return v
'''
SOURCE += INTAKE[INTAKE.index('def zero('):]
def labels():
    entries=list(LABELS.items());parts=[entries[i:i+8] for i in range(0,len(entries),8)]
    out=['def label(w:mutbuf,at:u64,n:u64) -> u64:']
    for i in range(len(parts)):out += [f'    v=labels_{i}(w,at,n)','    if v!=0:','        return v']
    out += ['    return 0']
    for i,part in enumerate(parts):
        out += ['',f'def labels_{i}(w:mutbuf,at:u64,n:u64) -> u64:']
        for key,value in part:
            b=value.encode();tests=[f'n=={len(b)}']+[f'loadn(w,at+{j},{len(b[j:j+8])})=={int.from_bytes(b[j:j+8],"little")}' for j in range(0,len(b),8)]
            out += ['    if '+' and '.join(tests)+':',f'        return {key}']
        out += ['    return 0']
    return '\n'.join(out)
def inventory():
    prefix=b'{"native-closure.image.bin":"';suffix=b'"}'
    lines=['def inventory(w:mutbuf) -> u64:']
    for i,c in enumerate(prefix):lines.append(f'    store(w,INVENTORY+{i},{c})')
    lines += ['    i=0','    while i<32:','        c=byte(w,ACTUAL+i)','        a=c>>4','        b=c&15',f'        store(w,INVENTORY+{len(prefix)}+2*i,a+choose(a<10,48,87))',f'        store(w,INVENTORY+{len(prefix)+1}+2*i,b+choose(b<10,48,87))','        i=i+1']
    for i,c in enumerate(suffix):lines.append(f'    store(w,INVENTORY+{len(prefix)+64+i},{c})')
    lines.append(f'    return {len(prefix)+64+len(suffix)}')
    return '\n'.join(lines)
def source_program():
    s=SOURCE+'\n'+labels()+'\n'+inventory()
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
def main():
    tree=document(source_program(),'multiversion_prepare_proof')
    p=ROOT/'examples/hia_bootstrap/multiversion_prepare_proof.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),flush=True)
if __name__=='__main__':main()
