"""Fresh native constructor capture and exact build-to-image handoff.

This private stage receives only the parent-owned admitted Core/ABI and an
expected sealed constructor identity. Artifact bytes/mapping/probes remain
separate mandatory owners; a build receipt is never execution authority.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_multiversion_intake import SOURCE as INTAKE
from tools.generate_hia_multiversion_prepare_proof import SOURCE as PROOF
ROOT=Path(__file__).resolve().parents[1]
C=dict(REQUEST=int.from_bytes(b'HIAMVBF1','little'),REPLY=int.from_bytes(b'HIAMVBR1','little'),
 ABI_MAGIC=int.from_bytes(b'HIAMVAB1','little'),PROCESS=int.from_bytes(b'HIAMVPS1','little'),
 PROCESS_REPLY=int.from_bytes(b'HIAMVPO1','little'),NONE=(1<<64)-1,NEG4=(1<<64)-4,
 WORK=128<<20,CORE=1<<20,ABI=9<<20,PATH=10<<20,PIN=11<<20,PROCWORK=20<<20,
 JSON=42<<20,ARENA=44<<20,JSONWORK=60<<20,IMAGE=68<<20,HASHWORK=131072,
 CLOCK=32768,STAT=32896,POUT=65536,EXPECTED=512,ACTUAL=544,CORE_SHA=576,ABI_SHA=608,
 ARTIFACT_SHA=640,OBJECT_SHA=672,TEXT_SHA=704)
LABELS={1:'schema',2:'hepta.hia.program.direct-native.v1',3:'profile',4:'hepta.hia.program.direct-linux-x86_64.v1',
5:'target',6:'x86_64-unknown-linux-gnu',7:'kind',8:'shared',9:'status',10:'native_emitted_not_executed',
11:'ok',12:'core_sha256',13:'input_sha256',14:'artifact_sha256',15:'artifact_bytes',
16:'object_sha256',17:'machine_text_sha256',18:'machine_text_bytes',19:'exports',
20:'foreign_buffer_exports',21:'claims',22:'standalone_core_reverified',23:'fallback_used',
24:'llvm_ir_used',25:'llvm_codegen_used',26:'c_codegen_used',27:'rust_codegen_used',
28:'assembler_used',29:'external_linker_used',30:'binary_inventory',31:'hepta.elf-shared-abi.v1',
32:'format',33:'ELF64',34:'ET_DYN',35:'machine',36:'source_exports_rechecked',37:'dynamic_exports'}
SOURCE=r'''
def prepare_build(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<512 or length(w)<WORK:
        return 4294967293
    phase=get(w,0)
    result=get(w,8)
    if phase==0:
        return begin(s,o,w)
    if phase<10:
        return capture(o,w,phase,result)
    if phase<30:
        return build(o,w,phase,result)
    if phase>=70 and phase<80:
        return cleanup(o,w,phase,result)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<256 or readword(s,0)!=REQUEST or readword(s,8)!=0:
        return 4294967293
    fd=readword(s,16)
    deadline=readword(s,24)
    cancel=readword(s,32)
    a=readword(s,40)
    ab=readword(s,48)
    pn=readword(s,56)
    if fd<3 or fd>2147483647 or deadline==0 or (cancel!=0 and (cancel&7)!=0):
        return 4294967293
    if a==0 or a>8388608 or a>length(s)-256 or ab>length(s)-256-a or pn!=length(s)-256-a-ab:
        return 4294967293
    if ab<336 or ab>5136 or readword(s,256+a)!=ABI_MAGIC or pn==0 or pn>4095:
        return 4294967293
    count=readword(s,264+a)
    if count==0 or count>16 or ab!=16+count*320 or abi_valid(s,256+a,count)==False:
        return 4294967293
    if byte(s,256+a+ab)!=47:
        return 4294967293
    i=0
    while i<pn:
        if byte(s,256+a+ab+i)==0:
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
    zero(w,72,32000)
    put(w,72,readword(s,16))
    put(w,80,NONE)
    put(w,104,readword(s,24))
    put(w,112,readword(s,32))
    put(w,120,a)
    put(w,128,ab)
    put(w,136,pn)
    put(w,144,NONE)
    put(w,152,NONE)
    copy_input(s,128,w,EXPECTED,32)
    copy_input(s,256,w,CORE,a)
    copy_input(s,256+a,w,ABI,ab)
    copy_input(s,256+a+ab,w,PATH,pn)
    store(w,PATH+pn,0)
    return call(o,w,1,228,4,1,CLOCK,0,0,0,0)

def capture(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==1:
        if failed(result):
            return fail(o,w,2,result)
        put(w,192,now(w))
        return call(o,w,2,72,0,get(w,72),1030,3,0,0,0)
    if phase==2:
        if failed(result):
            return fail(o,w,2,result)
        put(w,80,result)
        return call(o,w,3,5,4,result,STAT,0,0,0,0)
    if phase==3:
        if failed(result):
            return fail(o,w,2,result)
        mode=get(w,STAT+24)&65535
        n=get(w,STAT+48)
        if (mode&61440)!=32768 or (mode&4095)!=320 or get(w,STAT+16)!=0 or n<64 or n>8388608:
            return fail(o,w,3,1)
        put(w,88,n)
        return call(o,w,4,72,0,get(w,80),1034,0,0,0,0)
    if phase==4:
        if result!=15:
            return fail(o,w,3,2)
        put(w,96,0)
        return image_read(o,w,5)
    if phase==5:
        if result==NEG4:
            return image_read(o,w,5)
        if failed(result) or result==0 or result>get(w,88)-get(w,96):
            return fail(o,w,2,result)
        put(w,96,get(w,96)+result)
        if get(w,96)<get(w,88):
            return image_read(o,w,5)
        zero(w,HASHWORK,1184)
        return role(w,6,3,IMAGE,get(w,88),ACTUAL,32,HASHWORK,1184)
    if phase==6:
        if result!=32 or equal(w,EXPECTED,ACTUAL,32)==False:
            return fail(o,w,3,3)
        zero(w,HASHWORK,1184)
        return role(w,7,3,CORE,get(w,120),CORE_SHA,32,HASHWORK,1184)
    if phase==7:
        if result!=32:
            return fail(o,w,3,4)
        zero(w,HASHWORK,1184)
        return role(w,8,3,ABI,get(w,128),ABI_SHA,32,HASHWORK,1184)
    if phase==8:
        if result!=32:
            return fail(o,w,3,5)
        return launch(w)
    return 4294967293

def launch(w:mutbuf) -> u32:
    zero(w,PIN,128)
    put(w,PIN,PROCESS)
    put(w,PIN+8,3)
    put(w,PIN+16,get(w,80))
    put(w,PIN+24,get(w,104))
    put(w,PIN+32,get(w,120))
    put(w,PIN+40,1048576)
    put(w,PIN+48,67108864)
    put(w,PIN+56,get(w,136))
    put(w,PIN+64,get(w,112))
    copy(w,CORE,PIN+128,get(w,120))
    copy(w,PATH,PIN+128+get(w,120),get(w,136))
    zero(w,POUT,128)
    return role(w,10,2,PIN,128+get(w,120)+get(w,136),POUT,128,PROCWORK,20971520)

def build(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==10:
        if result!=0 or get(w,POUT)!=PROCESS_REPLY or get(w,POUT+8)!=result:
            return fail(o,w,2,result)
        a=get(w,POUT+48)
        b=get(w,POUT+56)
        put(w,144,a)
        put(w,152,b)
        put(w,184,get(w,POUT+24))
        put(w,160,get(w,POUT+64))
        put(w,168,get(w,POUT+72))
        if a<3 or a>2147483647 or b<3 or b>2147483647 or a==b:
            return fail(o,w,3,6)
        if get(w,POUT+96)!=1 or get(w,POUT+104)!=7 or get(w,POUT+112)!=15 or get(w,POUT+120)!=0:
            return fail(o,w,3,7)
        if get(w,184)!=0:
            put(w,256,1)
            return fail(o,w,1,get(w,184))
        if get(w,160)==0 or get(w,160)>1048576:
            return fail(o,w,3,8)
        put(w,176,0)
        return json_read(o,w)
    if phase==11:
        if result==NEG4:
            return json_read(o,w)
        if failed(result) or result==0 or result>get(w,160)-get(w,176):
            return fail(o,w,2,result)
        put(w,176,get(w,176)+result)
        if get(w,176)<get(w,160):
            return json_read(o,w)
        zero(w,JSONWORK,128)
        put(w,JSONWORK+48,131073)
        put(w,JSONWORK+56,128)
        return role(w,12,4,JSON,get(w,160),ARENA,16777216,JSONWORK,8388608)
    if phase==12:
        if result<64 or result>16777216:
            return fail(o,w,3,9)
        put(w,232,result)
        if check_receipt(w)==False:
            return fail(o,w,3,10)
        if length(o)-512<get(w,160):
            return fail(o,w,4,512+get(w,160))
        copy_output(w,JSON,o,512,get(w,160))
        put(w,224,get(w,160))
        put(w,96,0)
        return image_read(o,w,13)
    if phase==13:
        if result==NEG4:
            return image_read(o,w,13)
        if failed(result) or result==0 or result>get(w,88)-get(w,96):
            return fail(o,w,2,result)
        put(w,96,get(w,96)+result)
        if get(w,96)<get(w,88):
            return image_read(o,w,13)
        zero(w,HASHWORK,1184)
        return role(w,14,3,IMAGE,get(w,88),EXPECTED,32,HASHWORK,1184)
    if phase==14:
        if result!=32 or equal(w,EXPECTED,ACTUAL,32)==False:
            return fail(o,w,3,11)
        return final_close(o,w)
    return 4294967293

def check_receipt(w:mutbuf) -> bool:
    if node(w,0,0)!=6:
        return False
    if string_id(w,field(w,0,1))!=2 or string_id(w,field(w,0,3))!=4 or string_id(w,field(w,0,5))!=6:
        return False
    if string_id(w,field(w,0,7))!=8 or string_id(w,field(w,0,9))!=10 or node(w,field(w,0,11),0)!=2:
        return False
    if digest(w,field(w,0,12),EXPECTED)==False or equal(w,EXPECTED,CORE_SHA,32)==False:
        return False
    if digest(w,field(w,0,13),EXPECTED)==False or equal(w,EXPECTED,CORE_SHA,32)==False:
        return False
    if digest(w,field(w,0,14),ARTIFACT_SHA)==False or digest(w,field(w,0,16),OBJECT_SHA)==False or digest(w,field(w,0,17),TEXT_SHA)==False:
        return False
    amount=number(w,field(w,0,15))
    text=number(w,field(w,0,18))
    if amount<64 or amount>67108864 or text==0 or text>16777216:
        return False
    put(w,240,amount)
    put(w,248,text)
    if exports(w,field(w,0,19))==False or node(w,field(w,0,20),0)!=5 or node(w,field(w,0,20),32)!=0:
        return False
    claims=field(w,0,21)
    if node(w,field(w,claims,22),0)!=2:
        return False
    k=23
    while k<=29:
        if node(w,field(w,claims,k),0)!=1:
            return False
        k=k+1
    inv=field(w,0,30)
    if string_id(w,field(w,inv,1))!=31 or string_id(w,field(w,inv,32))!=33 or string_id(w,field(w,inv,7))!=34:
        return False
    if number(w,field(w,inv,35))!=62 or node(w,field(w,inv,36),0)!=2 or exports(w,field(w,inv,37))==False:
        return False
    return True

def exports(w:mutbuf,n:u64) -> bool:
    count=get(w,ABI+8)
    if node(w,n,0)!=5 or node(w,n,32)!=count:
        return False
    child=node(w,n,24)
    i=0
    while i<count:
        at=ABI+16+i*320
        if node(w,child,0)!=4 or node(w,child,32)!=get(w,at+8):
            return False
        if equal(w,ARENA+node(w,child,24),at+32,get(w,at+8))==False:
            return False
        child=node(w,child,16)
        i=i+1
    return child==NONE

def number(w:mutbuf,n:u64) -> u64:
    if node(w,n,0)!=3:
        return NONE
    size=node(w,n,32)
    at=JSON+node(w,n,24)
    if size==0 or size>20:
        return NONE
    value=0
    i=0
    while i<size:
        c=byte(w,at+i)
        if c<48 or c>57 or value>1844674407370955161:
            return NONE
        digit=c-48
        if value==1844674407370955161 and digit>5:
            return NONE
        value=value*10+digit
        i=i+1
    return value

def digest(w:mutbuf,n:u64,out:u64) -> bool:
    if node(w,n,0)!=4 or node(w,n,32)!=64:
        return False
    at=ARENA+node(w,n,24)
    i=0
    while i<32:
        a=hex(byte(w,at+i*2))
        b=hex(byte(w,at+i*2+1))
        if a>15 or b>15:
            return False
        store(w,out+i,a*16+b)
        i=i+1
    return True

def hex(c:u64) -> u64:
    if c>=48 and c<=57:
        return c-48
    if c>=97 and c<=102:
        return c-87
    return NONE

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

def image_read(o:mutbuf,w:mutbuf,next:u64) -> u32:
    n=get(w,88)-get(w,96)
    if n>65536:
        n=65536
    return call(o,w,next,17,4,get(w,80),IMAGE+get(w,96),n,get(w,96),0,0)

def json_read(o:mutbuf,w:mutbuf) -> u32:
    n=get(w,160)-get(w,176)
    if n>65536:
        n=65536
    return call(o,w,11,17,4,get(w,144),JSON+get(w,176),n,get(w,176),0,0)

def fail(o:mutbuf,w:mutbuf,status:u64,detail:u64) -> u32:
    put(w,208,status)
    put(w,216,detail)
    return final_close(o,w)

def final_close(o:mutbuf,w:mutbuf) -> u32:
    return cleanup(o,w,70,0)

def cleanup(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==70:
        fd=get(w,144)
        if fd!=NONE and get(w,256)==0:
            put(w,144,NONE)
            return call(o,w,71,3,0,fd,0,0,0,0,0)
        phase=71
    if phase==71:
        fd=get(w,152)
        if fd!=NONE and get(w,256)==0:
            put(w,152,NONE)
            return call(o,w,72,3,0,fd,0,0,0,0,0)
        phase=72
    if phase==72:
        fd=get(w,80)
        put(w,80,NONE)
        if fd!=NONE:
            return call(o,w,73,3,0,fd,0,0,0,0,0)
        phase=73
    if phase==73:
        return call(o,w,74,228,4,1,CLOCK,0,0,0,0)
    if phase==74:
        if failed(result):
            put(w,208,2)
            put(w,216,result)
        return finish(o,w)
    return 4294967293

def finish(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,512)
    put(o,0,REPLY)
    put(o,8,get(w,208))
    put(o,16,get(w,216))
    put(o,24,get(w,184))
    put(o,32,get(w,240))
    put(o,40,get(w,192))
    put(o,48,choose(now(w)>=get(w,192),now(w)-get(w,192),0))
    put(o,56,get(w,120))
    put(o,64,get(w,128))
    put(o,72,get(w,136))
    put(o,80,get(w,224))
    put(o,88,get(w,144))
    put(o,96,get(w,152))
    put(w,144,NONE)
    put(w,152,NONE)
    put(o,104,get(w,256))
    put(o,112,get(w,160))
    put(o,120,get(w,168))
    copy_output(w,ACTUAL,o,128,32)
    copy_output(w,CORE_SHA,o,160,32)
    copy_output(w,ABI_SHA,o,192,32)
    copy_output(w,ARTIFACT_SHA,o,224,32)
    copy_output(w,OBJECT_SHA,o,256,32)
    copy_output(w,TEXT_SHA,o,288,32)
    put(o,320,get(w,248))
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
SOURCE += '\n'+PROOF[PROOF.index('def abi_valid('):PROOF.index('def capture(')]
SOURCE += '\n'+INTAKE[INTAKE.index('def zero('):]
def labels():
    entries=list(LABELS.items());parts=[entries[i:i+6] for i in range(0,len(entries),6)]
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
def source_program():
    s=SOURCE+'\n'+labels()
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
def main():
    tree=document(source_program(),'multiversion_prepare_build')
    p=ROOT/'examples/hia_bootstrap/multiversion_prepare_build.hepta';p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),flush=True)
if __name__=='__main__':main()
