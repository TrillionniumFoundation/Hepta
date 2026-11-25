"""Author private HIA receipt rebinding and fresh translation-receipt checks.

The final public owner supplies arenas made by its embedded HIA JSON decoder.
No caller-provided proof bit, digest, arena, or receipt can bypass fresh proof.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_native_scalar_proof_policy as base
ROOT=Path(__file__).resolve().parents[1]
SOURCE_PATH='examples/hia_bootstrap/native_public_proof_receipt.hepta'
C={**base.C,'PUB_REQUEST':int.from_bytes(b'HIAJPR01','little'),
   'SELECTION_REPLY':int.from_bytes(b'HIAVRG01','little'),'ERROR_PREFIX':int.from_bytes(b'E_HIA_','little'),'CTX':2097152,'SEEN':4194304,'RWORK':8388608,'ROUT':1048576,
   'ORIGINAL1':61440,'ORIGINAL2':61472,'SUBJECT':61600,
   'DIAG_SIZE':61624,'DIAG_CODE':61632,'DIAG_TEXT':1048576,'DIAG_RAW':61640,'DIAG_RAW_N':61648,'DIAG_LARGE':61656,'DIAG_LIMIT':8654848}
LABELS={
1:'schema',2:'status',3:'profile',4:'function',5:'scope',
6:'program_sha256',7:'input_sha256',8:'before_sha256',9:'after_sha256',
10:'before_input_sha256',11:'after_input_sha256',12:'validator_sha256',
13:'request_input_sha256',14:'before_request_input_sha256',15:'after_request_input_sha256',
16:'wall_ns',17:'subject',18:'checker',19:'solver',20:'source_identity',
21:'source_identity_sha256',22:'native-closure.image.bin',23:'identity',
24:'native_closure_sha256',25:'timeout_ms',26:'structural_verification',
27:'before',28:'after',29:'property',30:'assumptions',31:'unproved_obligations',
32:'proof_scope_schema',33:'proved_meaning',34:'execution_authority',
35:'equivalence',36:'reason',37:'diagnostics',38:'message',39:'code',
101:'hepta.hia.scalar-totality.v1',102:'hepta.hia.translation-validation.v1',
103:'hia.scalar-acyclic-bitvector-totality.v1',104:'hia.scalar-acyclic-bitvector-traps.v1',
105:'unknown',106:'proved',107:'disproved',108:'E_DRIVER',
}
EXTRA={
501:',"validation_error":{"code":',502:',"message":',
503:'{"status":"error","error":{"code":"E_HIA_TRANSLATION_RECEIPT","message":',
504:'{"status":"error","error":{"code":"E_HIA_TRANSLATION_UNPROVED","message":',
505:'"translation receipt does not claim a supported proof"',
506:'"translation receipt is not bound to the current program/profile"',
507:'"translation proof scope is missing, stale or altered"',
508:'"translation proof could not be recomputed: ',
}
POLICY=r'''
def public_proof_receipt(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<768 or length(o)<ROUT or length(w)<RWORK or read64(s,0)!=PUB_REQUEST:
        return BAD
    action=read64(s,8)
    mode=read64(s,16)
    if action>3 or mode<1 or mode>2 or read64(s,48)>128 or read64(s,408)>2:
        return BAD
    flags=read64(s,56)
    large=(flags&256)!=0
    large_claimed=(flags&512)!=0
    if large_claimed and action!=2 and action!=3:
        return BAD
    if flags>1023 or read64(s,400)!=0:
        return BAD
    if large and (action!=1 and action!=2):
        return BAD
    if large and action==1 and (flags&64)==0:
        return BAD
    if large and action==2 and ((flags&64)!=0 or read64(s,408)!=0):
        return BAD
    i=416
    while i<512:
        if read64(s,i)!=0:
            return BAD
        i=i+8
    i=512+read64(s,48)
    while i<768:
        if byte(s,i)!=0:
            return BAD
        i=i+1
    if action>=2 and mode!=2:
        return BAD
    i=0
    while i<read64(s,48):
        c=byte(s,512+i)
        if ((c>=65 and c<=90) or (c>=97 and c<=122) or c==95 or (i!=0 and c>=48 and c<=57))==False:
            return BAD
        i=i+1
    at=768
    i=0
    while i<3:
        jn=read64(s,352+i*16)
        an=read64(s,360+i*16)
        limit=1048576
        arena_limit=16777216
        if large and ((action==1 and i==2) or (action==2 and i==0)):
            limit=67108864
            if action==2:
                arena_limit=83886080
        if large_claimed and i==1:
            limit=67108864
            arena_limit=83886080
        if jn>limit or an>arena_limit or jn>length(s)-at:
            return BAD
        put(w,CTX+i*16,at)
        at=at+jn
        put(w,CTX+8+i*16,at)
        if an>length(s)-at:
            return BAD
        if (jn==0)!=(an==0):
            return BAD
        if an!=0 and arena_valid(s,w,at,an,jn)==False:
            return BAD
        at=at+an
        i=i+1
    if at!=length(s):
        return BAD
    if action==1:
        return make_unknown(s,o,w)
    if action==3:
        return receipt_selection(s,o,w)
    if read64(s,352)==0:
        return BAD
    arena=get(w,CTX+8)
    if nodeword(s,arena,0,0)!=6:
        return BAD
    if action==2:
        if large and string_id(s,arena,field(s,arena,0,2))!=105:
            return BAD
        return verify_fresh(s,o,w)
    if string_id(s,arena,field(s,arena,0,1))!=100+mode:
        return BAD
    if string_id(s,arena,field(s,arena,0,3))!=102+mode:
        return BAD
    if string_id(s,arena,field(s,arena,0,2))!=105+read64(s,408):
        return BAD
    if digest_matches(s,arena,field(s,arena,0,12),288)==False:
        return BAD
    checker=field(s,arena,0,18)
    identity=field(s,arena,checker,20)
    if nodeword(s,arena,identity,0)!=6 or nodeword(s,arena,identity,32)!=1:
        return BAD
    if digest_matches(s,arena,field(s,arena,identity,22),288)==False:
        return BAD
    subject=field(s,arena,0,17)
    if nodeword(s,arena,subject,0)!=6:
        return BAD
    required_result=read64(s,408)!=0
    side=0
    while side<2:
        parent=choose(side==0,0,subject)
        if mode==1:
            if bound_digest(s,arena,parent,6,192,required_result)==False or bound_digest(s,arena,parent,7,192,required_result)==False:
                return BAD
        else:
            if bound_digest(s,arena,parent,8,192,required_result)==False or bound_digest(s,arena,parent,10,192,required_result)==False:
                return BAD
            if bound_digest(s,arena,parent,9,224,required_result)==False or bound_digest(s,arena,parent,11,224,required_result)==False:
                return BAD
        side=side+1
    fn=field(s,arena,0,4)
    if plain_same(s,arena,get(w,CTX),fn,arena,get(w,CTX),field(s,arena,subject,4),0)==False:
        return BAD
    if required_result and (nodeword(s,arena,fn,0)!=4 or nodeword(s,arena,fn,32)==0):
        return BAD
    if read64(s,48)!=0:
        if nodeword(s,arena,fn,0)!=4 or nodeword(s,arena,fn,32)!=read64(s,48):
            return BAD
        if same_bytes(s,arena+nodeword(s,arena,fn,24),512,read64(s,48))==False:
            return BAD
    required=choose(mode==1,51,63)
    if read64(s,408)!=0 and ((read64(s,56)&required)!=required or (read64(s,56)&128)!=0):
        return BAD
    put(w,CTX+64,0)
    at=patch_object(s,o,w,0,0,64,0)
    if get(w,CTX+64)!=0 or at>length(o):
        return BAD
    return reply(o,mode,read64(s,408),read64(s,32),at)

def arena_valid(s:readbuf,w:mutbuf,base:u64,size:u64,wire:u64) -> bool:
    if size<64 or read64(s,base)!=5208772604367785521:
        return False
    count=read64(s,base+8)
    first=64+72*count
    if count==0 or count>131073 or first>size:
        return False
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

def nodeword(s:readbuf,base:u64,node:u64,slot:u64) -> u64:
    if node==NONE or node>=read64(s,base+8):
        return NONE
    return read64(s,base+64+node*72+slot)

def field(s:readbuf,base:u64,node:u64,key:u64) -> u64:
    if nodeword(s,base,node,0)!=6:
        return NONE
    child=nodeword(s,base,node,24)
    while child!=NONE:
        if label(s,base+nodeword(s,base,child,40),nodeword(s,base,child,48))==key:
            return child
        child=nodeword(s,base,child,16)
    return NONE

def string_id(s:readbuf,base:u64,node:u64) -> u64:
    if nodeword(s,base,node,0)!=4:
        return 0
    return label(s,base+nodeword(s,base,node,24),nodeword(s,base,node,32))

def digest_matches(s:readbuf,base:u64,node:u64,digest:u64) -> bool:
    if nodeword(s,base,node,0)!=4 or nodeword(s,base,node,32)!=64:
        return False
    at=base+nodeword(s,base,node,24)
    i=0
    while i<32:
        b=byte(s,digest+i)
        high=b>>4
        low=b&15
        if byte(s,at+2*i)!=high+choose(high<10,48,87) or byte(s,at+2*i+1)!=low+choose(low<10,48,87):
            return False
        i=i+1
    return True

def bound_digest(s:readbuf,arena:u64,parent:u64,key:u64,digest:u64,required:bool) -> bool:
    node=field(s,arena,parent,key)
    if nodeword(s,arena,node,0)==0 and required==False:
        return True
    return digest_matches(s,arena,node,digest)

def patch_object(s:readbuf,o:mutbuf,w:mutbuf,node:u64,path:u64,at:u64,depth:u64) -> u64:
    arena=get(w,CTX+8)
    if depth>8 or nodeword(s,arena,node,0)!=6:
        put(w,CTX+64,1)
        return at
    at=emit(o,at,123)
    child=nodeword(s,arena,node,24)
    written=0
    while child!=NONE:
        key=label(s,arena+nodeword(s,arena,child,40),nodeword(s,arena,child,48))
        skip=path==1 and (key==13 or key==14 or key==15)
        if skip==False:
            if written!=0:
                at=emit(o,at,44)
            at=quote_input(s,o,at,arena+nodeword(s,arena,child,40),nodeword(s,arena,child,48))
            at=emit(o,at,58)
            at=patch_value(s,o,w,child,path,key,at,depth)
            written=written+1
        child=nodeword(s,arena,child,16)
    return emit(o,at,125)

def patch_value(s:readbuf,o:mutbuf,w:mutbuf,node:u64,path:u64,key:u64,at:u64,depth:u64) -> u64:
    flags=read64(s,56)
    if path==0 or path==1:
        if key==6 or key==8:
            return input_digest(s,o,at,192,(flags&2)!=0)
        if key==9:
            return input_digest(s,o,at,224,(flags&8)!=0)
        if key==7 or key==10:
            return input_digest(s,o,at,128,(flags&2)!=0)
        if key==11:
            return input_digest(s,o,at,160,(flags&8)!=0)
        if key==13 or key==14:
            return input_digest(s,o,at,64,(flags&1)!=0)
        if key==15:
            return input_digest(s,o,at,96,(flags&4)!=0)
    if path==0:
        if key==12:
            return input_digest(s,o,at,256,(flags&16)!=0)
        if key==16:
            return unsigned(o,w,at,read64(s,32))
        if key==17:
            return patch_object(s,o,w,node,1,at,depth+1)
        if key==18:
            return patch_object(s,o,w,node,2,at,depth+1)
        if key==19:
            return patch_object(s,o,w,node,3,at,depth+1)
    elif path==2:
        if key==20:
            return patch_object(s,o,w,node,4,at,depth+1)
        if key==21:
            return input_digest(s,o,at,320,(flags&32)!=0)
    elif path==3:
        if key==23:
            return patch_object(s,o,w,node,5,at,depth+1)
        if key==25:
            return unsigned(o,w,at,read64(s,40))
    elif path==4 and key==22:
        return input_digest(s,o,at,256,(flags&16)!=0)
    elif path==5 and key==24:
        return input_digest(s,o,at,256,(flags&16)!=0)
    return copy_node(s,o,get(w,CTX),get(w,CTX+8),node,at)

def copy_node(s:readbuf,o:mutbuf,json:u64,arena:u64,node:u64,at:u64) -> u64:
    kind=nodeword(s,arena,node,0)
    offset=choose(kind>=4,56,24)
    start=nodeword(s,arena,node,offset)
    size=nodeword(s,arena,node,offset+8)
    return input_copy(s,o,at,json+start,size)

def input_digest(s:readbuf,o:mutbuf,at:u64,start:u64,available:bool) -> u64:
    if available==False:
        return lit(o,at,12)
    at=emit(o,at,34)
    i=0
    while i<32:
        b=byte(s,start+i)
        a=b>>4
        b=b&15
        at=emit(o,at,a+choose(a<10,48,87))
        at=emit(o,at,b+choose(b<10,48,87))
        i=i+1
    return emit(o,at,34)

def quote_input(s:readbuf,o:mutbuf,at:u64,start:u64,size:u64) -> u64:
    at=emit(o,at,34)
    i=0
    while i<size:
        at=quote_byte(o,at,byte(s,start+i))
        i=i+1
    return emit(o,at,34)

def quote_byte(o:mutbuf,at:u64,c:u64) -> u64:
    if c==34 or c==92:
        at=emit(o,at,92)
        return emit(o,at,c)
    if c<32:
        at=emit(o,at,92)
        at=emit(o,at,117)
        at=emit(o,at,48)
        at=emit(o,at,48)
        a=c>>4
        b=c&15
        at=emit(o,at,a+choose(a<10,48,87))
        return emit(o,at,b+choose(b<10,48,87))
    return emit(o,at,c)

def input_copy(s:readbuf,o:mutbuf,at:u64,start:u64,size:u64) -> u64:
    i=0
    while i<size:
        at=emit(o,at,byte(s,start+i))
        i=i+1
    return at

def read64(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(8*i))
        i=i+1
    return value

def readn(s:readbuf,at:u64,n:u64) -> u64:
    value=0
    i=0
    while i<n:
        value=value|(byte(s,at+i)<<(8*i))
        i=i+1
    return value

def same_bytes(s:readbuf,a:u64,b:u64,n:u64) -> bool:
    i=0
    while i<n:
        if byte(s,a+i)!=byte(s,b+i):
            return False
        i=i+1
    return True

def plain_same(s:readbuf,aa:u64,aj:u64,a:u64,ba:u64,bj:u64,b:u64,depth:u64) -> bool:
    if depth>128 or a==NONE or b==NONE:
        return False
    kind=nodeword(s,aa,a,0)
    if kind!=nodeword(s,ba,b,0):
        return False
    if kind<3:
        return True
    if kind==4:
        n=nodeword(s,aa,a,32)
        return n==nodeword(s,ba,b,32) and same_bytes(s,aa+nodeword(s,aa,a,24),ba+nodeword(s,ba,b,24),n)
    if kind==3:
        ap=aj+nodeword(s,aa,a,24)
        bp=bj+nodeword(s,ba,b,24)
        an=nodeword(s,aa,a,32)
        bn=nodeword(s,ba,b,32)
        if an==2 and readn(s,ap,2)==12333:
            ap=ap+1
            an=1
        if bn==2 and readn(s,bp,2)==12333:
            bp=bp+1
            bn=1
        return an==bn and same_bytes(s,ap,bp,an)
    if nodeword(s,aa,a,32)!=nodeword(s,ba,b,32):
        return False
    ac=nodeword(s,aa,a,24)
    bc=nodeword(s,ba,b,24)
    while ac!=NONE:
        chosen=bc
        if kind==6:
            chosen=nodeword(s,ba,b,24)
            found=NONE
            while chosen!=NONE and found==NONE:
                kn=nodeword(s,aa,ac,48)
                if kn==nodeword(s,ba,chosen,48) and same_bytes(s,aa+nodeword(s,aa,ac,40),ba+nodeword(s,ba,chosen,40),kn):
                    found=chosen
                else:
                    chosen=nodeword(s,ba,chosen,16)
            chosen=found
        if chosen==NONE or plain_same(s,aa,aj,ac,ba,bj,chosen,depth+1)==False:
            return False
        ac=nodeword(s,aa,ac,16)
        if kind==5:
            bc=nodeword(s,ba,bc,16)
    return True

def receipt_selection(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if read64(s,368)==0:
        return receipt_error(s,o,w,1)
    arena=get(w,CTX+24)
    if string_id(s,arena,field(s,arena,0,1))!=102 or string_id(s,arena,field(s,arena,0,2))!=106:
        return receipt_error(s,o,w,1)
    node=field(s,arena,0,4)
    kind=nodeword(s,arena,node,0)
    size=0
    if kind==4:
        size=nodeword(s,arena,node,32)
        if size>128:
            return receipt_error(s,o,w,2)
    elif kind!=0 and node!=NONE:
        return receipt_error(s,o,w,2)
    i=0
    while i<64:
        store(o,i,0)
        i=i+1
    put(o,0,SELECTION_REPLY)
    put(o,8,size)
    if size!=0:
        start=arena+nodeword(s,arena,node,24)
        i=0
        while i<size:
            c=byte(s,start+i)
            if ((c>=65 and c<=90) or (c>=97 and c<=122) or c==95 or (i!=0 and c>=48 and c<=57))==False:
                return receipt_error(s,o,w,2)
            store(o,64+i,c)
            i=i+1
    return 64+size

def verify_fresh(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if read64(s,368)==0:
        return receipt_error(s,o,w,1)
    aa=get(w,CTX+8)
    ba=get(w,CTX+24)
    if string_id(s,ba,field(s,ba,0,1))!=102 or string_id(s,ba,field(s,ba,0,2))!=106:
        return receipt_error(s,o,w,1)
    i=0
    while i<9:
        key=verify_key(i)
        a=field(s,aa,0,key)
        b=field(s,ba,0,key)
        if nodeword(s,aa,a,0)!=4 or nodeword(s,ba,b,0)!=4 or plain_same(s,aa,get(w,CTX),a,ba,get(w,CTX+16),b,0)==False:
            return receipt_error(s,o,w,2)
        i=i+1
    if string_id(s,aa,field(s,aa,0,2))!=106:
        return receipt_error(s,o,w,3)
    i=0
    while i<9:
        key=scope_key(i)
        a=field(s,aa,0,key)
        b=field(s,ba,0,key)
        if plain_same(s,aa,get(w,CTX),a,ba,get(w,CTX+16),b,0)==False:
            return receipt_error(s,o,w,4)
        i=i+1
    at=input_copy(s,o,64,get(w,CTX),read64(s,352))
    if at>length(o):
        return BAD
    return reply(o,3,1,read64(s,32),at)

def verify_key(i:u64) -> u64:
    if i==0:
        return 1
    if i==1:
        return 3
    if i==2:
        return 4
    if i==3:
        return 5
    if i==4:
        return 8
    if i==5:
        return 9
    if i==6:
        return 10
    if i==7:
        return 11
    return 12

def scope_key(i:u64) -> u64:
    if i==0:
        return 17
    if i==1:
        return 29
    if i==2:
        return 3
    if i==3:
        return 30
    if i==4:
        return 18
    if i==5:
        return 31
    if i==6:
        return 32
    if i==7:
        return 33
    return 34

def receipt_error(s:readbuf,o:mutbuf,w:mutbuf,which:u64) -> u32:
    at=lit(o,64,choose(which==3,504,503))
    if which==1:
        at=lit(o,at,505)
    elif which==2:
        at=lit(o,at,506)
    elif which==4:
        at=lit(o,at,507)
    else:
        at=lit(o,at,508)
        arena=get(w,CTX+8)
        node=field(s,arena,0,36)
        if nodeword(s,arena,node,0)!=4:
            return BAD
        i=0
        while i<nodeword(s,arena,node,32):
            at=quote_byte(o,at,byte(s,arena+nodeword(s,arena,node,24)+i))
            i=i+1
        at=emit(o,at,34)
    at=emit(o,at,125)
    at=emit(o,at,125)
    if at>length(o):
        return BAD
    return reply(o,3,3,read64(s,32),at)

def reply(o:mutbuf,mode:u64,status:u64,wall:u64,at:u64) -> u32:
    put(o,0,REPLY_MAGIC)
    put(o,8,mode)
    put(o,16,status)
    put(o,24,at-64)
    put(o,32,wall)
    put(o,40,0)
    put(o,48,0)
    put(o,56,0)
    return at

def make_unknown(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    reason=read64(s,24)
    if reason<1 or reason>27:
        return BAD
    i=0
    while i<65536:
        store(w,i,0)
        i=i+1
    flags=read64(s,56)
    if (flags&64)!=0 and prepare_diagnostic(s,w)==False:
        return BAD
    put(w,256,read64(s,16))
    put(w,280,read64(s,40))
    put(w,288,read64(s,48))
    put(w,320,reason)
    put(w,328,choose((flags&2)!=0,1,0))
    put(w,336,choose((flags&8)!=0,1,0))
    put(w,512,flags&15)
    put(w,520,choose((flags&16)!=0,1,0))
    put(w,528,choose((flags&128)!=0,1,0))
    put(w,536,choose((flags&32)!=0,1,0))
    put(w,80,read64(s,32)//1000000000)
    put(w,88,read64(s,32)%1000000000)
    copy_to_work(s,w,512,NAME,read64(s,48))
    copy_to_work(s,w,64,RAW_BEFORE,32)
    copy_to_work(s,w,96,RAW_AFTER,32)
    copy_to_work(s,w,128,ORIGINAL1,32)
    copy_to_work(s,w,160,ORIGINAL2,32)
    copy_to_work(s,w,192,CORE_BEFORE,32)
    copy_to_work(s,w,224,CORE_AFTER,32)
    copy_to_work(s,w,256,WHOLE_ID,32)
    copy_to_work(s,w,320,1216,32)
    result=base_receipt(o,w)
    if get(w,DIAG_LARGE)!=0:
        return append_large_diagnostic(s,o,w,result)
    return result

def prepare_diagnostic(s:readbuf,w:mutbuf) -> bool:
    if read64(s,384)==0:
        return False
    a=get(w,CTX+40)
    list=field(s,a,0,37)
    if nodeword(s,a,list,0)!=5 or nodeword(s,a,list,32)==0:
        return False
    error=nodeword(s,a,list,24)
    if string_id(s,a,field(s,a,error,39))!=108:
        return False
    text=field(s,a,error,38)
    if nodeword(s,a,text,0)!=4:
        return False
    start=a+nodeword(s,a,text,24)
    n=nodeword(s,a,text,32)
    limit=choose((read64(s,56)&256)!=0,DIAG_LIMIT,131072)
    if n<9 or n>limit or readn(s,start,6)!=ERROR_PREFIX:
        return False
    code=0
    while code<n and byte(s,start+code)!=58:
        c=byte(s,start+code)
        if ((c>=65 and c<=90) or (c>=48 and c<=57) or c==95)==False:
            return False
        code=code+1
    if code<7 or code>128 or code+1>=n or byte(s,start+code)!=58 or byte(s,start+code+1)!=32:
        return False
    if (read64(s,56)&256)!=0:
        raw=get(w,CTX+32)+nodeword(s,a,text,56)
        count=nodeword(s,a,text,64)
        if count<2 or raw>length(s) or count>length(s)-raw:
            return False
        if byte(s,raw)!=34 or byte(s,raw+count-1)!=34:
            return False
        copy_to_work(s,w,start,DIAG_TEXT,code)
        put(w,DIAG_RAW,raw)
        put(w,DIAG_RAW_N,count)
        put(w,DIAG_LARGE,1)
    else:
        copy_to_work(s,w,start,DIAG_TEXT,n)
        put(w,DIAG_SIZE,n)
    put(w,DIAG_CODE,code)
    return True

def append_large_diagnostic(s:readbuf,o:mutbuf,w:mutbuf,n:u64) -> u32:
    if n<65 or n>length(o) or byte(o,n-1)!=125:
        return BAD
    at=lit(o,n-1,501)
    at=quote_work(o,w,at,DIAG_TEXT,get(w,DIAG_CODE))
    at=lit(o,at,502)
    at=input_copy(s,o,at,get(w,DIAG_RAW),get(w,DIAG_RAW_N))
    at=emit(o,at,125)
    at=emit(o,at,125)
    if at>length(o):
        return BAD
    return reply(o,read64(s,16),0,read64(s,32),at)

def copy_to_work(s:readbuf,w:mutbuf,start:u64,target:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,target+i,byte(s,start+i))
        i=i+1
    return 0

def validation_fields(o:mutbuf,w:mutbuf,at:u64) -> u64:
    if get(w,DIAG_SIZE)==0:
        return at
    at=lit(o,at,501)
    at=quote_work(o,w,at,DIAG_TEXT,get(w,DIAG_CODE))
    at=lit(o,at,502)
    at=quote_work(o,w,at,DIAG_TEXT,get(w,DIAG_SIZE))
    return emit(o,at,125)

def quote_work(o:mutbuf,w:mutbuf,at:u64,start:u64,n:u64) -> u64:
    at=emit(o,at,34)
    i=0
    while i<n:
        at=quote_byte(o,at,byte(w,start+i))
        i=i+1
    return emit(o,at,34)
'''
IDENTITIES=r'''
def identities(o:mutbuf,w:mutbuf,at:u64) -> u64:
    flags=get(w,512)
    if get(w,256)==1:
        at=lit(o,at,14)
        at=digest(o,w,at,CORE_BEFORE,(flags&2)!=0)
        at=lit(o,at,15)
        at=digest(o,w,at,ORIGINAL1,(flags&2)!=0)
        if get(w,SUBJECT)==0:
            at=lit(o,at,90)
            at=digest(o,w,at,RAW_BEFORE,(flags&1)!=0)
        return at
    at=lit(o,at,16)
    at=digest(o,w,at,CORE_BEFORE,(flags&2)!=0)
    at=lit(o,at,17)
    at=digest(o,w,at,CORE_AFTER,(flags&8)!=0)
    at=lit(o,at,18)
    at=digest(o,w,at,ORIGINAL1,(flags&2)!=0)
    at=lit(o,at,19)
    at=digest(o,w,at,ORIGINAL2,(flags&8)!=0)
    if get(w,SUBJECT)==0:
        at=lit(o,at,91)
        at=digest(o,w,at,RAW_BEFORE,(flags&1)!=0)
        at=lit(o,at,92)
        at=digest(o,w,at,RAW_AFTER,(flags&4)!=0)
    return at
'''
def source_program():
    render=base.RENDER.replace('def receipt(', 'def base_receipt(')
    first=render.index('\ndef identities(')
    last=render.index('\ndef solver_report(',first)
    render=render[:first]+'\n'+IDENTITIES+render[last:]
    old='    at = identities(o, w, at)'
    assert render.count(old)==2
    render=render.replace(old,'    put(w, SUBJECT, 0)\n'+old,1)
    at=render.index(old,render.index(old)+len(old))
    render=render[:at]+'    put(w, SUBJECT, 1)\n'+render[at:]
    marker='    at = lit(o, at, 27)'
    assert render.count(marker)==1
    render=render.replace(marker,'    at = validation_fields(o, w, at)\n'+marker)
    wanted={'get','getn','put','now','mask','trap_code'}
    helpers=[]
    for node in ast.parse(base.POLICY).body:
        if isinstance(node,ast.FunctionDef) and node.name in wanted:
            helpers.append(ast.get_source_segment(base.POLICY,node))
    assert len(helpers)==len(wanted)
    old_literals=base.LITERALS
    try:
        base.LITERALS={**old_literals,**EXTRA}
        literals=base.literal_source()
    finally:
        base.LITERALS=old_literals
    entries=list(LABELS.items())
    groups=[entries[i:i+12] for i in range(0,len(entries),12)]
    labels=['def label(s:readbuf,at:u64,n:u64) -> u64:']
    for i,group in enumerate(groups):
        labels += [f'    answer=label_part_{i}(s,at,n)','    if answer!=0:','        return answer']
    labels.append('    return 0')
    for i,group in enumerate(groups):
        labels += ['',f'def label_part_{i}(s:readbuf,at:u64,n:u64) -> u64:']
        for key,value in group:
            raw=value.encode()
            parts=[f'n=={len(raw)}']+[f'readn(s,at+{i},{len(raw[i:i+8])})=={int.from_bytes(raw[i:i+8],"little")}' for i in range(0,len(raw),8)]
            labels += ['    if '+' and '.join(parts)+':',f'        return {key}']
        labels.append('    return 0')
    source=POLICY+'\n'+render+'\n'+'\n\n'.join(helpers)+'\n'+literals+'\n'+'\n'.join(labels)
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+name+r'\b',str(value),source)
    return source
def program():
    return document(source_program(),'native_public_proof_receipt')
def json_program():
    from tools.generate_hia_json_decode import source_program as wire_source
    source=wire_source(wire_spans=True)
    assert source.count('length(s) > 8388608')==2
    source=source.replace('length(s) > 8388608','length(s) > 67108864')
    source=source.replace('def decode_json(', 'def decode_private_json(',1)
    wrapper='def public_proof_json(s:readbuf,o:mutbuf,w:mutbuf) -> u32:\n    if length(s)>8388608:\n        if length(w)<128 or get(w,120)!=3544411299729459528 or length(s)>67108864 or length(o)<83886080:\n            return 4294967293\n    return decode_private_json(s,o,w)\n'
    return document(wrapper+'\n'+source,'native_public_proof_json')
if __name__=='__main__':
    for name,tree in [('native_public_proof_receipt',program()),('native_public_proof_json',json_program())]:
        p=ROOT/'examples/hia_bootstrap'/(name+'.hepta');p.write_text(render_assembly(tree))
        print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']),flush=True)
