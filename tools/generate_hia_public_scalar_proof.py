"""Author the HIA process front-end for raw normalized scalar proofs.

The private binary interface is deliberately distinct from the complete typed
public API. Receipt semantics remain in the separately qualified receipt role.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
ROOT=Path(__file__).resolve().parents[1]
M=lambda t:int.from_bytes(t.encode(),'little')
C=dict(REQUEST=M('HIAPPR01'),REPLY=M('HIAMVR01'),NORM=M('HIAVCF01'),PREQUEST=M('HIAMVPS1'),PREPLY=M('HIAMVPO1'),PROOF=M('HIAMVP01'),RREQUEST=M('HIAJPR01'),SELECT=M('HIAVRG01'),NONE=(1<<64)-1,NEG4=(1<<64)-4,WORK=608<<20,ROUT=64<<20,LARGE_JSON=M('HIAJLG01'),
 N1=1<<20,N2=18<<20,PIN=35<<20,AJ=52<<20,DJ=196<<20,BJ=54<<20,AA=55<<20,BA=71<<20,DA=260<<20,RI=340<<20,RO=468<<20,FJ=532<<20,PW=160<<20,JW=180<<20,RW=188<<20,
 POUT=65536,CLOCK=32768,STAT=32832,SHABUF=262144,HW=8192,HTMP=4448,HOUT=4480,FUNCTION=4608,MFNAME=12288,INV=12416,
 WHOLE=4096,WHOLE_END=4128,NORMAL_ID=4160,ENGINE_ID=4192,RAW1=4224,RAW2=4256,ORIG1=4288,ORIG2=4320,CORE1=4352,CORE2=4384,INVENTORY=4416)
SOURCE=r'''
def public_proof(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)!=ROUT or length(w)!=WORK:
        return 4294967293
    phase=get(w,0)
    result=get(w,8)
    if phase==0:
        return begin(s,o,w)
    if phase>=400 and phase<410:
        return hashing(s,o,w,phase,result)
    if phase>=500 and phase<510:
        return streams(o,w,phase,result)
    if phase>=600 and phase<610:
        return reading(o,w,phase,result)
    if phase>=200 and phase<210:
        return closing(o,w,phase,result)
    if phase>=300 and phase<310:
        return guarded(s,o,w,phase,result)
    if phase<20:
        return initial(s,o,w,phase,result)
    if phase>=20 and phase<40:
        return capture(s,o,w,phase,result)
    if phase>=50 and phase<70:
        return normalizing(s,o,w,phase,result)
    if phase>=70 and phase<80:
        return diagnostic(s,o,w,phase,result)
    if phase>=80 and phase<90:
        return proving(s,o,w,phase,result)
    if phase>=100 and phase<130:
        return receipt(s,o,w,phase,result)
    return 4294967293

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or readword(s,0)!=REQUEST or readword(s,56)!=0:
        return 4294967293
    mode=readword(s,8)
    name=readword(s,24)
    first=readword(s,32)
    second=readword(s,40)
    claim=readword(s,48)
    if mode<1 or mode>3 or name>128 or first>8388608 or second>8388608 or claim>262144:
        return 4294967293
    if mode==1 and (second!=0 or claim!=0):
        return 4294967293
    if mode==2 and (second==0 or claim!=0):
        return 4294967293
    if mode==3 and (second==0 or claim==0):
        return 4294967293
    if length(s)!=64+name+first+second+claim:
        return 4294967293
    i=0
    while i<name:
        c=byte(s,64+i)
        if ((c>=65 and c<=90) or (c>=97 and c<=122) or c==95 or (i>0 and c>=48 and c<=57))==False:
            return 4294967293
        i=i+1
    if get(w,88)<176 or get(w,88)>16777216:
        return 4294967293
    if image_range(w,get(w,96),get(w,104))==False or image_range(w,get(w,112),get(w,120))==False:
        return 4294967293
    zero(w,256,768)
    zero(w,WHOLE,1024)
    put(w,256,mode)
    put(w,264,readword(s,16))
    put(w,272,name)
    put(w,280,first)
    put(w,288,second)
    put(w,296,claim)
    put(w,304,64+name)
    put(w,312,64+name+first)
    put(w,320,64+name+first+second)
    put(w,360,NONE)
    put(w,368,NONE)
    put(w,376,NONE)
    put(w,384,NONE)
    put(w,504,NONE)
    put(w,864,NONE)
    self_path(w)
    copy_input(s,64,w,FUNCTION,name)
    put(w,MFNAME,7309475729723812200)
    put(w,MFNAME+8,0)
    return call(o,w,1,228,4,1,CLOCK,0,0,0,0)

def image_range(w:mutbuf,at:u64,n:u64) -> bool:
    return n>=176 and n<=8388608 and at<=get(w,88) and n<=get(w,88)-at

def initial(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==1:
        if failed(result):
            return 4294967293
        start=clock(w)
        put(w,328,start)
        budget=get(w,264)
        if budget>=1 and budget<=60000 and start<=NONE-budget*1000000:
            put(w,336,start+budget*1000000)
        else:
            put(w,544,1)
        return call(o,w,4,257,4,18446744073709551516,12320,524288,0,0,0)
    if phase==4:
        if failed(result):
            return unavailable(o,w)
        put(w,864,result)
        return call(o,w,5,5,4,result,STAT,0,0,0,0)
    if phase==5:
        if failed(result) or get(w,STAT+48)!=get(w,88) or (get(w,STAT+24)&61440)!=32768:
            return identity_failure(o,w)
        copy(w,STAT,33024,144)
        return hash_begin(w,2,2,0,get(w,88),WHOLE,0)
    if phase==2:
        put(w,352,get(w,352)|16)
        inventory(w)
        return hash_begin(w,3,1,INV,95,INVENTORY,0)
    if phase==3:
        put(w,352,get(w,352)|32)
        if get(w,256)==3:
            copy_input(s,get(w,320),w,BJ,get(w,296))
            return decode(w,10,BJ,get(w,296),BA)
        return advance(w,11)
    if phase==10:
        if arena_ok(result)==False:
            return 4294967293
        put(w,784,result)
        put(w,832,3)
        return receipt_role(w,12,3)
    if phase==12:
        if result<64 or result>1048576:
            return unavailable(o,w)
        if get(w,RO)==REPLY:
            if get(w,RO+8)!=3 or get(w,RO+16)!=3 or get(w,RO+24)!=result-64:
                return unavailable(o,w)
            put(w,704,result)
            return close_all(o,w)
        if get(w,RO)!=SELECT or get(w,RO+8)>128 or result!=64+get(w,RO+8):
            return unavailable(o,w)
        if get(w,272)==0:
            put(w,272,get(w,RO+8))
            copy(w,RO+64,FUNCTION,get(w,272))
        return advance(w,11)
    if phase==11:
        if get(w,544)==1:
            return prepare_result(o,w)
        return hash_begin(w,13,0,get(w,304),get(w,280),RAW1,0)
    if phase==13:
        put(w,352,get(w,352)|1)
        if get(w,256)!=1:
            return hash_begin(w,14,0,get(w,312),get(w,288),RAW2,0)
        return advance(w,14)
    if phase==14:
        if get(w,256)!=1:
            put(w,352,get(w,352)|4)
        put(w,480,0)
        return guard(o,w,15)
    if phase==15:
        put(w,488,get(w,96))
        put(w,496,get(w,104))
        return hash_begin(w,20,2,get(w,488),get(w,496),NORMAL_ID,0)
    return 4294967293

def capture(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==20:
        return call(o,w,21,319,1,MFNAME,3,0,0,0,0)
    if phase==21:
        if failed(result):
            return unavailable(o,w)
        put(w,504,result)
        put(w,512,0)
        return call(o,w,22,91,0,result,384,0,0,0,0)
    if phase==22:
        if failed(result):
            return unavailable(o,w)
        return image_write(o,w)
    if phase==23:
        if result==NEG4:
            return image_write(o,w)
        if failed(result) or result==0 or result>get(w,520):
            return unavailable(o,w)
        put(w,512,get(w,512)+result)
        if get(w,512)<get(w,496):
            return image_write(o,w)
        return call(o,w,24,8,0,get(w,504),0,0,0,0,0)
    if phase==24:
        if result!=0:
            return unavailable(o,w)
        return call(o,w,29,91,0,get(w,504),320,0,0,0,0)
    if phase==29:
        if failed(result):
            return unavailable(o,w)
        return call(o,w,25,72,0,get(w,504),1033,15,0,0,0)
    if phase==25:
        if failed(result):
            return unavailable(o,w)
        return call(o,w,26,72,0,get(w,504),1034,0,0,0,0)
    if phase==26:
        if result!=15:
            return unavailable(o,w)
        return call(o,w,27,5,4,get(w,504),STAT,0,0,0,0)
    if phase==27:
        if failed(result) or get(w,STAT+16)!=0 or (get(w,STAT+24)&61440)!=32768 or (get(w,STAT+24)&511)!=320 or get(w,STAT+48)!=get(w,496):
            return unavailable(o,w)
        return hash_begin(w,28,3,0,get(w,496),HTMP,get(w,504))
    if phase==28:
        expected=choose(get(w,480)==0,NORMAL_ID,ENGINE_ID)
        if equal(w,expected,HTMP,32)==False:
            return identity_failure(o,w)
        if get(w,480)==0:
            put(w,360,get(w,504))
            put(w,504,NONE)
            put(w,480,1)
            put(w,488,get(w,112))
            put(w,496,get(w,120))
            return hash_begin(w,20,2,get(w,488),get(w,496),ENGINE_ID,0)
        put(w,368,get(w,504))
        put(w,504,NONE)
        put(w,392,0)
        return guard(o,w,50)
    return 4294967293

def image_write(o:mutbuf,w:mutbuf) -> u32:
    count=get(w,496)-get(w,512)
    if count>65536:
        count=65536
    put(w,520,count)
    return call(o,w,23,1,12,get(w,504),get(w,488)+get(w,512),count,0,0,0)
'''
SOURCE+=r'''
def normalizing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==50:
        return process_raw(s,w,51,1)
    if phase==51:
        if process_reply(w,result)==False:
            return process_failure(o,w,result)
        if get(w,464)!=0:
            if get(w,464)!=512 and get(w,464)!=768:
                return unavailable(o,w)
            return close_streams(o,w,70)
        n=get(w,448)
        if n<64 or n>16777280 or get(w,456)!=0:
            return unavailable(o,w)
        put(w,400+get(w,392)*8,n)
        return read_capture(o,w,52,choose(get(w,392)==0,N1,N2),n)
    if phase==52:
        return close_streams(o,w,53)
    if phase==53:
        base=choose(get(w,392)==0,N1,N2)
        n=get(w,400+get(w,392)*8)
        original=get(w,base+32)
        core=get(w,base+40)
        if get(w,base)!=NORM or get(w,base+8)!=0 or get(w,base+16)!=0 or get(w,base+24)>4 or get(w,base+48)!=0 or get(w,base+56)!=0:
            return unavailable(o,w)
        if original==0 or original>8388608 or core==0 or core>8388608 or n!=64+original+core:
            return unavailable(o,w)
        put(w,416+get(w,392)*16,original)
        put(w,424+get(w,392)*16,core)
        return hash_begin(w,54,1,base+64,original,choose(get(w,392)==0,ORIG1,ORIG2),0)
    if phase==54:
        base=choose(get(w,392)==0,N1,N2)
        original=get(w,416+get(w,392)*16)
        core=get(w,424+get(w,392)*16)
        return hash_begin(w,55,1,base+64+original,core,choose(get(w,392)==0,CORE1,CORE2),0)
    if phase==55:
        if get(w,392)==0:
            put(w,352,get(w,352)|2)
        else:
            put(w,352,get(w,352)|8)
        if get(w,392)==0 and get(w,256)!=1:
            put(w,392,1)
            return guard(o,w,50)
        return guard(o,w,80)
    return 4294967293

def diagnostic(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==70:
        return guard(o,w,71)
    if phase==71:
        return process_raw(s,w,72,4)
    if phase==72:
        if process_reply(w,result)==False:
            return process_failure(o,w,result)
        if get(w,464)!=512 or get(w,448)==0 or get(w,448)>67108864 or get(w,456)!=0:
            return unavailable(o,w)
        put(w,792,get(w,448))
        return read_capture(o,w,73,DJ,get(w,448))
    if phase==73:
        return close_streams(o,w,74)
    if phase==74:
        return decode(w,75,DJ,get(w,792),DA)
    if phase==75:
        if arena_ok(result)==False:
            return unavailable(o,w)
        put(w,800,result)
        put(w,544,choose(get(w,392)==0,2,3))
        flags=get(w,352)|64
        if get(w,792)>131072:
            flags=flags|256
        put(w,352,flags)
        return prepare_result(o,w)
    return 4294967293

def proving(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==80:
        remaining=(get(w,336)-clock(w))//1000000
        if remaining==0 or remaining>60000:
            return deadline_failure(o,w)
        zero(w,PIN,192)
        put(w,PIN+128,PROOF)
        put(w,PIN+136,choose(get(w,256)==1,1,2))
        put(w,PIN+144,remaining)
        put(w,PIN+152,get(w,272))
        put(w,PIN+160,get(w,424))
        second=choose(get(w,256)==1,0,get(w,440))
        put(w,PIN+168,second)
        copy(w,FUNCTION,PIN+192,get(w,272))
        cursor=PIN+192+get(w,272)
        copy(w,N1+64+get(w,416),cursor,get(w,424))
        cursor=cursor+get(w,424)
        if second!=0:
            copy(w,N2+64+get(w,432),cursor,second)
        count=64+get(w,272)+get(w,424)+second
        return process_ready(w,81,2,get(w,368),count,262144)
    if phase==81:
        if process_reply(w,result)==False:
            return process_failure(o,w,result)
        if get(w,464)!=0 or get(w,448)<64 or get(w,448)>262144 or get(w,456)!=0:
            return unavailable(o,w)
        return read_capture(o,w,82,AJ,get(w,448))
    if phase==82:
        return close_streams(o,w,83)
    if phase==83:
        n=get(w,448)
        if get(w,AJ)!=REPLY or get(w,AJ+8)!=choose(get(w,256)==1,1,2) or get(w,AJ+16)>2 or get(w,AJ+24)!=n-64:
            return unavailable(o,w)
        if get(w,AJ+40)!=0 or get(w,AJ+48)!=0 or get(w,AJ+56)!=0:
            return unavailable(o,w)
        put(w,744,get(w,AJ+16))
        put(w,760,AJ+64)
        put(w,768,n-64)
        put(w,808,AA)
        return decode(w,84,AJ+64,n-64,AA)
    if phase==84:
        if arena_ok(result)==False:
            return unavailable(o,w)
        put(w,776,result)
        if get(w,272)==0:
            inferred_function(w)
        return prepare_result(o,w)
    return 4294967293

def process_raw(s:readbuf,w:mutbuf,next:u64,role:u64) -> u32:
    at=get(w,304+get(w,392)*8)
    n=get(w,280+get(w,392)*8)
    copy_input(s,at,w,PIN+128,n)
    cap=choose(role==1,16777280,67108864)
    return process_ready(w,next,role,get(w,360),n,cap)

def process_ready(w:mutbuf,next:u64,role:u64,fd:u64,n:u64,cap:u64) -> u32:
    zero(w,PIN,128)
    put(w,PIN,PREQUEST)
    put(w,PIN+8,role)
    put(w,PIN+16,fd)
    put(w,PIN+24,get(w,336))
    put(w,PIN+32,n)
    put(w,PIN+40,cap)
    put(w,PIN+48,67108864)
    put(w,552,role)
    zero(w,POUT,128)
    return role_call(w,next,2,1,PIN,128+n,POUT,128,PW,20971520)

def process_reply(w:mutbuf,result:u64) -> bool:
    if get(w,POUT)!=PREPLY or get(w,POUT+8)!=result or get(w,POUT+120)!=0 or result!=0:
        return False
    a=get(w,POUT+48)
    b=get(w,POUT+56)
    if a<3 or a>2147483647 or b<3 or b>2147483647 or a==b:
        return False
    put(w,376,a)
    put(w,384,b)
    if get(w,POUT+96)!=1 or get(w,POUT+104)!=7 or get(w,POUT+112)!=15:
        return False
    cap=choose(get(w,552)==1,16777280,choose(get(w,552)==2,262144,67108864))
    if get(w,POUT+64)>cap or get(w,POUT+72)>67108864:
        return False
    put(w,448,get(w,POUT+64))
    put(w,456,get(w,POUT+72))
    put(w,464,get(w,POUT+24))
    return True

def process_failure(o:mutbuf,w:mutbuf,result:u64) -> u32:
    if get(w,POUT)==PREPLY and get(w,POUT+8)==1 and result==1:
        return deadline_failure(o,w)
    return unavailable(o,w)

def read_capture(o:mutbuf,w:mutbuf,next:u64,target:u64,n:u64) -> u32:
    put(w,560,next)
    put(w,568,0)
    put(w,576,target)
    put(w,584,n)
    return read_piece(o,w)

def read_piece(o:mutbuf,w:mutbuf) -> u32:
    n=get(w,584)-get(w,568)
    if n>65536:
        n=65536
    put(w,592,n)
    return call(o,w,600,17,4,get(w,376),get(w,576)+get(w,568),n,get(w,568),0,0)

def reading(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase!=600:
        return 4294967293
    if result==NEG4:
        return read_piece(o,w)
    if result==0 or failed(result) or result>get(w,592):
        return unavailable(o,w)
    put(w,568,get(w,568)+result)
    if get(w,568)<get(w,584):
        return read_piece(o,w)
    return advance(w,get(w,560))
'''
SOURCE+=r'''
def prepare_result(o:mutbuf,w:mutbuf) -> u32:
    return close_streams(o,w,100)

def receipt(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==100:
        if (get(w,352)&16)!=0 and get(w,848)==0:
            return hash_begin(w,101,2,0,get(w,88),WHOLE_END,0)
        return advance(w,102)
    if phase==101:
        if equal(w,WHOLE,WHOLE_END,32)==False:
            put(w,544,13)
            put(w,352,get(w,352)|128)
        return call(o,w,104,5,4,get(w,864),STAT,0,0,0,0)
    if phase==104:
        if failed(result) or equal(w,STAT,33024,72)==False or equal(w,STAT+88,33024+88,32)==False:
            put(w,544,13)
            put(w,352,get(w,352)|128)
        return advance(w,102)
    if phase==102:
        return call(o,w,103,228,4,1,CLOCK,0,0,0,0)
    if phase==103:
        if failed(result):
            return 4294967293
        if get(w,336)!=0 and clock(w)>=get(w,336):
            put(w,544,12)
            put(w,352,get(w,352)|128)
        put(w,736,clock(w)-get(w,328))
        if get(w,544)!=0:
            return receipt_role(w,110,1)
        return receipt_role(w,110,0)
    if phase==110:
        if root_reply(w,result,choose(get(w,256)==1,1,2),2)==False:
            return 4294967293
        put(w,704,result)
        if get(w,256)==3:
            n=get(w,RO+24)
            copy(w,RO+64,FJ,n)
            put(w,760,FJ)
            put(w,768,n)
            arena=choose(n>1048576,DA,AA)
            put(w,808,arena)
            return decode(w,111,FJ,n,arena)
        return advance(w,113)
    if phase==111:
        if arena_ok(result)==False:
            return 4294967293
        put(w,776,result)
        return receipt_role(w,112,2)
    if phase==112:
        if root_reply(w,result,3,3)==False or (get(w,RO+16)!=1 and get(w,RO+16)!=3):
            return 4294967293
        put(w,704,result)
        return advance(w,113)
    if phase==113:
        status=get(w,RO+16)
        if get(w,824)==0 and get(w,336)!=0 and (status==1 or status==2):
            return call(o,w,114,228,4,1,CLOCK,0,0,0,0)
        return close_all(o,w)
    if phase==114:
        if failed(result):
            return 4294967293
        if clock(w)>=get(w,336):
            put(w,544,12)
            put(w,352,get(w,352)|128)
            put(w,736,clock(w)-get(w,328))
            put(w,824,1)
            return receipt_role(w,110,1)
        return close_all(o,w)
    return 4294967293

def root_reply(w:mutbuf,n:u64,mode:u64,maxstatus:u64) -> bool:
    if n<64 or n>ROUT or get(w,RO)!=REPLY or get(w,RO+8)!=mode or get(w,RO+16)>maxstatus or get(w,RO+24)!=n-64:
        return False
    return get(w,RO+40)==0 and get(w,RO+48)==0 and get(w,RO+56)==0

def receipt_role(w:mutbuf,next:u64,action:u64) -> u32:
    zero(w,RI,768)
    put(w,RI,RREQUEST)
    put(w,RI+8,action)
    put(w,RI+16,choose(get(w,256)==1,1,2))
    put(w,RI+24,get(w,544))
    put(w,RI+32,get(w,736))
    put(w,RI+40,get(w,264))
    put(w,RI+48,get(w,272))
    flags=get(w,352)
    if action==2:
        flags=flags&18446744073709551551
    put(w,RI+56,flags)
    copy(w,RAW1,RI+64,32)
    copy(w,RAW2,RI+96,32)
    copy(w,ORIG1,RI+128,32)
    copy(w,ORIG2,RI+160,32)
    copy(w,CORE1,RI+192,32)
    copy(w,CORE2,RI+224,32)
    copy(w,WHOLE,RI+256,32)
    copy(w,ENGINE_ID,RI+288,32)
    copy(w,INVENTORY,RI+320,32)
    put(w,RI+408,get(w,744))
    copy(w,FUNCTION,RI+512,get(w,272))
    an=0
    aa=0
    if action==0 or action==2:
        an=get(w,768)
        aa=get(w,776)
    bn=choose(get(w,256)==3,get(w,296),0)
    ba=choose(get(w,256)==3,get(w,784),0)
    dn=choose(action==1 and (get(w,352)&64)!=0,get(w,792),0)
    da=choose(action==1 and (get(w,352)&64)!=0,get(w,800),0)
    put(w,RI+352,an)
    put(w,RI+360,aa)
    put(w,RI+368,bn)
    put(w,RI+376,ba)
    put(w,RI+384,dn)
    put(w,RI+392,da)
    cursor=RI+768
    copy(w,get(w,760),cursor,an)
    cursor=cursor+an
    copy(w,get(w,808),cursor,aa)
    cursor=cursor+aa
    copy(w,BJ,cursor,bn)
    cursor=cursor+bn
    copy(w,BA,cursor,ba)
    cursor=cursor+ba
    copy(w,DJ,cursor,dn)
    cursor=cursor+dn
    copy(w,DA,cursor,da)
    cursor=cursor+da
    return role_call(w,next,3,1,RI,cursor-RI,RO,ROUT,RW,8388608)

def decode(w:mutbuf,next:u64,source:u64,n:u64,target:u64) -> u32:
    zero(w,JW,64)
    put(w,JW+48,131073)
    put(w,JW+56,128)
    put(w,JW+120,choose(target==DA,LARGE_JSON,0))
    cap=choose(target==DA,83886080,16777216)
    return role_call(w,next,4,1,source,n,target,cap,JW,8388608)

def arena_ok(n:u64) -> bool:
    return n>=64 and n<=16777216

def inferred_function(w:mutbuf) -> u64:
    if get(w,AA+8)==0 or get(w,AA+64)!=6:
        return 0
    node=get(w,AA+64+24)
    seen=0
    while node!=NONE and seen<get(w,AA+8):
        if node>=get(w,AA+8):
            return 0
        row=AA+64+72*node
        at=get(w,row+40)
        n=get(w,row+48)
        if n==8 and at<=get(w,776) and n<=get(w,776)-at and get(w,AA+at)==7957704883298780518:
            if get(w,row)!=4:
                return 0
            at=get(w,row+24)
            n=get(w,row+32)
            if n==0 or n>128 or at>get(w,776) or n>get(w,776)-at:
                return 0
            copy(w,AA+at,FUNCTION,n)
            put(w,272,n)
            return 0
        node=get(w,row+16)
        seen=seen+1
    return 0

def unavailable(o:mutbuf,w:mutbuf) -> u32:
    put(w,544,14)
    put(w,352,get(w,352)|128)
    return prepare_result(o,w)

def identity_failure(o:mutbuf,w:mutbuf) -> u32:
    put(w,544,13)
    put(w,352,get(w,352)|128)
    return prepare_result(o,w)

def deadline_failure(o:mutbuf,w:mutbuf) -> u32:
    put(w,544,12)
    put(w,352,get(w,352)|128)
    return prepare_result(o,w)

def guard(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(w,344,next)
    return call(o,w,300,228,4,1,CLOCK,0,0,0,0)

def guarded(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase!=300:
        return 4294967293
    if failed(result):
        return unavailable(o,w)
    if get(w,336)==0 or clock(w)>=get(w,336):
        return deadline_failure(o,w)
    return advance(w,get(w,344))

def close_streams(o:mutbuf,w:mutbuf,next:u64) -> u32:
    put(w,720,next)
    fd=get(w,376)
    put(w,376,NONE)
    if fd!=NONE:
        return call(o,w,500,3,0,fd,0,0,0,0,0)
    return streams(o,w,500,0)

def streams(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==500:
        fd=get(w,384)
        put(w,384,NONE)
        if fd!=NONE:
            return call(o,w,501,3,0,fd,0,0,0,0,0)
        phase=501
    if phase==501:
        return advance(w,get(w,720))
    return 4294967293

def close_all(o:mutbuf,w:mutbuf) -> u32:
    return close_streams(o,w,200)

def closing(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==200:
        fd=get(w,504)
        put(w,504,NONE)
        if fd!=NONE:
            return call(o,w,201,3,0,fd,0,0,0,0,0)
        phase=201
    if phase==201:
        fd=get(w,360)
        put(w,360,NONE)
        if fd!=NONE:
            return call(o,w,202,3,0,fd,0,0,0,0,0)
        phase=202
    if phase==202:
        fd=get(w,368)
        put(w,368,NONE)
        if fd!=NONE:
            return call(o,w,203,3,0,fd,0,0,0,0,0)
        phase=203
    if phase==203:
        fd=get(w,864)
        put(w,864,NONE)
        if fd!=NONE:
            return call(o,w,204,3,0,fd,0,0,0,0,0)
        phase=204
    if phase==204:
        copy_output(w,RO,o,0,get(w,704))
        return 0
    return 4294967293
'''
SOURCE+=r'''
def hash_begin(w:mutbuf,next:u64,kind:u64,at:u64,n:u64,target:u64,fd:u64) -> u32:
    put(w,600,kind)
    put(w,608,at)
    put(w,616,n)
    put(w,624,0)
    put(w,632,target)
    put(w,640,next)
    put(w,648,fd)
    zero(w,HW,1184)
    store(w,SHABUF,0)
    return role_call(w,401,1,1,SHABUF,1,HOUT,32,HW,1184)

def hashing(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==401:
        if result!=0:
            return hash_failure(o,w)
        return hash_piece(s,o,w)
    if phase==402:
        if result!=0:
            return hash_failure(o,w)
        return hash_update(w)
    if phase==403:
        if result==NEG4:
            return hash_read(o,w)
        if result==0 or failed(result) or result>get(w,656)-get(w,664):
            return hash_failure(o,w)
        put(w,664,get(w,664)+result)
        if get(w,664)<get(w,656):
            return hash_read(o,w)
        return hash_update(w)
    if phase==404:
        if result!=0:
            return hash_failure(o,w)
        put(w,624,get(w,624)+get(w,656))
        return hash_piece(s,o,w)
    if phase==405:
        if result!=32:
            return hash_failure(o,w)
        return advance(w,get(w,640))
    return 4294967293

def hash_piece(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if get(w,624)==get(w,616):
        store(w,SHABUF,2)
        return role_call(w,405,1,1,SHABUF,1,get(w,632),32,HW,1184)
    n=get(w,616)-get(w,624)
    if n>65536:
        n=65536
    put(w,656,n)
    at=get(w,608)+get(w,624)
    kind=get(w,600)
    if kind==0:
        copy_input(s,at,w,SHABUF+1,n)
        return hash_update(w)
    if kind==1:
        copy(w,at,SHABUF+1,n)
        return hash_update(w)
    if kind==2:
        put(w,0,402)
        put(w,24,at)
        put(w,32,n)
        put(w,40,SHABUF+1)
        return 4
    if kind==3:
        put(w,664,0)
        return hash_read(o,w)
    return hash_failure(o,w)

def hash_read(o:mutbuf,w:mutbuf) -> u32:
    return call(o,w,403,17,4,get(w,648),SHABUF+1+get(w,664),get(w,656)-get(w,664),get(w,608)+get(w,624)+get(w,664),0,0)

def hash_update(w:mutbuf) -> u32:
    store(w,SHABUF,1)
    return role_call(w,404,1,1,SHABUF,1+get(w,656),HOUT,32,HW,1184)

def hash_failure(o:mutbuf,w:mutbuf) -> u32:
    put(w,848,1)
    return unavailable(o,w)

def role_call(w:mutbuf,next:u64,which:u64,kind:u64,at:u64,n:u64,target:u64,cap:u64,scratch:u64,space:u64) -> u32:
    put(w,0,next)
    put(w,16,kind)
    put(w,24,at)
    put(w,32,n)
    put(w,40,target)
    put(w,48,cap)
    put(w,56,scratch)
    put(w,64,space)
    put(w,128,which)
    return 2

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

def advance(w:mutbuf,next:u64) -> u32:
    put(w,0,next)
    put(w,8,0)
    return 3

def clock(w:mutbuf) -> u64:
    return get(w,CLOCK)*1000000000+get(w,CLOCK+8)

def failed(value:u64) -> bool:
    return value>=18446744073709547520

def readword(s:readbuf,index:u64) -> u64:
    return word_load(s,index)

def get(w:mutbuf,index:u64) -> u64:
    return word_load(w,index)

def put(w:mutbuf,index:u64,value:u64) -> u64:
    word_store(w,index,value)
    return 0

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n and n-i>=8:
        word_store(w,at+i,0)
        i=i+8
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0

def copy(w:mutbuf,source:u64,target:u64,n:u64) -> u64:
    i=0
    while i<n and n-i>=8:
        word_store(w,target+i,word_load(w,source+i))
        i=i+8
    while i<n:
        store(w,target+i,byte(w,source+i))
        i=i+1
    return 0

def copy_input(s:readbuf,source:u64,w:mutbuf,target:u64,n:u64) -> u64:
    i=0
    while i<n and n-i>=8:
        word_store(w,target+i,word_load(s,source+i))
        i=i+8
    while i<n:
        store(w,target+i,byte(s,source+i))
        i=i+1
    return 0

def copy_output(w:mutbuf,source:u64,o:mutbuf,target:u64,n:u64) -> u64:
    i=0
    while i<n and n-i>=8:
        word_store(o,target+i,word_load(w,source+i))
        i=i+8
    while i<n:
        store(o,target+i,byte(w,source+i))
        i=i+1
    return 0

def equal(w:mutbuf,a:u64,b:u64,n:u64) -> bool:
    i=0
    while i<n:
        if byte(w,a+i)!=byte(w,b+i):
            return False
        i=i+1
    return True
'''
def source_program():
    text=SOURCE.replace('7957704883298780518',str(M('function')))
    text+='\ndef self_path(w:mutbuf) -> u64:\n'
    for i,c in enumerate(b'/proc/self/exe\0'):text+=f'    store(w, 12320+{i}, {c})\n'
    text+='    return 0\n'
    prefix=b'{"native-closure.image.bin":"' 
    assert len(prefix)==29
    text+='\ndef inventory(w:mutbuf) -> u64:\n'
    for i in range(0,len(prefix),8):
        piece=prefix[i:i+8]
        for j,c in enumerate(piece):text+=f'    store(w, INV+{i+j}, {c})\n'
    text+='''    i=0
    while i<32:
        value=byte(w,WHOLE+i)
        a=value>>4
        b=value&15
        store(w,INV+29+2*i,choose(a<10,a+48,a+87))
        store(w,INV+30+2*i,choose(b<10,b+48,b+87))
        i=i+1
    store(w,INV+93,34)
    store(w,INV+94,125)
    return 0
'''
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+name+r'\b',str(value),text)
    return text
if __name__=='__main__':
    t=document(source_program(),'public_scalar_proof')
    p=ROOT/'examples/hia_bootstrap/public_scalar_proof.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']))
