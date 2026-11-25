"""Compose the public primitive, call and bounded owners in one HIA image.

The visible typed envelope contains raw JSON values, not caller-supplied type
tags, node arenas, identities or proof decisions. The mechanical adapter only
moves bounded buffers, calls fixed HIA entries and executes requested syscalls.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools import generate_hia_public_scalar_proof as shared
from tools.hia_public_proof_typed_flow import SOURCE as TYPED_HELPER
ROOT=Path(__file__).resolve().parents[1]
M=shared.M
C={**shared.C,'WORK':1632<<20,'TYPED':M('HIAPPT01'),'CALL_REQUEST':M('HIAPPC01'),
   'CALL_REPLY':M('HIAMCR01'),'CALL_PROOF':M('HIAMCP02'),'CALL_RREQUEST':M('HIAJPC01'),
   'VALUES':M('HIAJPV01'),'VALUE_SELECTED':M('HIAJPS01'),
   'FAMILY':1024,'TYPED_INPUT':1032,'SOURCE_KIND':1040,'OPTIONS_N':1048,
   'OPTIONS_ARENA_N':1056,'FUNCTION_DOC':1064,'FUNCTION_NODE':1072,
   'TIMEOUT_DOC':1080,'TIMEOUT_NODE':1088,'PATCH_FLAGS':1096,'MAX_NODE':1104,
   'BFRAME_N':1112,'BOUNDED_CALLBACK':1120,'B_SOURCE':1128,'B_SIZE':1136,
   'MAX_VALID':1144,'MAX_VALUE':1152,'FN_RAW':1160,'FN_RAW_N':1168,
   'MAX_RAW':1176,'MAX_RAW_N':1184,'TIME_RAW':1192,'TIME_RAW_N':1200,
   'B_REPLY_KIND':1208,'B_SAVED_MODE':1216,'EARLY_CLAIM_ERROR':1224,
   'CHOICE':1536,'DEFAULT_VALUES':1792,
   'BOFF':608<<20,'BWORK':768<<20,'BFI':1376<<20,'BFI_CAP':256<<20,
   'TJ':608<<20,'TA':640<<20,'TBJ':720<<20,'TBA':784<<20,
   'TI':864<<20,'OPT_FUNCTION':M('function'),'OPT_TIMEOUT':M('timeout_'),'OPT_MAX1':M('max_back'),'OPT_MAX2':M('ackedges'),'ABORT_NAME':M('abort'),'NULL_JSON':M('null'),'DEFAULT_JSON':M('2000'),
   'TV_REQ':1344<<20,'TV_RES':(1344<<20)+256,'TV_WORK':1360<<20,
   'BOUNDED_INPUT':M('HIABUC01'),'BOUNDED_PREFLIGHT':M('HIABPF01'),'BOUTPUT':(608+82)<<20}
def replace_one(text,old,new):
    assert text.count(old)==1,(old,text.count(old))
    return text.replace(old,new,1)
def replace_function(text,name,new):
    start=text.index('\ndef '+name+'(')
    end=text.find('\ndef ',start+1)
    if end<0:end=len(text)
    return text[:start]+'\n'+new.strip()+'\n'+text[end:]
BEGIN=r'''
def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64:
        return 4294967293
    tag=readword(s,0)
    if tag!=REQUEST and tag!=CALL_REQUEST and tag!=TYPED:
        return 4294967293
    zero(w,256,768)
    zero(w,1024,3072)
    zero(w,WHOLE,1024)
    put(w,FAMILY,choose(tag==CALL_REQUEST,2,1))
    put(w,360,NONE)
    put(w,368,NONE)
    put(w,376,NONE)
    put(w,384,NONE)
    put(w,504,NONE)
    put(w,864,NONE)
    if tag==TYPED:
        if length(s)<128:
            return 4294967293
        family=readword(s,8)
        mode=readword(s,16)
        options=readword(s,24)
        first=readword(s,32)
        second=readword(s,40)
        claim=readword(s,48)
        if family<1 or family>3 or mode<1 or mode>3 or (family==2 and mode==3):
            return 4294967293
        if options==0 or options>33554432 or first>67108864 or second>67108864 or claim>67108864:
            return 4294967293
        if mode==1 and (second!=0 or claim!=0):
            return 4294967293
        if mode==2 and claim!=0:
            return 4294967293
        if mode==3 and claim==0:
            return 4294967293
        if length(s)!=128+options+first+second+claim:
            return 4294967293
        i=56
        while i<128:
            if readword(s,i)!=0:
                return 4294967293
            i=i+8
        put(w,TYPED_INPUT,1)
        put(w,FAMILY,family)
        put(w,OPTIONS_N,options)
        put(w,256,mode)
        put(w,280,first)
        put(w,288,second)
        put(w,296,claim)
        put(w,304,128+options)
        put(w,312,128+options+first)
        put(w,320,128+options+first+second)
        copy_input(s,128,w,TJ,options)
    else:
        mode=readword(s,8)
        name=readword(s,24)
        first=readword(s,32)
        second=readword(s,40)
        claim=readword(s,48)
        if readword(s,56)!=0 or mode<1 or mode>3 or name>128 or first>8388608 or second>8388608 or claim>262144:
            return 4294967293
        if tag==CALL_REQUEST and (mode>2 or claim!=0):
            return 4294967293
        if mode==1 and (second!=0 or claim!=0):
            return 4294967293
        if mode==2 and claim!=0:
            return 4294967293
        if mode==3 and claim==0:
            return 4294967293
        if length(s)!=64+name+first+second+claim:
            return 4294967293
        i=0
        while i<name:
            c=byte(s,64+i)
            if ((c>=65 and c<=90) or (c>=97 and c<=122) or c==95 or (i>0 and c>=48 and c<=57))==False:
                return 4294967293
            i=i+1
        put(w,256,mode)
        put(w,264,readword(s,16))
        put(w,272,name)
        put(w,280,first)
        put(w,288,second)
        put(w,296,claim)
        put(w,304,64+name)
        put(w,312,64+name+first)
        put(w,320,64+name+first+second)
        copy_input(s,64,w,FUNCTION,name)
    if get(w,88)<176 or get(w,88)>16777216:
        return 4294967293
    if image_range(w,get(w,96),get(w,104))==False or image_range(w,get(w,112),get(w,120))==False or image_range(w,get(w,152),get(w,160))==False:
        return 4294967293
    self_path(w)
    put(w,MFNAME,7309475729723812200)
    put(w,MFNAME+8,0)
    if get(w,TYPED_INPUT)==1:
        return decode(w,1000,TJ,get(w,OPTIONS_N),TA)
    return call(o,w,1,228,4,1,CLOCK,0,0,0,0)

def start_budget(o:mutbuf,w:mutbuf) -> u32:
    start=get(w,328)
    budget=get(w,264)
    if budget>=1 and budget<=maximum(w) and start<=NONE-budget*1000000-PREPARATION_ALLOWANCE_NS:
        put(w,336,start+budget*1000000)
        put(w,TRANSPORT_DEADLINE,start+budget*1000000+PREPARATION_ALLOWANCE_NS)
    else:
        put(w,544,1)
        if start<=NONE-PREPARATION_ALLOWANCE_NS:
            put(w,TRANSPORT_DEADLINE,start+PREPARATION_ALLOWANCE_NS)
    zero(w,SIGNAL,32)
    put(w,SIGNAL,get(w,136))
    put(w,SIGNAL+8,67108864)
    put(w,SIGNAL+16,get(w,144))
    put(w,SIGNAL+24,16387)
    return call(o,w,6,158,4,4097,0,0,0,0,0)

def maximum(w:mutbuf) -> u64:
    return choose(get(w,FAMILY)==2,10000,60000)

def default_budget(w:mutbuf) -> u64:
    return choose(get(w,FAMILY)==2,10000,2000)

def public_reply_magic(w:mutbuf) -> u64:
    return choose(get(w,FAMILY)==2,CALL_REPLY,REPLY)

def claim_json(w:mutbuf) -> u64:
    return choose(get(w,TYPED_INPUT)==1,TBJ,BJ)

def claim_arena(w:mutbuf) -> u64:
    return choose(get(w,TYPED_INPUT)==1,TBA,BA)

def receipt_input(w:mutbuf) -> u64:
    return choose(get(w,TYPED_INPUT)==1 and get(w,FAMILY)!=3,TI,RI)

def copy_source(s:readbuf,w:mutbuf,source:u64,target:u64,n:u64) -> u64:
    if get(w,SOURCE_KIND)==0:
        return copy_input(s,source,w,target,n)
    return copy(w,source,target,n)
'''
TYPED_FLOW=r'''
def typed_flow(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==1000:
        if result<64 or result>83886080 or get(w,TA+64)!=6:
            return 4294967293
        put(w,OPTIONS_ARENA_N,result)
        fn=option_field(w,1)
        tm=option_field(w,2)
        put(w,FUNCTION_DOC,choose(fn==NONE,NONE,0))
        put(w,FUNCTION_NODE,fn)
        put(w,TIMEOUT_DOC,choose(tm==NONE,NONE,0))
        put(w,TIMEOUT_NODE,tm)
        put(w,MAX_NODE,option_field(w,3))
        if get(w,FAMILY)==3 and get(w,256)==3:
            put(w,RO,0)
            return role_call(w,1009,20,0,get(w,320),get(w,296),RO,ROUT,BOFF+153092096,67108864)
        if get(w,FAMILY)==1 and get(w,256)==3:
            copy_input(s,get(w,320),w,TBJ,get(w,296))
            return decode(w,1001,TBJ,get(w,296),TBA)
        return advance(w,1003)
    if phase==1001:
        if result<64 or result>83886080:
            return 4294967293
        put(w,784,result)
        return value_call(w,1002,2)
    if phase==1002:
        if result!=64 or get(w,TV_RES)!=VALUE_SELECTED or get(w,TV_RES+8)>1 or get(w,TV_RES+56)!=0:
            return 4294967293
        if get(w,TV_RES+8)==0:
            put(w,832,3)
            return receipt_role(w,1008,3)
        put(w,FUNCTION_DOC,get(w,TV_RES+16))
        put(w,FUNCTION_NODE,get(w,TV_RES+24))
        return advance(w,1003)
    if phase==1009:
        if result>1:
            return 4294967293
        put(w,EARLY_CLAIM_ERROR,choose(result==0,1,0))
        return advance(w,1003)
    if phase==1003:
        if get(w,EARLY_CLAIM_ERROR)!=0:
            return value_call(w,1005,0)
        return call(o,w,1004,228,4,1,CLOCK,0,0,0,0)
    if phase==1004:
        if failed(result):
            return 4294967293
        put(w,328,clock(w))
        return value_call(w,1005,0)
    if phase==1005:
        if result<64 or result>193:
            return 4294967293
        return role_call(w,1006,6,1,TV_RES,result,TV_REQ,224,TV_WORK,262144)
    if phase==1006:
        if public_typed_choice(w,TV_REQ,result,get(w,FAMILY)==2,CHOICE)==False:
            return 4294967293
        put(w,264,get(w,CHOICE))
        put(w,272,get(w,CHOICE+8))
        put(w,PATCH_FLAGS,get(w,CHOICE+16))
        copy(w,CHOICE+64,FUNCTION,get(w,272))
        if get(w,FAMILY)==3:
            if prepare_bounded_frame(s,w)==False:
                return 4294967293
            if get(w,EARLY_CLAIM_ERROR)!=0:
                return bounded_start(w)
        return start_budget(o,w)
    if phase==1008:
        if root_reply(w,result,3,3)==False or get(w,RO+16)!=3:
            return 4294967293
        put(w,704,result)
        return close_all(o,w)
    if phase==1080:
        if result<64 or result>83886080:
            return 4294967293
        put(w,776,result)
        put(w,808,DA)
        return value_call(w,1081,1)
    if phase==1081:
        if result==4294967293 or result>ROUT-64:
            return 4294967293
        put(w,RO+24,result)
        put(w,704,64+result)
        return after_receipt(o,w,64+result)
    return 4294967293

def option_field(w:mutbuf,which:u64) -> u64:
    node=get(w,TA+64+24)
    steps=0
    while node!=NONE and steps<get(w,TA+8):
        if node>=get(w,TA+8):
            return NONE
        row=TA+64+node*72
        at=get(w,row+40)
        n=get(w,row+48)
        if option_key(w,TA+at,n,which):
            return node
        node=get(w,row+16)
        steps=steps+1
    return NONE

def option_key(w:mutbuf,at:u64,n:u64,which:u64) -> bool:
    if which==1:
        return n==8 and get(w,at)==OPT_FUNCTION
    if which==2:
        return n==10 and get(w,at)==OPT_TIMEOUT and byte(w,at+8)==109 and byte(w,at+9)==115
    return n==13 and get(w,at)==OPT_MAX1 and get(w,at+5)==OPT_MAX2

def value_call(w:mutbuf,next:u64,action:u64) -> u32:
    zero(w,TI,256)
    put(w,TI,VALUES)
    put(w,TI+8,action)
    put(w,TI+16,maximum(w))
    put(w,TI+24,default_budget(w))
    put(w,TI+32,choose(action==1,get(w,PATCH_FLAGS),0))
    put(w,TI+40,get(w,FUNCTION_DOC))
    put(w,TI+48,get(w,FUNCTION_NODE))
    put(w,TI+56,get(w,TIMEOUT_DOC))
    put(w,TI+64,get(w,TIMEOUT_NODE))
    put(w,TI+72,NONE)
    put(w,TI+80,NONE)
    put(w,TI+88,get(w,FUNCTION_NODE))
    put(w,TI+96,get(w,TIMEOUT_NODE))
    count=1
    if get(w,FAMILY)==1 and get(w,256)==3:
        count=2
    if action==1:
        put(w,TI+72,count)
        put(w,TI+80,0)
        count=count+1
    elif action==2:
        put(w,TI+72,1)
        put(w,TI+80,0)
    put(w,TI+104,count)
    put(w,TI+128,get(w,OPTIONS_N))
    put(w,TI+136,get(w,OPTIONS_ARENA_N))
    cursor=TI+256
    copy(w,TJ,cursor,get(w,OPTIONS_N))
    cursor=cursor+get(w,OPTIONS_N)
    copy(w,TA,cursor,get(w,OPTIONS_ARENA_N))
    cursor=cursor+get(w,OPTIONS_ARENA_N)
    index=1
    if get(w,FAMILY)==1 and get(w,256)==3:
        put(w,TI+144,get(w,296))
        put(w,TI+152,get(w,784))
        copy(w,TBJ,cursor,get(w,296))
        cursor=cursor+get(w,296)
        copy(w,TBA,cursor,get(w,784))
        cursor=cursor+get(w,784)
        index=2
    if action==1:
        put(w,TI+128+16*index,get(w,768))
        put(w,TI+136+16*index,get(w,776))
        copy(w,FJ,cursor,get(w,768))
        cursor=cursor+get(w,768)
        copy(w,DA,cursor,get(w,776))
        cursor=cursor+get(w,776)
    if cursor>TI+469762048:
        return 4294967293
    if action==1:
        return role_call(w,next,7,1,TI,cursor-TI,RO+64,ROUT-64,TV_WORK,262144)
    return role_call(w,next,7,1,TI,cursor-TI,TV_RES,224,TV_WORK,262144)

def after_receipt(o:mutbuf,w:mutbuf,n:u64) -> u32:
    put(w,704,n)
    if get(w,256)==3:
        amount=get(w,RO+24)
        copy(w,RO+64,FJ,amount)
        put(w,760,FJ)
        put(w,768,amount)
        arena=choose(amount>1048576,DA,AA)
        put(w,808,arena)
        return decode(w,111,FJ,amount,arena)
    return advance(w,113)
'''

BOUNDED_FLOW=r'''
def prepare_bounded_frame(s:readbuf,w:mutbuf) -> bool:
    if get(w,272)==0:
        put(w,FUNCTION,ABORT_NAME)
        put(w,272,5)
    exact_maximum(w)
    zero(w,BFI,256)
    put(w,BFI,BOUNDED_INPUT)
    put(w,BFI+8,get(w,256))
    put(w,B_SAVED_MODE,get(w,256))
    put(w,BFI+16,get(w,264))
    put(w,BFI+24,get(w,MAX_VALUE))
    put(w,BFI+32,get(w,272))
    put(w,BFI+40,get(w,280))
    put(w,BFI+48,get(w,288))
    put(w,BFI+56,get(w,296))
    exact=choose(get(w,TV_REQ+56)<3,1,0)
    put(w,BFI+64,exact+2*get(w,MAX_VALID))
    cursor=BFI+256
    copy(w,FUNCTION,cursor,get(w,272))
    cursor=cursor+get(w,272)
    copy_input(s,get(w,304),w,cursor,get(w,280))
    cursor=cursor+get(w,280)
    copy_input(s,get(w,312),w,cursor,get(w,288))
    cursor=cursor+get(w,288)
    copy_input(s,get(w,320),w,cursor,get(w,296))
    cursor=cursor+get(w,296)
    n=append_option(w,get(w,FUNCTION_NODE),cursor,0)
    put(w,BFI+72,n)
    cursor=cursor+n
    n=append_option(w,get(w,MAX_NODE),cursor,0)
    put(w,BFI+80,n)
    cursor=cursor+n
    n=append_option(w,get(w,TIMEOUT_NODE),cursor,1)
    put(w,BFI+88,n)
    cursor=cursor+n
    if cursor>BFI+BFI_CAP:
        return False
    put(w,BFRAME_N,cursor-BFI)
    return True

def append_option(w:mutbuf,node:u64,target:u64,which:u64) -> u64:
    if node==NONE:
        if which==0:
            put(w,target,NULL_JSON)
            return 4
        put(w,target,DEFAULT_JSON)
        return 4
    row=TA+64+node*72
    slot=choose(get(w,row)>=4,56,24)
    at=get(w,row+slot)
    n=get(w,row+slot+8)
    copy(w,TJ+at,target,n)
    return n

def exact_maximum(w:mutbuf) -> u64:
    put(w,MAX_VALID,0)
    put(w,MAX_VALUE,33)
    node=get(w,MAX_NODE)
    if node==NONE or get(w,TA+64+node*72)!=3:
        return 0
    row=TA+64+node*72
    at=TJ+get(w,row+24)
    n=get(w,row+32)
    i=0
    negative=False
    if n!=0 and byte(w,at)==45:
        negative=True
        i=1
    value=0
    while i<n:
        c=byte(w,at+i)
        if c<48 or c>57:
            return 0
        if value<=32:
            value=value*10+c-48
        i=i+1
    if negative and value!=0:
        value=33
    if value>32:
        value=33
    put(w,MAX_VALID,1)
    put(w,MAX_VALUE,value)
    return 0

def bounded_preflight(w:mutbuf) -> u32:
    copy(w,WHOLE,BFI+96,32)
    copy(w,INVENTORY,BFI+160,32)
    put(w,RO,2)
    return role_call(w,1310,20,1,BFI,get(w,BFRAME_N),RO,ROUT,BOFF+153092096,67108864)

def bounded_start(w:mutbuf) -> u32:
    copy(w,WHOLE,BFI+96,32)
    copy(w,ENGINE_ID,BFI+128,32)
    copy(w,INVENTORY,BFI+160,32)
    zero(w,BOFF,512)
    zero(w,BOFF+65536,2048)
    return bounded_call(w)

def bounded_call(w:mutbuf) -> u32:
    return role_call(w,1201,11,1,BFI,get(w,BFRAME_N),RO,ROUT,BOFF,BWORK)

def bounded_flow(s:readbuf,o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==1201:
        if get(w,EARLY_CLAIM_ERROR)!=0 and result!=0:
            if result!=2 or get(w,BOFF+128)!=20:
                return 4294967293
        if result==0:
            n=get(w,BOFF+136)
            if n==0 or n>ROUT:
                return 4294967293
            copy(w,BOUTPUT,RO,n)
            put(w,704,n)
            if get(w,EARLY_CLAIM_ERROR)!=0:
                return close_all(o,w)
            return hash_begin(w,1300,2,0,get(w,88),WHOLE_END,0)
        if result==1:
            return bounded_syscall(o,w)
        if result==2:
            return bounded_role(w)
        if result==3:
            return bounded_normalize(o,w)
        if result==4:
            return bounded_translation(o,w)
        return 4294967293
    if phase==1202:
        put(w,BOFF+8,result)
        return bounded_call(w)
    if phase>=1250 and phase<1280:
        return bounded_normalizer(o,w,phase,result)
    if phase==1310:
        if result!=32 or get(w,RO)!=BOUNDED_PREFLIGHT or get(w,RO+8)>3 or get(w,RO+16)!=0 or get(w,RO+24)!=0:
            return 4294967293
        if get(w,RO+8)!=0:
            return bounded_start(w)
        put(w,480,0)
        return guard(o,w,15)
    if phase==1300:
        if equal(w,WHOLE,WHOLE_END,32)==False:
            put(w,704,0)
            return close_all(o,w)
        return call(o,w,1301,5,4,get(w,864),STAT,0,0,0,0)
    if phase==1301:
        if failed(result) or equal(w,STAT,33024,72)==False or equal(w,STAT+88,33024+88,32)==False:
            put(w,704,0)
        return close_all(o,w)
    if phase==1290:
        if failed(result):
            return unavailable(o,w)
        start=clock(w)
        budget=get(w,264)
        if budget<1 or budget>60000 or start>NONE-budget*1000000-PREPARATION_ALLOWANCE_NS:
            return unavailable(o,w)
        put(w,328,start)
        put(w,336,start+budget*1000000)
        put(w,TRANSPORT_DEADLINE,start+budget*1000000+PREPARATION_ALLOWANCE_NS)
        return hash_begin(w,13,1,get(w,304),get(w,280),RAW1,0)
    return 4294967293

def bounded_syscall(o:mutbuf,w:mutbuf) -> u32:
    mask=get(w,RO+8)
    if mask>=4096:
        return 4294967293
    put(o,0,get(w,RO))
    newmask=0
    index=0
    while index<6:
        kind=mask&3
        value=get(w,RO+16+8*index)
        if kind==1:
            if value>=BWORK:
                return 4294967293
            value=value+BOFF
        elif kind==2:
            if value>=get(w,BFRAME_N):
                return 4294967293
            value=value+BFI
            kind=1
        elif kind==3:
            return 4294967293
        put(o,16+8*index,value)
        newmask=newmask|(kind<<(2*index))
        mask=mask>>2
        index=index+1
    put(o,8,newmask)
    put(w,0,1202)
    return 1

def bounded_source(w:mutbuf) -> bool:
    kind=get(w,BOFF+16)
    at=get(w,BOFF+24)
    n=get(w,BOFF+32)
    if kind==0:
        if at>get(w,BFRAME_N) or n>get(w,BFRAME_N)-at:
            return False
        at=at+BFI
    elif kind==1:
        if at>BWORK or n>BWORK-at:
            return False
        at=at+BOFF
    else:
        return False
    put(w,B_SOURCE,at)
    put(w,B_SIZE,n)
    return True

def bounded_role(w:mutbuf) -> u32:
    which=get(w,BOFF+128)
    if ((which>=8 and which<=10) or (which>=15 and which<=20))==False:
        return 4294967293
    if bounded_source(w)==False:
        return 4294967293
    target=get(w,BOFF+40)
    cap=get(w,BOFF+48)
    scratch=get(w,BOFF+56)
    space=get(w,BOFF+64)
    if target>BWORK or cap>BWORK-target or scratch>BWORK or space>BWORK-scratch:
        return 4294967293
    return role_call(w,1202,which,1,get(w,B_SOURCE),get(w,B_SIZE),BOFF+target,cap,BOFF+scratch,space)

def bounded_normalize(o:mutbuf,w:mutbuf) -> u32:
    if bounded_source(w)==False:
        return 4294967293
    if get(w,B_SIZE)>8388608:
        n=oversize_diagnostic(w,BOUTPUT)
        put(w,BOFF+8,n)
        put(w,BOFF+144,1)
        return bounded_call(w)
    put(w,BOUNDED_CALLBACK,1)
    return call(o,w,1250,228,4,1,CLOCK,0,0,0,0)

def bounded_normalizer(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==1250:
        if failed(result):
            return bounded_norm_fail(o,w)
        now=clock(w)
        if now>NONE-PREPARATION_ALLOWANCE_NS-60000000000:
            return bounded_norm_fail(o,w)
        put(w,TRANSPORT_DEADLINE,now+PREPARATION_ALLOWANCE_NS+60000000000)
        copy(w,get(w,B_SOURCE),PIN+128,get(w,B_SIZE))
        return process_ready(w,1251,1,get(w,360),get(w,B_SIZE),16777280)
    if phase==1251:
        if process_reply(w,result)==False:
            return bounded_norm_fail(o,w)
        if get(w,464)==512 or get(w,464)==768:
            return close_streams(o,w,1260)
        if get(w,464)!=0 or get(w,456)!=0 or get(w,448)<64 or get(w,448)>16777280:
            return bounded_norm_fail(o,w)
        put(w,B_REPLY_KIND,0)
        return read_capture(o,w,1252,BOUTPUT,get(w,448))
    if phase==1252:
        if get(w,BOUTPUT)!=NORM or get(w,BOUTPUT+8)!=0 or get(w,BOUTPUT+16)!=0 or get(w,BOUTPUT+24)>4 or get(w,BOUTPUT+48)!=0 or get(w,BOUTPUT+56)!=0:
            return bounded_norm_fail(o,w)
        a=get(w,BOUTPUT+32)
        b=get(w,BOUTPUT+40)
        if a==0 or a>8388608 or b==0 or b>8388608 or get(w,448)!=64+a+b:
            return bounded_norm_fail(o,w)
        return close_streams(o,w,1253)
    if phase==1253:
        put(w,BOFF+8,get(w,448))
        put(w,BOFF+144,get(w,B_REPLY_KIND))
        put(w,BOUNDED_CALLBACK,0)
        return bounded_call(w)
    if phase==1259:
        put(w,BOFF+8,0)
        put(w,BOFF+144,2)
        put(w,BOUNDED_CALLBACK,0)
        return bounded_call(w)
    if phase==1260:
        copy(w,get(w,B_SOURCE),PIN+128,get(w,B_SIZE))
        return process_ready(w,1261,4,get(w,360),get(w,B_SIZE),67108864)
    if phase==1261:
        if process_reply(w,result)==False:
            return bounded_norm_fail(o,w)
        if get(w,464)!=512 or get(w,448)==0 or get(w,448)>67108864 or get(w,456)!=0:
            return bounded_norm_fail(o,w)
        put(w,B_REPLY_KIND,1)
        return read_capture(o,w,1262,BOUTPUT,get(w,448))
    if phase==1262:
        return close_streams(o,w,1253)
    return 4294967293

def bounded_norm_fail(o:mutbuf,w:mutbuf) -> u32:
    return close_streams(o,w,1259)

def bounded_translation(o:mutbuf,w:mutbuf) -> u32:
    first=get(w,BOFF+24)
    n=get(w,BOFF+32)
    second=get(w,BOFF+40)
    m=get(w,BOFF+48)
    fn=get(w,BOFF+56)
    name=get(w,BOFF+64)
    budget=get(w,BOFF+144)
    if first>BWORK or n>BWORK-first or n>8388608 or second>BWORK or m>BWORK-second or m>8388608:
        return 4294967293
    if fn>BWORK or name>BWORK-fn or name==0 or name>128 or budget==0 or budget>60000:
        return 4294967293
    zero(w,256,104)
    zero(w,392,112)
    zero(w,512,352)
    zero(w,RAW1,192)
    put(w,256,2)
    put(w,264,budget)
    put(w,272,name)
    put(w,280,n)
    put(w,288,m)
    put(w,304,BOFF+first)
    put(w,312,BOFF+second)
    put(w,352,48)
    put(w,BOUNDED_CALLBACK,2)
    put(w,SOURCE_KIND,1)
    copy(w,BOFF+fn,FUNCTION,name)
    return call(o,w,1290,228,4,1,CLOCK,0,0,0,0)

def bounded_translation_done(w:mutbuf) -> u32:
    n=get(w,704)
    if n<64 or n>ROUT or get(w,RO)!=REPLY:
        return 4294967293
    copy(w,RO,BOUTPUT,n)
    put(w,BOFF+8,n)
    put(w,BOFF+144,0)
    put(w,BOUNDED_CALLBACK,0)
    put(w,SOURCE_KIND,0)
    put(w,256,get(w,B_SAVED_MODE))
    return bounded_call(w)
'''

def source_program():
    source=shared.SOURCE
    source=replace_one(source,'def public_proof(', 'def public_proof_facade(')
    source=replace_function(source,'begin',BEGIN)
    old='''        start=clock(w)
        put(w,328,start)
        budget=get(w,264)
        if budget>=1 and budget<=60000 and start<=NONE-budget*1000000-PREPARATION_ALLOWANCE_NS:
            put(w,336,start+budget*1000000)
            put(w,TRANSPORT_DEADLINE,start+budget*1000000+PREPARATION_ALLOWANCE_NS)
        else:
            put(w,544,1)
        zero(w,SIGNAL,32)
        put(w,SIGNAL,get(w,136))
        put(w,SIGNAL+8,67108864)
        put(w,SIGNAL+16,get(w,144))
        put(w,SIGNAL+24,16387)
        return call(o,w,6,158,4,4097,0,0,0,0,0)'''
    source=replace_one(source,old,'''        put(w,328,clock(w))
        if get(w,TYPED_INPUT)==1:
            return decode(w,1000,TJ,get(w,OPTIONS_N),TA)
        return start_budget(o,w)''')
    source=replace_one(source,'    phase=get(w,0)\n    result=get(w,8)','''    phase=get(w,0)
    result=get(w,8)
    if get(w,CANCEL)!=0 and ((phase>=200 and phase<210) or (phase>=500 and phase<510))==False:
        return close_all(o,w)
    if phase>=1000 and phase<1100:
        return typed_flow(s,o,w,phase,result)
    if phase>=1200 and phase<1320:
        return bounded_flow(s,o,w,phase,result)''')
    source=replace_one(source,'        if get(w,256)==3:\n            copy_input(s,get(w,320),w,BJ,get(w,296))',
        '        if get(w,256)==3 and get(w,TYPED_INPUT)==0:\n            copy_input(s,get(w,320),w,BJ,get(w,296))')
    source=replace_one(source,'    if phase==11:\n        if get(w,544)==1:', '''    if phase==11:
        if get(w,FAMILY)==3:
            return bounded_preflight(w)
        if get(w,544)==1:''')
    source=replace_one(source,'return hash_begin(w,14,0,get(w,312),get(w,288),RAW2,0)',
        'return hash_begin(w,14,get(w,SOURCE_KIND),get(w,312),get(w,288),RAW2,0)')
    source=replace_one(source,'        put(w,480,0)\n        return guard(o,w,15)','''        if get(w,BOUNDED_CALLBACK)==2:
            put(w,392,0)
            return guard(o,w,50)
        put(w,480,0)
        return guard(o,w,15)''')
    source=replace_one(source,'put(w,488,get(w,112))','put(w,488,choose(get(w,FAMILY)==2,get(w,152),get(w,112)))')
    source=replace_one(source,'put(w,496,get(w,120))','put(w,496,choose(get(w,FAMILY)==2,get(w,160),get(w,120)))')
    source=replace_one(source,'        put(w,392,0)\n        return guard(o,w,50)','''        put(w,392,0)
        if get(w,FAMILY)==3:
            return bounded_start(w)
        return guard(o,w,50)''')
    source=replace_one(source,'    if phase==50:\n        return process_raw(s,w,51,1)',"""    if phase==50:
        if get(w,280+get(w,392)*8)>8388608:
            amount=oversize_diagnostic(w,DJ)
            put(w,792,amount)
            return decode(w,75,DJ,amount,DA)
        return process_raw(s,w,51,1)""")
    source=replace_one(source,'    if phase==80:\n        zero(w,PIN,192)','''    if phase==80:
        if get(w,FAMILY)==2 and (get(w,N1+24)!=0 or (get(w,256)==2 and get(w,N2+24)!=0)):
            put(w,544,19)
            return prepare_result(o,w)
        zero(w,PIN,192)''')
    source=replace_one(source,'put(w,PIN+128,PROOF)','put(w,PIN+128,choose(get(w,FAMILY)==2,CALL_PROOF,PROOF))')
    source=source.replace('get(w,AJ)!=REPLY','get(w,AJ)!=public_reply_magic(w)')
    source=source.replace('get(w,RO)!=REPLY','get(w,RO)!=public_reply_magic(w)')
    source=source.replace('get(w,RO)==REPLY','get(w,RO)==public_reply_magic(w)')
    source=replace_one(source,'    copy_input(s,at,w,PIN+128,n)','    copy_source(s,w,at,PIN+128,n)')
    old='''        put(w,704,result)
        if get(w,256)==3:
            n=get(w,RO+24)
            copy(w,RO+64,FJ,n)
            put(w,760,FJ)
            put(w,768,n)
            arena=choose(n>1048576,DA,AA)
            put(w,808,arena)
            return decode(w,111,FJ,n,arena)
        return advance(w,113)'''
    source=replace_one(source,old,'''        put(w,704,result)
        if get(w,TYPED_INPUT)==1 and get(w,FAMILY)!=3 and get(w,PATCH_FLAGS)!=0 and get(w,RO+16)==0:
            n=get(w,RO+24)
            copy(w,RO+64,FJ,n)
            put(w,760,FJ)
            put(w,768,n)
            return decode(w,1080,FJ,n,DA)
        return after_receipt(o,w,result)''')
    source=replace_one(source,'    if action==0 or action==2:\n        an=get(w,768)',
        '    if action==0 or action==2 or (action==1 and get(w,FAMILY)==2 and get(w,776)>=64 and get(w,768)>0):\n        an=get(w,768)')
    source=replace_one(source,'put(w,RI,RREQUEST)','put(w,RI,choose(get(w,FAMILY)==2,CALL_RREQUEST,RREQUEST))')
    source=replace_one(source,'return role_call(w,next,3,1,RI,cursor-RI,RO,ROUT,RW,8388608)',
        'return role_call(w,next,choose(get(w,FAMILY)==2,5,3),1,RI,cursor-RI,RO,ROUT,RW,8388608)')
    source=replace_one(source,'    put(w,RI+392,da)\n    cursor=RI+768','''    put(w,RI+392,da)
    if get(w,FAMILY)!=2:
        if (action==2 or action==3) and (bn>1048576 or ba>16777216):
            flags=flags|512
        if action==2 and get(w,744)==0 and (an>1048576 or aa>16777216):
            flags=flags|256
        put(w,RI+56,flags)
    cursor=RI+768''')
    # Relocated claimed JSON and large concatenation are only used while the
    # bounded view is idle. Bounded translation callbacks keep the 608 MiB view.
    start=source.index('\ndef receipt_role(');end=source.index('\ndef decode(',start)
    part=source[start:end]
    part=part.replace('    zero(w,RI,768)','    ri=receipt_input(w)\n    zero(w,RI,768)')
    part=re.sub(r'\bRI\b','ri',part)
    part=re.sub(r'\bBJ\b','claim_json(w)',part)
    part=re.sub(r'\bBA\b','claim_arena(w)',part)
    source=source[:start]+part+source[end:]
    source=replace_function(source,'decode',r'''
def decode(w:mutbuf,next:u64,source:u64,n:u64,target:u64) -> u32:
    wide=target==DA or target==TA or target==TBA
    zero(w,JW,64)
    put(w,JW+48,131073)
    put(w,JW+56,128)
    put(w,JW+120,choose(wide,LARGE_JSON,0))
    cap=choose(wide,83886080,16777216)
    return role_call(w,next,4,1,source,n,target,cap,JW,8388608)
''')
    source=replace_one(source,'return n>=64 and n<=16777216','return n>=64 and n<=83886080')
    source=replace_one(source,'def unavailable(o:mutbuf,w:mutbuf) -> u32:\n    put(w,544,14)',
        'def unavailable(o:mutbuf,w:mutbuf) -> u32:\n    if get(w,BOUNDED_CALLBACK)==1:\n        return bounded_norm_fail(o,w)\n    put(w,544,14)')
    source=replace_one(source,'def close_all(o:mutbuf,w:mutbuf) -> u32:\n    return close_streams(o,w,200)',
        '''def close_all(o:mutbuf,w:mutbuf) -> u32:
    if get(w,BOUNDED_CALLBACK)==2 and get(w,CANCEL)==0:
        return bounded_translation_done(w)
    return close_streams(o,w,200)''')
    source+=TYPED_FLOW+BOUNDED_FLOW+TYPED_HELPER
    # _decode's first immutable-bytes check precedes UTF-8/JSON admission.
    # This is that existing language refusal, not a larger admitted-Core limit.
    diagnostic=b'{"diagnostics":[{"code":"E_DRIVER","message":"E_HIA_LIMIT: program exceeds byte budget"}]}'
    source+='\ndef oversize_diagnostic(w:mutbuf,target:u64) -> u64:\n'
    for at in range(0,len(diagnostic),8):
        piece=diagnostic[at:at+8]
        if len(piece)==8:source+=f'    put(w,target+{at},{int.from_bytes(piece,"little")})\n'
        else:
            for j,c in enumerate(piece):source+=f'    store(w,target+{at+j},{c})\n'
    source+=f'    return {len(diagnostic)}\n'
    source=source.replace('7957704883298780518',str(M('function')))
    resolved=shared.source_program()
    source+=resolved[resolved.index('\ndef self_path('):]
    for name,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+name+r'\b',str(value),source)
    return source
def program():
    return document(source_program(),'public_proof_facade')
if __name__=='__main__':
    tree=program()
    target=ROOT/'examples/hia_bootstrap/public_proof_facade.hepta'
    target.write_text(render_assembly(tree))
    print(target.name,target.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']),flush=True)
