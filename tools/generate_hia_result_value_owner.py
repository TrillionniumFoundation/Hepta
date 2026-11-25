"""Closed native ownership of the mutable-value arena and its actual effects."""
from tools.generate_hia_result_value_common import ROOT,document,render_assembly,resolve
SOURCE=r'''
def result_value_owner(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<8192 or length(w)<256:
        return 4294967293
    phase=get(o,P_PHASE)
    if phase==0:
        return owner_begin(s,o,w)
    if phase<20:
        return admission(s,o,w,phase)
    if phase<100:
        return lifecycle(s,o,w,phase)
    if phase<200:
        return graph_driver(s,o,w,phase)
    return release(s,o,w,phase)
def owner_begin(s:readbuf,o:mutbuf,w:mutbuf) -> u64:
    if length(s)<128 or (readword(s,0)!=MAGIC and readword(s,0)!=MAGIC2) or readword(s,16)!=0 or readword(s,120)!=0 or readword(s,96)!=length(s)-128:
        return 4294967293
    op=readword(s,8)
    extended=readword(s,0)==MAGIC2
    if (extended==False and op>24) or (extended and (op<25 or op>31)):
        return 4294967293
    if op==25:
        base=readword(s,104)
        if base!=0 and base!=4 and base!=7:
            return 4294967293
        if base==0 and (readword(s,48)!=0 or readword(s,56)!=0 or readword(s,64)!=0):
            return 4294967293
    if op!=1 and op!=2 and readword(s,96)!=0:
        return 4294967293
    if op!=0 and op!=2 and op!=19 and op!=23 and op!=24 and op!=25 and op!=27 and (readword(s,104)!=0 or readword(s,112)!=0):
        return 4294967293
    if op==0 and (readword(s,112)!=0 or (readword(s,104)!=0 and readword(s,104)<640)):
        return 4294967293
    if op==24 and (readword(s,104)>1 or readword(s,112)!=0):
        return 4294967293
    if op==27 and (readword(s,104)>2 or readword(s,112)!=0):
        return 4294967293
    has_a=op>=5 and op<=19 or op==23 or op==22 or op==24 or (op>=25 and op<=30)
    has_b=op>=8 and op<=16 or op==24 or op==25
    has_c=op==10 or op==13 or op==14 or op==25
    if (has_a==False and (readword(s,24)!=0 or readword(s,32)!=0 or readword(s,40)!=0)) or (has_b==False and (readword(s,48)!=0 or readword(s,56)!=0 or readword(s,64)!=0)) or (has_c==False and (readword(s,72)!=0 or readword(s,80)!=0 or readword(s,88)!=0)):
        return 4294967293
    zero(o,0,8192)
    if drop_profile(s):
        put(o,P_DROP_KNOWN,1)
    return system(o,1,39,0,0,0,0,0,0,0)
def admission(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u64:
    if phase==1:
        pid=get(o,P_FEEDBACK)
        if pid==0 or pid>=18446744073709547521:
            return finish(s,o,11)
        put(o,P_PID,pid)
        if readword(s,8)==0:
            return atom(o,2,2,0,0,STATE)
        if get(w,0)!=STATE or get(w,8)!=pid:
            return finish(s,o,6)
        if get(w,24)!=0 and (drop_profile(s)==False or get(w,24)!=1):
            return finish(s,o,6)
        return atom(o,2,10,32,0,1)
    if phase==2:
        if get(o,P_FEEDBACK)!=0:
            return finish(s,o,6)
        put(w,8,get(o,P_PID))
        put(w,24,2)
        put(w,32,1)
        put(o,P_HELD,1)
        put(o,G_RUSED,0)
        return system(o,3,318,3,512,16,0,0,0,0)
    if phase==3:
        r=get(o,P_FEEDBACK)
        if r==MAX-3:
            return system(o,3,318,3,512+get(o,G_RUSED),16-get(o,G_RUSED),0,0,0,0)
        if r==0 or r>=18446744073709547521 or r>16-get(o,G_RUSED):
            put(w,24,1)
            return owner_fail(o,11)
        put(o,G_RUSED,get(o,G_RUSED)+r)
        if get(o,G_RUSED)!=16:
            return system(o,3,318,3,512+get(o,G_RUSED),16-get(o,G_RUSED),0,0,0,0)
        return system(o,4,9,0,0,65536,3,34,MAX,0)
    if phase==4:
        p=get(o,P_FEEDBACK)
        if p==0 or p>=18446744073709547521:
            put(w,24,1)
            return owner_fail(o,5)
        put(w,16,p)
        put(w,40,65536)
        put(w,48,readword(s,104))
        put(w,56,1)
        put(w,64,get(o,512))
        put(w,72,get(o,520))
        put(o,G_TAG0,get(o,512))
        put(o,G_INPUT,readword(s,104))
        put(o,G_PHASE,90)
        return graph_call(s,o,w,40,1)
    if phase==10:
        if get(o,P_FEEDBACK)==0:
            put(o,P_HELD,1)
            if get(w,8)!=get(o,P_PID):
                return owner_fail(o,6)
            if get(w,24)!=0 and (drop_profile(s)==False or get(w,24)!=1):
                return owner_fail(o,6)
            put(o,P_PHASE,20)
            return 10
        return system(o,11,202,4,32,128,1,0,0,0)
    if phase==11:
        r=get(o,P_FEEDBACK)
        if r==0 or r==MAX-3 or r==MAX-10:
            return atom(o,2,10,32,0,1)
        return finish(s,o,11)
    return owner_fail(o,11)
def lifecycle(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u64:
    if phase==40:
        if get(o,P_FEEDBACK)!=0:
            put(w,24,1)
            return owner_fail(o,11)
        put(w,24,0)
        return owner_fail(o,0)
    if phase==20:
        op=input_operation(s)
        if op==31:
            if get(w,24)!=1:
                return owner_fail(o,6)
            if get(w,80)==0:
                if get(w,16)==0 and get(w,40)==0:
                    return owner_fail(o,0)
                return owner_fail(o,6)
            if get(w,80)!=1 or get(w,56)!=0 or get(w,88)==0 or get(w,96)==0 or get(w,16)!=get(w,88) or get(w,40)!=get(w,96):
                return owner_fail(o,11)
            return system(o,22,11,0,get(w,88),get(w,96),0,0,0,0)
        if get(w,24)!=0:
            return owner_fail(o,6)
        if op==22 and readword(s,24)==0 and readword(s,32)==0 and readword(s,40)==0:
            if get(w,56)==0:
                return owner_fail(o,6)
            put(w,56,0)
            if readword(s,0)==MAGIC2 and readword(s,8)==30:
                put(o,P_DROP_CONSUMED,1)
            put(o,G_PHASE,91)
            return graph_call(s,o,w,21,1)
        if op==20:
            if get(w,56)>1:
                return owner_fail(o,6)
            put(o,G_PHASE,91)
            return graph_call(s,o,w,21,1)
        put(o,G_PHASE,0)
        return graph_call(s,o,w,100,graph_id(s))
    if phase==21:
        if get(o,P_FEEDBACK)!=0:
            return owner_fail(o,11)
        if get(o,G_N)!=0:
            return owner_fail(o,choose(readword(s,8)==20,6,0))
        put(w,24,1)
        put(w,56,0)
        if drop_profile(s):
            put(w,80,1)
            put(w,88,get(w,16))
            put(w,96,get(w,40))
        return system(o,22,11,0,get(w,16),get(w,40),0,0,0,0)
    if phase==22:
        if get(o,P_FEEDBACK)!=0:
            if drop_profile(s):
                put(w,104,get(o,P_FEEDBACK))
            return owner_fail(o,11)
        put(w,16,0)
        put(w,40,0)
        if drop_profile(s):
            put(w,80,0)
            put(w,88,0)
            put(w,96,0)
            put(w,104,0)
        return owner_fail(o,0)
    return owner_fail(o,11)
def graph_driver(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u64:
    if phase==100:
        action=get(o,P_FEEDBACK)
        if action==0:
            if (input_operation(s)==6 or input_operation(s)==22) and get(w,56)==0 and get(o,P_ERROR)==0:
                put(o,G_PHASE,91)
                return graph_call(s,o,w,21,1)
            return owner_fail(o,get(o,P_ERROR))
        if action==10:
            return graph_call(s,o,w,100,graph_id(s))
        if action==1:
            old=get(w,40)
            want=get(o,G_WANT)
            if want<=old or (want&(want-1))!=0:
                return owner_fail(o,11)
            put(o,P_OLD,old)
            return system(o,101,25,0,get(w,16),old,want,1,0,0)
        if action==4:
            put(o,P_PHASE,102)
            return 4
        if action==5:
            return system(o,102,318,1,get(o,G_RANDOM)+get(o,G_RUSED),get(o,G_RN)-get(o,G_RUSED),0,0,0,0)
        if drop_profile(s):
            put(o,P_DROP_KNOWN,0)
        return owner_fail(o,11)
    if phase==101:
        p=get(o,P_FEEDBACK)
        if p==0 or p>=18446744073709547521:
            put(o,G_ALLOC_FAILED,1)
            return graph_call(s,o,w,100,graph_id(s))
        put(w,16,p)
        put(w,40,get(o,G_WANT))
        put(o,704,get(o,G_PHASE))
        put(o,G_PHASE,92)
        return graph_call(s,o,w,103,1)
    if phase==102:
        put(o,G_FEEDBACK,get(o,P_FEEDBACK))
        return graph_call(s,o,w,100,graph_id(s))
    if phase==103:
        if get(o,P_FEEDBACK)!=10:
            return owner_fail(o,11)
        return graph_call(s,o,w,100,graph_id(s))
    return owner_fail(o,11)
def graph_id(s:readbuf) -> u64:
    if readword(s,8)==1:
        return 2
    if readword(s,8)==18:
        return 3
    if readword(s,8)==27 or readword(s,8)==28:
        return 8
    return 1
def graph_call(s:readbuf,o:mutbuf,w:mutbuf,next:u64,id:u64) -> u64:
    put(o,P_PHASE,next)
    return role(o,id,2,0,length(s),3,0,length(o),1,0,get(w,40))
def owner_fail(o:mutbuf,status:u64) -> u64:
    put(o,P_ERROR,status)
    put(o,P_PHASE,200)
    return 10
def release(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u64:
    if phase==200:
        if drop_profile(s) and get(o,P_HELD)!=0:
            put(o,P_DROP_PENDING,choose(get(w,80)==1,1,0))
        if get(o,P_HELD)!=0:
            put(o,P_HELD,0)
            return atom(o,3,201,32,0,0)
        return finish(s,o,get(o,P_ERROR))
    if phase==201:
        return system(o,202,202,4,32,129,2147483647,0,0,0)
    return finish(s,o,get(o,P_ERROR))
def finish(s:readbuf,o:mutbuf,status:u64) -> u64:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    if drop_profile(s):
        put(o,0,DROP_REPLY)
        put(o,80,get(o,P_DROP_PENDING))
        put(o,88,get(o,P_DROP_KNOWN))
        put(o,96,choose(get(o,P_DROP_KNOWN)!=0,get(o,P_DROP_CONSUMED),0))
        return 0
    if status==0:
        op=readword(s,8)
        if op==0 or op==6 or op==20 or op==22:
            return 0
        put(o,16,get(o,G_KIND))
        put(o,24,get(o,G_CAP))
        put(o,32,get(o,G_TAG0))
        put(o,40,get(o,G_TAG1))
        put(o,48,get(o,G_N))
        put(o,72,get(o,G_BYTES))
        if op==7 and get(o,G_KIND)==9:
            put(o,56,get(o,G_INDEX))
        if readword(s,8)==19:
            put(o,56,get(o,G_INDEX))
            put(o,64,get(o,G_PLAN))
        if readword(s,8)==23 or readword(s,8)==28:
            put(o,64,get(o,G_PLAN))
            put(o,72,get(o,G_REQUIRED))
        put(o,104,get(o,G_ID0))
        put(o,112,get(o,G_ID1))
    elif status==13:
        put(o,72,get(o,G_REQUIRED))
    return 0
def atom(o:mutbuf,action:u64,next:u64,offset:u64,expected:u64,value:u64) -> u64:
    put(o,P_PHASE,next)
    put(o,0,offset)
    put(o,8,expected)
    put(o,16,value)
    return action
def system(o:mutbuf,next:u64,number:u64,selectors:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u64:
    put(o,P_PHASE,next)
    put(o,P_ROLE,number)
    put(o,P_SELECT,selectors)
    put(o,P_ARG,a)
    put(o,P_ARG+8,b)
    put(o,P_ARG+16,c)
    put(o,P_ARG+24,d)
    put(o,P_ARG+32,e)
    put(o,P_ARG+40,f)
    return 1
'''
def source_program():return resolve('result_value_owner',SOURCE)
def program():return document(source_program(),'result_value_owner')
if __name__=='__main__':
 p=ROOT/'examples/hia_bootstrap/result_value_owner.hepta';p.write_text(render_assembly(program()));print(p.name,p.stat().st_size,flush=True)

