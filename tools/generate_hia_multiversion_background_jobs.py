from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={'MAGIC': 3544420087098329416, 'STATE': 3554271711283202376, 'REPLY': 3553990236306491720, 'OBJECT': 3553145811376359752, 'NODE_MAGIC': 3552864336399649096, 'PURE': 3544416840421820744, 'PURE_REPLY': 3544423394558691656, 'MAX': 18446744073709551615, 'NEGATIVE': 18446744073709547521, 'PHASE': 64, 'OP': 72, 'NEXT': 80, 'HELD': 88, 'ERROR': 96, 'CURSOR': 104, 'CAP': 112, 'OBJ': 120, 'AOBJ': 128, 'AN': 136, 'BOBJ': 144, 'BN': 152, 'REQUEST': 160, 'REQUEST_N': 168, 'NEWOBJ': 176, 'NEWOBJ_N': 184, 'NEWREF': 192, 'RESULT': 200, 'TAG0': 208, 'TAG1': 216, 'COMPARED': 224, 'N': 232, 'RANDOM_USED': 240, 'PID': 248, 'NODE': 256, 'HEADER': 352, 'RANDOM': 416, 'FEEDBACK': 448, 'TEMP': 456, 'DROP_OBJECT': 464, 'SCAN': 472, 'AFTER': 480, 'LIMIT': 488, 'FUTURE_INPUT': 3553698917449288008, 'FUTURE_REPLY': 3553980392425998664, 'PAYLOAD_INPUT': 3544431107984410952, 'PAYLOAD_REPLY': 3554001257192573256, 'OLD': 512, 'SLOTS': 576, 'FIELD': 808, 'RETIRE_INDEX': 824, 'META_VIEW': 840, 'INPUT_VIEW': 848, 'TRANSFERRED': 856, 'RESULT_KIND': 864, 'RQ': 1024, 'RP': 1152}
SOURCE=r'''
def multiversion_background_jobs(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<2048 or length(w)<256:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return admission(s,o,w,phase)
    if phase<200:
        return lookup(s,o,w,phase)
    if phase<300:
        return calculate(s,o,w,phase)
    if phase<400:
        return fields(s,o,w,phase)
    if phase<500:
        return attach(s,o,w,phase)
    if phase<600:
        return release(s,o,w,phase)
    if phase<800:
        return retirement(s,o,w,phase)
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<128 or readword(s,0)!=MAGIC:
        return 4294967293
    op=readword(s,8)
    n=readword(s,72)
    if op>8 or n!=length(s)-128 or (op!=1 and n!=0):
        return 4294967293
    at=16
    while at<128:
        used=0
        if op==0 and at>=24 and at<=48:
            used=1
        if op==1 and at==72:
            used=1
        if op==2 or op==3 or op==4 or op==6 or op==7 or op==8:
            if at>=24 and at<=40:
                used=1
        if op==4 and (at==48 or at==56):
            used=1
        if op==7 and at>=48 and at<=64:
            used=1
        if (op==7 or op==8) and at==80:
            used=1
        if used==0 and readword(s,at)!=0:
            return 4294967293
        at=at+8
    if op==7 and readword(s,48)==0 and (readword(s,56)!=0 or readword(s,64)!=0):
        return 4294967293
    zero(o,64,1984)
    put(o,OP,op)
    put(o,AFTER,20)
    return system(o,1,39,0,0,0,0,0,0,0)

def admission(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE:
            return finish(o,w,6)
        put(o,PID,pid)
        if get(o,OP)==0:
            if get(w,0)!=0 or readword(s,24)==0 or readword(s,32)==0 or readword(s,40)==0 or readword(s,48)<256:
                return finish(o,w,5)
            zero(w,0,256)
            put(w,0,STATE)
            put(w,8,pid)
            put(w,64,readword(s,24))
            put(w,72,readword(s,32))
            put(w,80,readword(s,40))
            put(w,88,readword(s,48))
            return finish(o,w,0)
        if get(w,0)!=STATE or get(w,8)!=pid or get(w,24)!=0:
            return finish(o,w,5)
        return atom(o,2,10,0,1)
    if phase==10:
        if get(o,FEEDBACK)==0:
            put(o,HELD,1)
            return again(o,get(o,AFTER))
        return system(o,11,202,1,32,128,1,0,0,0)
    if phase==11:
        result=get(o,FEEDBACK)
        if result==0 or result==MAX-3 or result==MAX-10:
            return atom(o,2,10,0,1)
        return finish(o,w,6)
    if phase==20:
        if get(w,24)!=0:
            return fail(o,5)
        op=get(o,OP)
        if op==5:
            if get(w,16)!=0 or get(w,40)!=0:
                return fail(o,5)
            put(w,24,1)
            return fail(o,0)
        if op==1:
            n=readword(s,72)
            if n>MAX-864:
                return fail(o,4)
            put(o,N,n)
            put(o,NEWOBJ_N,864+n)
            return allocate(o,200,864+n)
        put(o,SCAN,0)
        put(o,CAP,readword(s,24))
        put(o,CURSOR,get(w,16))
        return again(o,100)
    return fail(o,9)

def lookup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,CURSOR)==0:
            return fail(o,1)
        return memory(o,101,0,get(o,CURSOR),3,NODE,96)
    if phase==101:
        if get(o,NODE)!=NODE_MAGIC or get(o,NODE+64)!=get(o,PID):
            return fail(o,9)
        if get(o,CURSOR)!=get(o,CAP):
            put(o,CURSOR,get(o,NODE+24))
            return again(o,100)
        if get(o,NODE+48)!=readword(s,32) or get(o,NODE+56)!=readword(s,40):
            return fail(o,1)
        put(o,OBJ,get(o,NODE+8))
        return memory(o,102,0,get(o,OBJ),3,HEADER,64)
    if phase==102:
        n=get(o,HEADER+24)
        if get(o,HEADER)!=OBJECT or get(o,HEADER+8)!=get(o,PID) or n>MAX-864:
            return fail(o,9)
        if get(o,HEADER+16)<864+n or get(o,HEADER+32)==0:
            return fail(o,9)
        put(o,N,n)
        op=get(o,OP)
        if op==2:
            return again(o,400)
        if op==3:
            return again(o,500)
        if op==6:
            put(o,LIMIT,get(o,OBJ)+96)
            put(o,META_VIEW,get(o,OBJ)+608)
            put(o,INPUT_VIEW,get(o,OBJ)+864)
            return fail(o,0)
        if op==7 or op==8:
            if readword(s,80)>=8:
                return fail(o,3)
            put(o,FIELD,readword(s,80))
            return memory(o,300,0,get(o,OBJ)+672,3,SLOTS,192)
        if op!=4:
            return fail(o,9)
        offset=readword(s,48)
        count=readword(s,56)
        if offset>n or count>n-offset:
            return fail(o,3)
        if count>length(o)-2048:
            return fail(o,7)
        put(o,COMPARED,count)
        return memory(o,104,0,get(o,OBJ)+864+offset,3,2048,count)
    if phase==104:
        return fail(o,0)
    return fail(o,9)

def calculate(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        if get(o,FEEDBACK)==0:
            return fail(o,4)
        put(o,NEWOBJ,get(o,FEEDBACK))
        put(o,OBJ,get(o,FEEDBACK))
        zero(o,NODE,64)
        put(o,NODE,OBJECT)
        put(o,NODE+8,get(o,PID))
        put(o,NODE+16,get(o,NEWOBJ_N))
        put(o,NODE+24,get(o,N))
        return memory(o,201,3,NODE,0,get(o,OBJ),64)
    if phase==201:
        zero(o,RQ,768)
        return memory(o,202,3,RQ,0,get(o,OBJ)+96,768)
    if phase==202:
        return memory(o,203,2,128,0,get(o,OBJ)+864,get(o,N))
    if phase==203:
        return future(o,w,204,0)
    if phase==204:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=FUTURE_REPLY or get(o,RP+8)!=0:
            return fail(o,9)
        return again(o,400)
    return fail(o,9)

def fields(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        at=SLOTS+get(o,FIELD)*24
        copy_local(o,at,OLD,24)
        if get(o,OP)==8:
            if get(o,OLD)==0:
                put(o,N,0)
                return fail(o,0)
            payload_packet(o,2)
            copy_local(o,OLD,RQ+24,24)
            return payload(o,w,310)
        if readword(s,48)!=0:
            i=0
            while i<8:
                at=SLOTS+i*24
                if get(o,at)==readword(s,48) and get(o,at+8)==readword(s,56) and get(o,at+16)==readword(s,64):
                    return fail(o,3)
                i=i+1
            payload_packet(o,6)
            put(o,RQ+24,readword(s,48))
            put(o,RQ+32,readword(s,56))
            put(o,RQ+40,readword(s,64))
            return payload(o,w,301)
        return again(o,302)
    if phase==301:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=PAYLOAD_REPLY:
            return fail(o,9)
        if get(o,RP+8)!=0:
            return fail(o,1)
        return again(o,302)
    if phase==302:
        return memory(o,303,2,48,0,get(o,OBJ)+672+get(o,FIELD)*24,24)
    if phase==303:
        put(o,TRANSFERRED,choose(readword(s,48)!=0,1,0))
        if get(o,OLD)==0:
            return fail(o,0)
        put(o,HELD,0)
        return atom(o,3,304,0,0)
    if phase==304:
        return system(o,305,202,1,32,129,2147483647,0,0,0)
    if phase==305:
        payload_packet(o,3)
        copy_local(o,OLD,RQ+24,24)
        return payload(o,w,306)
    if phase==306:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=PAYLOAD_REPLY or get(o,RP+8)!=0:
            return finish(o,w,9)
        return finish(o,w,0)
    if phase==310:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=PAYLOAD_REPLY:
            return fail(o,9)
        status=get(o,RP+8)
        if status!=0:
            if status==4:
                return fail(o,4)
            return fail(o,9)
        put(o,RESULT,get(o,RP+16))
        put(o,TAG0,get(o,RP+24))
        put(o,TAG1,get(o,RP+32))
        put(o,N,get(o,RP+40))
        put(o,RESULT_KIND,1)
        return fail(o,0)
    return fail(o,9)

def attach(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==400:
        return memory(o,401,0,get(o,OBJ),3,HEADER,64)
    if phase==401:
        put(o,N,get(o,HEADER+24))
        return allocate(o,402,96)
    if phase==402:
        if get(o,FEEDBACK)==0:
            return fail(o,4)
        put(o,NEWREF,get(o,FEEDBACK))
        put(o,RANDOM_USED,0)
        return random(o,403)
    if phase==403:
        result=get(o,FEEDBACK)
        if result==MAX-3:
            return random(o,403)
        if result==0 or result>=NEGATIVE or result>16-get(o,RANDOM_USED):
            return fail(o,6)
        put(o,RANDOM_USED,get(o,RANDOM_USED)+result)
        if get(o,RANDOM_USED)!=16:
            return random(o,403)
        put(o,TAG0,get(o,RANDOM))
        put(o,TAG1,get(o,RANDOM+8))
        zero(o,NODE,96)
        put(o,NODE,NODE_MAGIC)
        put(o,NODE+8,get(o,OBJ))
        put(o,NODE+24,get(w,16))
        put(o,NODE+40,get(o,HEADER+32))
        put(o,NODE+48,get(o,TAG0))
        put(o,NODE+56,get(o,TAG1))
        put(o,NODE+64,get(o,PID))
        return memory(o,404,3,NODE,0,get(o,NEWREF),96)
    if phase==404:
        if get(w,16)!=0:
            return write_pointer(o,405,get(w,16)+16,get(o,NEWREF))
        return again(o,405)
    if phase==405:
        if get(o,HEADER+32)!=0:
            return write_pointer(o,406,get(o,HEADER+32)+32,get(o,NEWREF))
        return again(o,406)
    if phase==406:
        return write_pointer(o,407,get(o,OBJ)+32,get(o,NEWREF))
    if phase==407:
        put(w,16,get(o,NEWREF))
        put(o,RESULT,get(o,NEWREF))
        put(o,NEWREF,0)
        put(o,NEWOBJ,0)
        return fail(o,0)
    return fail(o,9)

def release(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==500:
        sole=get(o,NODE+32)==0 and get(o,NODE+40)==0
        put(o,DROP_OBJECT,choose(sole,1,0))
        if get(o,NODE+16)!=0:
            return write_pointer(o,501,get(o,NODE+16)+24,get(o,NODE+24))
        put(w,16,get(o,NODE+24))
        return again(o,501)
    if phase==501:
        if get(o,NODE+24)!=0:
            return write_pointer(o,502,get(o,NODE+24)+16,get(o,NODE+16))
        return again(o,502)
    if phase==502:
        if get(o,NODE+32)!=0:
            return write_pointer(o,503,get(o,NODE+32)+40,get(o,NODE+40))
        return write_pointer(o,503,get(o,OBJ)+32,get(o,NODE+40))
    if phase==503:
        if get(o,NODE+40)!=0:
            return write_pointer(o,504,get(o,NODE+40)+32,get(o,NODE+32))
        return again(o,504)
    if phase==504:
        return deallocate(o,505,get(o,CAP))
    if phase==505:
        if get(o,DROP_OBJECT)!=0:
            return write_pointer(o,600,get(o,OBJ)+40,0)
        return fail(o,0)
    return fail(o,9)

def retirement(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==600:
        return write_pointer(o,601,get(o,OBJ)+48,get(w,40))
    if phase==601:
        if get(w,40)!=0:
            return write_pointer(o,602,get(w,40)+40,get(o,OBJ))
        return again(o,602)
    if phase==602:
        put(w,40,get(o,OBJ))
        put(o,HELD,0)
        return atom(o,3,603,0,0)
    if phase==603:
        return system(o,604,202,1,32,129,2147483647,0,0,0)
    if phase==604:
        return future(o,w,605,10)
    if phase==605:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=FUTURE_REPLY or get(o,RP+8)!=0:
            return finish(o,w,9)
        put(o,RETIRE_INDEX,0)
        return again(o,610)
    if phase==610:
        index=get(o,RETIRE_INDEX)
        if index==8:
            put(o,AFTER,650)
            return atom(o,2,10,0,1)
        return memory(o,611,0,get(o,OBJ)+672+index*24,3,OLD,24)
    if phase==611:
        if get(o,OLD)==0:
            put(o,RETIRE_INDEX,get(o,RETIRE_INDEX)+1)
            return again(o,610)
        payload_packet(o,3)
        copy_local(o,OLD,RQ+24,24)
        return payload(o,w,612)
    if phase==612:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=PAYLOAD_REPLY or get(o,RP+8)!=0:
            return finish(o,w,9)
        put(o,RETIRE_INDEX,get(o,RETIRE_INDEX)+1)
        return again(o,610)
    if phase==650:
        return memory(o,651,0,get(o,OBJ),3,HEADER,64)
    if phase==651:
        if get(o,HEADER+40)!=0:
            return write_pointer(o,652,get(o,HEADER+40)+48,get(o,HEADER+48))
        put(w,40,get(o,HEADER+48))
        return again(o,652)
    if phase==652:
        if get(o,HEADER+48)!=0:
            return write_pointer(o,653,get(o,HEADER+48)+40,get(o,HEADER+40))
        return again(o,653)
    if phase==653:
        return deallocate(o,654,get(o,OBJ))
    if phase==654:
        return fail(o,0)
    return fail(o,9)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,REQUEST)!=0:
            pointer=get(o,REQUEST)
            put(o,REQUEST,0)
            return deallocate(o,900,pointer)
        if get(o,NEWREF)!=0:
            pointer=get(o,NEWREF)
            put(o,NEWREF,0)
            return deallocate(o,900,pointer)
        if get(o,NEWOBJ)!=0:
            pointer=get(o,NEWOBJ)
            put(o,NEWOBJ,0)
            return deallocate(o,900,pointer)
        if get(o,HELD)!=0:
            put(o,HELD,0)
            return atom(o,3,901,0,0)
        return finish(o,w,get(o,ERROR))
    if phase==901:
        return system(o,902,202,1,32,129,2147483647,0,0,0)
    if phase==902:
        return finish(o,w,get(o,ERROR))
    return finish(o,w,9)

def fail(o:mutbuf,status:u64) -> u32:
    put(o,ERROR,status)
    return again(o,900)

def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    result=get(o,RESULT)
    tag0=get(o,TAG0)
    tag1=get(o,TAG1)
    n=get(o,N)
    compared=get(o,COMPARED)
    borrowed=get(o,LIMIT)
    metadata=get(o,META_VIEW)
    input=get(o,INPUT_VIEW)
    transferred=get(o,TRANSFERRED)
    kind=get(o,RESULT_KIND)
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,result)
    put(o,24,tag0)
    put(o,32,tag1)
    put(o,40,n)
    put(o,48,compared)
    put(o,56,get(w,8))
    put(o,64,borrowed)
    put(o,72,metadata)
    put(o,80,input)
    if borrowed!=0:
        put(o,88,64)
        put(o,96,512)
    put(o,104,kind)
    put(o,112,transferred)
    return 0

def random(o:mutbuf,next:u64) -> u32:
    return system(o,next,318,3,RANDOM+get(o,RANDOM_USED),16-get(o,RANDOM_USED),0,0,0,0)

def allocate(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,n)
    return 6

def deallocate(o:mutbuf,next:u64,pointer:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,pointer)
    return 7

def write_pointer(o:mutbuf,next:u64,pointer:u64,value:u64) -> u32:
    put(o,TEMP,value)
    return memory(o,next,3,TEMP,0,pointer,8)

def memory(o:mutbuf,next:u64,source:u64,source_at:u64,target:u64,target_at:u64,n:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,source)
    put(o,8,source_at)
    put(o,16,target)
    put(o,24,target_at)
    put(o,32,n)
    return 8

def atom(o:mutbuf,action:u64,next:u64,expected:u64,value:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,32)
    put(o,8,expected)
    put(o,16,value)
    return action

def system(o:mutbuf,next:u64,number:u64,pointers:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,number)
    put(o,8,pointers)
    put(o,16,a)
    put(o,24,b)
    put(o,32,c)
    put(o,40,d)
    put(o,48,e)
    put(o,56,f)
    return 1

def again(o:mutbuf,next:u64) -> u32:
    put(o,PHASE,next)
    return 10

def zero(w:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,0)
        i=i+1
    return 0

def readword(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value

def get(w:mutbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(w,at+i)<<(i*8))
        i=i+1
    return value

def put(w:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0

def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no

def future(o:mutbuf,w:mutbuf,next:u64,op:u64) -> u32:
    zero(o,RQ,64)
    put(o,RQ,FUTURE_INPUT)
    put(o,RQ+8,op)
    zero(o,RP,512)
    return invoke(o,next,get(w,64),RQ,64,RP,512,get(o,OBJ)+96,512)
def payload_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,128)
    put(o,RQ,PAYLOAD_INPUT)
    put(o,RQ+8,op)
    zero(o,RP,512)
    return 0
def payload(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,72),RQ,128,RP,512,get(w,80),get(w,88))
def invoke(o:mutbuf,next:u64,fn:u64,src:u64,sn:u64,dest:u64,dn:u64,ctx:u64,cn:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,fn)
    put(o,8,51)
    put(o,16,src)
    put(o,24,sn)
    put(o,32,dest)
    put(o,40,dn)
    put(o,48,ctx)
    put(o,56,cn)
    return 9
def copy_local(o:mutbuf,src:u64,dest:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,dest+i,byte(o,src+i))
        i=i+1
    return 0
'''
def source_program():
    source=SOURCE
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
        source=re.sub(r'\b'+key+r'\b',str(value),source)
    return source
def main():
    result=document(source_program(),'multiversion_background_jobs')
    p=ROOT/'examples/hia_bootstrap/multiversion_background_jobs.hepta'
    p.write_text(render_assembly(result))
    print(p.name,p.stat().st_size,len(result['functions']),sum(len(f['blocks']) for f in result['functions']),flush=True)
if __name__=='__main__':main()
