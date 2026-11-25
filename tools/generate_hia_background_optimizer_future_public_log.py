"""Native caught callback diagnostics with exact Unicode content and ownership."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
ROOT=Path(__file__).resolve().parents[1]
C={"MAGIC":int.from_bytes("HIAFPL01".encode(),'little'),
"REPLY":int.from_bytes("HIAFPLR1".encode(),'little'),
"STATE":int.from_bytes("HIABFPS1".encode(),'little'),
"VREQUEST":int.from_bytes("HIABVQ01".encode(),'little'),
"VREPLY":int.from_bytes("HIABVR01".encode(),'little'),
"MAX":(1<<64)-1,
"NEGATIVE":(1<<64)-4095,
"PHASE":128,
"ERROR":136,
"FIELD":152,
"OFFSET":160,
"NBYTES":168,
"USED":176,
"WRITTEN":184,
"NEXT":192,
"HELD":208,
"VIN":216,
"CAP":224,
"KEY":248,
"STR":272,
"FEEDBACK":448,
"RQ":2048,
"VP":4096,
"RAW":12288,
"BUF":14336,
"OUT":16384}
SOURCE=r'''
def future_log(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=192 or length(o)<OUT or length(w)<256 or readword(s,0)!=MAGIC:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        at=8
        while at<192:
            if (at<24 or at>40) and readword(s,at)!=0:
                return 4294967293
            at=at+8
        zero(o,128,OUT-128)
        copy_input(s,24,o,CAP,24)
        return system(o,100,39,0,0,0,0,0,0,0)
    if phase>=100 and phase<130:
        return locks(o,w,phase)
    if phase>=1 and phase<=4:
        return field(o,w,phase)
    if phase==10:
        return system(o,11,1,12,2,BUF+get(o,WRITTEN),get(o,USED)-get(o,WRITTEN),0,0,0)
    if phase==11:
        n=get(o,FEEDBACK)
        if n==MAX-3:
            return again(o,10)
        if n==0 or n>=NEGATIVE or n>get(o,USED)-get(o,WRITTEN):
            return fail(o,107)
        put(o,WRITTEN,get(o,WRITTEN)+n)
        if get(o,WRITTEN)<get(o,USED):
            return again(o,10)
        return again(o,get(o,NEXT))
    if phase==20:
        if get(o,OFFSET)==get(o,NBYTES):
            value_packet(o,6)
            within(o,RQ+24,STR,24)
            return value(o,w,30)
        count=get(o,NBYTES)-get(o,OFFSET)
        if count>512:
            count=512
        value_packet(o,19)
        within(o,RQ+24,STR,24)
        put(o,RQ+104,get(o,OFFSET))
        put(o,RQ+112,count)
        return value(o,w,21)
    if phase==21:
        if ok(o)==False:
            return fail(o,107)
        render_chunk(o)
        if get(o,USED)==0:
            return fail(o,107)
        return write(o,20,get(o,USED))
    if phase==30:
        if ok(o)==False:
            return fail(o,107)
        zero(o,STR,24)
        if get(o,FIELD)==0:
            store(o,BUF,58)
            store(o,BUF+1,32)
            return write(o,40,2)
        store(o,BUF,10)
        return write(o,900,1)
    if phase==40:
        put(o,FIELD,1)
        return start_field(o,w)
    if phase>=900:
        return cleanup(o,w,phase)
    return fail(o,107)

def locks(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE or get(w,0)!=STATE or get(w,8)!=pid or get(w,24)!=0:
            return finish(o,107)
        return atom(o,2,110,0,1)
    if phase==110:
        if get(o,FEEDBACK)==0:
            put(o,HELD,1)
            return start_field(o,w)
        return system(o,111,202,1,44,128,1,0,0,0)
    if phase==111:
        return atom(o,2,110,0,1)
    if phase==115:
        return system(o,116,202,1,44,129,2147483647,0,0,0)
    if phase==116:
        return finish(o,get(o,ERROR))
    return fail(o,107)
def start_field(o:mutbuf,w:mutbuf) -> u32:
    value_packet(o,2)
    put(o,RQ+104,4)
    if get(o,FIELD)==0:
        put(o,RQ+96,5)
        store(o,RQ+128,99)
        store(o,RQ+129,108)
        store(o,RQ+130,97)
        store(o,RQ+131,115)
        store(o,RQ+132,115)
        put(o,VIN,133)
    else:
        put(o,RQ+96,7)
        store(o,RQ+128,109)
        store(o,RQ+129,101)
        store(o,RQ+130,115)
        store(o,RQ+131,115)
        store(o,RQ+132,97)
        store(o,RQ+133,103)
        store(o,RQ+134,101)
        put(o,VIN,135)
    return value(o,w,1)
def field(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        if ok(o)==False:
            return fail(o,choose(get(o,VP+8)==5,103,107))
        within(o,KEY,VP+24,24)
        value_packet(o,9)
        within(o,RQ+24,CAP,24)
        within(o,RQ+48,KEY,24)
        return value(o,w,2)
    if phase==2:
        if ok(o)==False:
            return fail(o,choose(get(o,VP+8)==5,103,107))
        within(o,STR,VP+24,24)
        value_packet(o,6)
        within(o,RQ+24,KEY,24)
        return value(o,w,3)
    if phase==3:
        if ok(o)==False:
            return fail(o,107)
        zero(o,KEY,24)
        value_packet(o,7)
        within(o,RQ+24,STR,24)
        return value(o,w,4)
    if phase==4:
        if ok(o)==False or get(o,VP+16)!=4:
            return fail(o,107)
        put(o,NBYTES,get(o,VP+72))
        put(o,OFFSET,0)
        if get(o,FIELD)==0:
            prefix(o)
            return write(o,20,27)
        return again(o,20)
    return fail(o,107)
def render_chunk(o:mutbuf) -> u64:
    n=get(o,VP+64)
    i=0
    used=0
    stop=False
    while i<n and stop==False:
        b=byte(o,RAW+i)
        if b==237 and n-i<3 and get(o,OFFSET)+n<get(o,NBYTES):
            stop=True
        else:
            escaped=False
            if b==237 and n-i>=3:
                second=byte(o,RAW+i+1)
                if second>=160 and second<=191:
                    code=((b&15)<<12)|((second&63)<<6)|(byte(o,RAW+i+2)&63)
                    store(o,BUF+used,92)
                    store(o,BUF+used+1,117)
                    store(o,BUF+used+2,hex_digit((code>>12)&15))
                    store(o,BUF+used+3,hex_digit((code>>8)&15))
                    store(o,BUF+used+4,hex_digit((code>>4)&15))
                    store(o,BUF+used+5,hex_digit(code&15))
                    i=i+3
                    used=used+6
                    escaped=True
            if escaped==False:
                store(o,BUF+used,b)
                used=used+1
                i=i+1
    put(o,OFFSET,get(o,OFFSET)+i)
    put(o,USED,used)
    return 0
def hex_digit(n:u64) -> u64:
    if n<10:
        return 48+n
    return 87+n
def prefix(o:mutbuf) -> u64:
    store(o,BUF+0,101)
    store(o,BUF+1,120)
    store(o,BUF+2,99)
    store(o,BUF+3,101)
    store(o,BUF+4,112)
    store(o,BUF+5,116)
    store(o,BUF+6,105)
    store(o,BUF+7,111)
    store(o,BUF+8,110)
    store(o,BUF+9,32)
    store(o,BUF+10,99)
    store(o,BUF+11,97)
    store(o,BUF+12,108)
    store(o,BUF+13,108)
    store(o,BUF+14,105)
    store(o,BUF+15,110)
    store(o,BUF+16,103)
    store(o,BUF+17,32)
    store(o,BUF+18,99)
    store(o,BUF+19,97)
    store(o,BUF+20,108)
    store(o,BUF+21,108)
    store(o,BUF+22,98)
    store(o,BUF+23,97)
    store(o,BUF+24,99)
    store(o,BUF+25,107)
    store(o,BUF+26,10)
    return 0
def write(o:mutbuf,next:u64,n:u64) -> u32:
    put(o,NEXT,next)
    put(o,USED,n)
    put(o,WRITTEN,0)
    return again(o,10)
def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,KEY)!=0:
            value_packet(o,6)
            within(o,RQ+24,KEY,24)
            return value(o,w,901)
        if get(o,STR)!=0:
            value_packet(o,6)
            within(o,RQ+24,STR,24)
            return value(o,w,902)
        if get(o,HELD)!=0:
            put(o,HELD,0)
            return atom(o,3,115,0,0)
        return finish(o,get(o,ERROR))
    if phase==901:
        if ok(o)==False:
            put(o,ERROR,107)
        zero(o,KEY,24)
        return again(o,900)
    if phase==902:
        if ok(o)==False:
            put(o,ERROR,107)
        zero(o,STR,24)
        return again(o,900)
    return finish(o,107)
def value_packet(o:mutbuf,op:u64) -> u64:
    zero(o,RQ,256)
    put(o,RQ,VREQUEST)
    put(o,RQ+8,op)
    put(o,VIN,128)
    return 0
def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,72),RQ,get(o,VIN),VP,8704,get(w,112),get(w,120))
def ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,VP)==VREPLY and get(o,VP+8)==0
def fail(o:mutbuf,status:u64) -> u32:
    put(o,ERROR,status)
    return again(o,900)
def finish(o:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,choose(status==0,0,1))
    put(o,16,status)
    return 0

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
def system(o:mutbuf,next:u64,nr:u64,mask:u64,a:u64,b:u64,c:u64,d:u64,e:u64,f:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,nr)
    put(o,8,mask)
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
def within(o:mutbuf,to:u64,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(o,at+i))
        i=i+1
    return 0
def copy_input(s:readbuf,at:u64,o:mutbuf,to:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,to+i,byte(s,at+i))
        i=i+1
    return 0
def zero(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,at+i,0)
        i=i+1
    return 0
def readword(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value
def get(o:mutbuf,at:u64) -> u64:
    return word_load(o,at)
def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
def choose(test:bool,yes:u64,no:u64) -> u64:
    if test:
        return yes
    return no
def narrow(n:u64) -> u32:
    return n

def atom(o:mutbuf,action:u64,next:u64,a:u64,b:u64) -> u32:
    put(o,PHASE,next)
    put(o,0,44)
    put(o,8,a)
    put(o,16,b)
    return narrow(action)

'''
def source_program():
 s=SOURCE
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
 return s
def program():return document(source_program(),'background_optimizer_future_public_log')
def main():
 d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_log.hepta';p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
