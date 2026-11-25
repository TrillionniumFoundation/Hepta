"""Own the unbounded accounting counters and 64 detached receipt references."""
from pathlib import Path
import re,ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_multiversion_background_jobs import SOURCE as JOBS_SOURCE
ROOT=Path(__file__).resolve().parents[1]
C={
 'MAGIC2':int.from_bytes(b'HIABLG02','little'),'PROFILE':80,'ORDERCOUNT':168,'ORDER':176,'SAVED_ORDERCOUNT':864,'SAVED_ORDER':872,
 'MAGIC':int.from_bytes(b'HIABLG01','little'),'STATE':int.from_bytes(b'HIABLGS1','little'),'REPLY':int.from_bytes(b'HIABLGR1','little'),
 'VALUES_INPUT':int.from_bytes(b'HIAMVU01','little'),'VALUES_REPLY':int.from_bytes(b'HIAMVUR1','little'),
 'PAYLOAD_INPUT':int.from_bytes(b'HIABPY01','little'),'PAYLOAD_REPLY':int.from_bytes(b'HIABPYR1','little'),
 'JOBS_INPUT':int.from_bytes(b'HIABJO01','little'),'JOBS_REPLY':int.from_bytes(b'HIABJOR1','little'),
 'MAX':(1<<64)-1,'NEGATIVE':(1<<64)-4095,
 'PHASE':64,'OP':72,'HELD':88,'ERROR':96,'PID':248,'FEEDBACK':448,'TEMP':456,
 'GUARD':512,'META':544,'MARK':552,'TRANSFER':560,'ALREADY':568,
 'NEW':576,'OLD':656,'OLD_RECEIPT':752,'INDEX':784,'ITER':792,'NROWS':800,
 'SAVED':808,'SNAP_OK':824,'CLEAN':832,'VALUE_N':840,'SAVED_COUNT':848,'SAVED_MASK':856,
 'RQ':1024,'RP':1280,'ROWS':4096,
 'VF':64,'VC':72,'VN':80,'PF':88,'PC':96,'PN':104,'JF':112,'JC':120,'JN':128,
 'RCNT':144,'RHEAD':152,'MASK':160,'COUNTERS':256,'RING':512,
}
SOURCE=r'''
def multiversion_background_ledger(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<8192 or length(w)<4096:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<100:
        return admission(s,o,w,phase)
    if phase<200:
        return settle(s,o,w,phase)
    if phase<300:
        return snapshot(s,o,w,phase)
    if phase<400:
        return destroy(s,o,w,phase)
    if phase<900:
        return 4294967293
    return cleanup(s,o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or (readword(s,0)!=MAGIC and readword(s,0)!=MAGIC2):
        return 4294967293
    op=readword(s,8)
    if op>4 or (readword(s,0)==MAGIC2 and op!=2):
        return 4294967293
    at=16
    while at<128:
        used=0
        if op==0 and at>=24 and at<=88:
            used=1
        if (op==1 or op==4) and at>=24 and at<=40:
            used=1
        if op==1 and at>=48 and at<=96:
            used=1
        if used==0 and readword(s,at)!=0:
            return 4294967293
        at=at+8
    if op==1 and readword(s,96)>=6:
        return 4294967293
    zero(o,64,8128)
    put(o,PROFILE,choose(readword(s,0)==MAGIC2,1,0))
    put(o,OP,op)
    return system(o,1,39,0,0,0,0,0,0,0)

def admission(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=NEGATIVE:
            return finish(o,w,6)
        put(o,PID,pid)
        if get(o,OP)==0:
            if get(w,0)!=0:
                return finish(o,w,5)
            if readword(s,24)==0 or readword(s,48)==0 or readword(s,72)==0:
                return finish(o,w,5)
            if readword(s,32)==0 or readword(s,56)==0 or readword(s,80)==0:
                return finish(o,w,5)
            if readword(s,40)<256 or readword(s,64)<256 or readword(s,88)<256:
                return finish(o,w,5)
            zero(w,0,4096)
            put(w,0,STATE)
            put(w,8,pid)
            put(w,VF,readword(s,24))
            put(w,VC,readword(s,32))
            put(w,VN,readword(s,40))
            put(w,PF,readword(s,48))
            put(w,PC,readword(s,56))
            put(w,PN,readword(s,64))
            put(w,JF,readword(s,72))
            put(w,JC,readword(s,80))
            put(w,JN,readword(s,88))
            request(o,VALUES_INPUT,1)
            put(o,RQ+72,1)
            store(o,RQ+128,48)
            return values(o,w,30,129)
        if get(w,0)!=STATE or get(w,8)!=pid or get(w,24)!=0:
            return finish(o,w,5)
        return atom(o,2,10,0,1)
    if phase==10:
        if get(o,FEEDBACK)==0:
            put(o,HELD,1)
            return again(o,20)
        return system(o,11,202,1,32,128,1,0,0,0)
    if phase==11:
        result=get(o,FEEDBACK)
        if result==0 or result==MAX-3 or result==MAX-10:
            return atom(o,2,10,0,1)
        return finish(o,w,6)
    if phase==20:
        if get(w,24)!=0:
            return fail(o,w,5)
        op=get(o,OP)
        if op==1 or op==4:
            request(o,JOBS_INPUT,2)
            copy_source(s,o,24,RQ+24,24)
            return jobs(o,w,100)
        if op==2:
            put(o,ITER,0)
            return again(o,200)
        if op==3:
            put(w,24,1)
            put(o,ITER,0)
            return again(o,300)
        return fail(o,w,9)
    if phase==30:
        if valid(o,VALUES_REPLY)==0:
            return fail(o,w,9)
        status=get(o,RP+8)
        if status!=0:
            return fail(o,w,choose(status==4,4,9))
        to_work(o,w,RP+16,COUNTERS,24)
        put(o,ITER,1)
        return again(o,31)
    if phase==31:
        index=get(o,ITER)
        if index==8:
            return finish(o,w,0)
        request(o,VALUES_INPUT,2)
        from_work(w,o,COUNTERS,RQ+24,24)
        return values(o,w,32,128)
    if phase==32:
        if valid(o,VALUES_REPLY)==0:
            return fail(o,w,9)
        status=get(o,RP+8)
        if status!=0:
            return fail(o,w,choose(status==4,4,9))
        to_work(o,w,RP+16,COUNTERS+get(o,ITER)*24,24)
        put(o,ITER,get(o,ITER)+1)
        return again(o,31)
    return fail(o,w,9)

def settle(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if valid(o,JOBS_REPLY)==0:
            return fail(o,w,9)
        status=get(o,RP+8)
        if status!=0:
            return fail(o,w,choose(status==4,4,1))
        copy_local(o,RP+16,GUARD,24)
        request(o,JOBS_INPUT,6)
        copy_local(o,GUARD,RQ+24,24)
        return jobs(o,w,101)
    if phase==101:
        if valid(o,JOBS_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+88)!=64:
            return fail(o,w,9)
        put(o,META,get(o,RP+72))
        return memory(o,102,0,get(o,META)+32,3,MARK,8)
    if phase==102:
        mark=get(o,MARK)
        if mark>1:
            return fail(o,w,9)
        put(o,ALREADY,mark)
        if mark==1 or get(o,OP)==4:
            return fail(o,w,0)
        index=0
        while index<get(w,RCNT):
            at=RING+((get(w,RHEAD)+index)%64)*24
            if get(w,at)==readword(s,48) and get(w,at+8)==readword(s,56) and get(w,at+16)==readword(s,64):
                return fail(o,w,3)
            index=index+1
        request(o,PAYLOAD_INPUT,6)
        copy_source(s,o,48,RQ+24,24)
        return payload(o,w,110)
    if phase==110:
        if valid(o,PAYLOAD_REPLY)==0:
            return fail(o,w,9)
        if get(o,RP+8)!=0:
            return fail(o,w,1)
        request(o,VALUES_INPUT,4)
        from_work(w,o,COUNTERS,RQ+24,24)
        return values(o,w,120,128)
    if phase==120:
        if valid(o,VALUES_REPLY)==0:
            return fail(o,w,9)
        status=get(o,RP+8)
        if status!=0:
            return fail(o,w,choose(status==4,4,9))
        copy_local(o,RP+16,NEW,24)
        request(o,VALUES_INPUT,5)
        from_work(w,o,COUNTERS+24,RQ+24,24)
        copy_source(s,o,72,RQ+48,24)
        return values(o,w,121,128)
    if phase==121:
        if valid(o,VALUES_REPLY)==0:
            return fail(o,w,9)
        status=get(o,RP+8)
        if status!=0:
            return fail(o,w,choose(status==4,4,1))
        copy_local(o,RP+16,NEW+24,24)
        put(o,INDEX,readword(s,96))
        request(o,VALUES_INPUT,4)
        from_work(w,o,COUNTERS+48+get(o,INDEX)*24,RQ+24,24)
        return values(o,w,122,128)
    if phase==122:
        if valid(o,VALUES_REPLY)==0:
            return fail(o,w,9)
        status=get(o,RP+8)
        if status!=0:
            return fail(o,w,choose(status==4,4,9))
        copy_local(o,RP+16,NEW+48,24)
        if (get(w,MASK)&(1<<get(o,INDEX)))==0 and get(w,ORDERCOUNT)>=6:
            return fail(o,w,9)
        from_work(w,o,COUNTERS,OLD,48)
        from_work(w,o,COUNTERS+48+get(o,INDEX)*24,OLD+48,24)
        to_work(o,w,NEW,COUNTERS,48)
        to_work(o,w,NEW+48,COUNTERS+48+get(o,INDEX)*24,24)
        zero(o,NEW,72)
        count=get(w,RCNT)
        head=get(w,RHEAD)
        at=RING+((head+count)%64)*24
        if count==64:
            at=RING+head*24
            from_work(w,o,at,OLD_RECEIPT,24)
            put(w,RHEAD,(head+1)%64)
        else:
            put(w,RCNT,count+1)
        source_work(s,w,48,at,24)
        if (get(w,MASK)&(1<<get(o,INDEX)))==0:
            ordinal=get(w,ORDERCOUNT)
            put(w,ORDER+ordinal*8,get(o,INDEX))
            put(w,ORDERCOUNT,ordinal+1)
        put(w,MASK,get(w,MASK)|(1<<get(o,INDEX)))
        put(o,TRANSFER,1)
        put(o,TEMP,1)
        return memory(o,140,3,TEMP,0,get(o,META)+32,8)
    if phase==140:
        return fail(o,w,0)
    return fail(o,w,9)

def snapshot(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==200:
        index=get(o,ITER)
        if index==8+get(w,RCNT):
            put(o,SNAP_OK,1)
            return fail(o,w,0)
        if index<8:
            request(o,VALUES_INPUT,2)
            from_work(w,o,COUNTERS+index*24,RQ+24,24)
            return values(o,w,201,128)
        request(o,PAYLOAD_INPUT,2)
        at=RING+((get(w,RHEAD)+index-8)%64)*24
        from_work(w,o,at,RQ+24,24)
        return payload(o,w,202)
    if phase==201 or phase==202:
        expected=VALUES_REPLY
        if phase==202:
            expected=PAYLOAD_REPLY
        if valid(o,expected)==0:
            return fail(o,w,9)
        status=get(o,RP+8)
        if status!=0:
            return fail(o,w,choose(status==4,4,9))
        index=get(o,ITER)
        at=ROWS+index*48
        put(o,at,choose(phase==201,1,2))
        put(o,at+8,choose(index<8,index,index-8))
        copy_local(o,RP+16,at+16,24)
        put(o,at+40,get(o,RP+40))
        put(o,NROWS,index+1)
        put(o,ITER,index+1)
        return again(o,200)
    return fail(o,w,9)

def destroy(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==300:
        index=get(o,ITER)
        if index==8+get(w,RCNT):
            return fail(o,w,0)
        if index<8:
            put(o,SAVED,COUNTERS+index*24)
            request(o,VALUES_INPUT,3)
            from_work(w,o,get(o,SAVED),RQ+24,24)
            return values(o,w,301,128)
        put(o,SAVED,RING+((get(w,RHEAD)+index-8)%64)*24)
        request(o,PAYLOAD_INPUT,3)
        from_work(w,o,get(o,SAVED),RQ+24,24)
        return payload(o,w,302)
    if phase==301 or phase==302:
        expected=VALUES_REPLY
        if phase==302:
            expected=PAYLOAD_REPLY
        if valid(o,expected)==0 or get(o,RP+8)!=0:
            return fail(o,w,9)
        zero(w,get(o,SAVED),24)
        put(o,ITER,get(o,ITER)+1)
        return again(o,300)
    return fail(o,w,9)

def cleanup(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==900:
        if get(o,HELD)!=0:
            put(o,HELD,0)
            return atom(o,3,901,0,0)
        return again(o,910)
    if phase==901:
        return system(o,902,202,1,32,129,2147483647,0,0,0)
    if phase==902:
        return again(o,910)
    if phase==910:
        if get(o,OP)==0:
            return initialization_rollback(o,w)
        index=get(o,CLEAN)
        while index<7:
            at=NEW+index*24
            if index>=3:
                at=OLD+(index-3)*24
            if index==6:
                at=OLD_RECEIPT
            if get(o,at)!=0:
                put(o,SAVED,at)
                request(o,choose(index==6,PAYLOAD_INPUT,VALUES_INPUT),3)
                copy_local(o,at,RQ+24,24)
                if index==6:
                    return payload(o,w,912)
                return values(o,w,911,128)
            index=index+1
        put(o,CLEAN,0)
        return again(o,920)
    if phase==911 or phase==912:
        expected=VALUES_REPLY
        if phase==912:
            expected=PAYLOAD_REPLY
        if valid(o,expected)==0 or get(o,RP+8)!=0:
            return finish(o,w,9)
        zero(o,get(o,SAVED),24)
        return again(o,910)
    if phase==915:
        if valid(o,VALUES_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,9)
        zero(w,get(o,SAVED),24)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,910)
    if phase==920:
        if get(o,SNAP_OK)!=0:
            return again(o,930)
        index=get(o,CLEAN)
        if index==get(o,NROWS):
            put(o,NROWS,0)
            return again(o,930)
        at=ROWS+index*48
        put(o,SAVED,at)
        if get(o,at)==1:
            request(o,VALUES_INPUT,3)
            copy_local(o,at+16,RQ+24,24)
            return values(o,w,921,128)
        request(o,PAYLOAD_INPUT,3)
        copy_local(o,at+16,RQ+24,24)
        return payload(o,w,922)
    if phase==921 or phase==922:
        expected=VALUES_REPLY
        if phase==922:
            expected=PAYLOAD_REPLY
        if valid(o,expected)==0 or get(o,RP+8)!=0:
            return finish(o,w,9)
        zero(o,get(o,SAVED),48)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,920)
    if phase==930:
        if get(o,GUARD)==0:
            return finish(o,w,get(o,ERROR))
        request(o,JOBS_INPUT,3)
        copy_local(o,GUARD,RQ+24,24)
        return jobs(o,w,931)
    if phase==931:
        if valid(o,JOBS_REPLY)==0 or get(o,RP+8)!=0:
            return finish(o,w,9)
        zero(o,GUARD,24)
        return finish(o,w,get(o,ERROR))
    return finish(o,w,9)

def initialization_rollback(o:mutbuf,w:mutbuf) -> u32:
    index=get(o,CLEAN)
    while index<8:
        at=COUNTERS+index*24
        if get(w,at)!=0:
            put(o,CLEAN,index)
            put(o,SAVED,at)
            request(o,VALUES_INPUT,3)
            from_work(w,o,at,RQ+24,24)
            return values(o,w,915,128)
        index=index+1
    status=get(o,ERROR)
    zero(w,0,4096)
    return finish(o,w,status)

def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,129)
    zero(o,RP,2048)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0

def values(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,VF),RQ,n,RP,512,get(w,VC),get(w,VN))
def payload(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,PF),RQ,128,RP,512,get(w,PC),get(w,PN))
def jobs(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,JF),RQ,128,RP,2048,get(w,JC),get(w,JN))
def valid(o:mutbuf,magic:u64) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,RP)==magic,1,0)

def fail(o:mutbuf,w:mutbuf,status:u64) -> u32:
    if get(o,HELD)!=0:
        put(o,SAVED_COUNT,get(w,RCNT))
        put(o,SAVED_MASK,get(w,MASK))
        if get(o,PROFILE)==1:
            count=get(w,ORDERCOUNT)
            if count>6:
                status=9
            else:
                put(o,SAVED_ORDERCOUNT,count)
                from_work(w,o,ORDER,SAVED_ORDER,count*8)
    put(o,ERROR,status)
    put(o,CLEAN,0)
    return again(o,900)

def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    count=get(o,NROWS)
    profile=get(o,PROFILE)
    transfer=get(o,TRANSFER)
    already=get(o,ALREADY)
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,get(o,SAVED_COUNT))
    put(o,24,get(o,SAVED_MASK))
    put(o,32,count)
    put(o,40,transfer)
    put(o,48,already)
    put(o,56,get(w,8))
    if status==0 and profile==1:
        put(o,64,get(o,SAVED_ORDERCOUNT))
        copy_local(o,SAVED_ORDER,72,get(o,SAVED_ORDERCOUNT)*8)
    return 0

def from_work(w:mutbuf,o:mutbuf,src:u64,dest:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,dest+i,byte(w,src+i))
        i=i+1
    return 0
def to_work(o:mutbuf,w:mutbuf,src:u64,dest:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,dest+i,byte(o,src+i))
        i=i+1
    return 0
def copy_source(s:readbuf,o:mutbuf,src:u64,dest:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(o,dest+i,byte(s,src+i))
        i=i+1
    return 0
def source_work(s:readbuf,w:mutbuf,src:u64,dest:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,dest+i,byte(s,src+i))
        i=i+1
    return 0
'''
HELPERS=['readword','get','put','zero','choose','copy_local','system','again','memory','atom','invoke']
def source_program():
 source=SOURCE
 tree=ast.parse(JOBS_SOURCE)
 for name in HELPERS:
  node=next(n for n in tree.body if n.name==name)
  source+='\n'+ast.get_source_segment(JOBS_SOURCE,node)+'\n'
 for key,value in sorted(C.items(),key=lambda x:-len(x[0])):
  source=re.sub(r'\b'+key+r'\b',str(value),source)
 return source
def main():
 result=document(source_program(),'multiversion_background_ledger')
 p=ROOT/'examples/hia_bootstrap/multiversion_background_ledger.hepta';p.write_text(render_assembly(result))
 print(p.name,p.stat().st_size,len(result['functions']),sum(len(f['blocks']) for f in result['functions']),flush=True)
if __name__=='__main__':main()
