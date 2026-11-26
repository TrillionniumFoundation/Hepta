"""Author the fixed native shutdown continuation; no host policy at runtime."""
from pathlib import Path
from tools import hia_background_retirement_source as R
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as BASE
ROOT=Path(__file__).resolve().parents[1]
C={
 'INPUT':int.from_bytes(b'HIABSHQ1','little'),'REPLY':int.from_bytes(b'HIABSHR1','little'),'CONTEXT':int.from_bytes(b'HIABSHC1','little'),
 'VALUE_INPUT':int.from_bytes(b'HIABVQ01','little'),'VALUE_REPLY':int.from_bytes(b'HIABVR01','little'),
 'VALUE_DROP_INPUT':int.from_bytes(b'HIABVQ02','little'),'VALUE_DROP_REPLY':int.from_bytes(b'HIABVR02','little'),
 'QUEUE_INPUT':int.from_bytes(b'HIABGQ04','little'),'QUEUE_REPLY':int.from_bytes(b'HIABGQR2','little'),
 'JOB_INPUT':int.from_bytes(b'HIABJO03','little'),'JOB_REPLY':int.from_bytes(b'HIABJOR2','little'),
 'PUBLIC_INPUT':int.from_bytes(b'HIABFP01','little'),'PUBLIC_REPLY':int.from_bytes(b'HIABFRP1','little'),
 'PUBLIC_DROP_INPUT':int.from_bytes(b'HIABFP03','little'),'PUBLIC_DROP_REPLY':int.from_bytes(b'HIABFRP2','little'),
 'CELL_INPUT':int.from_bytes(b'HIABFQ04','little'),'CELL_REPLY':int.from_bytes(b'HIABFR02','little'),
 'JOB_PENDING':256,'FUTURE_PENDING':264,'UNKNOWN_ROWS':272,'QUARANTINE_MODE':280,'VALUE_PENDING':288,
 'WORKER_INPUT':int.from_bytes(b'HIABGW01','little'),'WORKER_REPLY':int.from_bytes(b'HIABGWO1','little'),
 'NEGATIVE':(1<<64)-4095,'OUT':262144,'WORK':16384,
 'PHASE':128,'OP':136,'ERROR':144,'DETAIL':152,'PID':160,'TID':168,'WAIT':176,'CANCEL':184,
 'LOCK':192,'COUNT':200,'INDEX':208,'CLEAN':216,'SUBINDEX':224,'FLAG_INDEX':232,'FIRST_STATUS':240,'FIRST_KIND':248,
 'FEEDBACK':448,'ARG':512,'FIRST_ERROR':536,'EXTRA_ERROR':560,'RECORD':600,
 'ROWS':1024,'RQ':16384,'RP':24576,'PUBLIC_OUT':65536,
}
C.update(R.MAGICS)
C.update({'DROP_ACTIVE':296,'DROP_KNOWN':304})
SOURCE=r'''
def shutdown(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<OUT or length(w)<WORK:
        return 4294967293
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase<20:
        return start(s,o,w,phase)
    if phase<40:
        return close_pending(s,o,w,phase)
    if phase<60:
        return cancel_pending(o,w,phase)
    if phase<80:
        return joining(o,w,phase)
    return cleanup(o,w,phase)
def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word_load(s,0)!=INPUT or word_load(s,8)>1:
        return 4294967293
    op=word_load(s,8)
    at=16
    while at<128:
        if (op==1 or at>=64) and word_load(s,at)!=0:
            return 4294967293
        at=at+8
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return 4294967293
    if get(w,32)==0 or get(w,40)==0 or get(w,48)<4096 or get(w,56)==0 or get(w,64)==0 or get(w,72)<256:
        return 4294967293
    if get(w,80)==0 or get(w,88)==0 or get(w,96)<256 or get(w,104)==0:
        return 4294967293
    if get(w,128)==0 or get(w,136)==0 or get(w,144)<512 or get(w,152)==0 or get(w,160)<8192:
        return 4294967293
    if get(w,192)==0 or get(w,200)==0 or get(w,208)<256:
        return 4294967293
    at=216
    while at<512:
        if get(w,at)!=0:
            return 4294967293
        at=at+8
    if op==1:
        if get(w,176)!=1 or get(w,184)!=1:
            return 4294967293
        from_work(w,o,512,128,8064)
        put(o,OP,1)
    else:
        if get(w,176)!=0 or get(w,184)!=0:
            return 4294967293
        zero(o,128,8064)
        put(o,WAIT,1)
        put(o,CANCEL,1)
        put(w,184,1)
    return system(o,1,39,0,0,0,0,0,0,0)
def start(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid<2 or pid>=NEGATIVE or (get(w,168)!=0 and get(w,168)!=pid):
            if get(o,OP)==1:
                return quarantine(o,w,1)
            return fail(o,6,1)
        put(w,168,pid)
        put(o,PID,pid)
        return system(o,2,186,0,0,0,0,0,0,0)
    if phase==2:
        tid=get(o,FEEDBACK)
        if tid<2 or tid>=NEGATIVE:
            return quarantine(o,w,2)
        if get(o,OP)==1:
            if get(o,LOCK)!=0 and tid!=get(o,TID):
                return quarantine(o,w,2)
            put(w,176,0)
            return again(o,100)
        put(o,TID,tid)
        return again(o,3)
    if phase==3:
        index=get(o,FLAG_INDEX)
        if index>=2:
            request(o,QUEUE_INPUT,10)
            return queue(o,w,20)
        copy_source(s,o,16+index*24,ARG,24)
        if get(o,ARG)==0:
            if get(o,ARG+8)!=0 or get(o,ARG+16)!=0:
                return fail(o,6,3)
            put(o,FLAG_INDEX,index+1)
            return again(o,3)
        request(o,VALUE_INPUT,7)
        within(o,RQ+24,ARG,24)
        return values(o,w,4,128)
    if phase==4:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0:
            return fail(o,7,4)
        if get(o,RP+16)!=1:
            return error_value(o,w,0,1)
        request(o,VALUE_INPUT,19)
        within(o,RQ+24,ARG,24)
        put(o,RQ+112,1)
        return values(o,w,5,128)
    if phase==5:
        if valid(o,RP,VALUE_REPLY)==0 or get(o,RP+8)!=0 or get(o,RP+64)!=1 or get(o,RP+72)!=1 or byte(o,RP+8192)>1:
            return fail(o,7,5)
        if get(o,FLAG_INDEX)==0:
            put(o,WAIT,byte(o,RP+8192))
        else:
            put(o,CANCEL,byte(o,RP+8192))
        put(o,FLAG_INDEX,get(o,FLAG_INDEX)+1)
        return again(o,3)
    if phase==10:
        if valid(o,RP,VALUE_REPLY)==0:
            return fail(o,7,10)
        if get(o,RP+8)==5:
            put(o,FIRST_STATUS,1)
            put(o,FIRST_KIND,103)
            return again(o,100)
        if get(o,RP+8)!=0 or get(o,RP+24)==0 or get(o,FIRST_ERROR)!=0:
            return fail(o,7,10)
        within(o,FIRST_ERROR,RP+24,24)
        put(o,FIRST_STATUS,1)
        put(o,FIRST_KIND,200)
        return again(o,100)
    return fail(o,7,phase)
def close_pending(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==20:
        if valid(o,RP,QUEUE_REPLY)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,20)
        put(o,LOCK,1)
        request(o,QUEUE_INPUT,4)
        put(o,RQ+16,get(o,CANCEL))
        return queue(o,w,21)
    if phase==21:
        if valid(o,RP,QUEUE_REPLY)==0:
            return quarantine(o,w,21)
        if capture_rows(o)==0:
            return quarantine(o,w,21)
        if get(o,UNKNOWN_ROWS)!=0:
            return quarantine(o,w,21)
        if get(o,RP+8)!=0:
            if get(o,RP+8)==5:
                put(o,FIRST_STATUS,1)
                put(o,FIRST_KIND,103)
                return again(o,100)
            return fail(o,7,21)
        if get(o,RP+120)!=0:
            return quarantine(o,w,21)
        put(o,INDEX,0)
        return again(o,22)
    if phase==22:
        if get(o,INDEX)>=get(o,COUNT):
            request(o,QUEUE_INPUT,11)
            return queue(o,w,25)
        at=ROWS+get(o,INDEX)*128
        slot=get(o,at+96)
        if get(o,at)==0 or slot>=8 or get(o,at+88)==0:
            return quarantine(o,w,22)
        return memory(o,23,0,get(w,152)+1024+slot*128,3,RECORD,72)
    if phase==23:
        if get(o,RECORD)==0 or get(o,RECORD+24)==0 or get(o,RECORD+48)==0:
            return quarantine(o,w,23)
        request(o,PUBLIC_INPUT,5)
        from_work(w,o,104,RQ+16,24)
        within(o,RQ+40,RECORD+48,24)
        return public_owner(o,w,24)
    if phase==24:
        if valid(o,PUBLIC_OUT,PUBLIC_REPLY)==0:
            return quarantine(o,w,24)
        if get(o,PUBLIC_OUT+8)!=0:
            accept_error(o,ROWS+get(o,INDEX)*128)
            return again(o,100)
        if get(o,PUBLIC_OUT+48)==0:
            return quarantine(o,w,24)
        within(o,ROWS+get(o,INDEX)*128+24,PUBLIC_OUT+48,24)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,22)
    if phase==25:
        if valid(o,RP,QUEUE_REPLY)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,25)
        put(o,LOCK,0)
        put(o,INDEX,0)
        return again(o,40)
    return fail(o,7,phase)
def capture_rows(o:mutbuf) -> u64:
    n=get(o,RP+56)
    if n>8 or get(o,RP+64)!=choose(n!=0,1,0) or get(o,RP+120)>7:
        return 0
    put(o,COUNT,n)
    if (get(o,RP+120)&4)!=0:
        put(o,JOB_PENDING,1)
    i=0
    while i<n:
        source=RP+512+i*64
        at=ROWS+i*128
        within(o,at,source,24)
        put(o,at+88,get(o,source+24))
        put(o,at+96,get(o,source+40))
        put(o,at+104,get(o,source+48))
        if get(o,source+48)!=0:
            put(o,UNKNOWN_ROWS,1)
        i=i+1
    return 1
def cancel_pending(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==40:
        if get(o,INDEX)>=get(o,COUNT):
            return again(o,60)
        at=ROWS+get(o,INDEX)*128
        request(o,PUBLIC_INPUT,7)
        from_work(w,o,104,RQ+16,24)
        within(o,RQ+40,at+24,24)
        return public_owner(o,w,41)
    if phase==41:
        if valid(o,PUBLIC_OUT,PUBLIC_REPLY)==0:
            return quarantine(o,w,41)
        if get(o,PUBLIC_OUT+8)!=0:
            accept_error(o,ROWS+get(o,INDEX)*128)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,40)
    return fail(o,7,phase)
def joining(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==60:
        if get(o,WAIT)==0:
            return again(o,100)
        request(o,WORKER_INPUT,2)
        return invoke(o,61,get(w,128),51,RQ,128,RP,8192,get(w,136),get(w,144))
    if phase==61:
        if valid(o,RP,WORKER_REPLY)==0:
            return quarantine(o,w,61)
        status=get(o,RP+8)
        if status==6:
            within(o,EXTRA_ERROR,FIRST_ERROR,24)
            zero(o,FIRST_ERROR,24)
            put(o,FIRST_STATUS,0)
            put(o,FIRST_KIND,0)
            return error_value(o,w,1,1)
        if status!=0:
            return fail(o,7,61)
        return again(o,100)
    return fail(o,7,phase)
def accept_error(o:mutbuf,at:u64) -> u64:
    status=get(o,PUBLIC_OUT+8)
    kind=get(o,PUBLIC_OUT+16)
    if (status!=1 and status!=2) or (kind!=200 and (status!=1 or kind<100 or kind>107)):
        put(o,ERROR,7)
        put(o,DETAIL,get(o,PHASE))
        return 0
    if kind==200:
        if get(o,PUBLIC_OUT+72)==0 or get(o,at+48)!=0:
            put(o,ERROR,7)
            put(o,DETAIL,get(o,PHASE))
            return 0
        within(o,at+48,PUBLIC_OUT+72,24)
    if get(o,FIRST_STATUS)==0:
        put(o,FIRST_STATUS,status)
        put(o,FIRST_KIND,kind)
        within(o,FIRST_ERROR,at+48,24)
        zero(o,at+48,24)
    return 0
def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        if get(o,LOCK)!=0:
            request(o,QUEUE_INPUT,11)
            return queue(o,w,101)
        return again(o,110)
    if phase==101:
        if valid(o,RP,QUEUE_REPLY)==0 or get(o,RP+8)!=0:
            return quarantine(o,w,101)
        put(o,LOCK,0)
        return again(o,110)
    if phase==110:
        i=get(o,CLEAN)
        if i>=get(o,COUNT)*3:
            return again(o,115)
        at=ROWS+(i//3)*128+(i%3)*24
        if get(o,at)==0:
            put(o,CLEAN,i+1)
            return again(o,110)
        if i%3==0:
            if get(o,ROWS+(i//3)*128+104)!=0:
                return quarantine(o,w,110)
            release_begin(o)
            request(o,JOB_INPUT,11)
            within(o,RQ+24,at,24)
            return jobs(o,w,111)
        if i%3==1:
            release_begin(o)
            request(o,PUBLIC_DROP_INPUT,26)
            from_work(w,o,104,RQ+16,24)
            within(o,RQ+40,at,24)
            return public_owner(o,w,112)
        return drop_value(o,w,113,at)
    if phase>=111 and phase<=113:
        i=get(o,CLEAN)
        at=ROWS+(i//3)*128+(i%3)*24
        done=0
        if phase==111:
            done=release_job(o,at)
        elif phase==112:
            done=release_future(o,at)
        else:
            done=release_value(o,at)
        if done==0:
            if get(o,DROP_KNOWN)==1:
                return retry_cleanup(o,w,phase)
            return quarantine(o,w,phase)
        return released(o)
    if phase==114:
        if release_value(o,EXTRA_ERROR)==0:
            if get(o,DROP_KNOWN)==1:
                return retry_cleanup(o,w,114)
            return quarantine(o,w,114)
        return again(o,115)
    if phase==115:
        if get(o,JOB_PENDING)!=0:
            release_begin(o)
            request(o,JOB_INPUT,12)
            return jobs(o,w,116)
        if get(o,FUTURE_PENDING)!=0:
            release_begin(o)
            request(o,PUBLIC_INPUT,20)
            return public_owner(o,w,117)
        if get(o,VALUE_PENDING)!=0:
            release_begin(o)
            request(o,VALUE_DROP_INPUT,31)
            return values(o,w,119,128)
        if get(o,EXTRA_ERROR)!=0:
            return drop_value(o,w,114,EXTRA_ERROR)
        return finish(o,w)
    if phase==116:
        if release_job_retry(o)==0:
            if get(o,DROP_KNOWN)==1:
                return retry_cleanup(o,w,116)
            return quarantine(o,w,116)
        return again(o,115)
    if phase==117:
        if release_future_retry(o)==0:
            return quarantine(o,w,117)
        release_begin(o)
        request(o,CELL_QUERY_INPUT,21)
        return invoke(o,118,get(w,192),51,RQ,128,RP,16384,get(w,200),get(w,208))
    if phase==118:
        if release_cell_query(o)==0:
            if get(o,DROP_KNOWN)==1:
                return retry_cleanup(o,w,118)
            return quarantine(o,w,118)
        return again(o,115)
    if phase==119:
        if release_value_retry(o)==0:
            if get(o,DROP_KNOWN)==1:
                return retry_cleanup(o,w,119)
            return quarantine(o,w,119)
        return again(o,115)
    if phase==190:
        if valid(o,RP,QUEUE_REPLY)!=0 and get(o,RP+8)==0:
            put(o,LOCK,0)
        return save_quarantine(o,w,2)
    return quarantine(o,w,phase)
def released(o:mutbuf) -> u32:
    i=get(o,CLEAN)
    zero(o,ROWS+(i//3)*128+(i%3)*24,24)
    put(o,CLEAN,i+1)
    return again(o,110)
def jobs(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,56),51,RQ,128,RP,2048,get(w,64),get(w,72))
def value_drop_known(o:mutbuf) -> u64:
    if valid(o,RP,VALUE_DROP_REPLY)==0 or get(o,RP+88)!=1 or get(o,RP+96)>1 or get(o,RP+80)>1:
        return 0
    status=get(o,RP+8)
    if status!=0 and status!=1 and status!=5 and status!=6 and status!=11:
        return 0
    if status==0 and get(o,RP+96)!=1:
        return 0
    return 1
def error_value(o:mutbuf,w:mutbuf,which:u64,status:u64) -> u32:
    request(o,VALUE_INPUT,1)
    n=error_literal(o,RQ+128,which)
    put(o,RQ+96,n)
    return values(o,w,10,128+n)
def values(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,8193,get(w,16),get(w,24))
def drop_value(o:mutbuf,w:mutbuf,next:u64,at:u64) -> u32:
    release_begin(o)
    request(o,VALUE_DROP_INPUT,29)
    within(o,RQ+24,at,24)
    return values(o,w,next,128)
def public_owner(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,80),51,RQ,192,PUBLIC_OUT,65536,get(w,88),get(w,96))
def queue(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,32),51,RQ,128,RP,4096,get(w,40),get(w,48))
def request(o:mutbuf,magic:u64,op:u64) -> u64:
    zero(o,RQ,192)
    put(o,RQ,magic)
    put(o,RQ+8,op)
    return 0
def valid(o:mutbuf,at:u64,magic:u64) -> u64:
    return choose(get(o,FEEDBACK)==0 and get(o,at)==magic,1,0)
def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    return again(o,100)
def quarantine(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(o,DETAIL,detail)
    within(o,4096,RP,2048)
    within(o,6144,PUBLIC_OUT,128)
    if get(o,LOCK)!=0:
        request(o,QUEUE_INPUT,11)
        return queue(o,w,190)
    return save_quarantine(o,w,2)
def retry_cleanup(o:mutbuf,w:mutbuf,detail:u64) -> u32:
    put(o,DETAIL,detail)
    return save_quarantine(o,w,1)
def save_quarantine(o:mutbuf,w:mutbuf,kind:u64) -> u32:
    to_work(o,w,128,512,8064)
    put(w,176,kind)
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,9)
    put(o,48,get(o,DETAIL))
    put(o,56,kind)
    return 0
def finish(o:mutbuf,w:mutbuf) -> u32:
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,choose(get(o,ERROR)!=0,get(o,ERROR),get(o,FIRST_STATUS)))
    put(o,16,get(o,FIRST_KIND))
    within(o,24,FIRST_ERROR,24)
    put(o,48,get(o,DETAIL))
    zero(o,FIRST_ERROR,24)
    put(w,176,0)
    put(w,184,0)
    return 0
'''
SOURCE+='\n'+R.SOURCE
ERRORS=(
 b'{"class":"BackgroundOptimizationRejected","message":"E_HIA_BACKGROUND: shutdown flags must be exact booleans"}',
 b'{"class":"RuntimeError","message":"Failed joining thread"}',
)
def source_program(symbolic=False):
    s=SOURCE
    for name in ('invoke','memory','system','again','to_work','from_work','copy_source','within','zero','get','put','choose'):
        node=next(x for x in ast.parse(BASE).body if isinstance(x,ast.FunctionDef) and x.name==name)
        s+='\n'+ast.get_source_segment(BASE,node)+'\n'
    s+='\ndef error_literal(o:mutbuf,at:u64,which:u64) -> u64:\n'
    for i,raw in enumerate(ERRORS):
        s+='    if which=='+str(i)+':\n'
        for at in range(0,len(raw)-len(raw)%8,8):s+='        put(o,at+'+str(at)+','+str(int.from_bytes(raw[at:at+8],'little'))+')\n'
        for at in range(len(raw)-len(raw)%8,len(raw)):s+='        store(o,at+'+str(at)+','+str(raw[at])+')\n'
        s+='        return '+str(len(raw))+'\n'
    s+='    return 0\n'
    if not symbolic:
     for key,value in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+key+r'\b',str(value),s)
    return s
def main():
    tree=document(source_program(),'background_optimizer_shutdown')
    path=ROOT/'examples/hia_bootstrap/background_optimizer_shutdown.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),sum(len(f['blocks']) for f in tree['functions']),sum(len(b['ops']) for f in tree['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
