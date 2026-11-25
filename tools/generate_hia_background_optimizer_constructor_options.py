"""Original BG constructor option order over captured actual native values."""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as HELPERS
ROOT=Path(__file__).resolve().parents[1]
C=dict(MAX=(1<<64)-1,BAD=4294967293,PHASE=256,ERROR=264,CODE=272,DETAIL=280,
 INDEX=288,MAXPENDING=296,TIMEOUT=304,BTIME=312,BINT=320,SCALARN=328,SCALARKIND=336,
 KEYMASK=344,KEY0=352,KEY1=360,FINISHED=368,CLEAN=376,QUAR=384,PENDING=392,
 REFS=512,RQ=4096,RP=8192,ERR=2048,FEEDBACK=3840)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 MAGIC='HIABOPQ1',REPLY='HIABOPR1',CONTEXT='HIABOPC1',VQ='HIABVQ01',VR='HIABVR01',VQ2='HIABVQ02',VR2='HIABVR02').items()})
ERRORS={
 1:'E_HIA_BACKGROUND: max_pending must be an exact integer from one to eight',
 2:'E_HIA_BACKGROUND: translation validation timeout must be 1..5000 milliseconds',
 3:'E_HIA_BACKGROUND: bridge timeout must be finite and at most sixty seconds',
 4:'E_HIA_BACKGROUND: bridge requires binary and build_receipt paths'}
SOURCE=r"""
def options(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<32768 or length(w)<2048:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        if get(o,FEEDBACK)!=get(w,32):
            return finish(o,6)
        if word_load(s,8)==1:
            if get(w,40)==0:
                return finish(o,0)
            if get(w,40)==2:
                put(o,QUAR,2)
                return finish(o,9)
            from_work(w,o,128,256,1792)
            put(w,40,0)
            put(o,QUAR,0)
            put(o,CLEAN,0)
            return again(o,100)
        if get(w,40)!=0:
            return finish(o,6)
        put(o,MAXPENDING,8)
        put(o,TIMEOUT,2000)
        put(o,BTIME,4621819117588971520)
        return again(o,2)
    if phase<10:
        return primitives(s,o,w,phase)
    if phase<100:
        return bridge_keys(s,o,w,phase)
    return cleanup(o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word_load(s,0)!=MAGIC or word_load(s,8)>1:
        return BAD
    if word_load(s,16)!=0 or word_load(s,120)!=0:
        return BAD
    if word_load(s,8)==1:
        i=24
        while i<120:
            if word_load(s,i)!=0:
                return BAD
            i=i+8
    elif word_load(s,96)==0 and word_load(s,104)==0 and word_load(s,112)==0:
        return BAD
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return BAD
    if get(w,16)>MAX-get(w,24) or get(w,32)<2 or get(w,32)>2147483647 or get(w,40)>2:
        return BAD
    i=48
    while i<128:
        if get(w,i)!=0:
            return BAD
        i=i+8
    zero(o,192,3904)
    return system(o,1,39,0,0,0,0,0,0,0)

def primitives(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==2:
        i=get(o,INDEX)
        if i==3:
            request(o,VQ,7)
            copy_source(s,o,96,RQ+24,24)
            return value(o,w,10)
        at=24+i*24
        if word_load(s,at)==0 and word_load(s,at+8)==0 and word_load(s,at+16)==0:
            put(o,INDEX,i+1)
            return again(o,2)
        request(o,VQ,7)
        copy_source(s,o,at,RQ+24,24)
        return value(o,w,3)
    if phase==3:
        if value_ok(o)==False:
            return dependency(o)
        i=get(o,INDEX)
        kind=get(o,RP+16)
        if i<2 and kind!=2:
            return reject(o,i+1)
        if i==2 and kind!=2 and kind!=3:
            return reject(o,3)
        n=get(o,RP+72)
        if kind==2:
            maximum=1
            if i==1:
                maximum=4
            elif i==2:
                maximum=2
            if n==0 or n>maximum:
                return reject(o,i+1)
        elif n!=8:
            return fail(o,7,3)
        put(o,SCALARN,n)
        put(o,SCALARKIND,kind)
        request(o,VQ,19)
        copy_source(s,o,24+i*24,RQ+24,24)
        put(o,RQ+112,n)
        return value(o,w,4)
    if phase==4:
        if value_ok(o)==False:
            return dependency(o)
        n=get(o,SCALARN)
        kind=get(o,SCALARKIND)
        if get(o,RP+64)!=n or get(o,RP+72)!=n or get(o,RP+16)!=kind:
            return fail(o,7,4)
        i=get(o,INDEX)
        number=0
        if kind==3:
            number=get(o,RP+8192)
            if number==0 or number>4633641066610819072:
                return reject(o,3)
            put(o,BTIME,number)
            put(o,BINT,0)
        else:
            j=0
            while j<n:
                ch=byte(o,RP+8192+j)
                if ch<48 or ch>57:
                    return reject(o,i+1)
                number=number*10+ch-48
                j=j+1
            maximum=8
            if i==1:
                maximum=5000
            elif i==2:
                maximum=60
            if number<1 or number>maximum:
                return reject(o,i+1)
            if i==0:
                put(o,MAXPENDING,number)
            elif i==1:
                put(o,TIMEOUT,number)
            else:
                put(o,BTIME,number)
                put(o,BINT,1)
        put(o,INDEX,i+1)
        return again(o,2)
    return fail(o,7,phase)

def bridge_keys(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        if value_ok(o)==False:
            return dependency(o)
        if get(o,RP+16)!=6 or get(o,RP+48)!=2:
            return reject(o,4)
        put(o,INDEX,0)
        return again(o,20)
    if phase==20:
        i=get(o,INDEX)
        if i==2:
            put(o,FINISHED,1)
            put(o,CLEAN,0)
            return again(o,100)
        request(o,VQ,2)
        put(o,RQ+104,4)
        n=key_text(o,RQ+128,i)
        put(o,RQ+96,n)
        return value_n(o,w,21,128+n)
    if phase==21:
        if value_ok(o)==False:
            return dependency(o)
        if get(o,RP+24)==0:
            return fail(o,7,21)
        within(o,REFS+get(o,INDEX)*48,RP+24,24)
        request(o,VQ,9)
        copy_source(s,o,96,RQ+24,24)
        within(o,RQ+48,REFS+get(o,INDEX)*48,24)
        return value(o,w,22)
    if phase==22:
        if value_ok(o)==False:
            if get(o,FEEDBACK)==0 and get(o,RP)==VR and get(o,RP+8)==3:
                return reject(o,4)
            return dependency(o)
        if get(o,RP+24)==0:
            return fail(o,7,22)
        within(o,REFS+get(o,INDEX)*48+24,RP+24,24)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,20)
    return fail(o,7,phase)

def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        i=get(o,CLEAN)
        if i==4:
            if get(o,PENDING)!=0:
                request(o,VQ2,31)
                return value(o,w,102)
            return finish(o,get(o,ERROR))
        at=REFS+i*24
        if get(o,at)==0:
            put(o,CLEAN,i+1)
            return again(o,100)
        request(o,VQ2,29)
        within(o,RQ+24,at,24)
        return value(o,w,101)
    if phase==101:
        if cleanup_facts(o,29)==False:
            return quarantine(o,w,2,get(o,FEEDBACK))
        known=get(o,RP+88)
        consumed=get(o,RP+96)
        pending=get(o,RP+80)
        if known==0:
            return quarantine(o,w,2,get(o,RP+8))
        status=get(o,RP+8)
        if status==0 and (consumed==0 or pending!=0):
            return quarantine(o,w,2,101)
        if consumed!=0:
            zero(o,REFS+get(o,CLEAN)*24,24)
        if pending!=0:
            put(o,PENDING,1)
        if status!=0:
            kind=1
            if consumed!=0 and pending==0:
                kind=2
            return quarantine(o,w,kind,status)
        put(o,CLEAN,get(o,CLEAN)+1)
        return again(o,100)
    if phase==102:
        if cleanup_facts(o,31)==False or get(o,RP+88)==0 or get(o,RP+96)!=0:
            return quarantine(o,w,2,get(o,FEEDBACK))
        if get(o,RP+8)!=0:
            return quarantine(o,w,1,get(o,RP+8))
        if get(o,RP+80)!=0:
            return quarantine(o,w,2,102)
        put(o,PENDING,0)
        return finish(o,get(o,ERROR))
    return quarantine(o,w,2,phase)

def cleanup_facts(o:mutbuf,op:u64) -> bool:
    if get(o,FEEDBACK)!=0 or get(o,RP)!=VR2 or get(o,RP+80)>1 or get(o,RP+88)>1 or get(o,RP+96)>1:
        return False
    if get(o,RP+88)==0 and get(o,RP+96)!=0:
        return False
    status=get(o,RP+8)
    if status!=0 and status!=6 and status!=11 and (op==31 or status!=1):
        return False
    if get(o,RP+96)!=0 and status!=0 and status!=11:
        return False
    if get(o,RP+88)==0 and (op==31 or status!=11 or get(o,RP+80)!=0):
        return False
    if status==1 and (get(o,RP+88)!=1 or get(o,RP+80)!=0):
        return False
    i=16
    while i<80:
        if get(o,RP+i)!=0:
            return False
        i=i+8
    i=104
    while i<128:
        if get(o,RP+i)!=0:
            return False
        i=i+8
    return True

def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return value_n(o,w,next,128)
def value_n(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,16384,get(w,16),get(w,24))
def value_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==VR and get(o,RP+8)==0
def dependency(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,RP)!=VR:
        return fail(o,7,get(o,FEEDBACK))
    status=get(o,RP+8)
    if status==5:
        return fail(o,5,status)
    return fail(o,7,status)
def reject(o:mutbuf,code:u64) -> u32:
    put(o,CODE,code)
    return fail(o,1,0)
def fail(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,ERROR,status)
    put(o,DETAIL,detail)
    put(o,CLEAN,0)
    return again(o,100)
def quarantine(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    put(o,QUAR,kind)
    put(o,DETAIL,detail)
    to_work(o,w,256,128,1792)
    put(w,40,kind)
    return finish(o,9)
def finish(o:mutbuf,status:u64) -> u32:
    code=get(o,CODE)
    zero(o,0,192)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,120,code)
    put(o,136,get(o,QUAR))
    put(o,144,get(o,DETAIL))
    if status==0 and get(o,FINISHED)==1:
        put(o,16,1)
        put(o,24,get(o,MAXPENDING))
        put(o,32,get(o,TIMEOUT))
        put(o,40,get(o,BTIME))
        put(o,48,get(o,BINT))
    elif status==1:
        n=error_text(o,code)
        put(o,128,n)
        within(o,192,ERR,n)
    return 0
"""
def source_program():
    names={'request','invoke','system','again','copy_source','within','zero','get','put','to_work','from_work'}
    helpers='\n'.join(ast.unparse(f)for f in ast.parse(HELPERS).body if isinstance(f,ast.FunctionDef)and f.name in names)
    text=SOURCE+'\n'+helpers+'\ndef key_text(o:mutbuf,at:u64,id:u64) -> u64:\n'
    for id,label in enumerate((b'binary',b'build_receipt')):
        text+=f'    if id=={id}:\n'
        for i in range(0,len(label),8):text+=f'        put(o,at+{i},{int.from_bytes(label[i:i+8].ljust(8,bytes(1)),"little")})\n'
        text+=f'        return {len(label)}\n'
    text+='    return 0\n'
    text+='\ndef error_text(o:mutbuf,code:u64) -> u64:\n'
    for code,message in sorted(ERRORS.items()):
        raw=json.dumps({'class':'BackgroundOptimizationRejected','message':message},sort_keys=True,separators=(',',':')).encode()
        text+=f'    if code=={code}:\n'
        for i in range(0,len(raw),8):text+=f'        put(o,ERR+{i},{int.from_bytes(raw[i:i+8].ljust(8,bytes(1)),"little")})\n'
        text+=f'        return {len(raw)}\n'
    text+='    return 0\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'background_optimizer_constructor_options')
def main():
    d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_constructor_options.hepta';p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
