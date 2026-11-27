"""Original Runtime constructor option order over the sole actual Value arena.

This segment owns retained arguments and true native exception objects. It is
used by the enclosing constructor before VFY, directory conversion and Clang.
The context is captured by that fixed native constructor, never by public input.
"""
from pathlib import Path
import ast,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as HELPERS
ROOT=Path(__file__).resolve().parents[1]
C=dict(BAD=4294967293,MAX=(1<<64)-1,OUT=32768,WORK=8192,
 PHASE=128,STATUS=136,DETAIL=144,INDEX=152,TIMEOUT=160,LIMIT=168,PROVE=176,
 SUCCESS=184,CLEAN=192,QUAR=200,QUEUE=208,OP=216,CODE=224,N=232,
 AFTER=240,PRIMARY=256,REFS=512,TMP=704,CLASS=704,MESSAGE=728,LIST=752,TUPLE=776,
 RQ=4096,RP=8192,UNAME=2048,FEEDBACK=1024)
C.update({k:int.from_bytes(v.encode(),'little')for k,v in dict(
 Q='HIARTOQ1',R='HIARTOR1',CTX='HIARTOC1',VQ='HIABVQ01',V5='HIABVQ05',
 V6='HIABVQ06',V7='HIABVQ07',V11='HIABVQ11',VR='HIABVR01',VR2='HIABVR02').items()})
ERRORS={1:'E_HIA_MULTIVERSION: Linux x86-64 with sealing-capable memfd is required',
 2:'E_HIA_MULTIVERSION: translation validation timeout must be 1..30000 milliseconds',
 3:'E_HIA_MULTIVERSION: live generation limit must be 2..64',
 4:'E_HIA_MULTIVERSION: prove_total must be an explicit Boolean profile choice'}
SOURCE=r'''
def options(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid==0 or pid>=MAX-4094 or pid!=get(w,32):
            return finish(o,w,6)
        put(o,0,0)
        put(o,PHASE,2)
        return 4
    if phase==2:
        own=get(o,FEEDBACK)
        if get(w,40)!=0 and get(w,48)!=own:
            return finish(o,w,6)
        put(w,48,own)
        if get(o,OP)==1:
            if get(w,40)==0:
                return finish(o,w,0)
            if get(w,40)!=1:
                put(o,QUAR,2)
                return finish(o,w,9)
            from_work(w,o,256,128,896)
            put(o,OP,1)
            put(o,QUAR,0)
            put(w,40,0)
            return again(o,100)
        if get(w,40)!=0:
            return finish(o,w,6)
        put(o,TIMEOUT,2000)
        put(o,LIMIT,8)
        return again(o,3)
    if phase>=3 and phase<=6:
        return retaining(s,o,w,phase)
    if phase>=10 and phase<30:
        return primitive(s,o,w,phase)
    if phase>=40 and phase<60:
        return defaults(o,w,phase)
    if phase>=60 and phase<80:
        return exception(o,w,phase)
    return cleanup(o,w,phase)

def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=256 or length(o)<OUT or length(w)!=WORK or word_load(s,0)!=Q or word_load(s,8)>1:
        return BAD
    if get(w,0)!=CTX or get(w,8)==0 or get(w,16)==0 or get(w,24)!=256:
        return BAD
    if get(w,32)<2 or get(w,32)>2147483647 or get(w,40)>2:
        return BAD
    at=56
    while at<256:
        if get(w,at)!=0:
            return BAD
        at=at+8
    at=16
    while at<256:
        used=word_load(s,8)==0 and at>=24 and at<=184
        if used==False and word_load(s,at)!=0:
            return BAD
        at=at+8
    if word_load(s,8)==0 and (word_load(s,24)==0 or word_load(s,48)==0):
        return BAD
    zero(o,128,896)
    put(o,OP,word_load(s,8))
    return system(o,1,39,0,0,0,0,0,0,0)

def retaining(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==3:
        i=get(o,INDEX)
        if i==7:
            return system(o,10,63,3,UNAME,0,0,0,0,0)
        at=24+i*24
        if word_load(s,at)==0 and word_load(s,at+8)==0 and word_load(s,at+16)==0:
            put(o,INDEX,i+1)
            return again(o,3)
        request(o,V5,91)
        copy_source(s,o,at,RQ+24,24)
        return value(o,w,4,128)
    if phase==4:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=VR:
            return isolate(o,w,2,4)
        known=get(o,RP+88)
        delivered=get(o,RP+96)
        if known>1 or delivered>1 or get(o,RP+80)>1 or get(o,RP+120)!=1:
            return isolate(o,w,2,5)
        if delivered==1:
            if cap(o,RP+24)==False:
                return isolate(o,w,2,6)
            within(o,REFS+get(o,INDEX)*24,RP+24,24)
        elif cap(o,RP+24):
            return isolate(o,w,2,7)
        if known!=1 or get(o,RP+104)!=0:
            return isolate(o,w,2,8)
        if get(o,RP+112)!=0:
            put(o,QUEUE,1)
        if delivered!=1:
            return failed(o,choose(get(o,RP+8)==5,5,7),get(o,RP+8))
        if get(o,RP+8)!=0 and get(o,RP+8)!=11:
            return isolate(o,w,2,9)
        put(o,INDEX,get(o,INDEX)+1)
        return again(o,3)
    return failed(o,7,phase)

def primitive(s:readbuf,o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==10:
        if get(o,FEEDBACK)!=0:
            return failed(o,8,get(o,FEEDBACK))
        if text_equal(o,UNAME,0)==False or (text_equal(o,UNAME+260,1)==False and text_equal(o,UNAME+260,2)==False):
            return reject(o,1)
        put(o,INDEX,3)
        return again(o,11)
    if phase==11:
        i=get(o,INDEX)
        if i==6:
            return again(o,40)
        at=REFS+i*24
        if get(o,at)==0:
            put(o,INDEX,i+1)
            return again(o,11)
        request(o,V6,7)
        within(o,RQ+24,at,24)
        return value(o,w,12,128)
    if phase==12:
        if okay(o)==False:
            return dependency(o)
        i=get(o,INDEX)
        expected=2
        if i==5:
            expected=1
        if get(o,RP+16)!=expected:
            return reject(o,i-1)
        n=get(o,RP+72)
        maximum=5
        if i==4:
            maximum=2
        elif i==5:
            maximum=1
        if n==0 or n>maximum or (i==5 and n!=1):
            return reject(o,i-1)
        put(o,N,n)
        request(o,V6,19)
        within(o,RQ+24,REFS+i*24,24)
        put(o,RQ+112,n)
        return value(o,w,13,128)
    if phase==13:
        if okay(o)==False:
            return dependency(o)
        i=get(o,INDEX)
        n=get(o,N)
        if get(o,RP+64)!=n or get(o,RP+72)!=n:
            return failed(o,7,13)
        number=0
        if i==5:
            number=byte(o,RP+8192)
            if number>1:
                return failed(o,7,14)
        else:
            j=0
            while j<n:
                ch=byte(o,RP+8192+j)
                if ch<48 or ch>57:
                    return reject(o,i-1)
                number=number*10+ch-48
                j=j+1
            minimum=1
            maximum=30000
            if i==4:
                minimum=2
                maximum=64
            if number<minimum or number>maximum:
                return reject(o,i-1)
        if i==3:
            put(o,TIMEOUT,number)
        elif i==4:
            put(o,LIMIT,number)
        else:
            put(o,PROVE,number)
        put(o,INDEX,i+1)
        return again(o,11)
    return failed(o,7,phase)

def defaults(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==40:
        if get(o,REFS+48)==0:
            request(o,VQ,2)
            put(o,RQ+104,4)
            put(o,RQ+96,5)
            put(o,RQ+128,444233509987)
            return value(o,w,41,133)
        put(o,SUCCESS,1)
        put(o,CLEAN,0)
        return again(o,100)
    if phase==41:
        if okay(o)==False:
            return dependency(o)
        if cap(o,RP+24)==False:
            return isolate(o,w,2,41)
        within(o,REFS+48,RP+24,24)
        put(o,SUCCESS,1)
        put(o,CLEAN,0)
        return again(o,100)
    return failed(o,7,phase)

def exception(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==60:
        request(o,V11,87)
        put(o,RQ+104,41)
        return value(o,w,61,128)
    if phase==61:
        if okay(o)==False:
            return dependency(o)
        if cap(o,RP+24)==False:
            return isolate(o,w,2,61)
        within(o,CLASS,RP+24,24)
        request(o,VQ,2)
        put(o,RQ+104,4)
        n=message(o,RQ+128,get(o,CODE))
        put(o,RQ+96,n)
        return value(o,w,62,128+n)
    if phase==62:
        if okay(o)==False:
            return dependency(o)
        if cap(o,RP+24)==False:
            return isolate(o,w,2,62)
        within(o,MESSAGE,RP+24,24)
        request(o,V7,3)
        return value(o,w,63,128)
    if phase==63:
        if okay(o)==False:
            return dependency(o)
        if cap(o,RP+24)==False:
            return isolate(o,w,2,63)
        within(o,LIST,RP+24,24)
        request(o,V7,16)
        within(o,RQ+24,LIST,24)
        within(o,RQ+48,MESSAGE,24)
        return value(o,w,64,128)
    if phase==64:
        if okay(o)==False:
            return dependency(o)
        request(o,V11,40)
        within(o,RQ+24,LIST,24)
        return value(o,w,65,128)
    if phase==65:
        if okay(o)==False:
            return dependency(o)
        if cap(o,RP+24)==False:
            return isolate(o,w,2,65)
        within(o,TUPLE,RP+24,24)
        request(o,V11,75)
        within(o,RQ+24,CLASS,24)
        within(o,RQ+48,TUPLE,24)
        return value(o,w,66,128)
    if phase==66:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=VR:
            return isolate(o,w,2,66)
        if cap(o,RP+24):
            within(o,PRIMARY,RP+24,24)
        if get(o,RP+8)!=0:
            return failed(o,choose(get(o,RP+8)==5,5,7),get(o,RP+8))
        if get(o,PRIMARY)==0:
            return isolate(o,w,2,67)
        put(o,STATUS,1)
        put(o,CLEAN,0)
        return again(o,100)
    return failed(o,7,phase)

def cleanup(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    if phase==100:
        i=get(o,CLEAN)
        if i==11:
            put(w,40,0)
            return finish(o,w,get(o,STATUS))
        at=REFS+i*24
        if i>=7:
            at=TMP+(i-7)*24
        keep=get(o,SUCCESS)==1 and (i<3 or i==6)
        if keep or get(o,at)==0:
            put(o,CLEAN,i+1)
            return again(o,100)
        request(o,V5,78)
        within(o,RQ+24,at,24)
        return value(o,w,101,128)
    if phase==101:
        if get(o,FEEDBACK)!=0 or get(o,RP)!=VR2 or get(o,RP+88)>1 or get(o,RP+96)>1 or get(o,RP+80)>1 or get(o,RP+120)!=1:
            return isolate(o,w,2,101)
        if get(o,RP+88)!=1:
            return isolate(o,w,2,102)
        i=get(o,CLEAN)
        at=REFS+i*24
        if i>=7:
            at=TMP+(i-7)*24
        if get(o,RP+96)==1:
            zero(o,at,24)
        if get(o,RP+112)!=0:
            put(o,QUEUE,1)
        if get(o,RP+104)!=0 or get(o,RP+96)==0:
            return isolate(o,w,1,get(o,RP+8))
        if get(o,RP+8)!=0 and get(o,RP+8)!=11:
            return isolate(o,w,2,103)
        put(o,CLEAN,i+1)
        return again(o,100)
    return isolate(o,w,2,phase)

def finish(o:mutbuf,w:mutbuf,status:u64) -> u32:
    zero(o,0,128)
    put(o,0,R)
    put(o,8,status)
    put(o,80,get(o,QUEUE))
    put(o,88,choose(get(o,QUAR)==2,0,1))
    put(o,104,get(o,QUAR))
    put(o,112,get(o,DETAIL))
    if get(o,PRIMARY)!=0:
        within(o,24,PRIMARY,24)
        put(o,16,2)
        put(o,96,1)
        zero(o,PRIMARY,24)
        if get(w,40)!=0:
            zero(w,384,24)
    if get(o,SUCCESS)==1:
        timeout=get(o,TIMEOUT)
        limit=get(o,LIMIT)
        prove=get(o,PROVE)
        put(o,SUCCESS,0)
        put(o,16,1)
        put(o,96,1)
        put(o,128,timeout)
        put(o,136,limit)
        put(o,144,prove)
        within(o,160,REFS,72)
        within(o,232,REFS+144,24)
        zero(o,REFS,72)
        zero(o,REFS+144,24)
        if get(w,40)!=0:
            zero(w,640,72)
            zero(w,784,24)
            put(w,312,0)
    return 0
def failed(o:mutbuf,status:u64,detail:u64) -> u32:
    put(o,STATUS,status)
    put(o,DETAIL,detail)
    put(o,SUCCESS,0)
    put(o,CLEAN,0)
    return again(o,100)
def dependency(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,RP)!=VR:
        return failed(o,7,get(o,FEEDBACK))
    return failed(o,choose(get(o,RP+8)==5,5,7),get(o,RP+8))
def reject(o:mutbuf,code:u64) -> u32:
    put(o,CODE,code)
    return again(o,60)
def isolate(o:mutbuf,w:mutbuf,kind:u64,detail:u64) -> u32:
    put(o,QUAR,kind)
    put(o,DETAIL,detail)
    to_work(o,w,128,256,896)
    put(w,40,kind)
    return finish(o,w,9)
def cap(o:mutbuf,at:u64) -> bool:
    return get(o,at)!=0 and get(o,at+8)!=0 and get(o,at+16)!=0
def okay(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==VR and get(o,RP+8)==0
def value(o:mutbuf,w:mutbuf,next:u64,n:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,n,RP,16384,get(w,16),get(w,24))
'''
def source_program():
    names={'request','invoke','system','again','copy_source','within','zero','get','put','to_work','from_work','choose'}
    helpers='\n'.join(ast.unparse(f)for f in ast.parse(HELPERS).body if isinstance(f,ast.FunctionDef)and f.name in names)
    text=SOURCE+'\n'+helpers+'\ndef message(o:mutbuf,at:u64,code:u64) -> u64:\n'
    for code,message in ERRORS.items():
        raw=message.encode()
        text+='    if code=='+str(code)+':\n'
        for i in range(0,len(raw),8):text+=f'        put(o,at+{i},{int.from_bytes(raw[i:i+8].ljust(8,bytes(1)),"little")})\n'
        text+='        return '+str(len(raw))+'\n'
    text+='    return 0\n\ndef text_equal(o:mutbuf,at:u64,id:u64) -> bool:\n'
    for id,raw in enumerate((b'Linux',b'x86_64',b'amd64')):
        text+=f'    if id=={id}:\n'
        for i,ch in enumerate(raw+b'\0'):
            text+=f'        if byte(o,at+{i})!={ch}:\n            return False\n'
        text+='        return True\n'
    text+='    return False\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def main():
    tree=document(source_program(),'generation_runtime_constructor_options')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_constructor_options.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
