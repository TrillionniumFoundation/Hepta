"""Exact public runtime option admission through captured actual values."""
from pathlib import Path
import ast,json,re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools.generate_hia_background_optimizer_value_freeze import SOURCE as HELPERS
ROOT=Path(__file__).resolve().parents[1]
C={'MAGIC':int.from_bytes(b'HIAMVOP1','little'),'REPLY':int.from_bytes(b'HIAMVOR1','little'),
'CONTEXT':int.from_bytes(b'HIAMVOC1','little'),'VREQUEST':int.from_bytes(b'HIABVQ01','little'),
'VREPLY':int.from_bytes(b'HIABVR01','little'),'BAD':4294967293,'MAX':(1<<64)-1,
'PHASE':256,'INDEX':264,'TIMEOUT':272,'MAXLIVE':280,'PROVE':288,'SCALARN':296,
'RQ':4096,'RP':8192,'ERR':2048,'FEEDBACK':3840}
ERRORS={
1:'E_HIA_MULTIVERSION: translation validation timeout must be 1..30000 milliseconds',
2:'E_HIA_MULTIVERSION: live generation limit must be 2..64',
3:'E_HIA_MULTIVERSION: prove_total must be an explicit Boolean profile choice'}
SOURCE=r"""
def options(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(o)<32768 or length(w)<128:
        return BAD
    phase=get(o,PHASE)
    if phase==0:
        return begin(s,o,w)
    if phase==1:
        pid=get(o,FEEDBACK)
        if pid!=get(w,32):
            return finish(o,3,0,pid)
        put(o,TIMEOUT,2000)
        put(o,MAXLIVE,8)
        return again(o,2)
    if phase==2:
        i=get(o,INDEX)
        if i==3:
            return finish(o,0,0,0)
        at=24+i*24
        if word_load(s,at)==0 and word_load(s,at+8)==0 and word_load(s,at+16)==0:
            put(o,INDEX,i+1)
            return again(o,2)
        request(o,VREQUEST,7)
        copy_source(s,o,at,RQ+24,24)
        return value(o,w,3)
    if phase==3:
        if value_ok(o)==False:
            return dependency(o)
        i=get(o,INDEX)
        expected=2
        if i==2:
            expected=1
        if get(o,RP+16)!=expected:
            return finish(o,1,i+1,0)
        n=get(o,RP+72)
        if i<2:
            maximum=5
            if i==1:
                maximum=2
            if n==0 or n>maximum:
                return finish(o,1,i+1,0)
        elif n==0 or n>8:
            return finish(o,3,0,19)
        put(o,SCALARN,n)
        request(o,VREQUEST,19)
        copy_source(s,o,24+i*24,RQ+24,24)
        put(o,RQ+112,n)
        return value(o,w,4)
    if phase==4:
        if value_ok(o)==False:
            return dependency(o)
        n=get(o,SCALARN)
        if get(o,RP+64)!=n or get(o,RP+72)!=n:
            return finish(o,3,0,19)
        i=get(o,INDEX)
        number=0
        if i==2:
            j=0
            while j<n:
                number=number|(byte(o,RP+8192+j)<<(j*8))
                j=j+1
            if number>1 or get(o,RP+16)!=1:
                return finish(o,3,0,19)
            put(o,PROVE,number)
        else:
            if get(o,RP+16)!=2:
                return finish(o,3,0,19)
            j=0
            while j<n:
                ch=byte(o,RP+8192+j)
                if ch<48 or ch>57:
                    return finish(o,1,i+1,0)
                number=number*10+ch-48
                j=j+1
            minimum=1
            maximum=30000
            if i==1:
                minimum=2
                maximum=64
            if number<minimum or number>maximum:
                return finish(o,1,i+1,0)
            if i==0:
                put(o,TIMEOUT,number)
            else:
                put(o,MAXLIVE,number)
        put(o,INDEX,i+1)
        return again(o,2)
    return BAD
def begin(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word_load(s,0)!=MAGIC or word_load(s,8)!=0:
        return BAD
    i=16
    while i<128:
        used=i>=24 and i<=88
        if used==False and word_load(s,i)!=0:
            return BAD
        i=i+8
    if get(w,0)!=CONTEXT or get(w,8)==0 or get(w,16)==0 or get(w,24)<256:
        return BAD
    if get(w,16)>MAX-get(w,24) or get(w,32)<2 or get(w,32)>2147483647:
        return BAD
    i=40
    while i<128:
        if get(w,i)!=0:
            return BAD
        i=i+8
    zero(o,128,3968)
    return system(o,1,39,0,0,0,0,0,0,0)
def value(o:mutbuf,w:mutbuf,next:u64) -> u32:
    return invoke(o,next,get(w,8),51,RQ,128,RP,16384,get(w,16),get(w,24))
def value_ok(o:mutbuf) -> bool:
    return get(o,FEEDBACK)==0 and get(o,RP)==VREPLY and get(o,RP+8)==0
def dependency(o:mutbuf) -> u32:
    if get(o,FEEDBACK)!=0 or get(o,RP)!=VREPLY:
        return finish(o,3,0,get(o,FEEDBACK))
    status=get(o,RP+8)
    if status==5:
        return finish(o,2,0,status)
    return finish(o,3,0,status)
def finish(o:mutbuf,status:u64,code:u64,detail:u64) -> u32:
    timeout=get(o,TIMEOUT)
    maximum=get(o,MAXLIVE)
    prove=get(o,PROVE)
    zero(o,0,128)
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,code)
    put(o,56,detail)
    if status==0:
        put(o,24,timeout)
        put(o,32,maximum)
        put(o,40,prove)
    elif status==1:
        n=error_text(o,code)
        put(o,48,n)
        within(o,128,ERR,n)
    return 0
"""
def source_program():
    names={'request','invoke','system','again','copy_source','within','zero','get','put'}
    helpers='\n'.join(ast.unparse(f) for f in ast.parse(HELPERS).body if isinstance(f,ast.FunctionDef)and f.name in names)
    text=SOURCE+'\n'+helpers+'\ndef error_text(o:mutbuf,code:u64) -> u64:\n'
    for code,message in sorted(ERRORS.items()):
        raw=json.dumps({'class':'MultiversionRejected','message':message},sort_keys=True,separators=(',',':')).encode()
        text+=f'    if code=={code}:\n'
        for i in range(0,len(raw),8):
            text+=f'        put(o,ERR+{i},{int.from_bytes(raw[i:i+8].ljust(8,bytes(1)),"little")})\n'
        text+=f'        return {len(raw)}\n'
    text+='    return 0\n'
    for key,value in sorted(C.items(),key=lambda x:-len(x[0])):text=re.sub(r'\b'+key+r'\b',str(value),text)
    return text
def program():return document(source_program(),'multiversion_runtime_public_options')
def main():
    d=program();p=ROOT/'examples/hia_bootstrap/multiversion_runtime_public_options.hepta'
    p.write_text(render_assembly(d))
    print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
