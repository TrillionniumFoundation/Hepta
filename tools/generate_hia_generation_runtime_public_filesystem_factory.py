"""Real OSError construction from captured native directory syscall failures."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_runtime_public_cleanup_factory as prior
from tools import generate_hia_native_path_string_codec as codec
ROOT=Path(__file__).resolve().parents[1]
C=dict(prior.C)
C.update(FSCAPS=525088,FSERR=525232,FSN=525240,FSPATH=525248,FSINDEX=525256,
 MSGN=525264,MSGPTR=525272,PATHBUF=65536,ERRTEXT=524288,OSBYTE=524280,
 FSTAG=int.from_bytes(b'HIARTFE1','little'))
POLICY=r'''
def filesystem_failure(o:mutbuf,w:mutbuf,phase:u64) -> u32:
    r=get(o,FB)
    if phase==300 or phase==301 or phase==306 or phase==309 or phase==310 or phase==312 or phase==313:
        at=FSCAPS
        if phase==301:
            at=FSCAPS+24
        elif phase==306:
            at=FSCAPS+48
        elif phase==309:
            at=FSCAPS+72
        elif phase==310:
            at=FSCAPS+96
        elif phase==312:
            at=FSCAPS+120
        elif phase==313:
            at=PRIMARY
        state=collect_created(o,w,at)
        if phase==313 and cap(w,PRIMARY):
            put(w,DISPOSITION,2)
        if state==2:
            return quarantine(o,w,phase)
        if state!=0:
            return failure(o,w,choose(get(o,RP+8)==5,5,7),phase)
    if phase==300:
        request(o,V10,1)
        n=filesystem_number(o,get(w,FSERR))
        put(o,RQ+96,n)
        return invoke(o,301,13,128+n)
    if phase==301:
        return invoke(o,303,18,0)
    if phase==303:
        if r==0 or r>=NEG:
            return failure(o,w,7,303)
        put(w,MSGPTR,r)
        put(w,MSGN,0)
        return memory(o,304,0,r,3,OSBYTE,1)
    if phase==304:
        if r!=0:
            return quarantine(o,w,304)
        n=get(w,MSGN)
        b=byte(o,OSBYTE)
        if b==0:
            request(o,V6,2)
            put(o,RQ+104,4)
            n=filesystem_decode(o,ERRTEXT,n)
            put(o,RQ+96,n)
            return memory(o,305,3,RQ,0,get(w,MAP),128+n)
        if n>=131071:
            return failure(o,w,7,304)
        store(o,ERRTEXT+n,b)
        put(w,MSGN,n+1)
        return memory(o,304,0,get(w,MSGPTR)+n+1,3,OSBYTE,1)
    if phase==305:
        if r!=0:
            return quarantine(o,w,305)
        return invoke(o,306,17,128+get(o,RQ+96))
    if phase==306:
        return memory(o,307,0,get(w,MAP)+CARRIER_OUT+get(w,FSPATH),3,PATHBUF,get(w,FSN))
    if phase==307:
        if r!=0:
            return quarantine(o,w,307)
        request(o,V6,2)
        put(o,RQ+104,4)
        n=filesystem_decode(o,PATHBUF,get(w,FSN))
        put(o,RQ+96,n)
        return memory(o,308,3,RQ,0,get(w,MAP),128+n)
    if phase==308:
        if r!=0:
            return quarantine(o,w,308)
        return invoke(o,309,17,128+get(o,RQ+96))
    if phase==309:
        request(o,V7,3)
        return invoke(o,310,13,128)
    if phase==310:
        put(w,FSINDEX,0)
        return filesystem_append(o,w)
    if phase==311:
        if r!=0 or get(o,RP)!=BV:
            return quarantine(o,w,311)
        if get(o,RP+8)!=0:
            return failure(o,w,choose(get(o,RP+8)==5,5,7),311)
        i=get(w,FSINDEX)+1
        put(w,FSINDEX,i)
        if i<3:
            return filesystem_append(o,w)
        request(o,V11,40)
        to_output(w,o,FSCAPS+96,RQ+24,24)
        return invoke(o,312,13,128)
    if phase==312:
        request(o,V11,104)
        to_output(w,o,FSCAPS,RQ+24,24)
        to_output(w,o,FSCAPS+120,RQ+48,24)
        return invoke(o,313,13,128)
    if phase==313:
        return again(o,100)
    return quarantine(o,w,phase)

def filesystem_begin(o:mutbuf,w:mutbuf) -> u32:
    raw=get(o,GEN+352)
    at=get(o,GEN+360)
    n=get(o,GEN+368)
    if raw<NEG or n==0 or n>4095 or at<128 or at>CARRIER_SIZE-n:
        return quarantine(o,w,299)
    if cap(w,PRIMARY):
        return failure(o,w,1,get(o,GEN+16))
    put(w,FSERR,0-raw)
    put(w,FSN,n)
    put(w,FSPATH,at)
    put(w,STATUS,1)
    put(w,DETAIL,get(o,GEN+16))
    request(o,V11,32)
    put(o,RQ+104,25)
    return invoke(o,300,13,128)

def filesystem_append(o:mutbuf,w:mutbuf) -> u32:
    request(o,V7,16)
    to_output(w,o,FSCAPS+96,RQ+24,24)
    to_output(w,o,FSCAPS+24+get(w,FSINDEX)*24,RQ+48,24)
    return invoke(o,311,13,128)

def filesystem_number(o:mutbuf,value:u64) -> u64:
    n=1
    if value>=1000:
        n=4
    elif value>=100:
        n=3
    elif value>=10:
        n=2
    place=1000
    if n==3:
        place=100
    elif n==2:
        place=10
    elif n==1:
        place=1
    i=0
    while i<n:
        digit=0
        while value>=place:
            value=value-place
            digit=digit+1
        store(o,RQ+128+i,48+digit)
        if place==1000:
            place=100
        elif place==100:
            place=10
        else:
            place=1
        i=i+1
    return n

def filesystem_decode(o:mutbuf,at:u64,n:u64) -> u64:
    i=0
    count=0
    while i<n:
        b=byte(o,at+i)
        width=filesystem_utf8_width(o,at+i,n-i)
        if width==0:
            store(o,RQ+128+count,237)
            store(o,RQ+129+count,176+(b>>6))
            store(o,RQ+130+count,128+(b&63))
            count=count+3
            i=i+1
        else:
            j=0
            while j<width:
                store(o,RQ+128+count,byte(o,at+i+j))
                count=count+1
                j=j+1
            i=i+width
    return count
'''
def replace(s,a,b):
    assert s.count(a)==1,(a,s.count(a))
    return s.replace(a,b,1)
def source_program():
    s=prior.source_program()
    s=replace(s,'    return cleanup(o, w, phase)\n','    if phase >= 300 and phase < 320:\n        return filesystem_failure(o,w,phase)\n    return cleanup(o, w, phase)\n')
    marker=f"            return failure(o, w, 1, get(o, {C['GEN']} + 16))\n"
    s=replace(s,marker,f"""            if get(o,{C['GEN']}+344)=={C['FSTAG']}:
                return filesystem_begin(o,w)
"""+marker)
    s=replace(s,'        if i == 16:\n','        if i == 22:\n')
    marker=f"        elif i >= 9:\n            at = {C['CLEAN_CAPS']} + (i - 9) * 24\n"
    assert s.count(marker)==2,s.count(marker)
    s=s.replace(marker,f"        elif i >= 16:\n            at = {C['FSCAPS']} + (i - 16) * 24\n"+marker)
    s+=POLICY
    helper=re.search(r'^def utf8_width\(.*?(?=^def |\Z)',codec.SOURCE,re.M|re.S).group(0)
    s+='\n'+helper.replace('utf8_width','filesystem_utf8_width').replace('s:readbuf','s:mutbuf')
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):
        s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
def main():
    t=document(source_program(),'generation_runtime_public_filesystem_factory')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_public_filesystem_factory.hepta';p.write_text(render_assembly(t))
    print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
