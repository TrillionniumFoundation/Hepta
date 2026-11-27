"""Attach the actual failed-constructor cleanup dictionary to its original exception.

Only fixed native captures enter this continuation. JSON import, descriptor
reads and namespace mutation use the existing deferred Value profiles. The
exception's primary capability remains independent of diagnostic failure.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_generation_runtime_public_factory as prior
ROOT=Path(__file__).resolve().parents[1]
C=dict(prior.C)
C.update(CLEAN_DATA=524872,CLEAN_SIZE=524880,CLEAN_STARTED=524888,
 CLEAN_CAPS=524896,CLEAN_ATTACHED=525064,
 CLTAG=int.from_bytes(b'HIARTCL1','little'),DTAG=int.from_bytes(b'HIABVD01','little'),
 V6=int.from_bytes(b'HIABVQ06','little'),V10=int.from_bytes(b'HIABVQ10','little'))
POLICY="\ndef cleanup_observation(o:mutbuf,w:mutbuf,phase:u64) -> u32:\n    if phase==200:\n        if get(o,FB)!=0:\n            return quarantine(o,w,200)\n        return memory(o,201,0,get(w,MAP)+CARRIER_OUT+get(w,CLEAN_DATA),0,get(w,MAP)+128,get(w,CLEAN_SIZE))\n    if phase==201:\n        if get(o,FB)!=0:\n            return quarantine(o,w,201)\n        return invoke(o,202,17,128+get(w,CLEAN_SIZE))\n    if phase==202 or phase==203 or phase==204 or phase==206:\n        at=CLEAN_CAPS\n        if phase==203:\n            at=CLEAN_CAPS+24\n        elif phase==204:\n            at=CLEAN_CAPS+48\n        elif phase==206:\n            at=CLEAN_CAPS+144\n        state=collect_created(o,w,at)\n        if state==2:\n            return quarantine(o,w,phase)\n        if state!=0 or get(w,VALUE_PENDING)!=0:\n            return again(o,100)\n    if phase==202:\n        cleanup_key(o,0)\n        return invoke(o,203,13,135)\n    if phase==203:\n        request(o,V6,9)\n        to_output(w,o,CLEAN_CAPS,RQ+24,24)\n        to_output(w,o,CLEAN_CAPS+24,RQ+48,24)\n        return invoke(o,204,13,128)\n    if phase==204:\n        request(o,V6,26)\n        to_output(w,o,PRIMARY,RQ+24,24)\n        return invoke(o,205,13,128)\n    if phase==205:\n        if get(o,FB)!=0 or get(o,RP)!=BV:\n            return quarantine(o,w,205)\n        i=0\n        while i<3:\n            src=RP+8224+i*24\n            dst=CLEAN_CAPS+72+i*24\n            if get(o,src)!=0:\n                if get(o,src+8)==0 or get(o,src+16)==0:\n                    return quarantine(o,w,205)\n                from_output(o,w,src,dst,24)\n            elif get(o,src+8)!=0 or get(o,src+16)!=0:\n                return quarantine(o,w,205)\n            i=i+1\n        if get(o,RP+8)!=0 or get(w,VALUE_PENDING)!=0:\n            return again(o,100)\n        if get(o,RP+8200)!=0 or cap(w,CLEAN_CAPS+72)==False or cap(w,CLEAN_CAPS+96)==False or cap(w,CLEAN_CAPS+120)==False:\n            return quarantine(o,w,205)\n        cleanup_key(o,1)\n        return invoke(o,206,13,139)\n    if phase==206:\n        request(o,V6,10)\n        to_output(w,o,CLEAN_CAPS+72,RQ+24,24)\n        to_output(w,o,CLEAN_CAPS+144,RQ+48,24)\n        to_output(w,o,CLEAN_CAPS+48,RQ+72,24)\n        return invoke(o,207,13,128)\n    if phase==207:\n        if get(o,FB)!=0 or get(o,RP)!=BV:\n            return quarantine(o,w,207)\n        if get(o,RP+8)==0:\n            put(w,CLEAN_ATTACHED,1)\n        return again(o,100)\n    return quarantine(o,w,phase)\n\ndef cleanup_key(o:mutbuf,which:u64) -> u64:\n    request(o,V6,2)\n    put(o,RQ+104,4)\n    if which==0:\n        put(o,RQ+96,7)\n        store(o,RQ+128,99)\n        store(o,RQ+129,108)\n        store(o,RQ+130,101)\n        store(o,RQ+131,97)\n        store(o,RQ+132,110)\n        store(o,RQ+133,117)\n        store(o,RQ+134,112)\n    else:\n        put(o,RQ+96,11)\n        put(o,RQ+128,7018134768384567656)\n        store(o,RQ+136,110)\n        store(o,RQ+137,117)\n        store(o,RQ+138,112)\n    return 0\n"
def replace(s,a,b):
    assert s.count(a)==1,(a,s.count(a))
    return s.replace(a,b,1)
def source_program():
    s=prior.SOURCE
    s=replace(s,'    return cleanup(o, w, phase)\n',
      '    if phase >= 200 and phase < 220:\n        return cleanup_observation(o,w,phase)\n    return cleanup(o, w, phase)\n')
    s=replace(s,'        put(w, CHILD_STATUS, get(o, HEAD + 48))\n',
      '        put(w, CHILD_STATUS, get(o, HEAD + 48))\n        put(w, RAW_PENDING, get(o, HEAD + 72))\n')
    marker='            return failure(o, w, 1, get(o, GEN + 16))\n'
    s=replace(s,marker,'''            if get(o,GEN+304)==CLTAG:
                if get(o,GEN+336)!=1:
                    return quarantine(o,w,49)
                at=get(o,GEN+312)
                n=get(o,GEN+320)
                if at<128 or at>CARRIER_SIZE or n==0 or n>CARRIER_SIZE-at or n>CARRIER_OUT+at-128:
                    return quarantine(o,w,49)
                put(w,CLEAN_DATA,at)
                put(w,CLEAN_SIZE,n)
            if get(w,RAW_PENDING)>1:
                return quarantine(o,w,49)
'''+marker)
    marker='    if phase == 100:\n        put(w, STATE, 2)\n        put(w, PENDING, 0)\n'
    s=replace(s,marker,marker+'''        if get(w,CLEAN_SIZE)!=0 and get(w,CLEAN_STARTED)==0:
            put(w,CLEAN_STARTED,1)
            if get(w,DISPOSITION)==2 and cap(w,PRIMARY):
                request(o,V10,1)
                put(o,RQ+96,get(w,CLEAN_SIZE))
                return memory(o,200,3,RQ,0,get(w,MAP),128)
''')
    s=replace(s,'        if i == 9:\n','        if i == 16:\n')
    marker='        elif i >= 5:\n            at = ETMP + (i - 5) * 24\n'
    assert s.count(marker)==2
    s=s.replace(marker,'        elif i >= 9:\n            at = CLEAN_CAPS + (i - 9) * 24\n'+marker)
    s+=POLICY
    old=prior.SOURCE
    try:
        prior.SOURCE=s
        s=prior.source_program()
    finally:
        prior.SOURCE=old
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):
        s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s
def main():
    t=document(source_program(),'generation_runtime_public_cleanup_factory')
    p=ROOT/'examples/hia_bootstrap/generation_runtime_public_cleanup_factory.hepta'
    p.write_text(render_assembly(t))
    print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks'])for f in t['functions']),sum(len(b['ops'])for f in t['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
