"""Original capture-before-receipt ordering, with the same actual image holder."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image as image
from tools import generate_hia_multiversion_prepare_build as build
ROOT=Path(__file__).resolve().parents[1]
C={**image.CONSTANTS,'INPUT_MAGIC':int.from_bytes(b'HIAMVI02','little'),
   'JSON':73<<20,'ARENA':75<<20,'JSONWORK':91<<20,
   'CORE_SHA':1800,'RECEIPT_N':1832,'ARTIFACT_SHA':1840,'OBJECT_SHA':1872,'TEXT_SHA':1904,'EXPECTED':1936}
def source_program():
    s=image.POLICY
    replacements=[
      ('length(s)<64 or readword(s,0)!=INPUT_MAGIC','length(s)<128 or readword(s,0)!=INPUT_MAGIC'),
      ('expected_n=readword(s,24)','expected_n=64\n    receipt_n=readword(s,24)'),
      ('path_n>length(s)-64','path_n>length(s)-128'),
      ('if abi_n!=length(s)-64-path_n or abi_n<16:', 'if receipt_n==0 or receipt_n>1048576 or receipt_n>length(s)-128-path_n:\n        return 4294967293\n    if abi_n!=length(s)-128-path_n-receipt_n or abi_n<16:'),
      ('a=64+path_n','a=128+path_n'),
      ('byte(s,64+i)','byte(s,128+i)'),
      ('store(w,1700+i,byte(s,32+i))','store(w,CORE_SHA+i,byte(s,32+i))'),
      ('    return image_syscall(o,w,10,39,0,0,0,0,0,0,0)','''    i=64
    while i<128:
        if readword(s,i)!=0:
            return 4294967293
        i=i+8
    put(w,RECEIPT_N,receipt_n)
    i=0
    while i<receipt_n:
        store(w,JSON+i,byte(s,128+path_n+abi_n+i))
        i=i+1
    return image_syscall(o,w,10,39,0,0,0,0,0,0,0)'''),
      ('        put(w,200,n)\n        put(w,72,0)','        put(w,200,n)\n        put(w,64,n)\n        put(w,72,0)')
    ]
    for a,b in replacements:
        assert a in s,a;s=s.replace(a,b)
    start=s.index('    if phase==42:');end=s.index('    if phase==43:',start)
    old=s[start:end];prefix='''    if phase==42:
        if raw!=32 or image_equal(w,SHA_OUT,1700,32)==0:
            return image_fail(o,w,12,raw)
'''
    assert old.startswith(prefix)
    inspector=old[len(prefix):]
    # This branch is reached only after full raw read/stat/identity checks and
    # an actual complete artifact SHA. The pin remains owned throughout.
    replacement='''    if phase==42:
        if raw!=32:
            return image_fail(o,w,13,raw)
        image_copy(w,1700,SHA_OUT,32)
        i=0
        while i<128:
            store(w,JSONWORK+i,0)
            i=i+1
        put(w,JSONWORK+48,131073)
        put(w,JSONWORK+56,128)
        return image_role(o,w,49,7,JSON,get(w,RECEIPT_N),ARENA,16777216,JSONWORK,8388608)
    if phase==49:
        if raw<64 or raw>16777216:
            return image_fail(o,w,12,raw)
        if check_receipt(w)==False:
            return image_fail(o,w,12,0)
        if get(w,240)!=get(w,64) or image_equal(w,ARTIFACT_SHA,SHA_OUT,32)==0:
            return image_fail(o,w,12,0)
        return image_inspect(o,w)
'''
    s=s[:start]+replacement+s[end:]
    s+='\ndef image_inspect(o:mutbuf,w:mutbuf) -> u32:\n'+''.join(line[4:]+'\n' for line in inspector.splitlines())
    s+='\n'+build.SOURCE[build.SOURCE.index('def check_receipt('):build.SOURCE.index('def image_read(')]
    s+='\n'+build.SOURCE[build.SOURCE.index('def equal('):build.SOURCE.index('def abi_valid(')]
    s+='\n'+build.labels()
    for key,value in [('MEMNAME',b'hepta-hia-'),('FDPATH',b'/proc/self/fd/'),('MAPSPATH',b'/proc/self/maps\0')]:
        s=s.replace(key+'_LITERAL','\n'.join(f'    store(w,{key}+{i},{c})' for i,c in enumerate(value)))
    for k,v in sorted(C.items(),key=lambda x:-len(x[0])):s=re.sub(r'\b'+k+r'\b',str(v),s)
    return s

def main():
    t=document(source_program(),'multiversion_prepare_image');p=ROOT/'examples/hia_bootstrap/multiversion_prepare_image.hepta';p.write_text(render_assembly(t));print(p.name,p.stat().st_size,len(t['functions']),sum(len(f['blocks']) for f in t['functions']),flush=True)
if __name__=='__main__':main()
