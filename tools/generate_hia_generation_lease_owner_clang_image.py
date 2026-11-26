"""Actual Clang receipt to the existing pinned native image holder.

HIAMVI03 is private to the fixed enclosing producer. Four digest facts come
from actual admitted Core/input, a fresh fixed LLVM emission and the real Clang
producer. They are checked only after the artifact has been pinned and read.
The legacy VI01 and VI02 policies remain unchanged.
"""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_multiversion_image as image
from tools import generate_hia_multiversion_prepare_build as helper
ROOT=Path(__file__).resolve().parents[1]
C={**image.CONSTANTS,'INPUT_MAGIC':int.from_bytes(b'HIAMVI03','little'),
 'JSON':73<<20,'ARENA':75<<20,'JSONWORK':91<<20,
 'CORE_SHA':1800,'INPUT_SHA':1832,'IR_SHA':1864,'NATIVE_ARTIFACT_SHA':1896,
 'RECEIPT_N':1928,'EXPECTED':1936}
LABELS={1:'core_sha256',2:'input_sha256',3:'llvm_ir_sha256',4:'artifact_sha256',
        5:'artifact_bytes',6:'target',7:'x86_64-unknown-linux-gnu',8:'kind',9:'shared'}
CHECK=r'''
def check_receipt(w:mutbuf) -> bool:
    if node(w,0,0)!=6:
        return False
    if string_id(w,field(w,0,6))!=7 or string_id(w,field(w,0,8))!=9:
        return False
    if digest(w,field(w,0,1),EXPECTED)==False or equal(w,EXPECTED,CORE_SHA,32)==False:
        return False
    if digest(w,field(w,0,2),EXPECTED)==False or equal(w,EXPECTED,INPUT_SHA,32)==False:
        return False
    if digest(w,field(w,0,3),EXPECTED)==False or equal(w,EXPECTED,IR_SHA,32)==False:
        return False
    if digest(w,field(w,0,4),EXPECTED)==False or equal(w,EXPECTED,SHA_OUT,32)==False:
        return False
    if equal(w,EXPECTED,NATIVE_ARTIFACT_SHA,32)==False:
        return False
    amount=number(w,field(w,0,5))
    return amount==get(w,64) and amount>=64 and amount<=67108864
'''
def replace_once(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new)
def labels():
    old=helper.LABELS
    try:
        helper.LABELS=LABELS
        return helper.labels()
    finally:helper.LABELS=old
def source_program():
    s=image.POLICY
    changes=[
      ('length(s)<64 or readword(s,0)!=INPUT_MAGIC','length(s)<256 or readword(s,0)!=INPUT_MAGIC'),
      ('expected_n=readword(s,24)','expected_n=64\n    receipt_n=readword(s,24)'),
      ('path_n>length(s)-64','path_n>length(s)-256'),
      ('if abi_n!=length(s)-64-path_n or abi_n<16:',
       'if receipt_n==0 or receipt_n>1048576 or receipt_n>length(s)-256-path_n:\n        return 4294967293\n    if abi_n!=length(s)-256-path_n-receipt_n or abi_n<16:'),
      ('a=64+path_n','a=256+path_n'),
      ('byte(s,64+i)','byte(s,256+i)'),
      ('store(w,1700+i,byte(s,32+i))','store(w,CORE_SHA+i,byte(s,32+i))'),
      ('    return image_syscall(o,w,10,39,0,0,0,0,0,0,0)',"""
    i=160
    while i<256:
        if readword(s,i)!=0:
            return 4294967293
        i=i+8
    i=0
    while i<96:
        store(w,INPUT_SHA+i,byte(s,64+i))
        i=i+1
    put(w,RECEIPT_N,receipt_n)
    i=0
    while i<receipt_n:
        store(w,JSON+i,byte(s,256+path_n+abi_n+i))
        i=i+1
    return image_syscall(o,w,10,39,0,0,0,0,0,0,0)"""),
      ('        put(w,200,n)\n        put(w,72,0)','        put(w,200,n)\n        put(w,64,n)\n        put(w,72,0)')
    ]
    for old,new in changes:
        assert old in s,old
        s=s.replace(old,new)
    start=s.index('    if phase==42:');end=s.index('    if phase==43:',start)
    original=s[start:end]
    prefix='''    if phase==42:
        if raw!=32 or image_equal(w,SHA_OUT,1700,32)==0:
            return image_fail(o,w,12,raw)
'''
    assert original.startswith(prefix)
    inspector=original[len(prefix):]
    s=s[:start]+'''    if phase==42:
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
        if raw<64 or raw>16777216 or check_receipt(w)==False:
            return image_fail(o,w,12,raw)
        return image_inspect(o,w)
'''+s[end:]
    s+='\ndef image_inspect(o:mutbuf,w:mutbuf) -> u32:\n'+''.join(line[4:]+'\n' for line in inspector.splitlines())
    s+='\n'+CHECK
    s+='\n'+helper.SOURCE[helper.SOURCE.index('def number('):helper.SOURCE.index('def image_read(')]
    s+='\n'+helper.SOURCE[helper.SOURCE.index('def equal('):helper.SOURCE.index('def abi_valid(')]
    s+='\n'+labels()
    for key,value in [('MEMNAME',b'hepta-hia-'),('FDPATH',b'/proc/self/fd/'),('MAPSPATH',b'/proc/self/maps\0')]:
        s=s.replace(key+'_LITERAL','\n'.join(f'    store(w,{key}+{i},{c})' for i,c in enumerate(value)))
    for key,value in sorted(C.items(),key=lambda item:-len(item[0])):
        s=re.sub(r'\b'+key+r'\b',str(value),s)
    return s
def main():
    tree=document(source_program(),'generation_lease_owner_clang_image')
    path=ROOT/'examples/hia_bootstrap/generation_lease_owner_clang_image.hepta'
    path.write_text(render_assembly(tree))
    print(path.name,path.stat().st_size,len(tree['functions']),
          sum(len(f['blocks'])for f in tree['functions']),
          sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
