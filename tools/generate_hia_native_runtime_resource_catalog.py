"""Reviewed build-time fixed native Runtime/BG/LLVM resource pins."""
from pathlib import Path
import re,struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_multiversion_image_packer import emitters
ROOT=Path(__file__).resolve().parents[1]
Q=int.from_bytes(b'HIANGCQ1','little');R=int.from_bytes(b'HIANGCA1','little')
RESOURCES=(
 dict(id=1,artifact='components/hia-normalizer.bin',bytes=5980873,sha256='84619bd15d8408f52c04519af11664cc4fa52cac352e7ad6680b6d50429123c6'),
 dict(id=2,artifact='components/hia-proof.bin',bytes=3486129,sha256='3fc158954dbecbde001d51065347a4e10e728f3c503816525da853babf2ffb3a'),
 dict(id=3,artifact='components/hia-builder.bin',bytes=3819682,sha256='539ce9aab49b6f3e04517a511b08a6351421f86b978e03510ea3220e90f231e0'),
 dict(id=4,artifact='source/examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat',bytes=10100891,sha256='735f15939ea8fbf91283013a1719773d01018683e1fdb417c3f18ce22f2f1706'))
def record(row):
    path=row['artifact'].encode('ascii');source=b'source'
    assert path and not path.startswith(b'/') and all(p not in(b'',b'.',b'..')for p in path.split(b'/'))and b'\0'not in path
    assert row['id']in(1,2,3,4)and 64<=row['bytes']<=67108864
    return struct.pack('<8Q',R,row['id'],row['bytes'],len(path),len(source),row['id'],len(path)+len(source),0)+bytes.fromhex(row['sha256'])+bytes(32)+path+source
def source_program():
    head=f'''def catalog(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=128 or word(s,0)!={Q} or length(w)<64:
        return 4294967293
    i=16
    while i<128:
        if word(s,i)!=0:
            return 4294967293
        i=i+8
'''
    functions=[]
    for index,row in enumerate(RESOURCES):
        raw=record(row);calls,body=emitters('record_'+str(index),raw);functions.append(body)
        head+=f'''    if word(s,8)=={row['id']}:
        if length(o)<{len(raw)}:
            return 4294967294
'''
        for fn in calls:head+='        '+fn+'(o,0)\n'
        head+=f'        return {len(raw)}\n'
    head+='    return 4294967293\n'
    return head+'\n'+'\n'.join(functions)+r'''
def word(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(i*8))
        i=i+1
    return value
def write(w:mutbuf,at:u64,value:u64,n:u64) -> u64:
    i=0
    while i<n:
        store(w,at+i,(value>>(i*8))&255)
        i=i+1
    return 0
'''
def main():
    tree=document(source_program(),'native_runtime_resource_catalog')
    p=ROOT/'examples/hia_bootstrap/native_runtime_resource_catalog.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
