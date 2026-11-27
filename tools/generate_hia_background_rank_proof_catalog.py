"""Reviewed build-time fixed native Runtime/BG/LLVM resource pins."""
from pathlib import Path
import re,struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_multiversion_image_packer import emitters
ROOT=Path(__file__).resolve().parents[1]
Q=int.from_bytes(b'HIABPCQ1','little');R=int.from_bytes(b'HIABPCA1','little')
RESOURCES=(dict(id=1,artifact='components/hia-rank-public-proof.bin',bytes=16159172,
 sha256='744900be77472942723f0f9b3d640825cb48a75ae5bcb4a166092a0ddf0dc4f6'),)

def record(row):
    path=row['artifact'].encode('ascii');source=b'source'
    assert path and not path.startswith(b'/') and all(p not in(b'',b'.',b'..')for p in path.split(b'/'))and b'\0'not in path
    assert row['id']==1 and 64<=row['bytes']<=67108864
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
    tree=document(source_program(),'background_rank_proof_catalog')
    p=ROOT/'examples/hia_bootstrap/background_rank_proof_catalog.hepta'
    p.write_text(render_assembly(tree))
    print(p.name,p.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
