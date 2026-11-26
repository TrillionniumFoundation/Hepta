"""Emit a fixed native component catalog from reviewed build-time pins only."""
from pathlib import Path
import argparse,json,re,struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_multiversion_image_packer import emitters
Q=int.from_bytes(b'HIANCAQ1','little')
R=int.from_bytes(b'HIANLCA1','little')
def record(row):
    ident=row['id'];size=row['bytes'];sha=bytes.fromhex(row['sha256'])
    path=row['artifact'].encode('ascii');source=row['source_directory'].encode('ascii');exports=row['exports']
    assert isinstance(ident,int)and 0<ident<2**64 and 64<=size<=67108864 and len(sha)==32
    assert path and source and not path.startswith(b'/')and not source.startswith(b'/')and b'\0'not in path+source
    assert 0<len(exports)<=128 and len(exports)==len(set(exports))
    assert all(isinstance(n,str)and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,127}',n)for n in exports)
    body=path+source+b''.join(struct.pack('<Q',len(n))+n.encode('ascii')for n in exports)
    raw=struct.pack('<8Q',R,ident,size,len(path),len(source),len(exports),len(body),0)+sha+bytes(32)+body
    assert len(raw)<=65536
    return raw
def source_program(rows):
    assert rows and len({r['id']for r in rows})==len(rows)
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
    for index,row in enumerate(rows):
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
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    rows=json.loads(a.manifest.read_text())['components'];tree=document(source_program(rows),'native_fixed_component_catalog')
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(render_assembly(tree))
    print(a.output.name,a.output.stat().st_size,len(tree['functions']),sum(len(f['blocks'])for f in tree['functions']),sum(len(b['ops'])for f in tree['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
