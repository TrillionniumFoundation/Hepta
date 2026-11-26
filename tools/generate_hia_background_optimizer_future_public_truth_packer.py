"""Fixed native cleanup/truth capsule; both policies share the actual continuation."""
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_multiversion_future import document
from tools import generate_hia_multiversion_image_packer as common
ROOT=Path(__file__).resolve().parents[1]
MAGIC=int.from_bytes(b'HIABFTPK','little')
ROLES=('cleanup','truth')
BRIDGE=bytes.fromhex('4881f90000010072124885d2740d4881ba80000000080700007305e900000000e900000000')
HOLES={'cleanup': 28, 'truth': 33}
def reference_flat(parts):
 if len(parts)!=2 or any(not x or len(x)>4194304 for x in parts):raise ValueError('two bounded native roles required')
 out=bytearray(BRIDGE)
 for role,body in zip(ROLES,parts):
  out.extend(bytes((-len(out))%16));at=len(out)
  struct.pack_into('<i',out,HOLES[role],at-HOLES[role]-4)
  out.extend(body)
 if len(out)>4194304:raise ValueError('original four MiB role bound')
 return bytes(out)
def source_program():
 calls,emitters=common.emitters('bridge',BRIDGE)
 s=f'''def pack(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w)<128:
        return 4294967294
    if length(s)<32 or uint(s,0,8)!={MAGIC} or uint(s,8,8)!=2:
        return 4294967295
    a=uint(s,16,8)
    b=uint(s,24,8)
    if a==0 or b==0 or a>4194304 or b>4194304 or length(s)!=32+a+b:
        return 4294967295
    x=({len(BRIDGE)}+15)&18446744073709551600
    y=(x+a+15)&18446744073709551600
    size=y+b
    if size>4194304:
        return 4294967295
    if length(o)<size:
        return 4294967294
    i=0
    while i<size:
        store(o,i,0)
        i=i+1
'''
 for fn in calls:s+=f'    {fn}(o,0)\n'
 for role,at in [('cleanup','x'),('truth','y')]:
  h=HOLES[role];s+=f'    write(o,{h},{at}-{h+4},4)\n'
 s+='''    copy(s,o,32,x,a)
    copy(s,o,32+a,y,b)
    return size
'''
 return s+'\n'+emitters+common.HELPERS
def program():return document(source_program(),'background_optimizer_future_public_truth_packer')
def main():
 d=program();p=ROOT/'examples/hia_bootstrap/background_optimizer_future_public_truth_packer.hepta'
 p.write_text(render_assembly(d));print(p.name,p.stat().st_size,len(d['functions']),sum(len(f['blocks'])for f in d['functions']),sum(len(b['ops'])for f in d['functions']for b in f['blocks']),flush=True)
if __name__=='__main__':main()
