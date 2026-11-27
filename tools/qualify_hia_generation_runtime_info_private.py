"""Reject all new trusted Info/Value profiles at the public owner boundary."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,mmap,struct
from tools import qualify_hia_generation_lease_owner as q
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 spec=json.loads((a.build/'build.json').read_bytes());so=a.build/'install/hia-generation-component-root.so'
 assert pin(so.read_bytes())==spec['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False)
 owner=q.Owner(so);owner.initialize();rows=[]
 before=bytes(owner.context)
 with mmap.mmap(-1,q.OUT+64)as out:
  out[:1024]=b'\xa5'*1024;out[q.OUT:]=b'\x5a'*64
  checksum=hashlib.sha256(out).hexdigest()
  for magic,ops in((b'HIABVQ12',(116,0,999)),(b'HIABVQ13',(62,63,0,999)),(b'HIABVQ14',(60,64,65,66,0,999))):
   for op in ops:
    inner=bytearray(128);inner[:8]=magic;struct.pack_into('<Q',inner,8,op)
    raw=q.envelope(4,bytes(inner));s=C.create_string_buffer(raw)
    rc=int(owner.entry(s,len(raw),q.address(out),q.OUT,owner.context,q.CONTEXT_BYTES))
    assert rc==q.BAD,(magic,op,rc)
    assert s.raw==raw+b'\0' and bytes(owner.context)==before
    assert hashlib.sha256(out).hexdigest()==checksum,(magic,op)
    rows.append(dict(profile=magic.decode(),op=op,rc=rc,whole_output_unchanged=True,whole_context_unchanged=True))
 reply=owner.call(3);assert reply['status']==0 and reply['state']==3
 assert bytes(owner.context)[128:]==bytes(q.CONTEXT_BYTES-128)
 report=dict(passed=True,controls=len(rows),cases=rows,owner=pin(so.read_bytes()),construction=pin((a.build/'build.json').read_bytes()),qualifier=pin(Path(__file__).read_bytes()),whole_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 print('INFO_PUBLIC_PRIVATE_PROFILES_PASS',len(rows),flush=True)
if __name__=='__main__':main()
