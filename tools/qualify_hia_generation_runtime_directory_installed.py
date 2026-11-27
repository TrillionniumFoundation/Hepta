"""Original late-directory assertions on the installed native child.

This development fixture only calls native initialization/retirement exports.
No prefix, pointer, support mask, or receipt is written by the host.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct
from tools import qualify_hia_generation_runtime_directory as directory
q=directory.q
OriginalFixture=directory.custody.Fixture
class InstalledFixture(OriginalFixture):
 def __init__(self,path,out):
  super().__init__(path,out)
  self.initial_active,self.initial_side=self.active,self.side
  self.front=C.create_string_buffer(1<<20)
  self.installout=C.create_string_buffer(3<<20)
  self.installer=self.entry('hia_generation_runtime_frontend_install')
  self.binder=self.entry('hia_generation_runtime_frontend_bind')
  row=self.install(0)
  assert row['status']==0 and row['state']==2 and row['known']==1 and row['pending']==row['sessions']==0,row
  row=self.bind(0)
  assert row['status']==0 and row['state']==1 and row['known']==1 and row['pending']==row['retired']==0,row
  row=self.install(1);assert row['status']==6 and row['state']==2 and row['sessions']==1 and row['active']==0,row
  self.active=q.get(self.owner.context,72);self.side=q.get(self.owner.context,1208)
 def entry(self,name):
  f=getattr(self.owner.lib,name);f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32;return f
 def wire(self,magic,op):
  s=bytearray(128);s[:8]=magic;struct.pack_into('<Q',s,8,op);return bytes(s)
 def invoke(self,f,magic,op,out):
  raw=self.wire(magic,op);s=C.create_string_buffer(raw)
  rc=int(f(s,128,out,len(out),self.owner.context,2048))
  assert s.raw==raw+b'\0';return rc
 def install(self,op):
  rc=self.invoke(self.installer,b'HIARTIQ1',op,self.installout);raw=self.installout.raw
  assert rc==0 and raw[:8]==b'HIARTIR1',(rc,raw[:128].hex())
  return {k:q.get(raw,at)for k,at in dict(status=8,state=16,known=24,pending=32,retired=40,active=56,guards=72,sessions=104).items()}
 def bind(self,op):
  rc=self.invoke(self.binder,b'HIARTBQ1',op,self.front);raw=self.front.raw[1024:1152]
  assert rc==0 and raw[:8]==b'HIARTBR1',(rc,raw.hex())
  return {k:q.get(raw,at)for k,at in dict(status=8,state=16,pending=80,known=88,retired=104).items()}
 def finish(self):
  self.guard(0)
  row=self.bind(1);assert row==dict(status=0,state=3,pending=0,known=1,retired=1),row
  before=self.front.raw
  assert self.bind(1)==row and self.front.raw==before
  closed=self.install(1)
  assert closed==dict(status=0,state=4,known=1,pending=0,retired=1,active=0,guards=0,sessions=0),closed
  assert self.bind(1)==row and self.front.raw==before
  self.active,self.side=self.initial_active,self.initial_side
  result=super().finish()
  return dict(**result,actual_installed_frontend=True,repeated_retire_ack_before_and_after_unload=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',nargs='*',choices=directory.CASES);a=p.parse_args()
 spec=json.loads((a.build/'build.json').read_bytes());path=a.build/'install/hia-generation-component-root.so'
 assert directory.custody.pin(path.read_bytes())==spec['products']['hia-generation-component-root.so']
 a.output.mkdir(parents=True,exist_ok=False);rows=[]
 directory.custody.Fixture=InstalledFixture
 for name in a.cases or directory.CASES:
  here=a.output/name;here.mkdir()
  rows.append(directory.isolated(name,lambda name=name,here=here:directory.one(path,here,name)))
  (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n')
  print('RUNTIME_INSTALLED_DIRECTORY_PASS',name,flush=True)
 report=dict(passed=True,groups=len(rows),cases=rows,owner=directory.custody.pin(path.read_bytes()),construction=directory.custody.pin((a.build/'build.json').read_bytes()),qualifier=directory.custody.pin(Path(__file__).read_bytes()),original_qualifier=directory.custody.pin(Path(directory.__file__).read_bytes()),original_assertions_unchanged=True,actual_installed_frontend=True,public_constructor_qualified=False,whole_runtime_qualified=False)
 (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 print('RUNTIME_INSTALLED_DIRECTORY_ACTUAL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
