"""Actual same-root trusted resource initialization and retirement."""
from pathlib import Path
import argparse,ctypes as C,errno,fcntl,hashlib,json,os,struct
from tools import qualify_hia_generation_lease_owner as q
from tools import qualify_hia_native_runtime_resources as resources
from tools import qualify_hia_native_fixed_component_loader as faults
from tools import qualify_hia_generation_lease_owner_tempdir as tq
from tools.qualify_hia_clang_capture_faults import isolated
from tools import generate_hia_generation_runtime_global_capsule_packer as spec
Q=int.from_bytes(b'HIAGGIQ1','little');R=int.from_bytes(b'HIAGGIR1','little')
OUT=147456;BAD=0xfffffffd
def frame(op,cap=(0,0,0)):return struct.pack('<16Q',Q,op,0,*cap,*([0]*10))
class Global:
    def __init__(self,owner):
        self.owner=owner;self.context=owner.context;self.entry=owner.lib.hia_generation_runtime_global
        self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32
        self.address=C.cast(self.entry,C.c_void_p).value
    def raw(self,wire,context=None):
        src=C.create_string_buffer(wire);out=C.create_string_buffer(b'\xa5'*OUT,OUT)
        rc=int(self.entry(src,len(wire),out,OUT,self.context if context is None else context,2048))
        assert src.raw==wire+b'\0';return rc,out.raw
    def call(self,op,cap=(0,0,0)):
        rc,raw=self.raw(frame(op,cap));assert rc==0 and q.get(raw,0)==R,(rc,raw[:168].hex())
        return resources.decoded(raw)
    def deny(self,op,rules,cap=(0,0,0)):
        def run():
            old=faults.spec;faults.spec=spec
            try:faults.native_seccomp(self,rules)
            finally:faults.spec=old
            return self.call(op,cap)
        return faults.in_thread(run)
def sidecar(owner,op):
    fn=owner.lib.hia_generation_lease_owner_sidecar;fn.argtypes=[C.c_void_p,C.c_uint64]*3;fn.restype=C.c_uint32
    wire=struct.pack('<16Q',int.from_bytes(b'HIAGSCQ1','little'),op,*([0]*14));src=C.create_string_buffer(wire);out=C.create_string_buffer(128)
    rc=fn(src,128,out,128,owner.context,2048);assert rc==0 and out.raw[:8]==b'HIAGSCR1',(rc,out.raw.hex())
    return {k:q.get(out.raw,v)for k,v in dict(status=8,error=16,pending=24,retired=32,known=40,state=48).items()}
def owner(path):
    n=q.Owner(path);n.initialize();return n,Global(n)
def closed(n,g,row):
    resources.retired(row)
    assert q.get(n.context,1088)==0 and q.get(n.context,1096)==0 and q.get(n.context,72)==0
    assert all(q.get(n.context,at)==0 for at in(88,96,104,112,120))
    result=n.call(3);assert result['status']==0 and result['state']==3,result
def basic(path,out):
    n,g=owner(path);fds=tq.fdset();resources.ready(g.call(0));assert q.get(n.context,72)==1 and q.get(n.context,112)==1
    assert q.get(n.context,1088)!=0 and q.get(n.context,1096)==8<<20
    b=g.call(2);pins=resources.actual_fields(b)
    for i,fd in enumerate(b['tool_fds']):
        bank=q.get(n.context,88+i*8);assert bank>=3 and bank!=fd
        assert os.fstat(bank).st_ino==os.fstat(fd).st_ino and fcntl.fcntl(bank,1034)==15
    again=g.call(0);assert again['status']==6 and again['state']==2
    bound=sidecar(n,0);assert bound['status']==0 and bound['state']==2,bound
    assert q.get(n.context,680)==190
    busy=g.call(1);assert busy['status']==6 and busy['state']==2 and busy['retired']==0
    assert n.call(3)['status']==2
    sc=sidecar(n,1);assert sc['status']==0 and sc['retired']==1,sc
    busy2=g.call(1);assert busy2['status']==6 and busy2['count']==1 and busy2['state']==2,busy2
    drop=g.call(3,b['cap']);resources.ready(drop);assert drop['consumed']==1
    closed(n,g,g.call(1));assert tq.fdset()==fds
    return dict(passed=True,actual_fixed_resources=pins,actual_native_toolbank_duplicates=True,native_sidecar_value_code_future_initialized=True,mask=190,
       parent_active_and_actual_resource_borrow_both_prevent_premature_close=True,all_actual_mapping_fd_custody_retired=True)
def initialize_failure(path,out):
    rows=[]
    for nr in(9,72):
        n,g=owner(path);fds=tq.fdset();r=g.deny(0,[(nr,errno.EIO,None)])
        assert r['status']!=0 and r['known']==1 and r['pending']==0,r
        assert q.get(n.context,1088)==0 and q.get(n.context,72)==0 and q.get(n.context,112)==0
        resources.ready(g.call(0));closed(n,g,g.call(1));assert tq.fdset()==fds
        rows.append(dict(syscall=nr,reply=r))
    return dict(passed=True,actual_root_mmap_or_bank_dup_failures_recover=rows)
def final_context_retry(path,out):
    n,g=owner(path);fds=tq.fdset();resources.ready(g.call(0));ptr=q.get(n.context,1088)
    r=g.deny(1,[(11,errno.EIO,None)])
    assert r['status']!=0 and r['known']==1 and r['pending']==1 and r['retired']==0 and q.get(n.context,1088)==ptr,r
    assert q.get(n.context,72)==1 and n.call(3)['status']==2
    closed(n,g,g.call(4));assert tq.fdset()==fds
    return dict(passed=True,actual_owned_context_munmap_eio_retained=r,real_retry_closes_parent_guard=True)
def bank_retry(path,out):
    n,g=owner(path);fds=tq.fdset();resources.ready(g.call(0));bank=tuple(q.get(n.context,at)for at in(88,96,104))
    r=g.deny(1,[(436,errno.EIO,None)])
    assert r['status']!=0 and r['known']==1 and r['pending']==1 and r['retired']==0,r
    assert q.get(n.context,72)==1 and q.get(n.context,112)==2
    for fd in bank:os.fstat(fd)
    closed(n,g,g.call(4));assert tq.fdset()==fds
    return dict(passed=True,actual_bank_close_range_eio_keeps_all_descriptors=r,actual_retry=True)
def unknown_bank(path,out):
    n,g=owner(path);resources.ready(g.call(0))
    r=g.deny(1,[(436,errno.ENOSYS,None),(3,errno.EIO,None)])
    assert r['known']==0 and r['pending']==1 and r['retired']==0 and r['state']==5,r
    later=g.call(4);assert later['known']==0 and later['pending']==1 and later['retired']==0,later
    assert q.get(n.context,1088)!=0 and q.get(n.context,72)==1 and n.call(3)['status']==2
    return dict(passed=True,actual_ambiguous_bank_close_keeps_context_and_owner_guard=r,qa_subprocess_exit_reclaims_quarantined_resource=True)
def guards(path,out):
    n,g=owner(path);fds=tq.fdset();resources.ready(g.call(0));before=bytes(n.context)
    bad=[b'',frame(5),frame(0)+b'x']
    for off in(0,16,24,40,48,120):
        wire=bytearray(frame(0));struct.pack_into('<Q',wire,off,1);bad.append(bytes(wire))
    for wire in bad:
        rc,raw=g.raw(wire);assert rc==BAD and raw==b'\xa5'*OUT and bytes(n.context)==before,(rc,wire)
    copy=C.create_string_buffer(before);rc,raw=g.raw(frame(1),copy)
    assert rc==BAD and raw==b'\xa5'*OUT and copy.raw[:2048]==before
    rd,wr=os.pipe();pid=os.fork()
    if pid==0:
        try:
            os.close(rd);rc,raw=g.raw(frame(1));os.write(wr,json.dumps([rc,raw==b'\xa5'*OUT,bytes(n.context)==before]).encode());os._exit(0)
        except BaseException:os._exit(90)
    os.close(wr);row=json.loads(os.read(rd,4096));os.close(rd);_,status=os.waitpid(pid,0)
    assert status==0 and row==[BAD,True,True],row
    closed(n,g,g.call(1));assert tq.fdset()==fds
    return dict(passed=True,static_wire_guards=len(bad),copied_and_actual_forked_root_no_write=True)
CASES=(('actual-root-global-and-sidecar',basic),('root-init-failures',initialize_failure),
 ('global-context-retirement-retry',final_context_retry),('native-bank-close-retry',bank_retry),
 ('unknown-bank-custody',unknown_bank),('static-wire-fork-copy',guards))
def main():
    p=argparse.ArgumentParser();p.add_argument('--owner',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False);rows=[]
    for name,fn in CASES:
        here=a.output/name;here.mkdir();rows.append(isolated(name,lambda fn=fn,here=here:fn(a.owner,here)))
        (a.output/'partial.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n')
    report=dict(passed=True,groups=len(rows),cases=rows,owner=resources.pin(a.owner.read_bytes()),
      actual_fixed_native_binding=True,single_value_arena=True,public_constructor_qualified=False,whole_public_runtime_qualified=False)
    (a.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(dict(passed=True,groups=len(rows))),flush=True)
if __name__=='__main__':main()
