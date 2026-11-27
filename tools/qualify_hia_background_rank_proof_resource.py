"""Actual installed public-proof rejection and native compensation.

These gates use isolated installations, unchanged native products and real
filesystem failures. They never write native binding/context bytes.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,shutil,signal,struct,subprocess,sys

PROOF_REL=Path("components/hia-rank-public-proof.bin")
PROOF_PIN=dict(bytes=16159172,sha256="744900be77472942723f0f9b3d640825cb48a75ae5bcb4a166092a0ddf0dc4f6")
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def fdset():
    out={}
    for p in Path("/proc/self/fd").iterdir():
        try:out[p.name]=os.readlink(p)
        except FileNotFoundError:pass
    return out
def case(a):
    from tools import qualify_hia_generation_lease_owner as q
    from tools import qualify_hia_generation_runtime_global as globalqa
    from tools import qualify_hia_native_runtime_resources as resources
    signal.alarm(400)
    n=q.Owner(a.root);n.initialize();g=globalqa.Global(n);before=fdset()
    resources.ready(g.call(0))
    sc=globalqa.sidecar(n,0);assert sc["status"]==0 and sc["state"]==2,sc
    original_active=q.get(n.context,72);assert q.get(n.context,1208)==0
    fn=n.lib.hia_generation_background_bind
    fn.argtypes=[C.c_void_p,C.c_uint64]*3;fn.restype=C.c_uint32
    calls=[]
    def call(op):
        raw=struct.pack("<16Q",int.from_bytes(b"HIAGBNQ1","little"),op,*([0]*14))
        src=C.create_string_buffer(raw,128);out=C.create_string_buffer(b"\xa5"*(3<<20),3<<20)
        rc=int(fn(src,128,out,3<<20,n.context,2048))
        head=[q.get(out,i)for i in range(0,128,8)]
        gp=q.get(n.context,1088);anchor=C.string_at(gp+7340544,512)
        row=dict(op=op,rc=rc,head=head,anchor=[q.get(anchor,i)for i in range(0,512,8)],
            root_active=q.get(n.context,72),sidecar_active=q.get(n.context,1208),mask=q.get(n.context,680))
        calls.append(row);(a.output/"calls.json").write_text(json.dumps(calls,indent=2)+"\n")
        print("ACTUAL_PROOF_ADMISSION",a.case,json.dumps(row),flush=True)
        assert rc==0 and out.raw[:8]==b"HIAGBNR1" and src.raw==raw,row
        return out.raw,anchor
    reply,anchor=call(0)
    assert q.get(reply,8)!=0 and q.get(reply,24)==1 and q.get(reply,32)==0,reply[:128].hex()
    assert q.get(reply,16)==4 and q.get(reply,40)==1,reply[:128].hex()
    assert q.get(n.context,680)==190 and q.get(n.context,1208)==0
    assert q.get(n.context,72)==original_active
    assert q.get(anchor,32)==q.get(anchor,368)==q.get(anchor,376)==0
    assert all(q.get(anchor,i)==0 for i in (96,104,112,400,408,416,424,440))
    retired,_=call(1)
    assert q.get(retired,8)==0 and q.get(retired,16)==4 and q.get(retired,40)==1
    assert q.get(n.context,680)==190
    sc=globalqa.sidecar(n,1);assert sc["status"]==0 and sc["retired"]==1,sc
    globalqa.closed(n,g,g.call(1));assert fdset()==before,(before,fdset())
    report=dict(passed=True,case=a.case,calls=calls,actual_native_admission_rejected=True,
        native_global_borrow_and_both_guards_retired=True,separate_proof_context_retired=True,
        unchanged_scalar_proof_bank=True,all_actual_fds_retired=True,host_context_writes=False,
        root=pin(a.root.read_bytes()),whole_background_closed=False)
    (a.output/"report.json").write_text(json.dumps(report,indent=2)+"\n")
    signal.alarm(0);print("ACTUAL_PROOF_REJECTION_COMPENSATION_PASS",a.case,flush=True)
def main():
    p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--reference-root",type=Path,required=True)
    p.add_argument("--case",choices=("missing","digest","length","directory"))
    a=p.parse_args();root=Path(__file__).resolve().parents[1]
    sys.path[:0]=[str(root),str(a.reference_root)]
    import tools
    tools.__path__=[str(root/"tools"),str(a.reference_root/"tools")]
    import importlib.abc,importlib.machinery
    class FrozenTools(importlib.abc.MetaPathFinder):
        def find_spec(self,fullname,path=None,target=None):
            if fullname.startswith("tools."):
                return importlib.machinery.PathFinder.find_spec(fullname,[str(root/"tools"),str(a.reference_root/"tools")])
    sys.meta_path.insert(0,FrozenTools())
    if a.case:return case(a)
    a.output.mkdir(parents=True,exist_ok=False)
    expected=pin(a.root.read_bytes());proof=(a.root.parent/PROOF_REL).read_bytes()
    assert pin(proof)==PROOF_PIN
    rows=[]
    for name in ("missing","digest","length","directory"):
        here=a.output/name;here.mkdir();install=here/"install"
        shutil.copytree(a.root.parent,install,symlinks=True,copy_function=os.link)
        installed_root=install/a.root.name
        installed_root.unlink();shutil.copy2(a.root,installed_root)
        assert pin(installed_root.read_bytes())==expected
        target=install/PROOF_REL;target.unlink()
        if name=="digest":
            changed=bytearray(proof);changed[-1]^=1;target.write_bytes(changed);target.chmod(0o500)
        elif name=="length":
            target.write_bytes(proof[:-1]);target.chmod(0o500)
        elif name=="directory":target.mkdir()
        command=[sys.executable,"-B",str(Path(__file__).resolve()),"--root",str(installed_root),
            "--output",str(here),"--reference-root",str(a.reference_root),"--case",name]
        with (here/"execution.log").open("wb")as log:
            r=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=420)
        print(name,"exit",r.returncode,flush=True)
        assert r.returncode==0,(name,(here/"execution.log").read_text())
        report=json.loads((here/"report.json").read_text());assert report["passed"]is True
        rows.append(dict(name=name,report=report,execution_log=pin((here/"execution.log").read_bytes())))
        (a.output/"partial.json").write_text(json.dumps(rows,indent=2)+"\n")
    report=dict(passed=True,groups=len(rows),cases=rows,root=expected,public_proof=PROOF_PIN,
        scope="actual installed artifact rejection and native rollback",whole_background_closed=False)
    (a.output/"report.json").write_text(json.dumps(report,indent=2)+"\n")
    print("ACTUAL_INSTALLED_PROOF_REJECTIONS_PASS",len(rows),flush=True)
if __name__=="__main__":main()
