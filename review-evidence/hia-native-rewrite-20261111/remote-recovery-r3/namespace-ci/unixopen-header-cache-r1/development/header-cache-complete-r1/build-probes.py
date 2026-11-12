"""Fresh original/candidate and exact private loop/helper probes; strict original B3 gates."""
from __future__ import annotations
import ast,copy,hashlib,importlib.util,json,re,resource,signal,sys,textwrap,time,traceback
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
INPUT=ROOT.parent/"unix9-header-cache-r1"
BASE=ROOT.parent/"nine-role-local-r4"
REF=Path("/workspace/scratch/9acdfa9f5639/reference0ef")
B3=BASE/"evidence/compiler/B3.image.bin"
B3SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
def sha(b):return hashlib.sha256(b).hexdigest()
def ident(p):
    p=Path(p);b=p.read_bytes()
    return dict(path=str(p),bytes=len(b),sha256=sha(b),mode=p.stat().st_mode&0o777,gitsha=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest())
def save(p,v):
    raw=(json.dumps(v,sort_keys=True,indent=2)+"\n").encode();p.write_bytes(raw);assert p.read_bytes()==raw
def load(name,p):
    spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;exec(compile(Path(p).read_bytes(),str(p),"exec"),m.__dict__);return m
def main():
    started=time.monotonic_ns();resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def timeout(*_):raise TimeoutError("180 wall")
    signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,180)
    out=ROOT/"build-r2";out.mkdir(exist_ok=False);pins={};rows={};primary=None
    report=dict(status="INCOMPLETE",scope="LOCAL_DEVELOPMENT_FRESH_EIGHT_B3_NOT_QUALIFICATION",fresh_B3=0,VM=0,native_subject=0)
    def pin(p):
        p=Path(p);pins[str(p)]=ident(p);return p.read_bytes()
    try:
        pin(__file__);assert sha(pin(B3))==B3SHA
        assert ident(INPUT/"old.py")["gitsha"]=="33c3bde4fdae6781ae33a20be776a22ea29222f8"
        assert ident(INPUT/"new.py")["gitsha"]=="dc45ba1fc5910be5d591b7433ce79cb814229e40"
        for p in (INPUT/"old.py",INPUT/"new.py",INPUT/"exact-edits.json",INPUT/"proof.json"):pin(p)
        proof=json.loads((INPUT/"proof.json").read_bytes());assert proof["status"]=="PASS_SOURCE_PROFILE_CORE_ONLY"
        edits=json.loads((INPUT/"exact-edits.json").read_bytes())
        sys.path[:0]=[str(BASE/"source"),str(REF)]
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        q=load("header_cache_strict_compiler",REF/"tools/qualify_hia_selfhost.py");pin(q.CHILD);pin(REF/"tools/qualify_hia_selfhost.py")
        old=load("header_old_author",INPUT/"old.py");new=load("header_new_author",INPUT/"new.py")
        docs={}
        for label,m in (("old",old),("new",new)):
            doc=m.document();docs[label+"-full"]=doc
            # Original helper body and every other nonentry function remain exact.
            probe=copy.deepcopy(doc)
            nodes=ast.parse(m.source_program()).body
            names={n.name:"f"+str(i) for i,n in enumerate(nodes)}
            signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
            wrapper=ast.parse("def unixopen_issued_raw_join(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    if length(o) > 0:\n        store(o, 0, 90)\n    return ui_child_shape(s, w)\n").body[0]
            b=m.ObjectBuilder(wrapper,names,signatures,m.total_scalar_functions(nodes));b.statements(wrapper.body)
            replacement=dict(name="f0",params=[b.param(v) for v in b.params],returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks)
            probe["module"]="private_child_shape_probe";probe["functions"][0]=replacement
            probe=m.compact_authoring_cfg(probe)
            assert probe["functions"][1:]==doc["functions"][1:]
            docs[label+"-shape"]=probe
            helper_nodes={n.name:n for n in nodes}
            helpers="\n".join(ast.get_source_segment(m.source_program(),helper_nodes[n]) for n in ("read64","get"))
            for lane in (0,1):
                fragment=edits[lane]["before" if label=="old" else "after"]
                fragment=textwrap.indent(textwrap.dedent(fragment),"    ")
                prefix="def loop_probe(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    if length(o) > 0:\n        store(o, 0, 90)\n"
                if lane:prefix+="    start = 384 + read64(s, 304)\n"
                source=prefix+fragment+"    return 1\n\n"+helpers+"\n"
                ns=ast.parse(source).body;nn={n.name:"f"+str(i) for i,n in enumerate(ns)}
                sig={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in ns}
                functions=[]
                for n in ns:
                    b=m.ObjectBuilder(n,nn,sig,m.total_scalar_functions(ns));b.statements(n.body)
                    functions.append(dict(name=nn[n.name],params=[b.param(v) for v in b.params],returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
                d=m.compact_authoring_cfg(dict(schema=doc["schema"],module="private_exact_loop_"+str(lane),functions=functions))
                docs[label+"-loop"+str(lane)]=d
                (out/(label+"-loop"+str(lane)+".dsl.py")).write_text(source)
        assert len(docs)==8
        for name,doc in docs.items():
            raw=(json.dumps(doc,sort_keys=True,separators=(",",":"))+"\n").encode();(out/(name+".document.json")).write_bytes(raw)
            source=render_assembly(doc).encode();(out/(name+".hiaasm")).write_bytes(source);assemble_program(source)
            fs=doc["functions"];nums=[int(p["name"][1:]) for f in fs for p in f["params"]]+[int(p["name"][1:]) for f in fs for b in f["blocks"] for p in b["params"]]+[int(p["name"][1:]) for f in fs for b in f["blocks"] for op in b["ops"] for p in op["out"]]
            profile=dict(functions=len(fs),blocks=sum(len(f["blocks"]) for f in fs),ops=sum(len(b["ops"]) for f in fs for b in f["blocks"]),max_blocks=max(len(f["blocks"]) for f in fs),max_block_params=max(len(b["params"]) for f in fs for b in f["blocks"]),max_ssa=max(nums),source_bytes=len(source))
            save(out/(name+".profile.json"),profile)
            assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192 and profile["max_blocks"]<=256 and profile["max_block_params"]<=16 and profile["max_ssa"]<2048 and profile["source_bytes"]<=1<<20
            image,r=q.compile_stage(out,name,B3,source)
            assert r["artifact_sha256"]==B3SHA and r["input_sha256"]==sha(source)
            assert r["status"]=="returned" and r["limits"]["cpu_seconds"]==10 and r["limits"]["address_bytes"]==256<<20
            assert r["wall_elapsed_ns"]<20_000_000_000 and r["limits"]["output_capacity"]==r["limits"]["workspace_bytes"]==1<<20
            rows[name]=dict(profile=profile,source=ident(out/(name+".hiaasm")),document=ident(out/(name+".document.json")),image=ident(image),receipt=r)
            report["fresh_B3"]+=1;report["rows"]=rows;save(out/"summary.json",report)
        assert report["fresh_B3"]==8
        report["status"]="PASS_BUILD_ONLY"
        for module in tuple(sys.modules.values()):
            path=getattr(module,"__file__",None)
            if path:
                p=Path(path).resolve()
                if p.suffix==".py" and (p.is_relative_to(REF) or p.is_relative_to(BASE/"source")):pin(p)
    except BaseException as exc:
        primary=exc;report.update(status="FAIL",error=repr(exc),traceback=traceback.format_exc());traceback.print_exc()
    finally:
        errors=[]
        for path,before in pins.items():
            try:assert ident(path)==before
            except BaseException as exc:
                errors.append(dict(path=path,error=repr(exc)))
                if primary is None:primary=exc
                else:primary.add_note(repr(exc))
        report.update(source_before=pins,after_errors=errors,rows=rows)
        if primary is not None:report["status"]="FAIL"
        try:
            save(out/"summary.json",report);print(json.dumps(dict(status=report["status"],fresh_B3=report["fresh_B3"],profiles={k:v["profile"] for k,v in rows.items()})),flush=True)
            usage=resource.getrusage(resource.RUSAGE_SELF);child=resource.getrusage(resource.RUSAGE_CHILDREN)
            assert 0<=usage.ru_utime+usage.ru_stime+child.ru_utime+child.ru_stime<90 and 0<=time.monotonic_ns()-started<180_000_000_000
        except BaseException as exc:
            if primary is None:primary=exc
            else:primary.add_note(repr(exc))
        if primary is not None:
            report.update(status="FAIL",final_error=repr(primary))
            try:save(out/"summary.json",report)
            except BaseException as exc:primary.add_note("FAILreceipt:"+repr(exc))
        signal.setitimer(signal.ITIMER_REAL,0)
    if primary is not None:raise primary
if __name__=="__main__":main()
