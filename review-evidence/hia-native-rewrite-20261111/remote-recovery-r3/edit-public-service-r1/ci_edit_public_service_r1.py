"""Fresh E service generation and bounded original E progress observation.

The input is one exact original GitHub artifact. Its prior 87 cases are not
rerun or counted. New source generation/B3 and original-boundary diagnostics
have separate result records; neither alone closes the public CLI.
"""
from __future__ import annotations
import argparse,ast,importlib.util,io,json,os,resource,shutil,stat,struct,subprocess,sys,tarfile,threading,time,traceback,types,zipfile
from hashlib import sha1,sha256
from pathlib import Path,PurePosixPath
sys.dont_write_bytecode=True
PIN=dict(run_id=43122922476,job_id=130867669693,artifact_id=13901534373,
 zip_bytes=60079807,zip_sha256="f35d3b639e645e27dedfab101f869d3bc7f1d927e6f11a1fc78bb4b6b75c8986",
 inner_bytes=20992744,inner_sha256="b2f7d7583655a813c8aad3735e2bde703f883bd9ae25887ac6feab716fbd3ae3",
 index_bytes=402737,index_sha256="5a8a3e1577a201b63789ff8f2d069445b8770197d7205ed8e5e8e368593d3acc",
 members=966,raw_bytes=149824283)
def digest(raw):return sha256(raw).hexdigest()
def gitsha(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
def safe(name):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and ".." not in p.parts and "\\" not in name and "\0" not in name
    return p
def blob(repo,sha):
    raw=subprocess.check_output(["git","cat-file","blob",sha],cwd=repo)
    assert gitsha(raw)==sha
    return raw
def extract(archive,out):
    raw=archive.read_bytes()
    assert (len(raw),digest(raw))==(PIN["zip_bytes"],PIN["zip_sha256"])
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        assert z.testzip() is None
        names=z.namelist();assert len(names)==len(set(names))
        for name in names:safe(name)
        inner=[x for x in names if x.endswith("/evidence.tar.xz") or x=="evidence.tar.xz"]
        indexes=[x for x in names if x.endswith("/evidence-members.json") or x=="evidence-members.json"]
        assert len(inner)==len(indexes)==1
        data=z.read(inner[0]);index=z.read(indexes[0])
    assert (len(data),digest(data))==(PIN["inner_bytes"],PIN["inner_sha256"])
    assert (len(index),digest(index))==(PIN["index_bytes"],PIN["index_sha256"])
    rows=json.loads(index);expected={r["name"]:r for r in rows}
    assert len(rows)==len(expected)==PIN["members"] and sum(r["bytes"] for r in rows)==PIN["raw_bytes"]
    out.mkdir(exist_ok=False);seen=set()
    with tarfile.open(fileobj=io.BytesIO(data),mode="r:xz") as tf:
        for m in tf:
            relative=safe(m.name);assert m.isfile() and m.name not in seen
            r=expected[m.name];b=tf.extractfile(m).read()
            assert (len(b),digest(b),m.mode)==(r["bytes"],r["sha256"],r["mode"])
            p=out.joinpath(*relative.parts);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);p.chmod(m.mode)
            seen.add(m.name)
    assert seen==set(expected)
    return rows
def unchanged(root,rows):
    return all((root/r["name"]).stat().st_size==r["bytes"] and
      stat.S_IMODE((root/r["name"]).stat().st_mode)==r["mode"] and
      digest((root/r["name"]).read_bytes())==r["sha256"] for r in rows)
def load_module(name,path):
    sp=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def constants(raw,begin,end,env):
    selected=[];started=begin is None
    for node in ast.parse(raw).body:
        targets=[x.id for x in node.targets if isinstance(x,ast.Name)] if isinstance(node,ast.Assign) else []
        if end in targets:break
        if begin in targets:started=True
        if started:selected.append(node)
    exec(compile(ast.Module(body=selected,type_ignores=[]),"exact-constant-prefix","exec"),env)
    return env["CONSTANTS"]
def compile_new(args,original,rows,out):
    out.mkdir(exist_ok=False)
    reference=args.reference.resolve()
    assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=reference).strip()==b"0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5"
    assert subprocess.check_output(["git","rev-parse","HEAD^{tree}"],cwd=reference).strip()==b"6ef9e1713065436a3b1886fe9edcf0a4a1120773"
    sys.path.insert(0,str(reference))
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
    from tools.qualify_hia_selfhost import compile_stage
    helper=out/"hia_agent_edit_source_views.py"
    helper.write_bytes(blob(args.repo,"f7d123bdb2bf65b25182b571f024299cb0342828"))
    assert digest(helper.read_bytes())=="555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"
    CopyBuilder=load_module("exact_edit_copy_builder",helper).CopyBuilder
    lower=constants(blob(args.repo,"e56539a9cb76f95010ea6ca995737f40ab6e1850"),None,"COMMON",{})
    c=constants(blob(args.repo,"73096fe41a1e1d5d3e4c84e722707ac0b07eadf3"),"CONSTANTS","COMMON",
      dict(old=types.SimpleNamespace(CONSTANTS=lower),magic=lambda s:int.from_bytes(s.encode(),"little")))
    source_path=args.module.resolve();source_before=source_path.read_bytes()
    assert gitsha(source_before)=="6896c532705e39a86ed3015e9d14e80abfc3b042"
    module=load_module("new_edit_public_service",source_path)
    root_old=original/"edit-terminal-relay/development/agent_edit_root_terminal_relay.authoring.py"
    text56,text58,scope=module.expanded_sources(root_old.read_text(),c)
    def document(text,name):
        nodes=ast.parse(text).body
        names={n.name:"f"+str(i) for i,n in enumerate(nodes)}
        sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
        total=total_scalar_functions(nodes);functions=[]
        for n in nodes:
            b=CopyBuilder(n,names,sigs,total);b.statements(n.body)
            functions.append(dict(name=names[n.name],params=[b.param(p) for p in b.params],
              returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
        return compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module=name,functions=functions))
    (out/"root56.authoring.py").write_text(text56);(out/"post58.authoring.py").write_text(text58)
    rootdoc=document(text56,"cli_edit_service56_r1")
    postdoc=document(text58,"cli_edit_post58_r1")
    bundle=json.loads((original/"composed-latest-editor/development/build-r2/bundle.json").read_bytes())
    row=bundle["components"]["58"]
    choices=[original/r["name"] for r in rows if r["bytes"]==row["source_bytes"] and r["sha256"]==row["source_sha256"]]
    assert choices and all(p.read_bytes()==choices[0].read_bytes() for p in choices)
    old58=assemble_program(choices[0].read_bytes()).as_dict()
    # Keep every complete authored graph before linking so a generation
    # failure retains its exact inputs and phase, without claiming B3 execution.
    save(out/"root56-unlinked.document.json",rootdoc)
    save(out/"post58-unlinked.document.json",postdoc)
    save(out/"original58.document.json",old58)
    merged=module.merge_service_document(old58,postdoc,CopyBuilder,compact_authoring_cfg)
    compiler=original/"composed-latest-editor/development/build-r2/source/1/B3.image.bin"
    assert len(compiler.read_bytes())==669556 and digest(compiler.read_bytes())=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
    result=dict(scope=scope,status="FAIL",actual_compilations=0,actual_semantic_entries=0,
      public_CLI_closed=False,whole_stack_closed=False,components={})
    save(out/"old58-source.json",dict(original=row,selected=str(choices[0]),matching_copies=len(choices)))
    for role,doc in [(56,rootdoc),(58,merged)]:
        sub=out/("role-"+str(role));sub.mkdir()
        save(sub/"document.json",doc)
        raw=render_assembly(doc).encode();assemble_program(raw)
        source=sub/"source.hiaasm";source.write_bytes(raw)
        profile=dict(functions=len(doc["functions"]),blocks=sum(len(f["blocks"]) for f in doc["functions"]),
          max_blocks=max(len(f["blocks"]) for f in doc["functions"]),
          operations=sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]),
          max_block_params=max(len(b["params"]) for f in doc["functions"] for b in f["blocks"]))
        save(sub/"profile.json",profile)
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["max_blocks"]<=256
        assert profile["operations"]<=8192 and profile["max_block_params"]<=16 and len(raw)<=1<<20
        image,receipt=compile_stage(sub,"edit-service",compiler,raw)
        assert receipt["status"]=="returned" and receipt["abi_status"]==0 and receipt["source_unchanged"]
        assert not receipt["forbidden_compiler_modules_loaded"]
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        image_raw=Path(image).read_bytes()
        assert len(image_raw)==receipt["core_u32"] and digest(image_raw)==receipt["produced_sha256"]
        result["components"][str(role)]=dict(profile=profile,source=str(source),source_bytes=len(raw),
          source_sha256=digest(raw),image=str(image),image_bytes=len(image_raw),image_sha256=digest(image_raw))
        result["actual_compilations"]+=1;save(out/"progress.json",result)
    assert source_path.read_bytes()==source_before and unchanged(original,rows)
    result.update(status="PASS_GENERATION_AND_B3_ONLY",all_original_bytes_unchanged=True)
    save(out/"summary.json",result);return result
def diagnose_boundary(original,out):
    out.mkdir(exist_ok=False);(out/"empty").mkdir()
    root=original/"composed-latest-editor/development"
    executable=root/"build-r2/hia-edit-candidate-snapshot"
    assert digest(executable.read_bytes())=="83d3d073ea487187d73ff1b975b1427d00f0cd316891f50b86f7bad995dd426f"
    case=root/"snapshot-whole-boundary-r1/case-000"
    payload=(case/"input.bin").read_bytes()
    assert digest(payload)=="a8f3525be4e930fd7db01fdd309c38d74be6d54fa9c94c75c802145dae9627d4"
    expected=[(case/p).read_bytes() for p in ("expected-candidate.bin","expected-receipt.bin","expected-query.bin")]
    snapshots=[];errors=[];stop=threading.Event()
    def limits():
        resource.setrlimit(resource.RLIMIT_CPU,(90,90))
        resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
        resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def observe(child):
        while not stop.wait(2):
            try:
                maps=Path(f"/proc/{child.pid}/maps").read_text();contexts=[]
                with open(f"/proc/{child.pid}/mem","rb",buffering=0) as mem:
                    for line in maps.splitlines():
                        p=line.split()
                        if len(p)!=5 or p[1]!="rw-p":continue
                        lo,hi=(int(x,16) for x in p[0].split("-"))
                        for address in range(lo,hi-2303,4096):
                            c=struct.unpack("<288Q",os.pread(mem.fileno(),2304,address))
                            if c[256] not in range(1,64) or c[257] not in (111,112,113) or c[9]!=1<<20:continue
                            work=c[8]
                            row=dict(context=address,role=c[256],lease=c[257],sequence=c[258],
                              parent=c[281],child_target=c[282],kind=c[285],depth=c[286])
                            row["head"]=list(struct.unpack("<64Q",os.pread(mem.fileno(),512,work)))
                            row["arguments"]=list(struct.unpack("<12Q",os.pread(mem.fileno(),96,work+1024)))
                            row["owner"]=list(struct.unpack("<64Q",os.pread(mem.fileno(),512,work+8192)))
                            row["program"]=list(struct.unpack("<64Q",os.pread(mem.fileno(),512,work+12288)))
                            row["slots"]=[dict(slot=i,bytes=c[i*4+1],readonly=c[i*4+3]) for i in range(64) if c[i*4+1]]
                            contexts.append(row)
                snapshots.append(dict(elapsed_ns=time.monotonic_ns()-start,contexts=contexts))
                save(out/"progress.json",snapshots)
            except BaseException as e:
                errors.append(dict(elapsed_ns=time.monotonic_ns()-start,error_class=type(e).__name__,error=str(e)))
                if child.poll() is not None:return
    before=resource.getrusage(resource.RUSAGE_CHILDREN);start=time.monotonic_ns()
    with (out/"stdout.bin").open("xb") as stdout,(out/"stderr.bin").open("xb") as stderr:
        child=subprocess.Popen([str(executable)],stdin=subprocess.PIPE,stdout=stdout,stderr=stderr,
          cwd=out/"empty",env={},preexec_fn=limits)
        watcher=threading.Thread(target=observe,args=(child,),daemon=True);watcher.start()
        timed_out=False
        try:child.communicate(payload,timeout=180)
        except subprocess.TimeoutExpired:
            timed_out=True;child.kill();child.wait()
        finally:stop.set();watcher.join(5)
    after=resource.getrusage(resource.RUSAGE_CHILDREN)
    stdout=(out/"stdout.bin").read_bytes();stderr=(out/"stderr.bin").read_bytes()
    target=struct.pack("<8Q",int.from_bytes(b"HIAEDR01","little"),1,*map(len,expected),0,0,0)+b"".join(expected)
    event=list(struct.unpack_from("<16Q",stderr)) if len(stderr)>=128 else None
    equal=stdout==target and child.returncode==0 and len(stderr)==128 and event[:3]==[int.from_bytes(b"HIACDE01","little"),7,111] and event[4:8]==[0,0,30,0] and event[8]==len(stdout) and event[9]==1 and not any(event[11:])
    result=dict(status="DIAGNOSTIC_COMPLETE",original_boundary_status="PASS" if equal else "FAIL",
      original_CI_failure_overwritten=False,new_native_processes=1,timed_out=timed_out,exitcode=child.returncode,
      wall_ns=time.monotonic_ns()-start,cpu_s=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
      source_unchanged=digest(executable.read_bytes())=="83d3d073ea487187d73ff1b975b1427d00f0cd316891f50b86f7bad995dd426f",
      limits=dict(cpu_seconds=90,wall_seconds=180,address_space_bytes=1<<30,stack_bytes=8<<20,core_bytes=0),
      environment="empty; original CI populated PATH/HOME/LANG; executable does not read environment",
      stdout_bytes=len(stdout),stdout_sha256=digest(stdout),stderr_bytes=len(stderr),stderr_sha256=digest(stderr),
      complete_expected_stdout_equal=stdout==target,complete_terminal_valid=equal,event=event,
      snapshots=len(snapshots),observation_errors=errors,full_public_CLI_closed=False)
    save(out/"summary.json",result)
    print("E_ORIGINAL_BOUNDARY_DIAGNOSTIC "+json.dumps(result,sort_keys=True),flush=True)
    if snapshots:
        for row in (snapshots[0],snapshots[-1]):print("E_ORIGINAL_PROGRESS "+json.dumps(row,sort_keys=True),flush=True)
    return result
def main():
    p=argparse.ArgumentParser();p.add_argument("--zip",type=Path,required=True)
    p.add_argument("--repo",type=Path,required=True);p.add_argument("--reference",type=Path,required=True)
    p.add_argument("--module",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    args=p.parse_args();args.out.mkdir(exist_ok=False)
    original=args.out/"original";rows=extract(args.zip,original)
    report=dict(schema="hia-edit-public-service-development-r1",pin=PIN,status="FAIL",
      prior_87_cases_recounted=False,whole_stack_closed=False,production_activated=False)
    failures=[]
    for label,fn in (("generation",lambda:compile_new(args,original,rows,args.out/"generation")),
                     ("boundary_diagnostic",lambda:diagnose_boundary(original,args.out/"boundary-diagnostic"))):
        try:report[label]=fn()
        except BaseException as e:
            failure=dict(stage=label,error_class=type(e).__name__,error=str(e),traceback=traceback.format_exc())
            failures.append(failure);save(args.out/(label+"-failure.json"),failure);traceback.print_exc()
    report["all_original_bytes_sha_modes_unchanged"]=unchanged(original,rows)
    report["failures"]=failures
    if not failures and report["all_original_bytes_sha_modes_unchanged"]:report["status"]="PASS_DEVELOPMENT_AND_DIAGNOSTIC_COMPLETENESS_ONLY"
    save(args.out/"summary.json",report)
    print("E_SERVICE_DEVELOPMENT "+json.dumps(report,sort_keys=True),flush=True)
    if failures or not report["all_original_bytes_sha_modes_unchanged"]:raise SystemExit(1)
if __name__=="__main__":main()
