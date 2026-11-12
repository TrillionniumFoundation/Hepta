"""Fresh bounded B3 build of the unixOpen raw-FS continuation framer.

Not a cold qualification. The same exact original compiler and 128/1536/8192/
256/16 profile limits apply. Full generated documents are saved before gates.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,hashlib,importlib.util,json,resource,signal,stat,time,traceback
from pathlib import Path
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
AUTHOR="e5682dd85164edda7f7e2a6adcc7f8a567f72c9dcc9626b06b95afa47024e83b"
VALUES="7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50"
OBJECTS="2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def expired(*_):raise TimeoutError("framer build original180wall")
    signal.signal(signal.SIGALRM,expired);signal.alarm(180)
    ap=argparse.ArgumentParser();ap.add_argument("--context",type=Path,required=True);args=ap.parse_args()
    assert sys.version_info[:3]==(3,12,14)
    pins={}
    def pin(path,expected=None):
        path=Path(path).absolute();info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        raw=path.read_bytes();row=dict(path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
        if expected is not None:assert row["sha256"]==expected,(path,row,expected)
        if str(path) in pins:assert pins[str(path)]==row
        pins[str(path)]=row;return raw
    def load(name,path,expected=None):
        raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module
        exec(compile(raw,str(path),"exec"),module.__dict__);return module
    context=json.loads(pin(args.context));ref=Path(context["reference"]);tree=Path(context["namespace_working"])
    out=Path(context["namespace_evidence"])/"framer-build";out.mkdir(parents=False,exist_ok=False)
    report=dict(status="INCOMPLETE",scope="NEW_RAW_FS_FRAMER_BUILD_ONLY_PRIVATE_ISSUER_REQUIRED",
        fresh_B3_compiles=0,native_entries=0,VM_entries=0,actual_OS_syscalls=0,inherited_counts=False,
        limits=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0,
                    compiler_CPU=10,compiler_wall=20,compiler_address_bytes=256<<20),
        actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
            address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE))))
    started=time.monotonic_ns();cpu=time.process_time_ns()
    try:
        pin(__file__);sys.path.insert(0,str(ref))
        load("tools.generate_hia_agent_namespace_store",tree/"tools/generate_hia_agent_namespace_store.py",VALUES)
        load("tools.generate_hia_agent_namespace_objects",tree/"tools/generate_hia_agent_namespace_objects.py",OBJECTS)
        author=load("namespace_raw_fs_framer_author",tree/"tools/generate_hia_unixopen_raw_fs_framer.py",AUTHOR)
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        import tools.qualify_hia_selfhost as qualifier
        assert Path(qualifier.__file__).resolve()==ref/"tools/qualify_hia_selfhost.py"
        assert Path(qualifier.CHILD).resolve()==ref/"tools/hia_selfhost_child.py"
        compiler=Path(context["compiler"]);pin(compiler,B3);pin(qualifier.CHILD)
        document=author.document()
        raw=(json.dumps(document,sort_keys=True,separators=(",",":"))+"\n").encode()
        document_path=out/"framer.document.json";document_path.write_bytes(raw)
        profile=dict(functions=len(document["functions"]),blocks=sum(len(f["blocks"]) for f in document["functions"]),
            ops=sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"]),
            max_blocks=max(len(f["blocks"]) for f in document["functions"]),
            max_block_params=max(len(b["params"]) for f in document["functions"] for b in f["blocks"]))
        report.update(profile=profile,document=dict(path=str(document_path),bytes=len(raw),sha256=sha(raw)),
            function_profiles=[dict(name=f["name"],blocks=len(f["blocks"]),
              ops=sum(len(b["ops"]) for b in f["blocks"]),max_block_params=max(len(b["params"]) for b in f["blocks"]))
              for f in document["functions"]])
        save(out/"summary.json",report);print("NAMESPACE_RAW_FS_FRAMER_PROFILE "+json.dumps(report["profile"]),flush=True)
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
        assert profile["max_blocks"]<=256 and profile["max_block_params"]<=16
        source=render_assembly(document).encode();assemble_program(source)
        source_path=out/"agent_namespace_unixopen_fs_framer_r4.hiaasm";source_path.write_bytes(source)
        report["canonical_source"]=dict(path=str(source_path),bytes=len(source),sha256=sha(source))
        compile_dir=out/"compile";compile_dir.mkdir()
        image_path,receipt=qualifier.compile_stage(compile_dir,"unixopen-fs-framer",compiler,source)
        image=pin(image_path)
        assert receipt["source_sha256"]==receipt["input_sha256"]==sha(source)
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
        assert receipt["produced_sha256"]==sha(image) and receipt["produced_bytes"]==len(image)
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        assert receipt["runner_sha256"]==sha(pin(qualifier.CHILD))
        request=json.loads((compile_dir/"unixopen-fs-framer.request.json").read_bytes())
        assert request["capacity"]==request["workspace_size"]==1<<20 and 0<len(image)<=1<<20
        report.update(status="PASS_BUILD_ONLY",fresh_B3_compiles=1,compile_receipt=receipt,
            image=dict(path=str(image_path),bytes=len(image),sha256=sha(image)))
        for module in tuple(sys.modules.values()):
            filename=getattr(module,"__file__",None)
            if filename:
                path=Path(filename).resolve()
                if path.is_relative_to(ref) and path.suffix==".py":pin(path)
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        after={};errors=[]
        for name,row in pins.items():
            try:
                path=Path(name);info=path.lstat()
                assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
                raw=path.read_bytes();after[name]=dict(path=name,bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
            except BaseException as error:errors.append(dict(path=name,error=repr(error)))
        report.update(source_before=pins,source_after=after,source_pins_unchanged=after==pins and not errors,
            after_errors=errors,wall_ns=time.monotonic_ns()-started,CPU_ns=time.process_time_ns()-cpu)
        if not report["source_pins_unchanged"]:report["status"]="FAIL"
        save(out/"summary.json",report)
        print("NAMESPACE_RAW_FS_FRAMER_BUILD "+json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS_BUILD_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
