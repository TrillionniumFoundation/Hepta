"""Fresh FS8 and selected SQLite create-mode / URI HIA build; controlled C oracle only."""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import ctypes,hashlib,importlib.util,json,os,re,resource,shutil,signal,stat,subprocess,time,traceback
from pathlib import Path
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
ROLE_SOURCES={
    "fs":("generate_hia_agent_namespace_filesystem_r8.py","465014690a19e3910448769a90c38b2b10acbfb4d52ed5e13e91e28d6f409520"),
    "create_mode":("generate_hia_agent_namespace_create_mode_r1.py","31f6d7822682fd4c6081a9d649ae8167bdc08da8313304c86113f64f6d3fb356")}
BUILDERS={
    "generate_hia_agent_namespace_store":"7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50",
    "generate_hia_agent_namespace_objects":"2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de"}
ORACLE_SOURCE="3b3e5b303b3e87c950a1b0e1b5d0a05409ac0637aec2f4e804c7f42963d91f8f"
SELECTED_MANIFEST="970b5ef2b0d6d70c8e23e65a9dd823aabd950881c48058d419d1f320664b682f"
SQLITE_SOURCES={
    "global.c":"f575d9ab7af86fe0f6397adc4ca4b3a393ff22da32f2543d068d28fb2b994816",
    "main.c":"737c8f425acc046b1ca76fbbf6474cb4b5a68c3def652a982d4a1fef0ccb431e",
    "util.c":"93318efdd7140bbb7cba31f341b29eff558d9efd7f4543e001d043e73ca733eb",
    "pragma.c":"4df5a8173084abac72c0fc973e39809f418246877ab13b557edf8c6c1daee52b",
    "os_unix.c":"83e4f995c0cfc1362b46320d979b38349ac5b1c6a7c0b12cbc2c4577c6c13ef9"}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError("build wall180")))
    signal.alarm(180)
    assert sys.version_info[:3]==(3,12,14)
    context_path=Path(sys.argv[1]).resolve(strict=True)
    context=json.loads(context_path.read_bytes())
    ref=Path(context["reference"]).resolve(strict=True)
    working=Path(context["create_mode_working"]).resolve(strict=True)
    root=Path(context["create_mode_evidence"]).resolve(strict=True)
    out=root/"build-r1";out.mkdir()
    pins={};roles={}
    report=dict(status="INCOMPLETE",scope="NEW_SELECTED_SQLITE_CREATE_MODE_URI_AND_FS8_BUILD",
        fresh_HIA_B3_compiles=0,C_reference_compiles=0,actual_native_policy_entries=0,
        actual_physical_policy_syscalls=0,full_unixOpen_closed=False,ordinary_Store_closed=False,
        source_pins_unchanged=False,profiles={},compiled_roles={},
        process_limits=dict(cpu_seconds=90,wall_seconds=180,address_bytes=1<<30,core_bytes=0))
    report["actual_limits"]={
        "cpu":list(resource.getrlimit(resource.RLIMIT_CPU)),
        "address":list(resource.getrlimit(resource.RLIMIT_AS)),
        "core":list(resource.getrlimit(resource.RLIMIT_CORE))}
    assert report["actual_limits"]==dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
    def pin(path,expected=None):
        path=Path(path).absolute();st=path.lstat()
        assert stat.S_ISREG(st.st_mode) and not path.is_symlink()
        raw=path.read_bytes();row=dict(path=str(path),bytes=len(raw),mode=stat.S_IMODE(st.st_mode),sha256=sha(raw))
        assert len(raw)==st.st_size
        if expected is not None:assert row["sha256"]==expected,(str(path),row["sha256"],expected)
        if str(path) in pins:assert pins[str(path)]==row
        pins[str(path)]=row;return raw
    def load(name,path,expected):
        raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module
        exec(compile(raw,str(path),"exec"),module.__dict__);return module
    def c_compile(source,target):
        compiler=Path(shutil.which("cc") or "").resolve(strict=True)
        assert compiler.is_file();pin(compiler)
        argv=[str(compiler),"-std=c11","-O2","-fPIC","-shared","-Wall","-Wextra",
            "-Werror=implicit-function-declaration","-Werror=return-type",
            "-Werror=incompatible-pointer-types","-o",str(target),str(source)]
        parent=os.getpid()
        def child_limits():
            libc=ctypes.CDLL(None,use_errno=True)
            if libc.prctl(1,9,0,0,0)!=0 or os.getppid()!=parent:
                os._exit(124)
            resource.setrlimit(resource.RLIMIT_CPU,(10,10))
            resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
            resource.setrlimit(resource.RLIMIT_CORE,(0,0))
            limits={"cpu":list(resource.getrlimit(resource.RLIMIT_CPU)),
                "address":list(resource.getrlimit(resource.RLIMIT_AS)),
                "core":list(resource.getrlimit(resource.RLIMIT_CORE))}
            assert limits==dict(cpu=[10,10],address=[256<<20,256<<20],core=[0,0])
            message=(json.dumps(dict(kind="C_REFERENCE_COMPILER_ACTUAL_LIMITS",limits=limits,pid=os.getpid()),sort_keys=True)+"\n").encode()
            offset=0
            while offset<len(message):offset+=os.write(1,message[offset:])
        process=None;stdout=b"";stderr=b"";started=time.monotonic_ns()
        before=resource.getrusage(resource.RUSAGE_CHILDREN)
        rec=dict(argv=argv,timeout_seconds=20,status="INCOMPLETE")
        try:
            process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                start_new_session=True,preexec_fn=child_limits,
                env=dict(os.environ,LC_ALL="C",PYTHONDONTWRITEBYTECODE="1"))
            try:stdout,stderr=process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                rec["timed_out"]=True
                os.killpg(process.pid,signal.SIGKILL)
                stdout,stderr=process.communicate()
                raise
            rec["returncode"]=process.returncode
            assert process.returncode==0,stderr.decode("utf-8","replace")
            observed=[json.loads(x) for x in stdout.splitlines() if x.startswith(b'{"kind": "C_REFERENCE_COMPILER_ACTUAL_LIMITS"')]
            assert len(observed)==1 and observed[0]["limits"]==dict(cpu=[10,10],address=[256<<20,256<<20],core=[0,0])
            rec.update(status="PASS",actual_child_limits=observed[0]["limits"])
            return rec
        finally:
            if process is not None:
                if process.poll() is None:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    tailout,tailerr=process.communicate()
                    stdout+=tailout;stderr+=tailerr
                else:process.wait()
                for stream in (process.stdout,process.stderr):
                    if stream is not None:stream.close()
                rec["returncode"]=process.returncode
            after=resource.getrusage(resource.RUSAGE_CHILDREN)
            rec.update(elapsed_ns=time.monotonic_ns()-started,
                child_cpu_seconds=(after.ru_utime+after.ru_stime)-(before.ru_utime+before.ru_stime),
                stdout_bytes=len(stdout),stdout_sha256=sha(stdout),
                stderr_bytes=len(stderr),stderr_sha256=sha(stderr))
            (out/"oracle-compile.stdout").write_bytes(stdout)
            (out/"oracle-compile.stderr").write_bytes(stderr)
            save(out/"oracle-compile.json",rec)
    try:
        pin(context_path);pin(__file__)
        sys.path.insert(0,str(ref))
        for name,expected in BUILDERS.items():
            load("tools."+name,working/"tools"/(name+".py"),expected)
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        import tools.qualify_hia_selfhost as qualifier
        assert Path(qualifier.__file__).resolve()==ref/"tools/qualify_hia_selfhost.py"
        assert Path(qualifier.CHILD).resolve()==ref/"tools/hia_selfhost_child.py"
        compiler=root/"compiler/B3.image.bin"
        assert len(pin(compiler,B3))==669556
        originals={name:pin(working/"oracle/originals"/name,expected)
            for name,expected in SQLITE_SOURCES.items()}
        manifest=json.loads(pin(working/"oracle/selected-originals.json",SELECTED_MANIFEST))
        assert manifest["upstream_commit"]=="f3d536d37825302e31ed0eddd811c689f38f85a3"
        assert manifest["schema"]=="hia.sqlite-3.46.1.create-mode-and-uri.exact-selected-originals.v1"
        assert len(manifest["members"])==15
        oracle_source=working/"oracle/create_mode_reference.c"
        raw=pin(oracle_source,ORACLE_SOURCE)
        # Explicit markers bind all selected tables and functions, including
        # the two URI wrappers and integer/boolean helpers, to whole originals.
        pattern=rb"/\* BEGIN EXACT ([0-9]+) ([a-z_]+\.c) ([0-9a-f]{64}) \*/\n(.*?)\n/\* END EXACT \1 \*/"
        matches=list(re.finditer(pattern,raw,re.DOTALL))
        assert len(matches)==15
        selected=[]
        for i,(match,row) in enumerate(zip(matches,manifest["members"])):
            number,name,digest,body=match.groups()
            assert int(number)==i and name.decode()==row["file"]
            assert sha(body)==digest.decode()==row["sha256"] and len(body)==row["bytes"]
            assert originals[row["file"]].count(body)==1
            assert body.startswith(row["signature"].encode())
            selected.append(dict(index=i,file=row["file"],bytes=len(body),sha256=sha(body),
                entire_selected_source_byte_identical=True))
        report["exact_reference_policy"]=dict(upstream_commit=manifest["upstream_commit"],
            selected_members=selected,whole_original_sources=dict(SQLITE_SOURCES),
            compiled_C_is_controlled_provider_not_physical_IO=True)
        generated={}
        for role,(name,expected) in ROLE_SOURCES.items():
            owner=load("namespace_create_mode_author_"+role,working/"tools"/name,expected)
            document=owner.document()
            docraw=(json.dumps(document,sort_keys=True,separators=(",",":"))+"\n").encode()
            path=out/(role+".document.json");path.write_bytes(docraw)
            profile=dict(functions=len(document["functions"]),
                blocks=sum(len(f["blocks"]) for f in document["functions"]),
                max_blocks=max(len(f["blocks"]) for f in document["functions"]),
                ops=sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"]),
                max_block_params=max(len(b["params"]) for f in document["functions"] for b in f["blocks"]))
            report["profiles"][role]=profile
            save(out/"summary.json",report)
            print("HIA_NAMESPACE_CREATE_MODE_PROFILE "+json.dumps(dict(role=role,profile=profile,document_sha256=sha(docraw)),sort_keys=True),flush=True)
            assert 0<profile["functions"]<=128 and profile["blocks"]<=1536
            assert profile["ops"]<=8192 and profile["max_blocks"]<=256 and profile["max_block_params"]<=16
            source=render_assembly(document).encode("utf-8")
            assemble_program(source)
            asm=out/(role+".hiaasm");asm.write_bytes(source)
            generated[role]=(path,docraw,asm,source)
            pin(path);pin(asm)
        for module in tuple(sys.modules.values()):
            filename=getattr(module,"__file__",None)
            if filename:
                path=Path(filename).resolve()
                if path.is_relative_to(ref) and path.suffix==".py":pin(path)
        pin(qualifier.CHILD)
        save(out/"source-before.json",pins)
        for role,(docpath,docraw,asm,source) in generated.items():
            directory=out/"compile"/role;directory.mkdir(parents=True)
            image_path,receipt=qualifier.compile_stage(directory,role,compiler,source)
            image=pin(image_path)
            assert receipt["status"]=="returned" and receipt["abi_status"]==0
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
            assert receipt["source_sha256"]==receipt["input_sha256"]==sha(source)
            assert receipt["produced_bytes"]==len(image) and receipt["produced_sha256"]==sha(image)
            assert 0<len(image)<=1<<20
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["runner_sha256"]==sha(pin(qualifier.CHILD))
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
            request=json.loads((directory/(role+".request.json")).read_bytes())
            assert request["capacity"]==request["workspace_size"]==1<<20
            roles[role]=dict(document=dict(path=str(docpath),bytes=len(docraw),sha256=sha(docraw)),
                source=dict(path=str(asm),bytes=len(source),sha256=sha(source)),
                image=dict(path=str(image_path),bytes=len(image),sha256=sha(image)),compile_receipt=receipt)
            report["fresh_HIA_B3_compiles"]+=1
            report["compiled_roles"][role]=roles[role];save(out/"summary.json",report)
        shared=out/"create_mode_reference.so"
        c_compile(oracle_source,shared);pin(shared)
        report["C_reference_compiles"]=1
        before=dict(pins)
        for path,row in before.items():pin(path,row["sha256"])
        assert pins==before
        report["source_pins_unchanged"]=True
        bundle=dict(reference=str(ref),roles=roles,
            oracle=dict(path=str(shared),bytes=shared.stat().st_size,sha256=sha(shared.read_bytes())),
            input_pins=list(pins.values()),exact_reference_policy=report["exact_reference_policy"],
            inherited_counts=False,physical_IO=False)
        save(out/"bundle.json",bundle)
        report["bundle"]=dict(path=str(out/"bundle.json"),bytes=(out/"bundle.json").stat().st_size,
            sha256=sha((out/"bundle.json").read_bytes()))
        report["status"]="PASS_BUILD_ONLY"
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        final={}
        for path,row in list(pins.items()):
            try:
                raw=Path(path).read_bytes()
                final[path]=dict(path=path,bytes=len(raw),mode=stat.S_IMODE(Path(path).stat().st_mode),sha256=sha(raw))
            except BaseException as error:final[path]=dict(error=repr(error))
        report["source_pins_unchanged"]=bool(pins) and final==pins
        if not report["source_pins_unchanged"]:report["status"]="FAIL"
        save(out/"source-after.json",final);save(out/"summary.json",report)
        signal.alarm(0)
        print("HIA_NAMESPACE_CREATE_MODE_BUILD "+json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS_BUILD_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
