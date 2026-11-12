"""Fresh exact SQLite random.c / new HIA VM and native state proof.

All122 original C calls, all65 protocol refusals and every complete paired
buffer must execute in one original90CPU/180wall/1GiB development process tree.
Original C dependency hooks are explicit fixtures, not physical namespace peers.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,ctypes,gzip,hashlib,importlib.util,json,os,resource,shutil,signal,stat,subprocess,time,traceback
from pathlib import Path
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
PINS={
  "generate_hia_namespace_process_prng.py": "cc7309c3eb8e05abcceb362c32fb1a4096375a4d022906e558b7954bda06136d",
  "generate_hia_agent_namespace_store.py": "7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50",
  "generate_hia_agent_namespace_objects.py": "2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de",
  "prng_test_mechanics.py": "2431fb6b12a44a2f47c7b1c2fc1e9b8d871c6c043e4734a65de5982f70c70bc8",
  "prng_protocol_controls.py": "6438b1854efc6de32b6dfd00ca47a68bc08361b2e6d4ede419df0775ef94fc2a",
  "random.c": "d25ba0221b50349bb75ab568813e6f9f4882f883dbe093dd06859d40439bdb2a",
  "sqliteInt.h": "9c998ed7e0acc6145fda24a3e804ee55f0516525cec0d95eb1d13f17c4cdec9e",
  "prng_oracle.c": "6820c7b0187738649b86c09e04be1647fde6e51aebfbb31feefcadc853ab5abc",
  "semantic-corpus.json": "018207de81161e455c21895e53e5409785febfd99e303f7b5bdc6f9b901b10eb"
}
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    started=time.monotonic_ns();before_children=resource.getrusage(resource.RUSAGE_CHILDREN)
    before_parent=time.process_time_ns()
    def timeout(*_):raise TimeoutError("process PRNG full original180wall")
    signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,180)
    ap=argparse.ArgumentParser();ap.add_argument("--context",type=Path,required=True)
    ap.add_argument("--inputs",type=Path,required=True);args=ap.parse_args()
    assert sys.version_info[:3]==(3,12,14)
    assert sys.byteorder=="little"
    inputs=args.inputs.resolve();pins={};image=None;out=None
    report=dict(status="INCOMPLETE",scope="NEW_COMPLETE_SELECTED_PROCESS_PRNG_POLICY_WITH_CONTROLLED_FOREIGN_PEERS",
        fresh_B3_compiles=0,reference_C_compiles=0,original_C_calls=0,semantic_cases=0,
        protocol_controls=0,private_positive_controls=0,VM_entries=0,native_entries=0,
        actual_namespace_OS_effects=0,original_results_inherited=False,ordinary_Store_closed=False,
        actual_native_mutex_or_VFS_issuer=False,actual_process_limits=dict(
            cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),address=list(resource.getrlimit(resource.RLIMIT_AS)),
            core=list(resource.getrlimit(resource.RLIMIT_CORE))))
    def pin(path,expected=None):
        path=Path(path).absolute();info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        raw=path.read_bytes()
        row=dict(path=str(path),bytes=len(raw),sha256=sha(raw),git=git(raw),mode=stat.S_IMODE(info.st_mode))
        if expected is not None:assert row["sha256"]==expected,(str(path),row,expected)
        if str(path) in pins:assert pins[str(path)]==row
        pins[str(path)]=row;return raw
    def module(name,path,expected):
        raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        value=importlib.util.module_from_spec(spec);sys.modules[name]=value
        exec(compile(raw,str(path),"exec"),value.__dict__)
        return value
    primary=None
    try:
        context=json.loads(pin(args.context));ref=Path(context["reference"]);out=Path(context["prng_evidence"])
        out.mkdir(parents=False,exist_ok=False)
        pin(__file__)
        for filename,expected in PINS.items():pin(inputs/filename,expected)
        sys.path.insert(0,str(ref))
        module("tools.generate_hia_agent_namespace_store",inputs/"generate_hia_agent_namespace_store.py",PINS["generate_hia_agent_namespace_store.py"])
        module("tools.generate_hia_agent_namespace_objects",inputs/"generate_hia_agent_namespace_objects.py",PINS["generate_hia_agent_namespace_objects.py"])
        author=module("hia_prng_author",inputs/"generate_hia_namespace_process_prng.py",PINS["generate_hia_namespace_process_prng.py"])
        support=module("hia_prng_test_support",inputs/"prng_test_mechanics.py",PINS["prng_test_mechanics.py"])
        protocol=module("hia_prng_test_protocol",inputs/"prng_protocol_controls.py",PINS["prng_protocol_controls.py"])
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        import tools.qualify_hia_selfhost as qualifier
        assert Path(qualifier.__file__).resolve()==ref/"tools/qualify_hia_selfhost.py"
        assert Path(qualifier.CHILD).resolve()==ref/"tools/hia_selfhost_child.py"
        compiler=Path(context["compiler"]);compiler_raw=pin(compiler,B3);assert len(compiler_raw)==669556
        pin(qualifier.CHILD)
        corpus=json.loads(pin(inputs/"semantic-corpus.json",PINS["semantic-corpus.json"]))
        assert corpus["counts"]==dict(scenarios=34,complete_original_C_calls=122,random_calls=103,save_restore_calls=19)
        assert len(corpus["scenarios"])==34 and sum(len(s["operations"]) for s in corpus["scenarios"])==122
        document=author.document()
        document_raw=(json.dumps(document,sort_keys=True,separators=(",",":"))+"\n").encode()
        (out/"prng.document.json").write_bytes(document_raw)
        profile=dict(functions=len(document["functions"]),blocks=sum(len(f["blocks"]) for f in document["functions"]),
            ops=sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"]),
            max_blocks=max(len(f["blocks"]) for f in document["functions"]),
            max_block_params=max(len(b["params"]) for f in document["functions"] for b in f["blocks"]))
        report.update(profile=profile,function_profiles=[dict(name=f["name"],blocks=len(f["blocks"]),
            ops=sum(len(b["ops"]) for b in f["blocks"]),max_block_params=max(len(b["params"]) for b in f["blocks"]))
            for f in document["functions"]])
        save(out/"summary.json",report);print("NAMESPACE_PRNG_PROFILE "+json.dumps(profile,sort_keys=True),flush=True)
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
        assert profile["max_blocks"]<=256 and profile["max_block_params"]<=16
        source=render_assembly(document).encode();program=assemble_program(source)
        (out/"agent_namespace_sqlite3461_prng_r1.hiaasm").write_bytes(source)
        compile_dir=out/"compile";compile_dir.mkdir()
        image_path,receipt=qualifier.compile_stage(compile_dir,"process-prng",compiler,source)
        image_raw=pin(image_path)
        assert receipt["source_sha256"]==receipt["input_sha256"]==sha(source)
        assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
        assert receipt["produced_sha256"]==sha(image_raw) and receipt["produced_bytes"]==len(image_raw)
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        assert receipt["runner_sha256"]==sha(pin(qualifier.CHILD))
        request=json.loads((compile_dir/"process-prng.request.json").read_bytes())
        assert request["capacity"]==request["workspace_size"]==1<<20 and 0<len(image_raw)<=1<<20
        report.update(fresh_B3_compiles=1,compile_receipt=receipt,
            canonical_source=dict(path=str(out/"agent_namespace_sqlite3461_prng_r1.hiaasm"),bytes=len(source),sha256=sha(source)),
            image=dict(path=str(image_path),bytes=len(image_raw),sha256=sha(image_raw)))
        # Original C source is copied unchanged; only declarations and external
        # dependency hooks are supplied. There is no translated PRNG reference.
        cdir=out/"original-C-oracle";cdir.mkdir()
        for filename in ("random.c","sqliteInt.h","prng_oracle.c"):
            raw=pin(inputs/filename,PINS[filename]);target=cdir/filename
            target.write_bytes(raw);target.chmod(0o644);assert target.read_bytes()==raw
            pin(target,PINS[filename])
        cc=shutil.which("cc");assert cc,"C compiler unavailable"
        cc=Path(cc).resolve(strict=True);cc_identity=pin(cc)
        library=cdir/"original-prng.so"
        argv=[str(cc),"-std=c11","-O2","-fPIC","-shared","-fno-strict-aliasing",
              "-Wall","-Wextra","-Werror","-Wl,-Bsymbolic-functions","prng_oracle.c","-o",str(library)]
        parent=os.getpid();libc=ctypes.CDLL(None,use_errno=True)
        libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
        libc.prctl.restype=ctypes.c_int
        def c_limits():
            resource.setrlimit(resource.RLIMIT_CPU,(10,10))
            resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
            resource.setrlimit(resource.RLIMIT_CORE,(0,0))
            if libc.prctl(1,signal.SIGKILL,0,0,0)!=0:os._exit(125)
            if os.getppid()!=parent:os._exit(126)
        proc=None;c_primary=None;stdout=b"";stderr=b"";c_started=time.monotonic_ns()
        c_before=resource.getrusage(resource.RUSAGE_CHILDREN)
        save(cdir/"compile-request.json",dict(argv=argv,cwd=str(cdir),source_pins={k:PINS[k] for k in ("random.c","sqliteInt.h","prng_oracle.c")},
            limits=dict(cpu_seconds=10,wall_seconds=20,address_bytes=256<<20,core_bytes=0),compiler_path=str(cc)))
        try:
            proc=subprocess.Popen(argv,cwd=cdir,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                  start_new_session=True,preexec_fn=c_limits)
            stdout,stderr=proc.communicate(timeout=20)
            assert proc.returncode==0,("original C fixture compile",proc.returncode)
        except BaseException as error:
            c_primary=error
        finally:
            cleanup=[]
            if proc is not None:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                except BaseException as error:cleanup.append(repr(error))
                try:stdout,stderr=proc.communicate(timeout=5)
                except BaseException as error:cleanup.append(repr(error))
                for stream in (proc.stdin,proc.stdout,proc.stderr):
                    if stream is not None:
                        try:stream.close()
                        except BaseException as error:cleanup.append(repr(error))
            (cdir/"compile.stdout").write_bytes(stdout);(cdir/"compile.stderr").write_bytes(stderr)
            c_after=resource.getrusage(resource.RUSAGE_CHILDREN)
            c_cpu=c_after.ru_utime+c_after.ru_stime-c_before.ru_utime-c_before.ru_stime
            c_elapsed=time.monotonic_ns()-c_started
            save(cdir/"compile-result.json",dict(returncode=None if proc is None else proc.returncode,
                error=None if c_primary is None else repr(c_primary),cleanup_errors=cleanup,elapsed_ns=c_elapsed,
                reaped_child_cpu_seconds=c_cpu,stdout_bytes=len(stdout),stdout_sha256=sha(stdout),
                stderr_bytes=len(stderr),stderr_sha256=sha(stderr)))
            if c_primary is not None:
                for item in cleanup:c_primary.add_note(item)
                raise c_primary
            assert not cleanup and 0<=c_cpu<10 and 0<=c_elapsed<20_000_000_000
        oracle_raw=pin(library);report.update(reference_C_compiles=1,
            oracle_library=dict(path=str(library),bytes=len(oracle_raw),sha256=sha(oracle_raw)),
            oracle_scope=dict(original_random_c_unchanged=True,threadsafety=1,automatic_initialization=True,
                mutable_static_state=True,serial_save_restore_enabled=True,controlled_dependency_callbacks=True,
                actual_OS_mutex=False,actual_VFS_entropy=False,symbol_interposition_disabled=True))
        image=NativeHiaJsonImage(image_path,sha(image_raw))
        assert image.image_sha256==sha(image_raw)
        oracle=support.Oracle(library)
        for value in tuple(sys.modules.values()):
            filename=getattr(value,"__file__",None)
            if filename:
                path=Path(filename).resolve()
                if path.is_relative_to(ref) and path.suffix==".py":pin(path)
        save(out/"source-before.json",pins)
        cas=support.CAS(out/"cas");snapshots={};semantic=[]
        with gzip.open(out/"complete-entries.jsonl.gz","wt",encoding="utf-8",compresslevel=1) as ledger:
            pair=support.Pair(program,image,report,cas,ledger,out/"frontier.json")
            for scenario in corpus["scenarios"]:
                session=support.Session(pair,oracle,snapshots)
                for index,operation in enumerate(scenario["operations"]):
                    name=scenario["name"]+"/"+str(index)
                    save(out/"semantic-before.json",dict(name=name,operation=operation,
                         complete_prior_cases=report["semantic_cases"],original_C_calls=report["original_C_calls"]))
                    row=session.run(name,operation)
                    semantic.append(row);report["semantic_cases"]+=1
                    save(out/"semantic-progress.json",dict(status="INCOMPLETE",complete_cases=report["semantic_cases"],
                        VM_entries=report["VM_entries"],native_entries=report["native_entries"],last_complete_case=name))
            assert len(semantic)==report["original_C_calls"]==122
            assert set(snapshots)=={"grow","compute","completed","pending-1","pending-2","pending-3","pending-4","pending-5"}
            controls=protocol.run_controls(support,pair,snapshots)
            assert len(controls)==len(protocol.CONTROL_NAMES)==65
            assert {r["name"] for r in controls}==set(protocol.CONTROL_NAMES)
            assert all(row["refused"] for row in controls)
            report["protocol_controls"]=len(controls);report["private_positive_controls"]=1
        save(out/"semantic-results.json",semantic);save(out/"protocol-results.json",controls)
        assert report["VM_entries"]==report["native_entries"]>0
        for entry in cas.path.iterdir():
            assert entry.is_file() and not entry.is_symlink() and sha(entry.read_bytes())==entry.name
        report.update(status="PASS_COMPONENT_ONLY",semantic_scenarios=34,
            original_C_calls=122,random_original_C_calls=103,save_restore_original_C_calls=19,
            all_reference_output_current_saved_and_callback_order_equal=True,
            all_complete_return_input_output_workspace_equal=True,no_masks=True,
            source_image_bound=True,all_CAS_files_rehashed=True,
            permanent_refusal_where_poison_storage_exists=True,
            original_full_positive_int_no_added_quota=True)
    except BaseException as error:
        primary=error
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        cleanup=[]
        if image is not None:
            try:image._mapping.close()
            except BaseException as error:cleanup.append(dict(scope="native-image",error=repr(error)))
        after={};after_errors=[]
        for name,expected in pins.items():
            try:
                path=Path(name);info=path.lstat();assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
                raw=path.read_bytes()
                actual=dict(path=name,bytes=len(raw),sha256=sha(raw),git=git(raw),mode=stat.S_IMODE(info.st_mode))
                after[name]=actual;assert actual==expected
            except BaseException as error:after_errors.append(dict(path=name,error=repr(error)))
        elapsed=time.monotonic_ns()-started
        children=resource.getrusage(resource.RUSAGE_CHILDREN)
        cpu=(time.process_time_ns()-before_parent)/1e9+children.ru_utime+children.ru_stime-before_children.ru_utime-before_children.ru_stime
        if not 0<=cpu<90:after_errors.append(dict(scope="complete-process-tree-CPU90",seconds=cpu))
        if not 0<=elapsed<180_000_000_000:after_errors.append(dict(scope="whole-leaf-wall180",elapsed_ns=elapsed))
        report.update(source_before=pins,source_after=after,source_pins_unchanged=pins==after and not after_errors,
            after_errors=after_errors,cleanup_errors=cleanup,whole_tree_CPU_seconds=cpu,
            elapsed_ns_including_source_after=elapsed)
        if after_errors or cleanup:report["status"]="FAIL"
        signal.setitimer(signal.ITIMER_REAL,0)
        if out is not None:save(out/"summary.json",report)
        print("NAMESPACE_PROCESS_PRNG "+json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS_COMPONENT_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
