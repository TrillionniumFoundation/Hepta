"""Actual complete assembly CLI with independent exact public references.
All native work executes the generated fixed ELF. Separate direct native
protocol negatives use explicit private fixture states and grant no authority.
"""
from pathlib import Path
from hashlib import sha256
import argparse,copy,ctypes,importlib.util,json,os,resource,shutil,signal,stat,struct,subprocess,sys,time,traceback,zlib
sys.dont_write_bytecode=True
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
def main():
    parser=argparse.ArgumentParser()
    for name in ("assets","reference","inactive-map","inactive-dir","sha-source","sha-image","out"):
        parser.add_argument("--"+name,type=Path,required=True)
    a=parser.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    assert sys.version_info[:3]==(3,12,14),sys.version
    root=Path(__file__).resolve().parents[1];reference=a.reference.resolve()
    sys.path[:0]=[str(root/"tools"),str(root.parent/"Hepta-agent-edit-native"),str(reference)]
    from build_hia_assembly_cli import build,Custody,protected,checked
    custody=Custody(out);read=custody.read;cas=custody.cas
    rows=[];private=[];native_count=reference_count=private_entries=0;bundle=None
    result=dict(status="INCOMPLETE",scope="NEW_COMPLETE_ASSEMBLY_THREE_PUBLIC_ACTIONS",
        old_counts_inherited=False,old_component_suites_rerun=False,whole_CLI_closed=False,
        installed_activated=False,cold_qualified=False,inactive_E_qualified=False,
        native_runtime_python=False,source_header_is_authority=False)
    try:
        read(__file__)
        elf,bundle=build(root,reference,a.assets,a.inactive_map,a.inactive_dir,
            a.sha_source,a.sha_image,out/"build",custody)
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        import generate_hia_assembly_service as service
        constants=service.CONSTANTS
        by_label={row["label"]:row for row in bundle["compiled"]}
        r=by_label["assembly_A_root"];root_native=NativeHiaJsonImage(read(r["image_path"]),expected_sha256=r["image_sha256"])
        r=by_label["assembly_control"];control_native=NativeHiaJsonImage(read(r["image_path"]),expected_sha256=r["image_sha256"])
        def put(work,name,value):struct.pack_into("<Q",work,constants[name],value)
        def cap(work,slot,value):struct.pack_into("<Q",work,constants["CAPS"]+slot*8,value)
        def native_entry(label,image,source,before):
            nonlocal private_entries
            s=protected(source);o=protected(b"",128);w=protected(before)
            row=dict(label=label,source=cas(source),before=cas(before),output_before=cas(bytes(128)))
            save(out/"protocol"/(label+".pending.json"),row)
            ret=int(image._entry(s[1],s[2],o[1],o[2],w[1],w[2]));private_entries+=1
            for item in(s,o,w):checked(item)
            after=ctypes.string_at(w[1],w[2]);output=ctypes.string_at(o[1],o[2])
            assert ctypes.string_at(s[1],s[2])==source
            row.update(returned=ret,after=cas(after),output_after=cas(output))
            save(out/"protocol"/(label+".json"),row)
            return ret,after,output
        work=bytearray(1<<20)
        for slot,count in ((constants["B_EMPTY"],1),(constants["B_PROGRAM"],100),
                           (constants["B_CONTROLLER"],1<<20),(constants["B_ARGV"],512),
                           (constants["B_PARSER"],1536)):cap(work,slot,count)
        initial=struct.pack("<16Q",int.from_bytes(b"HIACBI01","little"),1,1,17,23,29,3,4300,100,512,1536,16,1024,32,0,0)
        valid_before=bytes(work)
        ret,started,ev=native_entry("valid-root-switch",root_native,initial,valid_before)
        event=struct.unpack("<16Q",ev)
        assert ret==128 and event[:4]==(constants["EVENT_MAGIC"],8,17,1)
        assert event[4]==59 and all(x==0 for x in event[5:])
        ack=struct.pack("<8Q",constants["ACK_MAGIC"],17,1,8,0,0,0,0)
        ret,pending,ev=native_entry("valid-controller-grow",control_native,ack,started)
        event=struct.unpack("<16Q",ev)
        assert ret==128 and event[:4]==(constants["EVENT_MAGIC"],2,17,2)
        assert event[4:6]==(51,96) and all(x==0 for x in event[6:])
        for number,(at,value) in enumerate(((0,0),(8,2),(16,2),(24,0),(32,0),(40,0),
            (48,2),(56,639),(64,101),(72,513),(80,1535),(88,15),(96,1025),(104,31),(112,1),(120,1))):
            wrong=bytearray(initial);struct.pack_into("<Q",wrong,at,value)
            label="init-"+str(number)
            ret,after,_=native_entry(label,root_native,bytes(wrong),valid_before)
            assert ret==0xfffffffd and struct.unpack_from("<Q",after,constants["L_STATUS"])[0]==3
            again,_,_=native_entry(label+"-poison",root_native,initial,after);assert again==0xfffffffd
            private.append(dict(label=label,permanent_poison=True,phase="INITIAL"))
        for number,(at,value) in enumerate(((0,0),(8,18),(16,2),(24,2),(32,1),(40,1),(48,8),(56,1))):
            wrong=bytearray(ack);struct.pack_into("<Q",wrong,at,value)
            label="switch-ack-"+str(number)
            ret,after,_=native_entry(label,control_native,bytes(wrong),started)
            assert ret==0xfffffffd and struct.unpack_from("<Q",after,constants["L_STATUS"])[0]==3
            again,_,_=native_entry(label+"-poison",control_native,ack,after);assert again==0xfffffffd
            private.append(dict(label=label,permanent_poison=True,phase="SWITCH_ACK"))
        for number,(name,value) in enumerate((("C_NEXT",69999),("L_NEXT_DRIVER",58),("A_ACTION",6),("AS_MAGIC",1))):
            wrong=bytearray(started);put(wrong,name,value);label="state-"+str(number)
            ret,after,_=native_entry(label,control_native,ack,bytes(wrong))
            assert ret==0xfffffffd and struct.unpack_from("<Q",after,constants["L_STATUS"])[0]==3
            again,_,_=native_entry(label+"-poison",control_native,ack,after);assert again==0xfffffffd
            private.append(dict(label=label,permanent_poison=True,phase="PRIVATE_STATE"))
        growack=struct.pack("<8Q",constants["ACK_MAGIC"],17,2,2,0,0,0,0)
        ret,after,ev=native_entry("valid-grow-ack-once",control_native,growack,pending)
        assert ret==128 and struct.unpack_from("<Q",ev,8)[0]==4
        ret,poisoned,_=native_entry("duplicate-grow-ack",control_native,growack,after)
        assert ret==0xfffffffd
        ret,_,_=native_entry("duplicate-grow-ack-poison",control_native,growack,poisoned);assert ret==0xfffffffd
        private.append(dict(label="duplicate-grow-ack",permanent_poison=True,phase="GROW_ACK"))
        assert len(private)==29
        save(out/"protocol-controls.json",private)

        # Construct the whole immutable public corpus before executing its first
        # native process. No expected row is removed after an observed failure.
        syntax=load_module("assembly_retained_syntax_corpus",root/"tests/assembly_syntax_corpus_reference.py")
        render=load_module("assembly_retained_render_corpus",root/"tests/assembly_render_corpus_reference.py")
        read(root/"tests/assembly_syntax_corpus_reference.py");read(root/"tests/assembly_render_corpus_reference.py")
        from hepta.hia_agent_assembly import render_assembly
        from tests.test_hia_program import arithmetic,resource_program,joined_loan_program
        plans=[]
        def add(label,action,raw,setup="none",close_stdin=False,umask=0o22):
            assert type(raw) is bytes
            plans.append(dict(label=label,action=action,raw=raw,setup=setup,close_stdin=close_stdin,umask=umask))
        chosen_prefixes=("basic-","crlf-","empty-exports-","absent-exports-","no-final-lf-",
            "source-","header-","attrs-","loans-","name-width-","list-","function-count-",
            "global-block","global-op","total-lines","line-bytes","source-bytes")
        chosen_exact={"duplicate-exports","late-exports","invalid-fn","missing-end","double-term",
            "missing-block","extra-line","fn-empty-before-bad-name","ret-empty-before-bad",
            "op-args-before-outs","unicode-space-160-params","unicode-space-133-fn",
            "unicode-space-8192-effects","unicode-space-8239-attrs",
            "control-before-earlier-syntax-0","control-before-earlier-syntax-65279"}
        selected=[]
        for label,value,digits in syntax.corpus():
            if digits!=4300 or type(value) not in (str,bytes):continue
            if not(label.startswith(chosen_prefixes) or label in chosen_exact):continue
            raw=value if type(value) is bytes else value.encode("utf-8","surrogatepass")
            # Keep equivalent text-vs-bytes component fixtures only once here;
            # the public CLI always obtains actual file bytes.
            if label.endswith("-bytes"):continue
            selected.append(label)
            add("import-"+label,"import-assembly",raw)
            add("check-"+label,"check-assembly",raw)
        assert len(selected)>80 and all(n in selected for n in chosen_exact)
        generated=render.public_corpus(reference,read)
        assert len(generated)==309
        for label,value in generated:
            raw=value if type(value) is bytes else json.dumps(value,ensure_ascii=True,separators=(",",":"),allow_nan=False).encode()
            add("render-"+label,"render-assembly",raw)
        for kind,document in (("resource",resource_program()),("loan",joined_loan_program())):
            document=copy.deepcopy(document);document["schema"]="hepta.hia.program.v8"
            raw=render_assembly(document).encode()
            mutations=[("valid",raw)]
            if kind=="resource":
                mutations.extend((("missing-drop",raw.replace(b"  _ = owner.drop(moved)\n",b"")),
                    ("use-after-move",raw.replace(b"owner.drop(moved)",b"owner.drop(owner)")),
                    ("live-overlap",raw.replace(b"  _ = loan.end(writer)\n",b""))))
            for label,data in mutations:
                for action in ("import-assembly","check-assembly"):
                    add(kind+"-"+label+"-"+action,action,data)
        seed=syntax.source_text().encode()
        for label,raw in (("bad-signature",seed.replace(b"block entry(a:u32,b:u32)",b"block entry(a:u64,b:u32)")),
                         ("duplicate-ssa",seed.replace(b"b64:u64",b"a64:u64")),
                         ("unknown-op",seed.replace(b"int.add.wrap",b"int.add.guess")),
                         ("missing-attrs",seed.replace(b' {"mode":"wrap"}',b"")),
                         ("bad-result-type",seed.replace(b"answer:u64",b"answer:u32"))):
            for action in ("import-assembly","check-assembly"):add(label+"-"+action,action,raw)
        primitive=json.dumps(dict(arithmetic(),schema="hepta.hia.program.v8"),separators=(",",":")).encode()
        for action,raw in (("import-assembly",seed),("render-assembly",primitive)):
            for setup in ("ordinary","relative","nested","existing","existing-dir","existing-link",
                "dangling","parent-file","parent-link","parent-dangling","unicode","bytes","dot",
                "parent-dotdot","double-leading","target-dot","target-trailing","long-name"):
                add(action+"-path-"+setup,action,raw,setup)
            add(action+"-fd-zero",action,raw,"ordinary",True)
            add(action+"-umask",action,raw,"nested",False,0o77)
        # Admission/roundtrip rejection wins over destination checks.
        add("import-invalid-before-existing","import-assembly",b"bad\n","existing")
        add("render-profile-before-existing","render-assembly",
            json.dumps(arithmetic(),separators=(",",":")).encode(),"existing")
        for action in ("verify","inspect","normalize"):
            add("retained-A-"+action,action,primitive)
        add("retained-A-normalize-publication","normalize",primitive,"nested")
        for action in ("import-assembly","render-assembly","check-assembly"):
            add(action+"-file-missing",action,b"","missing-input")
            add(action+"-file-directory",action,b"","directory-input")
            add(action+"-file-over-8MiB",action,b"x"*((8<<20)+1))
        assert len({p["label"] for p in plans})==len(plans)
        corpus=[]
        for p in plans:
            corpus.append({**{k:v for k,v in p.items() if k!="raw"},"input":cas(p["raw"])})
        save(out/"planned-corpus.json",dict(planned_cases=len(plans),syntax_cases=len(selected),
            renderer_cases=309,cases=corpus))
        result["expected_public_cases"]=len(plans);result["expected_syntax_sources"]=len(selected)

        oracle=out/"reference_cli.py"
        oracle.write_text("import sys\nsys.dont_write_bytecode=True\nsys.path.insert(0,"+repr(str(reference))+")\nfrom hepta.cli import hia_main\nraise SystemExit(hia_main(sys.argv[1:]))\n")
        read(oracle)
        libc=ctypes.CDLL(None,use_errno=True)
        libc.prctl.argtypes=[ctypes.c_int,*([ctypes.c_ulong]*4)];libc.prctl.restype=ctypes.c_int
        def invoke(label,kind,argv,cwd,closed,mask):
            nonlocal native_count,reference_count
            dest=out/"cases"/label/kind;dest.mkdir(parents=True,exist_ok=False)
            args=[str(elf),*argv] if kind=="native" else [sys.executable,"-I","-B",str(oracle),*argv]
            env=dict(PATH="",HOME="",LANG="C.UTF-8",LC_ALL="C.UTF-8",PYTHONINTMAXSTRDIGITS="4300",
                COLUMNS="80",PYTHONDONTWRITEBYTECODE="1",PYTHONNOUSERSITE="1")
            parent=os.getpid()
            def setup():
                if libc.prctl(1,signal.SIGKILL,0,0,0):
                    error=ctypes.get_errno();raise OSError(error,os.strerror(error))
                if os.getppid()!=parent:os.kill(os.getpid(),signal.SIGKILL)
                resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
                resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(mask)
                if closed:os.close(0)
            process=None;usage=status=None;timed_out=False;started=time.monotonic_ns()
            with (dest/"stdout.bin").open("wb") as stdout,(dest/"stderr.bin").open("wb") as stderr:
                try:
                    process=subprocess.Popen(args,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                        stdout=stdout,stderr=stderr,start_new_session=True,preexec_fn=setup)
                    if kind=="native":native_count+=1
                    else:reference_count+=1
                    while status is None:
                        pid,value,observed=os.wait4(process.pid,os.WNOHANG)
                        if pid:
                            status,usage=value,observed;process.returncode=os.waitstatus_to_exitcode(value);break
                        if time.monotonic_ns()-started>180_000_000_000:timed_out=True;break
                        time.sleep(0.01)
                finally:
                    original=sys.exception();errors=[]
                    if process is not None and process.returncode is None:
                        try:os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        except BaseException as error:errors.append(error)
                        try:
                            _,status,usage=os.wait4(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
                        except BaseException as error:errors.append(error)
                    if errors:
                        if original is None:raise errors[0]
                        for error in errors:original.add_note("child cleanup: "+repr(error))
            so=(dest/"stdout.bin").read_bytes();se=(dest/"stderr.bin").read_bytes()
            observation=dict(argv=argv,cwd=str(cwd),env=env,pid=process.pid,exit=process.returncode,
                wait_status=status,timed_out=timed_out,elapsed_ns=time.monotonic_ns()-started,
                user_cpu=usage.ru_utime,system_cpu=usage.ru_stime,maxrss_kib=usage.ru_maxrss,
                cpu_limit=90,wall_limit=180,address_limit=1<<30,close_stdin=closed,umask=mask,
                stdout=cas(so),stderr=cas(se))
            save(dest/"process.json",observation);assert not timed_out,(label,kind,"timeout")
            return (process.returncode,so,se),observation
        physical=out/"physical";physical.mkdir()
        def inventory(path):
            rows=[];objects=[]
            def walk(base):
                for child in sorted(base.iterdir(),key=lambda p:os.fsencode(p.name)):
                    s=child.lstat();row=dict(path_hex=os.fsencode(child.relative_to(path)).hex(),
                        type=stat.S_IFMT(s.st_mode),mode=stat.S_IMODE(s.st_mode))
                    observed=dict(row,dev=s.st_dev,inode=s.st_ino,nlink=s.st_nlink,size=s.st_size)
                    if stat.S_ISREG(s.st_mode):
                        data=child.read_bytes();row.update(bytes=len(data),sha256=digest(data));observed["data"]=cas(data)
                    elif stat.S_ISLNK(s.st_mode):
                        row["target_hex"]=os.fsencode(os.readlink(child)).hex();observed["target_hex"]=row["target_hex"]
                    rows.append(row);objects.append(observed)
                    if stat.S_ISDIR(s.st_mode):walk(child)
            walk(path);return rows,objects
        def destination(fx,kind):
            if kind in ("none","missing-input","directory-input"):return None
            if kind=="ordinary":return str(fx/"output")
            if kind=="relative":return "output"
            if kind=="nested":return "a/b/c/output"
            if kind=="existing":(fx/"output").write_bytes(b"preserved");return str(fx/"output")
            if kind=="existing-dir":(fx/"output").mkdir();return str(fx/"output")
            if kind in ("existing-link","dangling"):
                (fx/"output").symlink_to("input" if kind=="existing-link" else "absent");return str(fx/"output")
            if kind=="parent-file":(fx/"parent").write_bytes(b"regular");return "parent/output"
            if kind=="parent-link":(fx/"real").mkdir();(fx/"link").symlink_to("real",target_is_directory=True);return "link/output"
            if kind=="parent-dangling":(fx/"link").symlink_to("missing",target_is_directory=True);return "link/output"
            if kind=="unicode":return "é中😀/out-\n-\t-'\""
            if kind=="bytes":return os.fsdecode(b"invalid-\xff-\xfe/out-\x80")
            if kind=="dot":return "./output"
            if kind=="parent-dotdot":return "new/../output"
            if kind=="double-leading":return "/"+str(fx/"output")
            if kind=="target-dot":return "."
            if kind=="target-trailing":return "new-dir/"
            if kind=="long-name":return "n"*256
            raise AssertionError(kind)
        for plan in plans:
            label=plan["label"];fx=physical/label;observations=[];outputs=[];snapshots=[]
            for kind in ("reference","native"):
                if fx.exists():shutil.rmtree(fx)
                fx.mkdir(mode=0o700);source=fx/"input"
                if plan["setup"]=="directory-input":source.mkdir()
                elif plan["setup"]!="missing-input":source.write_bytes(plan["raw"])
                target=destination(fx,plan["setup"])
                before,raw_before=inventory(fx)
                save(out/"cases"/label/(kind+"-before.json"),dict(objects=raw_before,semantic=before))
                argv=[plan["action"],str(source)]
                if target is not None:argv+=["--output",target]
                answer,process=invoke(label,kind,argv,fx,plan["close_stdin"],plan["umask"])
                after,raw_after=inventory(fx)
                save(out/"cases"/label/(kind+"-after.json"),dict(objects=raw_after,semantic=after))
                outputs.append(answer);observations.append(process);snapshots.append((before,after))
            row=dict(label=label,action=plan["action"],reference=observations[0],native=observations[1],
                stdout_stderr_exit_equal=outputs[0]==outputs[1],filesystem_equal=snapshots[0]==snapshots[1])
            rows.append(row);save(out/"cases-so-far.json",rows)
            print("HIA_ASSEMBLY_PUBLIC_CASE "+json.dumps({k:v for k,v in row.items() if k not in("reference","native")},sort_keys=True),flush=True)
            assert row["stdout_stderr_exit_equal"],(label,outputs[0][0],outputs[1][0],digest(outputs[0][1]),digest(outputs[1][1]),digest(outputs[0][2]),digest(outputs[1][2]))
            assert row["filesystem_equal"],label
            shutil.rmtree(fx)
        assert len(rows)==len(plans)==native_count==reference_count
        assert all(r["stdout_stderr_exit_equal"] and r["filesystem_equal"] for r in rows)
        result.update(status="PASS",public_cases=len(rows),cases=rows,
            native_processes=native_count,reference_processes=reference_count,private_controls=len(private),
            private_native_entries=private_entries,actual_packer_entries=1,
            actual_new_B3_compilations=bundle["new_B3_compilations"],
            full_syntax_object_prefix_primitive_chain=True,actual_complete_render_roundtrip=True,
            canonical_roundtrip_compared_all_bytes=True,policy1_and_policy3_actual_publication=True,
            all_public_outputs_and_files_equal=True,private_controls_are_explicit_not_authority=True,
            table2_all_63_images_unchanged=True,inactive_E_executions=0,
            remaining=["Nondefault process locale and stdout configuration",
                       "Nondefault startup digits capture","Full installed dispatch",
                       "E runtime is inactive in this assembly qualification"])
    except BaseException as error:
        result.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc(),
            completed_cases=len(rows),cases=rows,native_processes=native_count,reference_processes=reference_count,
            private_native_entries=private_entries,private_controls=len(private),build=bundle)
        traceback.print_exc();raise
    finally:
        original=sys.exception()
        try:
            result["custody"]=custody.finish()
            save(out/"summary.json",result)
            print("HIA_ASSEMBLY_PUBLIC_SUMMARY "+json.dumps({k:v for k,v in result.items() if k!="cases"},sort_keys=True),flush=True)
        except BaseException as error:
            if original is None:raise
            original.add_note("custody failure: "+repr(error))
if __name__=="__main__":main()
