"""New public CLI argv/file/E/pretty integration, with exact retained assets.

Only the parent HIA is newly compiled in this integration; exact new E images are read back from their separately completed bounded compilation. The native ELF contains no interpreter,
shell, Python callback, host business dispatcher or external subprocess. The
separate exact CPython CLI is the oracle. No previous case count is inherited.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,importlib.util,json,os,resource,signal,stat,struct,subprocess,sys,tempfile,time,traceback,zlib

def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def protected(raw,size=None):
    size=len(raw) if size is None else size
    assert len(raw)<=size
    guard=b"HIA-FINITE-CARRIER-CANARY-32BYTE";assert len(guard)==32
    backing=ctypes.create_string_buffer(64+max(1,size));at=ctypes.addressof(backing)+32
    ctypes.memmove(at-32,guard,32);ctypes.memmove(at,raw,len(raw))
    ctypes.memmove(at+max(1,size),guard,32)
    return backing,at,size,guard
def checked(row):
    backing,at,size,guard=row
    assert ctypes.string_at(at-32,32)==guard and ctypes.string_at(at+max(1,size),32)==guard
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--assets",type=Path,required=True)
    ap.add_argument("--reference",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True)
    ap.add_argument("--edit-development",type=Path,required=True)
    a=ap.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    assert sys.version_info[:3]==(3,12,14),sys.version
    root=Path(__file__).resolve().parents[1];reference=a.reference.resolve()
    pins={};cases=[];compiled=[];native_count=reference_count=packer_entries=0
    result=dict(status="INCOMPLETE",scope="NEW_PUBLIC_CLI_E_NO_OUTPUT_NATIVE_INTEGRATION",
        old_cases_inherited=False,whole_cli_closed=False,installed_entry_activated=False,
        publication_closed=False,cold_qualified=False,native_runtime_python=False)
    def read(path):
        path=Path(path).resolve();raw=path.read_bytes()
        if path in pins:assert pins[path]==(len(raw),digest(raw))
        pins[path]=(len(raw),digest(raw));return raw
    def from_row(row):
        raw=read(row["path"]);assert (len(raw),digest(raw))==(row["bytes"],row["sha256"])
        return raw
    def cas(raw):
        raw=bytes(raw);h=digest(raw);p=out/"cas"/(h+".zlib");p.parent.mkdir(exist_ok=True)
        if not p.exists():p.write_bytes(zlib.compress(raw,6))
        assert zlib.decompress(p.read_bytes())==raw
        return dict(bytes=len(raw),sha256=h,path="cas/"+p.name,compression="zlib")
    try:
        read(__file__)
        for path in sorted((root/"tools").glob("*.py")):read(path)
        helper=root.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py"
        lower=root.parent/"native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py"
        assert digest(read(helper))=="555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"
        assert digest(read(lower))=="fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
        assert digest(read(root/"tools/cli_entry_owner.py"))=="529a4c5cab15d8fb74e81d991d79b32070078a4149ca5f87ccfa966f6e95e496"
        assets=json.loads(read(a.assets))
        assert assets["status"]=="PASS_READBACK_ONLY" and not assets["old_case_counts_inherited"]
        assert assets["source_image_bindings"] and assets["preserved_original_inputs_unchanged"]
        compiler=assets["compiler"];compiler_raw=from_row(compiler)
        assert (len(compiler_raw),digest(compiler_raw))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
        # Freeze every source and image before any actual image is mapped.
        parent_images={};service_images={};edit_images={}
        edit=a.edit_development.resolve()
        edit_report=json.loads(read(edit/"summary.json"))
        assert edit_report["generation"]["status"]=="PASS_GENERATION_AND_B3_ONLY"
        assert edit_report["all_original_bytes_sha_modes_unchanged"]
        original_edit=edit/"original/composed-latest-editor/development"
        edit_bundle=json.loads(read(original_edit/"build-r2/bundle.json"))
        source_candidates=list((edit/"original").rglob("*"))
        def exact_archived(size,sha):
            matches=[p for p in source_candidates if p.is_file() and p.stat().st_size==size and digest(p.read_bytes())==sha]
            assert matches,(size,sha)
            return read(matches[0])
        for role,row in edit_bundle["components"].items():
            exact_archived(row["source_bytes"],row["source_sha256"])
            edit_images[int(role)]=exact_archived(row["image_bytes"],row["image_sha256"])
        for role,row in edit_report["generation"]["components"].items():
            sub=edit/"generation"/("role-"+role)
            hia=read(sub/"source.hiaasm")
            receipt=json.loads(read(sub/"edit-service.receipt.json"))
            image=read(sub/"edit-service.image.bin")
            assert len(hia)==row["source_bytes"] and digest(hia)==row["source_sha256"]
            assert len(image)==row["image_bytes"] and digest(image)==row["image_sha256"]
            assert receipt["status"]=="returned" and receipt["abi_status"]==0 and receipt["source_unchanged"]
            assert receipt["input_sha256"]==digest(hia) and receipt["produced_sha256"]==digest(image)
            assert receipt["artifact_sha256"]=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
            edit_images[int(role)]=image
        assert set(edit_images)==set(range(1,64))
        assert set(edit_report["generation"]["components"])=={"56","58"}
        for roles,dest in ((assets["cli_roles"],parent_images),(assets["service_roles"],service_images)):
            for role,row in roles.items():
                from_row(row["source"]);dest[int(role)]=from_row(row["image"])
                if "manifest" in row:from_row(row["manifest"])
        packer_row=assets["packer"]
        packer_source=from_row(packer_row["source"]);packer_image=from_row(packer_row["image"])
        packer_manifest=json.loads(from_row(packer_row["manifest"]))
        assert packer_manifest["receipt"]["input_sha256"]==digest(packer_source)
        assert packer_manifest["receipt"]["produced_sha256"]==digest(packer_image)
        prefix=from_row(packer_row["prefix"]);layout=json.loads(from_row(packer_row["layout"]))
        assembly=from_row(packer_row["assembly"])
        assert digest(assembly)=="f06b915cdfb415894e05c8c4a3e7bbdba9fe9c0bc5b8791878516f91cdfa66de"
        assert len(layout["tables"])==3 and len(set(layout["tables"]))==3
        for at in layout["tables"]:assert 176<=at<=len(prefix)-512 and prefix[at:at+512]==bytes(512)
        inputs=[]
        for row in assets["inputs"]:inputs.append((row,from_row(row["input"])))
        assert len(inputs)==25 and sum(r["accepted"] for r,raw in inputs)==17
        sys.path[:0]=[str(root/"tools"),str(root.parent/"Hepta-agent-edit-native"),str(reference)]
        from tools.qualify_hia_selfhost import compile_stage
        assert digest(read(reference/"tools/qualify_hia_selfhost.py"))=="2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"
        from hepta.hia_agent_assembly import assemble_program,render_assembly
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        import cli_authoring,cli_business_parent
        body=cli_authoring.expanded(cli_business_parent.BODY+cli_business_parent.literals()+cli_business_parent.COMMON,
                                    cli_business_parent.CONSTANTS)
        document=cli_authoring.document(body,"cli_public_E_parent")
        profile=cli_authoring.profile(document)
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
        assert profile["max_params"]<=16
        where=out/"parent-compile";where.mkdir()
        hia=render_assembly(document).encode()
        (where/"expanded.py").write_text(body);(where/"source.hiaasm").write_bytes(hia)
        save(where/"profile.json",profile)
        assemble_program(hia)
        image,receipt=compile_stage(where,"cli-public-E-parent",Path(compiler["path"]),hia)
        parent=read(image)
        assert receipt["artifact_sha256"]==digest(compiler_raw)
        assert receipt["input_sha256"]==digest(hia) and receipt["produced_sha256"]==digest(parent)
        assert receipt["status"]=="returned" and receipt["abi_status"]==0
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        compiled.append(dict(source_bytes=len(hia),source_sha256=digest(hia),image_bytes=len(parent),
            image_sha256=digest(parent),profile=profile,receipt=receipt))
        save(where/"manifest.json",compiled[-1]);parent_images[7]=parent
        assert set(parent_images)==set(range(1,8))
        # Both complete finite tables are present. Every new case invokes
        # the actual E root and its exact original query/application peers.
        parts=[b""]*133
        for role,raw in parent_images.items():parts[role-1]=raw
        for role,raw in service_images.items():parts[7+role-1]=raw
        for role,raw in edit_images.items():parts[70+role-1]=raw
        assert parts[6] and parts[62] and parts[125]
        packet=struct.pack("<8Q",int.from_bytes(b"HIACBP01","little"),1,3,133,
            1128+sum(map(len,parts)),1128,64,0)+struct.pack("<133Q",*map(len,parts))+b"".join(parts)
        expected=bytearray(prefix)
        for index,raw in enumerate(parts):
            if not raw:continue
            assert len(raw)<=1048576
            expected+=bytes((-len(expected))&15)
            table=0 if index<7 else 1 if index<70 else 2
            role=index+1 if table==0 else index-6 if table==1 else index-69
            struct.pack_into("<Q",expected,layout["tables"][table]+role*8,0x400000+len(expected))
            expected+=raw
        struct.pack_into("<Q",expected,96,len(expected));struct.pack_into("<Q",expected,104,len(expected))
        # Re-read all original inputs before mapping; no warm cached digest can
        # endorse changed disk bytes under an earlier manifest.
        assert all((p.stat().st_size,digest(p.read_bytes()))==v for p,v in pins.items())
        packer=NativeHiaJsonImage(packer_image,expected_sha256=digest(packer_image))
        source_buffer=protected(packet);output=protected(b"",len(expected));scratch=protected(b"",64)
        ret=int(packer._entry(source_buffer[1],source_buffer[2],output[1],output[2],scratch[1],scratch[2]))
        packer_entries+=1
        for row in (source_buffer,output,scratch):checked(row)
        assert ctypes.string_at(source_buffer[1],source_buffer[2])==packet
        assert ctypes.string_at(scratch[1],64)==bytes(64)
        executable=ctypes.string_at(output[1],output[2])
        save(out/"pack.json",dict(input=cas(packet),output=cas(executable),expected=cas(expected),
             return_value=ret,full_expected_bytes_equal=executable==bytes(expected),
             full_input_unchanged=True,full_scratch_unchanged=True))
        assert ret==len(expected) and executable==bytes(expected)
        elf=out/"hia-cli-public-E-development";elf.write_bytes(executable);elf.chmod(0o700)
        read(elf)
        assert executable[:4]==b"\x7fELF" and struct.unpack_from("<H",executable,56)[0]==2
        assert [struct.unpack_from("<I",executable,64+56*i)[0] for i in range(2)]==[1,0x6474e551]
        save(out/"bundle.json",dict(scope=result["scope"],old_cases_inherited=False,assets=str(a.assets),
            parent=compiled[-1],actual_packer_entries=1,executable_path=str(elf),
            executable_bytes=len(executable),executable_sha256=digest(executable),
            publication_closed=False,installed_entry_activated=False))
        oracle=out/"reference-cli.py"
        oracle.write_text("import sys\nsys.dont_write_bytecode=True\nsys.path.insert(0,"+repr(str(reference))+
                         ")\nfrom hepta.cli import hia_main\nraise SystemExit(hia_main(sys.argv[1:]))\n")
        read(oracle)
        libc=ctypes.CDLL(None,use_errno=True)
        libc.prctl.argtypes=[ctypes.c_int,*([ctypes.c_ulong]*4)];libc.prctl.restype=ctypes.c_int
        def invoke(label,kind,argv,cwd,close_stdin=False):
            nonlocal native_count,reference_count
            dest=out/"cases"/label/kind;dest.mkdir(parents=True,exist_ok=False)
            command=[str(elf),*argv] if kind=="native" else [sys.executable,"-I","-B",str(oracle),*argv]
            env=dict(PATH="",HOME="",LANG="C.UTF-8",LC_ALL="C.UTF-8",PYTHONINTMAXSTRDIGITS="4300",
                     COLUMNS="80",PYTHONDONTWRITEBYTECODE="1",PYTHONNOUSERSITE="1")
            expected_parent=os.getpid()
            def before_exec():
                if libc.prctl(1,signal.SIGKILL,0,0,0):
                    e=ctypes.get_errno();raise OSError(e,os.strerror(e))
                if os.getppid()!=expected_parent:os.kill(os.getpid(),signal.SIGKILL)
                resource.setrlimit(resource.RLIMIT_CPU,(90,90))
                resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
                resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                if close_stdin:os.close(0)
            process=None;status=usage=None;timed_out=False;started=time.monotonic_ns()
            with (dest/"stdout.bin").open("wb") as so,(dest/"stderr.bin").open("wb") as se:
                try:
                    process=subprocess.Popen(command,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                        stdout=so,stderr=se,start_new_session=True,preexec_fn=before_exec)
                    if kind=="native":native_count+=1
                    else:reference_count+=1
                    while status is None:
                        pid,value,observed=os.wait4(process.pid,os.WNOHANG)
                        if pid:
                            status,usage=value,observed;process.returncode=os.waitstatus_to_exitcode(status);break
                        if time.monotonic_ns()-started>30_000_000_000:timed_out=True;break
                        time.sleep(0.01)
                finally:
                    original=sys.exception();errors=[]
                    if process is not None and process.returncode is None:
                        try:os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        except BaseException as exc:errors.append(exc)
                        try:
                            _,status,usage=os.wait4(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
                        except BaseException as exc:errors.append(exc)
                    if errors:
                        if original is None:raise errors[0]
                        for exc in errors:original.add_note("child cleanup: "+repr(exc))
            stdout=(dest/"stdout.bin").read_bytes();stderr=(dest/"stderr.bin").read_bytes()
            observed=dict(argv=argv,cwd=str(cwd),env=env,close_stdin=close_stdin,pid=process.pid,
                exit=process.returncode,wait_status=status,timed_out=timed_out,
                elapsed_ns=time.monotonic_ns()-started,user_cpu=usage.ru_utime,system_cpu=usage.ru_stime,
                maxrss_kib=usage.ru_maxrss,cpu_limit=90,address_limit=1<<30,wall_limit=30,
                stdout=cas(stdout),stderr=cas(stderr))
            save(dest/"process.json",observed)
            assert not timed_out,(label,kind,"timeout")
            return (process.returncode,stdout,stderr),observed
        def compare(label,argv,cwd,close_stdin=False):
            wanted,rr=invoke(label,"reference",argv,cwd,close_stdin)
            actual,nr=invoke(label,"native",argv,cwd,close_stdin)
            row=dict(label=label,status="PASS" if actual==wanted else "FAIL",
                scope="PUBLIC_ARGV_FILE_E_PRETTY_FULL_OUTPUT_EXIT_EQUALITY",reference=rr,native=nr,equal=actual==wanted)
            cases.append(row);save(out/"cases-so-far.json",cases)
            print("HIA_PUBLIC_E_CLI_CASE "+json.dumps(dict(label=label,status=row["status"],
                native_exit=actual[0],reference_exit=wanted[0],stdout_bytes=len(actual[1]),stderr_bytes=len(actual[2])),sort_keys=True),flush=True)
            assert actual==wanted,(label,actual[0],wanted[0],digest(actual[1]),digest(wanted[1]),
                                  digest(actual[2]),digest(wanted[2]))
        from copy import deepcopy
        from itertools import permutations
        from hepta.hia_program import verify_program
        from hepta.hia_edit_query import prepare_edit
        from hepta.hia_edit_batch import prepare_batch
        original_input=read(original_edit/"snapshot-whole-boundary-r1/case-000/input.bin")
        assert digest(original_input)=="a8f3525be4e930fd7db01fdd309c38d74be6d54fa9c94c75c802145dae9627d4"
        words=struct.unpack_from("<8Q",original_input)
        original_program=json.loads(original_input[64:64+words[4]])
        selected=[f for f in original_program["functions"] if f["name"]=="constant"]
        assert len(selected)==1
        case_inputs=[]
        with tempfile.TemporaryDirectory(prefix="hia-public-E-fixtures-") as temporary:
            fx=Path(temporary)
            def file(name,raw):
                raw=bytes(raw);p=fx/name;p.write_bytes(raw)
                frozen=out/"input-copies"/name;frozen.parent.mkdir(parents=True,exist_ok=True);frozen.write_bytes(raw)
                case_inputs.append((p,raw));return p
            def wire(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
            paths={}
            for version in range(1,9):
                doc=deepcopy(original_program)
                doc["schema"]="hepta.hia.program.v"+str(version)
                doc["module"]="public_edit_cli"
                doc["functions"]=deepcopy(selected)
                program=verify_program(doc)
                target=file("program-v"+str(version)+".hia",program.canonical_bytes)
                selector=dict(function="constant",block="entry",output="value",fields=["attrs"])
                query=prepare_edit(program,**selector)
                selections=[selector]
                batch=prepare_batch(program,selections)
                qp=file("query-v"+str(version)+".json",wire(query))
                bp=file("batch-v"+str(version)+".json",wire(batch))
                sp=file("selections-v"+str(version)+".json",wire(selections))
                rp=file("response-v"+str(version)+".json",b'{"attrs":{"value":2}}')
                br=file("batch-response-v"+str(version)+".json",b'{"edits":[{"site":0,"changes":{"attrs":{"value":2}}}]}')
                paths[version]=(target,qp,bp,sp,rp,br)
                compare("core-v"+str(version)+"-single-query",["edit-query",str(target),"--function","constant","--block","entry","--value","value","--fields","attrs"],fx)
                compare("core-v"+str(version)+"-single-apply",["edit-apply",str(target),"--query",str(qp),"--response",str(rp)],fx)
                compare("core-v"+str(version)+"-batch-query",["edit-batch-query",str(target),"--selections",str(sp)],fx)
                compare("core-v"+str(version)+"-batch-apply",["edit-batch-apply",str(target),"--query",str(bp),"--response",str(br)],fx)
            target,qp,bp,sp,rp,br=paths[8]
            def single(fields="attrs",function="constant",block="entry",value="value"):
                return ["edit-query",str(target),"--function",function,"--block",block,"--value",value,"--fields",fields]
            for count in (1,2,3):
                for fields in permutations(("op","args","attrs"),count):
                    if fields==("attrs",):continue
                    compare("field-order-"+",".join(fields),single(",".join(fields)),fx)
            for index,fields in enumerate(("","op,","attrs,attrs","OP","op,args,attrs,op","attrs,,op","x","attrs"+"x"*1000)):
                compare("bad-fields-"+str(index),single(fields),fx)
            for label,kwargs in (
                ("missing-function",dict(function="absent")),
                ("missing-block",dict(block="absent")),("missing-output",dict(value="absent")),
                ("empty-function",dict(function="")),("unicode-function",dict(function="\u51fd\u6570")),
                ("surrogateescaped-function",dict(function="\udc80"))):
                compare(label,single(**kwargs),fx)
            invalid=file("invalid-query.json",b"{")
            empty=file("empty.json",b"")
            object_query=file("object-query.json",b"{}")
            invalid_response=file("invalid-response.json",b"\xff")
            missing=fx/"does-not-exist.json"
            comparisons=[
                ("single-query-read-before-response",["edit-apply",str(target),"--query",str(missing),"--response",str(invalid)]),
                ("single-query-decode-before-response",["edit-apply",str(target),"--query",str(invalid),"--response",str(missing)]),
                ("single-response-read-before-query-semantic",["edit-apply",str(target),"--query",str(object_query),"--response",str(missing)]),
                ("batch-response-read-before-query-decode",["edit-batch-apply",str(target),"--query",str(invalid),"--response",str(missing)]),
                ("single-empty-query",["edit-apply",str(target),"--query",str(empty),"--response",str(rp)]),
                ("single-empty-response",["edit-apply",str(target),"--query",str(qp),"--response",str(empty)]),
                ("single-bad-response-utf8",["edit-apply",str(target),"--query",str(qp),"--response",str(invalid_response)]),
            ]
            for label,argv in comparisons:compare(label,argv,fx)
            limits=[
                ("single-query-plus-one","edit-apply","--query",8388608,["--response",str(rp)]),
                ("batch-query-plus-one","edit-batch-apply","--query",1048576,["--response",str(br)]),
                ("selections-plus-one","edit-batch-query","--selections",8388608,[]),
                ("single-response-plus-one","edit-apply","--response",16384,["--query",str(qp)]),
                ("batch-response-plus-one","edit-batch-apply","--response",65536,["--query",str(bp)]),
            ]
            for label,action,option,limit,other in limits:
                oversized=file(label+".json",b" "*(limit+1))
                compare(label,[action,str(target),option,str(oversized),*other],fx)
            for label,argv in (
                ("single-query-output-empty",single()),
                ("single-apply-output-empty",["edit-apply",str(target),"--query",str(qp),"--response",str(rp)]),
                ("batch-query-output-empty",["edit-batch-query",str(target),"--selections",str(sp)]),
                ("batch-apply-output-empty",["edit-batch-apply",str(target),"--query",str(bp),"--response",str(br)])):
                compare(label,[*argv,"--output",""],fx)
            bad_program=file("invalid-program.hia",b"{")
            for action,tail in (
                ("edit-query",["--function","constant","--block","entry","--value","value","--fields","invalid"]),
                ("edit-apply",["--query",str(missing),"--response",str(missing)]),
                ("edit-batch-query",["--selections",str(missing)]),
                ("edit-batch-apply",["--query",str(missing),"--response",str(missing)])):
                compare("program-error-first-"+action,[action,str(bad_program),*tail],fx)
            compare("single-query-OS-fd-zero",single(),fx,True)
            unicode=file("actual-\u00e9-\u4e2d.hia",target.read_bytes())
            compare("single-apply-Unicode-program-path",["edit-apply",str(unicode),"--query",str(qp),"--response",str(rp)],fx)
            assert all(p.read_bytes()==raw for p,raw in case_inputs)
            assert len(cases)==82,(len(cases),[row["label"] for row in cases])
        assert native_count==reference_count==82 and packer_entries==1
        assert len(compiled)==1 and all(row["equal"] for row in cases)
        result.update(status="PASS",exact_equivalence_cases=82,
            native_processes=native_count,reference_processes=reference_count,
            actual_packer_entries=packer_entries,new_parent_B3_compilations=1,
            new_E_B3_images_reused_from_exact_generation=2,
            real_E_service_bound=True,public_argv_and_file_owner=True,
            complete_stdout_stderr_exit_equal=True,cases=cases)
    except BaseException as error:
        result.update(status="FAIL",completed_cases=len(cases),error_class=type(error).__name__,
            error=str(error),traceback=traceback.format_exc(),native_processes=native_count,
            reference_processes=reference_count,actual_packer_entries=packer_entries,
            new_parent_B3_compilations=len(compiled))
        traceback.print_exc();raise
    finally:
        original=sys.exception()
        try:
            changed=[str(p) for p,v in pins.items() if (p.stat().st_size,digest(p.read_bytes()))!=v]
            result["source_pins_unchanged"]=not changed;result["changed_paths"]=changed
            save(out/"source-pins.json",[dict(path=str(p),bytes=v[0],sha256=v[1]) for p,v in pins.items()])
            save(out/"compiles.json",compiled);save(out/"summary.json",result)
            print("HIA_PUBLIC_E_CLI_SUMMARY "+json.dumps({k:v for k,v in result.items() if k!="cases"},sort_keys=True),flush=True)
            assert not changed
        except BaseException as error:
            if original is None:raise
            original.add_note("final custody: "+repr(error))
if __name__=="__main__":main()
