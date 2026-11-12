"""Fresh 140-image public-A publication and private policy-2 publication join.

All policy, path, JSON encoding, temp ownership, stage buffering, SHA, publication,
cleanup and continuation decisions execute as HIA inside the fixed ELF. Exact
CPython CLI is a separate oracle. The policy-2 query issuer is an explicit private
fixture, not E semantic qualification. Original completed suites are not rerun.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,importlib,json,os,resource,shutil,signal,stat,struct,subprocess,sys,tempfile,time,traceback,zlib

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
    ap.add_argument("--sha-source",type=Path,required=True)
    ap.add_argument("--sha-image",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True)
    a=ap.parse_args();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    assert sys.version_info[:3]==(3,12,14),sys.version
    root=Path(__file__).resolve().parents[1];reference=a.reference.resolve()
    pins={};cases=[];compiled=[];presentation_cases=[]
    native_count=reference_count=packer_entries=presentation_entries=0
    result=dict(status="INCOMPLETE",scope="NEW_140_IMAGE_PUBLIC_A_AND_PRIVATE_QUERY_PUBLICATION",
        old_cases_inherited=False,whole_cli_closed=False,installed_entry_activated=False,
        cold_qualified=False,native_runtime_python=False,ordinary_E_semantics_qualified=False,
        external_mutable_bytes_are_authority=False)
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
    def fail_pins():
        return all((p.stat().st_size,digest(p.read_bytes()))==v for p,v in pins.items())
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
        parent_images={};service_images={}
        for roles,dest in ((assets["cli_roles"],parent_images),(assets["service_roles"],service_images)):
            for role,row in roles.items():
                from_row(row["source"]);dest[int(role)]=from_row(row["image"])
                if "manifest" in row:from_row(row["manifest"])
        base_assembly=from_row(assets["packer"]["assembly"])
        assert digest(base_assembly)=="f06b915cdfb415894e05c8c4a3e7bbdba9fe9c0bc5b8791878516f91cdfa66de"
        assert (len(read(a.sha_source)),digest(read(a.sha_source)))==(33683,"a30377e1f08a3426cfffe609ddbe35de67e87791cb0e9645c79e063f5d3d205a")
        parent_images[10]=read(a.sha_image)
        assert (len(parent_images[10]),digest(parent_images[10]))==(38349,"7bca81777197af059b1b5c48e340c0215214370fec007bb82ae5cadca81ef274")
        inputs=[(row,from_row(row["input"])) for row in assets["inputs"]]
        assert len(inputs)==25 and sum(row["accepted"] for row,raw in inputs)==17
        sys.path[:0]=[str(root/"tools"),str(root.parent/"Hepta-agent-edit-native"),str(reference)]
        from tools.qualify_hia_selfhost import compile_stage
        assert digest(read(reference/"tools/qualify_hia_selfhost.py"))=="2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"
        from hepta.hia_agent_assembly import assemble_program,render_assembly
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        import cli_authoring
        def compile_body(label,body,constants):
            body=cli_authoring.expanded(body,constants)
            document=cli_authoring.document(body,label.replace("-","_"))
            profile=cli_authoring.profile(document)
            where=out/"compiled"/label;where.mkdir(parents=True)
            (where/"expanded.py").write_text(body);save(where/"profile.json",profile)
            assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
            assert profile["max_params"]<=16
            hia=render_assembly(document).encode();(where/"source.hiaasm").write_bytes(hia)
            assemble_program(hia)
            image,receipt=compile_stage(where,label,Path(compiler["path"]),hia)
            raw=read(image)
            assert receipt["artifact_sha256"]==digest(compiler_raw)
            assert receipt["input_sha256"]==digest(hia) and receipt["produced_sha256"]==digest(raw)
            assert receipt["status"]=="returned" and receipt["abi_status"]==0
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            row=dict(label=label,source_bytes=len(hia),source_sha256=digest(hia),
                image_bytes=len(raw),image_sha256=digest(raw),profile=profile,receipt=receipt)
            compiled.append(row);save(where/"manifest.json",row)
            read(where/"source.hiaasm");read(where/"manifest.json")
            print("HIA_FULL_PUBLICATION_COMPILED "+json.dumps(row,sort_keys=True),flush=True)
            return raw
        import cli_publication_presentation_owner as presentation
        body,constants,meta=presentation.source();save(out/"presentation-table-profile.json",meta)
        parent_images[14]=compile_body("cli-publication-presentation",body,constants)
        # This direct component is real native, but it is distinct from the final ELF join.
        assert fail_pins()
        presentation_image=NativeHiaJsonImage(parent_images[14],expected_sha256=digest(parent_images[14]))
        def presentation_call(label,kind,number,haspath,data,wanted,semantic_error=0):
            nonlocal presentation_entries
            command=struct.pack("<12Q",int.from_bytes(b"HIAPSC01","little"),1,17,23,kind,number,haspath,len(data),0,0,0,0)
            source=protected(data);request=protected(command);work=protected(b"",constants["BASE"])
            entries=[]
            for serial in range(16):
                before=ctypes.string_at(work[1],work[2]);entry=dict(serial=serial,source=cas(data),command=cas(command),before=cas(before))
                save(out/"presentation"/(label+".pending.json"),entry)
                returned=int(presentation_image._entry(source[1],source[2],request[1],request[2],work[1],work[2]))
                presentation_entries+=1
                for item in(source,request,work):checked(item)
                assert ctypes.string_at(source[1],source[2])==data and ctypes.string_at(request[1],request[2])==command
                after=ctypes.string_at(work[1],work[2]);event=struct.unpack_from("<16Q",after,256)
                entry.update(returned=returned,after=cas(after),event=list(event));entries.append(entry)
                save(out/"presentation"/(label+".entries.json"),entries)
                assert event[:1]==(int.from_bytes(b"HIAPSE01","little"),) and event[2:5]==(17,23,kind)
                assert all(v==0 for v in event[9:])
                if returned==0xfffffffe:
                    assert event[1]==1 and event[7]>work[2] and event[8]==0
                    work=protected(after,event[7]);continue
                assert returned==128 and event[1]==0 and event[8]==semantic_error
                assert event[5]<=len(after) and event[6]<=len(after)-event[5]
                actual=after[event[5]:event[5]+event[6]]
                row=dict(label=label,kind=kind,entries=len(entries),equal=actual==wanted,
                    expected=cas(wanted),actual=cas(actual),semantic_error=semantic_error)
                presentation_cases.append(row);save(out/"presentation-cases.json",presentation_cases)
                assert actual==wanted,(label,actual,wanted)
                return
            raise AssertionError(("unexpected unbounded presentation continuation",label))
        for n in range(1,134):
            presentation_call("errno-"+str(n),2,n,0,b"",str(OSError(n,os.strerror(n))).encode())
        strings=["","plain","é中😀","\x00\b\f\n\r\t\"\\","\ud800","\udfff","\ud800\udc80","A\udc80\ud800\udcffB"]
        for i,value in enumerate(strings):
            presentation_call("json-"+str(i),1,0,0,value.encode("utf-8","surrogatepass"),
                json.dumps(value,ensure_ascii=True).encode("ascii"))
        paths=[b"",b"plain",b"a'b",b'a"b',b'a\'"b',b"\xff",b"\xed\xa0\x80",b"x\n\t\r\x00y",
            "中é😀".encode(),b"\xf0\x90",bytes(range(1,256))]
        for i,raw in enumerate(paths):
            presentation_call("repr-"+str(i),5,0,0,raw,repr(os.fsdecode(raw)).encode())
            presentation_call("path-error-"+str(i),2,13,1,raw,str(PermissionError(13,os.strerror(13),os.fsdecode(raw))).encode())
        fixed=[
            "E_HIA_EDIT: destination must be a new file",
            "E_HIA_EDIT: output parent must not traverse symlinks",
            "JSON output must be a new file",
            "JSON output parent must not traverse a symlink",
            "[Errno 17] No usable temporary directory name found",
            "invalid buffering size","Cannot call rmtree on a symbolic link"]
        for i,word in enumerate(fixed,1):presentation_call("fixed-"+str(i),4,i,0,b"",word.encode())
        presentation_call("blocking-write",3,11,0,b"",str(BlockingIOError(11,"write could not complete without blocking",0)).encode())
        presentation_call("symlink-loop",4,8,0,b"/a/\xff",("Symlink loop from "+repr(os.fsdecode(b"/a/\xff"))).encode())
        encoded=strings+["x\udc80\udcffz","x\ud800\udcffz","x\udc80\ud800z","\ud800\udfff\udc80",
                         "x\ud800Z\udcff","😀\ud800x","a"*65537+"\udc80", "😀"*20000]
        for i,value in enumerate(encoded):
            source=value.encode("utf-8","surrogatepass")
            for kind,errors in((6,"surrogateescape"),(7,"backslashreplace")):
                flag=0
                try:wanted=value.encode("utf-8",errors)
                except UnicodeEncodeError as error:wanted=str(error).encode();flag=1
                presentation_call("encoding-"+str(i)+"-"+errors,kind,0,0,source,wanted,flag)
        for n in(134,255,4095):
            presentation_call("unknown-errno-"+str(n),2,n,0,b"",str(OSError(n,os.strerror(n))).encode())

        # Retain all 207 original presentation cases. shutil assigns filename
        # to its one-argument OSError before tempfile's callback re-raises it.
        assert len(presentation_cases)==207
        for i,raw in enumerate(paths):
            error=OSError("Cannot call rmtree on a symbolic link")
            error.filename=os.fsdecode(raw)
            presentation_call("root-symlink-filename-"+str(i),4,7,1,raw,str(error).encode())
        assert len(presentation_cases)==218

        private_presentation=[]
        def private_entry(label,data,command,before):
            nonlocal presentation_entries
            source=protected(data);request=protected(command);work=protected(before)
            row=dict(source=cas(data),command=cas(command),before=cas(before))
            save(out/"presentation-private"/(label+".pending.json"),row)
            returned=int(presentation_image._entry(source[1],source[2],request[1],request[2],work[1],work[2]))
            presentation_entries+=1
            for item in(source,request,work):checked(item)
            assert ctypes.string_at(source[1],source[2])==data and ctypes.string_at(request[1],request[2])==command
            after=ctypes.string_at(work[1],work[2]);row.update(returned=returned,after=cas(after))
            save(out/"presentation-private"/(label+".json"),row)
            return returned,after
        good=struct.pack("<12Q",int.from_bytes(b"HIAPSC01","little"),1,17,23,1,0,0,1,0,0,0,0)
        bad_commands=[]
        for offset,value in((0,0),(8,2),(16,0),(24,0),(32,8),(48,2),(56,2),(64,1)):
            bad=bytearray(good);struct.pack_into("<Q",bad,offset,value);bad_commands.append(bytes(bad))
        for i,bad in enumerate(bad_commands):
            returned,work=private_entry("header-"+str(i),b"a",bad,bytes(constants["BASE"]))
            assert returned==0xfffffffd and struct.unpack_from("<Q",work,8)[0]==1
            returned,work=private_entry("header-poison-"+str(i),b"a",good,work)
            assert returned==0xfffffffd
            private_presentation.append(dict(label="header-"+str(i),permanent_poison=True))
        for i,data in enumerate((b"\xff",b"\xc0",b"\xed")):
            returned,work=private_entry("source-"+str(i),data,good,bytes(constants["BASE"]+1))
            assert returned==0xfffffffd and struct.unpack_from("<Q",work,8)[0]==1
            returned,work=private_entry("source-poison-"+str(i),b"a",good,work)
            assert returned==0xfffffffd
            private_presentation.append(dict(label="source-"+str(i),permanent_poison=True))
        for i,mutation in enumerate(("command","source")):
            data=b'"'*1024
            command=bytearray(good);struct.pack_into("<Q",command,56,len(data));command=bytes(command)
            returned,work=private_entry("grow-measure-"+str(i),data,command,bytes(constants["BASE"]+len(data)))
            event=struct.unpack_from("<16Q",work,256)
            assert returned==0xfffffffe and event[7]>len(work)
            grown=work+bytes(event[7]-len(work))
            if mutation=="command":
                changed=bytearray(command);struct.pack_into("<Q",changed,24,24);changed=bytes(changed)
                returned,badwork=private_entry("grow-command",data,changed,grown)
            else:
                returned,badwork=private_entry("grow-source",b"a"+data[1:],command,grown)
            assert returned==0xfffffffd and struct.unpack_from("<Q",badwork,8)[0]==1
            returned,badwork=private_entry("grow-poison-"+str(i),data,command,badwork)
            assert returned==0xfffffffd
            private_presentation.append(dict(label="grow-"+mutation,permanent_poison=True,
                actual_measure_complete_before_mutation=True))
        returned,work=private_entry("complete",b"a",good,bytes(constants["BASE"]+4))
        assert returned==128
        returned,work=private_entry("stale-completion",b"a",good,work)
        assert returned==0xfffffffd and struct.unpack_from("<Q",work,8)[0]==1
        returned,work=private_entry("stale-poison",b"a",good,work)
        assert returned==0xfffffffd
        private_presentation.append(dict(label="stale-completion",permanent_poison=True))
        assert len(private_presentation)==14
        save(out/"presentation-private-controls.json",private_presentation)
        result["presentation"]=dict(cases=len(presentation_cases),native_entries=presentation_entries,private_controls=len(private_presentation))
        save(out/"component-so-far.json",result)
        owners={8:"cli_publication_verified_owner",9:"cli_publication_path_owner",
            11:"cli_publication_stage_writer",12:"cli_publication_tempdir_owner",
            13:"cli_publication_cleanup_owner"}
        for role,name in owners.items():
            owner=importlib.import_module(name)
            body=owner.BODY+(owner.message_body() if role==8 else "")
            parent_images[role]=compile_body(name,body,owner.CONSTANTS)
        import cli_publication_parent_owner as parent
        parent_images[7]=compile_body("cli-publication-parent",parent.BODY+parent.literals()+parent.COMMON,parent.CONSTANTS)
        import cli_publication_policy2_fixture as queryfixture
        fixture_body,fixture_constants=queryfixture.source()
        query_image=compile_body("private-policy2-query-issuer",fixture_body,fixture_constants)
        import compose_cli_publication_filesystem_r3 as compose
        assembly=compose.compose(base_assembly,root/"tools/compose_cli_publication_filesystem_r2.py")
        assert assembly[assembly.index(b".equ svc_"):]==base_assembly[base_assembly.index(b".equ svc_"):]
        native=out/"carrier";native.mkdir();(native/"cli_publication_executor.S").write_bytes(assembly)
        read(native/"cli_publication_executor.S")
        import generate_hia_cli_publication_packer_r3 as packer_module
        prefix,tables,original=packer_module.template(native/"cli_publication_executor.S",native)
        assert original==assembly
        (native/"prefix.bin").write_bytes(prefix);save(native/"layout.json",dict(tables=tables,rows=140,header=1184,
            assembly_sha256=digest(assembly),prefix_sha256=digest(prefix),prefix_bytes=len(prefix)))
        packer_image=compile_body("cli-publication-packer",packer_module.source(prefix,tables),{})
        assert set(parent_images)==set(range(1,15))
        parts=[b""]*140
        for role,raw in parent_images.items():parts[role-1]=raw
        for role,raw in service_images.items():parts[14+role-1]=raw
        parts[132]=query_image
        assert parts[6] and parts[69] and parts[132]
        packet=struct.pack("<8Q",int.from_bytes(b"HIACBP03","little"),3,3,140,
            1184+sum(map(len,parts)),1184,64,0)+struct.pack("<140Q",*map(len,parts))+b"".join(parts)
        expected=bytearray(prefix)
        for index,raw in enumerate(parts):
            if not raw:continue
            assert len(raw)<=1048576
            expected+=bytes((-len(expected))&15)
            table=0 if index<14 else 1 if index<77 else 2
            role=index+1 if table==0 else index-13 if table==1 else index-76
            struct.pack_into("<Q",expected,tables[table]+role*8,0x400000+len(expected))
            expected+=raw
        struct.pack_into("<Q",expected,96,len(expected));struct.pack_into("<Q",expected,104,len(expected))
        assert fail_pins()
        actual_packer=NativeHiaJsonImage(packer_image,expected_sha256=digest(packer_image))
        source_buffer=protected(packet);output=protected(b"",len(expected));scratch=protected(b"",64)
        ret=int(actual_packer._entry(source_buffer[1],source_buffer[2],output[1],output[2],scratch[1],scratch[2]))
        packer_entries+=1
        for item in(source_buffer,output,scratch):checked(item)
        assert ctypes.string_at(source_buffer[1],source_buffer[2])==packet and ctypes.string_at(scratch[1],64)==bytes(64)
        executable=ctypes.string_at(output[1],output[2])
        save(out/"pack.json",dict(input=cas(packet),output=cas(executable),expected=cas(expected),
            return_value=ret,full_expected_bytes_equal=executable==bytes(expected),
            full_input_unchanged=True,full_scratch_unchanged=True))
        assert ret==len(expected) and executable==bytes(expected)
        elf=out/"hia-cli-publication-development";elf.write_bytes(executable);elf.chmod(0o700);read(elf)
        assert executable[:4]==b"\x7fELF" and struct.unpack_from("<H",executable,56)[0]==2
        assert [struct.unpack_from("<I",executable,64+56*i)[0] for i in range(2)]==[1,0x6474e551]
        save(out/"bundle.json",dict(scope=result["scope"],compiled=compiled,actual_packer_entries=1,
            executable_path=str(elf),executable_bytes=len(executable),executable_sha256=digest(executable),
            parent_roles=14,service_tables=[63,63],nonzero_images=sum(bool(part) for part in parts),
            private_policy2_issuer=True,installed_entry_activated=False))

        oracle=out/"reference-cli.py"
        oracle.write_text(
            "import json,sys\nsys.dont_write_bytecode=True\nsys.path.insert(0,"+repr(str(reference))+")\n"
            "from hepta.cli import hia_main,output_json,publish_json_view\n"
            "if sys.argv[1]=='--private-policy2-oracle':\n"
            " from hepta.hia_diagnostic import diagnostic,render_diagnostics\n"
            " try:\n"
            "  value=json.loads(open(sys.argv[2],'rb').read())\n"
            "  output_json(publish_json_view(value,sys.argv[3]))\n"
            " except (OSError,ValueError,UnicodeError) as error:\n"
            "  output_json({'ok':False,'status':'error','diagnostics':[{'code':'E_DRIVER','message':str(error),'phase':'driver'}]})\n"
            "  raise SystemExit(2)\n"
            "else:raise SystemExit(hia_main(sys.argv[1:]))\n")
        # This private reference path invokes only the exact published JSON-view
        # function. It is not an alternate implementation used by the native ELF.
        oracle_text=oracle.read_text().replace(" from hepta.hia_diagnostic import diagnostic,render_diagnostics\n","")
        oracle.write_text(oracle_text);read(oracle)
        libc=ctypes.CDLL(None,use_errno=True)
        libc.prctl.argtypes=[ctypes.c_int,*([ctypes.c_ulong]*4)];libc.prctl.restype=ctypes.c_int
        def invoke(label,kind,argv,cwd,close_stdin=False,umask=0o22):
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
                resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(umask)
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
            observed=dict(argv=argv,cwd=str(cwd),env=env,close_stdin=close_stdin,umask=umask,pid=process.pid,
                exit=process.returncode,wait_status=status,timed_out=timed_out,elapsed_ns=time.monotonic_ns()-started,
                user_cpu=usage.ru_utime,system_cpu=usage.ru_stime,maxrss_kib=usage.ru_maxrss,
                cpu_limit=90,address_limit=1<<30,wall_limit=30,stdout=cas(stdout),stderr=cas(stderr))
            save(dest/"process.json",observed)
            assert not timed_out,(label,kind,"timeout")
            return (process.returncode,stdout,stderr),observed
        physical=out/"physical";physical.mkdir()
        def inventory(path):
            rows=[];objects=[]
            def walk(base):
                for child in sorted(base.iterdir(),key=lambda x:os.fsencode(x.name)):
                    st=child.lstat()
                    row=dict(path_hex=os.fsencode(child.relative_to(path)).hex(),
                        type=stat.S_IFMT(st.st_mode),mode=stat.S_IMODE(st.st_mode))
                    observed=dict(row,device=st.st_dev,inode=st.st_ino,nlink=st.st_nlink,size=st.st_size,
                        mtime_ns=st.st_mtime_ns,ctime_ns=st.st_ctime_ns)
                    if stat.S_ISREG(st.st_mode):
                        data=child.read_bytes();row["data_sha256"]=digest(data);row["data_bytes"]=len(data)
                        observed["data"]=cas(data)
                    elif stat.S_ISLNK(st.st_mode):
                        row["target_hex"]=os.fsencode(os.readlink(child)).hex()
                        observed["target_hex"]=row["target_hex"]
                    rows.append(row);objects.append(observed)
                    if stat.S_ISDIR(st.st_mode):walk(child)
            walk(path)
            return rows,objects
        def reset(fx):
            if fx.exists():shutil.rmtree(fx)
            fx.mkdir(mode=0o700)
        def compare(label,raw,setup,scope,private=False,close_stdin=False,umask=0o22):
            fx=physical/label;observations=[];results=[]
            for kind in("reference","native"):
                reset(fx);source=fx/"input.hia";source.write_bytes(raw)
                destination=setup(fx)
                start,objects=inventory(fx)
                save(out/"cases"/label/(kind+"-before.json"),dict(objects=objects,semantic_snapshot=start))
                if private:
                    argv=(["--private-policy2-oracle",str(source),destination] if kind=="reference" else
                          ["edit-query",str(source),"--function","f","--block","b","--value","x",
                           "--fields","attrs","--output",destination])
                else:argv=["normalize",str(source),"--output",destination]
                value,process=invoke(label,kind,argv,fx,close_stdin,umask)
                end,objects=inventory(fx)
                save(out/"cases"/label/(kind+"-after.json"),dict(objects=objects,semantic_snapshot=end))
                observations.append((start,end,process));results.append(value)
                assert source.read_bytes()==raw
            equal=results[0]==results[1]
            fs_equal=observations[0][0:2]==observations[1][0:2]
            row=dict(label=label,scope=scope,equal=equal,filesystem_equal=fs_equal,
                reference=observations[0][2],native=observations[1][2])
            cases.append(row);save(out/"cases-so-far.json",cases)
            print("HIA_FULL_PUBLICATION_CASE "+json.dumps(dict(label=label,equal=equal,
                filesystem_equal=fs_equal,native_exit=results[1][0],reference_exit=results[0][0],
                native_stdout_bytes=len(results[1][1]),native_stderr_bytes=len(results[1][2])),sort_keys=True),flush=True)
            assert equal,(label,results[1][0],results[0][0],digest(results[1][1]),digest(results[0][1]),
                          digest(results[1][2]),digest(results[0][2]))
            assert fs_equal,(label,"filesystem changes differ")
            # Keep inventory and complete bytes before the developer removes
            # only this finished fixture. The package must not follow symlinks.
            shutil.rmtree(fx)
        for row,raw in inputs:
            compare("public-"+row["label"],raw,lambda fx:str(fx/"output.hia"),
                "PUBLIC_A_INITIAL_ADMISSION_THEN_NATIVE_PUBLICATION")
        valid=next(raw for row,raw in inputs if row["label"]=="core-v1")
        def ordinary(fx):return str(fx/"output.hia")
        def nested(fx):return "a/b/c/output.hia"
        def existing(fx):
            p=fx/"output.hia";p.write_bytes(b"preserved-existing");return str(p)
        def existing_dir(fx):
            p=fx/"output.hia";p.mkdir();return str(p)
        def existing_link(fx):
            p=fx/"output.hia";p.symlink_to("input.hia");return str(p)
        def dangling_link(fx):
            p=fx/"output.hia";p.symlink_to("missing");return str(p)
        def parent_file(fx):
            (fx/"parent").write_bytes(b"regular");return "parent/output.hia"
        def parent_link(fx):
            (fx/"real").mkdir();(fx/"link").symlink_to("real",target_is_directory=True)
            return "link/output.hia"
        def parent_dangling(fx):
            (fx/"link").symlink_to("no-parent",target_is_directory=True);return "link/output.hia"
        def unicode_path(fx):return "é中😀/out-\n-\t-'\".hia"
        def byte_path(fx):return os.fsdecode(b"invalid-\xff-\xfe/out-\x80.hia")
        setups=[
            ("relative",lambda fx:"output.hia"),("nested",nested),
            ("existing-file",existing),("existing-directory",existing_dir),
            ("existing-symlink",existing_link),("dangling-symlink",dangling_link),
            ("parent-file",parent_file),("parent-symlink",parent_link),
            ("parent-dangling",parent_dangling),("unicode",unicode_path),("filesystem-bytes",byte_path),
            ("dot",lambda fx:"./output.hia"),("parent-dotdot",lambda fx:"new/../output.hia"),
            ("double-leading",lambda fx:"/"+str(fx/"output.hia")),
            ("target-dot",lambda fx:"."),("target-trailing",lambda fx:"new-dir/"),
            ("long-name",lambda fx:"n"*256)]
        for label,setup in setups:compare("path-"+label,valid,setup,"PUBLIC_A_NATIVE_PATH_PUBLICATION")
        compare("fd-zero",valid,ordinary,"PUBLIC_A_NATIVE_FD_ZERO",close_stdin=True)
        compare("private-umask",valid,nested,"PUBLIC_A_NATIVE_PUBLICATION_UMASK",umask=0o77)
        private_queries=[
            {"schema":"sample","value":None},{"schema":"sample","value":"é中😀"},
            {"schema":"sample","value":"\ud800\udcff"},{"schema":"sample","value":[0,True,False,-123]},
            {"schema":"sample","value":{"z":1,"a":"x\n\t\"\\\x00"}},
            {"schema":"sample","value":"s"*65537},{"schema":"sample","value":["é"]*8193},
            {"schema":"sample","value":[1.25,-0.0,1e100,1e-100]},
        ]
        for i,value in enumerate(private_queries):
            raw=json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
            compare("private-query-"+str(i),raw,nested,"PRIVATE_ISSUED_QUERY_POLICY2_REAL_PUBLICATION",private=True)
        raw=json.dumps({"schema":"sample","value":"é中😀"},sort_keys=True,separators=(",",":")).encode()
        for label,setup in(("existing",existing),("parent-symlink",parent_link),("filesystem-bytes",byte_path)):
            compare("private-query-"+label,raw,setup,"PRIVATE_ISSUED_QUERY_POLICY2_REAL_PUBLICATION",private=True)
        assert len(cases)==55 and native_count==55 and reference_count==55
        assert len(presentation_cases)==218
        assert len(compiled)==9 and packer_entries==1
        assert all(row["equal"] and row["filesystem_equal"] for row in cases)
        result.update(status="PASS",cases=cases,exact_public_A_publication_cases=44,
            private_policy2_publication_cases=11,ordinary_E_semantics_qualified=False,
            native_processes=native_count,reference_processes=reference_count,
            actual_packer_entries=packer_entries,new_B3_compilations=len(compiled),
            presentation_native_entries=presentation_entries,presentation_cases=len(presentation_cases),presentation_private_controls=len(private_presentation),
            real_A_service_bound=True,public_argv_and_file_owner=True,
            complete_stdout_stderr_exit_equal=True,complete_filesystem_semantic_snapshot_equal=True,
            public_parent_publication_executed=True,source_image_bindings=True,
            remaining_boundaries=["Path.resolve unhandled RuntimeError traceback",
                "over-PATH_MAX getcwd fallback","nondefault startup integer digits",
                "nondefault locale/stdout encoding configuration","E semantic publication join"])
    except BaseException as error:
        result.update(status="FAIL",completed_cases=len(cases),cases=cases,error_class=type(error).__name__,
            error=str(error),traceback=traceback.format_exc(),native_processes=native_count,
            reference_processes=reference_count,actual_packer_entries=packer_entries,
            new_B3_compilations=len(compiled),presentation_native_entries=presentation_entries,
            presentation_cases=len(presentation_cases))
        traceback.print_exc();raise
    finally:
        original=sys.exception()
        try:
            changed=[str(p) for p,v in pins.items() if (p.stat().st_size,digest(p.read_bytes()))!=v]
            result["source_pins_unchanged"]=not changed;result["changed_paths"]=changed
            objects=list((out/"cas").glob("*.zlib")) if (out/"cas").exists() else []
            total=0
            for p in objects:
                raw=zlib.decompress(p.read_bytes());assert digest(raw)==p.stem;total+=len(raw)
            result["cas_readback"]=dict(status="PASS",objects=len(objects),logical_bytes=total)
            save(out/"source-pins.json",[dict(path=str(p),bytes=v[0],sha256=v[1]) for p,v in pins.items()])
            save(out/"compiles.json",compiled);save(out/"summary.json",result)
            print("HIA_FULL_PUBLICATION_SUMMARY "+json.dumps({k:v for k,v in result.items() if k!="cases"},sort_keys=True),flush=True)
            assert not changed
        except BaseException as error:
            if original is None:raise
            original.add_note("final custody: "+repr(error))
if __name__=="__main__":main()
