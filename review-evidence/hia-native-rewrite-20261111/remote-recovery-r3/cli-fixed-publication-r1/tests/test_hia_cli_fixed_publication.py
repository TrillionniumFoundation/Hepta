"""Fresh fixed-ELF publication and filesystem execution, no Python dispatcher.

The original verified-publication kernel is reused without semantic changes.
23 filesystem outcomes and FD0 use the real fixed ELF; the HIA utility script
covers all 22 raw primitives; malformed private frames must stop before the
affected OS mutation. Public Path.absolute/staging/CLI formatting are open.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,importlib.util,json,os,resource,signal,stat,struct,subprocess,sys,time,traceback,zlib
MAX=(1<<64)-1
def magic(x):return int.from_bytes(x,"little")
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);v=importlib.util.module_from_spec(spec)
    sys.modules[name]=v;spec.loader.exec_module(v);return v
def guarded(raw,size=None):
    size=len(raw) if size is None else size;assert len(raw)<=size
    b=ctypes.create_string_buffer(64+max(size,1));at=ctypes.addressof(b)+32
    ctypes.memset(at-32,0xa7,32);ctypes.memmove(at,raw,len(raw));ctypes.memset(at+max(size,1),0xa7,32)
    return b,at,size
def check(buf):
    _,at,size=buf
    assert ctypes.string_at(at-32,32)==b"\xa7"*32
    assert ctypes.string_at(at+max(size,1),32)==b"\xa7"*32
def packet(stage,dest,payload):
    a=os.fsencode(stage);b=os.fsencode(dest)
    return struct.pack("<8Q",magic(b"HIAPVC01"),1,19,1,len(a),len(b),len(payload),66+len(a)+len(b)+len(payload))+a+b"\0"+b+b"\0"+payload

def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True)
    p.add_argument("--reference",type=Path,required=True);p.add_argument("--compiler",type=Path,required=True)
    p.add_argument("--sha-source",type=Path,required=True);p.add_argument("--sha-image",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    assert sys.version_info[:3]==(3,12,14)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    root=Path(__file__).resolve().parents[1];out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    fixtures=out.parent/"fixed-filesystem-fixtures";fixtures.mkdir(exist_ok=False)
    pins={};rows=[];compiles=[];cas_map={};native_processes=0;packer_entries=0;original_error=None
    result=dict(status="FAIL",scope="ACTUAL_FIXED_ELF_VERIFIED_PUBLICATION_AND_22_FS_PRIMITIVES",
        new_python_runtime_dispatch=False,whole_cli_publication_closed=False,
        path_absolute_mkdir_resolve_staging_closed=False,new_cold_qualification=False,
        old_967_cases_repeated=False,old_193_entry_calls_repeated=False,
        original_40_component_cases_repeated=False)
    def pin(path):
        path=Path(path).resolve();raw=path.read_bytes()
        if path in pins:assert pins[path]==raw
        else:
            dest=out/"frozen"/str(len(pins)).zfill(4);dest.parent.mkdir(exist_ok=True);dest.write_bytes(raw)
        pins[path]=raw;return raw
    def cas(raw):
        raw=bytes(raw);h=digest(raw);dest=out/"cas"/(h+".zlib");dest.parent.mkdir(exist_ok=True)
        if h not in cas_map:
            dest.write_bytes(zlib.compress(raw,6));assert zlib.decompress(dest.read_bytes())==raw;cas_map[h]=len(raw)
        else:assert cas_map[h]==len(raw)
        return dict(bytes=len(raw),sha256=h,path="cas/"+dest.name,compression="zlib")
    def files(folder):
        answer=[]
        for path in sorted(folder.rglob("*")):
            st=path.lstat();row=dict(path=path.relative_to(folder).as_posix(),type=stat.S_IFMT(st.st_mode),mode=stat.S_IMODE(st.st_mode))
            if stat.S_ISREG(st.st_mode):
                data=path.read_bytes();row.update(bytes=len(data),sha256=digest(data))
            elif stat.S_ISLNK(st.st_mode):row["target"]=os.readlink(path)
            answer.append(row)
        return answer
    try:
        sys.path[:0]=[str(root/"tools"),str(a.source),str(root.parent/"Hepta-agent-edit-native")]
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from tools.qualify_hia_selfhost import compile_stage
        import cli_authoring
        import cli_publication_verified_owner as verified
        import cli_publication_fixed_driver as fixed
        import cli_publication_filesystem_fixtures as utility
        import compose_cli_publication_filesystem as composer
        import generate_hia_cli_publication_packer as packer_author
        for path in sorted((root/"tools").glob("*.py")):pin(path)
        for path in sorted((root/"reference").glob("*")):pin(path)
        pin(Path(__file__));pin(root.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py")
        compiler=pin(a.compiler);assert (len(compiler),digest(compiler))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
        sha_source=pin(a.sha_source);sha_image=pin(a.sha_image)
        assert (len(sha_source),digest(sha_source))==(33683,"a30377e1f08a3426cfffe609ddbe35de67e87791cb0e9645c79e063f5d3d205a")
        assert (len(sha_image),digest(sha_image))==(38349,"7bca81777197af059b1b5c48e340c0215214370fec007bb82ae5cadca81ef274")
        base=pin(root/"reference/finite-carrier-passed.S")
        assert digest(base)==composer.BASE_SHA
        assembled=composer.compose(base);assembly=out/"fixed-publication-executor.S";assembly.write_bytes(assembled);pin(assembly)
        # The complete finite child interpreter suffix is exactly unchanged.
        child=base.index(b".equ svc_ROLE,2048\n")
        changed=assembled.index(b".equ svc_ROLE,2048\n")
        assert base[child:]==assembled[changed:]
        template=out/"template";template.mkdir()
        prefix,tables,source_asm=packer_author.template(assembly,template)
        assert source_asm==assembled
        (out/"prefix.bin").write_bytes(prefix);save(out/"layout.json",dict(tables=tables,rows=136,header=1152,prefix_bytes=len(prefix),prefix_sha256=digest(prefix)))
        cache={}
        def compile_body(label,body,constants=None):
            if constants is not None:body=cli_authoring.expanded(body,constants)
            doc=cli_authoring.document(body,label.replace("-","_"));prof=cli_authoring.profile(doc)
            assert prof["functions"]<=128 and prof["blocks"]<=1536 and prof["max_blocks"]<=256
            assert prof["ops"]<=8192 and prof["max_params"]<=16,prof
            hia=render_assembly(doc).encode();assert len(hia)<=1<<20;assemble_program(hia)
            where=out/"compiles"/label;where.mkdir(parents=True,exist_ok=False)
            (where/"authoring-expanded.py").write_text(body);(where/"source.hiaasm").write_bytes(hia)
            if digest(hia) in cache:
                previous=cache[digest(hia)];image=pin(previous["image_path"])
                assert digest(image)==previous["image_sha256"]
                row=dict(label=label,source_sha256=digest(hia),reused_same_immutable_source=previous,profile=prof)
                save(where/"reuse.json",row);compiles.append(row);return image
            image_path,receipt=compile_stage(where,label,a.compiler,hia);image=pin(image_path)
            assert receipt["source_sha256"]==receipt["input_sha256"]==digest(hia)
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==digest(compiler)
            assert receipt["produced_sha256"]==digest(image) and receipt["produced_bytes"]==len(image)
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["limits"]["core_dumpable"] is False and len(image)<=1<<20
            row=dict(label=label,source_sha256=digest(hia),source_bytes=len(hia),image_path=str(image_path),
                image_sha256=digest(image),image_bytes=len(image),receipt=receipt,profile=prof)
            save(where/"manifest.json",row);compiles.append(row);cache[digest(hia)]=row;return image
        publication=compile_body("verified-publication",verified.BODY+verified.message_body(),verified.CONSTANTS)
        controller=compile_body("fixed-publication-controller",*fixed.source())
        unused=compile_body("unused-service", "def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    return 4294967293\n")
        packer_bytes=compile_body("publication-packer",packer_author.source(prefix,tables))
        packer=NativeHiaJsonImage(packer_bytes,expected_sha256=digest(packer_bytes))
        def build(label,parent):
            nonlocal packer_entries
            parts=[b""]*136;parts[6]=parent;parts[7]=publication;parts[9]=sha_image
            parts[65]=unused;parts[128]=unused
            wire=struct.pack("<8Q",magic(b"HIACBP02"),2,3,136,1152+sum(map(len,parts)),1152,64,0)
            wire+=struct.pack("<136Q",*map(len,parts))+b"".join(parts)
            expected=bytearray(prefix)
            for index,raw in enumerate(parts):
                if not raw:continue
                expected+=bytes((-len(expected))&15)
                table=0 if index<10 else 1 if index<73 else 2
                role=index+1 if table==0 else index-9 if table==1 else index-72
                struct.pack_into("<Q",expected,tables[table]+role*8,0x400000+len(expected));expected+=raw
            struct.pack_into("<Q",expected,96,len(expected));struct.pack_into("<Q",expected,104,len(expected))
            first=guarded(wire);second=guarded(b"",len(expected));work=guarded(b"",64)
            ret=int(packer._entry(first[1],first[2],second[1],second[2],work[1],work[2]));packer_entries+=1
            for buf in (first,second,work):check(buf)
            actual=ctypes.string_at(second[1],second[2])
            assert ret==len(expected) and actual==bytes(expected)
            assert ctypes.string_at(first[1],first[2])==wire and ctypes.string_at(work[1],work[2])==bytes(64)
            where=out/"builds"/label;where.mkdir(parents=True,exist_ok=False)
            exe=where/"hia-publication";exe.write_bytes(actual);exe.chmod(0o700);pin(exe)
            save(where/"pack.json",dict(return_value=ret,input=cas(wire),output=cas(actual),
                tables=tables,rows=136,all_image_bytes_bound=True,independent_layout_equal=True))
            return exe
        executable=build("publication",controller)
        libc=ctypes.CDLL(None,use_errno=True)
        libc.prctl.argtypes=[ctypes.c_int,*([ctypes.c_ulong]*4)];libc.prctl.restype=ctypes.c_int
        def invoke(exe,label,argv=(),close_stdin=False):
            nonlocal native_processes
            where=out/"actual"/label;where.mkdir(parents=True,exist_ok=False)
            expected_parent=os.getpid();process=None;status=None;usage=None;timed_out=False;start=time.monotonic_ns()
            def limits():
                if libc.prctl(1,signal.SIGKILL,0,0,0):
                    e=ctypes.get_errno();raise OSError(e,os.strerror(e))
                if os.getppid()!=expected_parent:os.kill(os.getpid(),signal.SIGKILL)
                resource.setrlimit(resource.RLIMIT_CPU,(90,90))
                resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
                resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
                resource.setrlimit(resource.RLIMIT_CORE,(0,0))
                if close_stdin:os.close(0)
            with (where/"stdout.bin").open("wb") as stdout,(where/"stderr.bin").open("wb") as stderr:
                try:
                    process=subprocess.Popen([str(exe),*(str(v) for v in argv)],cwd=where,
                        stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True,
                        env=dict(PATH="",HOME="",LANG="C.UTF-8",LC_ALL="C.UTF-8"),preexec_fn=limits)
                    native_processes+=1
                    while status is None:
                        pid,value,rusage=os.wait4(process.pid,os.WNOHANG)
                        if pid:
                            status=value;usage=rusage;process.returncode=os.waitstatus_to_exitcode(value);break
                        if time.monotonic_ns()-start>120_000_000_000:
                            timed_out=True;break
                        time.sleep(.01)
                finally:
                    primary=sys.exception();cleanup=[]
                    if process is not None and process.returncode is None:
                        try:os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        except BaseException as error:cleanup.append(error)
                        try:
                            _,status,usage=os.wait4(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
                        except BaseException as error:cleanup.append(error)
                    if cleanup:
                        if primary is not None:
                            for error in cleanup:primary.add_note("cleanup: "+repr(error))
                        else:raise cleanup[0]
            so=(where/"stdout.bin").read_bytes();se=(where/"stderr.bin").read_bytes()
            row=dict(label=label,argv=[str(exe),*(str(v) for v in argv)],cwd=str(where),
                exit=process.returncode,wait_status=status,timed_out=timed_out,
                elapsed_ns=time.monotonic_ns()-start,user_cpu=usage.ru_utime,system_cpu=usage.ru_stime,
                maxrss_kib=usage.ru_maxrss,cpu_limit=90,address_limit=1<<30,
                stdin_closed_before_exec=close_stdin,stdout=cas(so),stderr=cas(se),
                actual_executable_sha256=digest(pin(exe)))
            save(where/"process.json",row)
            assert not timed_out
            return row,so,se
        oracle_path=a.reference/"hepta/artifact_publication.py";pin(oracle_path)
        assert "HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST" not in os.environ
        oracle=module("fixed_publication_reference",oracle_path)
        labels=[("success-"+str(n),n,"success") for n in (1,31,8191,8192,8193,65535,65536,65537,1048576,8388608)]
        labels += [(name,37,name) for name in ("wrong","short","long","empty","same","existing","directory-dest",
            "dangling-dest","missing-stage","directory-stage","fifo-stage","symlink-stage","missing-parent")]
        labels.append(("success-fd-zero",37,"success"))
        for label,n,mode in labels:
            pattern=b"\0HIA verified publication\xff\n";payload=(pattern*((n+len(pattern)-1)//len(pattern)))[:n]
            observed=[];native_info=None
            for which in ("reference","native"):
                folder=fixtures/label/which;folder.mkdir(parents=True)
                stage=folder/"stage";dest=folder/"destination";stage.write_bytes(payload);expected=payload
                if mode=="wrong":expected=b"x"*n
                if mode=="short":expected=payload[:-1]
                if mode=="long":expected=payload+b"!"
                if mode=="empty":expected=b""
                if mode=="same":dest=stage
                if mode=="existing":dest.write_bytes(b"competitor")
                if mode=="directory-dest":dest.mkdir()
                if mode=="dangling-dest":dest.symlink_to("absent")
                if mode=="missing-stage":stage.unlink()
                if mode=="directory-stage":stage.unlink();stage.mkdir()
                if mode=="fifo-stage":stage.unlink();os.mkfifo(stage)
                if mode=="symlink-stage":stage.rename(folder/"real");stage.symlink_to("real")
                if mode=="missing-parent":dest=folder/"absent"/"destination"
                before=files(folder)
                if which=="reference":
                    try:
                        value=oracle.publish_verified(stage,dest,expected)
                        answer=dict(domain=0,receipt=json.dumps(value,sort_keys=True,separators=(",",":")))
                    except oracle.PublicationRejected as error:answer=dict(domain=1,message=str(error))
                    except OSError as error:answer=dict(domain=2,errno=error.errno,path=os.fsencode(error.filename).hex())
                else:
                    wire=packet(stage,dest,expected);command=out/"inputs"/(label+".bin")
                    command.parent.mkdir(exist_ok=True);command.write_bytes(wire);pin(command)
                    process,so,se=invoke(executable,label,[command],close_stdin=(label=="success-fd-zero"))
                    assert se==b"" and len(so)>=192,(label,process,so[:256].hex(),se)
                    header=struct.unpack_from("<8Q",so);event=struct.unpack_from("<16Q",so,64)
                    assert header[0]==magic(b"HIAPFX01") and header[1]==1 and header[7]==len(so)
                    assert event[0]==magic(b"HIAPVE01") and event[1]==0 and event[2]==19
                    value=so[192:];assert len(value)==event[10]
                    if event[5]==0:answer=dict(domain=0,receipt=value.decode("ascii"))
                    elif event[5]==1:answer=dict(domain=1,message=value.decode("utf-8"))
                    else:
                        assert event[5]==2
                        answer=dict(domain=2,errno=event[7],path=value.hex())
                    assert process["exit"]==(0 if answer["domain"]==0 else 2)
                    assert header[2]>0 and header[3]>0 and header[5]>0 and header[6]>0
                    assert header[4]==(3 if answer["domain"]==0 else 0)
                    native_info=dict(process=process,telemetry=header,terminal=event,input=cas(wire))
                same=(stage.exists() and dest.exists() and stage.is_file() and dest.is_file() and stage.stat().st_ino==dest.stat().st_ino)
                observed.append(dict(outcome=answer,before=before,after=files(folder),same_inode=same))
            assert observed[0]==observed[1],(label,observed)
            row=dict(label=label,status="PASS",scope="FIXED_NATIVE_PUBLICATION_COMPLETE_OUTCOME",reference=observed[0],native=observed[1],actual=native_info)
            rows.append(row);save(out/"cases"/(str(len(rows)).zfill(4)+".json"),row)
            print(json.dumps(dict(label=label,status="PASS",telemetry=native_info["telemetry"]),sort_keys=True),flush=True)
        private_labels=["unknown-zero","unknown-high","unused-field","stat-short","stat-long",
            "write-controller","write-readonly","path-no-nul","path-interior","path-overflow",
            "token-missing","token-reopen","double-close","open-max-token","write-rw","terminal-live","business-live"]
        utilities=[]
        for mode in ("all","fd-zero",*private_labels):
            folder=fixtures/("utility-"+mode);folder.mkdir()
            (folder/"existing").write_bytes(b"original");(folder/"existing").chmod(0o644)
            if mode=="all":(folder/"symlink").symlink_to("dir/file")
            before=files(folder)
            body,constants,recipe=utility.make(folder,mode,fd_zero=(mode=="fd-zero"))
            image=compile_body("utility-"+mode,body,constants)
            exe=build("utility-"+mode,image)
            process,so,se=invoke(exe,"utility-"+mode,close_stdin=(mode=="fd-zero"))
            assert se==b""
            if mode in private_labels:
                assert process["exit"]==126 and so==b"", (mode,process,so[:256].hex())
                assert files(folder)==before,(mode,files(folder),before)
                actual_calls=None
            else:
                assert process["exit"]==0 and len(so)==64+16*len(recipe["syscalls"]),(mode,process,so[:256].hex())
                header=struct.unpack_from("<8Q",so)
                assert header[:3]==(magic(b"HIAPUT01"),1,len(recipe["syscalls"])) and header[3:]==(0,0,0,0,0)
                actual_calls=[struct.unpack_from("<2Q",so,64+i*16) for i in range(header[2])]
                assert [x[0] for x in actual_calls]==recipe["syscalls"]
                if mode=="all":
                    assert set(x[0] for x in actual_calls)==set(range(1,23))
                    assert files(folder)==[dict(path="existing",type=stat.S_IFREG,mode=420,bytes=8,sha256=digest(b"original"))]
                else:
                    assert actual_calls==[(1,0),(2,0)] and files(folder)==before
            row=dict(mode=mode,status="PASS",recipe=recipe,process=process,actual_calls=actual_calls,
                before=before,after=files(folder),private_protocol_refusal=mode in private_labels)
            utilities.append(row);save(out/"utilities"/(mode+".json"),row)
            print(json.dumps(dict(mode=mode,status="PASS",exit=process["exit"]),sort_keys=True),flush=True)
        assert len(rows)==24 and len(utilities)==19 and native_processes==43 and packer_entries==20
        result.update(status="PASS",publication_cases=24,utility_cases=2,private_controls=17,
            native_processes=native_processes,native_packer_entries=packer_entries,
            publication_actual_hia_calls=sum(r["actual"]["telemetry"][2] for r in rows),
            publication_actual_fs_calls=sum(r["actual"]["telemetry"][3] for r in rows),
            publication_actual_hash_calls=sum(r["actual"]["telemetry"][4] for r in rows),
            all_22_fs_kinds_executed=True,fd_zero_open_and_close_exact=True,
            sparse_live_fd_table_growth_executed=True,
            cases=rows,utilities=utilities,compiles=compiles,
            original_finite_service_child_body_exact=True)
    except BaseException as error:
        original_error=error;result.update(failure=traceback.format_exc())
        print(result["failure"],file=sys.stderr,flush=True);raise
    finally:
        try:
            inventory=[]
            for path in sorted(fixtures.rglob("*")):
                info=path.lstat()
                row=dict(path=path.relative_to(fixtures).as_posix(),mode=stat.S_IMODE(info.st_mode),
                    type=stat.S_IFMT(info.st_mode),dev=info.st_dev,inode=info.st_ino,links=info.st_nlink,
                    bytes=info.st_size,mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns)
                if stat.S_ISLNK(info.st_mode):row["target"]=os.readlink(path)
                elif stat.S_ISREG(info.st_mode):row["data"]=cas(path.read_bytes())
                inventory.append(row)
            save(out/"filesystem-object-inventory.json",inventory)
            for h,size in cas_map.items():
                raw=zlib.decompress((out/"cas"/(h+".zlib")).read_bytes())
                assert (len(raw),digest(raw))==(size,h)
            result["cas_readback"]=dict(status="PASS",objects=len(cas_map),raw_bytes=sum(cas_map.values()))
            result["source_pins_unchanged"]=all(p.read_bytes()==raw for p,raw in pins.items())
            result["completed_publication_cases"]=rows
            result["actual_processes_observed"]=native_processes
            save(out/"source-pins.json",{str(p):dict(bytes=len(raw),sha256=digest(raw)) for p,raw in pins.items()})
            save(out/"summary.json",result)
            print(json.dumps({k:v for k,v in result.items() if k not in ("cases","utilities","compiles","completed_publication_cases")},sort_keys=True),flush=True)
            assert result["source_pins_unchanged"]
        except BaseException as error:
            if original_error is not None:original_error.add_note("Evidence preservation also failed: "+repr(error))
            else:raise
if __name__=="__main__":main()
