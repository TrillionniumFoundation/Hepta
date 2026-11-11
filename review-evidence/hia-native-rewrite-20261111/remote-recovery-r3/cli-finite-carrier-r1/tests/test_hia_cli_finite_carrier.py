"""Actual finite CLI/service carrier fixtures and retained program-child checks.

Only HIA fixtures choose frames. Python builds source-bound images, invokes a
fresh ELF, and compares observations. It never services an in-flight request.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,importlib.util,json,os,resource,signal,struct,subprocess,sys,time,traceback,zlib

def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    spec.loader.exec_module(value)
    return value
def protected(raw,size=None):
    size=len(raw) if size is None else size
    assert len(raw)<=size
    guard=b"HIA-FINITE-CARRIER-CANARY-32BYTE"
    assert len(guard)==32
    backing=ctypes.create_string_buffer(64+max(1,size))
    address=ctypes.addressof(backing)+32
    ctypes.memmove(address-32,guard,32)
    ctypes.memmove(address,raw,len(raw))
    ctypes.memmove(address+max(1,size),guard,32)
    return backing,address,size,guard
def checked(record):
    backing,address,size,guard=record
    assert ctypes.string_at(address-32,32)==guard
    assert ctypes.string_at(address+max(1,size),32)==guard

ORACLE = r'''
import json,sys
from pathlib import Path
from hashlib import sha256
root=Path(sys.argv[1]);out=Path(sys.argv[2])
sys.dont_write_bytecode=True;sys.path.insert(0,str(root))
from hepta.hia_program import verify_program,HIAProgramRejected
from hepta.hia_schema import SCHEMA
from tests.test_hia_program import f,b,ret
from tests.test_hia_program_composite import module,record
base={"schema":SCHEMA,"module":"finite_cli","functions":[
    f("unit",[],[],[],[b("entry",[],[],ret())])]}
nominal=module([record("Pair",[("first","u64"),("second","u64")])],
    f("identity",[("x","Pair")],["Pair"],[],[b("entry",[("x","Pair")],[],ret("x"))]))
bad=json.loads(json.dumps(base));bad["functions"][0]["blocks"][0]["term"]={"op":"unknown"}
cases=[("primitive",base),("nominal",nominal),("empty",b""),("invalid-core",bad)]
rows=[]
for name,value in cases:
    raw=value if type(value) is bytes else json.dumps(value,separators=(",",":"),ensure_ascii=False).encode()
    path=out/name;path.mkdir(parents=True,exist_ok=False);(path/"input.bin").write_bytes(raw)
    row={"name":name,"input_bytes":len(raw),"input_sha256":sha256(raw).hexdigest()}
    try:
        p=verify_program(raw);core=p.canonical_bytes
        (path/"expected-core.bin").write_bytes(core)
        row.update(accepted=True,core_bytes=len(core),core_sha256=sha256(core).hexdigest())
    except HIAProgramRejected as error:
        row.update(accepted=False,error_class=type(error).__name__,message=str(error),code=error.code)
    rows.append(row)
(out/"summary.json").write_text(json.dumps({"status":"PASS","cases":rows},sort_keys=True,indent=2)+"\n")
print(json.dumps(rows,sort_keys=True),flush=True)
'''

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--reference",type=Path,required=True)
    parser.add_argument("--compiler",type=Path,required=True)
    parser.add_argument("--roles",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    options=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    out=options.out.resolve();out.mkdir(parents=True,exist_ok=False)
    assert sys.version_info[:3]==(3,12,14),sys.version
    source=options.source.resolve();reference=options.reference.resolve()
    pins={};rows=[];compiles=[];compile_cache={};packer_entries=0;native_processes=0
    def read(path):
        path=Path(path).resolve();raw=path.read_bytes()
        if path in pins:assert pins[path]==raw
        pins[path]=raw
        return raw
    def snapshot(path,label):
        raw=read(path);dest=out/"frozen"/label;dest.parent.mkdir(parents=True,exist_ok=True)
        if dest.exists():assert dest.read_bytes()==raw
        else:dest.write_bytes(raw)
        return raw,dest
    def cas(raw):
        raw=bytes(raw);h=digest(raw);p=out/"cas"/(h+".zlib");p.parent.mkdir(exist_ok=True)
        if not p.exists():p.write_bytes(zlib.compress(raw,6))
        assert zlib.decompress(p.read_bytes())==raw
        return dict(bytes=len(raw),sha256=h,path="cas/"+p.name,compression="zlib")
    def subrun(label,argv,cwd=None,timeout=120):
        target=out/"commands"/label;target.mkdir(parents=True,exist_ok=False)
        p=subprocess.run([str(x) for x in argv],cwd=cwd,capture_output=True,timeout=timeout)
        (target/"stdout.bin").write_bytes(p.stdout);(target/"stderr.bin").write_bytes(p.stderr)
        save(target/"process.json",dict(argv=[str(x) for x in argv],exit=p.returncode,
            stdout_bytes=len(p.stdout),stderr_bytes=len(p.stderr)))
        if p.returncode:
            sys.stdout.buffer.write(p.stdout);sys.stdout.buffer.flush()
            sys.stderr.buffer.write(p.stderr);sys.stderr.buffer.flush()
        p.check_returncode()
        return p.stdout

    result=dict(status="INCOMPLETE",scope="FRESH_NATIVE_FINITE_CARRIER_COMPONENT_DEVELOPMENT",
        whole_cli_closed=False,installed_activated=False,cold_qualified=False,
        python_runtime_dispatch=False)
    try:
        for path in sorted((root/"tools").glob("*")):
            if path.is_file():snapshot(path,"authoring/"+path.name)
        snapshot(Path(__file__),"test-source.py")
        for path in (root/"reference/cli-executor-r4.S",root/"reference/program-executor.S",
                     root/"reference/program-roles.json"):
            snapshot(path,"reference/"+path.name)
        dependency=root.parent/"native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py"
        snapshot(dependency,"authoring/hia_composite_lowering_driver_common.py")
        helper=root.parent/"Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py"
        snapshot(helper,"authoring/hia_agent_edit_source_views.py")
        compiler_raw,compiler=snapshot(options.compiler,"compiler/B3.image.bin")
        assert (len(compiler_raw),digest(compiler_raw))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
        sys.path.insert(0,str(root/"tools"));sys.path.insert(0,str(source))
        sys.path.insert(0,str(root.parent/"Hepta-agent-edit-native"))
        from tools.qualify_hia_selfhost import compile_stage
        from hepta.hia_agent_assembly import assemble_program,render_assembly
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        import cli_authoring
        fixtures=load_module("finite_fixtures",root/"tools/cli_business_fixture_owners.py")
        composer=load_module("finite_composer",root/"tools/compose_cli_business_executor.py")
        packer_author=load_module("finite_packer",root/"tools/generate_hia_cli_business_packer.py")

        cli=read(root/"reference/cli-executor-r4.S")
        service=read(root/"reference/program-executor.S")
        assert digest(cli)==composer.CLI_SHA and digest(service)==composer.SERVICE_SHA
        generated,composition=composer.compose(cli.decode(),service.decode())
        checked_source=read(root/"tools/cli_business_executor.S")
        assert generated.encode()==checked_source
        save(out/"composition.json",composition)
        # Preserve the actual forward-equate failure as an independent as-only
        # negative control. The old source is never executed or used for packing.
        old_asm=read(root/"reference/finite-executor-forward-equate-r2.S")
        old_line=(b"    /* Resume is the actual operation-18 ACK plus the exact HIA reply view. */\n"
                  b"    mov rax,svc_ACK\n")
        new_line=(b"    /* The parent ACK is already defined; avoid a forward absolute-equate\n"
                  b"     * operand that GNU as selects as a 32-bit displacement before resolution. */\n"
                  b"    mov rax,ACK\n")
        assert old_asm.count(old_line)==1 and old_asm.replace(old_line,new_line,1)==checked_source
        negative=out/"forward-equate-original-negative";negative.mkdir()
        (negative/"source.S").write_bytes(old_asm)
        command=["as","--64",str(negative/"source.S"),"-o",str(negative/"carrier.o")]
        result_as=subprocess.run(command,capture_output=True,timeout=20)
        (negative/"stdout.bin").write_bytes(result_as.stdout)
        (negative/"stderr.bin").write_bytes(result_as.stderr)
        save(negative/"process.json",dict(argv=command,exit=result_as.returncode,
            stdout_bytes=len(result_as.stdout),stderr_bytes=len(result_as.stderr),
            original_source_sha256=digest(old_asm),repaired_source_sha256=digest(checked_source)))
        assert result_as.returncode!=0 and b"value of 3130414443414948 too large for field of 4 bytes" in result_as.stderr
        template=out/"template";template.mkdir()
        prefix,tables,assembly=packer_author.template(root/"tools/cli_business_executor.S",template)
        (out/"prefix.bin").write_bytes(prefix)
        save(out/"layout.json",dict(prefix_bytes=len(prefix),prefix_sha256=digest(prefix),tables=tables))

        def compile_body(label,body,constants=None):
            if constants is not None:body=cli_authoring.expanded(body,constants)
            doc=cli_authoring.document(body,label.replace("-","_"))
            hia=render_assembly(doc).encode()
            prof=cli_authoring.profile(doc)
            assert prof["functions"]<=128 and prof["blocks"]<=1536 and prof["ops"]<=8192 and prof["max_params"]<=16,prof
            at=out/"compiles"/label;at.mkdir(parents=True,exist_ok=False)
            (at/"authoring-expanded.py").write_text(body)
            (at/"source.hiaasm").write_bytes(hia);save(at/"profile.json",prof)
            source_hash=digest(hia)
            if source_hash in compile_cache:
                original=compile_cache[source_hash]
                image_raw=read(original["path"])
                assert digest(image_raw)==original["image_sha256"]
                row=dict(label=label,source_sha256=source_hash,image_sha256=digest(image_raw),
                    actual_compile=False,reused_same_source=original,profile=prof)
                save(at/"reuse.json",row);compiles.append(row)
                return image_raw
            assemble_program(hia)
            image,receipt=compile_stage(at,label,compiler,hia)
            image_raw=read(image)
            assert receipt["artifact_sha256"]==digest(compiler_raw)
            assert receipt["input_sha256"]==source_hash and receipt["produced_sha256"]==digest(image_raw)
            assert len(image_raw)<=1048576
            row=dict(label=label,source_sha256=source_hash,image_sha256=digest(image_raw),
                image_bytes=len(image_raw),path=str(image),actual_compile=True,receipt=receipt,profile=prof)
            save(at/"manifest.json",row);compile_cache[source_hash]=row;compiles.append(row)
            return image_raw

        packer_body=packer_author.source(prefix,tables)
        packer_raw=compile_body("finite-packer",packer_body)
        packer=NativeHiaJsonImage(packer_raw,expected_sha256=digest(packer_raw))
        write_second=compile_body("write-second",fixtures.WRITE_SECOND)
        oracle=out/"reference-oracle.py";oracle.write_text(ORACLE)
        read(oracle)
        oracle_out=out/"oracle";oracle_out.mkdir()
        subrun("reference-oracle",[sys.executable,"-I","-B",oracle,reference,oracle_out],timeout=90)
        orows=json.loads((oracle_out/"summary.json").read_bytes())["cases"]
        assert len(orows)==4 and [row["accepted"] for row in orows]==[True,True,False,False]
        roles=json.loads(read(options.roles))["components"]
        # These are the exact issued source/image bytes of the already published
        # program and ordinary owners. Root 56 is always a new protocol fixture.
        originals={}
        for role in range(1,56):
            row=roles[str(role)]
            sr,sp=snapshot(row["source_path"],"issued-roles/"+str(role)+"/source.hiaasm")
            ir,ip=snapshot(row["image_path"],"issued-roles/"+str(role)+"/image.bin")
            assert (len(sr),digest(sr))==(row["source_bytes"],row["source_sha256"])
            assert (len(ir),digest(ir))==(row["image_bytes"],row["image_sha256"])
            originals[role]=ir
        read(options.roles)

        def build_elf(label,parent_image,service_image,service_id=1,real_child=False,write=False):
            nonlocal packer_entries
            parts=[b""]*133;parts[6]=parent_image
            # Both roots are mandatory in the immutable packer contract. Only
            # the table selected by the fixture's HIA request is actually run.
            parts[62]=service_image;parts[125]=service_image
            start=7 if service_id==1 else 70
            if real_child:
                for role,raw in originals.items():parts[start+role-1]=raw
            if write:parts[start+59]=write_second
            header=struct.pack("<8Q",int.from_bytes(b"HIACBP01","little"),1,3,133,
                1128+sum(map(len,parts)),1128,64,0)
            packet=header+struct.pack("<133Q",*map(len,parts))+b"".join(parts)
            assert len(header)==64 and len(packet)==1128+sum(map(len,parts))
            expected=bytearray(prefix)
            for index,raw in enumerate(parts):
                if not raw:continue
                expected+=bytes((-len(expected))&15)
                table=0 if index<7 else 1 if index<70 else 2
                role=index+1 if table==0 else index-6 if table==1 else index-69
                struct.pack_into("<Q",expected,tables[table]+role*8,0x400000+len(expected))
                expected+=raw
            struct.pack_into("<Q",expected,96,len(expected));struct.pack_into("<Q",expected,104,len(expected))
            a=protected(packet);b=protected(b"",len(expected));c=protected(b"",64)
            ret=int(packer._entry(a[1],a[2],b[1],b[2],c[1],c[2]));packer_entries+=1
            for item in (a,b,c):checked(item)
            assert ctypes.string_at(a[1],a[2])==packet and ctypes.string_at(c[1],c[2])==bytes(64)
            actual=ctypes.string_at(b[1],b[2])
            assert ret==len(expected) and actual==bytes(expected),(ret,len(expected))
            dst=out/"cases"/label;dst.mkdir(parents=True,exist_ok=False)
            save(dst/"pack.json",dict(input=cas(packet),output=cas(actual),
                independent_layout_exact=True,return_value=ret,
                complete_input_unchanged=True,complete_scratch_unchanged=True))
            elf=dst/"native-fixture";elf.write_bytes(actual);elf.chmod(0o700)
            assert elf.read_bytes()==actual
            assert struct.unpack_from("<H",actual,56)[0]==2
            assert [struct.unpack_from("<I",actual,64+56*i)[0] for i in range(2)]==[1,0x6474e551]
            return elf

        libc=ctypes.CDLL(None,use_errno=True)
        libc.prctl.argtypes=[ctypes.c_int,*([ctypes.c_ulong]*4)];libc.prctl.restype=ctypes.c_int
        def invoke(elf):
            nonlocal native_processes
            target=elf.parent;expected_parent=os.getpid()
            def limits():
                if libc.prctl(1,signal.SIGKILL,0,0,0):
                    e=ctypes.get_errno();raise OSError(e,os.strerror(e))
                if os.getppid()!=expected_parent:os.kill(os.getpid(),signal.SIGKILL)
                resource.setrlimit(resource.RLIMIT_CPU,(90,90))
                resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
                resource.setrlimit(resource.RLIMIT_CORE,(0,0))
            process=None;usage=None;status=None;timed_out=False;begin=time.monotonic_ns()
            with (target/"stdout.bin").open("wb") as so,(target/"stderr.bin").open("wb") as se:
                try:
                    process=subprocess.Popen([str(elf)],cwd=target,
                        stdin=subprocess.DEVNULL,stdout=so,stderr=se,start_new_session=True,
                        env=dict(PATH="",HOME="",LANG="C.UTF-8",LC_ALL="C.UTF-8"),
                        preexec_fn=limits)
                    native_processes+=1
                    while status is None:
                        pid,state,measured=os.wait4(process.pid,os.WNOHANG)
                        if pid:
                            status,usage=state,measured
                            process.returncode=os.waitstatus_to_exitcode(state)
                            break
                        if time.monotonic_ns()-begin>120_000_000_000:
                            timed_out=True;break
                        time.sleep(0.01)
                finally:
                    primary=sys.exception();cleanup=[]
                    if process is not None and process.returncode is None:
                        try:os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        except BaseException as error:cleanup.append(error)
                        try:
                            _,status,usage=os.wait4(process.pid,0)
                            process.returncode=os.waitstatus_to_exitcode(status)
                        except BaseException as error:cleanup.append(error)
                    if cleanup:
                        if primary is not None:
                            for error in cleanup:primary.add_note("cleanup: "+repr(error))
                        else:raise cleanup[0]
            stdout=(target/"stdout.bin").read_bytes();stderr=(target/"stderr.bin").read_bytes()
            row=dict(argv=[str(elf)],pid=process.pid,exit=process.returncode,
                wait_status=status,timed_out=timed_out,elapsed_ns=time.monotonic_ns()-begin,
                user_cpu=usage.ru_utime,system_cpu=usage.ru_stime,maxrss=usage.ru_maxrss,
                stdout=cas(stdout),stderr=cas(stderr),cpu_limit=90,address_limit=1<<30)
            save(target/"process.json",row)
            assert not timed_out
            return row,stdout,stderr

        specs=[(0,1,0),(1,1,0),(2,1,0),(3,1,126),(4,1,126),
            (5,1,126),(6,1,126),(7,1,126),(8,1,126),(9,1,126),
            (11,1,126),(12,1,126),(13,1,-signal.SIGSEGV),(14,2,0)]
        for mode,service_id,expected_exit in specs:
            label="mechanical-"+str(mode)
            pb,pc=fixtures.parent(mode,service_id)
            sb,sc=fixtures.service(mode,service_id)
            pi=compile_body(label+"-parent",pb,pc);si=compile_body(label+"-service",sb,sc)
            elf=build_elf(label,pi,si,service_id,write=mode in (13,14))
            row,stdout,stderr=invoke(elf)
            assert row["exit"]==expected_exit,(label,row)
            assert stderr==b""
            assert stdout==(b"NATIVE!\n" if expected_exit==0 else b""),(label,stdout)
            row.update(label=label,kind="private-carrier-mechanics",expected_exit=expected_exit,status="PASS")
            rows.append(row);save(out/"cases-so-far.json",rows)
            print("HIA_FINITE_CASE "+json.dumps(dict(label=label,status="PASS",exit=row["exit"]),sort_keys=True),flush=True)

        for index,case in enumerate(orows):
            mode=20+index;name=case["name"];label="actual-program-"+name
            raw=(oracle_out/name/"input.bin").read_bytes()
            pb,pc=fixtures.parent(mode,1,raw);sb,sc=fixtures.service(mode,1,True)
            pi=compile_body(label+"-parent",pb,pc);si=compile_body(label+"-service",sb,sc)
            elf=build_elf(label,pi,si,1,real_child=True)
            row,stdout,stderr=invoke(elf)
            assert row["exit"]==0 and stderr==b"",(label,row)
            assert len(stdout)>=224
            ack=struct.unpack_from("<28Q",stdout);terminal=ack[8:24]
            assert ack[0]==int.from_bytes(b"HIACDA01","little") and ack[3:8]==(15,0,128,160,0)
            assert terminal[0]==int.from_bytes(b"HIACDE01","little") and terminal[1]==7
            assert ack[25]==20 and ack[27]==0 and len(stdout)==224+ack[24]
            payload=stdout[224:]
            if case["accepted"]:
                core=(oracle_out/name/"expected-core.bin").read_bytes()
                assert terminal[4:6]==(0,0) and ack[26]==46
                assert terminal[6:8]==(56,256)
                assert terminal[11]==len(core) and len(payload)==256+len(core)
                assert payload[:8]==b"HIAPRV01" and payload[256:]==core
            else:
                assert terminal[4]!=0 and ack[26] in (44,46)
                if terminal[4]==8:
                    assert len(payload)>=65 and payload[:8]==b"HIACDT01"
                    dh=struct.unpack_from("<8Q",payload)
                    assert dh[1]==1 and dh[5]==len(payload)==64+dh[4] and dh[7]==0
                    assert payload[64:].decode("utf-8")==case["message"]
                else:assert not payload
            row.update(label=label,kind="actual-issued-program-child",status="PASS",
                reference=case,actual_terminal=list(terminal),actual_child_ack=list(ack),
                complete_owned_copy_after_retirement=True)
            rows.append(row);save(out/"cases-so-far.json",rows)
            print("HIA_FINITE_CASE "+json.dumps(dict(label=label,status="PASS",exit=row["exit"],
                actual_child_role=ack[26],actual_group=terminal[4],copied_bytes=ack[24]),sort_keys=True),flush=True)
        assert len(rows)==18 and native_processes==18 and packer_entries==18
        result.update(status="PASS",cases=18,private_mechanics_cases=14,issued_program_cases=4,
            accepted_programs=2,rejected_programs=2,native_processes=native_processes,
            actual_packer_entries=packer_entries,actual_compiles=sum(x["actual_compile"] for x in compiles),
            source_reuse_compiles=sum(not x["actual_compile"] for x in compiles),cases_detail=rows)
    except BaseException as error:
        result.update(status="FAIL",error_class=type(error).__name__,error=str(error),
            traceback=traceback.format_exc(),completed_cases=len(rows),
            native_processes=native_processes,actual_packer_entries=packer_entries)
        traceback.print_exc();raise
    finally:
        original=sys.exception()
        try:
            unchanged=all(path.read_bytes()==raw for path,raw in pins.items())
            result["source_pins_unchanged"]=unchanged
            save(out/"source-pins.json",[
                dict(path=str(path),bytes=len(raw),sha256=digest(raw)) for path,raw in pins.items()])
            save(out/"compiles.json",compiles);save(out/"summary.json",result)
            print("HIA_FINITE_SUMMARY "+json.dumps(result,sort_keys=True),flush=True)
            assert unchanged
        except BaseException as error:
            if original is None:raise
            original.add_note("Final evidence: "+repr(error))
if __name__=="__main__":main()
