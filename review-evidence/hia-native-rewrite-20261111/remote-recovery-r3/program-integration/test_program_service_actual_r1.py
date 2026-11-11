"""Actual A admission, projection and wire in the fixed native carrier.
A private HIA issuer supplies immutable views; no host services a pending event.
Original component case counts are not repeated or inherited.
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

ORACLE = r'''import copy,json,sys
from pathlib import Path
from hashlib import sha256
sys.dont_write_bytecode=True
root=Path(sys.argv[1]);out=Path(sys.argv[2]);sys.path.insert(0,str(root))
from hepta.hia_program import verify_program,HIAProgramRejected
from hepta.hia_program_tools import inspect_program
from tests.test_hia_composite_returned_loans import pair_program
base=json.loads((root/"examples/hia_program/counter.hia").read_bytes())
cases=[]
for version in range(1,9):
    doc=copy.deepcopy(base);doc["schema"]="hepta.hia.program.v"+str(version)
    cases.append(("core-v"+str(version),doc,True))
composite={}
for path in sorted((root/"examples/hia_program").glob("*.hia")):
    doc=json.loads(path.read_bytes())
    if doc["schema"] in ("hepta.hia.composite.v1","hepta.hia.composite.v2","hepta.hia.composite.v3"):
        composite.setdefault(doc["schema"],doc)
recursive=json.loads((root/"examples/hia_recursive_chain/composite_v2.json").read_bytes())
composite.setdefault(recursive["schema"],recursive)
assert set(composite)=={"hepta.hia.composite.v"+str(i) for i in (1,2,3)}
for schema,doc in sorted(composite.items()):cases.append((schema.replace(".","-"),doc,True))
for mode in ("read","mut"):cases.append(("composite-v4-pair-"+mode,pair_program(mode),True))
for exports in (None,[],["zulu","alpha"]):
    doc=copy.deepcopy(base);doc["schema"]="hepta.hia.program.v8"
    doc["functions"]=[copy.deepcopy(base["functions"][0]) for _ in range(2)]
    doc["functions"][0]["name"]="zulu";doc["functions"][1]["name"]="alpha"
    if exports is not None:doc["exports"]=exports
    cases.append(("exports-"+("absent" if exports is None else "empty" if not exports else "reverse"),doc,True))
cases.append(("noncanonical-input-spacing",b" \n"+json.dumps(base,indent=2).encode()+b"\n ",True))
bad=copy.deepcopy(base);bad["functions"][0]["blocks"][0]["term"]={"op":"not-an-operation"}
bad_module=copy.deepcopy(base);bad_module["module"]=False
invalid=[("empty",b""),("malformed-json",b"{"),("invalid-UTF8",b"\xff"),
 ("array-root",b"[]"),("unknown-schema",b'{"schema":"hepta.hia.program.v99"}'),
 ("invalid-core-term",bad),("duplicate-key",b'{"schema":"hepta.hia.program.v8","schema":"hepta.hia.program.v8"}'),
 ("invalid-module",bad_module)]
cases.extend((label,value,False) for label,value in invalid)
assert len(cases)==25 and sum(accepted for _,_,accepted in cases)==17
rows=[]
for label,value,accepted in cases:
    raw=value if type(value) is bytes else json.dumps(value,ensure_ascii=False,separators=(",",":")).encode()
    assert len(raw)<26000
    where=out/label;where.mkdir(parents=True,exist_ok=False);(where/"input.bin").write_bytes(raw)
    row=dict(label=label,accepted=accepted,input_bytes=len(raw),input_sha256=sha256(raw).hexdigest(),actions={})
    try:
        program=verify_program(raw)
        assert accepted,label
        values={6:{**program.report(),"status":"standalone_core_checked","native_executed":False},
                7:inspect_program(program),8:program.as_dict()}
        for action,value in values.items():
            payload=json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(",",":")).encode()
            (where/("expected-"+str(action)+".bin")).write_bytes(payload)
            row["actions"][str(action)]=dict(kind=3,domain=0,exit=0,format=1,bytes=len(payload),sha256=sha256(payload).hexdigest())
        row.update(input_schema=json.loads(raw)["schema"],core_schema=program.as_dict()["schema"],core_sha256=program.sha256)
    except HIAProgramRejected as error:
        assert not accepted,(label,str(error))
        payload=str(error).encode()
        for action in (6,7,8):
            (where/("expected-"+str(action)+".bin")).write_bytes(payload)
            row["actions"][str(action)]=dict(kind=4,domain=1,exit=2,format=0,bytes=len(payload),sha256=sha256(payload).hexdigest())
        row.update(error_class=type(error).__name__,error_code=error.code,message=str(error))
    rows.append(row)
result=dict(status="PASS_ORACLE_ONLY",inputs=25,accepted=17,rejected=8,cases=75,rows=rows)
(out/"summary.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
print(json.dumps(result,sort_keys=True),flush=True)
'''


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--reference",type=Path,required=True)
    parser.add_argument("--compiler",type=Path,required=True)
    parser.add_argument("--roles",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--assets",type=Path,required=True)
    parser.add_argument("--service-manifest",type=Path,required=True)
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

    result=dict(status="INCOMPLETE",scope="ACTUAL_A_SERVICE_FIXED_CARRIER_INTEGRATION",
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
        sys.path.insert(0,str(root/"tools"));sys.path.insert(0,str(reference))
        sys.path.insert(0,str(root.parent/"Hepta-agent-edit-native"))
        from tools.qualify_hia_selfhost import compile_stage
        assert digest(read(reference/"tools/qualify_hia_selfhost.py"))=="2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"
        from hepta.hia_agent_assembly import assemble_program,render_assembly
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        import cli_authoring
        fixtures=load_module("finite_fixtures",root/"tools/cli_business_fixture_owners.py")
        parent_owner=load_module("actual_A_parent",root/"tools/program_service_real_parent.py")
        composer=load_module("finite_composer",root/"tools/compose_cli_business_executor.py")
        packer_author=load_module("finite_packer",root/"tools/generate_hia_cli_business_packer.py")

        cli=read(root/"reference/cli-executor-r4.S")
        service=read(root/"reference/program-executor.S")
        assert digest(cli)==composer.CLI_SHA and digest(service)==composer.SERVICE_SHA
        generated,composition=composer.compose(cli.decode(),service.decode())
        checked_source=read(root/"tools/cli_business_executor.S")
        assert generated.encode()==checked_source
        save(out/"composition.json",composition)
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
        oracle=out/"reference-oracle.py";oracle.write_text(ORACLE)
        read(oracle)
        oracle_out=out/"oracle";oracle_out.mkdir()
        subrun("reference-oracle",[sys.executable,"-I","-B",oracle,reference,oracle_out],timeout=90)
        orows=json.loads((oracle_out/"summary.json").read_bytes())["rows"]
        assert len(orows)==25 and sum(row["accepted"] for row in orows)==17
        roles=json.loads(read(options.roles))["components"]
        # These are the exact issued source/image bytes of the already published
        # program and ordinary owners. Root 56 is always a new protocol fixture.
        originals={}
        for role in list(range(1,56))+[58]:
            row=roles[str(role)]
            sr,sp=snapshot(row["source_path"],"issued-roles/"+str(role)+"/source.hiaasm")
            ir,ip=snapshot(row["image_path"],"issued-roles/"+str(role)+"/image.bin")
            assert (len(sr),digest(sr))==(row["source_bytes"],row["source_sha256"])
            assert (len(ir),digest(ir))==(row["image_bytes"],row["image_sha256"])
            originals[role]=ir
        read(options.roles)
        assets=json.loads(read(options.assets))
        assert assets["status"]=="PASS_READBACK_ONLY" and assets["inherited_case_counts"] is False
        for label,row in assets["components"].items():
            raw=read(row["source_path"]);image=read(row["image_path"])
            assert (len(raw),digest(raw))==(row["source_bytes"],row["source_sha256"])
            assert (len(image),digest(image))==(row["image_bytes"],row["image_sha256"])
            originals[row["role"]]=image
        assert set(assets["components"])=={"wire-scan","wire-emit","projector"}
        manifest=json.loads(read(options.service_manifest))
        service_source=read(manifest["source_path"]);service_image=read(manifest["image_path"])
        assert manifest["actual_native_B3"] is True
        assert (len(service_source),digest(service_source))==(manifest["source_bytes"],manifest["source_sha256"])
        assert (len(service_image),digest(service_image))==(manifest["image_bytes"],manifest["image_sha256"])
        assert manifest["compiler_sha256"]==digest(compiler_raw)
        save(out/"actual-service-bundle.json",dict(root=manifest,assets=assets["components"],
            original_program_roles=[r for r in range(1,56) if r not in (29,30)],
            original_decoder_service_role=58,private_parent_issuer=True,public_CLI_parser_claim=False))

        def build_elf(label,parent_image,service_image,service_id=1,real_child=False,write=False):
            nonlocal packer_entries
            parts=[b""]*133;parts[6]=parent_image
            # Both roots are mandatory in the immutable packer contract. Only
            # the table selected by the fixture's HIA request is actually run.
            parts[62]=service_image;parts[125]=service_image
            start=7 if service_id==1 else 70
            if real_child:
                for role,raw in originals.items():parts[start+role-1]=raw
            if write:raise AssertionError("no fixture substitution permitted")
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

        core_schemas=set();input_schemas=set()
        for case in orows:
            raw=(oracle_out/case["label"]/"input.bin").read_bytes()
            assert len(raw)==case["input_bytes"] and digest(raw)==case["input_sha256"]
            if case["accepted"]:
                core_schemas.add(case["core_schema"]);input_schemas.add(case["input_schema"])
            for action in (6,7,8):
                label=case["label"]+"-action-"+str(action)
                parent_body,parent_constants,parent_metadata=parent_owner.source(raw,action)
                parent_image=compile_body(label+"-parent",parent_body,parent_constants)
                elf=build_elf(label,parent_image,service_image,1,real_child=True)
                row,stdout,stderr=invoke(elf)
                assert row["exit"]==0 and stderr==b"",(label,row)
                assert len(stdout)>128,(label,len(stdout))
                event=struct.unpack_from("<16Q",stdout)
                expected=case["actions"][str(action)]
                assert event[:4]==(int.from_bytes(b"HIACBE01","little"),1,1,2),(label,event)
                assert event[4]>0 and event[5]==0
                assert event[6:9]==(expected["kind"],expected["domain"],expected["exit"])
                assert event[9:13]==(0,expected["format"],0,128)
                assert event[13:]==(len(stdout)-128,len(stdout),0)
                wanted=(oracle_out/case["label"]/("expected-"+str(action)+".bin")).read_bytes()
                assert (len(wanted),digest(wanted))==(expected["bytes"],expected["sha256"])
                assert stdout[128:]==wanted,(label,stdout[128:],wanted)
                if case["accepted"]:
                    assert json.loads(stdout[128:])==json.loads(wanted)
                row.update(label=label,action=action,accepted=case["accepted"],status="PASS",
                    private_parent=parent_metadata,event=list(event),expected=cas(wanted),
                    actual_owned_result_after_service_retirement=True,
                    real_program_admission=True,real_projection_and_wire=case["accepted"],
                    public_CLI_entry_claim=False,publication_operations=0)
                rows.append(row);save(out/"cases-so-far.json",rows)
                print("HIA_A_REAL_CASE "+json.dumps(dict(label=label,status="PASS",action=action,
                    accepted=case["accepted"],result_bytes=len(stdout)),sort_keys=True),flush=True)
        assert len(rows)==75 and native_processes==75 and packer_entries==75
        assert core_schemas=={"hepta.hia.program.v"+str(i) for i in range(1,9)}
        assert input_schemas==core_schemas|{"hepta.hia.composite.v"+str(i) for i in range(1,5)}
        result.update(status="PASS",cases=75,accepted_cases=51,rejected_cases=24,
            native_processes=native_processes,actual_packer_entries=packer_entries,
            actual_compiles=sum(x["actual_compile"] for x in compiles),
            source_reuse_compiles=sum(not x["actual_compile"] for x in compiles),
            original_component_case_counts_inherited=False,public_CLI_entry_claim=False,
            publication_operations=0,source_bound_real_A_service=True,
            real_program_receipt_and_SHA_verification=True,real_native_decoder_projector_wire=True,
            complete_values_and_bytes_equal=True,core_schemas=sorted(core_schemas),
            input_schemas=sorted(input_schemas),cases_detail=rows)
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
            print("HIA_A_REAL_SUMMARY "+json.dumps(result,sort_keys=True),flush=True)
            assert unchanged
        except BaseException as error:
            if original is None:raise
            original.add_note("Final evidence: "+repr(error))
if __name__=="__main__":main()
