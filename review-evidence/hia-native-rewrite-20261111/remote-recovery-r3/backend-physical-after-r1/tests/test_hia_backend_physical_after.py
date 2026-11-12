"""Fresh physical implementation-after join, development qualification only.

The first digest is produced by an actual fixed two-image file/SHA process.
The exact unmodified reference emit_program_machine remains the oracle.
Only its implementation-hash call boundary is observed to mutate owned fixtures.
The target receives no after digest. It must run the actual file owner after
its independent ELF inventory and retain the original earlier-error order.
Public native Core admission, complete public error presentation, the second
compile emission and publication are deliberately outside this component.
"""
from pathlib import Path
from hashlib import sha256
import argparse,copy,ctypes,dataclasses,json,os,stat,struct,sys,time,traceback,types
sys.dont_write_bytecode=True
BAD=0xfffffffd
MASK=(1<<64)-1
ROOT=Path(__file__).resolve().parents[1]
SUBJECT_SHA="386c110c77ef3b89a5f3e72c54737dff60c8b8625f3e544b0cc2acb242e7a3b3"
PINS={
  "reference/backend_suite_reference.py": "072f61c4cbf9a90732346784362ce9108c2e6a550c78a0324cd7ae25d5977c03",
  "reference/implementation_files_test_reference.py": "ff09bf45efe5b32324de767c69401337008a458fe341051662fe35e5d6fe3837",
  "tests/physical_after_mechanical_harness.py": "15f3261db9b18efad5159598083d5a753de89efb0d7a098a36f591c6c8f97965",
  "tests/physical_after_native_adapter.py": "90c8312a18464f1c2dd55fcb3254c7baec36978f3d5c7920892ca1f92b625339",
  "tests/implementation_files_native_adapter.py": "c9ebdb266cc3a4e1b9796bc79ae412cfd73fd966e41217b28f7d5ff6ef4ae441",
  "tests/function_frame_test_reference.py": "b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6",
  "tests/function_lowering_test_reference.py": "e08023ddab7501313a45825e5e2cdbba40d3524fee3e4a0f9ad33ba65335bc17",
  "tests/wrapper_test_reference.py": "30950bd89da646f64061fc55bd0b855178c7e20fd214485b58b20ad86b4bd470",
  "tools/hia_backend_controller.py": "35ce9e9fccfb0601d3d000834c241ae9140eb70449fabc2747ae19e84c1d2a05",
  "tools/hia_backend_physical_after.py": "72c6b155dd1c3c3286f451af78f0f75feb0568a522a5411ddc934b9b28b6ed8e",
  "tools/hia_implementation_files.py": "a7fc5e1f656fdf4bacc3e35b754cc6f113c0b257b49dcc13c9a03fa5a23fc871"
}
def digest(raw):return sha256(raw).hexdigest()
def q(raw,at=0):return struct.unpack_from("<Q",raw,at)[0]
def magic(text):return int.from_bytes(text.encode("ascii"),"little")
def changed(raw,at,value):
    value_bytes=bytearray(raw);struct.pack_into("<Q",value_bytes,at,value);return bytes(value_bytes)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def load(name,path,expected):
    path=Path(path);raw=path.read_bytes();assert digest(raw)==expected,(str(path),digest(raw),expected)
    module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),"exec"),module.__dict__);return module
def initial(graph,checked,before,directory,*,digits=4300):
    assert type(directory) is bytes
    head=struct.pack("<16Q",magic("HIABFI01"),2,19,1,17,41,23,29,
        q(graph,24),len(graph),int(checked.structured_bytes is not None),digits,
        320+len(graph),len(directory),37,0)
    head+=bytes.fromhex(checked.sha256)+bytes.fromhex(checked.input_sha256)
    head+=bytes.fromhex(before)+bytes(96)
    assert len(head)==320 and head[224:256]==bytes(32)
    return head+graph+directory

class Suite:
    def __init__(self,args,subject):
        self.args=args;self.subject=subject;self.out=subject.out
        self.root=ROOT/"tests";self.started=subject.started_ns/1e9
        self.cases=[];self.pins={};self.protocol=0;self.admitted=0;self.owned_cases=[]
        self.native_entries=0;self.by_role={str(i):0 for i in range(1,24)}
        self.before_entries=0;self.before_by_role={"1":0,"2":0}
        self.before_syscalls=0;self.syscalls=0;self.started_before=0;self.started_backend=0
        self.encoding_cpu=0.;self.encoding_wall=0.;self.cleanup_rows=[]
        self.pin(__file__);self.pin(ROOT/"tools/bounded_physical_subject.py",SUBJECT_SHA)
        for path,expected in PINS.items():self.pin(ROOT/path,expected)
        self.B=load("physical_original_backend_suite",ROOT/"reference/backend_suite_reference.py",
            PINS["reference/backend_suite_reference.py"])
        self.I=load("physical_original_file_suite",ROOT/"reference/implementation_files_test_reference.py",
            PINS["reference/implementation_files_test_reference.py"])
        self.H=load("physical_full_CAS",self.root/"physical_after_mechanical_harness.py",
            PINS["tests/physical_after_mechanical_harness.py"])
        self.N=load("physical_fixed_native",self.root/"physical_after_native_adapter.py",
            PINS["tests/physical_after_native_adapter.py"])
        self.IN=load("physical_before_fixed_native",self.root/"implementation_files_native_adapter.py",
            PINS["tests/implementation_files_native_adapter.py"])
        self.F=self.H.F
        self.M=load("physical_lowering_fixtures",self.root/"function_lowering_test_reference.py",
            PINS["tests/function_lowering_test_reference.py"]);self.M.F=self.F
        self.W=load("physical_wrapper_fixtures",self.root/"wrapper_test_reference.py",
            PINS["tests/wrapper_test_reference.py"]);self.W.F=self.F
        self.control=load("physical_old_control_constants",ROOT/"tools/hia_backend_controller.py",
            PINS["tools/hia_backend_controller.py"])
        self.extension=load("physical_new_control_constants",ROOT/"tools/hia_backend_physical_after.py",
            PINS["tools/hia_backend_physical_after.py"])
        self.owner=load("physical_file_constants",ROOT/"tools/hia_implementation_files.py",
            PINS["tools/hia_implementation_files.py"]);self.names=self.owner.FILES
        for prefix in ("hepta","tools"):
            for path in sorted((args.reference/prefix).rglob("*.py")):
                self.pin(path,self.B.REF_PINS.get(str(path.relative_to(args.reference))))
        for path,expected in self.B.REF_PINS.items():self.pin(args.reference/path,expected)
        frozen={p:raw for p,(raw,mode) in self.pins.items()
            if p.is_relative_to(args.reference) and p.suffix==".py"}
        assert not any(n.split(".")[0] in ("hepta","tools") for n in sys.modules)
        self.finder=self.B.FrozenImports(args.reference,frozen)
        sys.meta_path.insert(0,self.finder);sys.path.insert(0,str(args.reference))
        from hepta import hia_program_native,hia_native_byte_abi,hia_machine_x64,hia_program,hia_machine_plan,object_symbols
        self.original=hia_program_native;self.byte=hia_native_byte_abi;self.code=hia_machine_x64
        self.core=hia_program;self.plan=hia_machine_plan;self.symbols=object_symbols
        self.verify=hia_program.verify_program
        self.assets=json.loads(self.pin(args.assets));self.before_assets=json.loads(self.pin(args.before_assets))
        assert self.assets["schema"]=="hia-backend-physical-after-assets-v1"
        assert set(self.assets["roles"])=={str(i) for i in range(1,24)}
        assert self.before_assets["schema"]=="hia-implementation-files-runtime-assets-v1"
        assert set(self.before_assets["roles"])=={"1","2"}
        for doc in (self.assets,self.before_assets):
            for row in doc["roles"].values():
                m=row["manifest"]
                for kind in ("source","image"):
                    assert len(self.pin(m[kind+"_path"],m[kind+"_sha256"]))==m[kind+"_bytes"]
        for alias,role in (("1","22"),("2","19")):
            assert self.before_assets["roles"][alias]["manifest"]==self.assets["roles"][role]["manifest"]
        for carrier in (args.carrier,args.before_carrier):
            self.pin(carrier);self.pin(carrier.with_suffix(".build.json"))
    def pin(self,path,expected=None):
        path=Path(path).absolute();raw=self.subject.capture(path,expected)
        mode=stat.S_IMODE(path.lstat().st_mode)
        if path in self.pins:assert self.pins[path]==(raw,mode)
        else:self.pins[path]=(raw,mode)
        return raw
    def forbidden(self,*args,**kw):raise AssertionError("reference semantic runtime fallback")
    def guard(self):return self.B.Suite.guard(self)
    def unguard(self,saved):return self.B.Suite.unguard(saved)
    def simple(self,name="entry",typ="u64"):return self.B.Suite.simple(self,name,typ)
    def plan_for(self,document,version=3):return self.B.Suite.plan_for(self,document,version)
    def remaining(self):return max(.001,180-(time.monotonic_ns()-self.subject.started_ns)/1e9)
    def case(self,label):
        path=self.out/"cases"/("%04d"%len(self.cases));path.mkdir(parents=True,exist_ok=False)
        self.owned_cases.append(path)
        save(path/"case-start.json",dict(label=label,status="STARTED",group=self.args.group,variant=self.args.variant))
        return path
    def fixture(self,case,kind="varied"):
        root,index=self.I.Suite.fixture(self,case,kind,0)
        assert index is None
        return root
    def fixture_snapshot(self,case):
        # Walk only the owned fixture tree and explicit owned aliases. Native
        # evidence is validated separately and is never a filesystem input.
        rows=[dict(row,path_hex=(b"fixture/"+bytes.fromhex(row["path_hex"])).hex())
            for row in self.I.snapshot_layout(case/"fixture")]
        for path in sorted(case.iterdir(),key=lambda p:os.fsencode(p.name)):
            if path.is_symlink():
                info=path.lstat();rows.append(dict(path_hex=os.fsencode(path.name).hex(),
                    kind="symlink",mode=stat.S_IMODE(info.st_mode),
                    target_hex=os.fsencode(os.readlink(path)).hex()))
        return sorted(rows,key=lambda row:bytes.fromhex(row["path_hex"]))
    def retire_aliases(self,case):
        rows=[];errors=[]
        for path in sorted(case.iterdir(),key=lambda p:os.fsencode(p.name)):
            if not path.is_symlink():continue
            try:
                target=os.fsencode(os.readlink(path));path.unlink()
                rows.append(dict(path_hex=os.fsencode(path.name).hex(),target_hex=target.hex()))
            except BaseException as error:errors.append(error)
        try:save(case/"fixture-owned-alias-retirement.json",rows)
        except BaseException as error:errors.append(error)
        if errors:
            for error in errors[1:]:errors[0].add_note(repr(error))
            raise errors[0]
    def close_owned_aliases(self):
        errors=[]
        for case in self.owned_cases:
            try:
                if any(path.is_symlink() for path in case.iterdir()):self.retire_aliases(case)
            except BaseException as error:errors.append(error)
        if errors:
            for error in errors[1:]:errors[0].add_note(repr(error))
            raise errors[0]
    def record_final(self,actual,case,label):
        if isinstance(actual,self.H.Mechanical):
            slots={str(slot):dict(size=b["size"],readonly=b["readonly"],
                    complete_bytes=actual.evidence.memory(b,"physical-final-"+str(slot)))
                for slot,b in sorted(actual.slots.items())}
            save(case/(label+"-final-CAS.json"),dict(slots=slots,entries=actual.entries,
                by_role={str(i):actual.calls[i] for i in range(1,24)},
                commands=actual.commands,raw_syscalls=actual.syscalls,owned_FD=actual.owned))
        else:
            save(case/(label+"-final-native.json"),dict(
                slots={str(i):dict(size=b["size"],readonly=b["readonly"]) for i,b in actual.slots.items()},
                entries=actual.entries,by_role={str(i):n for i,n in actual.calls.items()},
                commands=actual.commands,raw_syscalls=actual.syscalls,
                trace=str(actual.trace),final=str(actual.final)))
    def cleanup(self,case,items,success,primary,retire=True):
        errors=[];rows=[]
        for scope,item in items:
            if item is None:continue
            try:
                counts={str(i):n for i,n in item.calls.items()}
                assert item.entries==sum(counts.values())
                if scope=="before":
                    assert set(counts)=={"1","2"}
                    self.before_entries+=item.entries;self.before_syscalls+=item.syscalls
                    for role,n in counts.items():self.before_by_role[role]+=n
                else:
                    assert set(counts)==set(self.by_role)
                    self.native_entries+=item.entries;self.syscalls+=item.syscalls
                    for role,n in counts.items():self.by_role[role]+=n
            except BaseException as error:errors.append(error)
            try:
                closed=item.close() if isinstance(item,self.H.Mechanical) else item.close(encode=success)
                if isinstance(item,self.H.Mechanical):assert item.owned==-1
                if closed and "lossless_original_encoding" in closed:
                    encoded=closed["lossless_original_encoding"]
                    self.encoding_cpu+=encoded["cpu_seconds"];self.encoding_wall+=encoded["wall_seconds"]
                rows.append(dict(scope=scope,closed=closed))
            except BaseException as error:errors.append(error)
        if retire:
            try:self.retire_aliases(case)
            except BaseException as error:errors.append(error)
        try:
            path=case/("cleanup-"+str(len(self.cleanup_rows))+".json")
            save(path,dict(rows=rows,errors=[repr(e) for e in errors],primary=None if primary is None else repr(primary)))
            self.cleanup_rows.append(str(path.relative_to(self.out)))
        except BaseException as error:errors.append(error)
        if primary is not None:
            for error in errors:primary.add_note("physical cleanup: "+repr(error))
        elif errors:
            for error in errors[1:]:errors[0].add_note(repr(error))
            raise errors[0]
    def before(self,case,root):
        module_path=self.original.__file__
        try:
            self.original.__file__=os.fsdecode(root)+"/private_module_location.py"
            expected=self.original._implementation_hash()
        finally:self.original.__file__=module_path
        wire=self.I.initial(root);actual=None;success=False
        try:
            saved=self.guard()
            try:
                self.started_before+=1
                actual=self.IN.NativeMechanical(self.args.before_assets,self.args.before_carrier,
                    case/"actual-before-native",wire,wall_seconds=self.remaining())
            finally:self.unguard(saved)
            descriptor=self.I.Suite.validate(self,actual,actual.result,wire,
                dict(kind="success",sha256=expected),None,case)
            native_digest=actual.read(descriptor[11],0,descriptor[12])
            assert len(native_digest)==32 and native_digest.hex()==expected
            (case/"actual-before-sha256.bin").write_bytes(native_digest)
            save(case/"actual-before.json",dict(sha256=native_digest.hex(),actual_two_image_native=True,
                owner_alias=1,owner_physical_role=22,SHA_alias=2,SHA_physical_role=19,
                native_entries=actual.entries,by_role={str(i):n for i,n in actual.calls.items()},
                raw_syscalls=actual.syscalls,descriptor_hex=actual.result["payload"].hex()))
            success=True
            return native_digest.hex()
        finally:self.cleanup(case,[("before",actual)],success,sys.exception(),retire=False)
    def mutate(self,case,kind,index,records):
        assert not records and 0<=index<20
        path=case/"fixture"/self.names[index];raw=path.read_bytes()
        folder=case/"mutation";folder.mkdir();(folder/"before.bin").write_bytes(raw)
        mode=stat.S_IMODE(path.stat().st_mode)
        if kind=="change":
            after=raw+b"\x00actual-after-change\xff";path.write_bytes(after);path.chmod(mode)
            (folder/"after.bin").write_bytes(after)
            future=time.time_ns()+2*86400*10**9;os.utime(path,ns=(future,path.stat().st_mtime_ns))
        elif kind=="missing":path.unlink();after=None
        elif kind=="directory":path.unlink();path.mkdir(mode=mode);after=None
        else:raise AssertionError(kind)
        records.append(dict(kind=kind,index=index,name=self.names[index],
            before=dict(bytes=len(raw),sha256=digest(raw),mode=mode),
            after=None if after is None else dict(bytes=len(after),sha256=digest(after),mode=mode)))
        save(folder/"actual-mutation.json",records)
    def oracle(self,case,root,document,plan,foreign,before,mutation=None):
        checked=self.verify(document);self.admitted+=1;doc=checked.as_dict()
        plan=copy.deepcopy(plan)
        if type(plan) is dict and "core_sha256" in plan:plan["core_sha256"]=checked.sha256
        calls=[];mutations=[];module_path=self.original.__file__;old_hash=self.original._implementation_hash
        def observe_hash():
            ordinal=len(calls)+1
            if ordinal==2 and mutation is not None:self.mutate(case,*mutation,mutations)
            try:value=old_hash()
            except BaseException as error:
                calls.append(dict(ordinal=ordinal,error_class=type(error).__name__,error=str(error)))
                raise
            calls.append(dict(ordinal=ordinal,sha256=value));return value
        result=None;error=None;domain=None
        try:
            self.original.__file__=os.fsdecode(root)+"/private_module_location.py"
            self.original._implementation_hash=observe_hash
            try:result=self.original.emit_program_machine(checked,machine_plan=plan,foreign_buffer_exports=foreign)
            except (ValueError,TypeError,OverflowError,OSError) as caught:error=caught
        finally:
            self.original._implementation_hash=old_hash;self.original.__file__=module_path
        assert calls and calls[0].get("sha256")==before
        assert len(calls) in (1,2)
        if mutation is not None and not mutations:
            # Keep the exact original earlier error; then make the after-file
            # input fail if the target incorrectly reads it before returning.
            assert error is not None and len(calls)==1
            self.mutate(case,*mutation,mutations)
        plan_bytes=None;metadata=None
        if error is None:
            assert result is not None and len(calls)==2 and calls[1]["sha256"]==before
            if plan is not None:plan_bytes=canonical(self.plan.validate_plan(checked,plan))
            fields=dataclasses.asdict(result)
            assert fields.pop("object_bytes")==result.object_bytes and fields.pop("text_bytes")==result.text_bytes
            fields["machine_text_sha256"]=digest(result.text_bytes);metadata=canonical(fields)
        elif isinstance(error,OSError):domain=5
        elif isinstance(error,self.plan.MachinePlanRejected):domain=3
        elif isinstance(error,self.original.HIAProgramNativeRejected):domain=2
        elif isinstance(error,self.code.MachineEncodingError):domain=1
        else:raise AssertionError(("unexpected exact reference exception",type(error).__name__,str(error)))
        expectation=dict(label=case.name,error=None if error is None else dict(
            type=type(error).__name__,text=str(error),domain=domain,
            errno=getattr(error,"errno",None),
            filename_hex=None if getattr(error,"filename",None) is None else os.fsencode(error.filename).hex()),
            implementation_calls=calls,mutation=mutations,
            implementation_before=before,core_sha256=checked.sha256,input_sha256=checked.input_sha256,
            full_original_emit_program_machine_used=True,after_hash_not_supplied_to_target=True,
            native_public_Core_admission=False,admitted_Core_fixture_is_private=True)
        save(case/"oracle.json",expectation)
        if error is not None:(case/"reference.error.bin").write_bytes(str(error).encode("utf-8","surrogatepass"))
        if result is not None:
            (case/"reference.object.bin").write_bytes(result.object_bytes)
            (case/"reference.text.bin").write_bytes(result.text_bytes)
            (case/"reference.metadata.json").write_bytes(metadata)
            if plan_bytes is not None:(case/"reference.plan.json").write_bytes(plan_bytes)
        return checked,doc,plan,result,error,domain,plan_bytes,metadata,calls,expectation

    def audit_order(self,actual,needs_after,case,label):
        inspected=False;active=False;switches=[];raw_calls=0;file_entries=0
        def returned(role,header):
            nonlocal inspected,file_entries
            if role==17 and len(header)==128 and q(header,16)==0:
                assert q(header,112)==5
                inspected=True
            if role==22:
                assert active and inspected
                file_entries+=1
        def command(raw):
            nonlocal active
            values=struct.unpack("<16Q",raw)
            if values[1]==8:
                target=values[4];switches.append(target)
                if target==23:assert inspected and not active;active=True
                else:assert target==20 and active;active=False
        if isinstance(actual,self.H.Mechanical):
            actual.evidence.entries.flush()
            with (actual.out/"entries.jsonl").open() as stream:
                for line in stream:
                    row=json.loads(line)
                    if row["status"]=="RETURNED":returned(row["role"],bytes.fromhex(row["event_hex"]))
                    elif row["status"]=="MECHANICAL_ACK":command(bytes.fromhex(row["event_hex"]))
                    elif row["status"]=="RAW_SYSCALL":
                        assert active and inspected;raw_calls+=1
        else:
            for kind,raw in self.N.trace_records(actual.trace):
                if kind==4:
                    serial,role,result,n=struct.unpack_from("<4Q",raw)
                    assert len(raw)==32+n;returned(role,raw[32:])
                elif kind==5:command(raw)
                elif kind==9:assert active and inspected;raw_calls+=1
        assert raw_calls==actual.syscalls
        if needs_after:
            assert inspected and switches==[23,20] and not active
            assert file_entries==actual.calls[22]>0 and actual.calls[23]>0 and raw_calls>0
        else:
            assert not switches and not active and raw_calls==file_entries==0
            assert actual.calls[22]==actual.calls[23]==0
        assert all(slot not in actual.slots for slot in range(39,50))
        proof=dict(successful_inventory_observed_before_file_child=needs_after,
            exact_switch_targets=switches,file_owner_entries=file_entries,raw_syscalls=raw_calls,
            file_slots_39_through_49_retired=True,earlier_error_issued_no_IO=not needs_after,
            full_trace_checked=True)
        save(case/(label+"-actual-order.json"),proof);return proof
    def validate(self,actual,result,checked,doc,plan,expected,error,domain,plan_bytes,metadata,before,calls,case,label):
        assert result["status"]=="TERMINAL" and result["returned"]==128,result
        event=struct.unpack("<16Q",result["event"]);payload=result["payload"]
        assert event[:3]==(magic("HIACDE01"),7,19) and event[15]==1
        (case/(label+"-terminal.bin")).write_bytes(result["event"])
        (case/(label+"-result.bin")).write_bytes(payload)
        after=calls[1].get("sha256") if len(calls)==2 else None
        if error is not None:
            assert event[4]==domain and event[5]>0 and event[6:9]==(36,0,len(payload))
            assert actual.slots[36]["readonly"] and 35 not in actual.slots
            if isinstance(error,OSError):
                assert domain==5 and event[5]==error.errno and len(payload)>=128
                head=struct.unpack_from("<16Q",payload)
                assert head[:6]==(magic("HIABFE01"),1,19,1,37,1)
                assert head[6] in (1,5) and head[7]==error.errno and head[9]==0 and head[10]==1
                assert head[11:]==(128,len(payload)-128,len(payload),0,0)
                assert error.filename is not None and payload[128:]==os.fsencode(error.filename)
                assert 0<=head[8]<20 and payload[128:].endswith(self.names[head[8]].encode())
                assert head[6]==(5 if error.errno==21 else 1)
                save(case/(label+"-OS-error-fields.json"),dict(class_name=type(error).__name__,
                    errno=head[7],filename_hex=payload[128:].hex(),file_index=head[8],
                    full_public_error_text_rendered=False,actual_raw_fields_equal=True))
            else:
                assert payload.decode("utf-8")==str(error),(type(error).__name__,str(error),payload)
            if after is not None:
                assert actual.read(2,self.control.CONSTANTS["H_IMPL_AFTER"],32).hex()==after
        else:
            assert event[4:9]==(0,0,35,0,512) and actual.slots[35]["readonly"]
            head=struct.unpack("<64Q",payload)
            assert head[:8]==(magic("HIABMR01"),1,19,1,17,41,23,29) and head[60:]==(0,)*4
            assert head[8]==31 and head[11]==30 and head[14:16]==(19,0) and head[17:19]==(32,0)
            assert head[23]==int(plan is not None) and head[24] in ((0,) if plan is None else (1,2,3,4))
            assert head[25]==len(expected.foreign_buffer_exports) and head[26]==len(doc["functions"])
            assert head[27]==len(expected.exports) and head[28]>0 and head[29]==int(checked.structured_bytes is not None)
            assert head[31]==head[26]+head[27]
            for slot in (31,30,19,32):assert actual.slots[slot]["readonly"]
            obj=actual.read(*head[8:11]);text=actual.read(*head[11:14]);meta=actual.read(*head[14:17])
            assert obj==expected.object_bytes and text==expected.text_bytes and meta==metadata
            (case/(label+"-object.bin")).write_bytes(obj);(case/(label+"-text.bin")).write_bytes(text)
            (case/(label+"-metadata.json")).write_bytes(meta)
            if plan is None:assert head[20:23]==(0,0,0) and 11 not in actual.slots
            else:
                assert head[20:22]==(11,0) and head[22]==len(plan_bytes) and actual.slots[11]["readonly"]
                actual_plan=actual.read(*head[20:23]);assert actual_plan==plan_bytes
                (case/(label+"-plan.json")).write_bytes(actual_plan)
            hashes=b"".join(bytes.fromhex(v) for v in (checked.sha256,checked.input_sha256,
                before,after,digest(obj),digest(text)))
            hashes+=bytes(32) if plan_bytes is None else sha256(plan_bytes).digest()
            assert payload[256:480]==hashes
            assert event[9:15]==(len(meta),len(obj),len(text),0 if plan_bytes is None else len(plan_bytes),
                len(doc["functions"]),len(expected.exports))
            assert actual.calls[17]>0 and actual.calls[18]>=2 and actual.calls[19]>=6 and actual.calls[21]>0
            assert (actual.calls[16]>0)==(plan is not None)
        order=self.audit_order(actual,len(calls)==2,case,label)
        self.record_final(actual,case,label)
        return order
    def exact(self,label,document,plan=None,foreign=(),*,kind="varied",mutation=None,
              cross=False,expect_success=True,expect_no_after=False):
        case=self.case(label);root=self.fixture(case,kind)
        pristine=self.fixture_snapshot(case);save(case/"fixture-pristine.json",pristine)
        before=self.before(case,root)
        checked,doc,plan,expected,error,domain,plan_bytes,metadata,calls,oracle=self.oracle(
            case,root,document,plan,foreign,before,mutation)
        assert (error is None)==expect_success,(label,type(error).__name__,str(error))
        assert (len(calls)==1)==expect_no_after,(label,calls)
        graph=self.F.capture([doc,plan,foreign],17)
        wire=initial(graph,checked,before,root,digits=sys.get_int_max_str_digits())
        (case/"initial.bin").write_bytes(wire)
        before_target=self.fixture_snapshot(case);save(case/"fixture-before-target.json",before_target)
        actual=None;other=None;success=False;row=None
        try:
            saved=self.guard()
            try:
                if cross:
                    actual=self.H.Mechanical(self.args.assets,self.args.reference,case/"python-full-CAS")
                    result=actual.run(wire)
                    self.started_backend+=1
                    other=self.N.NativeMechanical(self.args.assets,self.args.carrier,case/"actual-after-native",
                        wire,wall_seconds=self.remaining())
                    assert other.result["event"]==result["event"] and other.result["payload"]==result["payload"]
                    assert other.result["returned"]==result["returned"]
                    comparison=other.compare_python(actual)
                else:
                    self.started_backend+=1
                    actual=self.N.NativeMechanical(self.args.assets,self.args.carrier,case/"actual-after-native",
                        wire,wall_seconds=self.remaining());result=actual.result;comparison=None
            finally:self.unguard(saved)
            order=self.validate(actual,result,checked,doc,plan,expected,error,domain,plan_bytes,metadata,before,calls,case,
                "python" if cross else "native")
            if other is not None:
                self.validate(other,other.result,checked,doc,plan,expected,error,domain,plan_bytes,metadata,
                    before,calls,case,"native")
            after_target=self.fixture_snapshot(case);save(case/"fixture-after-target.json",after_target)
            assert after_target==before_target
            by_role={str(i):sum(obj.calls[i] for obj in (actual,other) if obj is not None) for i in range(1,24)}
            row=dict(label=label,status="PASS",private=False,oracle=oracle,
                actual_native_entries=sum(by_role.values()),by_role=by_role,
                primary_entries=actual.entries,primary_by_role={str(i):n for i,n in actual.calls.items()},
                crosscheck_entries=0 if other is None else other.entries,
                crosscheck_by_role={} if other is None else {str(i):n for i,n in other.calls.items()},
                full_CAS=cross,complete_fixed_carrier_comparison=comparison,
                actual_before_native_processes=1,actual_backend_native_processes=1,
                actual_after_raw_syscalls=sum(obj.syscalls for obj in (actual,other) if obj is not None),
                actual_after_HIA_file_owner=len(calls)==2,ordered_file_read_after_inventory=order,
                complete_object_text_metadata_equal=error is None,
                original_error_full_text_equal=error is not None and not isinstance(error,OSError),
                original_OS_error_fields_equal=isinstance(error,OSError),
                native_public_Core_admission=False,full_public_error_presentation=False,
                whole_compile_program_machine=False)
            success=True
        finally:self.cleanup(case,[("target",actual),("target",other)],success,sys.exception())
        save(case/"result.json",row);self.cases.append(row)
        return row

    def prototype(self,label):
        base=self.out/"private-prototype";base.mkdir(exist_ok=False)
        self.owned_cases.append(base)
        root=self.fixture(base,"empty");before=self.before(base,root)
        checked=self.verify(self.simple());self.admitted+=1
        graph=self.F.capture([checked.as_dict(),None,()],17)
        wire=initial(graph,checked,before,root,digits=sys.get_int_max_str_digits())
        (base/"initial.bin").write_bytes(wire)
        save(base/"issued-fixture.json",dict(label=label,actual_before_native=True,sha256=before,
            private_reference_admitted_Graph=True,header_is_authentication=False))
        return wire
    def private_bad(self,label,wire,inject=None):
        case=self.case(label);(case/"initial.bin").write_bytes(wire)
        actual=None;success=False;driver=[20];used=[False];row=None
        def observe(instance,event,ack):
            values=struct.unpack("<16Q",event)
            if values[1]==8:driver[0]=values[4]
            if inject is None or used[0]:return ack
            replaced=inject(instance,values,ack)
            if replaced!=ack:used[0]=True
            return replaced
        try:
            actual=self.H.Mechanical(self.args.assets,self.args.reference,case/"python-full-CAS")
            saved=self.guard()
            try:
                result=actual.run(wire,intercept=observe)
                assert result["status"]=="PRIVATE_BAD",result
                if inject is not None:assert used[0] and actual.interceptions==1
                commands=actual.commands;syscalls=actual.syscalls
                repeat=actual.last_original_ack or wire
                operand=actual.buffers.allocate(len(repeat),repeat,True)
                try:
                    returned=actual.native(driver[0],(operand,actual.slots[3],actual.slots[2]),
                        (operand,actual.slots[3],actual.slots[2]),("valid-original-retry","slot3","slot2"))
                    assert returned==BAD
                finally:actual.buffers.close(operand)
                assert actual.commands==commands and actual.syscalls==syscalls
            finally:self.unguard(saved)
            if inject is None:assert actual.calls[22]==actual.calls[23]==actual.syscalls==0
            self.record_final(actual,case,"python")
            (case/"actual-first-BAD.bin").write_bytes(result["event"])
            row=dict(label=label,status="PASS",private=True,full_CAS=True,
                actual_native_entries=actual.entries,by_role={str(i):n for i,n in actual.calls.items()},
                primary_entries=actual.entries,primary_by_role={str(i):n for i,n in actual.calls.items()},
                crosscheck_entries=0,crosscheck_by_role={},actual_backend_native_processes=0,
                actual_after_raw_syscalls=actual.syscalls,interceptions=actual.interceptions,
                original_valid_ACK_retry_permanent_BAD=True,no_replayed_syscall_or_command=True,
                retry_driver=driver[0],actual_owned_FD_before_abort_cleanup=actual.owned)
            success=True
        finally:self.cleanup(case,[("target",actual)],success,sys.exception(),retire=False)
        save(case/"result.json",row);self.cases.append(row);self.protocol+=1
        return row

    def cross_group(self,variant):
        if variant==0:self.exact("actual-empty-files-complete-backend",self.simple(),kind="empty",cross=True)
        else:
            doc=self.M.doc(self.simple("zeta")["functions"][0],self.simple("alpha")["functions"][0])
            plan=self.plan_for(doc,3);plan["function_order"].reverse()
            self.exact("actual-varied-files-reordered-functions",doc,plan,cross=True)
    def plan_group(self):
        for version in (1,2,3,4):
            doc=self.simple();plan=self.plan_for(doc,version)
            if version>=3:plan["value_registers"]={"entry":{"x":"r8" if version==4 else "r12"}}
            self.exact("actual-file-after-plan-v"+str(version),doc,plan)
    def borrowed_group(self):
        for count in (1,8):
            doc=self.W.fixture(["readbuf" if i%2==0 else "mutbuf" for i in range(count)],["u32"],"loan")
            self.exact("actual-file-after-borrowed-"+str(count),doc,foreign=(("loan",1 if count==1 else 1<<20),))
        doc=self.M.doc(self.M.fn("scalar"),self.W.fixture(["readbuf"],["u32"],"borrowed")["functions"][0])
        self.exact("actual-file-after-scalar-and-borrowed",doc,foreign=(("borrowed",4096),))
    def paths_group(self):
        for kind in ("relative","trailing","parentlink","undecodable"):
            self.exact("actual-directory-"+kind,self.simple(),kind=kind)
    def stale_group(self,variant):
        if variant==0:
            for index in (0,19):
                self.exact("actual-stale-file-"+str(index),self.simple(),mutation=("change",index),expect_success=False)
        else:self.exact("actual-stale-whole-CAS-crosscheck",self.simple(),mutation=("change",7),cross=True,expect_success=False)
    def files_group(self,variant):
        kind,indexes=("missing",(0,7,19)) if variant==0 else ("directory",(0,19))
        for index in indexes:
            self.exact("actual-late-"+kind+"-"+str(index),self.simple(),mutation=(kind,index),expect_success=False)
    def precedence_group(self):
        rows=[("machine-plan-False",self.simple(),False,()),
              ("reserved-_init",self.M.doc(self.M.fn("normal"),self.M.fn("_init")),None,()),
              ("scalar-unit-no-admitted-export",self.simple(typ="unit"),None,()),
              ("borrowed-without-export",self.W.fixture(["readbuf"],["u32"],"loan"),None,())]
        for label,doc,plan,foreign in rows:
            self.exact("earlier-"+label,doc,plan,foreign,mutation=("missing",0),
                expect_success=False,expect_no_after=True)
    def initial_group(self):
        wire=self.prototype("new-private-header-only");directory=q(wire,96)
        changes=[(0,0),(8,1),(96,0),(104,q(wire,104)+1),(112,0),(112,19),(112,23),(112,29),
            (120,1),(224,1),(248,1)]
        for i,(at,value) in enumerate(changes):self.private_bad("new-header-"+str(i),changed(wire,at,value))
        value=bytearray(wire);value[directory]=0
        self.private_bad("new-header-embedded-directory-NUL",bytes(value))
        self.private_bad("new-header-unclaimed-trailing-byte",wire+b"x")
    def switch_group(self,variant):
        wire=self.prototype("switch-"+str(variant))
        at,value=((0,0),(8,20),(16,0),(40,1))[variant]
        def inject(actual,v,ack):
            return changed(ack,at,value) if v[1]==8 and v[4]==23 else ack
        self.private_bad("switch-ACK-"+str(variant),wire,inject)
    def peer_group(self,variant):
        wire=self.prototype("peer-"+str(variant))
        at,value=((80,38),(88,0),(184,1))[variant]
        def inject(actual,v,ack):
            if v[1]==1 and v[4]==22 and q(ack,40)==128:
                assert len(ack)==192 and q(ack,72)==2
                return changed(ack,at,value)
            return ack
        self.private_bad("file-owner-actual-return-poison-"+str(variant),wire,inject)
    def fs_group(self,variant):
        wire=self.prototype("syscall-"+str(variant))
        def inject(actual,v,ack):
            if v[1]==19 and v[4]==(1 if variant==0 else 4):
                assert actual.owned>=0
                return changed(ack,8,20) if variant==0 else changed(ack,48,143)
            return ack
        row=self.private_bad("actual-system-ACK-poison-"+str(variant),wire,inject)
        assert row["actual_owned_FD_before_abort_cleanup"]>=0
    def summary(self):
        return dict(cases=len(self.cases),private_controls=self.protocol,
            native_entries=self.native_entries,by_role=self.by_role,actual_after_raw_syscalls=self.syscalls,
            before_native_entries=self.before_entries,before_by_role=self.before_by_role,
            before_raw_syscalls=self.before_syscalls,actual_before_processes_started=self.started_before,
            actual_backend_processes_started=self.started_backend,reference_admitted_fixtures=self.admitted,
            completed_case_entries=sum(row["actual_native_entries"] for row in self.cases),
            complete_full_CAS_cases=sum(row["full_CAS"] for row in self.cases),
            complete_fixed_carrier_crosschecks=sum(row.get("complete_fixed_carrier_comparison") is not None for row in self.cases),
            exact_raw_encoding_cpu_seconds=self.encoding_cpu,exact_raw_encoding_wall_seconds=self.encoding_wall,
            encoding_in_subject_budget=True,cleanup_receipts=self.cleanup_rows,
            all_target_semantics_HIA=True,header_is_authentication=False,
            native_public_Core_admission=False,full_public_error_presentation=False,
            second_compile_emission=False,publication=False,whole_public_build=False,
            installed=False,cold=False,old_results_inherited=False)

SCHEDULE=[
 ["cross",0,1,0],["cross",1,1,0],["plan",0,4,0],["borrowed",0,3,0],
 ["paths",0,4,0],["stale",0,2,0],["stale",1,1,0],["files",0,3,0],["files",1,2,0],
 ["precedence",0,4,0],["initial",0,13,13],
 ["switch",0,1,1],["switch",1,1,1],["switch",2,1,1],["switch",3,1,1],
 ["peer",0,1,1],["peer",1,1,1],["peer",2,1,1],["fs",0,1,1],["fs",1,1,1]]
def main():
    parser=argparse.ArgumentParser()
    for name in ("assets","carrier","before-assets","before-carrier","reference","out"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--group",required=True);parser.add_argument("--variant",type=int,default=0)
    args=parser.parse_args()
    for key in ("assets","carrier","before_assets","before_carrier","reference"):
        setattr(args,key,getattr(args,key).resolve())
    subject_module=load("physical_subject_test",ROOT/"tools/bounded_physical_subject.py",SUBJECT_SHA)
    subject=subject_module.Subject(args.out,"physical-after-"+args.group+"-"+str(args.variant))
    subject.report.update(group=args.group,variant=args.variant,expected_cases=0,expected_private_controls=0)
    suite=None
    try:
        assert sys.version_info[:3]==(3,12,14)
        assert len(SCHEDULE)==20 and sum(row[2] for row in SCHEDULE)==47 and sum(row[3] for row in SCHEDULE)==22
        selected=[row for row in SCHEDULE if row[:2]==[args.group,args.variant]];assert len(selected)==1
        subject.report.update(expected_cases=selected[0][2],expected_private_controls=selected[0][3])
        suite=Suite(args,subject)
        if args.group in ("cross","stale","files","switch","peer","fs"):
            getattr(suite,args.group+"_group")(args.variant)
        else:getattr(suite,args.group+"_group")()
        assert (len(suite.cases),suite.protocol)==tuple(selected[0][2:])
        observation=suite.summary()
        assert observation["native_entries"]==observation["completed_case_entries"]==sum(observation["by_role"].values())
        assert observation["before_native_entries"]==sum(observation["before_by_role"].values())
        assert observation["actual_before_processes_started"]==(1 if args.group in ("initial","switch","peer","fs") else len(suite.cases))
        subject.report.update(observation,status="PASS")
    except BaseException as error:
        subject.failure(error);subject.attempt("traceback",traceback.print_exc)
    finally:
        if suite is not None:
            subject.attempt("owned-fixture-alias-cleanup",suite.close_owned_aliases)
            subject.attempt("case-counter-receipt",lambda:subject.report.update(suite.summary()))
        subject.finish("PASS")
if __name__=="__main__":main()
