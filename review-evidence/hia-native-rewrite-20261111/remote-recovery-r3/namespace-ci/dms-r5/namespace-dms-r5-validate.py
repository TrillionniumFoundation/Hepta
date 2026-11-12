"""Fresh real B3 and full-buffer CoreVM/native DMS/FS5 differential.
Only private synthetic kernel replies are used. No physical DMS/store claim.
"""
import sys
sys.dont_write_bytecode=True
import ctypes,gzip,hashlib,importlib.util,json,os,pathlib,stat,time,traceback,unittest
CONTEXT_PATH=pathlib.Path(os.environ["HIA_NAMESPACE_CI_CONTEXT"]).resolve()
CONTEXT_RAW=CONTEXT_PATH.read_bytes();CONTEXT=json.loads(CONTEXT_RAW)
assert os.environ.get("GITHUB_ACTIONS")=="true"
TREE=pathlib.Path(CONTEXT["namespace_working"]);DEV=pathlib.Path(CONTEXT["namespace_evidence"])
REF=pathlib.Path(CONTEXT["reference"]);OUT=DEV/"validation-r1"
OUT.mkdir(mode=0o700,exist_ok=False);(OUT/"source").mkdir()
CANARY=bytes(range(192,224))
EXPECTED_TESTS=29
def sha(raw):return hashlib.sha256(raw).hexdigest()
def dump(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
before={}
def pin(path):
    path=pathlib.Path(path).resolve();info=path.stat();assert stat.S_ISREG(info.st_mode)
    raw=path.read_bytes();row=dict(bytes=len(raw),mode=stat.S_IMODE(info.st_mode),sha256=sha(raw))
    if str(path) in before:assert before[str(path)]==row
    before[str(path)]=row;return raw
def load(name,path):
    raw=pin(path);spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    exec(compile(raw,str(path),"exec"),module.__dict__);return module
sys.path.insert(0,str(REF))
generation=json.loads((DEV/"generation-r1/result.json").read_bytes())
assert generation["status"]=="GENERATED" and generation["source_unchanged"]
for name in ("generate_hia_agent_namespace_store","generate_hia_agent_namespace_objects",
             "generate_hia_agent_namespace_filesystem_r5","generate_hia_agent_namespace_dms_lifetime"):
    load("tools."+name,TREE/"tools"/(name+".py"))
suite_module=load("tests.namespace_dms_r5_development",TREE/"tests/test_hia_agent_namespace_dms_lifetime.py")
from tools.qualify_hia_selfhost import compile_stage,CHILD
from hepta.hia_json_preflight_native import NativeHiaJsonImage
import hepta.hia_program_runtime,hepta.hia_agent_assembly,tools.qualify_hia_selfhost
assert pathlib.Path(tools.qualify_hia_selfhost.__file__).resolve()==REF/"tools/qualify_hia_selfhost.py"
assert pathlib.Path(CHILD).resolve()==REF/"tools/hia_selfhost_child.py"
assert pathlib.Path(hepta.hia_program_runtime.__file__).resolve()==REF/"hepta/hia_program_runtime.py"
assert pin(CONTEXT_PATH)==CONTEXT_RAW
for path,row in generation["source_after"].items():
    raw=pin(path)
    assert len(raw)==row["bytes"] and sha(raw)==row["sha256"] and stat.S_IMODE(pathlib.Path(path).stat().st_mode)==row["mode"]
sources={}
for role,row in generation["generated"].items():
    raw=pin(row["path"]);assert sha(raw)==row["sha256"] and len(raw)==row["bytes"]
    sources[role]=raw
assert set(sources)=={"dms","fs"}
compiler=DEV/"compiler/B3.image.bin";compiler_raw=pin(compiler)
assert len(compiler_raw)==669556 and sha(compiler_raw)=="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
for module in tuple(sys.modules.values()):
    filename=getattr(module,"__file__",None)
    if filename:
        p=pathlib.Path(filename).resolve()
        if p.is_relative_to(REF) and p.suffix==".py":pin(p)
pin(CHILD);pin(__file__)
for index,(path,row) in enumerate(before.items()):
    p=pathlib.Path(path);target=OUT/"source"/str(index)/p.name;target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(p.read_bytes());target.chmod(row["mode"]);assert sha(target.read_bytes())==row["sha256"]
dump(OUT/"source-before.json",before)
report=dict(status="INCOMPLETE",scope="NEW_DMS_R4_FS5_SYNTHETIC_KERNEL_TWO_REAL_IMAGES",
    whole_store_closed=False,DMS_mapping_closed=False,ordinary_AgentStore_closed=False,
    actual_physical_syscalls=0,private_frames_are_not_external_authentication=True,
    reference_commit="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5",compiler_sha256=sha(compiler_raw),
    vm_entries=0,native_entries=0,entries_by_role={"dms":{"vm":0,"native":0},"fs":{"vm":0,"native":0}},
    synthetic_kernel_acks=0,tests={},images={},compile_receipts={})
contexts={};images={}
ledger=gzip.open(OUT/"invocations.jsonl.gz","wt",encoding="utf-8")
phase="vm"
def record(value):ledger.write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n");ledger.flush()
class RecordedVM(suite_module.NamespaceDmsTests):
    def invoke_program(self,role,raw,work,capacity=256,steps=4000000):
        original=bytes(raw);pre=bytes(work)
        entry=dict(phase=phase,role=role,test_id=self.id(),input_hex=original.hex(),
                   pre_workspace_hex=pre.hex(),output_capacity=capacity,vm_step_budget=steps)
        report["vm_entries"]+=1;report["entries_by_role"][role]["vm"]+=1
        try:
            result=super().invoke_program(role,raw,work,capacity,steps)
            entry.update(returned=result[0],output_hex=result[2].hex(),post_workspace_hex=bytes(work).hex())
            return result
        except BaseException as error:
            entry.update(exception_class=type(error).__name__,exception=str(error),post_workspace_hex=bytes(work).hex());raise
        finally:record(entry)
    def primitive(self,c,output):
        before=len(c["syscalls"]);raw=super().primitive(c,output);assert len(c["syscalls"])==before+1
        report["synthetic_kernel_acks"]+=1
        record(dict(phase="synthetic_kernel",test_id=self.id(),source_hex=bytes(output).hex(),
                    ack_hex=raw.hex(),observation=c["syscalls"][-1],actual_syscalls_executed=0))
        return raw
libc=ctypes.CDLL(None,use_errno=True)
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
libc.mmap.restype=ctypes.c_void_p
libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int
libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap.restype=ctypes.c_int
class Guarded:
    def __init__(self,size,initial=b"",readonly=False):
        assert 0<=len(initial)<=size
        self.size=size;self.middle=(size+2*len(CANARY)+4095)&~4095
        self.total=self.middle+8192;self.base=None
        address=libc.mmap(None,self.total,0,0x22,-1,0)
        if address==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),"mmap")
        self.base=address;self.address=address+4096+len(CANARY)
        try:
            if libc.mprotect(address+4096,self.middle,3):raise OSError(ctypes.get_errno(),"mprotect RW")
            ctypes.memmove(self.address-len(CANARY),CANARY,len(CANARY))
            ctypes.memmove(self.address+size,CANARY,len(CANARY))
            if initial:ctypes.memmove(self.address,initial,len(initial))
            if readonly and libc.mprotect(address+4096,self.middle,1):raise OSError(ctypes.get_errno(),"mprotect RO")
        except BaseException:
            self.close();raise
    def read(self):return ctypes.string_at(self.address,self.size)
    def check(self):
        assert ctypes.string_at(self.address-len(CANARY),len(CANARY))==CANARY
        assert ctypes.string_at(self.address+self.size,len(CANARY))==CANARY
    def close(self):
        if self.base is not None:
            base=self.base;self.base=None
            if libc.munmap(base,self.total):raise OSError(ctypes.get_errno(),"munmap")

class Paired(RecordedVM):
    def invoke_program(self,role,raw,work,capacity=256,steps=4000000):
        pre=bytes(work);key=(role,id(work));mutation=None
        if key in contexts:
            held,buffer,prior_size,serial=contexts[key];assert held is work
            buffer.check();old=buffer.read()
            if len(pre)!=prior_size:
                mutation=dict(kind="fixture_resize_same_owned_workspace",prior_bytes=prior_size,next_bytes=len(pre),
                    prior_prefix_matches=pre[:min(len(pre),prior_size)]==old[:min(len(pre),prior_size)])
                assert mutation["prior_prefix_matches"]
                next_buffer=Guarded(len(pre),pre);buffer.close();buffer=next_buffer
            elif old!=pre:
                mutation=dict(kind="explicit_private_workspace_mutation_from_frozen_test",before_hex=old.hex(),after_hex=pre.hex())
                ctypes.memmove(buffer.address,pre,len(pre))
            contexts[key]=(work,buffer,len(pre),serial)
        else:
            buffer=Guarded(len(pre),pre);contexts[key]=(work,buffer,len(pre),len(contexts)+1)
        expected=super().invoke_program(role,raw,work,capacity,steps)
        original=bytes(raw);input_buffer=output_buffer=None
        try:
            input_buffer=Guarded(len(original),original,readonly=True);output_buffer=Guarded(capacity)
            started=time.monotonic_ns()
            actual=int(images[role]._entry(input_buffer.address,len(original),output_buffer.address,capacity,buffer.address,len(pre)))
            elapsed=time.monotonic_ns()-started
            report["native_entries"]+=1;report["entries_by_role"][role]["native"]+=1
            output=output_buffer.read();post=buffer.read()
            for item in (input_buffer,output_buffer,buffer):item.check()
            unchanged=input_buffer.read()==original
            record(dict(phase="paired_native",role=role,test_id=self.id(),entry=report["native_entries"],
                workspace_id=contexts[key][3],private_mutation=mutation,input_hex=original.hex(),pre_workspace_hex=pre.hex(),
                expected_return=expected[0],actual_return=actual,expected_output_hex=expected[2].hex(),actual_output_hex=output.hex(),
                expected_workspace_hex=bytes(work).hex(),actual_workspace_hex=post.hex(),
                guards={"input":True,"output":True,"workspace":True},source_unchanged=unchanged,source_mapping_readonly=True,elapsed_ns=elapsed))
            self.assertTrue(unchanged);self.assertEqual(actual,expected[0]);self.assertEqual(output,expected[2]);self.assertEqual(post,bytes(work))
            return expected
        finally:
            for item in (output_buffer,input_buffer):
                if item is not None:item.close()
def run_tests(cls,label):
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(cls);ids=[t.id() for t in suite]
    assert 0<len(ids)==len(set(ids))==EXPECTED_TESTS
    with (OUT/(label+".stdout.log")).open("w",encoding="utf-8") as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    value=dict(test_ids=ids,tests_loaded=len(ids),tests_run=result.testsRun,
        failures=[(t.id(),text) for t,text in result.failures],errors=[(t.id(),text) for t,text in result.errors],
        skipped=[(t.id(),reason) for t,reason in result.skipped],expected_failures=[(t.id(),text) for t,text in result.expectedFailures],
        unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
    value["passed"]=bool(result.wasSuccessful() and 0<result.testsRun==len(ids) and not value["skipped"] and not value["expected_failures"] and not value["unexpected_successes"])
    dump(OUT/(label+".json"),value);report["tests"][label]=value
    if not value["passed"]:print(json.dumps(dict(failed_group=label,result=value),sort_keys=True),flush=True)
    return value["passed"]
try:
    assert run_tests(RecordedVM,"vm"),"new VM semantics/protocol controls failed"
    directory=OUT/"compile";directory.mkdir()
    for role in ("fs","dms"):
        name="namespace-"+role+"-lifetime-r1";source=sources[role]
        produced,receipt=compile_stage(directory,name,compiler,source);actual=produced.read_bytes()
        assert receipt["input_sha256"]==receipt["source_sha256"]==sha(source)
        assert receipt["artifact_sha256"]==sha(compiler_raw) and receipt["produced_sha256"]==sha(actual)
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        request=json.loads((directory/(name+".request.json")).read_bytes())
        assert request["capacity"]==request["workspace_size"]==1<<20
        assert receipt["runner_sha256"]==sha(pathlib.Path(CHILD).read_bytes())
        assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
        report["compile_receipts"][role]=receipt
        images[role]=NativeHiaJsonImage(actual,sha(actual));assert images[role].image_sha256==sha(actual)
        report["images"][role]=dict(path=str(produced),bytes=len(actual),sha256=sha(actual),mode=stat.S_IMODE(produced.stat().st_mode))
    phase="paired_vm"
    assert run_tests(Paired,"paired"),"actual two-image VM/native full-byte differential failed"
    assert set(images)=={"dms","fs"} and all(x["native"]>0 for x in report["entries_by_role"].values())
    assert report["vm_entries"]==2*report["native_entries"]
    report["status"]="PASS"
except BaseException as error:
    report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc());traceback.print_exc()
finally:
    ledger.close()
    for held,buffer,prior_size,serial in contexts.values():buffer.close()
    contexts.clear()
    for image in images.values():image._mapping.close()
    after={path:dict(bytes=len(pathlib.Path(path).read_bytes()),mode=stat.S_IMODE(pathlib.Path(path).stat().st_mode),
                    sha256=sha(pathlib.Path(path).read_bytes())) for path in before}
    report.update(source_before=before,source_after=after,source_unchanged=before==after,
        ledger=dict(path=str(OUT/"invocations.jsonl.gz"),bytes=(OUT/"invocations.jsonl.gz").stat().st_size,
                    sha256=sha((OUT/"invocations.jsonl.gz").read_bytes())))
    image_checks={}
    for role,item in report["images"].items():
        p=pathlib.Path(item["path"])
        image_checks[role]=(p.is_file() and p.stat().st_size==item["bytes"] and stat.S_IMODE(p.stat().st_mode)==item["mode"] and sha(p.read_bytes())==item["sha256"])
    report["produced_images_unchanged"]=image_checks
    if before!=after or (report["status"]=="PASS" and (set(image_checks)!={"dms","fs"} or not all(image_checks.values()))):
        report["status"]="FAIL"
    dump(OUT/"result.json",report)
    print(json.dumps(dict(status=report["status"],scope=report["scope"],vm_entries=report["vm_entries"],native_entries=report["native_entries"],
        entries_by_role=report["entries_by_role"],synthetic_kernel_acks=report["synthetic_kernel_acks"],actual_physical_syscalls=0,
        tests={k:dict(tests_run=v["tests_run"],failures=len(v["failures"]),errors=len(v["errors"]),skipped=len(v["skipped"]),passed=v["passed"]) for k,v in report["tests"].items()},
        result_path=str(OUT/"result.json"),result_sha256=sha((OUT/"result.json").read_bytes())),sort_keys=True),flush=True)
raise SystemExit(0 if report["status"]=="PASS" else 1)
