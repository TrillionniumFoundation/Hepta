"""NEW inode policy VM/actual-image differential; synthetic FS ACKs are private controls.
The separate physical harness is required for actual FS-provider/fcntl evidence.
"""
import sys
sys.dont_write_bytecode=True
import ctypes,gzip,hashlib,importlib.util,json,os,pathlib,stat,struct,time,traceback,unittest
CONTEXT_PATH=pathlib.Path(os.environ["HIA_NAMESPACE_CI_CONTEXT"]).resolve()
CONTEXT_RAW=CONTEXT_PATH.read_bytes()
CONTEXT=json.loads(CONTEXT_RAW)
assert os.environ.get("GITHUB_ACTIONS")=="true"
ROOT=pathlib.Path(CONTEXT["base"])
NS=pathlib.Path(CONTEXT["namespace_working"]).parent;TREE=pathlib.Path(CONTEXT["namespace_working"]);DEV=pathlib.Path(CONTEXT["namespace_evidence"])
REF=pathlib.Path(CONTEXT["reference"]);OUT=DEV/"validation-r1"
CANARY=bytes(range(192,224))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def dump(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
generation=json.loads((DEV/"generation-r1/result.json").read_bytes())
assert generation["status"]=="GENERATED" and generation["source_unchanged"]
OUT.mkdir(mode=0o700,exist_ok=False);(OUT/"source").mkdir()
(OUT/"source/runner.py").write_bytes(pathlib.Path(__file__).read_bytes())
sys.path.insert(0,str(REF))
before={}
def pin(path):
    path=pathlib.Path(path).resolve();raw=path.read_bytes()
    row=dict(bytes=len(raw),mode=stat.S_IMODE(path.stat().st_mode),sha256=sha(raw))
    if str(path) in before:assert before[str(path)]==row
    before[str(path)]=row
    return raw
def load(name,path):
    raw=pin(path);spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    exec(compile(raw,str(path),"exec"),module.__dict__)
    return module
for name in ("generate_hia_agent_namespace_store","generate_hia_agent_namespace_objects","generate_hia_agent_namespace_inode"):
    load("tools."+name,TREE/"tools"/(name+".py"))
suite_module=load("tests.namespace_inode_r2_development",TREE/"tests/test_hia_agent_namespace_inode.py")
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
for row in generation["files"]:
    raw=pin(row["path"]);assert len(raw)==row["bytes"] and sha(raw)==row["sha256"]
source_path=TREE/"examples/hia_bootstrap/agent_namespace_inode_r2.hiaasm"
source=pin(source_path);assert sha(source)==generation["generated"]["sha256"]
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
report=dict(status="INCOMPLETE",scope="NEW_INODE_R2_SYNTHETIC_PROTOCOL_VM_NATIVE_COMPONENT_NOT_PHYSICAL_STORE",whole_store_closed=False,
    synthetic_FS_frames_do_not_authenticate_sources=True,physical_provider_executed_here=False,source_sha256=sha(source),reference_commit="0ef9541b2fc12f4b01ab5078b05d0b304cfa90f5",
    compiler_sha256=sha(compiler_raw),vm_entries=0,native_entries=0,tests={})
contexts={};image=None
ledger=gzip.open(OUT/"invocations.jsonl.gz","wt",encoding="utf-8")
phase="vm"
class RecordedVM(suite_module.NamespaceInodeOwnerTests):
    def invoke(self,raw,work,capacity=256,steps=4000000):
        original=bytes(raw);pre=bytes(work)
        record=dict(phase=phase,test_id=self.id(),input_hex=original.hex(),pre_workspace_hex=pre.hex(),
                    output_capacity=capacity,vm_step_budget=steps)
        report["vm_entries"]+=1
        try:
            result=super().invoke(raw,work,capacity,steps)
            record.update(returned=result[0],output_hex=result[2].hex(),post_workspace_hex=bytes(work).hex())
            return result
        except BaseException as error:
            record.update(exception_class=type(error).__name__,exception=str(error),post_workspace_hex=bytes(work).hex())
            raise
        finally:
            ledger.write(json.dumps(record,sort_keys=True,separators=(",",":"))+"\n");ledger.flush()

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
    def invoke(self,raw,work,capacity=256,steps=4000000):
        pre=bytes(work);key=id(work);mutation=None
        if key in contexts:
            held,buffer,prior_size,serial=contexts[key]
            assert held is work
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
            buffer=Guarded(len(pre),pre)
            contexts[key]=(work,buffer,len(pre),len(contexts)+1)
        expected=super().invoke(raw,work,capacity,steps)
        original=bytes(raw);input_buffer=output_buffer=None
        try:
            input_buffer=Guarded(len(original),original,readonly=True)
            output_buffer=Guarded(capacity)
            started=time.monotonic_ns()
            actual=int(image._entry(input_buffer.address,len(original),output_buffer.address,capacity,buffer.address,len(pre)))
            elapsed=time.monotonic_ns()-started;report["native_entries"]+=1
            output=output_buffer.read();post=buffer.read()
            for item in (input_buffer,output_buffer,buffer):item.check()
            guards=dict(input=True,output=True,workspace=True)
            unchanged=input_buffer.read()==original
            row=dict(phase="paired_native",test_id=self.id(),entry=report["native_entries"],workspace_id=contexts[key][3],
                private_mutation=mutation,input_hex=original.hex(),pre_workspace_hex=pre.hex(),
                expected_return=expected[0],actual_return=actual,expected_output_hex=expected[2].hex(),actual_output_hex=output.hex(),
                expected_workspace_hex=bytes(work).hex(),actual_workspace_hex=post.hex(),guards=guards,
                source_unchanged=unchanged,source_mapping_readonly=True,elapsed_ns=elapsed)
            ledger.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n");ledger.flush()
            self.assertTrue(unchanged)
            self.assertEqual(actual,expected[0]);self.assertEqual(output,expected[2]);self.assertEqual(post,bytes(work))
            return expected
        finally:
            for item in (output_buffer,input_buffer):
                if item is not None:item.close()

def run_tests(cls,label):
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(cls)
    ids=[t.id() for t in suite];assert 0<len(ids)==len(set(ids))==18
    with (OUT/(label+".stdout.log")).open("w",encoding="utf-8") as stream:
        result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    value=dict(test_ids=ids,tests_loaded=len(ids),tests_run=result.testsRun,
        failures=[(t.id(),text) for t,text in result.failures],errors=[(t.id(),text) for t,text in result.errors],
        skipped=[(t.id(),reason) for t,reason in result.skipped],
        expected_failures=[(t.id(),text) for t,text in result.expectedFailures],
        unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
    value["passed"]=bool(result.wasSuccessful() and 0<result.testsRun==len(ids) and not value["skipped"] and not value["expected_failures"] and not value["unexpected_successes"])
    dump(OUT/(label+".json"),value);report["tests"][label]=value
    if not value["passed"]:print(json.dumps(dict(failed_group=label,result=value),sort_keys=True),flush=True)
    return value["passed"]

try:
    assert run_tests(RecordedVM,"vm"),"VM controls failed; actual B3 phase not started"
    directory=OUT/"compile";directory.mkdir()
    produced,receipt=compile_stage(directory,"namespace-inode-r2",compiler,source)
    actual=produced.read_bytes()
    assert receipt["input_sha256"]==receipt["source_sha256"]==sha(source)
    assert receipt["artifact_sha256"]==sha(compiler_raw)
    assert receipt["produced_sha256"]==sha(actual)
    assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
    compile_request=json.loads((directory/"namespace-inode-r2.request.json").read_bytes())
    assert compile_request["capacity"]==compile_request["workspace_size"]==1<<20
    assert receipt["runner_sha256"]==sha(pathlib.Path(CHILD).read_bytes())
    assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
    report["compile_receipt"]=receipt
    image=NativeHiaJsonImage(actual,sha(actual));assert image.image_sha256==sha(actual)
    report["image"]=dict(path=str(produced),bytes=len(actual),sha256=sha(actual),mode=stat.S_IMODE(produced.stat().st_mode))
    phase="paired_vm"
    assert run_tests(Paired,"paired"),"actual B3 / VM full-byte replay failed"
    assert report["native_entries"]>0
    report["status"]="PASS"
except BaseException as error:
    report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    ledger.close()
    for held,buffer,prior_size,serial in contexts.values():buffer.close()
    contexts.clear()
    if image is not None:image._mapping.close()
    after={path:dict(bytes=len(pathlib.Path(path).read_bytes()),mode=stat.S_IMODE(pathlib.Path(path).stat().st_mode),sha256=sha(pathlib.Path(path).read_bytes())) for path in before}
    report.update(source_before=before,source_after=after,source_unchanged=before==after,
        ledger=dict(path=str(OUT/"invocations.jsonl.gz"),bytes=(OUT/"invocations.jsonl.gz").stat().st_size,sha256=sha((OUT/"invocations.jsonl.gz").read_bytes())))
    if "image" in report:
        item=report["image"];p=pathlib.Path(item["path"])
        report["produced_image_before_after_equal"]=(p.is_file() and p.stat().st_size==item["bytes"] and stat.S_IMODE(p.stat().st_mode)==item["mode"] and sha(p.read_bytes())==item["sha256"])
    else:
        report["produced_image_before_after_equal"]=None
    if before!=after or (report["status"]=="PASS" and report["produced_image_before_after_equal"] is not True):report["status"]="FAIL"
    dump(OUT/"result.json",report)
    print(json.dumps(dict(status=report["status"],scope=report["scope"],vm_entries=report["vm_entries"],native_entries=report["native_entries"],
        tests={k:dict(tests_run=v["tests_run"],failures=len(v["failures"]),errors=len(v["errors"]),skipped=len(v["skipped"]),passed=v["passed"]) for k,v in report["tests"].items()},
        result_path=str(OUT/"result.json"),result_sha256=sha((OUT/"result.json").read_bytes())),sort_keys=True),flush=True)
raise SystemExit(0 if report["status"]=="PASS" else 1)
