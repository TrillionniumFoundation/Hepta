"""New exact-byte helper proof: old/new VM and real old/new native processes.

The reference _Machine is unchanged. Expected program-bounds traps use actual
fresh child SIGILL results and full MAP_SHARED before/after operands, so partial
writes survive the child's abort and remain comparable. This is a development
leaf, not a Store, cold, or original 42-case qualification.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,ast,ctypes,gzip,hashlib,importlib.util,json,os,resource,signal,stat,struct,time,traceback
from pathlib import Path
B3="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
TRANSFORM="b4614d75cb79f8c8a3242cadb390c1c04dd8efa1851f16c91905c561dd8c4a2c"
AUTHOR="b58362db22db3e3dadc860283779f8e37d58925d5023f7362f58755faea62169"
CORPUS="211e43dddb7cc2505caa5f61b8e91bcf93014cb70ad67a9e99342c6438e734e3"
VALUES="7c3f0299291cf4b99d5c2296351dcfd5e471507d4903ab9da171420c126c5c50"
OBJECTS="2320a0363d312f1f07b48cc370f06ac7dbaedefa28437c28230fff6fba4dc3de"
RUNTIME="ce39be78627f253447f1d4e4b3272ba6689c594c31b22e3be204b1fcfea2ca56"
MASK=(1<<64)-1
READY=int.from_bytes(b"HIA8RD01","little");RETURN=int.from_bytes(b"HIA8RT01","little")
CANARY=bytes(range(160,176))
def sha(raw):return hashlib.sha256(raw).hexdigest()
def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def main():
    resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    started=time.monotonic_ns();parent_start=time.process_time_ns()
    children_start=resource.getrusage(resource.RUSAGE_CHILDREN)
    def timeout(*_):raise TimeoutError("exact-byte complete leaf original180wall")
    signal.signal(signal.SIGALRM,timeout);signal.setitimer(signal.ITIMER_REAL,180)
    parser=argparse.ArgumentParser();parser.add_argument("--context",type=Path,required=True)
    parser.add_argument("--inputs",type=Path,required=True)
    args=parser.parse_args();assert sys.version_info[:3]==(3,12,14)
    inputs=args.inputs.resolve();pins={};images={};report={}
    def pin(path,expected=None):
        path=Path(path).absolute();info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
        raw=path.read_bytes();row=dict(path=str(path),bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode))
        if expected is not None:assert row["sha256"]==expected,(str(path),row["sha256"],expected)
        if str(path) in pins:assert pins[str(path)]==row
        pins[str(path)]=row;return raw
    def load(name,path,expected):
        raw=pin(path,expected);spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module
        exec(compile(raw,str(path),"exec"),module.__dict__);return module
    context=json.loads(pin(args.context));ref=Path(context["reference"])
    out=Path(context["output"])/"namespace-exact-byte-unroll-r1";out.mkdir(parents=True,exist_ok=False)
    report=dict(schema="hia.namespace.exact-byte-unroll.fresh-boundary-proof.v1",status="INCOMPLETE",
        source_only_predecessor=True,actual_compiles=0,VM_old=0,VM_new=0,native_old=0,native_new=0,
        cases_completed=0,returned_cases=0,trapped_cases=0,steps_old=0,steps_new=0,
        ordinary_Store_closed=False,old42_qualification_reexecuted=False,old42_failure_unchanged=True,
        reference_VM_modified=False,arbitrary_fuel_equivalence_claimed=False,
        complete_return_and_operand_comparison=True,partial_native_writes_observed=True,
        actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
            address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall=180))
    save(out/"summary.json",report)
    cas=out/"cas";cas.mkdir()
    def store(raw):
        raw=bytes(raw);digest=sha(raw);path=cas/digest
        if not path.exists():
            with path.open("xb") as stream:stream.write(raw)
        assert path.read_bytes()==raw
        return dict(path=str(path),bytes=len(raw),sha256=digest)
    libc=ctypes.CDLL(None,use_errno=True)
    libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
    libc.mmap.restype=ctypes.c_void_p
    libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];libc.mprotect.restype=ctypes.c_int
    libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];libc.munmap.restype=ctypes.c_int
    libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
    libc.prctl.restype=ctypes.c_int
    class Shared:
        def __init__(self,raw,readonly=False):
            self.size=len(raw);self.middle=(self.size+32+4095)&~4095;self.total=self.middle+8192;self.raw=None
            address=libc.mmap(None,self.total,0,0x21,-1,0)
            if address==ctypes.c_void_p(-1).value:raise OSError(ctypes.get_errno(),"MAP_SHARED mmap")
            self.raw=address;self.base=address+4096;self.address=address+4112
            try:
                if libc.mprotect(self.base,self.middle,3):raise OSError(ctypes.get_errno(),"mprotect RW")
                ctypes.memmove(self.base,CANARY,16)
                if raw:ctypes.memmove(self.address,raw,len(raw))
                ctypes.memmove(self.address+self.size,CANARY,16)
                if readonly and libc.mprotect(self.base,self.middle,1):raise OSError(ctypes.get_errno(),"mprotect RO")
            except BaseException:
                self.close();raise
        def read(self):
            assert ctypes.string_at(self.base,16)==CANARY
            assert ctypes.string_at(self.address+self.size,16)==CANARY
            return ctypes.string_at(self.address,self.size)
        def close(self):
            if self.raw is not None:
                address=self.raw;self.raw=None
                if libc.munmap(address,self.total):raise OSError(ctypes.get_errno(),"munmap")
    try:
        pin(__file__);sys.path.insert(0,str(ref))
        load("tools.generate_hia_agent_namespace_store",inputs/"namespace-values.py",VALUES)
        load("tools.generate_hia_agent_namespace_objects",inputs/"namespace-objects.py",OBJECTS)
        rewrite=load("tools.hia_namespace_exact_byte_helpers",inputs/"exact-byte-helpers.py",TRANSFORM)
        author=load("namespace_exact_byte_author",inputs/"exact-byte-probe.py",AUTHOR)
        values_module=sys.modules["tools.generate_hia_agent_namespace_store"]
        assert values_module.VALUES.count(rewrite.OLD)==1
        from hepta.hia_agent_assembly import render_assembly,assemble_program
        from hepta.hia_program import verify_program
        import hepta.hia_program_runtime as runtime
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        import tools.qualify_hia_selfhost as qualifier
        assert Path(runtime.__file__).resolve()==ref/"hepta/hia_program_runtime.py"
        pin(runtime.__file__,RUNTIME)
        assert Path(qualifier.__file__).resolve()==ref/"tools/qualify_hia_selfhost.py"
        assert Path(qualifier.CHILD).resolve()==ref/"tools/hia_selfhost_child.py"
        compiler=Path(context["compiler"]);raw_compiler=pin(compiler,B3);assert len(raw_compiler)==669556
        pin(qualifier.CHILD)
        corpus_raw=pin(inputs/"boundary-corpus.json",CORPUS);corpus=json.loads(corpus_raw)
        assert corpus["counts"]["cases"]==len(corpus["cases"])==564
        assert corpus["counts"]["trap_cases"]==379 and corpus["counts"]["returned_cases"]==185
        assert len({row["label"] for row in corpus["cases"]})==564
        programs={};documents={};compiled={}
        for label,optimized in (("old",False),("new",True)):
            directory=out/label;directory.mkdir()
            dsl=author.source_program(optimized);(directory/"authoring.dsl.py").write_text(dsl)
            doc=author.document(optimized);documents[label]=doc
            docraw=(json.dumps(doc,sort_keys=True,separators=(",",":"))+"\n").encode()
            (directory/"document.json").write_bytes(docraw)
            profile=dict(functions=len(doc["functions"]),blocks=sum(len(f["blocks"]) for f in doc["functions"]),
                ops=sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]),
                max_blocks=max(len(f["blocks"]) for f in doc["functions"]),
                max_params=max(len(b["params"]) for f in doc["functions"] for b in f["blocks"]))
            save(directory/"profile.json",profile)
            assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
            assert profile["max_blocks"]<=256 and profile["max_params"]<=16
            source=render_assembly(doc).encode();source_path=directory/"probe.hiaasm";source_path.write_bytes(source)
            programs[label]=assemble_program(source)
            compile_dir=directory/"compile";compile_dir.mkdir()
            image_path,receipt=qualifier.compile_stage(compile_dir,"exact-byte-"+label,compiler,source)
            image_bytes=pin(image_path)
            assert receipt["source_sha256"]==receipt["input_sha256"]==sha(source)
            assert receipt["artifact_sha256"]==receipt["image_sha256"]==B3
            assert receipt["produced_sha256"]==sha(image_bytes) and receipt["produced_bytes"]==len(image_bytes)
            assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
            assert receipt["source_unchanged"] and not receipt["forbidden_compiler_modules_loaded"]
            assert receipt["runner_sha256"]==sha(pin(qualifier.CHILD))
            request=json.loads((compile_dir/("exact-byte-"+label+".request.json")).read_bytes())
            assert request["capacity"]==request["workspace_size"]==1<<20
            assert 0<len(image_bytes)<=1<<20
            image=NativeHiaJsonImage(image_bytes,sha(image_bytes));assert image.image_sha256==sha(image_bytes)
            images[label]=image;report["actual_compiles"]+=1
            compiled[label]=dict(profile=profile,source=dict(path=str(source_path),bytes=len(source),sha256=sha(source)),
                image=dict(path=str(image_path),bytes=len(image_bytes),sha256=sha(image_bytes)),receipt=receipt)
            report["compiled"]=compiled;save(out/"summary.json",report)
        assert documents["old"]["functions"][0]==documents["new"]["functions"][0]
        assert set(documents["old"])==set(documents["new"])
        assert all(documents["old"][k]==documents["new"][k] for k in documents["old"] if k!="functions")
        assert [f["name"] for f in documents["old"]["functions"]]==["f0","f1","f2","f3"]
        assert [f["name"] for f in documents["new"]["functions"]]==["f0","f1","f2","f3"]
        for a,b in zip(documents["old"]["functions"],documents["new"]["functions"],strict=True):
            assert {k:v for k,v in a.items() if k!="blocks"}=={k:v for k,v in b.items() if k!="blocks"}
        def uint64(text):
            assert type(text) is str and text and text.isascii() and text.isdecimal()
            assert text=="0" or text[0]!="0"
            value=int(text);assert 0<=value<=MASK and str(value)==text
            return value
        def operand_bytes(row):
            n=row["target_bytes"];seed=row["pattern_seed"]
            assert type(n) is int and 0<=n<=4096 and type(seed) is int and 0<=seed<=255
            target=bytes((seed+i*29+(i>>3)*17)&255 for i in range(n))
            source=target if row["operation"]==1 else bytes(range(31))
            work=target if row["operation"] in (2,3) else bytes(range(24))
            control=struct.pack("<3Q",row["operation"],uint64(row["index_decimal"]),uint64(row["value_decimal"]))+bytes(range(40))
            return source,control,work
        def mathematical(row,buffers):
            source,output,work=buffers;op=row["operation"];index=uint64(row["index_decimal"]);value=uint64(row["value_decimal"])
            output=bytearray(output);work=bytearray(work)
            if op not in (1,2,3):return dict(status="returned",returncode=1),source,bytes(output),bytes(work)
            target=source if op==1 else work
            prefix=0 if index>len(target) else min(8,len(target)-index)
            if op==3:
                wire=value.to_bytes(8,"little")
                if prefix:work[index:index+prefix]=wire[:prefix]
                # Avoid Python slice insertion semantics for a huge index with
                # a zero prefix: it must leave the exact original extent.
                assert len(work)==len(buffers[2])
            if prefix<8:
                return dict(status="trapped",code="bounds"),source,bytes(output),bytes(work)
            result=int.from_bytes(bytes(target[index:index+8]),"little") if op in (1,2) else 0
            output[24:32]=result.to_bytes(8,"little")
            return dict(status="returned",returncode=0),source,bytes(output),bytes(work)
        def vm(label,buffers):
            owners=[runtime._Owner(-i-1,bytearray(raw)) for i,raw in enumerate(buffers)]
            machine=runtime._Machine(programs[label],4000000,32<<20,None,64)
            try:
                returned=machine.invoke(programs[label].as_dict()["functions"][0],
                    [runtime._View(owners[0],False),runtime._View(owners[1],True),runtime._View(owners[2],True)])[0]
                status=dict(status="returned",returncode=returned)
            except runtime.HIAProgramTrap as error:
                status=dict(status="trapped",code=error.code,message=str(error))
            report["VM_"+label]+=1;report["steps_"+label]+=machine.steps
            return status,tuple(bytes(owner.data) for owner in owners),machine.steps,machine.resources()
        def native(label,buffers,case,index):
            allocations=[];primary=None;readfd=writefd=None;pid=None;waited=False;observed=None
            start=time.monotonic_ns()
            stderr_path=case/(label+".native.stderr");stdout_path=case/(label+".native.stdout")
            try:
                for position,raw in enumerate(buffers):
                    allocations.append(Shared(raw,readonly=position==0))
                readfd,writefd=os.pipe();parent_pid=os.getpid()
                with stderr_path.open("xb") as error_stream,stdout_path.open("xb") as output_stream:
                    pid=os.fork()
                    if pid==0:
                        try:
                            os.close(readfd);os.setsid()
                            if libc.prctl(1,signal.SIGKILL,0,0,0):raise OSError(ctypes.get_errno(),"PDEATHSIG")
                            if os.getppid()!=parent_pid:os._exit(125)
                            os.dup2(error_stream.fileno(),2);os.dup2(output_stream.fileno(),1)
                            c=resource.getrlimit(resource.RLIMIT_CPU);a=resource.getrlimit(resource.RLIMIT_AS);z=resource.getrlimit(resource.RLIMIT_CORE)
                            ready=struct.pack("<12Q",READY,os.getpid(),os.getppid(),*c,*a,*z,index+1,0 if label=="old" else 1,0)
                            assert os.write(writefd,ready)==len(ready)
                            s,o,w=allocations
                            result=int(images[label]._entry(s.address,s.size,o.address,o.size,w.address,w.size))
                            terminal=struct.pack("<2Q",RETURN,result)
                            assert os.write(writefd,terminal)==len(terminal)
                            os._exit(0)
                        except BaseException:
                            os.write(2,traceback.format_exc().encode("utf-8","replace"));os._exit(125)
                    os.close(writefd);writefd=None
                    while True:
                        found,status,usage=os.wait4(pid,os.WNOHANG)
                        if found:
                            assert found==pid;waited=True;observed=(status,usage);break
                        if time.monotonic_ns()-started>=180000000000:raise TimeoutError("exact-byte child original180wall")
                        time.sleep(.001)
                payload=bytearray()
                while True:
                    chunk=os.read(readfd,256)
                    if not chunk:break
                    payload.extend(chunk);assert len(payload)<=112
                assert len(payload) in (96,112)
                h=struct.unpack_from("<12Q",payload)
                assert h==(READY,pid,parent_pid,90,90,1<<30,1<<30,0,0,index+1,0 if label=="old" else 1,0)
                report["native_"+label]+=1
                status,usage=observed
                if os.WIFEXITED(status):
                    assert os.WEXITSTATUS(status)==0 and len(payload)==112
                    marker,result=struct.unpack_from("<2Q",payload,96);assert marker==RETURN
                    outcome=dict(status="returned",returncode=result)
                else:
                    assert os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGILL and len(payload)==96
                    outcome=dict(status="trapped",code="bounds")
                actual=tuple(buffer.read() for buffer in allocations)
                assert actual[0]==buffers[0]
                assert stdout_path.read_bytes()==b""
                record=dict(pid=pid,parent_pid=parent_pid,wait_status=status,returncode=os.waitstatus_to_exitcode(status),
                    actual_limits=dict(cpu=[h[3],h[4]],address=[h[5],h[6]],core=[h[7],h[8]]),
                    process_ready_bytes=store(payload),elapsed_ns=time.monotonic_ns()-start,
                    child_usage=dict(user=usage.ru_utime,system=usage.ru_stime,maxrss_kib=usage.ru_maxrss),
                    outcome=outcome,complete_buffers=[store(raw) for raw in actual],guards=True,
                    stderr=dict(path=str(stderr_path),bytes=stderr_path.stat().st_size,sha256=sha(stderr_path.read_bytes())),
                    stdout=dict(path=str(stdout_path),bytes=0,sha256=sha(b"")),source_unchanged=True)
                save(case/(label+".native.json"),record)
                return outcome,actual,record
            except BaseException as error:
                primary=error;raise
            finally:
                failures=[]
                if pid is not None and not waited:
                    try:
                        try:os.killpg(pid,signal.SIGKILL)
                        except ProcessLookupError:os.kill(pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    except BaseException as error:failures.append(error)
                    try:
                        found,status,usage=os.wait4(pid,0);assert found==pid;waited=True
                        save(case/(label+".aborted-child.json"),dict(pid=pid,wait_status=status,
                            returncode=os.waitstatus_to_exitcode(status),user=usage.ru_utime,system=usage.ru_stime))
                    except BaseException as error:failures.append(error)
                for fd in (readfd,writefd):
                    if fd is not None:
                        try:os.close(fd)
                        except BaseException as error:failures.append(error)
                for buffer in reversed(allocations):
                    try:buffer.close()
                    except BaseException as error:failures.append(error)
                if failures:
                    if primary is not None:
                        for error in failures:primary.add_note("native child cleanup: "+repr(error))
                    else:
                        for error in failures[1:]:failures[0].add_note(repr(error))
                        raise failures[0]
        with gzip.open(out/"all-cases.jsonl.gz","wt",encoding="utf-8",compresslevel=1) as ledger:
            for index,row in enumerate(corpus["cases"]):
                case=out/"cases"/("%04d"%index);case.mkdir(parents=True)
                buffers=operand_bytes(row)
                before=dict(index=index,case=row,buffers=[store(raw) for raw in buffers])
                save(case/"before.json",before);save(out/"frontier.json",dict(index=index,label=row["label"],stage="BEFORE_OLD_VM"))
                old,oldbytes,oldsteps,oldresources=vm("old",buffers)
                save(out/"frontier.json",dict(index=index,label=row["label"],stage="BEFORE_NEW_VM",old_steps=oldsteps))
                new,newbytes,newsteps,newresources=vm("new",buffers)
                assert old==new and oldbytes==newbytes and oldresources==newresources
                assert 0<newsteps<=oldsteps<=4000000
                expected,es,eo,ew=mathematical(row,buffers)
                assert {k:v for k,v in old.items() if k!="message"}==expected
                assert oldbytes==(es,eo,ew)
                natives={}
                for label in ("old","new"):
                    save(out/"frontier.json",dict(index=index,label=row["label"],stage="BEFORE_"+label.upper()+"_NATIVE"))
                    result,actual,record=native(label,buffers,case,index)
                    assert result==expected and actual==oldbytes
                    natives[label]=record
                report["cases_completed"]+=1;report["returned_cases" if expected["status"]=="returned" else "trapped_cases"]+=1
                row=dict(index=index,case=row,old_VM=old,new_VM=new,old_steps=oldsteps,new_steps=newsteps,
                    old_resources=oldresources,new_resources=newresources,full_bytes=[store(raw) for raw in oldbytes],
                    native=natives,complete_equal=True,no_masks=True)
                ledger.write(json.dumps(row,sort_keys=True,separators=(",",":"))+"\n");ledger.flush()
                save(case/"result.json",row);save(out/"summary.json",report)
        assert report["cases_completed"]==564 and report["returned_cases"]==185 and report["trapped_cases"]==379
        assert report["VM_old"]==report["VM_new"]==report["native_old"]==report["native_new"]==564
        assert report["steps_new"]<report["steps_old"]
        for module in tuple(sys.modules.values()):
            filename=getattr(module,"__file__",None)
            if filename:
                path=Path(filename).resolve()
                if path.is_relative_to(ref) and path.suffix==".py":pin(path)
        report["status"]="PASS_DEVELOPMENT_BOUNDARY_ONLY"
    except BaseException as error:
        report.update(status="FAIL",error_class=type(error).__name__,error=str(error),traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        cleanup=[]
        for label,image in images.items():
            try:image._mapping.close()
            except BaseException as error:cleanup.append(dict(label=label,error=repr(error)))
        after={};changes=[]
        for name,before in pins.items():
            try:
                path=Path(name);info=path.lstat();assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
                raw=path.read_bytes();now=dict(path=name,bytes=len(raw),sha256=sha(raw),mode=stat.S_IMODE(info.st_mode));after[name]=now
                if now!=before:changes.append(name)
            except BaseException as error:changes.append(dict(path=name,error=repr(error)))
        children=resource.getrusage(resource.RUSAGE_CHILDREN)
        parent_ns=time.process_time_ns()-parent_start
        child_seconds=children.ru_utime+children.ru_stime-children_start.ru_utime-children_start.ru_stime
        total_CPU=parent_ns/1e9+child_seconds;wall_ns=time.monotonic_ns()-started
        report.update(source_before=pins,source_after=after,source_pins_unchanged=not changes,
            source_changes=changes,cleanup_errors=cleanup,parent_CPU_ns=parent_ns,reaped_child_CPU_seconds=child_seconds,
            full_process_tree_CPU_seconds=total_CPU,wall_ns=wall_ns,within_original_tree90=0<=total_CPU<90,
            within_original_wall180=0<=wall_ns<180000000000)
        if changes or cleanup or not report["within_original_tree90"] or not report["within_original_wall180"]:report["status"]="FAIL"
        save(out/"summary.json",report);signal.setitimer(signal.ITIMER_REAL,0)
        print("HIA_NAMESPACE_EXACT_BYTE_BOUNDARY "+json.dumps(report,sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS_DEVELOPMENT_BOUNDARY_ONLY" else 1
if __name__=="__main__":raise SystemExit(main())
