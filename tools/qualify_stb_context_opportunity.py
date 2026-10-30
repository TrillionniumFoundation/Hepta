"""Prospective guarded specialization of real stb_divide with strong controls.

Development runs never consume the registered holdout seeds. Formal runs require
an exact clean registered HEAD, a matching bound source inventory and immutable
protocol. All process images and DSOs are loaded from sealed memfds on Linux.
"""
from __future__ import annotations
import argparse, ctypes, fcntl, hashlib, json, os, platform, random, shutil, copy
import subprocess, sys, time, traceback, signal, threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from hepta.c_migrate import migrate_c_project
from hepta.hia_program_source import lower_source
from hepta.hia_program import execute_program, verify_program
from hepta.hia_context_specialization import selected_leaf, propose_context_specialization, verify_context_specialization
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_scalar_lowering_check import verify_scalar_lowering

CLANG="/usr/bin/clang-20"
LLD="/usr/lib/llvm-20/bin/ld.lld"
RUSTC="/workspace/scratch/cd43ab608057/toolchains/rust-1.90.0/bin/rustc"
PROTOCOL=ROOT/"experiments/stb_context_opportunity/PROTOCOL.json"
ARM_MACROS={"clang-stb-lto":"ARM_STB", "gcc-stb-lto":"ARM_STB",
    "clang-libdivide-scalar":"ARM_LIB_FULL", "clang-libdivide-branchfree":"ARM_LIB_FREE",
    "clang-libdivide-avx2":"ARM_LIB_AVX2", "clang-libdivide-avx2-free":"ARM_LIB_AVX2_FREE",
    "clang-libdivide-avx512":"ARM_LIB_AVX512", "clang-libdivide-avx512-free":"ARM_LIB_AVX512_FREE",
    "gcc-libdivide-scalar":"ARM_LIB_FULL", "gcc-libdivide-branchfree":"ARM_LIB_FREE",
    "gcc-libdivide-avx2":"ARM_LIB_AVX2", "gcc-libdivide-avx2-free":"ARM_LIB_AVX2_FREE",
    "gcc-libdivide-avx512":"ARM_LIB_AVX512", "gcc-libdivide-avx512-free":"ARM_LIB_AVX512_FREE"}

def digest(data):return hashlib.sha256(data).hexdigest()
def write(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def file_identity(path):
    path=Path(path);data=path.read_bytes()
    return {"path":str(path),"bytes":len(data),"sha256":digest(data),"git_blob":hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()}
def run(argv,work,processes,*,timeout=120,pass_fds=(),env_extra=None,expected=0):
    if threading.active_count()!=1 or signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL:
        raise RuntimeError("single process owner required")
    env=os.environ.copy();env["TMPDIR"]=str(work);env["PYTHONDONTWRITEBYTECODE"]="1"
    env.update(env_extra or {})
    begin=time.monotonic_ns();command=[str(v) for v in argv]
    row={"argv":command,"returncode":None,"status":"starting","pass_fds":list(pass_fds)}
    processes.append(row)
    process=None
    try:
        process=subprocess.Popen(command,cwd=work,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            text=True,pass_fds=pass_fds,start_new_session=True)
        row.update(pid=process.pid,pgid=process.pid)
        try:
            stdout,stderr=process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Never reap before group signalling: waitid(WNOWAIT) retains the
            # child PID, so it cannot be reused for a different process group.
            os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            stdout,stderr=process.communicate(timeout=5)
            row.update(status="timed_out",stdout=stdout,stderr=stderr,returncode=process.returncode,
                owned_group_signalled=True,leader_reaped=True)
            raise TimeoutError("bounded child process timed out")
        row.update(status="exited",returncode=process.returncode,stdout=stdout,stderr=stderr,
            leader_reaped=True)
        if expected is not None and process.returncode!=expected:
            raise RuntimeError("child failed: "+json.dumps(row))
        return row
    except BaseException as error:
        row["error"]={"type":type(error).__name__,"message":str(error)}
        raise
    finally:
        row["wall_ns"]=time.monotonic_ns()-begin


def seal(path):
    data=Path(path).read_bytes();fd=os.memfd_create(Path(path).name,os.MFD_ALLOW_SEALING)
    try:
        offset=0
        while offset<len(data):offset+=os.write(fd,data[offset:])
        os.fchmod(fd,0o500)
        flags=getattr(fcntl,"F_SEAL_SEAL",1)|getattr(fcntl,"F_SEAL_SHRINK",2)|getattr(fcntl,"F_SEAL_GROW",4)|getattr(fcntl,"F_SEAL_WRITE",8)
        fcntl.fcntl(fd,getattr(fcntl,"F_ADD_SEALS",1033),flags)
        if fcntl.fcntl(fd,getattr(fcntl,"F_GET_SEALS",1034))!=flags:raise RuntimeError("incomplete image sealing")
        if digest(os.pread(fd,len(data),0))!=digest(data):raise RuntimeError("sealed bytes mismatch")
        return fd
    except BaseException:os.close(fd);raise

def bound_source():
    paths=[p for folder in ("hepta","tools") for p in (ROOT/folder).glob("*.py")]
    paths += [ROOT/"tools/fixtures"/f for f in ("stb_context_batch.c","stb_context_batch.rs","stb_context_host.c")]
    paths += [p for folder in ("stb_divide","libdivide_5_2_0")
        for p in (ROOT/"tests/fixtures/c_migration"/folder).glob("*") if p.is_file()]
    paths += [PROTOCOL]
    rows=[]
    for p in sorted(paths):
        r=file_identity(p);r["path"]=p.relative_to(ROOT).as_posix();rows.append(r)
    return {"scope":"all materialized Python implementation/tools plus the complete selected batch/upstream/protocol dependencies; not all historical evidence files",
        "files":rows,"sha256":digest(json.dumps(rows,sort_keys=True,separators=(",",":")).encode())}

def migrate(work,processes):
    fixture=ROOT/"tests/fixtures/c_migration/stb_divide"
    metadata=json.loads((fixture/"UPSTREAM.json").read_text())
    if metadata["commit"]!="003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5" or metadata["source_modifications"]:raise ValueError("upstream pin changed")
    for row in metadata["files"]:
        actual=file_identity(fixture/row["local_path"])
        if any(actual[k]!=row[k] for k in ("sha256","git_blob","bytes")):raise ValueError("upstream byte mismatch")
    for filename in ("stb_divide.h","implementation.c"):(work/filename).write_bytes((fixture/filename).read_bytes())
    database=work/"compile_commands.json"
    write(database,[{"directory":str(work),"file":"implementation.c","arguments":[CLANG,"-std=c11","-O3","-DC_INTEGER_DIVISION_TRUNCATES","-c","implementation.c","-o","implementation.o"]}])
    report=migrate_c_project(database,work/"translated",clang=CLANG)
    write(work/"migration.json",report)
    if not report["ok"] or report["coverage"]["status_counts"]!={"function_converted":6,"prototype_resolved":6}:raise ValueError("whole library migration failed")
    source=(work/"translated/source.hepta").read_text()
    program=lower_source(source)
    (work/"migrated-program.hia.json").write_bytes(program.canonical_bytes)
    leaf=selected_leaf(program,"c_stb_div_trunc")
    (work/"selected.hia.json").write_bytes(leaf.canonical_bytes)
    return leaf,report

def compile_static(work,processes,*,pgo=False):
    batch=ROOT/"tools/fixtures/stb_context_batch.c"
    includes=["-I"+str(ROOT/"tests/fixtures/c_migration"/folder) for folder in ("stb_divide","libdivide_5_2_0")]
    libraries={}
    for name,macro in ARM_MACROS.items():
        target=work/(name+".so");compiler="/usr/bin/gcc" if name.startswith("gcc-") else CLANG
        cmd=[compiler,"-shared","-fPIC","-O3","-march=native","-flto","-fvisibility=hidden","-Wl,-Bsymbolic",*includes,"-D"+macro,batch,"-o",target]
        if compiler==CLANG:cmd.insert(1,"-fuse-ld="+LLD)
        run(cmd,work,processes);libraries[name]=target
    target=work/"rust-native-release.so"
    run([RUSTC,"--crate-type=cdylib","--edition=2021","-Copt-level=3","-Clto=fat","-Ccodegen-units=1","-Ctarget-cpu=native","-Cpanic=abort","-Clinker="+CLANG,"-Clink-arg=-fuse-ld="+LLD,
         ROOT/"tools/fixtures/stb_context_batch.rs","-o",target],work,processes)
    libraries["rust-native-release"]=target
    host=work/"host"
    run([CLANG,"-O3","-std=c11",ROOT/"tools/fixtures/stb_context_host.c","-ldl","-o",host],work,processes)
    return libraries,host

def compile_candidate(program,divisor,work,processes):
    path=work/("context-"+str(divisor));path.mkdir()
    stages={};begin=time.monotonic_ns()
    candidate=propose_context_specialization(program,parameter=1,value=divisor)
    stages["proposal_ns"]=time.monotonic_ns()-begin
    begin=time.monotonic_ns();proof=verify_context_specialization(program,candidate)
    stages["proof_ns"]=time.monotonic_ns()-begin
    write(path/"proof.json",proof)
    if not proof["verified"]:raise ValueError("context proof rejected")
    begin=time.monotonic_ns();lower=verify_scalar_lowering(candidate)
    stages["lowering_check_ns"]=time.monotonic_ns()-begin
    write(path/"lowering.json",lower)
    if not lower["verified"]:raise ValueError("actual lowering not verified")
    (path/"candidate.hia.json").write_bytes(candidate.canonical_bytes)
    begin=time.monotonic_ns()
    # Export the already validated hot block under its own public scalar name.
    # The outer batch guard remains explicitly trusted/observed C bridge code.
    combined=candidate.as_dict()
    hot=copy.deepcopy(next(b for b in combined["functions"][0]["blocks"] if b["id"]=="ctx_hot"))
    combined["functions"].append({"name":"c_stb_div_trunc_hot","params":hot["params"],"returns":["i32"],"effects":["trap"],"entry":hot["id"],"blocks":[hot]})
    combined["exports"].append("c_stb_div_trunc_hot")
    hot_lower=verify_scalar_lowering(combined,function="c_stb_div_trunc_hot")
    write(path/"hot-lowering.json",hot_lower)
    if not hot_lower["verified"]:raise ValueError("hot extraction lowering rejected")
    ir=emit_program_llvm(verify_program(combined))
    hot_header="define i32 @c_stb_div_trunc_hot(i32 %a0, i32 %a1) {"
    if ir.text.count(hot_header)!=1:raise ValueError("unexpected hot wrapper ABI")
    hinted=ir.text.replace(hot_header,hot_header[:-2]+" alwaysinline {")
    # Only the foreign wrapper receives an inlining hint. Internal bodies,
    # arithmetic, abort declaration and Core are byte-identical.
    if hinted.replace(" alwaysinline {", " {")!=ir.text:raise ValueError("hint changed LLVM semantics")
    actual_check=verify_scalar_lowering(combined,function="c_stb_div_trunc_hot",llvm_text=hinted)
    write(path/"actual-hot-lowering.json",actual_check)
    if not actual_check["verified"]:raise ValueError("hinted actual hot body failed lowering check")
    (path/"candidate.ll").write_text(hinted)
    write(path/"native-module.hia.json",combined)
    stages["emission_ns"]=time.monotonic_ns()-begin
    (path/"exports.map").write_text("{ global: batch; c_stb_div_trunc; local: *; };\n")
    target=path/"hia.so";begin=time.monotonic_ns()
    run([CLANG,"-O3","-march=native","-emit-llvm","-c",path/"candidate.ll","-o",path/"candidate.lto.o"],work,processes)
    run([CLANG,"-fuse-ld="+LLD,"-shared","-fPIC","-O3","-march=native","-flto","-fvisibility=hidden","-Wl,-Bsymbolic","-Wl,--version-script="+str(path/"exports.map"),"-DARM_HIA","-DHIA_CONTEXT_VALUE="+str(divisor),ROOT/"tools/fixtures/stb_context_batch.c",path/"candidate.lto.o","-o",target],work,processes)
    stages["compile_ns"]=time.monotonic_ns()-begin
    # Keep native text to make actual specialization inspectable.
    run(["/usr/bin/objdump","-d",target],work,processes)
    return target,stages,candidate

def observation(host,library,seed,divisor,count,rounds,work,processes,*,warmup=8,timeout=120):
    begun=time.monotonic_ns();fds=[]
    try:
        hf=seal(host);fds.append(hf)
        lf=seal(library);fds.append(lf)
        sealed_ns=time.monotonic_ns()-begun
        row=run(["/proc/self/fd/"+str(hf),"/proc/self/fd/"+str(lf),seed,divisor,count,rounds,warmup],work,processes,timeout=timeout,pass_fds=(hf,lf))
        value=json.loads(row["stdout"])
        if (value.get("schema")!="hepta.stb-context-host.v1" or value.get("correct") is not True
            or value.get("count")!=count or value.get("rounds")!=rounds
            or value.get("divisor")!=divisor or value.get("calls")!=count*rounds):
            raise ValueError("native observation receipt differs from requested work")
        value["seal_ns"]=sealed_ns;value["process_wall_ns"]=row["wall_ns"]
        value["library"]=file_identity(library);value["input_seed"]=seed
        return value
    finally:
        close_begin=time.monotonic_ns()
        for fd in reversed(fds):os.close(fd)
        if "value" in locals():
            value["image_retirement_ns"]=time.monotonic_ns()-close_begin
            value["all_in_wall_ns"]=time.monotonic_ns()-begun


def development(work):
    work.mkdir(parents=True,exist_ok=False)
    processes=[];report={"phase":"development-no-formal-holdout","processes":processes}
    try:
        program,migration=migrate(work,processes)
        libraries,host=compile_static(work,processes)
        candidate,stages,_=compile_candidate(program,1009,work,processes)
        libraries["hia-context"]=candidate
        report["candidate_stages"]=stages;report["observations"]={}
        for name,library in libraries.items():
            report["observations"][name]=observation(host,library,9047281,1009,16384,4096,work,processes)
            print(name,report["observations"][name]["wall_ns"],flush=True)
        report["complete"]=True
    except BaseException as exc:report.update(complete=False,error=repr(exc),traceback=traceback.format_exc());raise
    finally:write(work/"RESULT.json",report)



def build_pgo(work,host,processes,training,pgo_profile):
    batch=ROOT/"tools/fixtures/stb_context_batch.c"
    includes=["-I"+str(ROOT/"tests/fixtures/c_migration"/folder) for folder in ("stb_divide","libdivide_5_2_0")]
    result={}
    for name,macro in (("clang-stb-irpgo-lto","ARM_STB"),("clang-libdivide-avx512-irpgo","ARM_LIB_AVX512"),("clang-libdivide-avx512-free-irpgo","ARM_LIB_AVX512_FREE")):
        folder=work/name;folder.mkdir();instrumented=folder/"instrumented.so"
        common=[CLANG,"-fuse-ld="+LLD,"-shared","-fPIC","-O3","-march=native","-flto","-fvisibility=hidden","-Wl,-Bsymbolic",*includes,"-D"+macro]
        run([*common,"-fprofile-generate="+str(folder),batch,"-o",instrumented],work,processes)
        for repeat in range(pgo_profile["repeats"]):
            for row in training:
                observation(host,instrumented,row["seed"],row["divisor"],pgo_profile["count"],pgo_profile["rounds"],work,processes)
        profiles=sorted(folder.glob("*.profraw"))
        if not profiles:raise ValueError("PGO training wrote no actual profile")
        merged=folder/"training.profdata"
        run(["/usr/lib/llvm-20/bin/llvm-profdata","merge","-o",merged,*profiles],work,processes)
        target=folder/"trained.so"
        run([*common,"-fprofile-use="+str(merged),"-Werror=profile-instr-out-of-date","-Werror=profile-instr-unprofiled",batch,"-o",target],work,processes)
        result[name]=target
    return result


def formal(work,expected_source):
    work.mkdir(parents=True,exist_ok=False)
    started=time.monotonic_ns();processes=[]
    report={"schema":"hepta.stb-context-opportunity.v1","phase":"prospective-formal",
        "complete":False,"economic_gate":False,"processes":processes}
    original_affinity=os.sched_getaffinity(0)
    try:
        protocol=json.loads(PROTOCOL.read_text());report["protocol"]=protocol
        head=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip()
        status=subprocess.run(["git","status","--porcelain","--untracked-files=all"],cwd=ROOT,text=True,capture_output=True,check=True).stdout
        if head!=expected_source or status:raise ValueError("formal execution requires exact clean registered source")
        before=bound_source()
        for row in before["files"]:
            actual=subprocess.run(["git","rev-parse",head+":"+row["path"]],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip()
            if actual!=row["git_blob"]:raise ValueError("bound dependency differs from registered Git blob")
        report["source"]={"commit":head,"tree":subprocess.run(["git","rev-parse","HEAD^{tree}"],cwd=ROOT,text=True,capture_output=True,check=True).stdout.strip(),"bound":before}
        report["environment"]={"platform":platform.platform(),"machine":platform.machine(),"cpuinfo":Path("/proc/cpuinfo").read_text(),"initial_affinity":sorted(original_affinity),"exclusive_cpu_attested":False}
        if platform.system()!="Linux" or platform.machine()!="x86_64" or not {"avx2","avx512f"}<=set(report["environment"]["cpuinfo"].split()):raise ValueError("registered native SIMD host unavailable")
        os.sched_setaffinity(0,{sorted(original_affinity)[protocol["affinity_index"]%len(original_affinity)]})
        report["environment"]["selected_affinity"]=sorted(os.sched_getaffinity(0))
        native_tools={executable:file_identity(Path(executable).resolve(strict=True))
                      for executable in (CLANG,"/usr/bin/gcc",RUSTC,LLD,sys.executable)}
        report["native_tools_before"]=native_tools
        report["python_version"]=sys.version
        for executable in (CLANG,"/usr/bin/gcc",RUSTC,LLD):
            run([executable,"--version"],work,processes)
        for component in ("stb_divide","libdivide_5_2_0"):
            folder=ROOT/"tests/fixtures/c_migration"/component;metadata=json.loads((folder/"UPSTREAM.json").read_text())
            for row in metadata["files"]:
                data=file_identity(folder/row.get("local_path",row.get("path")))
                if any(data[k]!=row[k] for k in ("bytes","sha256","git_blob")):raise ValueError("frozen upstream byte mismatch")
        stage=time.monotonic_ns();program,migration=migrate(work,processes)
        report["migration_ns"]=time.monotonic_ns()-stage
        stage=time.monotonic_ns();libraries,host=compile_static(work,processes)
        training=protocol["training"]
        libraries.update(build_pgo(work,host,processes,training,protocol["pgo_training"]))
        if sorted(libraries)!=sorted(protocol["static_arms"]):raise ValueError("static arm inventory changed")
        report["static_build_ns"]=time.monotonic_ns()-stage
        report["artifacts"]={name:file_identity(path) for name,path in libraries.items()}
        stage=time.monotonic_ns();training_rows=[]
        for repeat in range(protocol["training_repeats"]):
            for task_index,row in enumerate(training):
                names=sorted(libraries);rotation=(repeat+task_index)%len(names);names=names[rotation:]+names[:rotation]
                for name in names:
                    obs=observation(host,libraries[name],row["seed"],row["divisor"],protocol["count"],protocol["training_rounds"],work,processes)
                    training_rows.append({"arm":name,"repeat":repeat,"task":task_index,"observation":obs})
        training_costs={name:sum(r["observation"]["all_in_wall_ns"] for r in training_rows if r["arm"]==name) for name in libraries}
        # Primary winner and two challengers are frozen from training only.
        selected=sorted(training_costs,key=lambda name:(training_costs[name],name))[:3]
        report["training"]={"observations":training_rows,"total_cost_ns":training_costs,"selected_before_holdout":selected}
        report["training_ns"]=time.monotonic_ns()-stage
        write(work/"STATIC_SELECTION.json",report["training"])
        rng=random.Random(protocol["formal_seed"])
        contexts=[]
        for index in range(protocol["contexts"]):
            contexts.append({"index":index,"divisor":2*rng.randrange(2,1<<19)+1,"seed":rng.randrange(1,1<<32)})
        report["frozen_materialized_contexts"]=contexts;write(work/"FORMAL_INPUTS.json",contexts)
        candidates={};stage=time.monotonic_ns();report["candidate_stages"]={}
        for context in contexts:
            divisor=context["divisor"]
            target,cost,candidate=compile_candidate(program,divisor,work,processes)
            candidates[divisor]=target;report["candidate_stages"][str(divisor)]=cost
            # Guard-hit, guard-miss, edge-size and native exceptional controls
            # happen before timed treatment and their costs stay in preparation.
            for d in (2,3,divisor,divisor+2,2147483647):
                observation(host,target,protocol["development_seed"],d,257,2,work,processes,warmup=0)
            for label in ("zero","overflow"):
                trap_fds=[]
                try:
                    hf=seal(host);trap_fds.append(hf)
                    lf=seal(target);trap_fds.append(lf)
                    r=run(["/proc/self/fd/"+str(hf),"--trap","/proc/self/fd/"+str(lf),label],work,processes,pass_fds=(hf,lf),expected=None)
                    if r["returncode"]!=-6 or r["stdout"]!="ENTERED_HIA\n":raise ValueError("native exceptional fallback changed")
                finally:
                    for fd in reversed(trap_fds):os.close(fd)
        report["candidate_preparation_ns"]=time.monotonic_ns()-stage
        report["preparation_charged_ns"]=time.monotonic_ns()-started
        report["observations"]=[]
        timed_phase_started=time.monotonic_ns()
        for context in contexts:
            names=selected+["hia-context"]
            for repetition in range(protocol["repeats"]):
                rotation=(context["index"]+repetition)%len(names)
                for arm in names[rotation:]+names[:rotation]:
                    if (time.monotonic_ns()-started)/1e9>protocol["max_wall_seconds"]-10:raise TimeoutError("registered study deadline")
                    path=candidates[context["divisor"]] if arm=="hia-context" else libraries[arm]
                    observation_result=observation(host,path,context["seed"],context["divisor"],protocol["count"],protocol["rounds"],work,processes,warmup=protocol["warmup_rounds"],timeout=min(protocol["cell_timeout_seconds"],max(0.001,protocol["max_wall_seconds"]-(time.monotonic_ns()-started)/1e9-10)))
                    report["observations"].append({"context":context["index"],"repetition":repetition,"arm":arm,"observation":observation_result})
                    print(json.dumps({"context":context["index"],"repetition":repetition,"arm":arm,"wall_ns":observation_result["wall_ns"]}),flush=True)
                write(work/"CHECKPOINT.json",{k:v for k,v in report.items() if k!="environment"})
        report["timed_phase_wall_ns"]=time.monotonic_ns()-timed_phase_started
        accounting_started=time.monotonic_ns()
        report["all_observation_bookkeeping_charged_ns"]=max(0,report["timed_phase_wall_ns"]-sum(r["observation"]["all_in_wall_ns"] for r in report["observations"]))
        def charge(obs):return obs["all_in_wall_ns"]
        savings=[];primary_savings=[]
        for context in contexts:
            for repetition in range(protocol["repeats"]):
                rows={r["arm"]:charge(r["observation"]) for r in report["observations"] if r["context"]==context["index"] and r["repetition"]==repetition}
                savings.append({"context":context["index"],"repetition":repetition,"ns":min(rows[a] for a in selected)-rows["hia-context"]})
                primary_savings.append(rows[selected[0]]-rows["hia-context"])
        report["pointwise_strong_static_envelope_savings"]=savings
        report["gross_envelope_ns"]=sum(r["ns"] for r in savings)
        report["gross_primary_ns"]=sum(primary_savings)
        context_sums=[sum(r["ns"] for r in savings if r["context"]==i) for i in range(protocol["contexts"])]
        report["per_context_envelope_ns"]=context_sums
        stage=accounting_started
        if bound_source()!=before:raise ValueError("bound source drifted during actual study")
        report["native_tools_after"]={executable:file_identity(Path(executable).resolve(strict=True)) for executable in native_tools}
        if report["native_tools_after"]!=native_tools:raise ValueError("native tools drifted during actual study")
        if subprocess.run(["git","status","--porcelain","--untracked-files=all"],cwd=ROOT,text=True,capture_output=True,check=True).stdout:raise ValueError("source dirtied during study")
        # Artifacts remain as evidence; release of every live memfd/DSO/buffer is
        # measured per invocation. Evidence archival is reported separately.
        os.sched_setaffinity(0,original_affinity)
        report["affinity_restored_before_gate"]=os.sched_getaffinity(0)==original_affinity
        report["final_identity_and_cleanup_ns"]=time.monotonic_ns()-stage
        report["net_envelope_ns"]=report["gross_envelope_ns"]-report["preparation_charged_ns"]-report["final_identity_and_cleanup_ns"]-report["all_observation_bookkeeping_charged_ns"]
        report["net_primary_ns"]=report["gross_primary_ns"]-report["preparation_charged_ns"]-report["final_identity_and_cleanup_ns"]-report["all_observation_bookkeeping_charged_ns"]
        report["economic_gate"]=report["net_envelope_ns"]>0 and all(n>0 for n in context_sums)
        report["measured_divisions_per_arm"]=protocol["contexts"]*protocol["repeats"]*protocol["count"]*protocol["rounds"]
        report["claims"]={"whole_application":False,"new_algorithm":False,"global_optimality":False,"population_speedup":False,"native_machine_refinement_proved":False,"batch_bridge_and_clang_trusted":True,"future_amortization_counted":False,"pointwise_envelope_is_not_statistical_confidence_bound":True}
        report["cost_scope"]={"measured":"actual declared controller machine wall-time horizon",
            "human_engineering_ns":None,"human_review_ns":None,"ai_input_tokens":None,"ai_output_tokens":None,
            "earlier_toolchain_or_dependency_acquisition_ns":None,"total_project_roi_claim":False}
        report["complete"]=True
    except BaseException as exc:report.update(error=repr(exc),traceback=traceback.format_exc());raise
    finally:
        if os.sched_getaffinity(0)!=original_affinity:os.sched_setaffinity(0,original_affinity)
        report["total_wall_ns"]=time.monotonic_ns()-started
        report["within_registered_wall_budget"]=report["total_wall_ns"]<=json.loads(PROTOCOL.read_text())["max_wall_seconds"]*1_000_000_000
        if not report["within_registered_wall_budget"]:
            report["economic_gate"]=False;report["complete"]=False;report["budget_failure"]="actual total controller wall time exceeded"
        write(work/"RESULT.json",report)

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--workdir",type=Path,required=True)
    parser.add_argument("--development",action="store_true");parser.add_argument("--expected-source")
    args=parser.parse_args()
    if args.development:development(args.workdir.resolve())
    elif args.expected_source:formal(args.workdir.resolve(),args.expected_source)
    else:raise SystemExit("formal requires --expected-source")
