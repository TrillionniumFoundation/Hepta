#!/usr/bin/env python3
"""Small, frozen, actual-HIA result-reuse pilot. Every failure is evidence.

HIA supplies computation; the same Python bounded payload cache supplies all
policies' direct/preparation/reuse executor. Original Rust NDU only advises.
This is a distinct workload from the earlier Rust matrix-packing experiment.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
from hashlib import sha256
import itertools
import json
import os
from pathlib import Path
import random
import resource
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_result_cache import CacheError, NativeKernel, ResultCache, oracle, require
from hepta.hia_ndu_dynamic import (JsonProcess, MODEL_SCHEMA, MODES, action, digest,
    invocation_gate, live_mask, resident_bytes, validate_model, wire)
from tools.qualify_hia_ndu_dynamic import independent_exact_minimum
from hepta.hia_result_cache_audit import matched_model_audit

FIXTURE = ROOT / "benchmarks/hia_result_cache"


def timed(fn):
    before = time.monotonic_ns()
    value = fn()
    return value, time.monotonic_ns() - before


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as f:
        json.dump(value, f, sort_keys=True, indent=2, allow_nan=False)
        f.write("\n")


def identity(path):
    p = Path(path).resolve(strict=True)
    return {"path": str(p), "bytes": p.stat().st_size, "sha256": sha256(p.read_bytes()).hexdigest()}


def sources():
    selected = [Path(__file__), FIXTURE / "kernel.hepta", FIXTURE / "PROTOCOL.json",
        ROOT / "hepta/hia_result_cache.py", ROOT / "tests/test_hia_result_cache.py",
        ROOT / "hepta/hia_ndu_dynamic.py", ROOT / "tools/qualify_hia_ndu_dynamic.py"]
    # Bind the complete Python compiler/verifier package and the actual adapter.
    selected += list((ROOT / "hepta").glob("*.py"))
    selected += [p for p in (ROOT / "rust/hia-ndu-dynamic-model").rglob("*") if p.is_file()]
    return {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in sorted(set(selected))}


def git_state(root=ROOT):
    def git(*a): return subprocess.check_output(["git", *a], cwd=root, text=True).strip()
    commit = git("rev-parse", "HEAD")
    state = {"commit": commit, "tree": git("rev-parse", commit + "^{tree}"),
             "full_status": git("status", "--porcelain=v1", "--untracked-files=all")}
    require(git("rev-parse", "HEAD") == commit, "HEAD changed while observing source state")
    return state


def require_clean_source(state):
    require(state["full_status"] == "", "tracked or untracked files must be committed before registration")


def bound_inputs(args, *, protocol=FIXTURE / "PROTOCOL.json"):
    """Before/after observations on a trusted host, not atomic file custody."""
    return {"source": git_state(), "sources": sources(), "protocol": identity(protocol),
            "planner": identity(args.planner), "planner_manifest": identity(args.planner_manifest),
            "python": identity(sys.executable), "clang": identity(args.clang)}


def require_same_bindings(before, after):
    changed = sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))
    require(not changed, "qualification input binding changed: " + ", ".join(changed))


def check_frozen_evidence(report, output):
    expected = {}
    if "registration_sha256" in report:
        expected["registration.json"] = report["registration_sha256"]
    if "frozen_training_sha256" in report:
        expected["frozen-before-holdout.json"] = report["frozen_training_sha256"]
    if "hia_build" in report:
        expected["kernel.so"] = report["hia_build"]["artifact_sha256"]
    observation = {"expected": expected, "actual": {}}
    report.setdefault("evidence_binding_observations", []).append(observation)
    for name in expected:
        observation["actual"][name] = identity(Path(output) / name)
    # A later return to the original bytes must not erase an earlier mismatch.
    for observed in report["evidence_binding_observations"]:
        for name, digest_value in observed["expected"].items():
            require(observed["actual"].get(name, {}).get("sha256") == digest_value,
                    "frozen evidence changed: " + name)


def trace(family, repetition, spec, *, training=False):
    # Training and holdout use different queue orders, fixed independently of timings.
    sequences = {
        "stable": [0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1],
        "phase_shift": [0, 1, 0, 1, 0, 1, 2, 3, 2, 3, 2, 3],
        "invalidate": [0, 1, 0, 2, 0, 1, 0, 2, 0, 1, 0, 2]}
    targets = sequences[family][:]
    if training:
        targets = targets[2:] + targets[:2]
    elif repetition:
        targets = targets[::-1]
    seeds = list(spec["training_seeds"])
    if not training:
        seeds = [(x + 19 + 13 * repetition) & 0xffffffff for x in seeds]
    epochs = [1] * spec["object_count"]
    jobs = []
    for index, target in enumerate(targets):
        changes = []
        if family == "invalidate" and index in (3, 6, 9):
            changed = 0 if index != 6 else 1
            epochs[changed] += 1
            seeds[changed] = (seeds[changed] + 17 + index) & 0xffffffff
            changes.append({"id": changed, "epoch": epochs[changed], "seed": seeds[changed]})
        jobs.append({"target": target, "epochs": list(epochs), "seeds": list(seeds), "mutations": changes})
    return jobs


def make_model(cache, jobs, index, spec, estimates, decision, elapsed, kernel_hash):
    window = jobs[index:index + spec["lookahead"]]
    direct = max(1, round(estimates["direct_ns"] * cache.n / spec["training_n"]))
    prepare = max(1, round(estimates["prepare_ns"] * cache.n / spec["training_n"]))
    state = cache.snapshot()
    ready = sum(1 << i for i in state["ready"])
    result = {"schema": MODEL_SCHEMA, "generation": cache.generation,
        "objective_digest": digest(["all-requests-correct", "elapsed-cost", spec["schema"]]),
        "observation_digest": digest({"state": state, "window": window}),
        "workload_sha256": kernel_hash,
        "artifacts": [{"id": "result-"+str(i), "resident_bytes": 64,
            "prepare_ns": prepare, "retire_ns": estimates["retire_ns"],
            "epochs": [j["epochs"][i] for j in window]} for i in range(spec["object_count"])],
        "targets": [j["target"] for j in window], "direct_ns": [direct] * len(window),
        "packed_ns": [estimates["cached_ns"]] * len(window),
        "ready_mask": ready, "ready_epochs": [cache.epochs[i] if ready & (1 << i) else 0
            for i in range(spec["object_count"])],
        "memory_quota_bytes": cache.slots * 64, "budget_ns": max(0, spec["episode_budget_ns"]-elapsed),
        "sunk_cost_ns": elapsed, "completion_value_ns": spec["completion_value_ns"],
        "decision": dict(decision), "session_ready": True}
    return validate_model(result)


def local_light(model):
    """One pass over the same announced horizon. No search and no native IPC."""
    live = live_mask(model, 0, model["ready_mask"])
    scored = []
    for i, a in enumerate(model["artifacts"]):
        epoch = a["epochs"][0]
        savings = sum(max(0, model["direct_ns"][j] - model["packed_ns"][j])
            for j, t in enumerate(model["targets"])
            if t == i and a["epochs"][j] == epoch)
        score = savings - (0 if live & (1 << i) else a["prepare_ns"])
        # Evicting a valid row itself has a cost, which favors retaining a tie.
        if live & (1 << i): score += a["retire_ns"]
        scored.append((score, bool(live & (1 << i)), -i, i))
    destination = 0
    for score, _, _, i in sorted(scored, reverse=True):
        if score > 0 and resident_bytes(model, destination | (1 << i)) <= model["memory_quota_bytes"]:
            destination |= 1 << i
    return action(model, 0, model["ready_mask"], destination)


def calibrate_kernel(kernel, spec):
    started = time.monotonic_ns()
    observations = {k: [] for k in ("direct_ns", "prepare_ns", "cached_ns", "retire_ns")}
    for _ in range(spec["calibration_repetitions"]):
        cache = ResultCache(kernel, spec["training_n"], list(spec["training_seeds"]), slots=spec["cache_slots"])
        for ident in (0, 1):
            _, ns = timed(lambda: cache.run(ident, 1, "direct")); observations["direct_ns"].append(ns)
            _, ns = timed(lambda: cache.prepare(ident, 1)); observations["prepare_ns"].append(ns)
            _, ns = timed(lambda: cache.run(ident, 1, "cached")); observations["cached_ns"].append(ns)
            _, ns = timed(lambda: cache.retire(ident, 1)); observations["retire_ns"].append(ns)
        cache.close()
    return {"samples": observations,
            "estimates": {k: max(1, round(statistics.median(v))) for k, v in observations.items()},
            "wall_ns": time.monotonic_ns() - started,
            "forecast": "direct/preparation scale linearly by n/training_n; cache/retire stay constant; frozen"}


def choose_fixed(spec, estimates):
    started = time.monotonic_ns()
    choices = []
    for mask in range(1 << spec["object_count"]):
        if mask.bit_count() > spec["cache_slots"]: continue
        cost = 0
        for family in spec["families"]:
            ready = 0
            for job in trace(family, 0, spec, training=True):
                for change in job["mutations"]:
                    if ready & (1 << change["id"]):
                        cost += estimates["retire_ns"]
                        ready &= ~(1 << change["id"])
                cost += (mask & ~ready).bit_count() * estimates["prepare_ns"]
                ready = mask
                cost += min(estimates["cached_ns"], estimates["direct_ns"]) if mask & (1 << job["target"]) else estimates["direct_ns"]
            cost += ready.bit_count() * estimates["retire_ns"]
        choices.append({"mask": mask, "forecast_training_ns": cost})
    selected = min(choices, key=lambda r:(r["forecast_training_ns"],r["mask"]))
    return {"choices": choices, "selected": selected, "selection_wall_ns": time.monotonic_ns()-started,
            "holdout_timings_used": False}


def actual_controls(kernel):
    before = time.monotonic_ns()
    accepted, rejected = [], []
    for n in [0, 1, 255, 256, 515, 65521]:
        for seed in [0, 3, 0xffffffff]:
            actual = kernel.evaluate(n, seed)
            require(actual == oracle(n, seed), "real HIA control mismatch")
            accepted.append({"n": n, "seed": seed, "value": actual})
    # Check the native entry's own bound, not just the Python guard.
    refusal = int(kernel.function(1048577, 0))
    require(refusal == (1 << 63) + 1, "native input-bound refusal")
    rejected.append({"case": "native-size-over-bound", "value": refusal})
    def reject(label, fn):
        try: fn()
        except (CacheError, ValueError) as exc:
            rejected.append({"case": label, "type": type(exc).__name__, "message": str(exc)})
        else: raise AssertionError("negative control accepted: " + label)
    c = ResultCache(kernel, 515, [3, 79, 251, 17], slots=2)
    c.prepare(0, 1); c.prepare(1, 1)
    reject("payload-quota", lambda:c.prepare(2,1))
    c.mutate(0,2,4)
    reject("stale-epoch",lambda:c.run(0,1,"cached"))
    reject("invalidated-row",lambda:c.run(0,2,"cached"))
    c.prepare(0,2)
    c.arena[c._slot(0)*64] ^= 1
    reject("code-key-corruption",lambda:c.run(0,2,"cached"))
    c.retire(0,2); c.prepare(0,2)
    c.arena[c._slot(0)*64+63] ^= 1
    reject("value-corruption",lambda:c.run(0,2,"cached"))
    c.advance_generation(2)
    reject("generation-cleared",lambda:c.run(1,1,"cached"))
    c.close()
    reject("closed-executor",lambda:c.run(1,1,"direct"))
    require(c.snapshot()["allocated_payload_bytes"] == 0, "control cache not released")
    return {"accepted":accepted,"rejected":rejected,"wall_ns":time.monotonic_ns()-before,
            "native_hia":True,"finite_controls_only":True}


def calibrate_planner(session, mode, kernel, spec, estimates):
    started = time.monotonic_ns()
    c = ResultCache(kernel,spec["training_n"],list(spec["training_seeds"]),slots=spec["cache_slots"])
    zeros = dict.fromkeys(["gate_ns","solve_ns","transport_validation_ns","startup_ns","close_ns"],0)
    model = make_model(c,trace("stable",0,spec,training=True),0,spec,estimates,zeros,0,kernel.sha256)
    samples = []
    try:
        for _ in range(3):
            _,gate_ns = timed(lambda: invocation_gate(model))
            response,receipt = session.evaluate(model,mode)
            samples.append({"search_ns":response["search_ns"],"outer_call_ns":receipt["outer_call_ns"],"gate_ns":gate_ns})
    finally: c.close()
    d={"gate_ns":round(statistics.median(r["gate_ns"] for r in samples)),
       "solve_ns":round(statistics.median(r["search_ns"] for r in samples)),
       "transport_validation_ns":round(statistics.median(max(0,r["outer_call_ns"]-r["search_ns"]) for r in samples)),
       "startup_ns":session.startup_ns,"close_ns":0}
    return {"samples":samples,"estimates":d,"wall_ns":time.monotonic_ns()-started,
        "close_estimate": "zero in model for already resident campaign session; actual close charged separately"}


def paired_control(sessions,kernel,spec,estimates,decisions):
    c=ResultCache(kernel,spec["training_n"],list(spec["training_seeds"]),slots=spec["cache_slots"])
    common={key:max(decisions[m][key] for m in ("beam","beam_ndu")) for key in decisions["beam"]}
    model=make_model(c,trace("phase_shift",0,spec,training=True),0,spec,estimates,common,0,kernel.sha256)
    try:
        a,ra=sessions["beam"].evaluate(model,"beam")
        b,rb=sessions["beam_ndu"].evaluate(model,"beam_ndu")
        require(a["bundle"]["plans"]==b["bundle"]["plans"],"beam/NDU candidate set differs under identical model")
        require(a["selected_first_action"]==b["selected_first_action"],"scalar NDU ablation differs")
        return {"identical_model":True,"identical_candidates":True,"identical_selected_action":True,
                "beam_receipt":ra,"ndu_receipt":rb,"model":model,"beam":a,"ndu":b}
    finally:c.close()


def episode(policy,family,n,repetition,spec,kernel,estimates,decisions,sessions,fixed,audits,raw):
    started=time.monotonic_ns()
    jobs=trace(family,repetition,spec)
    name=f"{family}-n{n}-r{repetition}-{policy}"
    cache=None
    row={"name":name,"policy":policy,"family":family,"n":n,"repetition":repetition,
         "completed":False,"planner_requests":0,"ndu_requests":0,"skips":0,"steps":[],
         "components_ns":{},"payload_byte_ns":0,"max_payload_bytes":0}
    try:
        cache,ns=timed(lambda:ResultCache(kernel,n,list(jobs[0]["seeds"]),slots=spec["cache_slots"],generation=1+repetition))
        row["components_ns"]["initialization"]=ns
        resident_tick=time.monotonic_ns()
        resident_payload=0
        def account():
            nonlocal resident_tick,resident_payload
            now=time.monotonic_ns()
            row["payload_byte_ns"]+=(now-resident_tick)*resident_payload
            resident_payload=len(cache.ready())*64
            row["max_payload_bytes"]=max(row["max_payload_bytes"],resident_payload)
            resident_tick=now
        for index,job in enumerate(jobs):
            step={"index":index,"job":job,"mutations":[],"retired":[],"prepared":[]}
            for change in job["mutations"]:
                account()
                value,ns=timed(lambda change=change:cache.mutate(change["id"],change["epoch"],change["seed"]))
                step["mutations"].append({"change":change,"invalidated":value,"wall_ns":ns})
                account()
            require(cache.epochs==job["epochs"] and cache.seeds==job["seeds"],"actual input state mismatch")
            model,ns=timed(lambda:make_model(cache,jobs,index,spec,estimates,decisions[policy],time.monotonic_ns()-started,kernel.sha256))
            step["model_construction_ns"]=ns
            decision_started=time.monotonic_ns()
            response=None
            if policy in ("direct","fixed"):
                chosen=action(model,0,model["ready_mask"],0 if policy=="direct" else fixed["selected"]["mask"])
                decision={"fixed_mask":chosen["ready_after"]}
            elif policy=="local_light":
                chosen=local_light(model); decision={"local_linear_heuristic":True}
            else:
                gate=invocation_gate(model); decision={"gate":gate}
                if gate["invoke"]:
                    response,receipt=sessions[policy].evaluate(model,policy)
                    chosen=response["selected_first_action"]
                    decision.update({"receipt":receipt,"response":response})
                    row["planner_requests"]+=1; row["ndu_requests"]+=int(policy=="beam_ndu")
                    audits.append({"episode":name,"step":index,"policy":policy,"model":model,"response":response})
                else:
                    row["skips"]+=1
                    chosen=action(model,0,model["ready_mask"],live_mask(model,0,model["ready_mask"]))
            step["decision_ns"]=time.monotonic_ns()-decision_started
            if chosen is None or time.monotonic_ns()-started >= spec["episode_budget_ns"]:
                decision["optional_action_withheld"]=True
                chosen=action(model,0,model["ready_mask"],live_mask(model,0,model["ready_mask"]))
            step.update({"model":model,"decision":decision,"selected":chosen})
            target=chosen["ready_after"]
            require(sum(1<<i for i in cache.ready())==model["ready_mask"],"cache state drift")
            require(resident_bytes(model,target)<=cache.slots*64,"executor admission quota")
            for ident in cache.ready():
                if not target & (1<<ident):
                    account();_,ns=timed(lambda ident=ident:cache.retire(ident,cache.epochs[ident]))
                    step["retired"].append({"id":ident,"wall_ns":ns}); account()
            for ident in range(spec["object_count"]):
                if target & (1<<ident) and ident not in cache.ready():
                    if time.monotonic_ns()-started >= spec["episode_budget_ns"]:
                        step.setdefault("preparation_withheld",[]).append(ident);continue
                    account();_,ns=timed(lambda ident=ident:cache.prepare(ident,cache.epochs[ident]))
                    step["prepared"].append({"id":ident,"wall_ns":ns}); account()
            dispatch="cached" if job["target"] in cache.ready() and model["packed_ns"][0]<model["direct_ns"][0] else "direct"
            value,ns=timed(lambda:cache.run(job["target"],job["epochs"][job["target"]],dispatch))
            step.update({"dispatch":dispatch,"result":value,"execution_and_oracle_ns":ns,"state":cache.snapshot()})
            row["steps"].append(step)
            raw.write(json.dumps({"episode":name,"step":step},sort_keys=True,separators=(",",":"))+"\n");raw.flush()
            account()
        require(cache.executions==spec["jobs_per_episode"],"missing workload output")
        row["completed"]=True
    except BaseException as exc:
        row["error"]={"type":type(exc).__name__,"message":str(exc)}
    finally:
        if cache is not None:
            row["pre_cleanup_state"]=cache.snapshot()
            account()
            _,ns=timed(cache.close)
            account()
            row["components_ns"]["cleanup"]=ns; row["final_state"]=cache.snapshot()
        row["service_ns"]=time.monotonic_ns()-started
        row["maxrss_kib_process_highwater"]=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return row


def audit(rows):
    started=time.monotonic_ns();result=[]
    for row in rows:
        expected,ns=timed(lambda:independent_exact_minimum(row["model"]))
        actual=min((p["total_ns"] for p in row["response"]["bundle"]["plans"].values()),default=None)
        if row["policy"]=="exact_dp":require(expected==actual,"native exact DP differs from independent bottom-up audit")
        require(expected is None or actual is None or actual>=expected,"candidate below independently enumerated minimum")
        result.append({"episode":row["episode"],"step":row["step"],"policy":row["policy"],
            "independent_minimum_ns":expected,"best_candidate_ns":actual,
            "candidate_gap_ns":None if expected is None or actual is None else actual-expected,"audit_ns":ns})
    return {"rows":result,"wall_ns":time.monotonic_ns()-started,"all_exact_minima_match":True,
        "scope":"finite forecast model only; not observed-runtime optimum"}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--clang",required=True)
    parser.add_argument("--planner",required=True)
    parser.add_argument("--planner-manifest",required=True)
    args=parser.parse_args()
    require(not args.output.resolve().is_relative_to(ROOT), "output must be outside the frozen source checkout")
    args.output.mkdir(parents=True,exist_ok=False)
    begin=time.monotonic_ns();spec={};sessions={};frozen_inputs=None
    report={"schema":"hepta.hia.result-cache.result.v1","authority":"DENY_ALL",
        "production_activation":False,"p1_closed":False,"completed":False,
        "binding_scope":"before/after file and git observations on a trusted host; no atomic custody or transitive Python/libc closure"}
    try:
        protocol_bytes=(FIXTURE/"PROTOCOL.json").read_bytes()
        spec=json.loads(protocol_bytes);report["protocol"]=spec
        clang=shutil.which(args.clang);require(clang is not None,"Clang path does not resolve")
        args.clang=clang
        frozen_inputs=bound_inputs(args)
        state,inv=frozen_inputs["source"],frozen_inputs["sources"]
        require_clean_source(state)
        require(frozen_inputs["protocol"]["sha256"]==sha256(protocol_bytes).hexdigest(),"protocol changed while loading")
        manifest_bytes=Path(args.planner_manifest).read_bytes()
        require(sha256(manifest_bytes).hexdigest()==frozen_inputs["planner_manifest"]["sha256"],"planner manifest changed while loading")
        build_manifest=json.loads(manifest_bytes)
        require(build_manifest["binary_sha256"]==frozen_inputs["planner"]["sha256"],"registered planner disagrees with build manifest")
        report["inputs_before"]=frozen_inputs
        registration={"source":state,"sources":inv,"protocol":spec,"holdout_started":False,
            "bound_inputs":frozen_inputs,"binding_scope":report["binding_scope"],
            "cpu_affinity":sorted(os.sched_getaffinity(0)),"uname":list(os.uname()),
            "load_average":list(os.getloadavg()),"command":sys.argv,"registered_unix_ns":time.time_ns(),
            "planner":frozen_inputs["planner"],"planner_manifest":frozen_inputs["planner_manifest"],
            "python":frozen_inputs["python"],"clang":frozen_inputs["clang"],
            "existing_planner_build":build_manifest["build_cost"]}
        save(args.output/"registration.json",registration)
        report["registration_sha256"]=sha256((args.output/"registration.json").read_bytes()).hexdigest()
        from hepta.hia_program_source import lower_source
        from hepta.hia_program_llvm import emit_program_llvm,compile_program_llvm
        build_started=time.monotonic_ns()
        core=lower_source((FIXTURE/"kernel.hepta").read_text(),path="benchmarks/hia_result_cache/kernel.hepta")
        if hasattr(core,"program"):core=core.program
        if isinstance(core,tuple):core=core[0]
        (args.output/"kernel.core.json").write_bytes(core.canonical_bytes+b"\n")
        ir=emit_program_llvm(core)
        (args.output/"kernel.ll").write_text(ir.text)
        ledger=[]
        build=compile_program_llvm(ir,program=core,output=args.output/"kernel.so",clang=args.clang,command_log=ledger)
        report["hia_build_ns"]=time.monotonic_ns()-build_started
        report["hia_build"]=build;save(args.output/"hia-build-commands.json",ledger)
        require(all(build["toolchain"][key]==frozen_inputs["clang"][key] for key in ("path","sha256")),"compiler receipt differs from registered tool")
        kernel=NativeKernel(args.output/"kernel.so",build["artifact_sha256"])
        report["hia_load_ns"]=kernel.load_ns
        report["actual_controls"]=actual_controls(kernel)
        try:NativeKernel(args.output/"kernel.so","00"*32)
        except CacheError as exc:report["artifact_substitution_refused"]=str(exc)
        else:raise AssertionError("incorrect code digest accepted")
        training=calibrate_kernel(kernel,spec);report["training"]=training
        estimates=training["estimates"]
        fixed=choose_fixed(spec,estimates);report["fixed_selection"]=fixed
        decisions={};calibrations={}
        zeros={k:0 for k in ["gate_ns","solve_ns","transport_validation_ns","startup_ns","close_ns"]}
        for policy in spec["policies"]:
            if policy not in MODES:decisions[policy]=dict(zeros);continue
            sessions[policy]=JsonProcess(args.planner,args.planner_manifest,role="--planner-stream",log=args.output/("planner-"+policy+".jsonl"))
            require(sessions[policy].binary_sha256==frozen_inputs["planner"]["sha256"],"executing planner differs from registration")
            calibrations[policy]=calibrate_planner(sessions[policy],policy,kernel,spec,estimates)
            decisions[policy]=calibrations[policy]["estimates"]
        report["planner_calibration"]=calibrations
        paired_started=time.monotonic_ns()
        report["paired_ablation"]=paired_control(sessions,kernel,spec,estimates,decisions)
        report["paired_ablation_ns"]=time.monotonic_ns()-paired_started
        frozen={"training":training,"fixed":fixed,"decisions":decisions,"sources":inv}
        save(args.output/"frozen-before-holdout.json",frozen)
        report["frozen_training_sha256"]=identity(args.output/"frozen-before-holdout.json")["sha256"]
        report["inputs_before_holdout"]=bound_inputs(args)
        require_same_bindings(frozen_inputs,report["inputs_before_holdout"])
        check_frozen_evidence(report,args.output)
        rows=[];audits=[]
        with (args.output/"raw.jsonl").open("x",encoding="utf-8") as raw:
            for family,n,rep in itertools.product(spec["families"],spec["holdout_sizes"],range(spec["repeats"])):
                policies=list(spec["policies"])
                random.Random("result-cache-v1:"+family+":"+str(n)+":"+str(rep)).shuffle(policies)
                for policy in policies:
                    rows.append(episode(policy,family,n,rep,spec,kernel,estimates,decisions,sessions,fixed,audits,raw))
                    # Keep every episode and its failures immediately, before an offline audit.
                    save(args.output/(rows[-1]["name"]+".json"),rows[-1])
        report["episodes"]=rows
        report["audit"]=audit(audits)
        report["matched_model_audit"]=matched_model_audit(audits,sessions["beam"])
        require(report["matched_model_audit"]["all_match"],"identical-model beam/NDU candidate or action mismatch")
        report["native_kernel_calls"]=kernel.calls;report["native_kernel_timed_ns"]=kernel.native_ns
        require(all(r["completed"] for r in rows),"one or more pilot episodes failed")
        report["inputs_after_audit"]=bound_inputs(args)
        require_same_bindings(frozen_inputs,report["inputs_after_audit"])
        check_frozen_evidence(report,args.output)
        report["sources_unchanged"]=True
        report["completed"]=True
    except BaseException as exc:
        report["fatal_error"]={"type":type(exc).__name__,"message":str(exc)}
    finally:
        session_costs={}
        for mode,session in sessions.items():
            session.close()
            session_costs[mode]={"startup_ns":session.startup_ns,"close_ns":session.close_ns,
                "returncode":session.returncode,"calls":session.calls}
            if session.returncode!=0:report["completed"]=False
        report["planner_lifecycle"]=session_costs
        if frozen_inputs is not None:
            try:
                report["inputs_final"]=bound_inputs(args)
                for checkpoint in ("inputs_before_holdout","inputs_after_audit","inputs_final"):
                    if checkpoint in report:
                        require_same_bindings(frozen_inputs,report[checkpoint])
                check_frozen_evidence(report,args.output)
                report["input_bindings_unchanged"]=True
            except Exception as exc:
                report["input_bindings_unchanged"]=False;report["completed"]=False
                report["final_binding_error"]={"type":type(exc).__name__,"message":str(exc)}
        report["observed_campaign_wall_ns"]=time.monotonic_ns()-begin
        report["final_load_average"]=list(os.getloadavg())
        report["maxrss_kib_process_highwater"]=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if "episodes" in report:
            totals={}
            common=report.get("hia_build_ns",0)+report.get("hia_load_ns",0)+report.get("training",{}).get("wall_ns",0)
            for mode in spec["policies"]:
                rows=[r for r in report["episodes"] if r["policy"]==mode]
                lifecycle=session_costs.get(mode,{"startup_ns":0,"close_ns":0})
                known=sum(r["service_ns"] for r in rows)+common
                known+=lifecycle["startup_ns"]+lifecycle["close_ns"]
                known+=report.get("planner_calibration",{}).get(mode,{}).get("wall_ns",0)
                known+=report.get("fixed_selection",{}).get("selection_wall_ns",0) if mode=="fixed" else 0
                if mode in MODES:known+=registration["existing_planner_build"]["wall_ns"]
                totals[mode]={"episodes":len(rows),"completed":sum(r["completed"] for r in rows),
                    "service_ns":sum(r["service_ns"] for r in rows),"known_standalone_cost_ns":known,
                    "planner_requests":sum(r["planner_requests"] for r in rows),"ndu_requests":sum(r["ndu_requests"] for r in rows),
                    "preparations":sum(r.get("pre_cleanup_state",{}).get("preparations",0) for r in rows),
                    "reuses":sum(r.get("pre_cleanup_state",{}).get("reuses",0) for r in rows),
                    "invalidations":sum(r.get("pre_cleanup_state",{}).get("invalidations",0) for r in rows),
                    "payload_byte_ns":sum(r["payload_byte_ns"] for r in rows)}
            report["totals"]=totals
            ndu=totals["beam_ndu"]
            report["observed_ndu_service_beats_every_control"]=bool(ndu["ndu_requests"] and all(ndu["service_ns"]<v["service_ns"] for k,v in totals.items() if k!="beam_ndu"))
            report["known_standalone_ndu_beats_every_control"]=bool(ndu["ndu_requests"] and all(ndu["known_standalone_cost_ns"]<v["known_standalone_cost_ns"] for k,v in totals.items() if k!="beam_ndu"))
            report["cost_scope"]={"observed_campaign":"one actual run, includes shared setup, exact-state and matched-model audits, final input checks; excludes external interpreter startup and final report serialization",
                "known_standalone":"each policy is allocated a full HIA build/load/base-calibration; native planner policies also pay full historical pinned bridge build and their calibration/session costs; do not sum these counterfactual totals",
                "not_measured":["human effort","energy","toolchain provisioning","fully isolated hardware","future workload generalization"],
                "peak_rss":"whole Python process highwater including mapped image and Python metadata; not per policy", 
                "residency":"payload byte-nanoseconds, no invented currency penalty; fixed 128-byte payload arena per episode"}
        save(args.output/"result.json",report)
        summary={k:report[k] for k in ["completed","p1_closed","totals","observed_campaign_wall_ns","observed_ndu_service_beats_every_control","known_standalone_ndu_beats_every_control","fatal_error"] if k in report}
        save(args.output/"summary.json",summary)
        print(json.dumps(summary,sort_keys=True))
    return 0 if report["completed"] else 1

if __name__=="__main__":raise SystemExit(main())
