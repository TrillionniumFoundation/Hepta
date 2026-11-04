#!/usr/bin/env python3
"""Real native qualification of full-cost invoke/skip and artifact residency.

All arms receive identical frozen performance observations and only the current
request, generation and remaining horizon. Native NDU additionally pays its real
identity-checked transport. Cost estimates are forecasts, not elapsed-time proofs.
This runner retains raw driver and Rust request/response evidence and reports
negative results without rewriting the earlier stateful/native studies.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import statistics
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from hepta.hia_ndu_cost import (SCHEMA, AdvisoryController, build_request, digest,
    exact_control, invocation_gate, lightweight_control, skip_schedule, validate_model)
from hepta.hia_ndu_session import NduSession, STREAM_PROFILE_PINS
from hepta.hia_native_differential import _pin_native_artifact
from hepta.hia_program import verify_program
import qualify_hia_native_ndu as native


def write(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def timed(fn):
    started = time.monotonic_ns()
    result = fn()
    return result, time.monotonic_ns() - started


def median(values):
    return math.ceil(statistics.median(values))


def policy_model_evidence(rows):
    """Separate attempted calls from completed, validated response evidence.

    AdvisoryController records response only after successful native evaluation
    and projection. An exception can set native_invoked without that receipt.
    A surviving successful subset cannot hide failed calls in aggregate agreement.
    """
    attempts = [step["decision"] for row in rows if row["policy"] == "native_ndu"
                for step in row["steps"] if step["decision"]["native_invoked"] is True]
    completed = [item for item in attempts if type(item.get("response")) is dict
                 and bool(item["response"]) and "native_error" not in item]
    failed = len(attempts) - len(completed)
    return {"native_model_attempted_count": len(attempts),
            "native_model_evaluated_count": len(completed),
            "native_model_failed_count": failed,
            "native_policy_evidence_present": bool(completed),
            "native_model_all_attempts_completed": not failed if attempts else None,
            "native_matches_same_information_exact_model": (
                not failed and all(item.get("native_matches_exact_model") is True for item in completed)
                if completed else None)}


def full_cost_totals(rows, offline_wall_ns, manifest):
    """Keep an absent build observation unknown; never charge it as zero."""
    build = manifest.get("build_cost")
    build_ns = build.get("wall_ns") if type(build) is dict else None
    known = type(build_ns) is int and build_ns >= 0
    totals = {policy: offline_wall_ns + sum(row["service_wall_ns"] for row in rows
                                           if row["policy"] == policy)
              for policy in ("fixed", "exact_dp", "lightweight", "native_ndu")}
    totals["native_ndu"] = totals["native_ndu"] + build_ns if known else None
    return {"build_cost_observed": known, "bridge_build_wall_ns": build_ns if known else None,
            "arm_full_cost_ns": totals,
            "cost_scope": ("Declared bridge build, shared offline build/training/proof/calibration, "
                           "and actual per-policy service wall times. Parent interpreter startup/imports "
                           "and final report output require separate composition outer receipts."),
            "execution_scope_cost_complete": known,
            "unknown_costs": [] if known else ["native_bridge_build_wall_ns"],
            "unknown_costs_scope": "declared execution scope only",
            "full_lifecycle_cost_complete": False,
            "unmeasured_lifecycle_costs": {
                "toolchain_acquisition_ns": None,
                "dependency_acquisition_before_campaign_ns": None,
                "human_engineering_and_review_ns": None,
                "long_term_residency_and_evidence_retention_ns": None,
                "maintenance_and_recovery_beyond_observed_campaign_ns": None}}


def episodes_without_native_start(rows):
    """Count proven skips, not failed starts or unknown legacy receipts.

    Zero elapsed startup time alone cannot prove the factory was never entered.
    A factory attempt does not establish whether a process actually started.
    Missing attempt/session evidence in retained older rows stays unproven; do
    not manufacture it or rewrite their original qualification reports.
    """
    return sum(row["policy"] == "native_ndu"
               and type(row.get("native_invocations")) is int and row["native_invocations"] == 0
               and "native_session" not in row and bool(row["steps"])
               and all(decision.get("startup_attempted") is False
                       and decision.get("session_ready_before") is False
                       and decision.get("native_invoked") is False
                       and type(decision.get("startup_ns")) is int and decision["startup_ns"] == 0
                       and "native_error" not in decision and "response" not in decision
                       for decision in (step["decision"] for step in row["steps"]))
               for row in rows)


def source_inventory():
    files = [*ROOT.glob("hepta/*.py"), *ROOT.glob("benchmarks/hia_native_ndu/*"),
             *ROOT.glob("benchmarks/hia_ndu_cost/*"), Path(__file__),
             ROOT / "tools/qualify_hia_native_ndu.py"]
    return {str(p.relative_to(ROOT)): native.file_identity(p)["sha256"]
            for p in sorted(set(files)) if p.is_file()}


class ResidentDriver(native.Driver):
    @staticmethod
    def sealed_identity(descriptor, access_path):
        """Bind a readable fd alias to its retained, immutable kernel object."""
        import fcntl
        native.require(type(descriptor) is int and descriptor >= 0,
                       "sealed artifact descriptor is invalid")
        required = (getattr(fcntl, "F_SEAL_WRITE", 0x0008)
                    | getattr(fcntl, "F_SEAL_GROW", 0x0004)
                    | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
                    | getattr(fcntl, "F_SEAL_SEAL", 0x0001))
        seals = fcntl.fcntl(descriptor, getattr(fcntl, "F_GET_SEALS", 1034))
        native.require(seals & required == required, "native artifact is not fully sealed")
        held, accessed = os.fstat(descriptor), Path(access_path).stat()
        native.require((held.st_dev, held.st_ino, held.st_size) ==
                       (accessed.st_dev, accessed.st_ino, accessed.st_size),
                       "sealed artifact access path differs from retained descriptor")
        actual = native.file_identity(access_path)
        native.require(actual["bytes"] == held.st_size, "sealed artifact byte count differs")
        return {**actual, "access_path": str(access_path), "descriptor": descriptor,
                "device": held.st_dev, "inode": held.st_ino, "seals": seals}

    @classmethod
    def bind_product(cls, product, descriptor, access_path):
        """Keep the build identity and the sealed access path as separate fields."""
        original = native.file_identity(product["path"])
        native.require(all(original[key] == product[key] for key in ("path", "bytes", "sha256")),
                       "native library identity differs before sealed binding")
        sealed = cls.sealed_identity(descriptor, access_path)
        native.require(all(sealed[key] == product[key] for key in ("bytes", "sha256")),
                       "sealed native library differs from fixed build product")
        return {**product, "original_path": product["path"], "path": str(access_path),
                "sealed_identity": sealed}

    def load(self, label, products):
        if label in self.loaded:
            return None
        started = time.monotonic_ns()
        expected = products[label]
        binding = expected.get("sealed_identity")
        native.require(type(binding) is dict, "resident artifact lacks sealed identity")
        actual = self.sealed_identity(binding["descriptor"], expected["path"])
        native.require(actual == binding and
                       all(actual[key] == expected[key] for key in ("bytes", "sha256")),
                       "sealed native library identity differs before load")
        order = native.protocol()["backends"].index(label)
        row = self.ask(f"L {order} {expected['path']}")
        native.require(row.get("loaded") == order, "wrong loaded library")
        self.loaded.add(label)
        self.path_ids[expected["path"]] = order
        row["mapping"] = self.mapping(expected["path"])
        row["artifact_identity"] = actual
        row["load_outer_ns"] = time.monotonic_ns() - started
        return row

    def unload(self, label, products):
        if label not in self.loaded:
            return None
        identifier = native.protocol()["backends"].index(label)
        row = self.ask(f"U {identifier}")
        native.require(row.get("unloaded") == identifier, "retirement acknowledgement")
        self.loaded.remove(label)
        self.path_ids.pop(products[label]["path"])
        return row


def spec():
    return {"baseline": "hia", "variants": ["rust", "cpp"], "backends": ["c","cpp","rust","hia"],
        "sizes": [64,4096,65536], "training_seeds": [19,811,2347],
        "correctness_sizes": [0,1,31,63,255,4097,65536], "correctness_seeds": [7,1025],
        "batch_calls": 1024, "training_samples_per_request": 3, "warmup_calls": 4,
        "resident_quota_bytes": 65536, "model_budget_ns": 10_000_000_000,
        "completion_value_ns": 100_000_000_000, "repetitions": 3,
        "episodes": [
            {"id":"tiny", "sizes":[64,64,64,64], "valid":[True]*4, "epochs":[0]*4},
            {"id":"amortized", "sizes":[65536]*4, "valid":[True]*4, "epochs":[0]*4},
            {"id":"invalidate-recover", "sizes":[65536,65536,4096,65536],
             "valid":[True,True,False,True], "epochs":[0,0,1,2]}]}


def model_from(training, products, specification, fees, current, horizon, ready, epoch,
               valid, spent, session):
    # No future episode vector or evaluation timing is accepted at this boundary.
    base = specification["baseline"]
    return {"schema":SCHEMA, "objective_digest":digest({k:v for k,v in specification.items() if k != "episodes"}),
        "generation":epoch+1, "baseline":{"source_sha256":products[base]["sha256"],
            "verification_sha256":digest(["core-and-bounded-native",products[base]["sha256"]]),
            "latency_ns":[training[base]["latency_ns"][str(current)]]*horizon},
        "variants":[{"id":n,"source_sha256":products[n]["sha256"],
            "verification_sha256":digest(["bounded-native-only",products[n]["sha256"],epoch]),
            "support_sha256":digest(training), "status":"verified" if valid else "rejected",
            "valid":[valid]*horizon, "prepare_ns":training[n]["preparation_ns"],
            "proof_ns":training[n]["proof_ns"], "retire_ns":training[n]["retire_ns"],
            "holding_ns":0, "resident_bytes":training[n]["resident_bytes"],
            "latency_ns":[training[n]["latency_ns"][str(current)]]*horizon} for n in specification["variants"]],
        "ready":sorted(ready), "memory_budget_bytes":specification["resident_quota_bytes"],
        "budget_ns":max(0,specification["model_budget_ns"]-spent), "sunk_cost_ns":spent,
        "completion_value_ns":specification["completion_value_ns"], "decision":deepcopy(fees),
        "session_ready":session, "observation_sha256":digest({"training":training,"current":current,
            "epoch":epoch,"valid":valid,"forecast":"current request persistence","future_visible":False})}


def calibrated_fees(directory, example, factory):
    """Calibrate before workload disclosure, retaining every native exchange."""
    gates, searches, transport = [], [], []
    session, startup = timed(factory)
    rows = []
    try:
        for index in range(7):
            _, elapsed = timed(lambda: invocation_gate(example))
            gates.append(elapsed)
            bundle, elapsed = timed(lambda: build_request(example))
            searches.append(elapsed)
            response, elapsed = timed(lambda: session.evaluate(bundle["request"]))
            transport.append(elapsed)
            rows.append({"request":bundle["request"], "response":response,
                         "raw_envelope":session._last_received_frame.hex(), "request_ns":elapsed})
    finally:
        _, close = timed(session.close)
    write(directory/"calibration-native.json", rows)
    # The unchanged native protocol exposes no internal evaluation timer.
    # Native+serialization+transport+response validation remain one measured,
    # indivisible term. We explicitly avoid inventing their decomposition.
    fees = {"gate_ns":median(gates), "search_ns":median(searches),
            "native_ns":0, "transport_ns":median(transport), "validation_ns":0,
            "startup_ns":startup, "close_ns":close}
    return fees, {"gate_ns":gates,"search_ns":searches,"native_roundtrip_ns":transport,
        "startup_ns":startup,"close_ns":close,"fees":fees,
        "native_transport_validation_are_combined":True,
        "zero_components_mean_included_in_roundtrip_not_free":True,
        "session_identity":session.snapshot(),
        "measurement_scope":"wall time for real calls; costs calibrated before evaluation, not a hard upper bound"}


def strong_fixed(training, specification):
    rows = []
    names = specification["variants"]
    for count in range(len(names)+1):
        for selected in itertools.combinations(names,count):
            if sum(training[n]["resident_bytes"] for n in selected) > specification["resident_quota_bytes"]:
                continue
            # Known horizon=4 and equal weights for registered sizes, without
            # the evaluation episode, order, seeds or epoch schedule.
            cost = sum(training[n]["preparation_ns"]+training[n]["proof_ns"] for n in selected)
            cost += 4*sum(min(training[n]["latency_ns"][str(size)] for n in ("hia",*selected))
                          for size in specification["sizes"])//len(specification["sizes"])
            rows.append({"ready":list(selected),"cost_ns":cost})
    return min(rows,key=lambda r:(r["cost_ns"],r["ready"])), rows


def native_refusal_recovery(directory, example, factory):
    session = factory()
    rows = []
    try:
        for refused in (True,False):
            bundle = build_request(example)
            request = bundle["request"]
            if refused:
                for row in request["candidates"]:
                    if row["id"] != "abstain":
                        row["verified"] = False
            response,elapsed = timed(lambda: session.evaluate(request))
            if refused:
                native.require(response["evaluated_candidate_ids"] == ["abstain"],"unverified candidate was admitted by native NDU")
            else:
                native.require(any(n != "abstain" for n in response["evaluated_candidate_ids"]),"native recovery did not evaluate delivery candidates")
            rows.append({"phase":"refusal" if refused else "recovery", "request":request,
                         "response":response,"wall_ns":elapsed,"raw_envelope":session._last_received_frame.hex()})
    finally:
        session.close()
    write(directory/"native-refusal-recovery.json",rows)
    return {"passed":True,"session":session.snapshot(),"phases":[r["phase"] for r in rows],
        "scope":"native model-level rejection of verified=false, then valid request on same process; independent verifier remains separate"}


def admission(name, epoch, products, proof_receipts, core):
    """Independent, actual check outside NDU. No safety claim for C++/Rust."""
    native.require(native.file_identity(products[name]["original_path"])["sha256"] == products[name]["sha256"],
                   "artifact changed after bounded native admission")
    native.require(proof_receipts[name]["passed"], "candidate lacks independent bounded execution evidence")
    if name == "hia":
        verify_program(core)
    return {"artifact":name,"epoch":epoch,"artifact_sha256":products[name]["sha256"],
            "admission_sha256":digest(proof_receipts[name]),"authority":"DENY_ALL","safety_certificate":False,
            "scope":"HIA Core verifier plus finite differential/lifetime probes" if name == "hia" else
                    "finite native behavior/lifetime probes only; no all-input native safety theorem"}


def execute(directory, products, training, specification, fees, factory, receipts, core):
    rows = []
    fixed, fixed_candidates = strong_fixed(training,specification)
    # Same workload information; independent controls use their own measured
    # planning overhead, never the native bridge's fee as a fake DP expense.
    control_models = []
    empty_fees = dict.fromkeys(fees,0)
    for size in specification["sizes"]:
        sample = model_from(training,products,specification,empty_fees,size,4,[],0,True,0,False)
        control_models.append(sample)
    dp_ns = median([timed(lambda m=m: exact_control(m))[1] for m in control_models for _ in range(3)])
    light_ns = median([timed(lambda m=m: lightweight_control(m))[1] for m in control_models for _ in range(3)])
    costs = {"exact_dp":{**empty_fees,"search_ns":dp_ns,"gate_ns":fees["gate_ns"]},
             "lightweight":{**empty_fees,"search_ns":light_ns,"gate_ns":fees["gate_ns"]},
             "native_ndu":fees, "fixed":empty_fees}
    arms = ["fixed","exact_dp","lightweight","native_ndu"]
    for repeat in range(specification["repetitions"]):
        for episode_index, episode in enumerate(specification["episodes"]):
            offset = (repeat+episode_index)%len(arms)
            order = arms[offset:]+arms[:offset]
            for policy in order:
                identity = f"{repeat}-{episode['id']}-{policy}"
                started = time.monotonic_ns()
                child = ResidentDriver(directory/"driver",directory/(identity+"-driver.jsonl"))
                controller = AdvisoryController(factory) if policy == "native_ndu" else None
                row = {"id":identity,"episode":episode["id"],"repeat":repeat,"policy":policy,
                       "steps":[],"native_invocations":0,"actual_prepare_ns":0,"actual_proof_ns":0,
                       "actual_retire_ns":0,"actual_execution_roundtrip_ns":0,"actual_decision_ns":0}
                try:
                    _, base_proof = timed(lambda: admission("hia",0,products,receipts,core))
                    _, base_load = timed(lambda: child.load("hia",products))
                    row["baseline_proof_ns"],row["baseline_load_ns"] = base_proof,base_load
                    ready, last_epoch = set(), 0
                    for batch,(size,valid,epoch) in enumerate(zip(episode["sizes"],episode["valid"],episode["epochs"])):
                        step = {"batch":batch,"size":size,"valid":valid,"epoch":epoch,"retired":[],"prepared":[],"reused":[]}
                        if epoch != last_epoch or not valid:
                            for name in sorted(ready):
                                evidence, elapsed = timed(lambda n=name: child.unload(n,products))
                                step["retired"].append({"artifact":name,"evidence":evidence,"wall_ns":elapsed,"reason":"epoch invalidation"})
                                row["actual_retire_ns"] += elapsed
                            ready.clear()
                        last_epoch = epoch
                        spent = time.monotonic_ns()-started
                        model = model_from(training,products,specification,costs[policy],size,4-batch,
                                           ready,epoch,valid,spent,bool(controller and controller.session))
                        planning = time.monotonic_ns()
                        if policy == "native_ndu":
                            action, decision = controller.decide(model)
                            row["native_invocations"] += int(decision["native_invoked"])
                            if decision["native_invoked"] and controller.session is not None:
                                step["native_raw_envelope"] = controller.session._last_received_frame.hex()
                        elif policy == "fixed":
                            destination = set(fixed["ready"]) if valid else set()
                            action = {"ready_after":sorted(destination)}
                            decision = {"fixed_ready":fixed,"native_invoked":False}
                        else:
                            gate = invocation_gate(model)
                            if gate["mode"] == "skip":
                                action = gate["skip"]["actions"][0]
                            elif policy == "exact_dp":
                                result = exact_control(model)
                                action = result["best"]["actions"][0] if result["best"] else None
                            else:
                                action = lightweight_control(model)
                            decision = {"gate":gate,"native_invoked":False,"control_model":model}
                        elapsed = time.monotonic_ns()-planning
                        row["actual_decision_ns"] += elapsed
                        step["decision"],step["decision_wall_ns"] = decision,elapsed
                        # Refusal/conflicting advice keeps only currently valid
                        # admitted artifacts and the verifier-checked baseline.
                        destination = set(action["ready_after"]) if action else set(ready)
                        native.require(valid or not destination,"invalid candidate selected")
                        native.require(sum(training[n]["resident_bytes"] for n in destination) <= specification["resident_quota_bytes"],"resident quota")
                        for name in sorted(ready-destination):
                            evidence, elapsed = timed(lambda n=name: child.unload(n,products))
                            step["retired"].append({"artifact":name,"evidence":evidence,"wall_ns":elapsed,"reason":"policy eviction"})
                            row["actual_retire_ns"] += elapsed
                        for name in sorted(destination-ready):
                            evidence, elapsed = timed(lambda n=name: admission(n,epoch,products,receipts,core))
                            row["actual_proof_ns"] += elapsed
                            load, load_ns = timed(lambda n=name: child.load(n,products))
                            row["actual_prepare_ns"] += load_ns
                            step["prepared"].append({"artifact":name,"admission":evidence,"proof_ns":elapsed,"load":load,"prepare_ns":load_ns})
                        step["reused"] = sorted(destination&ready)
                        ready = destination
                        chosen = min(("hia",*sorted(ready)),key=lambda n:(training[n]["latency_ns"][str(size)],n))
                        result, elapsed = timed(lambda: child.measure(chosen,size,7001+repeat*100+batch*17,
                                                                      specification["batch_calls"],1))
                        row["actual_execution_roundtrip_ns"] += elapsed
                        step.update(dispatch=chosen,ready=sorted(ready),execution=result,execution_roundtrip_ns=elapsed,
                                    remaining_budget_ns=max(0,specification["model_budget_ns"]-(time.monotonic_ns()-started)))
                        row["steps"].append(step)
                finally:
                    row["native_close_ns"] = controller.close() if controller else 0
                    _,row["driver_close_ns"] = timed(child.close)
                row["service_wall_ns"] = time.monotonic_ns()-started
                row["component_wall_ns"] = sum(row[k] for k in ("baseline_proof_ns","baseline_load_ns","actual_prepare_ns",
                    "actual_proof_ns","actual_retire_ns","actual_execution_roundtrip_ns","actual_decision_ns","native_close_ns","driver_close_ns"))
                row["other_service_ns"] = row["service_wall_ns"]-row["component_wall_ns"]
                native.require(row["other_service_ns"] >= 0,"service accounting overlap")
                if controller and controller.session:
                    row["native_session"] = controller.session.snapshot()
                write(directory/(identity+".json"),row)
                rows.append(row)
    return rows,{"fixed_training_candidates":fixed_candidates,"fixed_selected":fixed,
                 "policy_cost_estimates":costs,"same_workload_information":True,
                 "native_uses_exact_first_action_compression":True,
                 "exact_dp_quality_upper_bound":"Native cannot improve a correctly solved same-information deterministic scalar model; any incremental value must come from measured end-to-end cost or a richer model."}


def qualify(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True,exist_ok=False)
    started = time.monotonic_ns()
    stream_profile = getattr(args, "stream_profile", "original-v1")
    if stream_profile not in STREAM_PROFILE_PINS:
        raise ValueError("unknown native stream source profile")
    report = {"schema":"hepta.hia.ndu.full-cost-qualification.v3", "status":"running",
              "authority":"DENY_ALL","safety_certificate":False,"source_before":source_inventory(),
              "git":native.source_state(),"specification":spec(),"command":sys.argv,
              "stream_profile":stream_profile,"native_source_pin":STREAM_PROFILE_PINS[stream_profile]}
    descriptors = []
    try:
        products = native.build(output,args.clang,args.rustc,report,build_profile="optimized-release-v1")
        native.run_command([args.clang,"-O2","-I",native.FIXTURES,ROOT/"benchmarks/hia_ndu_cost/driver.c",
                            "-ldl","-o",output/"driver"],output,report["build_commands"])
        report["driver_identity"] = native.file_identity(output/"driver")
        training = native.measure_training(output,products,report,report["specification"])
        receipts = {n:{"passed":True,"rows_sha256":digest([r for r in report["correctness"] if r["backend"]==n]),
                       "artifact_sha256":products[n]["sha256"],"scope":"finite observed native cases only"} for n in products}
        core = json.loads((output/"hia.core.json").read_bytes())
        # Pin the actual bytes once; drivers load sealed memfds through this
        # parent's proc descriptors. The coherent PID namespace is required.
        for name,product in products.items():
            raw,_,descriptor = _pin_native_artifact(Path(product["path"]))
            descriptors.append(descriptor)
            native.require(len(raw)==product["bytes"] and hashlib.sha256(raw).hexdigest()==product["sha256"],
                           "sealed artifact binding")
            products[name] = ResidentDriver.bind_product(product, descriptor, f"/proc/{os.getpid()}/fd/{descriptor}")
            with_probe = ResidentDriver(output/"driver",output/("residency-"+name+".jsonl"))
            try:
                proof,e1 = timed(lambda n=name: admission(n,0,products,receipts,core))
                load,e2 = timed(lambda n=name: with_probe.load(n,products))
                retired,e3 = timed(lambda n=name: with_probe.unload(n,products))
                reload,e4 = timed(lambda n=name: with_probe.load(n,products))
                observed = with_probe.measure(name,31,17,1,1)
                training[name].update(proof_ns=e1,retire_ns=e3,preparation_ns=max(training[name]["preparation_ns"],e2))
                report.setdefault("residency_probes",[]).append({"artifact":name,"proof":proof,"load":load,
                    "retire":retired,"reload":reload,"recovery_execution":observed,"proof_ns":e1,"load_ns":e2,
                    "retire_ns":e3,"reload_ns":e4})
            finally:
                with_probe.close()
        manifest = json.loads(Path(args.identity).read_bytes())
        report["native_bridge"] = {"binary":native.file_identity(args.bridge),"manifest":native.file_identity(args.identity),
            "identity":manifest["identity"],"build_cost":manifest.get("build_cost"),
            "rebuilt_this_campaign":args.bridge_built_this_campaign,
            "no_python_native_algorithm_substitution":True}
        factory = lambda: NduSession.for_stream_profile(args.bridge,args.identity,profile=stream_profile)
        zero = {k:0 for k in ("gate_ns","search_ns","native_ns","transport_ns","validation_ns","startup_ns","close_ns")}
        example = model_from(training,products,report["specification"],zero,65536,4,[],0,True,0,False)
        fees,report["decision_calibration"] = calibrated_fees(output,example,factory)
        report["native_refusal_recovery"] = native_refusal_recovery(output,example,factory)
        report["frozen_training"]["values"] = training
        report["frozen_training"]["sha256"] = digest(training)
        report["offline_wall_ns"] = time.monotonic_ns()-started
        rows,report["controls"] = execute(output,products,training,report["specification"],fees,factory,receipts,core)
        report["episodes"] = [{k:v for k,v in row.items() if k != "steps"} for row in rows]
        comparisons = []
        for episode in report["specification"]["episodes"]:
            selected = [r for r in rows if r["episode"]==episode["id"]]
            medians = {p:median([r["service_wall_ns"] for r in selected if r["policy"]==p])
                       for p in ("fixed","exact_dp","lightweight","native_ndu")}
            comparisons.append({"episode":episode["id"],"median_service_ns":medians,
                "native_beats_all_controls":all(medians["native_ndu"]<medians[p] for p in medians if p!="native_ndu"),
                "native_over_best_control":medians["native_ndu"]/min(v for p,v in medians.items() if p!="native_ndu")})
        report["comparisons"] = comparisons
        costs = full_cost_totals(rows, report["offline_wall_ns"], manifest)
        report["acceptance"] = {"complete_cost_accounting":costs["execution_scope_cost_complete"],
            "complete_cost_accounting_scope":costs["cost_scope"],
            "full_lifecycle_cost_complete":False,"same_information_controls":True,
            "actual_native_invocations":sum(r["native_invocations"] for r in rows),
            **policy_model_evidence(rows),
            "skip_only_episodes_without_native_start":episodes_without_native_start(rows),
            "native_net_win_scenarios":sum(c["native_beats_all_controls"] for c in comparisons),
            "scenario_count":len(comparisons),"native_net_benefit_established":False,
            "finite_native_correctness_passed":True,
            "reason":"Three repetitions are exploratory, never an application-wide or statistical net-benefit theorem."}
        report["shared_cost_policy"] = {"offline_build_training_proof_calibration_wall_ns":report["offline_wall_ns"],
            **costs,
            "charged_per_arm":"one full shared offline campaign cost plus sum of actual service walls; no unreported amortization",
            "limits":"Shared offline calibration includes native calibration for every arm as an identical workload-information campaign; bridge build is additional only for native. No fully cold host claim."}
        report["outer_measurement_scope"] = "Service accounting includes driver start/stop and all online work; campaign_wall_ns starts after module imports and excludes final report serialization. The integration command ledger must additionally retain outer process wall time, including imports and report output."
        report["status"] = "completed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = {"type":type(error).__name__,"message":str(error)}
        raise
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        report["source_after"] = source_inventory()
        report["source_stable"] = report["source_before"] == report["source_after"]
        if "acceptance" in report:
            report["acceptance"]["source_stable_during_run"] = report["source_stable"]
        report["campaign_wall_ns"] = time.monotonic_ns()-started
        write(output/"REPORT.json",report)
    print(json.dumps({"report":str(output/"REPORT.json"),"status":report["status"],
                      "acceptance":report["acceptance"],"comparisons":report["comparisons"]},sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    for name in ("output","clang","rustc","bridge","identity"):
        parser.add_argument("--"+name,required=True)
    parser.add_argument("--bridge-built-this-campaign",action="store_true")
    parser.add_argument("--stream-profile", choices=tuple(STREAM_PROFILE_PINS), default="original-v1")
    qualify(parser.parse_args())


if __name__ == "__main__":
    main()
