#!/usr/bin/env python3
"""Four-language native measurements consumed by the existing stateful NDU.

Owns only research fixtures and evidence. All policies receive the same frozen
training observations and current request size; future timings are not inputs.
An executed negative economics result is a valid result, not a reason to retry.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
FIXTURES = ROOT / "benchmarks/hia_native_ndu"
METRIC_NAMES = ("attempts", "allocations", "frees", "refusals", "live",
    "requested_total", "usable_total", "peak_requested", "peak_usable",
    "live_requested", "live_usable", "accounting_errors", "stack_anchor", "stack_max_distance")
MASK32 = (1 << 32) - 1


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return sha256(wire(value)).hexdigest()


def file_identity(path):
    path = Path(path)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size,
            "sha256": sha256(path.read_bytes()).hexdigest()}


def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_NATIVE_ECONOMICS: " + message)


def protocol():
    return json.loads((FIXTURES / "PROTOCOL.json").read_bytes())


def checksum(n, seed):
    """Independent periodic-byte formula, without invoking any measured code."""
    cycles, tail = divmod(n, 256)
    return cycles * 32640 + sum(((seed & 255) + i) & 255 for i in range(tail))


def batch_checksum(n, seed, calls):
    return sum(checksum(n, (seed + i) & MASK32) for i in range(calls))


def percentile(samples, probability):
    require(samples and all(type(n) is int and n >= 0 for n in samples), "missing native samples")
    return sorted(samples)[max(0, math.ceil(probability * len(samples)) - 1)]


def summary(samples):
    return {"count": len(samples), "minimum": min(samples), "median": statistics.median(samples),
            "p95": percentile(samples, .95), "p99": percentile(samples, .99), "maximum": max(samples),
            "relative_mad": statistics.median(abs(x-statistics.median(samples)) for x in samples)
                            / max(1, statistics.median(samples)), "excluded": 0}


def run_command(argv, directory, ledger, *, timeout=60):
    index = len(ledger)
    start = time.monotonic_ns()
    row = {"argv": list(map(str, argv)), "status": "attempted", "started_ns": start}
    ledger.append(row)
    try:
        result = subprocess.run(row["argv"], cwd=ROOT, capture_output=True, timeout=timeout, check=False)
        row.update(returncode=result.returncode, stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr))
        for name, raw in (("stdout", result.stdout), ("stderr", result.stderr)):
            destination = directory / f"command-{index:03d}.{name}"
            destination.write_bytes(raw)
            row[name] = file_identity(destination)
        require(len(result.stdout) + len(result.stderr) < 8_000_000, "command output bound")
        require(result.returncode == 0, "command failed: " + str(argv[0]) + ": " + result.stderr.decode(errors="replace")[:1200])
        row["status"] = "passed"
        return result.stdout.decode(errors="replace")
    finally:
        row["wall_ns"] = time.monotonic_ns() - start


def source_inventory():
    paths = list(FIXTURES.glob("*")) + list((ROOT / "hepta").glob("*.py"))
    paths += [Path(__file__), ROOT / "tools/qualify_hia_ndu_stateful_reference.py",
              ROOT / "tools/qualify_hia_ndu_stateful.py"]
    return {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in sorted(paths) if p.is_file()}


def source_state():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, env={**os.environ, "GIT_NO_LAZY_FETCH": "1"}).decode().strip()
    return {"head": git("rev-parse", "HEAD"), "status": git("status", "--porcelain")}


def build(directory, clang, rustc, report):
    from hepta.hia_program_source import lower_source
    from hepta.hia_program_llvm import emit_program_llvm, compile_program_llvm
    ledger = report.setdefault("build_commands", [])
    report["toolchains"] = {}
    for name, tool in (("clang", clang), ("rustc", rustc), ("objdump", "/usr/bin/objdump")):
        report["toolchains"][name] = {**file_identity(tool), "version": run_command([tool, "--version"], directory, ledger).splitlines()[0]}
    flags = ["-O3", "-fPIC", "-fno-omit-frame-pointer", "-fstack-usage", "-fno-builtin-malloc", "-fno-builtin-calloc", "-fno-builtin-free"]
    wraps = ["-Wl,--wrap=" + name for name in ("malloc", "calloc", "realloc", "free")]
    for name in ("metrics", "probe_exports"):
        run_command([clang, *flags, "-I", FIXTURES, "-c", FIXTURES / (name+".c"), "-o", directory / (name+".o")], directory, ledger)
    products, costs = {}, {}
    for name in ("c", "cpp", "rust", "hia"):
        start = time.monotonic_ns()
        target = directory / (name + ".so")
        if name in {"c", "cpp"}:
            compiler_flags = ["-x", "c++", "-std=c++17", "-fno-exceptions"] if name == "cpp" else ["-std=c11"]
            run_command([clang, *flags, *compiler_flags, "-c", FIXTURES / ("kernel."+name), "-o", directory / (name+".o")], directory, ledger)
            run_command([clang, "-shared", directory / (name+".o"), directory / "metrics.o", directory / "probe_exports.o", *wraps, "-o", target], directory, ledger)
        elif name == "rust":
            args = [rustc, "--edition=2021", "--crate-type=cdylib", "--emit=link="+str(target)+",asm="+str(directory/"rust.s"), "-C", "opt-level=3",
                    "-C", "panic=abort", "-C", "overflow-checks=on", "-C", "force-frame-pointers=yes",
                    "-C", "linker="+str(clang), "-C", "link-arg="+str(directory / "metrics.o")]
            for flag in wraps:
                args += ["-C", "link-arg="+flag]
            run_command([*args, FIXTURES / "kernel.rs"], directory, ledger)
        else:
            source = (FIXTURES / "kernel.hepta").read_text()
            lowered = lower_source(source, path="benchmarks/hia_native_ndu/kernel.hepta")
            # lower_source returns a checked, source-independent Core object.
            core = lowered.program if hasattr(lowered, "program") else lowered
            if isinstance(core, tuple):
                core = core[0]
            raw = core.as_dict() if hasattr(core, "as_dict") else core
            (directory / "hia.core.json").write_bytes(wire(raw)+b"\n")
            llvm = emit_program_llvm(core)
            (directory / "hia.ll").write_text(llvm.text)
            report["hia_compilation"] = compile_program_llvm(llvm, program=core, output=directory / "hia.o", clang=str(clang), kind="object")
            run_command([clang, "-shared", directory / "hia.o", directory / "metrics.o", directory / "probe_exports.o", *wraps, "-o", target], directory, ledger)
        costs[name] = time.monotonic_ns() - start
        products[name] = file_identity(target)
        assembly = run_command(["/usr/bin/objdump", "-d", "--disassemble=calculate", target], directory, ledger)
        (directory / (name+".calculate.asm")).write_text(assembly)
    run_command([clang, "-O2", "-fno-omit-frame-pointer", "-fstack-usage", "-I", FIXTURES,
                 FIXTURES / "driver.c", "-ldl", "-o", directory / "driver"], directory, ledger)
    report["native_artifacts"] = products
    report["backend_build_wall_ns"] = costs
    report["driver_identity"] = file_identity(directory / "driver")
    report["stack_evidence"] = {"compiler_su_files": {p.name: p.read_text() for p in directory.glob("*.su")},
        "disassembly": {name: file_identity(directory / (name+".calculate.asm")) for name in products},
        "scope": "compiler-emitted static-frame files where supported and actual function disassembly; no complete call-graph, recursion or native stack bound"}
    return products


class Driver:
    """A bounded owned child, executing only this campaign's generated files."""
    def __init__(self, executable, raw_path):
        self.raw = raw_path.open("xb")
        self.process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, bufsize=0)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.buffer = b""
        self.loaded = set()
        self.path_ids = {}
        self.sequence = 0
        self.handshake = self.receive()
        require(self.handshake.get("ready") is True and self.handshake.get("pid") == self.process.pid, "driver handshake")

    def receive(self):
        deadline = time.monotonic() + 10
        while b"\n" not in self.buffer:
            require(time.monotonic() < deadline, "driver response timed out")
            if not self.selector.select(max(0, deadline-time.monotonic())):
                continue
            part = os.read(self.process.stdout.fileno(), 65536)
            require(part, "driver closed before response")
            self.buffer += part
            require(len(self.buffer) <= 262144, "driver response bound")
        line, self.buffer = self.buffer.split(b"\n", 1)
        self.raw.write(wire({"sequence": self.sequence, "response_hex": line.hex()})+b"\n")
        self.raw.flush()
        return json.loads(line)

    def ask(self, command):
        self.sequence += 1
        self.raw.write(wire({"sequence": self.sequence, "request": command})+b"\n")
        start = time.monotonic_ns()
        self.process.stdin.write(command.encode()+b"\n")
        self.process.stdin.flush()
        value = self.receive()
        value["transport_outer_ns"] = time.monotonic_ns() - start
        return value

    def load(self, label, products):
        if label in self.loaded:
            return None
        order = protocol()["backends"].index(label)
        row = self.ask(f"L {order} {products[label]['path']}")
        require(row.get("loaded") == order, "wrong loaded library")
        self.loaded.add(label)
        self.path_ids[products[label]["path"]] = order
        row["mapping"] = self.mapping(products[label]["path"])
        return row

    def mapping(self, path):
        row = self.ask(f"M {self.path_ids[path]}")
        require(row["mapped_bytes"] > 0,"actual loader mappings unavailable")
        row["scope"] = "Actual PT_LOAD segment page union via dl_iterate_phdr; mincore observes resident backing pages, not process RSS/private bytes. Process peak RSS is separate getrusage evidence."
        if row["mincore_failed_pages"]:
            row["backing_resident_bytes"] = None
        return row

    def measure(self, label, n, seed, calls, samples, warmup=0, fail=0):
        identifier = protocol()["backends"].index(label)
        row = self.ask(f"R {identifier} {n} {seed} {calls} {samples} {warmup} {fail}")
        require(row.get("id") == identifier and row.get("n") == n and row.get("seed") == seed, "native response identity")
        require(row["cold_value"] == checksum(n,seed), "cold result mismatch")
        require(row["batch_checksum"] == batch_checksum(n,seed,calls), "native checksum mismatch")
        require(len(row["times_ns"]) == samples and sum(row["times_ns"]) == row["elapsed_ns"], "native sample accounting mismatch")
        require(len(row["metrics"]) == len(METRIC_NAMES), "allocator observation shape")
        row["metrics"] = dict(zip(METRIC_NAMES, row["metrics"]))
        expected = 1001 if fail and n else checksum(n,seed)
        require(row["observed"] == expected, "refusal/normal behavior mismatch")
        metrics = row["metrics"]
        require(metrics["accounting_errors"] == 0 and metrics["live"] == 0
                and metrics["live_requested"] == 0 and metrics["live_usable"] == 0, "observed allocator lifetime mismatch")
        if n:
            require(metrics["attempts"] == 1 and metrics["refusals"] == fail, "allocator attempt/refusal not preserved")
            require(metrics["allocations"] == 1-fail and metrics["frees"] == 1-fail, "actual allocation/free count")
            if not fail:
                require(metrics["peak_requested"] == n and metrics["peak_usable"] >= n, "actual requested/usable bytes")
        else:
            require(metrics["attempts"] == metrics["allocations"] == metrics["frees"] == 0, "empty owner allocated")
        metrics["allocator_slack_bytes"] = metrics["peak_usable"] - metrics["peak_requested"]
        row["backend"] = label
        return row

    def close(self):
        if self.process.poll() is None:
            try:
                value = self.ask("Q")
                require(value.get("closed") is True, "driver cleanup acknowledgement")
                self.process.wait(timeout=5)
            except BaseException:
                self.process.kill()
                self.process.wait(timeout=5)
                raise
        stderr = self.process.stderr.read(65536)
        self.raw.write(wire({"exit_code": self.process.returncode, "stderr_hex": stderr.hex()})+b"\n")
        self.raw.close()
        self.selector.close()
        require(self.process.returncode == 0, "native child failed")


@contextmanager
def driver(executable, raw_path):
    instance = Driver(executable, raw_path)
    try:
        yield instance
    finally:
        instance.close()


def measure_training(directory, products, report, spec):
    report["correctness"] = []
    report["training"] = []
    report["loads"] = []
    for offset, seed in enumerate(spec["training_seeds"]):
        names = spec["backends"][offset:] + spec["backends"][:offset]
        if offset % 2: names.reverse()
        for name in names:
            with driver(directory / "driver", directory / f"training-{offset}-{name}.jsonl") as child:
                load = child.load(name, products)
                report["loads"].append({"phase": "training", "backend": name, **load})
                for n in spec["sizes"]:
                    row = child.measure(name,n,seed,spec["batch_calls"],spec["training_samples_per_request"],spec["warmup_calls"])
                    row["mapping_after"] = child.mapping(products[name]["path"])
                    report["training"].append(row)
    for name in spec["backends"]:
        with driver(directory / "driver", directory / f"correctness-{name}.jsonl") as child:
            child.load(name,products)
            for n in spec["correctness_sizes"]:
                for seed in spec["correctness_seeds"]:
                    report["correctness"].append(child.measure(name,n,seed,1,1))
                report["correctness"].append(child.measure(name,n,29,1,1,fail=1))
    training = {}
    for name in spec["backends"]:
        rows = [r for r in report["training"] if r["backend"] == name]
        loads = [r for r in report["loads"] if r["backend"] == name]
        training[name] = {"latency_ns": {str(n): math.ceil(statistics.median(t for r in rows if r["n"] == n for t in r["times_ns"])) for n in spec["sizes"]},
            "preparation_ns": math.ceil(statistics.median(r["transport_outer_ns"] for r in loads)),
            "resident_bytes": max(r["mapping_after"]["mapped_bytes"] for r in rows)}
    report["training_summary"] = {name:{str(n):summary([t for r in report["training"] if r["backend"] == name and r["n"] == n for t in r["times_ns"]]) for n in spec["sizes"]} for name in spec["backends"]}
    report["frozen_training"] = {"values": training, "sha256": digest(training),
        "future_evaluation_timing_rows_used": 0, "preparation_scope": "already-built artifact dlopen and bounded transport, not compilation",
        "samples_are_admission_domain": "finite observed native cases, not an all-input theorem"}
    return training


def observed_model(training, products, spec, current_size, horizon, ready, generation, sunk_ns):
    """No episode or future-size argument exists at the policy input boundary."""
    from hepta.hia_ndu_stateful import SCHEMA
    require(current_size in spec["sizes"] and 1 <= horizon <= 4, "unsupported observed request")
    baseline = spec["baseline"]
    def identity(name):
        return products[name]["sha256"]
    objective = {key:value for key,value in spec.items() if key not in {
        "episodes", "training_seeds", "correctness_seeds", "correctness_sizes"}}
    return {"schema": SCHEMA, "name": "native-owned-bytes", "objective_digest": digest(objective),
        "generation": generation, "baseline": {"source_sha256": identity(baseline),
            "verification_sha256": digest(["bounded-native-differential",identity(baseline)]),
            "latency_ns": [training[baseline]["latency_ns"][str(current_size)]]*horizon},
        "variants": [{"id": name, "source_sha256": identity(name),
            "verification_sha256": digest(["bounded-native-differential",identity(name)]),
            "support_sha256": digest(training), "status": "verified",
            "preparation_ns": training[name]["preparation_ns"], "holding_ns": [0]*horizon,
            "resident_bytes": training[name]["resident_bytes"],
            "latency_ns": [training[name]["latency_ns"][str(current_size)]]*horizon} for name in spec["variants"]],
        "initial_ready": sorted(ready), "memory_budget_bytes": spec["resident_quota_bytes"],
        "budget_ns": max(0,spec["model_budget_ns"]-sunk_ns), "completion_value_ns": spec["completion_value_ns"],
        "sunk_cost_ns": sunk_ns, "observations": [{"training_sha256":digest(training), "observed_size":current_size,
            "forecast":"current-size persistence", "future_workload_visible":False}],
        "cost_basis":"caller-measurement-estimates"}


def first_ready(reference, ready):
    winners = reference.get("winners",[])
    if not winners: return set(ready)
    return set(sorted((r["schedule"] for r in winners))[0][0])


def fixed_ready(training, spec):
    """One frozen fixed bank selected from training, before episode disclosure."""
    from itertools import combinations
    require(set(spec) == {"variants", "resident_quota_bytes", "sizes", "baseline"},
            "fixed policy input must exclude future episodes and evaluation seeds")
    names = spec["variants"]
    rows = []
    for count in range(len(names)+1):
        for selected in combinations(names,count):
            if sum(training[n]["resident_bytes"] for n in selected)>spec["resident_quota_bytes"]: continue
            cost = sum(training[n]["preparation_ns"] for n in selected)
            cost += sum(min(training[n]["latency_ns"][str(size)] for n in (spec["baseline"],*selected)) for size in spec["sizes"])
            rows.append((cost,selected))
    return set(min(rows)[1])


def execute_policies(directory, products, training, report, spec, bridge, identity):
    from hepta.hia_ndu_session import NduSession
    from hepta.hia_ndu_stateful import build_request
    from tools.qualify_hia_ndu_stateful_reference import exact_dp_control, greedy_control
    report["policy_runs"] = []
    report["fixed_training_selections"] = []
    for episode_index, episode in enumerate(spec["episodes"]):
        order = spec["policy_arms"][episode_index:]+spec["policy_arms"][:episode_index]
        for arm in order:
            row = {"episode":episode_index,"arm":arm,"steps":[],"status":"running"}
            report["policy_runs"].append(row)
            session = None
            started = time.monotonic_ns()
            ready, sunk = set(), 0
            last_size, sleeping = None, False
            try:
                if arm == "fixed":
                    t = time.monotonic_ns()
                    fixed_inputs = {key: spec[key] for key in
                                    ("variants", "resident_quota_bytes", "sizes", "baseline")}
                    frozen = fixed_ready(training,fixed_inputs)
                    row["fixed_selection_ns"] = time.monotonic_ns()-t
                    row["fixed_training_selection"] = sorted(frozen)
                    report["fixed_training_selections"].append(sorted(frozen))
                if arm == "native_ndu":
                    t = time.monotonic_ns()
                    session = NduSession.for_stream_profile(bridge,identity,timeout=10)
                    row["ndu_startup_ns"] = time.monotonic_ns()-t
                with driver(directory/"driver",directory/f"policy-{episode_index}-{arm}.jsonl") as child:
                    row["baseline_load"] = child.load(spec["baseline"],products)
                    sunk = time.monotonic_ns()-started
                    for index in range(len(episode["sizes"])):
                        # The next request is first disclosed here, after the previous native batch.
                        n, seed = episode["sizes"][index], episode["seeds"][index]
                        model = observed_model(training,products,spec,n,len(episode["sizes"])-index,ready,index+1,sunk)
                        step = {"index":index,"observed_size":n,"seed":seed,"model":model,"loads":[]}
                        row["steps"].append(step)
                        decision_start = time.monotonic_ns()
                        if arm == "fixed":
                            chosen = set(frozen)
                            sleeping = True
                        elif sleeping and n == last_size:
                            chosen = set(ready)
                            step["decision"] = {"status":"stop_until_observed_workload_change"}
                        elif arm in {"exact_dp","greedy"}:
                            result = exact_dp_control(model) if arm == "exact_dp" else greedy_control(model)
                            step["decision"] = result
                            chosen = first_ready(result,ready)
                            sleeping = bool(result.get("winners")) and all(set(x)==chosen for x in sorted(r["schedule"] for r in result["winners"])[0])
                        else:
                            bundle = build_request(model,search="dynamic-frontier")
                            response = session.evaluate(bundle["request"])
                            step["bundle"],step["response"] = bundle,response
                            step["native_raw_frame_hex"] = session._last_received_frame.hex()
                            recommendation = response.get("advisory_candidate_id")
                            if recommendation in bundle["plans"]:
                                first = bundle["plans"][recommendation]["actions"][0]
                                state = first["target"]
                                chosen = set(bundle["stateful_binding"]["states"][state]["ready"])
                                sleeping = first["mode"] == "stop"
                            else:
                                chosen = set(ready)
                                sleeping = True
                        step["controller_ns"] = time.monotonic_ns()-decision_start
                        last_size = n
                        step["stopped_until_size_change"] = sleeping
                        # Audit costs are retained separately and removed from service-only
                        # comparisons. The same independent computation runs for every arm.
                        audit_start = time.monotonic_ns()
                        check = exact_dp_control(model)
                        step["same_model_dp_best_value_q32"] = check["best_value_q32"]
                        if "response" in step:
                            native_values = [p["values_q32"][0] for p in step["response"]["paths"]]
                            require(max(native_values)==check["best_value_q32"], "native advice disagrees with independent finite DP")
                        step["independent_audit_ns"] = time.monotonic_ns()-audit_start
                        require(ready <= chosen, "cannot forget already prepared variants")
                        for name in sorted(chosen-ready):
                            step["loads"].append({"backend":name,**child.load(name,products)})
                        ready = chosen
                        dispatched = min((spec["baseline"],*sorted(ready)),key=lambda name:(training[name]["latency_ns"][str(n)],name))
                        step["dispatched"] = dispatched
                        step["execution"] = child.measure(dispatched,n,seed,spec["batch_calls"],1)
                        step["resident_observations"] = {name:child.mapping(products[name]["path"]) for name in sorted(child.loaded)}
                        load_cost = sum(r["transport_outer_ns"] for r in step["loads"])
                        charged = step["controller_ns"]+load_cost+step["execution"]["transport_outer_ns"]
                        sunk = time.monotonic_ns()-started-sum(s.get("independent_audit_ns",0) for s in row["steps"])
                        step["charged_step_ns"] = charged
                        residents=[r["backing_resident_bytes"] for r in step["resident_observations"].values()]
                        step["partial_right_sample_resident_backing_byte_ns"] = None if None in residents else sum(residents)*charged
                        step["residency_estimate_scope"] = "Post-execution mapping sample times charged_step_ns only; not an integral over the full service interval."
                row["status"] = "passed"
            except BaseException as error:
                row["status"] = "failed"
                row["error"] = {"type":type(error).__name__,"message":str(error)}
                raise
            finally:
                if session is not None:
                    t=time.monotonic_ns()
                    session.close()
                    row["ndu_shutdown_ns"] = time.monotonic_ns()-t
                    row["ndu_session"] = session.snapshot()
                row["actual_total_ns"] = time.monotonic_ns()-started
                row["independent_audit_ns"] = sum(s.get("independent_audit_ns",0) for s in row["steps"])
                row["service_total_ns"] = row["actual_total_ns"]-row["independent_audit_ns"]
                row["scope"] = "driver startup/load, current-only planning, actual native execution/probes, response validation and cleanup; shared offline build/training separately charged once"


def evaluate(report,spec):
    performance = []
    for n in spec["sizes"]:
        hia=report["training_summary"]["hia"][str(n)]
        for name in ("c","cpp","rust"):
            control=report["training_summary"][name][str(n)]
            performance.append({"size":n,"baseline":name,"median_ratio":hia["median"]/control["median"],
                "p95_ratio":hia["p95"]/control["p95"],"passed":hia["median"]<=1.1*control["median"] and hia["p95"]<=1.2*control["p95"]})
    economies=[]
    for episode in range(len(spec["episodes"])):
        rows={r["arm"]:r for r in report["policy_runs"] if r["episode"]==episode}
        for name in ("fixed","exact_dp","greedy"):
            economies.append({"episode":episode,"baseline":name,"ndu_ns":rows["native_ndu"]["service_total_ns"],
                "baseline_ns":rows[name]["service_total_ns"],"ratio":rows["native_ndu"]["service_total_ns"]/rows[name]["service_total_ns"],
                "passed":rows["native_ndu"]["service_total_ns"]<rows[name]["service_total_ns"]})
    return {"performance_comparisons":performance,"economic_comparisons":economies,
            "four_language_finite_correctness_and_allocator_probes":True,
            "performance_gate_passed":all(r["passed"] for r in performance),
            "service_scope_net_ndu_benefit_established":all(r["passed"] for r in economies),
            "whole_lifecycle_net_ndu_benefit_established":False,
            "whole_language_safety_proved":False,"global_optimum_proved":False,
            "complete_lifecycle_cost_known":False,"future_timing_leakage_used":False}


def finalize_acceptance(report):
    """Identity drift or incomplete execution withdraws every acceptance gate."""
    valid = report.get("status") == "completed" and report.get("source_unchanged") is True
    report["acceptance_observation_valid"] = valid
    if not valid:
        report.pop("acceptance", None)


def qualify(args):
    start=time.monotonic_ns()
    directory=Path(args.output).resolve()
    require(not directory.exists(),"new evidence directory required")
    directory.mkdir(parents=True,mode=0o700)
    report={"schema":"hepta.hia.native-economics.results.v1","status":"failed",
            "observed_utc":datetime.now(timezone.utc).isoformat(),"protocol":protocol(),
            "host":{"system":platform.system(),"machine":platform.machine(),"python":sys.version},
            "mode":"formal" if args.expected_source else "development","reused_native_ndu":file_identity(args.bridge),
            "reused_native_identity":json.loads(Path(args.identity).read_bytes()),
            "reused_native_build_is_new_measurement":False}
    report["measurement_boundaries"]={
        "cold_ns":"First un-warmed invocation for this request; only the first request per newly loaded library is process/dispatch cold. No hardware cache flush or fully cold host claim.",
        "timed_calls":"Resource observer is disabled during timing; its wrapper dispatch overhead remains in every backend.",
        "allocator":"Requested payload, malloc_usable_size allocation capacity and slack; arena metadata and fragmentation unobserved.",
        "stack":"Sampled begin-to-allocator helper address distance plus compiler stack files/disassembly; no global peak proof.",
        "resident":"Loader PT_LOAD pages and mincore backing residency; not process-private RSS. Process peak RSS is getrusage, separately.",
        "planning":"Measured planning/validation/transport costs are charged in actual service totals. The inherited preparation model's zero future decision-cost parameter remains a declared model limitation; no net-gain claim follows from its predicted optimum."}
    (directory/"protocol.json").write_bytes((FIXTURES/"PROTOCOL.json").read_bytes())
    try:
        require(platform.system()=="Linux" and platform.machine()=="x86_64","Linux x86-64 profile only")
        if hasattr(os,"sched_getaffinity"):
            allowed=os.sched_getaffinity(0); os.sched_setaffinity(0,{min(allowed)})
            report["host"].update(affinity=sorted(os.sched_getaffinity(0)),exclusive_cpu=False)
        report["source_before"]=source_state()
        if args.expected_source:
            require(report["source_before"]=={"head":args.expected_source,"status":""},"formal exact clean source required")
        report["input_hashes_before"]=source_inventory()
        t=time.monotonic_ns()
        products=build(directory,Path(args.clang),Path(args.rustc),report)
        report["offline_build_wall_ns"]=time.monotonic_ns()-t
        t=time.monotonic_ns()
        training=measure_training(directory,products,report,report["protocol"])
        report["offline_validation_training_wall_ns"]=time.monotonic_ns()-t
        from tools.qualify_hia_ndu_stateful import translation_refusal_probe
        t=time.monotonic_ns()
        report["actual_failed_translation"],_=translation_refusal_probe()
        report["failed_translation_outer_ns"]=time.monotonic_ns()-t
        require(report["actual_failed_translation"]["status"]=="actual-refusal-observed","real proof/refusal/replay required")
        report["shared_campaign_cost_ns"]=(report["offline_build_wall_ns"]+report["offline_validation_training_wall_ns"]+report["failed_translation_outer_ns"])
        report["shared_campaign_cost_scope"]="Actual shared bank preparation/validation/training and rejected proof paid once in this campaign, disclosed without arbitrary amortization. Per-policy service totals exclude this common sunk work and the independently recorded audit."
        execute_policies(directory,products,training,report,report["protocol"],args.bridge,args.identity)
        report["acceptance"]=evaluate(report,report["protocol"])
        report["status"]="completed"
    except BaseException as error:
        report["error"]={"type":type(error).__name__,"message":str(error)}
    finally:
        report["input_hashes_after"]=source_inventory()
        report["source_after"]=source_state()
        report["source_unchanged"]=report.get("input_hashes_before")==report["input_hashes_after"] and report.get("source_before")==report["source_after"]
        if not report["source_unchanged"]:
            report["status"]="failed"
            report["source_error"]="source changed during execution"
        finalize_acceptance(report)
        report["wall_ns_before_final_encoding"]=time.monotonic_ns()-start
        report["cost_exclusions"]=["tool installation","source acquisition","past reused NDU build (separately preserved original identity/cost)","human implementation/review","energy","allocator arena/metadata/fragmentation","final report and archive publication"]
        report["artifact_inventory"]={str(p.relative_to(directory)):file_identity(p) for p in sorted(directory.iterdir()) if p.is_file()}
        (directory/"RESULT.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True)
    parser.add_argument("--clang",required=True)
    parser.add_argument("--rustc",required=True)
    parser.add_argument("--bridge",required=True)
    parser.add_argument("--identity",required=True)
    parser.add_argument("--expected-source")
    args=parser.parse_args()
    report=qualify(args)
    print(json.dumps({"status":report["status"],"error":report.get("error"),"acceptance":report.get("acceptance"),"output":args.output},indent=2))
    return 0 if report["status"]=="completed" else 1


if __name__=="__main__":
    raise SystemExit(main())
