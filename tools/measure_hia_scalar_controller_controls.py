#!/usr/bin/env python3
"""Freeze, execute and independently audit 64 identical-pool scalar controls.

The complete existing strong-ordinary and real-native NDU selector calls are
timed, including native identity admission, sealing, process ownership and
capture. Evidence writes are outside both calls and inside the outer interval.
These authored cost tables do not establish incremental NDU or economic value.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from fractions import Fraction
from hashlib import sha256
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import resource
import statistics
import subprocess
import sys
import time
import traceback

SCHEMA = "hepta.hia.scalar-controller-controls.v1"
ALLOWANCE_NS = 1_000_000_000
ARMS = ("ordinary", "ndu")
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_BYTES = 32 * 1024 * 1024


def require(ok, message):
    if not ok:
        raise ValueError("E_HIA_SCALAR_CONTROLS: " + message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value):
    return sha256(wire(value)).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs,
                      parse_constant=lambda _: require(False, "nonfinite JSON"))


def read_bytes(path):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), "ordinary evidence file required")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "evidence exceeds byte bound")
    return raw


def write_new(path, value):
    with Path(path).open("xb") as stream:
        stream.write(wire(value) + b"\n")


class Store:
    def __init__(self, root):
        self.root = Path(root)

    def put(self, raw):
        require(type(raw) is bytes and len(raw) <= MAX_BYTES, "bounded bytes required")
        key = sha256(raw).hexdigest()
        path = self.root / "objects" / key
        try:
            with path.open("xb") as stream:
                stream.write(raw)
        except FileExistsError:
            require(read_bytes(path) == raw, "existing object differs")
        return {"path": "objects/" + key, "sha256": key, "bytes": len(raw)}

    def json(self, value):
        return self.put(wire(value))

    def read(self, ref):
        require(type(ref) is dict and set(ref) == {"path", "sha256", "bytes"}
                and type(ref["sha256"]) is str and HEX.fullmatch(ref["sha256"])
                and ref["path"] == "objects/" + ref["sha256"]
                and type(ref["bytes"]) is int and 0 <= ref["bytes"] <= MAX_BYTES,
                "invalid object reference")
        raw = read_bytes(self.root / ref["path"])
        require(len(raw) == ref["bytes"] and sha256(raw).hexdigest() == ref["sha256"],
                "object differs from original digest")
        return raw

    def pack(self, value):
        if type(value) is bytes:
            return {"raw_bytes": self.put(value)}
        if type(value) is dict:
            return {key: self.pack(item) for key, item in value.items()}
        if type(value) is list:
            return [self.pack(item) for item in value]
        return value

    def unpack(self, value):
        if type(value) is dict:
            if set(value) == {"raw_bytes"}:
                return self.read(value["raw_bytes"])
            return {key: self.unpack(item) for key, item in value.items()}
        if type(value) is list:
            return [self.unpack(item) for item in value]
        return value


def cases():
    """Expected winners are specified before any native measurement."""
    def row(cid, cost, uncertainty=0, quality=True):
        return {"id": cid, "quality_complete": quality, "immediate_ns": 1,
            "remaining_cost_ns": cost, "uncertainty_ns": uncertainty,
            "support_sha256": digest({"authored_row": cid, "cost": cost}),
            "artifact_sha256": digest({"nonexecuted_fixture": cid}), "artifact_bytes": 1}
    m = 1_000_000
    specs = [
        ("unique_challenger", [row("zeta", 30*m), row("beta", 20*m), row("alpha", 10*m)], "alpha"),
        ("unique_incumbent", [row("zeta", 10*m), row("beta", 20*m), row("alpha", 30*m)], "zeta"),
        ("incumbent_tie", [row("zeta", 10*m), row("beta", 10*m), row("alpha", 30*m)], "zeta"),
        ("cheaper_alternative_tie", [row("zeta", 30*m), row("beta", 10*m), row("alpha", 10*m)], "alpha"),
        ("all_tied", [row("zeta", 10*m), row("beta", 10*m), row("alpha", 10*m)], "zeta"),
        ("quality_rejection", [row("zeta", 30*m), row("beta", 1, quality=False), row("alpha", 10*m)], "alpha"),
        ("resource_rejection", [row("zeta", 30*m), row("beta", ALLOWANCE_NS+1), row("alpha", 10*m)], "alpha"),
        ("inclusive_budget", [row("zeta", ALLOWANCE_NS-7, 7),
                              row("beta", ALLOWANCE_NS, 1), row("alpha", 1, quality=False)], "zeta"),
    ]
    return [{"id": name, "pool": pool, "remaining_wall_ns": ALLOWANCE_NS, "expected_id": winner}
            for name, pool, winner in specs]


def schedule():
    result, table = [], cases()
    for repetition in range(8):
        for position in range(8):
            case = (position + 3 * repetition) % 8
            order = ARMS if (case + repetition) % 2 == 0 else ARMS[::-1]
            result.append({"pair": len(result)+1, "repetition": repetition+1,
                           "case_id": table[case]["id"], "order": list(order)})
    return result


def protocol():
    return {"pairs": 64, "cases": 8, "repetitions_per_case": 8,
        "planned_controller_calls": 128, "planned_native_calls": 64,
        "same_input": "same frozen pool, allowance, objective and generation within each pair",
        "order": "eight scenario rotations; 32 ordinary-first and 32 native-first; four of each per case",
        "primary": "same specified winner; original native request, reply, identity and cleanup verified",
        "secondary": "descriptive paired complete-call wall and parent/child CPU costs",
        "timeout": "existing selector allows at most one second including native identity; not a hard OS quota",
        "failure_policy": "freeze later calls after any exception, mutation, mismatch or unsettled cleanup; no replacement, retry, warmup exclusion or sample extension",
        "cost_scope": "checked_pool_selection including native identity/sealing/process/capture; persistence is separately counted in the outer interval",
        "excluded_costs": ["prior source acquisition", "original native build", "harness authorship",
                           "provider fees", "final summary write", "artifact upload"],
        "task_scope": "authored scalar tables; quality flags and costs supplied, not observed task success",
        "statistical_scope": "within-host invocation costs; not independent training runs or a real-task cohort",
        "incremental_decision_value_established": False, "economic_benefit_established": False,
        "new_provider_calls": 0, "formal_mcp_calls": 0, "real_user_tasks": 0}


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args],
                                   env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})


def source_state(source, store):
    changed = git(source, "ls-files", "--modified", "--others", "--exclude-standard", "-z")
    files = {}
    for name in sorted(set(changed.decode().split("\0")) - {""}):
        path = source / name
        files[name] = store.put(read_bytes(path)) if path.is_file() else {"absent": True}
    return {"head": git(source, "rev-parse", "HEAD").decode().strip(),
        "tree": git(source, "rev-parse", "HEAD^{tree}").decode().strip(),
        "status_porcelain": git(source, "status", "--porcelain", "--untracked-files=all").decode(),
        "working_files": files, "source_clean_required": False,
        "scope": "base commit plus exact working files; actual execution inputs are separately frozen"}


def load_source(source):
    source = Path(source).resolve(strict=True)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source))
    from tools.qualify_hia_macro_multistep import checked_pool_selection
    from hepta.hia_ndu_optimizer import _bridge_identity
    for function in (checked_pool_selection, _bridge_identity):
        require(Path(sys.modules[function.__module__].__file__).resolve().is_relative_to(source),
                "imported execution code came from a different source")
    return checked_pool_selection, _bridge_identity


def execution_inputs(source):
    paths = {Path(__file__).resolve(), source / "tools/build_hia_ndu_bridge.py"}
    for module in list(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if filename and str(filename).endswith(".py") and Path(filename).resolve().is_relative_to(source):
            paths.add(Path(filename).resolve())
    paths.update(path for path in (source / "rust/hia-ndu-bridge").rglob("*") if path.is_file())
    return {str(path): read_bytes(path) for path in sorted(paths)}


def cpu():
    return {name: round((value.ru_utime + value.ru_stime) * 1e9)
            for name, value in ((name, resource.getrusage(kind)) for name, kind in
                (("parent", resource.RUSAGE_SELF), ("children", resource.RUSAGE_CHILDREN)))}


def environment():
    return {"python": sys.version, "executable": sys.executable, "platform": platform.platform(),
        "logical_cpus": os.cpu_count(), "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "dependencies": {name: importlib.metadata.version(name) for name in ("jsonschema", "z3-solver")},
        "clock": vars(time.get_clock_info("monotonic")),
        "scope": "reported environment; no exclusive-machine or hardware attestation"}


def prepare(args):
    started = time.monotonic_ns()
    require(sys.platform == "linux", "Linux native runner required")
    source = args.source.resolve(strict=True)
    require(git(source, "rev-parse", "HEAD").decode().strip() == args.expected_source,
            "source HEAD differs from explicit expected source")
    require(not args.output.resolve().is_relative_to(source), "evidence must be outside source checkout")
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "objects").mkdir()
    store = Store(args.output)
    _, admission = load_source(source)
    bridge = {"binary": str(args.native_binary.resolve(strict=True)),
              "build_receipt": str(args.native_build_receipt.resolve(strict=True))}
    _, identity = admission(bridge)  # No native call before the plan is frozen.
    binary, receipt = (store.put(read_bytes(bridge[key])) for key in ("binary", "build_receipt"))
    require(binary["sha256"] == identity["binary_sha256"] and
            receipt["sha256"] == identity["build_receipt_sha256"], "retained native input changed")
    objective = {"schema": SCHEMA, "objective": "same supplied conservative scalar cost",
                 "incremental_value_claim": False}
    plan = {"schema": SCHEMA, "source": str(source), "source_state": source_state(source, store),
        "harness_sha256": sha256(read_bytes(__file__)).hexdigest(),
        "execution_inputs": {path: store.put(raw) for path, raw in execution_inputs(source).items()},
        "native": {"binary": binary, "build_receipt": receipt, "identity": identity,
            "provenance": store.put(read_bytes(args.native_provenance)) if args.native_provenance else None,
            "provenance_scope": "retained caller provenance and trusted build receipt, not remote attestation"},
        "protocol": protocol(), "cases": cases(), "schedule": schedule(), "objective": objective,
        "objective_sha256": digest(objective), "environment": environment(),
        "prepared_unix_ns": time.time_ns(), "preparation_wall_ns": time.monotonic_ns()-started,
        "native_calls_at_preparation": 0}
    write_new(args.output / "PLAN.json", plan)
    return {"plan": str(args.output / "PLAN.json"),
            "plan_sha256": sha256(read_bytes(args.output / "PLAN.json")).hexdigest(),
            "pairs": 64, "native_calls": 0}


def read_plan(directory, expected_sha):
    raw = read_bytes(Path(directory) / "PLAN.json")
    require(type(expected_sha) is str and HEX.fullmatch(expected_sha)
            and sha256(raw).hexdigest() == expected_sha, "plan changed from pre-run pin")
    plan = decode(raw)
    require(plan["schema"] == SCHEMA and plan["protocol"] == protocol()
            and plan["cases"] == cases() and plan["schedule"] == schedule()
            and plan["objective_sha256"] == digest(plan["objective"]), "frozen protocol differs")
    return plan


def reference_request(case, objective, generation):
    """Reconstruct the expected request offline, without the production helper."""
    cap, pool = case["remaining_wall_ns"], case["pool"]
    valid = [item for item in pool if cap > 0 and item["quality_complete"]
             and item["remaining_cost_ns"] + item["uncertainty_ns"] <= cap]
    require(valid, "registered native case must have a feasible incumbent")
    incumbent = valid[0]["id"]
    q32 = lambda ns: round(Fraction(ns * 2**32, 1_000_000))
    rows = []
    for item in pool:
        cost = item["remaining_cost_ns"] + item["uncertainty_ns"]
        rows.append({"id": "abstain" if item["id"] == incumbent else item["id"],
            "cost_q32": q32(cost), "uncertainty_q32": 0, "resource_q32": q32(cost),
            "hard_violation": item not in valid, "support_sha256": item["support_sha256"]})
    rows.sort(key=lambda row: row["id"] != "abstain")  # Stable alternative order.
    return {"schema": "hepta.hia.ndu-request.v1", "objective_sha256": objective,
            "generation": generation, "resource_cap_q32": q32(cap), "candidates": rows}


def audit_completed(row, case, plan, store):
    """Only reads original bytes; never invokes a selector or process."""
    require(row["status"] == "completed" and row["call_error"] is None, "call did not complete")
    frozen = {"pool": case["pool"], "remaining_wall_ns": case["remaining_wall_ns"],
              "objective_sha256": plan["objective_sha256"], "generation": row["pair"]}
    require(row["input_sha256"] == digest(frozen), "cell input differs from frozen pair")
    result = decode(store.read(row["result"]))
    require(result["pool"] == case["pool"] and result["remaining_wall_ns"] == case["remaining_wall_ns"]
            and result["arm"] == row["arm"] and result["selected_id"] == case["expected_id"],
            "result differs from specified same-pool winner")
    observations = store.unpack(decode(store.read(row["observations"])))
    require(type(row["wall_ns"]) is int and row["wall_ns"] >= 0
            and row["end_offset_ns"]-row["start_offset_ns"] == row["wall_ns"]
            and set(row["cpu_ns"]) == {"parent", "children"}
            and all(type(n) is int and n >= 0 for n in row["cpu_ns"].values()), "invalid call costs")
    if row["arm"] == "ordinary":
        require(observations == [] and result["native_ndu_evaluated"] is False
                and result["native_response"] is None and result["native_identity"] is None,
                "ordinary control claimed a native evaluation")
        return result["selected_id"]
    require(row["arm"] == "ndu" and result["native_ndu_evaluated"] is True
            and len(observations) == 1, "one actual native observation required")
    native, identity = observations[0], plan["native"]["identity"]
    pump = native["pump"]
    audit_pump_wall(pump, row)
    require(native["response_admitted"] is True and native["error"] is None
            and native["native_identity"] == result["native_identity"] == identity,
            "native identity or admission differs")
    require(pump["started"] is True and type(pump["pid"]) is int
            and pump["cleanup_confirmed"] is True and pump["streams_complete"] is True
            and pump["eof"] == {"stdout": True, "stderr": True}
            and pump["returncode"] == 0 and pump["error"] is None, "native cleanup incomplete")
    request, response = result["native_request"], result["native_response"]
    require(request == reference_request(case, plan["objective_sha256"], row["pair"]),
            "native request did not use the frozen pool")
    require(native["stdin"] == wire(request) and decode(pump["stdout"]) == response,
            "raw request or reply differs from retained decision")
    require(response["request_sha256"] == sha256(native["stdin"]).hexdigest()
            and response["objective_sha256"] == plan["objective_sha256"]
            and response["generation"] == row["pair"], "native reply binding differs")
    feasible = [item for item in request["candidates"] if not item["hard_violation"]
                and item["resource_q32"] <= request["resource_cap_q32"]]
    minimum = min(item["cost_q32"] for item in feasible)
    frontier = sorted(item["id"] for item in feasible if item["cost_q32"] == minimum)
    rejected = sorted(item["id"] for item in request["candidates"] if item not in feasible)
    require(response["pareto_frontier"] == frontier
            and [item["id"] for item in response["rejected"]] == rejected, "native frontier/partition differs")
    if len(feasible) == 1:
        disposition, recommendation = "InfeasibleExplicitAbstain", "abstain"
    elif len(frontier) == 1:
        disposition, recommendation = "UniqueParetoRecommendation", frontier[0]
    else:
        disposition, recommendation = "ParetoSetRequiresSlowPath", None
    require(response["disposition"] == disposition and response["advisory_recommendation"] == recommendation
            and response["schema"] == "hepta.hia.ndu-response.v1"
            and response["upstream_commit"] == identity["upstream_commit"]
            and response["authority"] == "ADVISORY_ONLY" and response["proves_program_safety"] is False,
            "native disposition or claim scope differs")
    selection = result["selection_resolution"]
    resolved = result["feasible_incumbent_id"] if selection["selected_id"] == "abstain" else selection["selected_id"]
    require(selection["native_response_sha256"] == digest(response)
            and selection["request_sha256"] == digest(request) and resolved == case["expected_id"]
            and selection["incremental_ndu_advantage_established"] is False, "caller selection differs")
    return result["selected_id"]


def audit_pump_wall(pump, row):
    """A retained inner pump cannot outlast the complete enclosing call."""
    if pump is not None:
        require(type(pump) is dict and type(pump.get("wall_ns")) is int
                and 0 <= pump["wall_ns"] <= row["wall_ns"],
                "invalid native pump wall or pump exceeds enclosing call")


def descriptive(values):
    return {"count": len(values), "sum_ns": sum(values) if values else None,
        "mean_ns": statistics.mean(values) if values else None,
        "median_ns": statistics.median(values) if values else None,
        "min_ns": min(values) if values else None, "max_ns": max(values) if values else None,
        "sample_stdev_ns": statistics.stdev(values) if len(values) > 1 else None}


def audit_retained_attempt(row, case, plan, store):
    """Check every attempted cell, including failures and partial raw streams.

    Retaining failed bytes does not admit their decision or promote a partial
    stream to complete. A successful cell gets its semantic audit even if the
    other arm in its pair failed. Only paired timing needs two successes.
    """
    status = row["status"]
    require(status in {"not_started", "failed", "completed"}, "unknown call status")
    if status == "not_started":
        require(all(row.get(key) is None for key in ("result", "observations", "wall_ns",
                    "cpu_ns", "start_offset_ns", "end_offset_ns", "call_error", "audit_error")),
                "unstarted call contains execution observations")
        return None
    require(type(row["wall_ns"]) is int and row["wall_ns"] >= 0
            and type(row["start_offset_ns"]) is int and row["start_offset_ns"] >= 0
            and type(row["end_offset_ns"]) is int
            and row["end_offset_ns"]-row["start_offset_ns"] == row["wall_ns"]
            and type(row["cpu_ns"]) is dict and set(row["cpu_ns"]) == {"parent", "children"}
            and all(type(n) is int and n >= 0 for n in row["cpu_ns"].values()),
            "invalid attempted call costs")
    frozen = {"pool": case["pool"], "remaining_wall_ns": case["remaining_wall_ns"],
              "objective_sha256": plan["objective_sha256"], "generation": row["pair"]}
    require(row["input_sha256"] == digest(frozen), "attempt input differs from frozen pair")
    # Reading both top-level references and unpacking all nested raw references
    # is necessary: enumerating existing objects cannot detect an absent object.
    retained_result = decode(store.read(row["result"]))
    observations = store.unpack(decode(store.read(row["observations"])))
    require(type(observations) is list and all(type(item) is dict for item in observations),
            "attempt observations must be a list of original records")
    require((row["arm"] == "ordinary" and observations == [])
            or (row["arm"] == "ndu" and len(observations) <= 1),
            "unexpected native observations for attempted arm")
    for native in observations:
        require(type(native.get("stdin")) is bytes, "original request bytes missing")
        pump = native.get("pump")
        require(pump is None or (type(pump) is dict
                and type(pump.get("stdout")) is bytes and type(pump.get("stderr")) is bytes),
                "original native stream bytes missing")
        audit_pump_wall(pump, row)
    if status == "failed":
        require(type(row.get("call_error")) is dict and retained_result is None,
                "failed call must retain its error and absent result")
        return None
    require(row.get("call_error") is None, "completed call retains a call error")
    if row.get("audit_error") is not None:
        require(type(row["audit_error"]) is dict, "invalid retained audit error")
        return None
    return audit_completed(row, case, plan, store)


def results_summary(rows, plan, store):
    cases_by_id = {case["id"]: case for case in plan["cases"]}
    pairs = []
    require(len(rows) == 128, "all 128 scheduled calls must be accounted for")
    for entry in plan["schedule"]:
        found = [row for row in rows if row["pair"] == entry["pair"]]
        require([row["arm"] for row in found] == entry["order"], "missing or reordered cell")
        winners = [audit_retained_attempt(row, cases_by_id[entry["case_id"]], plan, store)
                   for row in found]
        complete = all(winner is not None for winner in winners)
        if complete:
            require(winners[0] == winners[1], "selectors disagree on identical pool")
        arms = {row["arm"]: row for row in found}
        pairs.append({**entry, "complete_and_same_choice": complete,
            "ordinary_minus_ndu_wall_ns": arms["ordinary"]["wall_ns"]-arms["ndu"]["wall_ns"] if complete else None,
            "ordinary_minus_ndu_cpu_ns": {kind: arms["ordinary"]["cpu_ns"][kind]-arms["ndu"]["cpu_ns"][kind]
                                         for kind in ("parent", "children")} if complete else None})
    attempted = [row for row in rows if row["status"] != "not_started"]
    return {"status": "MECHANISM_COMPLETE" if all(pair["complete_and_same_choice"] for pair in pairs) else "INCOMPLETE",
        "planned_pairs": 64, "planned_calls": 128, "attempted_calls": len(attempted),
        "completed_pairs": sum(pair["complete_and_same_choice"] for pair in pairs),
        "successful_native_calls": sum(row["arm"] == "ndu" and row["status"] == "completed"
            and row["audit_error"] is None for row in rows),
        "failed_calls": sum(row["status"] == "failed" or row["audit_error"] is not None for row in attempted),
        "all_attempted_call_wall_ns": {arm: descriptive([row["wall_ns"] for row in attempted if row["arm"] == arm]) for arm in ARMS},
        "all_attempted_cpu_ns": {arm: {kind: descriptive([row["cpu_ns"][kind] for row in attempted if row["arm"] == arm])
                                      for kind in ("parent", "children")} for arm in ARMS},
        "paired_ordinary_minus_ndu_wall_ns": descriptive([pair["ordinary_minus_ndu_wall_ns"] for pair in pairs if pair["complete_and_same_choice"]]),
        "pairs_favoring_ndu_wall": sum(pair["ordinary_minus_ndu_wall_ns"] > 0 for pair in pairs if pair["complete_and_same_choice"]),
        "pairs": pairs, "cost_interpretation": "descriptive within-host complete-call costs; no downstream benefit or population inference",
        "incremental_decision_value_established": False, "stable_total_benefit_established": False,
        "economic_benefit_established": False, "global_full_cost_complete": False, "money": None,
        "model_calls": 0, "real_user_tasks": 0, "formal_mcp_calls": 0}


def error_record(error):
    return {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}


def run(args):
    root = args.directory.resolve(strict=True)
    store, plan = Store(root), read_plan(root, args.expected_plan_sha256)
    started, cpu_before = time.monotonic_ns(), cpu()
    write_new(root / "RUN-STARTED.json", {"plan_sha256": args.expected_plan_sha256,
        "unix_ns": time.time_ns(), "monotonic_ns": started, "pid": os.getpid()})
    rows, halted, admitted = [], None, False
    source = Path(plan["source"])
    bridge = {key: str(root / plan["native"][key]["path"]) for key in ("binary", "build_receipt")}
    try:
        require(sha256(read_bytes(__file__)).hexdigest() == plan["harness_sha256"], "harness changed after freeze")
        require(environment() == plan["environment"], "execution environment changed after freeze")
        require(git(source, "rev-parse", "HEAD").decode().strip() == plan["source_state"]["head"], "source HEAD changed")
        for path, ref in plan["execution_inputs"].items():
            require(read_bytes(path) == store.read(ref), "frozen execution input changed: " + path)
        selector, admission = load_source(source)
        require(set(execution_inputs(source)) == set(plan["execution_inputs"]), "import closure changed")
        _, identity = admission(bridge)
        require(identity == plan["native"]["identity"], "retained native admission differs")
        admitted = True
    except BaseException as error:
        halted = {"phase": "initial_admission", **error_record(error)}
    cases_by_id = {case["id"]: case for case in plan["cases"]}
    for entry in plan["schedule"]:
        case = cases_by_id[entry["case_id"]]
        original = {"pool": case["pool"], "remaining_wall_ns": case["remaining_wall_ns"],
                    "objective_sha256": plan["objective_sha256"], "generation": entry["pair"]}
        for position, arm in enumerate(entry["order"], 1):
            row = {"pair": entry["pair"], "case_id": case["id"], "position": position, "arm": arm,
                "input_sha256": digest(original), "status": "not_started", "wall_ns": None,
                "cpu_ns": None, "start_offset_ns": None, "end_offset_ns": None,
                "result": None, "observations": None, "call_error": None, "audit_error": None}
            if halted is None:
                supplied, observations, result = deepcopy(original), [], None
                before, call_start = cpu(), time.monotonic_ns()
                try:
                    result = selector(arm, **supplied, bridge=bridge, observer=observations.append)
                    row["status"] = "completed"
                except BaseException as error:
                    row.update(status="failed", call_error=error_record(error))
                call_end, after = time.monotonic_ns(), cpu()
                row.update(wall_ns=call_end-call_start, start_offset_ns=call_start-started,
                    end_offset_ns=call_end-started, cpu_ns={key: after[key]-before[key] for key in before},
                    result=store.json(result), observations=store.json(store.pack(observations)))
                try:
                    require(supplied == original, "controller mutated frozen input")
                    audit_completed(row, case, plan, store)
                except BaseException as error:
                    row["audit_error"] = error_record(error)
                    halted = {"phase": "call_or_audit", "pair": row["pair"], "arm": arm,
                              "call_error": row["call_error"], "audit_error": row["audit_error"]}
            else:
                row["not_started_reason"] = halted
            rows.append(row)
            write_new(root / f"cell-{row['pair']:02d}-{arm}.json", row)
        if entry["pair"] % 8 == 0:
            print(json.dumps({"pairs_accounted": entry["pair"], "halted": halted is not None}), flush=True)
    unchanged = False
    try:
        require(admitted, "initial source/native admission failed")
        require(git(source, "rev-parse", "HEAD").decode().strip() == plan["source_state"]["head"], "source HEAD changed during execution")
        for path, ref in plan["execution_inputs"].items():
            require(read_bytes(path) == store.read(ref), "execution input changed: " + path)
        _, final_identity = admission(bridge)
        require(final_identity == plan["native"]["identity"], "native identity changed during execution")
        unchanged = True
    except BaseException as error:
        halted = halted or {"phase": "final_identity", **error_record(error)}
    after_state = source_state(source, store)
    report = results_summary(rows, plan, store)
    end, cpu_after = time.monotonic_ns(), cpu()
    call_wall = sum(row["wall_ns"] for row in rows if row["wall_ns"] is not None)
    report.update(schema=SCHEMA, plan_sha256=args.expected_plan_sha256,
        source_state_after=after_state, execution_inputs_unchanged=unchanged, halted_reason=halted, cells=rows,
        measurement={"outer_wall_ns_to_summary_preparation": end-started,
            "all_attempted_call_wall_ns": call_wall, "admission_capture_export_audit_wall_ns": end-started-call_wall,
            "outer_cpu_ns": {key: cpu_after[key]-cpu_before[key] for key in cpu_before},
            "native_build_included": False, "final_summary_write_included": False, "nested_costs_added_again": False})
    if halted is not None or not unchanged:
        report["status"] = "INCOMPLETE"
    write_new(root / "SUMMARY.json", report)
    return {"status": report["status"], "summary": str(root / "SUMMARY.json"),
            "paired_ordinary_minus_ndu_wall_ns": report["paired_ordinary_minus_ndu_wall_ns"],
            "economic_benefit_established": False}


def verify(args):
    root = args.directory.resolve(strict=True)
    store, plan = Store(root), read_plan(root, args.expected_plan_sha256)
    marker = decode(read_bytes(root / "RUN-STARTED.json"))
    require(marker["plan_sha256"] == args.expected_plan_sha256, "run marker differs")
    summary = decode(read_bytes(root / "SUMMARY.json"))
    require(summary["schema"] == SCHEMA and summary["plan_sha256"] == args.expected_plan_sha256, "summary plan differs")
    rows = []
    for pair in plan["schedule"]:
        for position, arm in enumerate(pair["order"], 1):
            row = decode(read_bytes(root / f"cell-{pair['pair']:02d}-{arm}.json"))
            require(row["pair"] == pair["pair"] and row["arm"] == arm
                    and row["case_id"] == pair["case_id"] and row["position"] == position, "cell schedule differs")
            rows.append(row)
    require(wire(summary["cells"]) == wire(rows), "summary differs from original cells")
    recomputed = results_summary(rows, plan, store)
    for key, value in recomputed.items():
        if key == "status" and (summary["halted_reason"] is not None or not summary["execution_inputs_unchanged"]):
            value = "INCOMPLETE"
        require(wire(summary[key]) == wire(value), "summary recomputation differs: " + key)
    attempted = [row for row in rows if row["status"] != "not_started"]
    require(all(a["end_offset_ns"] <= b["start_offset_ns"] for a, b in zip(attempted, attempted[1:])), "call intervals overlap")
    costs = summary["measurement"]
    require(all(type(costs[name]) is int and costs[name] >= 0 for name in (
        "outer_wall_ns_to_summary_preparation", "all_attempted_call_wall_ns",
        "admission_capture_export_audit_wall_ns")), "invalid outer cost integers")
    require(all(row["end_offset_ns"] <= costs["outer_wall_ns_to_summary_preparation"]
                for row in attempted), "attempted call ends outside the measured outer interval")
    require(sum(row["wall_ns"] for row in attempted) == costs["all_attempted_call_wall_ns"]
            and costs["outer_wall_ns_to_summary_preparation"] == costs["all_attempted_call_wall_ns"] + costs["admission_capture_export_audit_wall_ns"]
            and costs["admission_capture_export_audit_wall_ns"] >= 0, "outer cost accounting differs")
    objects = 0
    for path in (root / "objects").iterdir():
        require(HEX.fullmatch(path.name) and sha256(read_bytes(path)).hexdigest() == path.name, "stored object integrity failure")
        objects += 1
    for ref in plan["execution_inputs"].values():
        store.read(ref)
    native = plan["native"]
    binary, receipt = store.read(native["binary"]), decode(store.read(native["build_receipt"]))
    require(sha256(binary).hexdigest() == native["identity"]["binary_sha256"] == receipt["binary_sha256"], "native binary differs from original build")
    require(native["build_receipt"]["sha256"] == native["identity"]["build_receipt_sha256"], "build receipt identity differs")
    if native["provenance"] is not None:
        store.read(native["provenance"])
    result = {"schema": SCHEMA, "verification": "ORIGINAL_BYTES_AND_ACCOUNTING_VERIFIED",
        "campaign_status": summary["status"], "plan_sha256": args.expected_plan_sha256,
        "summary_sha256": sha256(read_bytes(root / "SUMMARY.json")).hexdigest(),
        "objects_verified": objects, "scheduled_cells_verified": len(rows),
        "completed_pairs": summary["completed_pairs"], "successful_native_calls": summary["successful_native_calls"],
        "new_native_calls": 0, "new_provider_calls": 0, "economic_benefit_established": False,
        "scope": "independent original-byte replay; trusted local timing/process receipts, not remote/hardware attestation"}
    if args.output:
        write_new(args.output, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("prepare")
    freeze.add_argument("--source", type=Path, required=True)
    freeze.add_argument("--expected-source", required=True)
    freeze.add_argument("--native-binary", type=Path, required=True)
    freeze.add_argument("--native-build-receipt", type=Path, required=True)
    freeze.add_argument("--native-provenance", type=Path)
    freeze.add_argument("--output", type=Path, required=True)
    for name in ("run", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--directory", type=Path, required=True)
        command.add_argument("--expected-plan-sha256", required=True)
        if name == "verify":
            command.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = {"prepare": prepare, "run": run, "verify": verify}[args.command](args)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 2 if result.get("status") == "INCOMPLETE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
