#!/usr/bin/env python3
"""Execute sealed artifacts after independent resource-call and loop checks.

The finite corpus is a qualification observation, not backend refinement. A
component Core can be added from the separate actual C++ capture qualifier;
that qualifier, not this pass, establishes its finite source/original oracle.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_call_expansion import (propose_leaf_call_expansion, build_expanded_native,
    propose_expanded_guarded, build_expanded_guarded_native, expanded_guarded_program)
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramTrap
from hepta.hia_program_llvm import build_program_native
from hepta.hia_native_differential import _pin_native_artifact, _check_artifact_unchanged
from tests.test_hia_call_expansion import loop_resources, checked_loop_resources, bundle_call, loan_call

TYPES = {"u8", "u16", "u32", "u64", "usize", "i8", "i16", "i32", "i64", "isize", "bool"}
RETURN_WORKER = """import ctypes,json,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_CPU,(2,2))
resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2))
resource.setrlimit(resource.RLIMIT_FSIZE,(1024**2,1024**2))
t={'u8':ctypes.c_uint8,'u16':ctypes.c_uint16,'u32':ctypes.c_uint32,'u64':ctypes.c_uint64,
'usize':ctypes.c_uint64,'i8':ctypes.c_int8,'i16':ctypes.c_int16,'i32':ctypes.c_int32,
'i64':ctypes.c_int64,'isize':ctypes.c_int64,'bool':ctypes.c_bool}
d=json.loads(sys.argv[3]);f=getattr(ctypes.CDLL(sys.argv[1]),sys.argv[2])
f.argtypes=[t[x] for x in d['params']];f.restype=t[d['result']]
print(json.dumps([f(*args) for args in d['cases']],separators=(',',':')))
"""
TRAP_WORKER = """import ctypes,json,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_CPU,(2,2))
resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2))
resource.setrlimit(resource.RLIMIT_FSIZE,(4096,4096))
t={'usize':ctypes.c_uint64,'u8':ctypes.c_uint8}
f=getattr(ctypes.CDLL(sys.argv[1]),sys.argv[2]);f.argtypes=[t['usize']];f.restype=t['u8']
print(json.dumps(f(int(sys.argv[3]))))
"""


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def save(path, value):
    with Path(path).open("xb") as stream:
        stream.write(wire(value))


def source_manifest():
    paths = [*sorted((ROOT / "hepta").glob("*.py")), Path(__file__), ROOT / "tests/test_hia_call_expansion.py",
             ROOT / "tests/test_hia_program.py", ROOT / "tests/test_hia_program_composite.py"]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def observe(core, function, args, fail_at=None):
    try:
        result = execute_program(core, function, args, allocation_fail_at=fail_at)
        return {"status": "value", "value": result["result"], "resources": result["resources"]}
    except HIAProgramTrap as error:
        return {"status": "trap", "code": error.code, "resources": error.report["resources"]}


def run_case_profile(out, name, base, function, cases, clang, *, guarded=False):
    folder = out / name
    folder.mkdir()
    original = verify_program(base)
    proposal = propose_expanded_guarded(original, maximum=16) if guarded else propose_leaf_call_expansion(original)
    candidate = expanded_guarded_program(original, proposal) if guarded else verify_program(proposal["candidate_core"])
    save(folder / "original.core.json", original.as_dict())
    save(folder / "proposal.json", proposal)
    save(folder / "candidate.core.json", candidate.as_dict())
    save(folder / "cases.json", cases)
    rows = []
    for args in cases:
        before, after = observe(original, function, args), observe(candidate, function, args)
        if before != after:
            raise AssertionError((name, args, before, after))
        if name in {"loop", "guarded_loop"} and before["status"] == "value":
            if before["value"] != sum(k % 256 for k in range(args[0])):
                raise AssertionError("independent mathematical reduction oracle differs")
        if name == "composite" and before["value"] != 2 * args[0]:
            raise AssertionError("independent composite length oracle differs")
        rows.append({"arguments": args, "observation": before})
    if name == "captured_cpp_component" and not any(
            row["observation"].get("value") == 4001 for row in rows):
        raise AssertionError("registered callback-error path was not observed")
    failures = []
    for args in cases[:4]:
        for fail_at in (1, 2):
            before, after = observe(original, function, args, fail_at), observe(candidate, function, args, fail_at)
            if before != after:
                raise AssertionError((name, args, fail_at, before, after))
            failures.append({"arguments": args, "fail_at": fail_at, "observation": before})
    records = []
    for label, core in (("original", original), ("candidate", candidate)):
        destination = folder / (label + ".so")
        started = time.monotonic_ns()
        if label == "original":
            native = build_program_native(core, destination, clang=clang)
            receipt = {"native": native}
        else:
            builder = build_expanded_guarded_native if guarded else build_expanded_native
            receipt = builder(original, proposal, destination, clang=clang)
            native = receipt["native"]
        build_ns = time.monotonic_ns() - started
        save(folder / (label + ".build.json"), receipt)
        data, identity, descriptor = _pin_native_artifact(destination)
        if hashlib.sha256(data).hexdigest() != native["artifact_sha256"]:
            raise AssertionError("executed sealed bytes differ from bound artifact")
        fn = next(fn for fn in core.as_dict()["functions"] if fn["name"] == function)
        if len(fn["returns"]) != 1 or fn["returns"][0] not in TYPES:
            raise ValueError("qualification requires one scalar result")
        actual = []
        started = time.monotonic_ns()
        try:
            ordinary = [row for row in rows if row["observation"]["status"] == "value"]
            payload = {"params": [p["type"] for p in fn["params"]], "result": fn["returns"][0],
                       "cases": [row["arguments"] for row in ordinary]}
            process = subprocess.run([sys.executable, "-I", "-S", "-c", RETURN_WORKER,
                "/proc/self/fd/" + str(descriptor), function, json.dumps(payload, separators=(",", ":"))],
                pass_fds=(descriptor,), env={"LC_ALL": "C"}, capture_output=True, timeout=5)
            if process.returncode != 0 or process.stderr:
                raise AssertionError(("native return worker failed", process.returncode, process.stderr.decode(errors="replace")))
            answers = json.loads(process.stdout)
            if answers != [row["observation"]["value"] for row in ordinary]:
                raise AssertionError("native batch differs from all registered return observations")
            values = iter(answers)
            for row in rows:
                args, expected = row["arguments"], row["observation"]
                if expected["status"] == "trap":
                    if name != "borrowed":
                        raise ValueError("unregistered native trap case")
                    process = subprocess.run([sys.executable, "-I", "-S", "-c", TRAP_WORKER,
                        "/proc/self/fd/" + str(descriptor), function, str(args[0])],
                        pass_fds=(descriptor,), env={"LC_ALL": "C"},
                        capture_output=True, timeout=5)
                    if process.returncode != -signal.SIGABRT or process.stdout or process.stderr:
                        raise AssertionError("native trap differs from the registered silent abort")
                    value = {"status": "trap", "signal": "SIGABRT"}
                else:
                    answer = next(values)
                    value = {"status": "value", "value": answer}
                actual.append({"arguments": args, "native": value})
            _check_artifact_unchanged(destination, data, identity)
        finally:
            os.close(descriptor)
        record = {"label": label, "core_sha256": core.sha256, "artifact_sha256": native["artifact_sha256"],
                  "sealed_bytes_loaded": True, "proof_compile_publish_ns": build_ns,
                  "finite_execution_wall_ns": time.monotonic_ns() - started, "observations": actual}
        records.append(record)
    report = {"profile": name, "function": function, "original_sha256": original.sha256,
              "candidate_sha256": candidate.sha256, "semantic_cases": len(rows),
              "vm_failure_injection_cases": len(failures), "observations": rows,
              "failure_injections": failures, "native": records,
              "claims": {"finite_observations_match": True, "ordered_core_resources_preserved": True,
                         "native_allocation_trace_observed": False, "backend_refinement_proved": False,
                         "performance_qualified": False, "vm_budget_failures_preserved": False}}
    save(folder / "RESULT.json", report)
    return report


def run(output, clang, component_core=None):
    started = time.monotonic_ns()
    out = Path(output).absolute()
    out.mkdir(parents=True, exist_ok=False)
    sources = source_manifest()
    inputs = [("loop", loop_resources(), "run", [[n] for n in (0, 1, 2, 15, 16, 17, 255, 256, 257, 1025)], False),
              ("guarded_loop", checked_loop_resources(), "run", [[n] for n in (0, 1, 2, 15, 16, 17, 255, 256, 257, 1025)], True),
              ("composite", bundle_call(), "bundle", [[n] for n in (0, 1, 2, 31, 257)], False),
              ("borrowed", loan_call(), "use", [[0], [1], [2**64 - 1]], False)]
    component = None
    component_payload = None
    if component_core is not None:
        path = Path(component_core).resolve(strict=True)
        component_payload = path.read_bytes()
        component = {"path": str(path), "sha256": hashlib.sha256(component_payload).hexdigest()}
        cases = [list(row) for row in itertools.product((0, 1, 7), (0, 1, 5), (0, 255), (0, 1, 7), range(4), range(4))]
        inputs.append(("captured_cpp_component", json.loads(component_payload), "composed_case", cases, False))
    save(out / "PLAN.json", {"schema": "hepta.hia.call-expansion-qualification.v1", "source_sha256": sources,
        "component_core": component, "planned_profiles": [{"name": row[0], "cases": len(row[3]), "guarded": row[4]} for row in inputs],
        "started_unix_ns": time.time_ns(), "native_execution": "sealed Linux memfd of receipt-bound bytes",
        "scope": "finite behavior observations, checked expansion and guarded-loop proofs; no performance claim"})
    try:
        reports = [run_case_profile(out, name, base, function, cases, clang, guarded=guarded)
                   for name, base, function, cases, guarded in inputs]
    except Exception as error:
        save(out / "FAILURE.json", {"type": type(error).__name__, "message": str(error),
             "wall_ns": time.monotonic_ns() - started, "sources_unchanged": source_manifest() == sources})
        raise
    component_stable = component is None or Path(component["path"]).read_bytes() == component_payload
    stable = source_manifest() == sources and component_stable
    report = {"schema": "hepta.hia.call-expansion-qualification.v1", "status": "passed" if stable else "source_drift",
              "sources_unchanged": stable, "component_input_unchanged": component_stable,
              "profiles": [{"name": row["profile"], "semantic_cases": row["semantic_cases"],
                  "vm_failure_injection_cases": row["vm_failure_injection_cases"],
                  "native_observations": sum(len(n["observations"]) for n in row["native"])} for row in reports],
              "total_wall_ns": time.monotonic_ns() - started,
              "claims": {"safety_theorem": False, "backend_refinement_proved": False, "performance_qualified": False}}
    save(out / "RESULT.json", report)
    if not stable:
        raise RuntimeError("source identity changed during qualification")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--component-core")
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.clang, args.component_core), sort_keys=True))


if __name__ == "__main__":
    main()
