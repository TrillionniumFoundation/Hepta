#!/usr/bin/env python3
"""Retain finite return-loan, cross-file, allocator and trap observations.

Native allocation events come from an independently compiled C linker wrapper.
Native loans are erased, so their lifetimes are checked by Core and compared in
the Python and optional Rust interpreters, not claimed as native telemetry.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_call_expansion import (build_expanded_native, propose_leaf_call_expansion,
                                     verify_leaf_call_expansion)
from hepta.hia_native_differential import _pin_native_artifact, _check_artifact_unchanged
from hepta.hia_optimization_contract import POLICY_SCHEMA, qualify_expansion_contract
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_static_budget import HIAStaticBudgetRejected
from tests.test_hia_call_return_lifetimes import (
    comparable, cross_module_source, loop_returned_loan, observe, trap_after_returned_loan,
)
from tests.test_hia_returned_loans import (
    fallible_return_program, loan_program, multiple_shared, swapped_mutable,
)

TYPES = {"u8": "uint8_t", "u64": "uint64_t", "usize": "uint64_t"}
OBSERVER = ROOT / "examples/hia_call_return_lifetimes/allocator_observer.c"


def save(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_manifest():
    paths = [*sorted((ROOT / "hepta").glob("*.py")), Path(__file__),
             ROOT / "tests/test_hia_call_return_lifetimes.py", ROOT / "tests/test_hia_returned_loans.py",
             ROOT / "tests/test_hia_program.py", *sorted(OBSERVER.parent.glob("*"))]
    return {str(path.relative_to(ROOT)): digest(path) for path in paths if path.is_file()}


def profiles():
    rows = [(mode + "_forward", loan_program(mode, "forward"), "entry_" + mode + "_forward",
             [[n, byte] for n in (0, 1, 3) for byte in (0, 71, 255)], [None, 1, 2])
            for mode in ("read", "mut")]
    rows += [("shared_" + construction, multiple_shared(construction), "shared",
              [[byte] for byte in (0, 71, 255)], [None, 1, 2])
             for construction in ("forward", "mixed", "children")]
    rows += [("swapped", swapped_mutable(), "swapped", [[]], [None, 1, 2, 3]),
             ("fallible", fallible_return_program(), "fallible_entry", [[]], [None, 1, 2, 3]),
             ("loop", loop_returned_loan(), "repeat", [[n, 71] for n in (0, 1, 17)], [None, 1, 2]),
             ("cross_module", cross_module_source(), "cross_module",
              [[n, byte, cancel] for n in (0, 1, 3) for byte in (0, 71, 255) for cancel in (0, 1)], [None, 1, 2])]
    rows += [("trap_" + mode, trap_after_returned_loan(mode), "entry_" + mode + "_forward",
              [[1, 71]], [None, 1, 2]) for mode in ("read", "mut")]
    return rows


def oracle(name, args, failure):
    size = args[0] if name in {"read_forward", "mut_forward", "cross_module"} else 1
    if size and failure == 1 or name == "swapped" and failure == 2:
        return "trapped", "allocation"
    if name in {"read_forward", "mut_forward"}:
        return ("returned", (args[1] + (5 if name == "mut_forward" else 0)) % 256) if size else ("trapped", "bounds")
    if name.startswith("shared_"):
        return "returned", args[0] * 2 % 256
    if name == "swapped":
        return "returned", 28
    if name == "fallible":
        return "returned", 0 if failure == 2 else 1
    if name == "loop":
        return "returned", args[0] * args[1]
    if name == "cross_module":
        return ("returned", 0) if args[2] else ("returned", args[1] ^ 90) if size else ("trapped", "bounds")
    if name.startswith("trap_"):
        return "trapped", "bounds"
    raise AssertionError("unregistered independent oracle")


def build_observer(folder, label, original, proposal, core, entry, clang):
    object_path = folder / (label + ".o")
    start = time.monotonic_ns()
    receipt = ({"native": build_program_native(core, object_path, clang=clang, kind="object")}
               if label == "original" else build_expanded_native(original, proposal, object_path, clang=clang, kind="object"))
    if digest(object_path) != receipt["native"]["artifact_sha256"]:
        raise AssertionError("published object differs from its build receipt")
    fn = next(fn for fn in core.as_dict()["functions"] if fn["name"] == entry)
    result = TYPES[fn["returns"][0]]
    parameters = [TYPES[p["type"]] for p in fn["params"]]
    signature = result + " " + entry + "(" + (", ".join(parameters) or "void") + ");"
    arguments = ["(" + typ + ")strtoull(argv[" + str(index + 2) + "], NULL, 10)"
                 for index, typ in enumerate(parameters)]
    call = ("if (argc != " + str(len(parameters) + 2) + ") return 64;\n"
            "    refuse_at = strtoull(argv[1], NULL, 10);\n"
            "    uint64_t result = " + entry + "(" + ", ".join(arguments) + ");")
    driver = folder / (label + ".observer.c")
    driver.write_text(OBSERVER.read_text().replace("/* ENTRY_DECLARATION */", signature)
                      .replace("/* ENTRY_CALL */", call))
    binary = folder / (label + ".observer")
    command = [clang, "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
               *["-Wl,--wrap=" + symbol for symbol in ("malloc", "calloc", "free", "abort")],
               str(driver), str(object_path), "-o", str(binary)]
    process = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if process.returncode:
        raise AssertionError(process.stderr)
    if digest(object_path) != receipt["native"]["artifact_sha256"]:
        raise AssertionError("receipt-bound object changed during observer link")
    record = {"receipt": receipt, "observer_source_sha256": digest(driver), "command": command,
              "executable_sha256": digest(binary), "compile_link_wall_ns": time.monotonic_ns() - start}
    save(folder / (label + ".build.json"), record)
    return binary, record


def native_cases(binary, build, rows):
    data, identity, descriptor = _pin_native_artifact(binary)
    if hashlib.sha256(data).hexdigest() != build["executable_sha256"]:
        raise AssertionError("observer executable changed before sealing")
    observations = []
    try:
        for row in rows:
            command = ["/proc/self/fd/" + str(descriptor), str(row["allocation_fail_at"] or 0),
                       *[str(value) for value in row["arguments"]]]
            process = subprocess.run(command, pass_fds=(descriptor,), env={"LC_ALL": "C"},
                                     capture_output=True, text=True, timeout=5)
            expected = row["python"]["original"]
            code = 0 if expected["status"] == "returned" else -signal.SIGABRT
            if process.returncode != code or process.stderr:
                raise AssertionError(("native observer outcome", row, process.returncode, process.stderr))
            observed = json.loads(process.stdout)
            if observed["status"] != expected["status"] or observed["bad_frees"]:
                raise AssertionError(("native status or ownership", observed, expected))
            if observed["status"] == "returned" and observed["result"] != expected["result"]:
                raise AssertionError(("native return", observed, expected))
            for native, vm in (("attempts", "allocation_attempts"), ("allocations", "allocations"),
                               ("frees", "frees"), ("live_bytes", "live_bytes"), ("peak_bytes", "peak_bytes")):
                if observed[native] != expected["resources"][vm]:
                    raise AssertionError(("actual native allocation counter", native, observed, expected))
            observations.append({"returncode": process.returncode, "observation": observed})
        _check_artifact_unchanged(binary, data, identity)
    finally:
        os.close(descriptor)
    return observations


def rust_observation(binary, core, entry, args, fail):
    command = [str(binary), "--owned-run", entry, json.dumps(args), "1000000", "1048576",
               "none" if fail is None else str(fail)]
    process = subprocess.run(command, input=core.canonical_bytes, capture_output=True, timeout=10)
    if process.returncode or process.stderr:
        raise AssertionError(("Rust shadow process", process.returncode, process.stderr.decode()))
    report = json.loads(process.stdout)
    if report["program_sha256"] != core.sha256:
        raise AssertionError("Rust execution names a different Core")
    return report


def qualify_profile(out, profile, clang, rust_shadow):
    name, base, entry, cases, failures = profile
    folder = out / name
    folder.mkdir()
    original = verify_program(base)
    started = time.monotonic_ns()
    proposal = propose_leaf_call_expansion(original)
    proof = verify_leaf_call_expansion(original, proposal)
    if proof["status"] != "verified":
        raise AssertionError(proof)
    candidate = verify_program(proposal["candidate_core"])
    save(folder / "original.core.json", original.as_dict())
    save(folder / "proposal.json", proposal)
    save(folder / "proof.json", proof)
    rows = []
    for args in cases:
        for fail in failures:
            pair = {label: observe(core, entry, args, allocation_fail_at=fail,
                                  max_steps=1000000, max_heap_bytes=1048576, max_call_depth=32)
                    for label, core in (("original", original), ("candidate", candidate))}
            if comparable(pair["original"]) != comparable(pair["candidate"]):
                raise AssertionError((name, args, fail, pair))
            expected_status, expected = oracle(name, args, fail)
            observed = pair["original"]
            if observed["status"] != expected_status or (observed["result"] if expected_status == "returned"
                    else observed["error"]["code"]) != expected:
                raise AssertionError(("independent oracle", name, args, fail, observed))
            row = {"arguments": args, "allocation_fail_at": fail, "python": pair}
            if rust_shadow:
                row["rust"] = {}
                for label, core in (("original", original), ("candidate", candidate)):
                    rust = rust_observation(rust_shadow, core, entry, args, fail)
                    if comparable(rust) != comparable(pair[label]) or rust["steps"] != pair[label]["steps"]:
                        raise AssertionError(("independent Rust interpreter", name, label, args, fail, rust, pair[label]))
                    row["rust"][label] = rust
            rows.append(row)
    save(folder / "vm.json", rows)
    native = {}
    for label, core in (("original", original), ("candidate", candidate)):
        binary, build = build_observer(folder, label, original, proposal, core, entry, clang)
        native[label] = native_cases(binary, build, rows)
    if native["original"] != native["candidate"]:
        raise AssertionError("original and expanded native event prefixes differ")
    save(folder / "native.json", native)
    success = next((row for row in rows if row["allocation_fail_at"] is None
                    and row["python"]["original"]["status"] == "returned"), None)
    if success:
        try:
            contract = qualify_expansion_contract(original, proposal, function=entry, arguments=success["arguments"],
                policy={"schema": POLICY_SCHEMA, "budget_mode": "both_fit_same_quotas", "max_allocator_interactions": 64,
                        "max_vm_ticks": 4096, "max_call_depth": 2, "max_live_heap_bytes": 4})
        except HIAStaticBudgetRejected as error:
            if name != "loop" or error.code != "E_HIA_BUDGET_UNBOUNDED":
                raise
            contract = {"status": "refused", "code": error.code, "reason": str(error),
                        "finite_observations_establish_a_static_loop_bound": False}
        save(folder / "resource-contract.json", contract)
    result = {"profile": name, "function": entry, "cases": len(rows), "call_sites": len(proposal["sites"]),
              "original_sha256": original.sha256, "candidate_sha256": candidate.sha256,
              "native_executions": 2 * len(rows), "rust_executions": 2 * len(rows) if rust_shadow else 0,
              "trapping_native_executions": 2 * sum(row["returncode"] != 0 for row in native["original"]),
              "exact_native_allocator_events_match": True, "wall_ns": time.monotonic_ns() - started}
    save(folder / "RESULT.json", result)
    return result


def negative_controls(out):
    records = []
    for name, source in (("erase_boundary_loan", loan_program("read", "forward")), ("wrong_origin", swapped_mutable())):
        original = verify_program(source)
        proposal = deepcopy(propose_leaf_call_expansion(original))
        operations = proposal["candidate_core"]["functions"][1]["blocks"][0]["ops"]
        if name == "erase_boundary_loan":
            boundary = next(op for op in operations if op["op"] == "borrow.read" and op["args"] == ["parent"])
            child = boundary["out"][0]["name"]
            operations[:] = [op for op in operations if op is not boundary and
                             not (op["op"] == "loan.end" and op["args"] == [child])]
            for op in operations:
                op["args"] = ["parent" if arg == child else arg for arg in op["args"]]
            entry, args = "entry_read_forward", [1, 71]
        else:
            boundaries = [op for op in operations if op["op"] == "borrow.mut" and op["args"][0] in {"left", "right"}]
            boundaries[0]["args"], boundaries[1]["args"] = boundaries[1]["args"], boundaries[0]["args"]
            entry, args = "swapped", []
        candidate = verify_program(proposal["candidate_core"])
        proof = verify_leaf_call_expansion(original, proposal)
        if proof["status"] != "rejected":
            raise AssertionError("a resource-valid semantic counterexample received an expansion proof")
        records.append({"name": name, "core_valid": True, "proposal": proposal, "proof": proof,
                        "original": observe(original, entry, args), "counterexample": observe(candidate, entry, args)})
    save(out / "negative-controls.json", records)
    return len(records)


def run(output, clang, rust_shadow=None):
    out = Path(output).absolute()
    out.mkdir(parents=True, exist_ok=False)
    manifest = source_manifest()
    rust = {"path": str(Path(rust_shadow).absolute()), "sha256": digest(rust_shadow)} if rust_shadow else None
    planned = profiles()
    save(out / "PLAN.json", {"source_sha256": manifest, "rust_shadow": rust,
                              "profiles": [{"name": row[0], "cases": len(row[3]) * len(row[4])} for row in planned],
                              "oracle": "independent arithmetic answers, VM full resource ledgers, wrapped native allocations",
                              "native_observer_events": {"0": "attempt", "1": "failed", "2": "allocated", "3": "free",
                                                         "4": "actual abort", "5": "null free"}})
    try:
        reports = [qualify_profile(out, row, clang, rust_shadow) for row in planned]
        negatives = negative_controls(out)
        stable = source_manifest() == manifest and (rust is None or digest(rust["path"]) == rust["sha256"])
        if not stable:
            raise AssertionError("qualification sources or independent Rust executable changed")
        result = {"schema": "hepta.hia.return-loan-expansion-qualification.v1", "status": "passed",
                  "sources_unchanged": True, "profiles": reports, "negative_controls": negatives,
                  "claims": {"finite_registered_cases_match": True, "actual_native_allocator_events_observed": True,
                             "independent_rust_execution_observed": rust is not None,
                             "native_loan_counters_observed": False, "all_input_backend_refinement_proved": False,
                             "asynchronous_cancellation_or_unwinding_proved": False,
                             "vm_budget_stop_equivalence": False, "performance_superiority_qualified": False}}
        save(out / "RESULT.json", result)
        return result
    except Exception as error:
        save(out / "FAILURE.json", {"type": type(error).__name__, "message": str(error),
                                   "sources_unchanged": source_manifest() == manifest})
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--rust-shadow")
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.clang, args.rust_shadow), sort_keys=True))
