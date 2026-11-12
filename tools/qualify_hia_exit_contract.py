"""Exercise the shared exit contract with an explicitly pinned Rust executable.

This tool does not build Rust. It preserves actual process observations, finite
Python/Rust comparisons, transformation outcomes and captured-response negative
controls. The caller supplies the executable SHA-256; reuse is never described
as a fresh build or a source-to-binary attestation.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta import hia_rust_crosscheck as transport
from hepta.hia_call_expansion import propose_leaf_call_expansion
from hepta.hia_optimization_contract import execute_contracted_expansion
from hepta.hia_rust_byte_dag import HIARustByteDagRejected, execute_rust_byte_dag
from hepta.hia_static_budget import analyze_static_budget
from tests.test_hia_execution_contract import held_program, observe
from tests.test_hia_optimization_contract import cleanup_module, policy


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def projection(result):
    common = {key: result[key] for key in ("status", "steps", "resources")}
    if result["status"] == "returned":
        common["values"] = result["values"]
    else:
        common["error_code"] = result["error"]["code"]
    return common


def qualify(executable, digest, output, prior_manifest=None):
    executable, output = Path(executable).resolve(), Path(output)
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None or sha256(executable.read_bytes()).hexdigest() != digest:
        raise ValueError("explicit Rust executable SHA-256 differs")
    output.mkdir(parents=True, exist_ok=True)
    rust_sources = sorted((ROOT / "rust/hia-core-shadow/src").rglob("*.rs"))
    rust_sources += [ROOT / "rust/hia-core-shadow/Cargo.toml", ROOT / "rust/hia-core-shadow/Cargo.lock"]
    source_hashes = {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest() for path in rust_sources}
    prior = None
    if prior_manifest is not None:
        prior_manifest = Path(prior_manifest)
        frozen = json.loads(prior_manifest.read_text())["source_sha256"]
        if any(frozen.get(name) != digest for name, digest in source_hashes.items()):
            raise ValueError("current Rust source/lock closure differs from the supplied prior source manifest")
        prior = {"path": str(prior_manifest), "sha256": sha256(prior_manifest.read_bytes()).hexdigest(),
                 "current_rust_source_lock_closure_matches": True,
                 "source_to_binary_rebuild_verified_this_run": False}

    processes, cases, refusals, transforms = [], [], [], []
    real_transport = transport._run_pinned_shadow

    def record(binary, argv, payload, timeout, **kwargs):
        stdout, stderr, code = real_transport(binary, argv, payload, timeout, **kwargs)
        processes.append({"argv_after_pinned_executable": argv, "stdin_utf8": payload.decode(),
            "stdin_sha256": sha256(payload).hexdigest(), "executable_sha256": sha256(binary).hexdigest(),
            "stdout": stdout.decode(), "stderr": stderr.decode(), "returncode": code})
        return stdout, stderr, code

    specifications = (
        ("normal", cleanup_module(), "run", [False, 3], {}, "returned", 4),
        ("cooperative_cancel", cleanup_module(), "run", [True, 0], {}, "returned", 2),
        ("allocation_failure_as_error_value", cleanup_module(), "run", [False, 0],
         {"allocation_fail_at": 1}, "returned", 1),
        ("explicit_trap", cleanup_module(), "run", [False, 0], {}, "trapped", "division_by_zero"),
        ("allocation_failure_as_trap", held_program(), "held", [4, 0],
         {"allocation_fail_at": 1}, "trapped", "allocation"),
        ("live_loan_bounds_trap", held_program(), "held", [4, 4], {}, "trapped", "bounds"),
        ("live_loan_step_stop", held_program(), "held", [4, 0],
         {"max_steps": 3}, "budget_exceeded", "steps"),
        ("heap_stop", held_program(), "held", [4, 0], {"max_heap_bytes": 3}, "budget_exceeded", "heap"),
        ("call_stop", cleanup_module(), "run", [False, 3], {"max_call_depth": 1}, "budget_exceeded", "calls"),
    )
    for name, source, entry, arguments, limits, expected_status, expected in specifications:
        rows = analyze_static_budget(source)["functions"]  # Test oracle only; raw Rust admission is independent.
        static = {key: max(row[key] for row in rows)
                  for key in ("max_allocator_interactions", "max_vm_ticks", "max_call_depth")}
        raw = wire(source)
        with patch.object(transport, "_run_pinned_shadow", record):
            envelope = execute_rust_byte_dag(raw, entry, arguments, executable,
                executable_sha256=digest, static_policy=static, **limits)
        report = envelope["rust_report"]
        actual = report["runtime"]["execution"]
        oracle = observe(source, entry, arguments, **limits)
        semantic = actual["values"][0] if actual["status"] == "returned" else actual["error"]["code"]
        matched = projection(actual) == projection(oracle)
        if not matched or (actual["status"], semantic) != (expected_status, expected):
            raise AssertionError("actual exit differential failed: " + name)
        cases.append({"name": name, "arguments": arguments, "limits": limits, "static_policy": static,
                      "rust_report": report, "python_report": oracle, "matched": matched})

        if name in {"live_loan_bounds_trap", "live_loan_step_stop"}:
            for change in ({"live_local_loans": 0}, {"loans_ended": 2}, {"live_bytes": 0},
                           {"owners_dropped": 1, "live_owners": 0}, {"allocations": 0}):
                altered = deepcopy(report)
                altered["runtime"]["execution"]["resources"].update(change)
                with patch.object(transport, "_run_pinned_shadow", return_value=(wire(altered) + b"\n", b"", 0)):
                    try:
                        execute_rust_byte_dag(raw, entry, arguments, executable,
                            executable_sha256=digest, static_policy=static, **limits)
                    except HIARustByteDagRejected as exc:
                        refusals.append({"case": name, "changed_fields": change, "rejected": True,
                                         "diagnostic": str(exc), "captured_response_control": True})
                    else:
                        raise AssertionError("contradictory stopped ledger was accepted")

        if entry == "run":
            proposal = propose_leaf_call_expansion(source, callees=["make"])
            selected = policy("candidate_requalified", max_call_depth=1) if name == "call_stop" else policy()
            transformed = execute_contracted_expansion(source, proposal, entry, arguments,
                policy=selected, allocation_fail_at=limits.get("allocation_fail_at"))
            candidate = projection(transformed["execution"])
            before = projection(oracle)
            if name == "call_stop":
                # Explicitly requalified policy permits this change: expansion
                # removes a call frame. Exact quota-stop behavior is unproved.
                if candidate["status"] != "returned" or candidate["values"] != [4]:
                    raise AssertionError("requalified candidate did not return")
            elif {k: v for k, v in candidate.items() if k != "steps"} != {k: v for k, v in before.items() if k != "steps"}:
                raise AssertionError("transformation changed the observed ordinary/trap ledger")
            transforms.append({"case": name, "before": before, "candidate": candidate,
                               "receipt": transformed["contract"], "exact_tick_count_preserved": False})

    bound_files = ("hepta/hia_opcodes.py", "hepta/hia_program_runtime.py", "hepta/hia_rust_byte_dag.py",
        "hepta/hia_rust_crosscheck.py", "hepta/hia_static_budget.py", "hepta/hia_program.py",
        "hepta/hia_schema.py", "hepta/hia_optimization_contract.py", "hepta/hia_call_expansion.py",
        "tests/test_hia_execution_contract.py", "tests/test_hia_optimization_contract.py",
        "tests/test_hia_program.py", "tools/qualify_hia_exit_contract.py")
    result = {"schema": "hepta.hia.exit-contract-qualification.v1", "passed": True,
        "rust_executable": str(executable), "rust_executable_sha256": digest,
        "rust_built_this_run": False, "prior_rust_source_manifest": prior,
        "source_sha256": {**source_hashes,
            **{name: sha256((ROOT / name).read_bytes()).hexdigest() for name in bound_files}},
        "cases": cases, "processes": processes, "negative_controls": refusals, "transformations": transforms,
        "claims": {"finite_actual_rust_python_exit_differential": True,
                   "contradictory_stopped_response_controls_rejected": True,
                   "producer_honesty_proved": False, "asynchronous_cancellation_proved": False,
                   "native_unwind_cleanup_proved": False, "whole_language_soundness_proved": False}}
    (output / "qualification.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-executable", required=True, type=Path)
    parser.add_argument("--rust-sha256", required=True)
    parser.add_argument("--prior-rust-source-manifest", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = qualify(args.rust_executable, args.rust_sha256, args.output, args.prior_rust_source_manifest)
    print(json.dumps({"passed": result["passed"], "actual_rust_cases": len(result["cases"]),
        "rejected_controls": len(result["negative_controls"]), "transformations": len(result["transformations"]),
        "rust_built_this_run": False}, sort_keys=True))


if __name__ == "__main__":
    main()
