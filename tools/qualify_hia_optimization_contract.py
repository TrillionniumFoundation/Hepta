#!/usr/bin/env python3
"""Retain actual exit/budget observations for the fixed resource contract fixture."""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_call_expansion import propose_leaf_call_expansion
from hepta.hia_optimization_contract import (HIAOptimizationContractRejected, SOURCE_FILES,
    execute_contracted_expansion, qualify_expansion_contract, validate_expansion_contract)
from hepta.hia_program import verify_program
from tests.test_hia_optimization_contract import cleanup_module, observe, policy


def require(condition, message):
    if not condition:
        raise ValueError(message)


def qualify():
    paths = tuple("hepta/" + name for name in SOURCE_FILES) + (
        "tools/qualify_hia_optimization_contract.py", "tests/test_hia_optimization_contract.py",
        "tests/test_hia_program.py")
    identities = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in paths}
    base = verify_program(cleanup_module())
    proposal = propose_leaf_call_expansion(base, callees=["make"])
    cases = []
    for label, arguments, failure, expected_status, expected_value in (
        ("normal", [False, 3], None, "returned", 4),
        ("allocation_error_as_value", [False, 0], 1, "returned", 1),
        ("explicit_cooperative_cancel_branch", [True, 0], None, "returned", 2),
        ("first_program_trap", [False, 0], None, "trapped", None),
    ):
        before = observe(base, arguments, allocation_fail_at=failure,
                         max_steps=64, max_call_depth=2, max_heap_bytes=4)
        after = execute_contracted_expansion(base, proposal, "run", arguments,
                                             allocation_fail_at=failure, policy=policy())
        executed = after["execution"]
        require(before["status"] == executed["status"] == expected_status,
                "actual exit classification differs: " + label)
        require(before.get("result") == executed.get("result") == expected_value
                and before["resources"] == executed["resources"], "actual value/resource ledger differs: " + label)
        if expected_status == "returned":
            require(executed["resources"]["live_owners"] == 0
                    and executed["resources"]["live_local_loans"] == 0, "ordinary exit did not clean resources")
        else:
            require(before["error"]["code"] == executed["error"]["code"] == "division_by_zero"
                    and executed["resources"]["live_owners"] == 1
                    and executed["resources"]["owners_dropped"] == 0, "trap ledger falsely claims cleanup")
        cases.append({"case": label, "arguments": arguments, "allocation_fail_at": failure,
                      "source_execution": before, "candidate": after})
    stopped = []
    for name, changed, runtime_limit in (
        ("call_depth", {"max_call_depth": 1}, {"max_call_depth": 1}),
        ("vm_ticks", {"max_vm_ticks": 11}, {"max_steps": 11}),
    ):
        selected_policy = policy("candidate_requalified", **changed)
        before = observe(base, [False, 3], **runtime_limit)
        after = execute_contracted_expansion(base, proposal, "run", [False, 3], policy=selected_policy)
        require(before["status"] == "budget_exceeded" and after["execution"]["status"] == "returned",
                "budget-failure difference control was not actually observed")
        require(after["contract"]["source_fits_same_quotas"] is False, "source quota failure hidden")
        stopped.append({"case": name, "source_execution": before, "candidate": after})
    rejected = []
    for name, selected_policy in (
        ("source_depth_must_also_fit", policy(max_call_depth=1)),
        ("candidate_payload_exceeds_policy", policy(max_live_heap_bytes=3)),
    ):
        try:
            qualify_expansion_contract(base, proposal, function="run", arguments=[False, 3], policy=selected_policy)
        except HIAOptimizationContractRejected as error:
            rejected.append({"case": name, "status": "rejected_as_expected", "error": str(error)})
        else:
            raise ValueError("intended resource refusal was admitted: " + name)
    forged = deepcopy(cases[0]["candidate"]["contract"])
    forged["after"]["functions"][0]["max_live_heap_bytes"] = 0
    try:
        validate_expansion_contract(base, proposal, forged, function="run", arguments=[False, 3], policy=policy())
    except HIAOptimizationContractRejected as error:
        rejected.append({"case": "forged_payload_receipt", "status": "rejected_as_expected", "error": str(error)})
    else:
        raise ValueError("forged resource receipt was accepted")
    log = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromName(
        "tests.test_hia_optimization_contract.ExpansionResourceContractTests")
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    require(result.wasSuccessful() and result.testsRun == 13 and not result.skipped,
            "full resource-contract regression selection did not pass without skips:\n" + log.getvalue())
    require(all(sha256((ROOT / name).read_bytes()).hexdigest() == value for name, value in identities.items()),
            "contract source changed during qualification")
    return {"schema": "hepta.hia.optimization-resource-qualification.v1", "ok": True,
        "source_identity": identities, "source_core": base.as_dict(), "proposal": proposal,
        "exit_cases": cases, "budget_difference_cases": stopped, "rejection_cases": rejected,
        "regressions": {"passed": True, "tests_run": result.testsRun, "skipped": len(result.skipped),
                        "log": log.getvalue()},
        "claims": {"fixed_actual_exit_and_resource_observations_passed": True,
                   "exact_budget_stop_equivalence": False, "native_resource_bounds_proved": False,
                   "general_cancellation_or_host_failure_cleanup_proved": False,
                   "whole_language_soundness_proved": False}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = qualify()
    except (ValueError, OSError, RuntimeError) as error:
        report = {"schema": "hepta.hia.optimization-resource-qualification.v1",
                  "ok": False, "error": str(error)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"ok": report["ok"], "exit_cases": len(report.get("exit_cases", [])),
                      "budget_difference_cases": len(report.get("budget_difference_cases", [])),
                      "rejection_cases": len(report.get("rejection_cases", [])),
                      "tests_run": report.get("regressions", {}).get("tests_run", 0),
                      **({"error": report["error"]} if "error" in report else {})}))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
