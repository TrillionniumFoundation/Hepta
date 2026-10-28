#!/usr/bin/env python3
"""Run the finite integration/regression gate and retain source-bound evidence.

This gate never turns scientific performance/productivity failures into a pass.
It checks implementation behavior; those experiments retain separate outcomes.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MODULES = (
    "tests.test_core_unification", "tests.test_hia_program", "tests.test_hia_program_tools",
    "tests.test_hia_inmemory_json_key_collisions", "tests.test_hia_inmemory_surrogate_wire",
    "tests.test_hia_program_source", "tests.test_hia_program_llvm",
    "tests.test_hia_schema_unification", "tests.test_hia_core_upgrade",
    "tests.test_hia_schema_collision", "tests.test_hia_schema_binding_audit",
    "tests.test_hia_allocation_normalization", "tests.test_hia_empty_owner_native",
    "tests.test_hia_native_side_effects", "tests.test_hia_recursive_chain",
    "tests.test_hia_returned_loans", "tests.test_hia_returned_chain_loans",
    "tests.test_hia_returned_loan_interfaces", "tests.test_hia_patch_impact",
    "tests.test_hia_rust_bulk_vm", "tests.test_hia_rust_owned_cfg", "tests.test_hia_rust_owned_vm",
    "tests.test_c_project_semantic_flags", "tests.test_c_project_source_arguments", "tests.test_c_project",
    "tests.test_hia_batch_disclosed_choices",
    "tests.test_cpp_composed_migrate", "tests.test_cpp_scoped_ownership_migration",
    "tests.test_hia_optimization", "tests.test_hia_profile_integration",
    "tests.test_hia_routes", "tests.test_hia_ndu",
    "tests.test_hia_ndu_loop", "tests.test_hia_ndu_bridge_isolation", "tests.test_hia_adaptive",
    "tests.test_hia_optimizer_bench", "tests.test_hia_agent_holdout",
)


def inventory():
    paths = list((ROOT / "hepta").glob("*.py")) + [Path(__file__)]
    paths += [ROOT / (name.replace(".", "/") + ".py") for name in MODULES]
    return {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest() for path in sorted(set(paths))}


def run(output):
    destination = Path(output).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    before = inventory()
    plan = {"schema": "hepta.hia.verified-increment.tests.v1", "modules": list(MODULES),
            "source_sha256": before,
            "git_base": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "git_worktree_status": subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True),
            "python": sys.version, "python_executable": sys.executable,
            "claims": {"whole_language_soundness_proved": False,
                       "performance_or_agent_superiority_established": False,
                       "full_seven_deliverables_complete": False}}
    (destination / "plan.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    started = time.monotonic_ns()
    with (destination / "tests.log").open("w") as stream:
        suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    after = inventory()
    report = {**plan, "tests": result.testsRun, "failures": len(result.failures),
              "errors": len(result.errors), "skipped": [(str(test), reason) for test, reason in result.skipped],
              "elapsed_ns": time.monotonic_ns() - started,
              "source_unchanged": before == after,
              "failure_details": [(str(test), trace) for test, trace in result.failures + result.errors],
              "passed": result.wasSuccessful() and not result.skipped and before == after,
              "log_sha256": sha256((destination / "tests.log").read_bytes()).hexdigest()}
    (destination / "result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in ("tests", "failures", "errors", "skipped", "source_unchanged", "passed")}, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    raise SystemExit(0 if run(options.output)["passed"] else 1)
