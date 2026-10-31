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
    "tests.test_hia_runtime_policy_predecode",
    "tests.test_hia_runtime_source_preflight",
    "tests.test_hia_owned_entry_abi_preflight",
    "tests.test_hia_optimizer_bench", "tests.test_hia_agent_holdout",
    "tests.test_hia_guarded_optimization", "tests.test_hia_ndu_graph",
    "tests.test_hia_ndu_cache",
    "tests.test_cpp_upstream_host", "tests.test_cpp_contract_capture",
    "tests.test_cpp_composed_project", "tests.test_hia_stateful",
    "tests.test_hia_native_mapping_identity",
    "tests.test_hia_next_evaluation",
    "tests.test_hia_recursive_ndu_builder",
    "tests.test_hia_prepared", "tests.test_hia_ndu_session", "tests.test_hia_ndu_net_value",
    "tests.test_hia_narrowing", "tests.test_hia_narrowing_bench",
    "tests.test_cpp_unique_capture", "tests.test_cpp_unique_project",
    "tests.test_c_contract_identity",
    "tests.test_hia_round3_routes", "tests.test_hia_registered_followup",
    "tests.test_c2hepta_api_path_isolation", "tests.test_c2hepta_bounded_source",
    "tests.test_c2hepta_snapshot_capture", "tests.test_migration_ir_identifier_guard",
    "tests.test_migration_ir_literal_guard", "tests.test_migration_ir_neg_payload_guard",
    "tests.test_migration_ir_parser_budget", "tests.test_migration_ir_structural_budget",
    "tests.test_hia_scalar_lowering_check", "tests.test_hia_cursor_math",
    "tests.test_hia_c_project_views", "tests.test_hia_ndu_activation",
    "tests.test_hia_agent_repair",
    "tests.test_hia_artifact_session",
    "tests.test_hia_artifact_driver_preflight", "tests.test_hia_native_pinning",
    "tests.test_hia_ndu_prepared_reuse",
    "tests.test_hia_legacy_irpgo",
    "tests.test_hia_agent_primitive_into",
    "tests.test_hia_entry_payload_bound",
    "tests.test_hia_agent_structured",
    "tests.test_hia_agent_toolstudy",
    "tests.test_hia_agent_toolstudy_v9",
    "tests.test_hia_agent_tool_references",
    "tests.test_hia_guarded_batch",
    "tests.test_hia_finite_v8_heap",
    "tests.test_c_project_do_while",
    "tests.test_hia_borrowed_extent_heap",
    "tests.test_hia_bounded_unroll",
    "tests.test_hia_crc_kernel",
    "tests.test_hia_c_posttest_hosts",
    "tests.test_hia_finite_context",
    "tests.test_clang_capture_environment",
    "tests.test_hia_crc_context_study",
    "tests.test_hia_native_source_reinspect",
    "tests.test_hia_v6_differential",
    "tests.test_hia_runtime_argument_snapshot",
    "tests.test_hia_rust_executable_custody",
    "tests.test_hia_rust_budget_v3",
    "tests.test_hia_rust_api_v4",
    "tests.test_hia_ndu_optimizer_budget",
    "tests.test_hia_ndu_optimizer_transport",
    "tests.test_c2hepta_preprocessor_guard",
    "tests.test_hia_c_loop_jumps",
    "tests.test_hia_c_do_while",
    "tests.test_hia_c_loop_migration_qualification",
    "tests.test_hia_ndu_narrowed_controls",
    "tests.test_hia_artifact_narrowing",
    "tests.test_hia_agent_assembly", "tests.test_hia_round4_routes",
    "tests.test_hia_continuation", "tests.test_hia_ndu_sealed_identity",
    "tests.test_hia_ndu_session_cost", "tests.test_cpp_unique_assignment_project",
    "tests.test_hia_round4_bench",
    "tests.test_hia_opcode_catalog", "tests.test_hia_optimization_contract",
    "tests.test_hia_register_safety.RegisterSafetyInputTests",
    "tests.test_ring_maintenance_qualification", "tests.test_hia_agent_public_tools",
    "tests.test_hia_ndu_convergence", "tests.test_hia_ndu_converged_holdout",
    "tests.test_hia_verified_increment_gate",
    "tests.test_hia_call_expansion",
    "tests.test_hia_call_return_lifetimes",
    "tests.test_cpp_gsl_final_action",
    "tests.test_cpp_gsl_branching_callback",
    "tests.test_hia_background_optimizer",
    "tests.test_hia_native_ndu",
    "tests.test_hia_agent_gguf",
    "tests.test_hia_trial_observations",

)



def _planned_test_ids(suite) -> tuple[str, ...]:
    """Freeze exact discovery order; a count alone cannot establish coverage."""
    pending = [suite]
    ids = []
    while pending:
        node = pending.pop()
        if isinstance(node, unittest.TestSuite):
            pending.extend(reversed(list(node)))
        elif isinstance(node, unittest.TestCase):
            identity = node.id()
            if type(identity) is not str or not identity:
                raise ValueError("noncanonical integration test identity")
            ids.append(identity)
        else:
            raise ValueError("non-TestCase integration test discovered")
    return tuple(ids)


class _IdentityRecordingResult(unittest.TextTestResult):
    """Record both start and completion, including skipped/expected-failure cases."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started_ids: list[str] = []
        self.finished_ids: list[str] = []

    def startTest(self, test):
        self.started_ids.append(test.id())
        super().startTest(test)

    def stopTest(self, test):
        self.finished_ids.append(test.id())
        super().stopTest(test)


def _outcome_admissible(result, planned: tuple[str, ...], *,
                        source_unchanged: bool, worktree_unchanged: bool) -> bool:
    """An expected failure, missing/replaced test, or source drift never qualifies."""
    return bool(
        type(planned) is tuple and planned and len(planned) == len(set(planned))
        and all(type(identity) is str and identity for identity in planned)
        and result.testsRun == len(planned)
        and tuple(result.started_ids) == planned
        and tuple(result.finished_ids) == planned
        and result.wasSuccessful()
        and not result.failures and not result.errors and not result.skipped
        and not result.expectedFailures and not result.unexpectedSuccesses
        and source_unchanged and worktree_unchanged
    )


def _ids_digest(ids) -> str:
    """Canonical ordered identity digest, never a substitute for equality."""
    return sha256(json.dumps(list(ids), ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8")).hexdigest()


def selector_source(selector):
    """Bind the source module for a unittest module/class/method selector."""
    parts = selector.split(".")
    for end in range(len(parts), 0, -1):
        path = ROOT.joinpath(*parts[:end]).with_suffix(".py")
        if path.is_file():
            return path
    raise ValueError("unresolved integration test source: " + selector)


def inventory():
    paths = list((ROOT / "hepta").glob("*.py")) + [Path(__file__)]
    paths += list((ROOT / "tools").rglob("*.py"))
    for folder in ("examples/cpp/composed_project_migration", "examples/cpp/scoped_ownership_migration",
                   "examples/cpp/unique_project_migration",
                   "examples/cpp/unique_assignment_project_migration",
                   "experiments/hia_optimizer_eval/next_20261028",
                   "experiments/hia_optimizer_eval/round3_20261028",
                   "experiments/hia_ndu_graph_eval/round3_20261028",
                   "experiments/hia_stateful_eval/round3_20261028"):
        paths += [path for path in (ROOT / folder).iterdir()
                  if path.is_file() and path.suffix in {".py", ".json", ".h", ".cpp", ".c"}
                  and (not folder.startswith("experiments/") or
                       path.suffix in {".py", ".c"} or path.name in {"PROTOCOL.json", "FIXTURES.json", "REGISTRATION.json",
                                                            "ADMISSION_CONTROLS.json"})]
    paths += [selector_source(name) for name in MODULES]
    for folder in ("examples/hia_legacy_queue", "tests/fixtures/c_migration/ring_buffer",
                   "tests/fixtures/c_migration/musl_compare", "experiments/hia_legacy_queue",
                   "experiments/hia_ndu_activation", "experiments/hia_ndu_prepared_reuse",
                   "experiments/hia_agent_factorial_v5_20261028",
                   "experiments/hia_agent_factorial_v6_20261028",
                   "experiments/hia_agent_structured_v7_20261029",
                   "experiments/hia_agent_toolstudy_v8_20261029",
                   "experiments/hia_agent_toolstudy_v9_20261029",
                   "tests/fixtures/hia_payload_bound"):
        paths += [path for path in (ROOT / folder).rglob("*") if path.is_file()
                  and "__pycache__" not in path.parts]
    paths += list((ROOT / "experiments/hia_guarded_opportunity").glob("*.json"))
    paths += list((ROOT / "experiments/hia_crc_context").glob("*.json"))
    return {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest() for path in sorted(set(paths))}


def run(output):
    if len(MODULES) != len(set(MODULES)):
        raise ValueError("duplicate integration test module")
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
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    planned = _planned_test_ids(suite)
    started = time.monotonic_ns()
    with (destination / "tests.log").open("w") as stream:
        result = unittest.TextTestRunner(
            stream=stream, verbosity=2, resultclass=_IdentityRecordingResult
        ).run(suite)
    after = inventory()
    git_status_after = subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=ROOT, text=True
    )
    source_unchanged = before == after
    worktree_unchanged = plan["git_worktree_status"] == git_status_after
    admitted = _outcome_admissible(
        result, planned, source_unchanged=source_unchanged,
        worktree_unchanged=worktree_unchanged
    )
    report = {
        **plan,
        "tests": result.testsRun,
        "tests_planned": len(planned),
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": [(str(test), reason) for test, reason in result.skipped],
        "expected_failures": [(str(test), trace) for test, trace in result.expectedFailures],
        "unexpected_successes": [str(test) for test in result.unexpectedSuccesses],
        "test_identity": {
            "planned_sha256": _ids_digest(planned),
            "started_sha256": _ids_digest(result.started_ids),
            "finished_sha256": _ids_digest(result.finished_ids),
            "discovery_duplicates": len(planned) != len(set(planned)),
            "started_matches_planned": tuple(result.started_ids) == planned,
            "finished_matches_planned": tuple(result.finished_ids) == planned,
        },
        "elapsed_ns": time.monotonic_ns() - started,
        "source_unchanged": source_unchanged,
        "git_worktree_status_after": git_status_after,
        "worktree_unchanged": worktree_unchanged,
        "failure_details": [(str(test), trace) for test, trace in result.failures + result.errors],
        "passed": admitted,
        "authority": "DENY_ALL",
        "safety_certificate": False,
        "log_sha256": sha256((destination / "tests.log").read_bytes()).hexdigest(),
    }
    (destination / "result.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        key: report[key] for key in (
            "tests", "tests_planned", "failures", "errors", "skipped",
            "expected_failures", "unexpected_successes", "test_identity",
            "source_unchanged", "worktree_unchanged", "passed",
        )
    }, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    raise SystemExit(0 if run(options.output)["passed"] else 1)
