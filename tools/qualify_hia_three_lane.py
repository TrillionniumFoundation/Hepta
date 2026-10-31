#!/usr/bin/env python3
"""Source-bound HIA cross-lane test gate: zero errors, failures AND skips.

Scoped proof/test evidence, never a production authorization. It refuses
unknown scopes, zero-test successes, missing Git source identity, and writes
an immutable per-run receipt with explicit negative outcomes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest

# Direct script execution sets sys.path[0] to tools/, not to repository root.
# Agent/CI invocations and python -m must resolve the exact same tests package.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


SUITES = {
    "gate": ("tests.test_hia_three_lane_gate",),
    "core": (
        "tests.test_hia_bounded_mutable_snapshot",
        "tests.test_hia_bounded_input_utf8",
        "tests.test_hia_bounded_research_wire",
        "tests.test_hia_evidence_json_structure",
        "tests.test_hia_stateful_wire",
        "tests.test_hia_program",
        "tests.test_hia_json_preflight",
        "tests.test_hia_program_composite",
        "tests.test_hia_execution_contract",
        "tests.test_hia_exit_accounting",
        "tests.test_hia_opcode_catalog",
        "tests.test_hia_full_cost_gate",
        "tests.test_hia_paired_holdout",
    ),
    "native": (
        "tests.test_hia_stateful_clone_partial",
        "tests.test_hia_stateful_generation_fence",
        "tests.test_hia_stateful_queue_token_admission",
        "tests.test_hia_native_process_observer",
        "tests.test_hia_native_paired_replay",
    ),
    "rust": (
        "tests.test_hia_rust_byte_dag",
    ),
    "legacy": (
        "tests.test_hsir_wire_audit",
        "tests.test_hsir_bridge",
        "tests.test_cfg_analysis",
        "tests.test_ssa_scalar",
        "tests.test_ssa_verify",
        "tests.test_hia_schema_unification",
        "tests.test_hia_agent_assembly",
        "tests.test_hia_routes",
    ),
    "llvm": (
        "tests.test_hia_agent_public_tools",
        "tests.test_hia_program_llvm",
        "tests.test_hia_composite_abi",
        "tests.test_hia_native_differential",
    ),
    "migration": (
        "tests.test_cpp_gsl_branching_callback",
        "tests.test_hia_c_project_views",
        "tests.test_hia_c_loop_migration_qualification",
        "tests.test_c_fixed_slice_shift",
        "tests.test_hia_native_ndu",
    ),
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, timeout=10, cwd=ROOT).strip()


def _planned_test_ids(suite) -> tuple[str, ...]:
    """Freeze the exact discovered tests before unittest may consume the suite."""
    ids = []
    stack = [suite]
    while stack:
        current = stack.pop()
        if isinstance(current, unittest.TestSuite):
            stack.extend(reversed(list(current)))
        else:
            if not isinstance(current, unittest.TestCase) or not callable(getattr(current, "id", None)):
                raise ValueError("non-TestCase discovery entry")
            ids.append(current.id())
    return tuple(ids)


class _IdentityRecordingResult(unittest.TextTestResult):
    """Record the exact started and stopped tests, not only unittest.testsRun.

    A result may claim the expected test count despite running a different test,
    or finishing before a planned test has run. Neither case admits evidence.
    """

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


def _verified_receipt_destination(output: Path) -> Path:
    """Enforce outside-worktree, absolute evidence output before any tests run.

    Otherwise the receipt itself can make the checkout dirty *after* the source
    status check, while falsely claiming a clean post-run source. The resolved
    path check also rejects an output alias into the checkout.
    """
    if not output.is_absolute():
        raise ValueError("qualification receipt path must be absolute")
    destination = output.resolve(strict=False)
    if destination.is_relative_to(ROOT.resolve()):
        raise ValueError("qualification receipt must be outside the source worktree")
    return output



def _write_immutable_receipt(output: Path, receipt: dict) -> None:
    """No-clobber, no-symlink receipt publication using a real directory FD.

    A path verified earlier can be retargeted through a parent symlink before
    ordinary Path.open('x'). Open every directory component with O_NOFOLLOW
    relative to the previously opened directory, and create the final file
    exclusively against that same pinned parent. This is a Linux research
    qualifier; unsupported hosts must fail closed rather than silently
    downgrade to path-based writes.
    """
    if not output.is_absolute():
        raise ValueError("qualification receipt path must be absolute")
    if (not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY")
            or os.open not in os.supports_dir_fd
            or os.mkdir not in os.supports_dir_fd
            or not Path("/proc/self/fd").is_dir()):
        raise OSError("secure Linux directory-fd receipt publication unavailable")
    components = output.parts[1:]
    if not components or any(part in {"", ".", ".."} for part in components):
        raise ValueError("unsafe qualification receipt path component")
    directory_flags = (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                       | getattr(os, "O_CLOEXEC", 0))
    directory_fd = os.open("/", directory_flags)
    try:
        for component in components[:-1]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=directory_fd)
            except FileExistsError:
                pass
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        actual_parent = Path(
            os.readlink(f"/proc/self/fd/{directory_fd}")
        ).resolve(strict=True)
        if actual_parent.is_relative_to(ROOT.resolve()):
            raise ValueError("qualification receipt resolved inside source worktree")
        # A symlink substituted after _verified_receipt_destination cannot
        # move the final open. O_EXCL and O_NOFOLLOW also deny a leaf alias.
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | getattr(os, "O_CLOEXEC", 0))
        file_fd = os.open(components[-1], flags, 0o600, dir_fd=directory_fd)
        with os.fdopen(file_fd, "w", encoding="utf-8") as target:
            target.write(json.dumps(receipt, ensure_ascii=False, sort_keys=True,
                                    indent=2) + "\n")
            target.flush()
            os.fsync(target.fileno())
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _outcome_admissible(result, planned_ids, *, immutable: bool) -> bool:
    """Strict pure gate; expectedFailures and missing/duplicated tests refuse."""
    return bool(
        immutable and planned_ids
        and len(set(planned_ids)) == len(planned_ids)
        and result.testsRun == len(planned_ids)
        and tuple(getattr(result, "started_ids", ())) == tuple(planned_ids)
        and tuple(getattr(result, "finished_ids", ())) == tuple(planned_ids)
        and result.wasSuccessful()
        and not result.errors and not result.failures and not result.skipped
        and not result.expectedFailures and not result.unexpectedSuccesses
    )


def check(scope: str, output: Path) -> dict:
    if scope not in SUITES:
        raise ValueError("unknown exact cross-lane suite")
    output = _verified_receipt_destination(output)
    # Reject both tracked modifications and untracked material inside the
    # repository: test discovery must not silently import an extra local file.
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("source checkout dirty before cross-lane gate")
    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    suite = unittest.defaultTestLoader.loadTestsFromNames(SUITES[scope])
    planned_ids = _planned_test_ids(suite)
    result = unittest.TextTestRunner(
        stream=sys.stderr, verbosity=2, resultclass=_IdentityRecordingResult,
    ).run(suite)
    status_after = git("status", "--porcelain", "--untracked-files=all")
    head_after = git("rev-parse", "HEAD")
    tree_after = git("rev-parse", "HEAD^{tree}")
    dirty_after = bool(status_after)
    identity_drift = (head_after != head or tree_after != tree)
    passed = _outcome_admissible(
        result, planned_ids, immutable=(not dirty_after and not identity_drift))
    receipt = {
        "schema": "hepta.hia.three-lane-test-receipt.v1",
        "source_commit": head,
        "source_tree": tree,
        "scope": scope,
        "test_modules": list(SUITES[scope]),
        "tests_executed": result.testsRun,
        "tests_planned": len(planned_ids),
        "planned_test_ids_sha256": hashlib.sha256(json.dumps(
            planned_ids, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(),
        "started_test_ids_sha256": hashlib.sha256(json.dumps(
            result.started_ids, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(),
        "finished_test_ids_sha256": hashlib.sha256(json.dumps(
            result.finished_ids, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(),
        "actual_test_identity_drift": (tuple(result.started_ids) != planned_ids
                                       or tuple(result.finished_ids) != planned_ids),
        "duplicate_test_identity": len(planned_ids) != len(set(planned_ids)),
        "expected_failures": [test.id() for test, _ in result.expectedFailures],
        "errors": [test.id() for test, _ in result.errors],
        "failures": [test.id() for test, _ in result.failures],
        "skipped": [{"test": test.id(), "reason": reason}
                    for test, reason in result.skipped],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
        "source_identity_drift": identity_drift,
        "worktree_dirty_after": dirty_after,
        "tracked_source_mutated": dirty_after,
        "python_version": platform.python_version(),
        "passed": passed,
        "authority": "DENY_ALL",
        "production_activation_allowed": False,
        "claims": {
            "whole_language_soundness_proved": False,
            "source_to_native_refinement_proved": False,
            "p0_through_p7_production_closed": False,
            "ndu_real_full_cost_gain_established": False,
        },
    }
    # The previously checked spelling is not trusted: parent symlinks may have
    # changed since admission. Publish through an exclusively opened dirfd.
    _write_immutable_receipt(output, receipt)
    print(json.dumps({k: receipt[k] for k in ("scope", "source_commit",
          "source_tree", "tests_planned", "tests_executed", "errors", "failures",
          "skipped", "expected_failures", "duplicate_test_identity",
          "actual_test_identity_drift", "source_identity_drift", "worktree_dirty_after", "passed", "authority")}, sort_keys=True))
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=sorted(SUITES), required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not check(args.suite, Path(args.output))["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
