"""One exact-source test inventory for the integrated HIA P0-P3 candidate.

Passing this finite gate does not promote missing deployment, economic benefit,
or selfhosting evidence into success. Those acceptance dimensions stay separate.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from tools.qualify_hia_direct_native import SUITES as ORIGINAL_DIRECT_SUITES, Result, _ids

NEW_SUITES = (
    "tests.test_core_seven_shared_acceptance",
    "tests.test_core_seven_shared_source_closure",
    "tests.test_hia_agent_native_tools",
    "tests.test_hia_agent_native_machine_choices",
    "tests.test_hia_agent_native_campaign",
    "tests.test_hia_machine_plan",
    "tests.test_hia_machine_registers",
    "tests.test_hia_machine_leaf_registers",
    "tests.test_hia_native_byte_abi",
    "tests.test_hia_bootstrap_components",
    "tests.test_hia_selfhost",
    "tests.test_hia_selfhost_contract",
    "tests.test_hia_selfhost_machine_plans",
    "tests.test_hia_agent_macro_policy",
    "tests.test_hia_macro_campaign",
    "tests.test_hia_macro_codex_provider",
    "tests.test_hia_candidate_preflight",
    "tests.test_hia_release",
    "tests.test_hia_first_use",
    "tests.test_hia_agent_provider",
    "tests.test_hia_agent_first_use_recovery",
)


def sources():
    entries = {}
    for folder in ("hepta", "tests", "tools"):
        for path in sorted((ROOT / folder).rglob("*.py")):
            entries[path.relative_to(ROOT).as_posix()] = sha256(path.read_bytes()).hexdigest()
    for folder in ("hia_program", "hia_recursive_chain", "hia_bootstrap"):
        for path in sorted((ROOT / "examples" / folder).rglob("*")):
            if path.is_file():
                entries[path.relative_to(ROOT).as_posix()] = sha256(path.read_bytes()).hexdigest()
    for path in sorted((ROOT / "docs").glob("HIA_*.md")):
        entries[path.relative_to(ROOT).as_posix()] = sha256(path.read_bytes()).hexdigest()
    for relative in ("docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json", "docs/HIA_SELFHOST_CORE_SUPPORT.json",
                     ".github/workflows/hia-unified-candidate.yml"):
        entries[relative] = sha256((ROOT / relative).read_bytes()).hexdigest()
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": sha256(payload).hexdigest(), "files": entries}


def git(*args):
    result = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, timeout=20)
    return result.stdout.strip() if result.returncode == 0 else None


def qualify():
    started = time.monotonic_ns()
    before = sources()
    suites = ORIGINAL_DIRECT_SUITES + NEW_SUITES
    suite = unittest.defaultTestLoader.loadTestsFromNames(suites)
    inventory = _ids(suite)
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2, resultclass=Result).run(suite)
    complete = len(inventory) == len(set(inventory)) and sorted(result.executed_ids) == sorted(inventory)
    stable = before == sources()
    ok = result.wasSuccessful() and complete and stable and not result.skipped and not result.expectedFailures
    from hepta.hia_agent_contract import installation_manifest
    return {"schema": "hepta.hia.unified-candidate-qualification.v1", "ok": bool(ok),
        "completed_utc": datetime.now(timezone.utc).isoformat(), "elapsed_ns": time.monotonic_ns() - started,
        "git_head": git("rev-parse", "HEAD"), "git_tree": git("rev-parse", "HEAD^{tree}"),
        "git_status": git("status", "--porcelain", "--untracked-files=all"),
        "host": {"platform": platform.platform(), "python": sys.version},
        "source": before, "source_unchanged": stable, "installation": installation_manifest(),
        "original_direct_suites": list(ORIGINAL_DIRECT_SUITES), "new_suites": list(NEW_SUITES),
        "tests_run": result.testsRun, "test_inventory": inventory, "executed_ids": result.executed_ids,
        "inventory_complete": complete,
        "failures": [{"id": test.id(), "traceback": trace} for test, trace in result.failures],
        "errors": [{"id": test.id(), "traceback": trace} for test, trace in result.errors],
        "skipped": [{"id": test.id(), "reason": reason} for test, reason in result.skipped],
        "expected_failures": [{"id": test.id(), "traceback": trace} for test, trace in result.expectedFailures],
        "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
        "acceptance": {"finite_same_source_tests_passed": bool(ok),
            "production_connector_deployed": False, "full_core_to_machine_refinement_proved": False,
            "real_task_ndu_strategy_benefit_proved": False, "complete_hia_selfhosting_achieved": False,
            "fixed_core_selfhosting_test_gate_passed": bool(ok),
            "checked_scalar_register_plan_test_gate_passed": bool(ok),
            "general_register_allocation_qualified": False},
        "notes": ["All original direct-backend suites remain in this inventory; no deleted tests or skips are accepted.",
                  "Native NDU execution and runtime preflight have separately retained receipts.",
                  "The separate fixed-Core compiler executes B0-B3 and modified-self rebuilding in its native tests; retain the standalone generation artifacts as well.",
                  "The full HIA language and universal backend refinement remain outside this fixed-Core evidence.",
                  "Checked scalar register and instruction plans preserve their own independent admission and native validation gates."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        parser.error("--output must be a new file in an existing directory")
    report = qualify()
    with output.open("x") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"ok": report["ok"], "tests_run": report["tests_run"],
                      "source_sha256": report["source"]["sha256"], "output": str(output)}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
