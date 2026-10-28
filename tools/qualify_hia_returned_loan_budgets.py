#!/usr/bin/env python3
"""Retain actual v8 budget receipts, refusal cases and VM prefix observations."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
from hashlib import sha256
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap
from tests import test_hia_returned_loan_budgets as corpus
from tools.qualify_hia_integrated import _source_state
from tools.qualify_hia_ndu_pipeline import _write


def qualify(expected_head: str) -> dict:
    before = _source_state()
    if before["head"] != expected_head or before["status"]:
        raise ValueError("qualification requires the exact clean committed source")
    started = datetime.now(timezone.utc).isoformat()
    sources, candidates = {}, {}
    executions, receipts, rejections = [], [], []

    def remember(program):
        checked = verify_program(program)
        sources[checked.sha256] = checked.as_dict()
        return checked.sha256

    original_execute = corpus.execute_program

    def execute(program, function, arguments, **options):
        identity = remember(program)
        try:
            result = original_execute(program, function, arguments, **options)
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as stopped:
            result = stopped.report
            executions.append({"program_sha256": identity, "function": function,
                               "arguments": list(arguments), "options": options, "report": result})
            raise
        executions.append({"program_sha256": identity, "function": function,
                           "arguments": list(arguments), "options": options, "report": result})
        return result

    def observed_analysis(name, original):
        def analyze(program, *arguments, **options):
            try:
                report = original(program, *arguments, **options)
            except ValueError as error:
                # Some negative cases deliberately present a future-verifier
                # stub. Retain their exact candidate bytes as UNADMITTED data;
                # do not pretend a new canonical Core accepted that program.
                if isinstance(program, bytes):
                    raw = program
                elif isinstance(program, dict):
                    raw = json.dumps(program, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()
                else:
                    raw = program.canonical_bytes
                candidate = sha256(raw).hexdigest()
                candidates[candidate] = json.loads(raw)
                rejections.append({"analyzer": name, "candidate_sha256": candidate,
                                   "arguments": list(arguments), "options": options,
                                   "diagnostic": {"code": getattr(error, "code", None), "message": str(error)}})
                raise
            identity = remember(program)
            receipts.append({"analyzer": name, "program_sha256": identity,
                             "arguments": list(arguments), "options": options, "report": report})
            return report
        return analyze

    captured = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(corpus.ReturnedLoanBudgetTests)
    with ExitStack() as stack:
        stack.enter_context(patch.object(corpus, "execute_program", execute))
        for name in ("analyze_static_budget", "qualify_vm_call_depth", "qualify_entry_live_heap_budget"):
            stack.enter_context(patch.object(corpus, name, observed_analysis(name, getattr(corpus, name))))
        stack.enter_context(redirect_stdout(captured))
        result = unittest.TextTestRunner(stream=captured, verbosity=2).run(suite)
    after = _source_state()
    heap_bounds, event_bounds = {}, {}
    for row in receipts:
        report = row["report"]
        identity = row["program_sha256"]
        if row["analyzer"] == "qualify_entry_live_heap_budget":
            key = identity, report["function"]
            heap_bounds[key] = min(heap_bounds.get(key, report["peak_bound_bytes"]), report["peak_bound_bytes"])
        elif row["analyzer"] == "analyze_static_budget":
            for fn in report["functions"]:
                event_bounds[identity, fn["function"]] = fn
    comparisons = []
    for index, row in enumerate(executions):
        observed = row["report"]
        key = row["program_sha256"], row["function"]
        entry = {"execution_index": index,
                 "program_binding_matches": observed["program_sha256"] == row["program_sha256"]}
        if key in heap_bounds:
            entry["peak_bound_bytes"] = heap_bounds[key]
            entry["actual_peak_bytes"] = observed["resources"]["peak_bytes"]
            entry["payload_within_bound"] = entry["actual_peak_bytes"] <= entry["peak_bound_bytes"]
        if key in event_bounds:
            bound = event_bounds[key]
            actual_events = observed["resources"]["allocation_attempts"] + observed["resources"]["frees"]
            entry["vm_ticks_within_bound"] = observed["steps"] <= bound["max_vm_ticks"]
            entry["allocator_interactions_within_bound"] = actual_events <= bound["max_allocator_interactions"]
        comparisons.append(entry)
    compared = bool(comparisons) and all(
        all(value is True for key, value in row.items()
            if key.endswith("_matches") or key.endswith("_within_bound")) for row in comparisons)
    passed = (result.wasSuccessful() and not result.skipped and result.testsRun > 0
              and before == after and compared and bool(heap_bounds) and bool(event_bounds))
    executable = Path(sys.executable).resolve()
    return {
        "schema": "hepta.hia.returned-loan-budget-qualification.v1",
        "ok": passed,
        "status": "finite_v8_budget_observations_passed" if passed else "finite_v8_budget_observations_failed",
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "source_before": before, "source_after": after, "source_unchanged": before == after,
        "python": {"executable": str(executable), "sha256": sha256(executable.read_bytes()).hexdigest(),
                   "version": sys.version},
        "tests": {"run": result.testsRun, "failures": len(result.failures),
                  "errors": len(result.errors), "skipped": len(result.skipped)},
        "test_log": captured.getvalue(),
        "counts": {"executions": len(executions), "receipts": len(receipts), "refusals": len(rejections),
                   "canonical_programs": len(sources), "unadmitted_candidates": len(candidates),
                   "executions_with_payload_bound": sum("payload_within_bound" in row for row in comparisons),
                   "executions_with_event_bound": sum("vm_ticks_within_bound" in row for row in comparisons)},
        "programs_by_sha256": sources, "unadmitted_candidates_by_sha256": candidates,
        "executions": executions, "analysis_receipts": receipts,
        "refusals": rejections, "comparisons": comparisons,
        "claims": {
            "actual_core_analyzers_and_vm_executed": passed,
            "full_source_inventory_unchanged": before == after,
            "observations_added_to_test_denominator": False,
            "native_execution_or_backend_refinement_proved": False,
            "private_external_payload_extents_assumed_bounded": False,
            "whole_language_soundness_proved": False,
            "full_P1_P2_P7_closed": False,
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args(argv)
    destination = options.output.resolve()
    if destination.is_relative_to(ROOT) or destination.exists():
        raise ValueError("choose a new report path outside the source inventory")
    report = qualify(options.expected_head)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _write(destination, report)
    print(json.dumps({"ok": report["ok"], "status": report["status"],
                      "tests": report["tests"], "counts": report["counts"],
                      "report": str(destination)}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
