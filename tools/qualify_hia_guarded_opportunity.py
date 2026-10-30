#!/usr/bin/env python3
"""Run the preregistered two-u32 native opportunity gate before any NDU study.

Nonpositive evidence is a completed experiment, not a failing correctness gate.
Missing tools, unknown proofs, failed native checks or incomplete frozen samples
are qualification failures and cannot be reinterpreted as an economic outcome.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_guarded_batch import (PROFILE, PROTOCOL_PATH, PROTOCOL_SHA256,
    GuardedBatchRejected, assess_opportunities, build_candidate, build_driver,
    candidates, expected_checksum, export_code_identity, load_protocol, pinned,
    reprice_opportunities, sample, wire)
from tools.qualify_hia_integrated import _source_state


def _sources():
    paths = sorted((ROOT / "hepta").rglob("*.py"))
    paths += [Path(__file__), PROTOCOL_PATH]
    return {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest() for path in paths}


def _remaining(started, protocol):
    if time.monotonic_ns() - started >= protocol["max_optimization_wall_ns"]:
        raise GuardedBatchRejected("E_HIA_GUARDED_BATCH: registered study wall budget exhausted")


def _run(clang, directory, report, started):
    protocol = report["protocol"]
    bank = candidates()
    report["candidate_order"] = list(bank)
    report["candidates"] = {}
    report["samples"] = []
    report["descriptor_releases"] = []
    code = report["exported_code"] = {}
    with ExitStack() as stack:
        for label, program in bank.items():
            _remaining(started, protocol)
            (directory / (label + ".hia.json")).write_bytes(wire(program) + b"\n")
            row = report["candidates"][label] = {"status": "attempted"}
            artifact_sha = build_candidate(program, directory / (label + ".so"), clang=clang, report=row)
            image = stack.enter_context(pinned(directory / (label + ".so"), artifact_sha,
                                               releases=report["descriptor_releases"]))
            row["image"] = image
            code[label] = export_code_identity(image["bytes"])
        _remaining(started, protocol)
        driver = report["driver"] = build_driver(directory, clang=clang)
        if any(row["compilation"]["toolchain"]["sha256"] != driver["compiler_sha256"]
               for row in report["candidates"].values()):
            raise GuardedBatchRejected("E_HIA_GUARDED_BATCH: candidate/driver compiler identities differ")
        pinned_driver = stack.enter_context(pinned(driver["path"], driver["sha256"],
                                                   releases=report["descriptor_releases"]))
        # The bank has no mutable path execution. The same held sealed image is
        # used for every measurement until all bounded children are cleaned up.
        labels = list(bank)
        for phase in ("training", "validation"):
            for module in protocol["modules"]:
                for trial, seed in enumerate(protocol[phase + "_seeds"]):
                    _remaining(started, protocol)
                    expected = expected_checksum(protocol["iterations_per_batch"], seed,
                                                 module["hot_denominator"])
                    offset = trial % len(labels)
                    order = labels[offset:] + labels[:offset]
                    if trial % 2:
                        order.reverse()
                    for label in order:
                        _remaining(started, protocol)
                        row = {"candidate": label, "phase": phase, "module": module["id"], "trial": trial}
                        report["samples"].append(row)
                        sample(pinned_driver, report["candidates"][label]["image"],
                               calls=protocol["iterations_per_batch"], warmup=protocol["warmup_iterations"],
                               seed=seed, hot=module["hot_denominator"], expected=expected, report=row)


def qualify(*, clang, workdir, expected_source):
    started = time.monotonic_ns()
    if type(expected_source) is not str or re.fullmatch(r"[0-9a-f]{40}", expected_source) is None:
        raise GuardedBatchRejected("E_HIA_GUARDED_BATCH: expected source must be a full lowercase commit SHA")
    directory = Path(workdir).resolve()
    if directory == ROOT or ROOT in directory.parents:
        raise GuardedBatchRejected("E_HIA_GUARDED_BATCH: output directory must be outside the source tree")
    directory.mkdir(parents=True, exist_ok=False)
    protocol = load_protocol()
    report = {"schema": "hepta.hia.guarded-opportunity-qualification.v1", "profile": PROFILE,
              "status": "failed", "qualified": False, "protocol": protocol,
              "protocol_sha256": PROTOCOL_SHA256, "observed_utc": datetime.now(timezone.utc).isoformat(),
              "host": {"system": platform.system(), "machine": platform.machine(),
                       "python": sys.version.split()[0]}, "expected_source": expected_source,
              "artifact_directory": str(directory),
              "claims": {"all_input_Core_equivalence_proved": False, "selected_LLVM_equivalence_proved": False,
                         "finite_native_differential_passed": False, "NDU_superiority_established": False,
                         "performance_advantage_established": False, "machine_code_refinement_proved": False,
                         "global_optimality_proved": False, "resource_or_concurrency_proof": False,
                         "persistent_state_migration": False, "production_demand_established": False}}
    # Copy byte-for-byte before the first proof, compiler or timing observation.
    report["cost_stages"] = {}
    (directory / "frozen-protocol.json").write_bytes(PROTOCOL_PATH.read_bytes())
    try:
        # Reuse the existing raw HEAD tree/blob/mode check rather than trusting
        # only git status, the index or a selected-source hash inventory.
        before = report["source_state_before"] = _source_state()
        if before["head"] != expected_source or before["status"]:
            raise GuardedBatchRejected("E_HIA_GUARDED_BATCH: exact expected clean source is required before native work")
        report["source_before"] = _sources()
        report["cost_stages"]["preflight_wall_ns"] = time.monotonic_ns() - started
        if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
            raise GuardedBatchRejected("E_HIA_GUARDED_BATCH: actual Linux x86-64 host required")
        stage_started = time.monotonic_ns()
        try:
            _run(clang, directory, report, started)
        finally:
            report["cost_stages"]["qualification_wall_ns"] = time.monotonic_ns() - stage_started
        stage_started = time.monotonic_ns()
        # Compute every observed envelope before final source hashing and cost
        # capture. The zero here is only a temporary report-calculation input;
        # no decision or receipt escapes before actual costs are rebound below.
        report["economics"] = assess_opportunities(protocol, report["samples"], report["exported_code"],
                                                   0)
        report["cost_stages"]["opportunity_analysis_wall_ns"] = time.monotonic_ns() - stage_started
        report["qualified"] = True
        report["claims"].update(all_input_Core_equivalence_proved=True, selected_LLVM_equivalence_proved=True,
                               finite_native_differential_passed=True)
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        # Internal fds and executable bytes are capabilities, not report content.
        for row in report.get("candidates", {}).values():
            row.pop("image", None)
        stage_started = time.monotonic_ns()
        report["source_inputs_unchanged"] = False
        if "source_before" in report:
            try:
                report["source_after"] = _sources()
                report["source_state_after"] = _source_state()
                report["source_inputs_unchanged"] = (
                    report["source_after"] == report["source_before"]
                    and report["source_state_after"] == report["source_state_before"]
                    and report["source_state_after"]["head"] == expected_source
                    and not report["source_state_after"]["status"])
            except Exception as error:
                report["source_identity_error"] = {"type": type(error).__name__, "message": str(error)}
        report["cost_stages"]["final_source_hash_wall_ns"] = time.monotonic_ns() - stage_started
        report["charged_search_wall_ns"] = time.monotonic_ns() - started
        report["cost_stages"]["preflight_and_final_analysis_included"] = True
        if not report["source_inputs_unchanged"]:
            report.update(qualified=False, status="failed")
            report.setdefault("error", {"type": "GuardedBatchRejected", "message": "implementation source changed during campaign"})
        if report["charged_search_wall_ns"] > protocol["max_optimization_wall_ns"]:
            report.update(qualified=False, status="failed")
            report["budget_error"] = "registered study wall budget exhausted"
        if "economics" in report:
            report["economics"] = reprice_opportunities(protocol, report["economics"], report["charged_search_wall_ns"])
            if not report["qualified"]:
                report["economics"].update(
                    status="invalid_qualification_evidence", opportunity_gate_passed=False,
                    ndu_comparison_authorized_by_this_evidence=False,
                    qualification_denial={"reason": "complete_qualification_failed",
                        "source_inputs_unchanged": report["source_inputs_unchanged"],
                        "error": report.get("error"), "budget_error": report.get("budget_error")})
        if report["qualified"]:
            report["status"] = report["economics"]["status"]
        report["cost_exclusions"] = ["tool installation", "outer interpreter startup/imports/arguments",
                                      "final cost-field rebinding/report decoration/JSON encoding/writing"]
        report["limits"] = ["Synthetic scalar research demand; no real C/C++ application trace",
            "Native LLVM compiler, linker, loader, libc and operating system remain trusted",
            "VM first-trap codes are proved at Core; native trap cases observe silent SIGABRT, not its root cause",
            "The complete candidate bank was actually built; a one-selection slot does not imply a one-build online budget",
            "Budget is checked between bounded stages; compilation and proof have their own finite timeouts",
            "No NDU invocation, production admission, persistent owner state or whole-language safety claim"]
        report["wall_ns_before_result_encoding"] = time.monotonic_ns() - started
        (directory / "RESULT.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--workdir", required=True, help="new output directory, preferably outside the source tree")
    parser.add_argument("--expected-source", required=True, help="exact full source commit; dirty/raw-byte drift refuses")
    args = parser.parse_args()
    report = qualify(clang=args.clang, workdir=args.workdir, expected_source=args.expected_source)
    print(json.dumps({key: report.get(key) for key in
        ("status", "qualified", "error", "economics", "charged_search_wall_ns", "source_inputs_unchanged")}, sort_keys=True))
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
