#!/usr/bin/env python3
"""Qualify an actual closed Core owner-transfer/exit profile with pinned Lean.

Kernel theorems concern the independent phase-indexed model. Actual Core is
rechecked and projected afresh, actual VM operations are observed, and source,
toolchain, theorem and negative-control identities are retained. This receipt
does not attest an untrusted producer or prove Python/LLVM refinement.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta import hia_program_runtime as runtime
from hepta.hia_call_expansion import propose_leaf_call_expansion
from hepta.hia_owned_exit_core import (
    check_call_erasure, evaluate_model, export_core, lean_program,
)
from tools import qualify_hia_selected_formal as selected
from tools.evidence_checks import normalized_errors, require, strict_equal

SCHEMA = "hepta.hia.owned-exit-qualification.v1"
MODEL = ROOT / "formal/HiaOwnedExit.lean"
SELECTED = ROOT / "formal/selected_owned_exit.hia.json"
GENERIC_THEOREMS = {
    "create_owned", "create_preserves", "create_identity_fresh",
    "drop_empty", "drop_preserves", "zero_allocation_exact",
    "oversize_allocation_exact", "quota_stop_exact",
    "positive_refusal_exact", "positive_success_exact",
    "allocation_heap_unchanged", "allocation_next_preserves", "execute_safety",
    "initial_valid", "initial_empty", "ordinary_exit_balanced",
    "payload_budget_bound", "trap_keeps_store", "observe_emit",
    "call_erasure_preserves",
}
ACTUAL_THEOREMS = {
    "selected_call_erasure", "selected_source_safety", "selected_candidate_safety",
    "selected_source_clean_exit", "selected_candidate_clean_exit",
    "selected_payload_bound", "selected_resource_equivalence",
    "selected_refusal_exit", "selected_cancel_exit",
    "selected_trap_retains_owner", "selected_normal_exit",
}
THEOREMS = GENERIC_THEOREMS | ACTUAL_THEOREMS
MUTATIONS = {
    "empty_owner_frees_nonexistent_payload": "drop_preserves",
    "quota_stop_becomes_allocator_refusal": "quota_stop_exact",
    "actual_candidate_changes_cancel_result": "selected_call_erasure",
}
CLAIMS = {
    "generic_phase_indexed_owner_ledger_conservation": True,
    "generic_selected_payload_quota_bound": True,
    "generic_ordinary_exit_has_no_live_owner": True,
    "generic_trap_preserves_stopped_store": True,
    "generic_call_erasure_preserves_exit_store_resource_events": True,
    "actual_core_source_and_candidate_reverified_and_exported": True,
    "selected_imported_refusal_cancel_normal_and_trap_contracts_proved": True,
    "finite_actual_vm_ledger_and_operation_trace_replayed": True,
    "python_projection_or_checker_refinement_proved": False,
    "python_vm_refinement_proved": False,
    "llvm_or_machine_code_refinement_proved": False,
    "exact_step_or_call_budget_stops_preserved": False,
    "asynchronous_cancellation_cleanup_proved": False,
    "arbitrary_ownership_borrowing_ffi_or_concurrency_proved": False,
    "whole_language_soundness_proved": False,
}
LIMITATIONS = [
    "The Lean theorem ranges over finite phase-indexed programs with at most one byte-owner, not arbitrary production HIA.",
    "Actual projection accepts explicit v7/v8 Core, one closed allocator leaf and one scalar entry, boolean CFG branches, literal results and an explicit division_by_zero trap; cycles and other opcodes are rejected.",
    "Zero-size success and oversize refusal create empty owner capabilities without allocator attempts; positive quota stops create no owner; positive allocator refusal consumes an attempt.",
    "Payload allocations/frees count nonempty byte arrays. Owner capabilities have separate counters. The quota bounds modeled payload, not host RSS or allocator metadata.",
    "Cancellation is a caller-supplied cooperative boolean checked after successful allocation. Trap and evaluator budget stops retain the stopped ledger; no unwind is invented.",
    "The generated source/candidate terms are extracted from actual checked Core. Their all-input theorem is in the independent Lean semantics; Python projection/checker/VM correspondence is exercised and byte-bound, not proved.",
    "Call erasure preserves resource observations after dropping administrative call-enter/return events. Removed call/return ticks and reduced call depth require fresh budget qualification.",
    "Lean's pinned kernel, support files, Python runtime and host are trusted. JSON receipts alone are not execution authority or attestation of a hostile producer.",
    "This qualification has no LLVM/native, FFI, borrowing, concurrency, process-memory or performance claim.",
]
SOURCE_FILES = (
    "formal/HiaOwnedExit.lean", "formal/selected_owned_exit.hia.json",
    "formal/toolchain-lock.json", "formal/proof-dependencies.txt",
    "hepta/hia_owned_exit_core.py", "hepta/hia_program.py", "hepta/hia_opcodes.py",
    "hepta/hia_schema.py", "hepta/hia_json_preflight.py",
    "hepta/hia_program_composite.py", "hepta/hia_program_runtime.py",
    "hepta/hia_bounded_memory.py", "hepta/hia_call_expansion.py",
    "hepta/hia_optimization.py", "tools/qualify_hia_selected_formal.py",
    "tools/qualify_hia_owned_exit.py", "tools/evidence_checks.py",
)
MODELED_COUNTERS = {
    "allocations", "frees", "allocation_attempts", "owners_created",
    "owners_dropped", "live_owners", "live_bytes", "peak_bytes",
}
ZERO_COUNTERS = {
    "loans_started", "loans_ended", "live_local_loans", "chains_created",
    "chains_consumed", "live_chains", "chain_nodes_created",
    "chain_nodes_dropped", "live_chain_nodes",
}


def digest(data):
    return sha256(data).hexdigest()


def source_identity():
    return {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def model_text():
    text = MODEL.read_text()
    require(re.findall(r"(?m)^import ([^\n]+)$", text) == ["Lean.Elab.Tactic.Omega"],
            "unexpected OwnedExit proof import")
    require(re.search(r"(?m)^\s*(axiom|unsafe|opaque|constant|initialize|builtin_initialize|"
                      r"run_elab|run_cmd|elab|macro|syntax|set_option|#)\b|\bsorry\b", text) is None,
            "unreviewed OwnedExit proof declaration or placeholder")
    found = re.findall(r"(?m)^theorem (\w+)", text)
    require(len(found) == len(GENERIC_THEOREMS) and set(found) == GENERIC_THEOREMS,
            "OwnedExit generic theorem inventory differs")
    return text


def generated_pair(document, *, candidate_override=None, model_override=None):
    source = export_core(document)
    proposal = propose_leaf_call_expansion(source.core_bytes, callees=[source.allocator])
    candidate = export_core(proposal["candidate_core"] if candidate_override is None else candidate_override)
    # The actual theorem, not the producer's proposal receipt, asserts this relation.
    text = model_text() if model_override is None else model_override
    text += "\nnamespace HiaOwnedExit\n"
    text += "def sourceProgram : Program .empty := " + lean_program(source.tree) + "\n"
    text += "def candidateProgram : Program .empty := " + lean_program(candidate.tree) + "\n"
    text += """
theorem selected_call_erasure :
    inlineCalls sourceProgram = candidateProgram := by rfl

theorem selected_source_safety (inputs : Inputs) :
    Safe inputs.quota (run sourceProgram inputs initial) :=
  execute_safety sourceProgram inputs initial (initial_valid _) initial_empty

theorem selected_candidate_safety (inputs : Inputs) :
    Safe inputs.quota (run candidateProgram inputs initial) :=
  execute_safety candidateProgram inputs initial (initial_valid _) initial_empty

theorem selected_source_clean_exit (inputs : Inputs) (value : Nat)
    (returned : (run sourceProgram inputs initial).exit = .returned value) :
    (run sourceProgram inputs initial).store.owner = none ∧
    (run sourceProgram inputs initial).store.created = (run sourceProgram inputs initial).store.dropped ∧
    (run sourceProgram inputs initial).store.allocations = (run sourceProgram inputs initial).store.frees :=
  ordinary_exit_balanced sourceProgram inputs value returned

theorem selected_candidate_clean_exit (inputs : Inputs) (value : Nat)
    (returned : (run candidateProgram inputs initial).exit = .returned value) :
    (run candidateProgram inputs initial).store.owner = none ∧
    (run candidateProgram inputs initial).store.created = (run candidateProgram inputs initial).store.dropped ∧
    (run candidateProgram inputs initial).store.allocations = (run candidateProgram inputs initial).store.frees :=
  ordinary_exit_balanced candidateProgram inputs value returned

theorem selected_payload_bound (inputs : Inputs) :
    liveBytes (run sourceProgram inputs initial).store ≤ inputs.quota ∧
    (run sourceProgram inputs initial).store.peak ≤ inputs.quota :=
  payload_budget_bound sourceProgram inputs

theorem selected_resource_equivalence (inputs : Inputs) :
    observe (run candidateProgram inputs initial) = observe (run sourceProgram inputs initial) := by
  rw [← selected_call_erasure]
  exact call_erasure_preserves sourceProgram inputs initial

theorem selected_refusal_exit (inputs : Inputs) (owned : Store)
    (allocated : allocateOwner inputs inputs.size initial = .next owned)
    (refused : owned.ok = false) :
    (run sourceProgram inputs initial).exit = .returned 1 := by
  simp [sourceProgram, run, extentValue, allocated, conditionValue, refused, emit]

theorem selected_cancel_exit (inputs : Inputs) (owned : Store)
    (allocated : allocateOwner inputs inputs.size initial = .next owned)
    (succeeded : owned.ok = true) (cancelled : inputs.cancel = true) :
    (run sourceProgram inputs initial).exit = .returned 2 := by
  simp [sourceProgram, run, extentValue, allocated, conditionValue, succeeded, cancelled, emit]

theorem selected_trap_retains_owner (inputs : Inputs) (owned : Store)
    (allocated : allocateOwner inputs inputs.size initial = .next owned)
    (succeeded : owned.ok = true) (notCancelled : inputs.cancel = false)
    (aborted : inputs.abort = true) :
    (run sourceProgram inputs initial).exit = .trapped ∧
    (run sourceProgram inputs initial).store = owned := by
  simp [sourceProgram, run, extentValue, allocated, conditionValue, succeeded, notCancelled, aborted, emit]

theorem selected_normal_exit (inputs : Inputs) (owned : Store)
    (allocated : allocateOwner inputs inputs.size initial = .next owned)
    (succeeded : owned.ok = true) (notCancelled : inputs.cancel = false)
    (notAborted : inputs.abort = false) :
    (run sourceProgram inputs initial).exit = .returned 0 := by
  simp [sourceProgram, run, extentValue, allocated, conditionValue, succeeded, notCancelled, notAborted, emit]
end HiaOwnedExit
"""
    text += "".join("#print axioms HiaOwnedExit." + name + "\n" for name in sorted(THEOREMS))
    return source, candidate, text, {"source": source.mapping(), "candidate": candidate.mapping()}


def mutation_inputs(document):
    source, candidate, _, _ = generated_pair(document)
    model = model_text()
    free = "frees := s.frees + realOwners s"
    quota = "else if inputs.quota < requested then .heap s"
    require(model.count(free) == model.count(quota) == 1, "mutation sites differ")
    changed = json.loads(candidate.core_bytes)
    outputs = [op for fn in changed["functions"] if fn["name"] == "run"
               for block in fn["blocks"] for op in block["ops"]
               if op["op"] == "const" and op["out"][0]["type"] == "u8"
               and op["attrs"]["value"] == 2]
    require(len(outputs) == 1, "selected cancellation result mutation site differs")
    outputs[0]["attrs"]["value"] = 3
    return {
        "empty_owner_frees_nonexistent_payload": generated_pair(source.core_bytes,
            model_override=model.replace(free, "frees := s.frees + 1")),
        "quota_stop_becomes_allocator_refusal": generated_pair(source.core_bytes,
            model_override=model.replace(quota,
                "else if inputs.quota < requested then .next (createOwner s 0 false)")),
        "actual_candidate_changes_cancel_result": generated_pair(source.core_bytes,
            candidate_override=changed),
    }


def dependencies(log, *, broken=False):
    found = re.findall(r"^'HiaOwnedExit\.([^']+)' depends on axioms: \[([^\]]*)\]$", log, re.M)
    found += [(name, "") for name in re.findall(
        r"^'HiaOwnedExit\.([^']+)' does not depend on any axioms$", log, re.M)]
    require(len(found) == len(THEOREMS) and {name for name, _ in found} == THEOREMS,
            "OwnedExit theorem dependency inventory differs")
    allowed = {"propext", "Quot.sound", "Classical.choice"} | ({"sorryAx"} if broken else set())
    result = {name: [a.strip() for a in used.split(",") if a.strip()] for name, used in found}
    require(all(set(used) <= allowed and len(used) == len(set(used)) for used in result.values()),
            "OwnedExit proof depends on unreviewed axioms")
    if not broken:
        require("error:" not in log and "sorryAx" not in log,
                "positive OwnedExit proof has errors or placeholders")
    return result


def observe_vm(core, arguments, *, quota, fail_at=None, max_steps=256, max_call_depth=2):
    """Observe actual VM methods while executing the unmodified public boundary.

    This synchronous qualifier is single-threaded. Temporary subclass hooks
    call the production implementations; they do not replace their semantics.
    """
    events = []
    original = runtime._Machine

    class ObservedMachine(original):
        def allocate(self, size, optional):
            try:
                owner, ok = super().allocate(size, optional)
            except runtime.HIAProgramBudgetExceeded as error:
                if error.code == "heap":
                    events.append({"kind": "heap_stop", "requested": size})
                raise
            events.append({"kind": "allocate", "requested": size, "owner": owner.ident,
                           "bytes": len(owner.data), "ok": ok})
            return owner, ok

        def drop(self, owner):
            before = {"kind": "drop", "owner": owner.ident, "bytes": len(owner.data)}
            result = super().drop(owner)
            events.append(before)
            return result

        def invoke(self, fn, arguments, depth=0):
            entered = depth > 0 and depth < self.max_call_depth
            if entered:
                events.append({"kind": "call_enter"})
            values = super().invoke(fn, arguments, depth)
            if entered:
                events.append({"kind": "call_return"})
            return values

    with patch.object(runtime, "_Machine", ObservedMachine):
        try:
            report = runtime.execute_program(core, "run", arguments,
                max_heap_bytes=quota, allocation_fail_at=fail_at,
                max_steps=max_steps, max_call_depth=max_call_depth)
        except (runtime.HIAProgramTrap, runtime.HIAProgramBudgetExceeded) as error:
            report = error.report
    require(type(report) is dict, "VM did not retain stopped state")
    return {"status": report["status"], "value": report.get("result"),
            "error": report.get("error", {}).get("code"),
            "resources": report["resources"], "steps": report["steps"], "events": events,
            "resource_events": [e for e in events if e["kind"] not in {"call_enter", "call_return"}]}


def case_inputs():
    # Frozen before execution, no outcome-directed selection; huge lengths are
    # oversize or stopped by quota, never passed to bytearray.
    for size in (0, 1, 7, 8, 9, (1 << 63) - 1, 1 << 63, (1 << 64) - 1):
        for quota in (0, 8):
            for cancel, abort in ((False, False), (False, True), (True, False), (True, True)):
                for fail_at in (None, 1, 2):
                    yield {"arguments": [size, cancel, abort], "quota": quota, "fail_at": fail_at}


def vm_observations(source, candidate):
    cases = []
    for case in case_inputs():
        sides = {}
        for label, exported in (("source", source), ("candidate", candidate)):
            actual = observe_vm(exported.core_bytes, case["arguments"],
                                quota=case["quota"], fail_at=case["fail_at"])
            model = evaluate_model(exported.tree, *case["arguments"],
                                   quota=case["quota"], allocation_fail_at=case["fail_at"])
            require(set(actual["resources"]) == MODELED_COUNTERS | ZERO_COUNTERS,
                    "VM resource field inventory changed")
            require(all(actual["resources"][k] == 0 for k in ZERO_COUNTERS),
                    "unmodeled resource became live")
            reduced = {**actual, "resources": {k: actual["resources"][k] for k in MODELED_COUNTERS}}
            reduced.pop("steps")
            require(strict_equal(reduced, model), "actual VM/resource model disagreement")
            sides[label] = actual
        for key in ("status", "value", "error", "resources", "resource_events"):
            require(strict_equal(sides["source"][key], sides["candidate"][key]),
                    "call expansion changed actual selected resource observation")
        cases.append({**case, **sides})
    return cases


def budget_observations(source, candidate):
    arguments, quota = [8, False, False], 8
    full_before = observe_vm(source.core_bytes, arguments, quota=quota)
    full_after = observe_vm(candidate.core_bytes, arguments, quota=quota)
    require(full_before["status"] == full_after["status"] == "returned"
            and full_before["steps"] > full_after["steps"], "call tick reduction not observed")
    limits = {"steps": {"max_steps": full_after["steps"], "max_call_depth": 2},
              "calls": {"max_steps": 256, "max_call_depth": 1}}
    result = {"arguments": arguments, "quota": quota, "sufficient_limits":
              {"max_steps": 256, "max_call_depth": 2},
              "sufficient": {"source": full_before, "candidate": full_after}, "stops": {}}
    for kind, options in limits.items():
        before = observe_vm(source.core_bytes, arguments, quota=quota, **options)
        after = observe_vm(candidate.core_bytes, arguments, quota=quota, **options)
        require(before["status"] == "budget_exceeded" and before["error"] == kind
                and after["status"] == "returned",
                "fresh budget counterexample did not expose call-expansion limit change")
        result["stops"][kind] = {"limits": options, "source": before, "candidate": after}
    return result


def qualify(lean, output_directory, *, core_path=SELECTED):
    executable = Path(lean).resolve(strict=True)
    pin = json.loads((ROOT / "formal/toolchain-lock.json").read_bytes())
    binary = digest(executable.read_bytes())
    require(binary == pin["lean_binary_sha256"], "Lean binary does not match the fixed pin")
    version = subprocess.check_output([str(executable), "--version"], text=True).strip()
    require("version " + pin["version"] + "," in version, "Lean version differs")
    raw = Path(core_path).read_bytes()
    source, candidate, generated, mapping = generated_pair(raw)
    check_call_erasure(source.core_bytes, candidate.core_bytes)
    sources, support = source_identity(), selected._support_identity(executable)
    output = Path(output_directory).absolute()
    output.mkdir(parents=True, exist_ok=False)
    for name, data in (("input.hia.json", raw), ("source.hia.json", source.core_bytes),
                       ("candidate.hia.json", candidate.core_bytes), ("positive.lean", generated.encode())):
        (output / name).write_bytes(data)
    selected._json(output / "instruction-map.json", mapping)
    selected._json(output / "lean-support-files.json", support)
    report = {"schema": SCHEMA, "ok": False, "status": "running",
              "source_core_sha256": source.core_sha256, "candidate_core_sha256": candidate.core_sha256,
              "input_sha256": digest(raw), "generated_lean_sha256": digest(generated.encode()),
              "source_identity": sources, "lean_binary_sha256": binary, "lean_version": version,
              "support_manifest_sha256": digest((output / "lean-support-files.json").read_bytes()),
              "claims": dict(CLAIMS), "limitations": list(LIMITATIONS),
              "vm_case_count": len(list(case_inputs())), "model_requests": 0,
              "negative_controls": []}
    try:
        positive = selected._run_lean(executable, output / "positive.lean")
        report["positive"] = positive
        log = positive["stdout"] + positive["stderr"]
        require(positive["returncode"] == 0, "Lean rejected OwnedExit:\n" + log)
        report["theorems"] = dependencies(log)
        for name, (mut_source, mut_candidate, broken, _) in mutation_inputs(raw).items():
            (output / (name + ".lean")).write_text(broken)
            (output / (name + ".candidate.hia.json")).write_bytes(mut_candidate.core_bytes)
            observed = selected._run_lean(executable, output / (name + ".lean"))
            badlog = observed["stdout"] + observed["stderr"]
            require(observed["returncode"] == 1 and "error:" in badlog,
                    "Lean did not reject intended OwnedExit mutation: " + name)
            used = dependencies(badlog, broken=True)
            require("sorryAx" in used[MUTATIONS[name]], "mutation missed intended theorem: " + name)
            report["negative_controls"].append({"name": name, "status": "rejected_as_expected",
                "source_core_sha256": mut_source.core_sha256, "candidate_core_sha256": mut_candidate.core_sha256,
                "generated_lean_sha256": digest(broken.encode()), "theorems": used, **observed})
        report["vm_cases"] = vm_observations(source, candidate)
        report["budget_requalification"] = budget_observations(source, candidate)
        require(source_identity() == sources and selected._support_identity(executable) == support
                and digest(executable.read_bytes()) == binary,
                "proof source/toolchain changed during qualification")
        report.update(ok=True, status="passed")
        validate_report(report, output)
    except Exception as error:
        report.update(ok=False, status="failed", error=f"{type(error).__name__}: {error}")
        report["claims"] = {name: False for name in CLAIMS}
        selected._json(output / "qualification.json", report)
        raise
    selected._json(output / "qualification.json", report)
    return report


@normalized_errors
def validate_report(report, directory):
    """Reproject source and replay VM evidence; retained JSON never grants authority."""
    directory = Path(directory)
    require(type(report) is dict and report.get("schema") == SCHEMA
            and report.get("ok") is True and report.get("status") == "passed",
            "OwnedExit qualification did not pass")
    raw = (directory / "input.hia.json").read_bytes()
    source, candidate, generated, mapping = generated_pair(raw)
    check_call_erasure(source.core_bytes, candidate.core_bytes)
    require(report.get("source_core_sha256") == source.core_sha256
            and report.get("candidate_core_sha256") == candidate.core_sha256
            and report.get("input_sha256") == digest(raw)
            and (directory / "source.hia.json").read_bytes() == source.core_bytes
            and (directory / "candidate.hia.json").read_bytes() == candidate.core_bytes
            and (directory / "positive.lean").read_text() == generated
            and report.get("generated_lean_sha256") == digest(generated.encode())
            and strict_equal(json.loads((directory / "instruction-map.json").read_bytes()), mapping),
            "actual Core/model/source mapping differs")
    pin = json.loads((ROOT / "formal/toolchain-lock.json").read_bytes())
    require(strict_equal(report.get("claims"), CLAIMS) and report.get("limitations") == LIMITATIONS
            and report.get("source_identity") == source_identity()
            and report.get("lean_binary_sha256") == pin["lean_binary_sha256"]
            and type(report.get("lean_version")) is str and
            "version " + pin["version"] + "," in report["lean_version"]
            and report.get("support_manifest_sha256") == digest((directory / "lean-support-files.json").read_bytes())
            and type(report.get("vm_case_count")) is int and report["vm_case_count"] == len(list(case_inputs()))
            and type(report.get("model_requests")) is int and report["model_requests"] == 0,
            "OwnedExit scope/source/checker identity differs")
    positive = report.get("positive", {})
    log = positive.get("stdout", "") + positive.get("stderr", "")
    require(type(positive.get("returncode")) is int and positive["returncode"] == 0
            and positive.get("output_sha256") == digest(log.encode())
            and strict_equal(dependencies(log), report.get("theorems")),
            "positive kernel evidence differs")
    negative = report.get("negative_controls")
    require(type(negative) is list and len(negative) == len(MUTATIONS)
            and {row.get("name") for row in negative} == set(MUTATIONS),
            "OwnedExit negative-control inventory differs")
    expected = mutation_inputs(raw)
    for row in negative:
        name = row["name"]
        mut_source, mut_candidate, broken, _ = expected[name]
        badlog = row.get("stdout", "") + row.get("stderr", "")
        require(row.get("status") == "rejected_as_expected" and type(row.get("returncode")) is int
                and row["returncode"] == 1 and "error:" in badlog
                and row.get("source_core_sha256") == mut_source.core_sha256
                and row.get("candidate_core_sha256") == mut_candidate.core_sha256
                and (directory / (name + ".candidate.hia.json")).read_bytes() == mut_candidate.core_bytes
                and (directory / (name + ".lean")).read_text() == broken
                and row.get("generated_lean_sha256") == digest(broken.encode())
                and row.get("output_sha256") == digest(badlog.encode())
                and strict_equal(dependencies(badlog, broken=True), row.get("theorems"))
                and "sorryAx" in row["theorems"][MUTATIONS[name]],
                "negative kernel evidence differs")
    require(strict_equal(report.get("vm_cases"), vm_observations(source, candidate))
            and strict_equal(report.get("budget_requalification"), budget_observations(source, candidate)),
            "retained VM resource/budget evidence differs from fresh replay")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", required=True)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--core", type=Path, default=SELECTED)
    args = parser.parse_args(argv)
    try:
        report = qualify(args.lean, args.output_directory, core_path=args.core)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 2
    print(json.dumps({"ok": report["ok"], "theorems": len(report["theorems"]),
                      "negative_controls": len(report["negative_controls"]),
                      "vm_cases": len(report["vm_cases"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
