#!/usr/bin/env python3
"""Kernel-check the explicit provenance and typed-expression models.

These proofs deliberately do not upgrade production compiler/FFI claims.
The executable identity, every theorem dependency, and five rejected mutations
are retained. A version-looking substitute executable is not sufficient.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_THEOREMS = {
    "Hepta.Memory." + name for name in (
        "access_authorized", "access_within_allocation", "other_identity_rejected",
        "stale_generation_rejected", "retired_allocation_rejected",
        "reuse_does_not_revive_old_pointer", "one_past_cannot_read",
        "narrowing_preserves_origin", "narrowing_preserves_authority",
        "narrowing_cannot_gain_write", "compatible_symmetric",
        "admission_preserves_exclusivity", "overlapping_mutable_view_rejected",
    )
} | {
    "Hepta.TypedCore." + name for name in (
        "word_canonical", "bool_canonical", "preservation", "progress",
        "trace_preservation", "well_typed_cannot_get_stuck",
    )
}
MUTATIONS = {
    "discard_allocation_identity": ("p.identity = a.identity ∧", "True ∧"),
    "discard_generation": ("p.generation = a.generation ∧", "True ∧"),
    "discard_access_extent": ("p.offset + width ≤ a.bytes\n", "True\n"),
    "gain_write_on_readonly_view": (
        "offset + length ≤ v.length ∧ (write = true → v.writable = true)",
        "offset + length ≤ v.length"),
    "addition_changes_value_type": (
        "(.word (a + b))", "(.boolean true)"),
}
CLAIMS = {
    "abstract_provenance_theorems_checked": True,
    "closed_expression_type_soundness_checked": True,
    "production_type_system_soundness_proved": False,
    "source_to_ir_or_backend_refinement_proved": False,
    "foreign_pointer_validity_proved": False,
    "hardware_behavior_proved": False,
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(lean: str, output: Path) -> dict:
    executable = Path(lean).resolve(strict=True)
    expected = json.loads((ROOT / "formal/toolchain-lock.json").read_text())
    executable_hash = digest(executable.read_bytes())
    if executable_hash != expected["lean_binary_sha256"]:
        raise RuntimeError("The proof checker must match the pinned Lean binary SHA-256")
    version = subprocess.run([str(executable), "--version"], capture_output=True, text=True, timeout=20)
    if version.returncode or "version 4.19.0," not in version.stdout:
        raise RuntimeError("The pinned Lean executable did not run: " + version.stdout + version.stderr)
    path = ROOT / "formal/HeptaMemory.lean"
    source = path.read_text()
    if re.search(r"(?m)^\s*(axiom|unsafe|opaque)\s|\bsorry\b", source):
        raise RuntimeError("Proof source contains an untrusted declaration or placeholder")
    namespace = ""
    declared = set()
    for line in source.splitlines():
        match = re.fullmatch(r"namespace ([A-Za-z0-9_.]+)", line)
        if match:
            namespace = match.group(1)
        match = re.match(r"theorem ([A-Za-z0-9_]+)", line)
        if match:
            declared.add(namespace + "." + match.group(1))
    if declared != EXPECTED_THEOREMS:
        raise RuntimeError("The declared theorem inventory differs from the qualification contract")
    checks = "\n".join("#print axioms " + name for name in sorted(declared))
    with tempfile.TemporaryDirectory(prefix="hepta-memory-proofs-") as temporary:
        checked = Path(temporary) / "Check.lean"
        checked.write_text(source + "\n" + checks + "\n")
        proc = subprocess.run([str(executable), str(checked)], capture_output=True, text=True, timeout=60)
        log = proc.stdout + proc.stderr
        if proc.returncode or "sorryAx" in log:
            raise RuntimeError("Lean rejected the memory/type core:\n" + log)
        axioms = {name: [x.strip() for x in used.split(",") if x.strip()]
                  for name, used in re.findall(r"'([^']+)' depends on axioms: \[([^\]]*)\]", log)}
        for name in re.findall(r"'([^']+)' does not depend on any axioms", log):
            axioms[name] = []
        if set(axioms) != declared or any(set(used) - {"propext", "Quot.sound", "Classical.choice"}
                                          for used in axioms.values()):
            raise RuntimeError("Missing theorem dependencies or unexpected axioms")
        rejected = []
        for label, (old, new) in MUTATIONS.items():
            if source.count(old) != 1:
                raise RuntimeError("Expected one mutation site: " + label)
            broken = source.replace(old, new, 1)
            checked.write_text(broken + "\n" + checks + "\n")
            bad = subprocess.run([str(executable), str(checked)], capture_output=True, text=True, timeout=60)
            bad_log = bad.stdout + bad.stderr
            if bad.returncode == 0 or "error:" not in bad_log:
                raise RuntimeError("Broken semantics did not invalidate the proofs: " + label)
            rejected.append({"mutation": label, "status": "rejected_as_expected",
                             "source_sha256": digest(broken.encode()), "returncode": bad.returncode,
                             "log": bad_log, "log_sha256": digest(bad_log.encode())})
    if digest(path.read_bytes()) != digest(source.encode()) or digest(executable.read_bytes()) != executable_hash:
        raise RuntimeError("Proof source or executable changed during qualification")
    report = {"schema": "hepta.memory-proofs.v1", "status": "passed",
              "lean": version.stdout.strip(), "lean_binary_sha256": executable_hash,
              "source": str(path.relative_to(ROOT)), "source_sha256": digest(source.encode()),
              "theorems": axioms, "negative_mutations": rejected, "kernel_output": log,
              "claims": CLAIMS,
              "scope": {"memory": "fresh allocation identity and generation, byte ranges, view narrowing and pairwise loan compatibility",
                        "types": "closed wrapping-u64/boolean/add/equality/conditional expression small-step progress and preservation",
                        "limits": ["Natural-number extents and fresh generations do not model machine integer wraparound or address reuse internals.",
                                   "Loan admission alone is not the production lifetime/ownership checker.",
                                   "No correspondence theorem to Python, resource IR, Rust or C lowering is established.",
                                   "No foreign pointer, thread interleaving, hardware or full language proof is asserted."]}}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def validate_report(report: dict) -> None:
    source = ROOT / "formal/HeptaMemory.lean"
    lock = json.loads((ROOT / "formal/toolchain-lock.json").read_text())
    if (report.get("schema") != "hepta.memory-proofs.v1" or report.get("status") != "passed"
            or report.get("source") != str(source.relative_to(ROOT))
            or report.get("source_sha256") != digest(source.read_bytes())
            or report.get("lean_binary_sha256") != lock["lean_binary_sha256"]
            or set(report.get("theorems", {})) != EXPECTED_THEOREMS
            or report.get("claims") != CLAIMS):
        raise ValueError("Proof report identity, theorem inventory, or claims differ")
    for used in report["theorems"].values():
        if not isinstance(used, list) or any(not isinstance(x, str) for x in used) or set(used) - {"propext", "Quot.sound", "Classical.choice"}:
            raise ValueError("Untrusted proof dependencies")
    negative = report.get("negative_mutations", [])
    if len(negative) != len(MUTATIONS) or {x.get("mutation") for x in negative} != set(MUTATIONS):
        raise ValueError("Incomplete proof mutation denominator")
    for item in negative:
        old, new = MUTATIONS[item["mutation"]]
        broken = source.read_text().replace(old, new, 1)
        if (item.get("status") != "rejected_as_expected" or type(item.get("returncode")) is not int
                or item["returncode"] == 0 or item.get("source_sha256") != digest(broken.encode())
                or not isinstance(item.get("log"), str) or "error:" not in item["log"]
                or item.get("log_sha256") != digest(item["log"].encode())):
            raise ValueError("A broken proof was not actually rejected with retained diagnostics")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", default=os.environ.get("LEAN", str(ROOT.parent / "toolchains/lean-4.19.0/bin/lean")))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/memory-proofs.json")
    args = parser.parse_args()
    report = verify(args.lean, args.output)
    validate_report(report)
    print(json.dumps({"status": report["status"], "theorems": len(report["theorems"]),
                      "negative_mutations": len(report["negative_mutations"]), "output": str(args.output)}))


if __name__ == "__main__":
    main()
