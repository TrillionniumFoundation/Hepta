#!/usr/bin/env python3
"""Check actual Lean proofs and ensure two broken guards are rejected."""
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


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(lean: str, output: Path):
    version = subprocess.run([lean, "--version"], capture_output=True, text=True, timeout=20)
    if version.returncode or "version 4.19.0," not in version.stdout:
        raise RuntimeError("Require a functioning, pinned Lean 4.19.0: " + version.stdout + version.stderr)
    file = ROOT / "formal/HeptaCore.lean"
    source = file.read_text()
    if re.search(r"(?m)^\s*(axiom|unsafe|opaque)\s|\bsorry\b", source):
        raise RuntimeError("Core source contains an untrusted axiom, escape or placeholder")
    names = re.findall(r"(?m)^theorem\s+([A-Za-z0-9_]+)", source)
    checks = "\n".join("#print axioms Hepta." + name for name in names)
    with tempfile.TemporaryDirectory(prefix="hepta-proofs-") as td:
        p = Path(td) / "Check.lean"
        p.write_text(source + "\n" + checks + "\n")
        result = subprocess.run([lean, str(p)], capture_output=True, text=True, timeout=60)
        log = result.stdout + result.stderr
        if result.returncode or "sorryAx" in log:
            raise RuntimeError("Lean rejected the core:\n" + log)
        found = re.findall(r"'Hepta\.([^']+)' depends on axioms: \[([^\]]*)\]", log)
        axioms = {name: [a.strip() for a in used.split(",") if a.strip()] for name, used in found}
        if set(axioms) != set(names):
            raise RuntimeError("Missing kernel dependency reports")
        for name, used in axioms.items():
            if set(used) - {"propext", "Quot.sound", "Classical.choice"}:
                raise RuntimeError("Unexpected axioms in " + name)
        mutations = {
            "release_while_borrowed": source.replace(
                "| .release =>\n    if s.live = true ∧ s.readers = 0 ∧ s.writer = false then",
                "| .release =>\n    if s.live = true ∧ s.writer = false then"),
            "unbounded_task_admission": source.replace(
                "if u.admitted + 1 ≤ b.tasks ∧ u.inputBytes + bytes ≤ b.inputBytes then",
                "if u.inputBytes + bytes ≤ b.inputBytes then"),
        }
        negative = []
        for name, broken in mutations.items():
            if broken == source:
                raise RuntimeError("Mutation did not apply: " + name)
            p.write_text(broken)
            rejected = subprocess.run([lean, str(p)], capture_output=True, text=True, timeout=60)
            if rejected.returncode == 0 or "error:" not in rejected.stdout + rejected.stderr:
                raise RuntimeError("Broken core was not rejected: " + name)
            negative.append({"mutation": name, "status": "rejected_as_expected", "source_sha256": sha(broken.encode()),
                             "log_sha256": sha((rejected.stdout + rejected.stderr).encode())})
    if sha(file.read_bytes()) != sha(source.encode()):
        raise RuntimeError("Formal source changed while checking")
    report = {"schema": "hepta.formal.v1", "status": "passed", "lean": version.stdout.strip(),
              "lean_binary_sha256": sha(Path(lean).read_bytes()), "source": "formal/HeptaCore.lean",
              "source_sha256": sha(source.encode()), "theorems": axioms, "negative_mutations": negative,
              "kernel_output": log, "claims": {"abstract_core_theorems_checked": True,
                  "production_compiler_refinement_proved": False, "whole_language_soundness_proved": False,
                  "ffi_or_hardware_proved": False, "termination_or_bounded_cancellation_proved": False},
              "scope": "Abstract loan-count resource states, group admission/channel occupancy, wrapping-u64 expression-to-stack lowering"}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lean", default=os.environ.get("LEAN", str(ROOT.parent / "toolchains/lean-4.19.0/bin/lean")))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/formal-validation.json")
    args = parser.parse_args()
    report = verify(args.lean, args.output)
    print(json.dumps({"status": report["status"], "theorems": len(report["theorems"]), "negative_mutations": len(report["negative_mutations"]), "output": str(args.output)}))


if __name__ == "__main__":
    main()
