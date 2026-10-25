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

# The unchanged source already prints these dependencies after the proofs.
# A generic loader/import/resource error is not an intended proof rejection.
MUTATION_FAILURE = {"release_while_borrowed": "resource_preservation",
                    "unbounded_task_admission": "budget_preservation"}

# Finite diagnostics verified in leanprover/lean4 v4.19.0 (6caaee842e94):
# CoreM.lean:339, Prelude.lean:4186, Message.lean:608-611,
# runtime/exception.cpp:21-29, IOError.lean:279-280, Init/Util.lean:34,40.
# This is not a complete diagnostic parser or proof of failure causality.
KNOWN_LEAN_419_FAILURE_MARKERS = (
    "(deterministic) timeout", "maximum recursion depth has been reached",
    "(kernel) deterministic timeout", "excessive memory consumption detected",
    "deep recursion was detected at '", "(kernel) deep recursion detected",
    "(kernel) interrupted", "resource exhausted", "PANIC at ",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def negative_sources(source: str) -> dict[str, str]:
    """Construct precisely the rejected core variants used by the Lean verifier."""
    replacements = {
        "release_while_borrowed": (
            "| .release =>\n    if s.live = true ∧ s.readers = 0 ∧ s.writer = false then",
            "| .release =>\n    if s.live = true ∧ s.writer = false then",
        ),
        "unbounded_task_admission": (
            "if u.admitted + 1 ≤ b.tasks ∧ u.inputBytes + bytes ≤ b.inputBytes then",
            "if u.inputBytes + bytes ≤ b.inputBytes then",
        ),
    }
    result = {}
    for name, (original, broken) in replacements.items():
        if source.count(original) != 1:
            raise RuntimeError("Mutation is not unique or did not apply: " + name)
        result[name] = source.replace(original, broken)
    return result


def reject_known_runtime_failure(log: str) -> None:
    """Known resource/runtime failures never qualify as semantic rejection."""
    if any(marker in log for marker in KNOWN_LEAN_419_FAILURE_MARKERS):
        raise ValueError("Lean output contains a known resource limit or runtime failure")


def require_negative_rejection(name: str, exit_code: int, log: str) -> None:
    """Check reported proof failure, not external attestation of an execution."""
    if (name not in MUTATION_FAILURE or type(exit_code) is not int or exit_code <= 0
            or not isinstance(log, str) or "error:" not in log):
        raise ValueError("Negative proof did not report a normal failing Lean exit")
    reject_known_runtime_failure(log)
    target = MUTATION_FAILURE[name]
    found = re.findall(r"'Hepta\.([^']+)' depends on axioms: \[([^\]]*)\]", log)
    target_axioms = [[item.strip() for item in used.split(",") if item.strip()]
                     for theorem, used in found if theorem == target]
    allowed_broken = {"propext", "Quot.sound", "Classical.choice", "sorryAx"}
    if (not target_axioms or any("sorryAx" not in used or set(used) - allowed_broken
                                or len(used) != len(set(used)) for used in target_axioms)
            or any(used != target_axioms[0] for used in target_axioms)):
        raise ValueError("Negative output did not invalidate its intended theorem")


def verify(lean: str, output: Path):
    executable = Path(lean).resolve(strict=True)
    executable_hash = sha(executable.read_bytes())
    pin = json.loads((ROOT / "formal/toolchain-lock.json").read_text())["lean_binary_sha256"]
    if executable_hash != pin:
        raise RuntimeError("The proof checker must match the pinned Lean binary SHA-256")
    lean = str(executable)
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
        checked_source = source + "\n" + checks + "\n"
        p.write_text(checked_source)
        result = subprocess.run([lean, str(p)], capture_output=True, text=True, timeout=60)
        log = result.stdout + result.stderr
        reject_known_runtime_failure(log)
        if result.returncode or "sorryAx" in log or "error:" in log:
            raise RuntimeError("Lean rejected the core:\n" + log)
        found = re.findall(r"'Hepta\.([^']+)' depends on axioms: \[([^\]]*)\]", log)
        axioms = {name: [a.strip() for a in used.split(",") if a.strip()] for name, used in found}
        if set(axioms) != set(names):
            raise RuntimeError("Missing kernel dependency reports")
        for name, used in axioms.items():
            if set(used) - {"propext", "Quot.sound", "Classical.choice"}:
                raise RuntimeError("Unexpected axioms in " + name)
        mutations = negative_sources(source)
        negative = []
        for name, broken in mutations.items():
            p.write_text(broken)
            rejected = subprocess.run([lean, str(p)], capture_output=True, text=True, timeout=60)
            require_negative_rejection(name, rejected.returncode, rejected.stdout + rejected.stderr)
            negative.append({"mutation": name, "status": "rejected_as_expected", "source_sha256": sha(broken.encode()),
                             "exit_code": rejected.returncode, "log": rejected.stdout + rejected.stderr,
                             "log_sha256": sha((rejected.stdout + rejected.stderr).encode())})
    if sha(file.read_bytes()) != sha(source.encode()) or sha(executable.read_bytes()) != executable_hash:
        raise RuntimeError("Formal source or executable changed while checking")
    report = {"schema": "hepta.formal.v2", "status": "passed", "lean": version.stdout.strip(),
              "lean_binary_sha256": executable_hash, "source": "formal/HeptaCore.lean",
              "source_sha256": sha(source.encode()), "theorems": axioms, "negative_mutations": negative,
              "checked_source_sha256": sha(checked_source.encode()),
              "version_exit_code": version.returncode, "kernel_exit_code": result.returncode,
              "kernel_output": log, "kernel_output_sha256": sha(log.encode()),
              "claims": {"abstract_core_theorems_checked": True,
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
