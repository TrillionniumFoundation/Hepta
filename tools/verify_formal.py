#!/usr/bin/env python3
"""Kernel-check the pinned abstract core and its intended broken-guard controls.

Version-looking output is not executable identity. Receipts bind the exact
checked text and actual positive/negative output; their structural validator
does not authenticate a report invented by an untrusted third-party producer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.evidence_checks import normalized_errors, require, strict_equal

SCHEMA = "hepta.formal.v2"
EXPECTED_THEOREMS = {
    "resource_preservation", "no_release_with_readers", "no_release_with_writer",
    "released_cannot_be_borrowed", "release_is_not_repeatable",
    "resource_trace_preservation", "budget_preservation",
    "full_channel_rejects_send", "exhausted_tasks_reject_admission",
    "execute_append", "lowering_preserves_value",
}
MUTATIONS = {
    "release_while_borrowed": (
        "| .release =>\n    if s.live = true ∧ s.readers = 0 ∧ s.writer = false then",
        "| .release =>\n    if s.live = true ∧ s.writer = false then"),
    "unbounded_task_admission": (
        "if u.admitted + 1 ≤ b.tasks ∧ u.inputBytes + bytes ≤ b.inputBytes then",
        "if u.inputBytes + bytes ≤ b.inputBytes then"),
}
MUTATION_FAILURE = {
    "release_while_borrowed": "no_release_with_readers",
    "unbounded_task_admission": "exhausted_tasks_reject_admission",
}
CLAIMS = {"abstract_core_theorems_checked": True,
          "production_compiler_refinement_proved": False,
          "whole_language_soundness_proved": False,
          "ffi_or_hardware_proved": False,
          "termination_or_bounded_cancellation_proved": False}
SCOPE = "Abstract loan-count resource states, group admission/channel occupancy, wrapping-u64 expression-to-stack lowering"
LIMITS = [
    "The core does not model production pointer provenance, lifetimes, allocator behavior, FFI, scheduling or hardware.",
    "No correspondence theorem to the Python checker, resource IR or actual Rust/C/LLVM backend is established.",
    "The pinned executable relies on its installed Lean runtime and imported standard library as trusted infrastructure.",
    "Receipt validation checks retained observations and identities; it does not authenticate arbitrary third-party JSON or a hostile host.",
]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_text(source: str) -> str:
    """Use the reviewed core profile and print each expected dependency once."""
    require(isinstance(source, str) and 0 < len(source.encode()) <= 1024 * 1024,
            "Core source missing or oversized")
    if re.search(r"(?m)^\s*(axiom|unsafe|opaque|constant|initialize|builtin_initialize|"
                 r"run_elab|run_cmd|elab|macro|syntax|set_option)\b|\bsorry\b", source):
        raise ValueError("Core source contains an untrusted declaration, option or placeholder")
    require(re.findall(r"(?m)^import\s+([^\n]+)$", source) == ["Lean.Elab.Tactic.Omega"],
            "Core import profile differs from the reviewed standard-library dependency")
    require(re.findall(r"(?m)^(namespace|end)\s+([^\n]+)$", source) ==
            [("namespace", "Hepta"), ("end", "Hepta")], "Core namespace profile differs")
    declared = re.findall(r"(?m)^theorem\s+([A-Za-z0-9_]+)", source)
    require(len(declared) == len(EXPECTED_THEOREMS) and set(declared) == EXPECTED_THEOREMS,
            "The declared theorem inventory differs from the qualification contract")
    printed = []
    for line in source.splitlines():
        if not line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"#print axioms (?:Hepta\.)?([A-Za-z0-9_]+)", line)
        require(match is not None and match.group(1) in EXPECTED_THEOREMS,
                "Only reviewed theorem dependency print commands are supported")
        printed.append(match.group(1))
    require(len(set(printed)) == len(printed), "Duplicate source dependency print")
    checks = "\n".join("#print axioms Hepta." + name for name in sorted(EXPECTED_THEOREMS - set(printed)))
    return source + "\n" + checks + "\n"


def dependencies(log: str, *, broken: bool = False) -> dict:
    require(isinstance(log, str) and 0 < len(log) <= 1024 * 1024,
            "Kernel dependency output missing or oversized")
    found = re.findall(r"^'Hepta\.([^']+)' depends on axioms: \[([^\]]*)\]$", log, re.MULTILINE)
    found += [(name, "") for name in re.findall(r"^'Hepta\.([^']+)' does not depend on any axioms$", log, re.MULTILINE)]
    require(len(found) == len(EXPECTED_THEOREMS) and {name for name, _ in found} == EXPECTED_THEOREMS,
            "Missing, unexpected or duplicated kernel theorem reports")
    allowed = {"propext", "Quot.sound", "Classical.choice"} | ({"sorryAx"} if broken else set())
    result = {}
    for name, text in found:
        used = [a.strip() for a in text.split(",") if a.strip()]
        require(len(set(used)) == len(used) and not set(used) - allowed,
                "Unexpected or duplicated axioms in " + name)
        result[name] = used
    if not broken:
        require(re.search(r"(?i)\berror:|\bsorryAx\b|declaration uses ['\"]sorry['\"]", log) is None,
                "Successful proof output contains an error or placeholder")
    return result


def _streams(stdout, stderr) -> str:
    require(isinstance(stdout, str) and isinstance(stderr, str)
            and len(stdout) + len(stderr) <= 1024 * 1024, "Missing or oversized command streams")
    return stdout + stderr


def _version(probe: dict) -> str:
    require(isinstance(probe, dict) and type(probe.get("returncode")) is int
            and probe["returncode"] == 0, "The pinned Lean version probe did not succeed")
    _streams(probe.get("stdout"), probe.get("stderr"))
    require(probe["stderr"] == "" and re.fullmatch(r"Lean \(version 4\.19\.0, [^\n]+\)\n?", probe["stdout"]) is not None,
            "Pinned Lean version output differs")
    return probe["stdout"].strip()


def verify(lean: str, output: Path) -> dict:
    executable = Path(lean).resolve(strict=True)
    lock_path = ROOT / "formal/toolchain-lock.json"
    lock_bytes = lock_path.read_bytes()
    expected = json.loads(lock_bytes)
    executable_hash = sha(executable.read_bytes())
    if executable_hash != expected["lean_binary_sha256"]:
        raise RuntimeError("The proof checker must match the pinned Lean binary SHA-256 before execution")
    version = subprocess.run([str(executable), "--version"], capture_output=True, text=True, timeout=20)
    probe = {"returncode": version.returncode, "stdout": version.stdout, "stderr": version.stderr}
    lean_version = _version(probe)
    path = ROOT / "formal/HeptaCore.lean"
    source_bytes = path.read_bytes()
    source = source_bytes.decode("utf-8")
    checked = checked_text(source)

    def unchanged():
        if (path.read_bytes() != source_bytes or lock_path.read_bytes() != lock_bytes
                or sha(executable.read_bytes()) != executable_hash):
            raise RuntimeError("Proof source, toolchain lock or executable changed during qualification")

    def run(input_path: Path, text: str):
        unchanged()
        data = text.encode("utf-8")
        input_path.write_bytes(data)
        proc = subprocess.run([str(executable), str(input_path)], capture_output=True, text=True, timeout=60)
        if input_path.read_bytes() != data:
            raise RuntimeError("The checked temporary proof input changed during execution")
        unchanged()
        return proc, _streams(proc.stdout, proc.stderr)

    with tempfile.TemporaryDirectory(prefix="hepta-proofs-") as temporary:
        input_path = Path(temporary) / "Check.lean"
        positive, log = run(input_path, checked)
        require(type(positive.returncode) is int and positive.returncode == 0, "Lean rejected the abstract core:\n" + log)
        axioms = dependencies(log)
        negative = []
        for name, (old, new) in MUTATIONS.items():
            require(source.count(old) == 1, "Expected exactly one mutation site: " + name)
            broken = source.replace(old, new, 1)
            broken_checked = checked_text(broken)
            bad, bad_log = run(input_path, broken_checked)
            require(type(bad.returncode) is int and bad.returncode == 1 and "error:" in bad_log,
                    "Broken semantics were not rejected as a Lean proof error: " + name)
            require("sorryAx" in dependencies(bad_log, broken=True)[MUTATION_FAILURE[name]],
                    "Mutation did not invalidate its intended theorem: " + name)
            negative.append({"mutation": name, "status": "rejected_as_expected",
                             "source_sha256": sha(broken.encode()),
                             "checked_source_sha256": sha(broken_checked.encode()),
                             "returncode": bad.returncode, "stdout": bad.stdout, "stderr": bad.stderr,
                             "log": bad_log, "log_sha256": sha(bad_log.encode()),
                             "failed_theorem": "Hepta." + MUTATION_FAILURE[name]})
    unchanged()
    report = {"schema": SCHEMA, "status": "passed", "lean": lean_version,
              "lean_binary_sha256": executable_hash, "version_probe": probe,
              "toolchain_lock_sha256": sha(lock_bytes), "source": "formal/HeptaCore.lean",
              "source_sha256": sha(source_bytes), "checked_source_sha256": sha(checked.encode()),
              "theorems": axioms, "negative_mutations": negative,
              "kernel_stdout": positive.stdout, "kernel_stderr": positive.stderr,
              "kernel_output": log, "kernel_returncode": positive.returncode,
              "kernel_output_sha256": sha(log.encode()),
              "claims": dict(CLAIMS), "scope": SCOPE, "limits": list(LIMITS)}
    validate_report(report)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


@normalized_errors
def validate_report(report: dict) -> None:
    """Validate retained observations, not an attestation of a hostile producer."""
    source_path = ROOT / "formal/HeptaCore.lean"
    source_bytes = source_path.read_bytes()
    source = source_bytes.decode("utf-8")
    checked = checked_text(source)
    lock_bytes = (ROOT / "formal/toolchain-lock.json").read_bytes()
    lock = json.loads(lock_bytes)
    require(isinstance(report, dict) and report.get("schema") == SCHEMA and report.get("status") == "passed"
            and report.get("source") == "formal/HeptaCore.lean"
            and report.get("source_sha256") == sha(source_bytes)
            and report.get("checked_source_sha256") == sha(checked.encode())
            and report.get("lean_binary_sha256") == lock["lean_binary_sha256"]
            and report.get("toolchain_lock_sha256") == sha(lock_bytes),
            "Proof report source, checker or checked-input identity differs")
    require(strict_equal(report.get("claims"), CLAIMS) and strict_equal(report.get("scope"), SCOPE)
            and strict_equal(report.get("limits"), LIMITS), "Proof report scope or claims differ")
    require(report.get("lean") == _version(report.get("version_probe")), "Lean version differs from its actual probe")
    require(type(report.get("kernel_returncode")) is int and report["kernel_returncode"] == 0,
            "Positive kernel execution missing")
    log = _streams(report.get("kernel_stdout"), report.get("kernel_stderr"))
    require(report.get("kernel_output") == log and report.get("kernel_output_sha256") == sha(log.encode()),
            "Positive output differs from retained command streams")
    require(strict_equal(dependencies(log), report.get("theorems")), "Theorem dependencies differ from actual kernel output")
    negative = report.get("negative_mutations")
    require(isinstance(negative, list) and len(negative) == len(MUTATIONS)
            and {item.get("mutation") for item in negative} == set(MUTATIONS),
            "Incomplete or duplicated negative mutation denominator")
    for item in negative:
        name = item["mutation"]
        old, new = MUTATIONS[name]
        require(source.count(old) == 1, "Expected exactly one mutation site: " + name)
        broken = source.replace(old, new, 1)
        log = _streams(item.get("stdout"), item.get("stderr"))
        require(item.get("status") == "rejected_as_expected"
                and type(item.get("returncode")) is int and item["returncode"] == 1
                and item.get("source_sha256") == sha(broken.encode())
                and item.get("checked_source_sha256") == sha(checked_text(broken).encode())
                and item.get("log") == log and item.get("log_sha256") == sha(log.encode())
                and item.get("failed_theorem") == "Hepta." + MUTATION_FAILURE[name]
                and "error:" in log, "Broken proof input or retained rejection evidence differs")
        require("sorryAx" in dependencies(log, broken=True)[MUTATION_FAILURE[name]],
                "Mutation rejection did not reach its intended theorem")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", default=os.environ.get("LEAN", str(ROOT.parent / "toolchains/lean-4.19.0/bin/lean")))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/formal-validation.json")
    args = parser.parse_args()
    report = verify(args.lean, args.output)
    print(json.dumps({"status": report["status"], "theorems": len(report["theorems"]),
                      "negative_mutations": len(report["negative_mutations"]), "output": str(args.output)}))


if __name__ == "__main__":
    main()
