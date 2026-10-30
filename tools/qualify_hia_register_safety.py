#!/usr/bin/env python3
"""Kernel-check register safety and an actual selected dead-literal rewrite.

The proof quantifies over every well-formed program in the selected register
machine. Actual before/after Core is reverified and exported to that machine;
the exporter and production backend are explicitly outside the proved theorem.
No missing checker, skipped mutation, or failed kernel invocation can pass.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_program_runtime import execute_program
from tools import qualify_hia_selected_formal as selected
from tools.evidence_checks import normalized_errors, require, strict_equal

SCHEMA = "hepta.hia.register-safety.v1"
MODEL = ROOT / "formal/HiaRegisterSafety.lean"
SELECTED = ROOT / "formal/selected_u32_dead_literal.hia.json"
GENERIC_THEOREMS = {
    "read_defined", "evaluate_total", "executeOne_total", "run_total", "execute_total",
    "read_append_existing", "dead_literal_preserves",
}
ACTUAL_THEOREMS = {
    "source_well_formed", "candidate_well_formed", "source_is_dead_extension",
    "selected_source_total", "selected_candidate_total", "selected_rewrite_equivalent",
}
THEOREMS = GENERIC_THEOREMS | ACTUAL_THEOREMS | {"run_append"}
MUTATIONS = {
    "off_by_one_register_guard": "evaluate_total",
    "dead_literal_changes_result": "dead_literal_preserves",
    "actual_candidate_add_becomes_sub": "source_is_dead_extension",
}
CLAIMS = {
    "all_well_formed_selected_register_programs_total": True,
    "exact_register_growth_proved": True,
    "generic_dead_literal_removal_preserves_value": True,
    "actual_before_after_core_reverified": True,
    "selected_rewrite_all_u32_arguments_proved_in_imported_model": True,
    "exporter_or_python_verifier_refinement_proved": False,
    "resource_lifetimes_or_cancellation_proved": False,
    "backend_or_machine_code_refinement_proved": False,
    "whole_language_soundness_proved": False,
}
LIMITATIONS = [
    "The mathematical machine admits straight-line u32 literals and wrapping add/sub with positional registers.",
    "The generic proof establishes defined register reads, total execution and exact logical register growth, not heap or process memory bounds.",
    "The selected actual Core has two u32 parameters, one u32 return and one block; its final unused literal is removed.",
    "Exported Core mapping and production Python checking are re-executed and byte-bound, but their refinement is not machine-proved.",
    "LLVM, native machine code, ownership, borrowing, traps, FFI, concurrency and cancellation remain outside these theorems.",
    "A deleted instruction changes evaluator tick counts; this proof does not preserve budget-stop behavior.",
    "Lean's pinned kernel, standard-library support and host are trusted; retained JSON is not an attestation of an untrusted producer.",
]
SOURCE_FILES = tuple(dict.fromkeys((*selected.SOURCE_FILES,
    "formal/HiaRegisterSafety.lean", "tools/qualify_hia_register_safety.py",
    "hepta/hia_program_composite.py", "hepta/hia_json_preflight.py", "hepta/hia_opcodes.py")))


def digest(data):
    return sha256(data).hexdigest()


def _json(path, value):
    selected._json(path, value)


def _source_identity():
    return {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def _safety_text():
    text = MODEL.read_text(encoding="utf-8")
    require(re.search(r"(?m)^\s*(import|axiom|unsafe|opaque|constant|initialize|builtin_initialize|"
                      r"run_elab|run_cmd|elab|macro|syntax|set_option|#)\b|\bsorry\b", text) is None,
            "register model has an unreviewed declaration, import or placeholder")
    names = re.findall(r"(?m)^theorem (\w+)", text)
    require(len(names) == len(GENERIC_THEOREMS) and set(names) == GENERIC_THEOREMS,
            "generic register theorem inventory differs")
    return text


def _definition(name, mapping):
    code = ", ".join(row["lean_operation"] for row in mapping["instructions"])
    return (f"def {name} : Program := {{\n  code := [{code}],\n"
            f"  result := {mapping['result_register']}\n}}\n")


def export_pair(document, *, candidate_override=None, model_override=None):
    source, _, source_map = selected.export_program(document)
    core = source.as_dict()
    last = core["functions"][0]["blocks"][0]["ops"][-1]
    require(last["op"] == "const" and len(source_map["instructions"]) > 1
            and source_map["result_register"] != source_map["instructions"][-1]["result_register"],
            "selected source must end in an actually unused u32 literal")
    derived = deepcopy(core)
    derived["functions"][0]["blocks"][0]["ops"].pop()
    candidate, _, candidate_map = selected.export_program(
        derived if candidate_override is None else candidate_override)
    literal = last["attrs"]["value"]
    model = _safety_text() if model_override is None else model_override
    text = selected._model_text() + "\n" + model + "\nnamespace HiaSelectedCore\n"
    text += _definition("sourceProgram", source_map) + _definition("candidateProgram", candidate_map)
    text += (
        "theorem source_well_formed : WellFormed sourceProgram 2 := by\n"
        "  simp [WellFormed, ValidCode, ValidOperation, sourceProgram]\n"
        "theorem candidate_well_formed : WellFormed candidateProgram 2 := by\n"
        "  simp [WellFormed, ValidCode, ValidOperation, candidateProgram]\n"
        "theorem source_is_dead_extension :\n"
        f"    sourceProgram = appendDeadLiteral candidateProgram (BitVec.ofNat 32 {literal}) := by rfl\n"
        "theorem selected_source_total (x y : Word) :\n"
        "    ∃ value, execute sourceProgram [x, y] = some value :=\n"
        "  execute_total sourceProgram [x, y] source_well_formed\n"
        "theorem selected_candidate_total (x y : Word) :\n"
        "    ∃ value, execute candidateProgram [x, y] = some value :=\n"
        "  execute_total candidateProgram [x, y] candidate_well_formed\n"
        "theorem selected_rewrite_equivalent (x y : Word) :\n"
        "    execute sourceProgram [x, y] = execute candidateProgram [x, y] := by\n"
        "  rw [source_is_dead_extension]\n"
        "  exact dead_literal_preserves candidateProgram [x, y] _ candidate_well_formed\n"
        "end HiaSelectedCore\n"
    )
    text += "".join("#print axioms HiaSelectedCore." + name + "\n" for name in sorted(THEOREMS))
    return source, candidate, text, {"source": source_map, "candidate": candidate_map}


def mutation_inputs(document):
    source, candidate, _, _ = export_pair(document)
    model = _safety_text()
    guard = "left < available ∧ right < available"
    require(model.count(guard) == 1, "register-guard mutation site differs")
    result = "result := program.result }"
    require(model.count(result) == 1, "dead-code result mutation site differs")
    changed = candidate.as_dict()
    additions = [op for op in changed["functions"][0]["blocks"][0]["ops"]
                 if op["op"] == "int.add.wrap"]
    require(additions, "actual candidate mutation needs an existing wrapping add")
    additions[0]["op"] = "int.sub.wrap"
    return {
        "off_by_one_register_guard": export_pair(source,
            model_override=model.replace(guard, "left ≤ available ∧ right ≤ available")),
        "dead_literal_changes_result": export_pair(source,
            model_override=model.replace(result, "result := program.result + 1 }")),
        "actual_candidate_add_becomes_sub": export_pair(source, candidate_override=changed),
    }


def dependencies(log, *, broken=False):
    found = re.findall(r"^'HiaSelectedCore\.([^']+)' depends on axioms: \[([^\]]*)\]$", log, re.M)
    found += [(name, "") for name in re.findall(
        r"^'HiaSelectedCore\.([^']+)' does not depend on any axioms$", log, re.M)]
    require(len(found) == len(THEOREMS) and {name for name, _ in found} == THEOREMS,
            "register theorem dependency inventory differs")
    allowed = {"propext", "Quot.sound", "Classical.choice"} | ({"sorryAx"} if broken else set())
    result = {name: [a.strip() for a in used.split(",") if a.strip()] for name, used in found}
    require(all(set(used) <= allowed and len(used) == len(set(used)) for used in result.values()),
            "register proof depends on unreviewed axioms")
    if not broken:
        require("error:" not in log and "sorryAx" not in log, "positive proof has errors or placeholders")
    return result


def _vm_observations(source, candidate):
    function = source.as_dict()["functions"][0]["name"]
    cases = []
    # Reuse the frozen 272 boundary/seeded pairs, not samples selected after proof.
    for arguments in selected.native_case_arguments():
        before = execute_program(source, function, arguments)
        after = execute_program(candidate, function, arguments)
        require(before["values"] == after["values"] and before["resources"] == after["resources"],
                "actual VM values or resource ledgers differ")
        require(before["steps"] == after["steps"] + 1, "deleted literal must remove one actual VM tick")
        cases.append({"arguments": arguments, "source_value": before["result"],
                      "candidate_value": after["result"], "source_steps": before["steps"],
                      "candidate_steps": after["steps"]})
    return cases


def qualify(lean, output_directory, *, core_path=SELECTED):
    executable = Path(lean).resolve(strict=True)
    binary = digest(executable.read_bytes())
    require(binary == json.loads((ROOT / "formal/toolchain-lock.json").read_bytes())["lean_binary_sha256"],
            "Lean must match the pinned binary SHA-256 before execution")
    raw = Path(core_path).read_bytes()
    source, candidate, generated, mapping = export_pair(raw)
    sources, support = _source_identity(), selected._support_identity(executable)
    output = Path(output_directory).absolute()
    output.mkdir(parents=True, exist_ok=False)
    (output / "input.hia.json").write_bytes(raw)
    (output / "source.hia.json").write_bytes(source.canonical_bytes)
    (output / "candidate.hia.json").write_bytes(candidate.canonical_bytes)
    (output / "positive.lean").write_text(generated, encoding="utf-8")
    _json(output / "instruction-map.json", mapping)
    _json(output / "lean-support-files.json", support)
    report = {"schema": SCHEMA, "ok": False, "status": "running",
              "source_core_sha256": source.sha256, "candidate_core_sha256": candidate.sha256,
              "input_sha256": digest(raw), "generated_lean_sha256": digest(generated.encode()),
              "source_identity": sources, "lean_binary_sha256": binary,
              "support_manifest_sha256": digest((output / "lean-support-files.json").read_bytes()),
              "claims": dict(CLAIMS), "limitations": list(LIMITATIONS),
              "selected_input_domain_size": str(2**64), "negative_controls": []}
    try:
        positive = selected._run_lean(executable, output / "positive.lean")
        report["positive"] = positive
        log = positive["stdout"] + positive["stderr"]
        require(positive["returncode"] == 0, "Lean rejected register safety:\n" + log)
        report["theorems"] = dependencies(log)
        for name, (mut_source, mut_candidate, broken, _) in mutation_inputs(raw).items():
            (output / (name + ".lean")).write_text(broken, encoding="utf-8")
            (output / (name + ".candidate.hia.json")).write_bytes(mut_candidate.canonical_bytes)
            observed = selected._run_lean(executable, output / (name + ".lean"))
            badlog = observed["stdout"] + observed["stderr"]
            require(observed["returncode"] == 1 and "error:" in badlog,
                    "intended broken control was not rejected by Lean: " + name)
            used = dependencies(badlog, broken=True)
            require("sorryAx" in used[MUTATIONS[name]], "mutation missed intended theorem: " + name)
            report["negative_controls"].append({"name": name, "status": "rejected_as_expected",
                "source_core_sha256": mut_source.sha256, "candidate_core_sha256": mut_candidate.sha256,
                "generated_lean_sha256": digest(broken.encode()), "theorems": used, **observed})
        report["vm_cases"] = _vm_observations(source, candidate)
        require(_source_identity() == sources and selected._support_identity(executable) == support
                and digest(executable.read_bytes()) == binary, "proof inputs changed during qualification")
        report.update(ok=True, status="passed")
        validate_report(report, output)
    except Exception as error:
        report.update(ok=False, status="failed", error=f"{type(error).__name__}: {error}")
        report["claims"] = {key: False for key in CLAIMS}
        _json(output / "qualification.json", report)
        raise
    _json(output / "qualification.json", report)
    return report


@normalized_errors
def validate_report(report, directory):
    directory = Path(directory)
    require(type(report) is dict and report.get("schema") == SCHEMA
            and report.get("ok") is True and report.get("status") == "passed", "register proof did not pass")
    raw = (directory / "input.hia.json").read_bytes()
    source, candidate, generated, mapping = export_pair(raw)
    require(report.get("source_core_sha256") == source.sha256
            and report.get("candidate_core_sha256") == candidate.sha256
            and report.get("input_sha256") == digest(raw)
            and (directory / "source.hia.json").read_bytes() == source.canonical_bytes
            and (directory / "candidate.hia.json").read_bytes() == candidate.canonical_bytes
            and (directory / "positive.lean").read_text() == generated
            and report.get("generated_lean_sha256") == digest(generated.encode())
            and strict_equal(json.loads((directory / "instruction-map.json").read_bytes()), mapping),
            "actual Core, mapping or generated theorem binding differs")
    require(strict_equal(report.get("claims"), CLAIMS) and report.get("limitations") == LIMITATIONS
            and report.get("source_identity") == _source_identity()
            and report.get("selected_input_domain_size") == str(2**64)
            and report.get("lean_binary_sha256") == json.loads((ROOT / "formal/toolchain-lock.json").read_bytes())["lean_binary_sha256"]
            and report.get("support_manifest_sha256") == digest((directory / "lean-support-files.json").read_bytes()),
            "scope or source/checker identity changed")
    positive = report.get("positive", {})
    log = positive.get("stdout", "") + positive.get("stderr", "")
    require(type(positive.get("returncode")) is int and positive["returncode"] == 0
            and positive.get("output_sha256") == digest(log.encode())
            and strict_equal(dependencies(log), report.get("theorems")), "positive kernel evidence differs")
    negative = report.get("negative_controls")
    require(type(negative) is list and len(negative) == len(MUTATIONS)
            and {row.get("name") for row in negative} == set(MUTATIONS), "negative denominator differs")
    expected = mutation_inputs(raw)
    for row in negative:
        name = row["name"]
        mut_source, mut_candidate, broken, _ = expected[name]
        badlog = row.get("stdout", "") + row.get("stderr", "")
        require(row.get("status") == "rejected_as_expected" and type(row.get("returncode")) is int
                and row["returncode"] == 1 and "error:" in badlog
                and row.get("source_core_sha256") == mut_source.sha256
                and row.get("candidate_core_sha256") == mut_candidate.sha256
                and (directory / (name + ".candidate.hia.json")).read_bytes() == mut_candidate.canonical_bytes
                and (directory / (name + ".lean")).read_text() == broken
                and row.get("generated_lean_sha256") == digest(broken.encode())
                and row.get("output_sha256") == digest(badlog.encode())
                and strict_equal(dependencies(badlog, broken=True), row.get("theorems"))
                and "sorryAx" in row["theorems"][MUTATIONS[name]], "negative kernel evidence differs")
    require(strict_equal(report.get("vm_cases"), _vm_observations(source, candidate)),
            "retained actual VM observations differ from fresh replay")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
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
