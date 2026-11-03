#!/usr/bin/env python3
"""Kernel-check a structural lifecycle model and finite production observations.

The observer does not replace production checker bindings. Independently
observed before/after states must satisfy a Lean transition. Neither the
Python exporter nor whole-language memory safety is proved by this tool.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import verify_hia_capabilities as edges
from tools.qualify_hia_selected_formal import _run_lean, _support_identity

MAX_INSTRUCTIONS = 512
MAX_CAPABILITIES = 512
SUPPORTED = frozenset({"buffer.new", "buffer.try_new", "chain.empty", "borrow.read",
                       "borrow.mut", "loan.end", "owner.drop"})
NAMES = {"HiaCapabilityLifecycle." + name for name in (
    "fresh_not_member", "fresh_parent_absent", "extend_rank_old", "fresh_cons_unique",
    "owner_closed", "loan_closed", "owner_ranked", "loan_ranked", "erased_member",
    "erase_closed", "erase_ranked", "erase_unique", "step_closed", "step_ranked",
    "step_unique", "unique_projection", "unique_rename", "transfer_unique",
    "trace_closed", "trace_ranked", "trace_unique", "trace_no_parent_cycle")}
INSTANCE_THEOREMS = ("_result", "_step", "_closed_before", "_ranked_before",
                     "_unique_before", "_closed_after", "_ranked_after",
                     "_unique_after", "_no_parent_cycle")
MODEL_MUTATIONS = {
    "loan_root_rebound": ("⟨name, source.root, some source.name", "⟨name, name, some source.name", "loan_closed"),
    "loan_parent_self": ("⟨name, source.root, some source.name", "⟨name, source.root, some name", "loan_ranked"),
    "freshness_removed": ("∀ c ∈ caps, c.name ≠ name\n", "True\n", "fresh_not_member"),
    "release_references_ignored": (
        "∀ c ∈ caps, c.name ≠ name → c.root ≠ name ∧ c.parent ≠ some name", "True", "erase_closed"),
}
CALLER = "hepta.hia_program._verify_function"


@contextmanager
def production_instruction_trace():
    """Observe this thread's actual _verify_function -> instruction calls."""
    from hepta import hia_program as core
    previous = sys.getprofile()
    if previous is not None and not callable(previous):
        raise ValueError("cannot safely preserve an opaque existing profiler")
    target, verifier = core._BlockCheck.instruction.__code__, core._verify_function.__code__
    rows, active = [], {}

    def snapshot(owner):
        if type(owner.caps) is not dict or len(owner.caps) > MAX_CAPABILITIES:
            raise ValueError("observed instruction capability graph exceeds budget")
        return {name: asdict(cap) for name, cap in owner.caps.items()}

    def observe(frame, event, arg):
        if previous is not None:
            previous(frame, event, arg)
        if frame.f_code is not target:
            return
        if event == "call":
            if len(rows) + len(active) >= MAX_INSTRUCTIONS:
                raise ValueError("observed instruction budget exceeded")
            owner, instruction = frame.f_locals["self"], frame.f_locals["ins"]
            if frame.f_back.f_code is not verifier or type(owner) is not core._BlockCheck:
                raise ValueError("instruction trace is outside the actual function verifier")
            occurrences = [i for i, item in enumerate(owner.block["ops"]) if item is instruction]
            if len(occurrences) != 1:
                raise ValueError("instruction does not identify one actual block occurrence")
            active[id(frame)] = {"caller": CALLER, "function": owner.fn["name"],
                "block": owner.block["id"], "operation_index": occurrences[0],
                "instruction": deepcopy(instruction), "before": snapshot(owner)}
        elif event == "return":
            row = active.pop(id(frame))
            row["after"] = snapshot(frame.f_locals["self"])
            rows.append(row)

    try:
        sys.setprofile(observe)
        yield rows
    finally:
        sys.setprofile(previous)


def expected_instruction_inventory(document):
    """Inventory source occurrences independently of the checker's visit loop."""
    inventory = {}
    for fn in document["functions"]:
        for block in fn["blocks"]:
            for index, instruction in enumerate(block["ops"]):
                identity = (fn["name"], block["id"], index)
                if identity in inventory or len(inventory) >= MAX_INSTRUCTIONS:
                    raise ValueError("duplicate or over-budget static instruction inventory")
                inventory[identity] = instruction
    if not inventory:
        raise ValueError("nonempty instruction inventory required")
    return inventory


def validate_instruction_coverage(document, rows):
    expected, observed = expected_instruction_inventory(document), {}
    for row in rows:
        identity = (row.get("function"), row.get("block"), row.get("operation_index"))
        if row.get("caller") != CALLER or identity not in expected or identity in observed:
            raise ValueError("duplicate, foreign or unexpected actual instruction caller")
        if row.get("instruction") != expected[identity]:
            raise ValueError("observed instruction differs from its static occurrence")
        observed[identity] = row
    if set(observed) != set(expected):
        raise ValueError("actual instruction coverage is incomplete")
    return [{"function": fn, "block": block, "operation_index": index,
             "instruction": expected[(fn, block, index)],
             "modelled": expected[(fn, block, index)]["op"] in SUPPORTED}
            for fn, block, index in sorted(expected)]


def capture_core_instructions(document):
    from hepta.hia_program import verify_program
    canonical = verify_program(document)
    expected_instruction_inventory(canonical.as_dict())
    with production_instruction_trace() as rows:
        checked = verify_program(canonical.canonical_bytes)
    if checked.canonical_bytes != canonical.canonical_bytes:
        raise ValueError("production verification changed its canonical input")
    validate_instruction_coverage(checked.as_dict(), rows)
    return checked, rows


def model_source():
    base = (ROOT / "formal/HiaCapabilityRenaming.lean").read_text()
    lifecycle = (ROOT / "formal/HiaCapabilityLifecycle.lean").read_text()
    for source, namespace, names, imports in (
            (base, "HiaCapabilityRenaming", edges.NAMES, ["Lean.Elab.Tactic.Omega"]),
            (lifecycle, "HiaCapabilityLifecycle", NAMES, ["HiaCapabilityRenaming"])):
        if re.findall(r"(?m)^import ([^\n]+)$", source) != imports:
            raise ValueError("unreviewed Lean model import")
        if re.search(r"(?m)^\s*(axiom|unsafe|opaque|constant|initialize|builtin_initialize|"
                     r"run_elab|run_cmd|elab|macro|syntax|set_option|#)\b|\bsorry\b", source):
            raise ValueError("unreviewed Lean declaration or placeholder")
        if {namespace + "." + n for n in re.findall(r"(?m)^theorem (\w+)", source)} != names:
            raise ValueError("model theorem inventory changed")
    return base + "\n" + lifecycle.replace("import HiaCapabilityRenaming\n", "", 1)


def _instruction_encoding(row):
    """Keep actual fields even when mutated; never rebuild the after graph."""
    before, after, instruction = row["before"], row["after"], row["instruction"]
    if instruction["op"] not in SUPPORTED:
        raise ValueError("instruction is outside the structural lifecycle model")
    fields = {"typ", "root", "parent", "external", "origin"}
    for graph in (before, after):
        if type(graph) is not dict or len(graph) > MAX_CAPABILITIES:
            raise ValueError("invalid bounded capability inventory")
        for name, cap in graph.items():
            if (type(name) is not str or not 0 < len(name) <= 256 or type(cap) is not dict or set(cap) != fields
                    or type(cap["typ"]) is not str or cap["typ"] not in edges.KINDS
                    or type(cap["root"]) is not str or type(cap["external"]) is not bool
                    or any(cap[key] is not None and type(cap[key]) is not str for key in ("parent", "origin"))):
                raise ValueError("invalid observed capability fields")
    if any(cap["root"] not in before or cap["parent"] is not None and cap["parent"] not in before
           for cap in before.values()):
        raise ValueError("observed input graph omits a root or parent")
    ranks = {}
    for name in before:
        seen, current = set(), name
        while current is not None:
            if current in seen:
                raise ValueError("observed input graph contains a parent cycle")
            seen.add(current)
            current = before[current]["parent"]
        ranks[name] = len(seen) - 1
    op = instruction["op"]
    creates = op not in {"loan.end", "owner.drop"}
    output = instruction["out"][0]["name"] if creates else None
    source = instruction["args"][0] if op in {"borrow.read", "borrow.mut", "loan.end", "owner.drop"} else None
    if source is not None and source not in before:
        raise ValueError("observed operation source is absent")
    identifiers = set(before) | set(after)
    if output is not None:
        identifiers.add(output)
    for graph in (before, after):
        for cap in graph.values():
            identifiers.add(cap["root"])
            if cap["parent"] is not None:
                identifiers.add(cap["parent"])
    names = {name: index for index, name in enumerate(sorted(identifiers))}
    origins = {name: index for index, name in enumerate(sorted({cap["origin"]
        for graph in (before, after) for cap in graph.values() if cap["origin"] is not None}))}

    def encode(name, cap):
        option = lambda value: "none" if value is None else "(some " + str(value) + ")"
        return "⟨" + ", ".join((str(names[name]), str(names[cap["root"]]),
            option(None if cap["parent"] is None else names[cap["parent"]]),
            str(edges.KINDS[cap["typ"]]), str(cap["external"]).lower(),
            option(None if cap["origin"] is None else origins[cap["origin"]]))) + "⟩"

    # Only order is normalized for a cons. Unexpected/lost entries and actual
    # fields remain, so the kernel can reject an incorrect observed result.
    after_order = ([output] if creates and output in after else []) + sorted(set(after) - ({output} if creates else set()))
    return {"names": names, "origins": origins, "kind_tags": dict(edges.KINDS),
            "before": [encode(name, before[name]) for name in sorted(before)],
            "after": [encode(name, after[name]) for name in after_order],
            "source": None if source is None else encode(source, before[source]),
            "output": None if output is None else names[output],
            "parent_ranks": {names[name]: ranks[name] for name in sorted(before)}}


def export_observed_instructions(rows):
    if not 1 <= len(rows) <= MAX_INSTRUCTIONS or any(row["instruction"]["op"] not in SUPPORTED for row in rows):
        raise ValueError("nonempty bounded supported instruction inventory required")
    text = model_source() + "\nnamespace HiaCapabilityLifecycle\nopen HiaCapabilityRenaming\n"
    names, mappings = set(NAMES | edges.NAMES), []
    for index, row in enumerate(rows):
        mapping = _instruction_encoding(row)
        mappings.append(mapping)
        prefix, op = "instruction" + str(index), row["instruction"]["op"]
        text += f"def {prefix}Before : List Capability := [" + ", ".join(mapping["before"]) + "]\n"
        text += f"def {prefix}After : List Capability := [" + ", ".join(mapping["after"]) + "]\n"
        text += f"def {prefix}Rank (n : Nat) : Nat :=\n  match n with\n"
        text += "".join(f"  | {name} => {rank}\n" for name, rank in mapping["parent_ranks"].items()) + "  | _ => 0\n"
        if mapping["source"] is not None:
            text += f"def {prefix}Source : Capability := {mapping['source']}\n"
        if op in {"buffer.new", "buffer.try_new", "chain.empty"}:
            kind = 1 if op == "chain.empty" else 0
            expected = f"owner {mapping['output']} {kind} :: {prefix}Before"
            witness = f"Step.allocate (by simp [Fresh, {prefix}Before]) (by decide)"
        elif op in {"borrow.read", "borrow.mut"}:
            expected = f"loan {prefix}Source {mapping['output']} {2 if op == 'borrow.read' else 3} :: {prefix}Before"
            constructor = "borrowRead" if op == "borrow.read" else "borrowMut"
            witness = (f"Step.{constructor} (by simp [{prefix}Source, {prefix}Before]) "
                       f"(by simp [Fresh, {prefix}Before]) (by decide)")
        else:
            expected = f"erase {prefix}Source.name {prefix}Before"
            witness = f"Step.{'endLoan' if op == 'loan.end' else 'dropOwner'} (c := {prefix}Source) "
            witness += f"(by simp [{prefix}Source, {prefix}Before]) (by decide) (by decide) "
            if op == "owner.drop":
                witness += "(by decide) (by decide) "
            witness += f"(by simp [Unreferenced, {prefix}Before, {prefix}Source])"
        text += (f"theorem {prefix}_result : {prefix}After = {expected} := by decide\n"
                 f"theorem {prefix}_step : Step {prefix}Before {prefix}After := by\n"
                 f"  rw [{prefix}_result]\n  exact {witness}\n"
                 f"theorem {prefix}_closed_before : Closed {prefix}Before := by\n"
                 f"  simp [Closed, {prefix}Before]\n"
                 f"theorem {prefix}_ranked_before : Ranked {prefix}Before := by\n"
                 f"  refine ⟨{prefix}Rank, ?_⟩\n  simp [ParentRanks, ChildOf, {prefix}Before, {prefix}Rank]\n"
                 f"theorem {prefix}_unique_before : Unique {prefix}Before := by\n"
                 f"  simp [Unique, {prefix}Before]\n"
                 f"theorem {prefix}_closed_after : Closed {prefix}After :=\n"
                 f"  step_closed {prefix}_step {prefix}_closed_before\n"
                 f"theorem {prefix}_ranked_after : Ranked {prefix}After :=\n"
                 f"  step_ranked {prefix}_step {prefix}_closed_before {prefix}_ranked_before\n"
                 f"theorem {prefix}_unique_after : Unique {prefix}After :=\n"
                 f"  step_unique {prefix}_step {prefix}_unique_before\n"
                 f"theorem {prefix}_no_parent_cycle (name : Nat) : ¬ ParentPath {prefix}After name name :=\n"
                 f"  ranked_no_parent_cycle {prefix}After {prefix}_ranked_after name\n")
        names.update("HiaCapabilityLifecycle." + prefix + suffix for suffix in INSTANCE_THEOREMS)
    text += "end HiaCapabilityLifecycle\n"
    text += "".join("#print axioms " + name + "\n" for name in sorted(names))
    if len(text.encode()) > 1_048_576:
        raise ValueError("generated instruction witness exceeds byte budget")
    return text, names, mappings


def observed_mutations(rows, *, require_all=True):
    mutations = {}
    predicates = {
        "root_rebound": lambda name, cap: cap["root"] != name,
        "parent_discarded": lambda _name, cap: cap["parent"] is not None,
        "kind_changed": lambda _name, _cap: True,
        "external_flipped": lambda _name, _cap: True,
        "origin_discarded": lambda _name, cap: cap["origin"] is not None,
    }
    for mutation, predicate in predicates.items():
        selected = next(((i, name) for i, row in enumerate(rows)
                         for name, cap in row["after"].items() if predicate(name, cap)), None)
        if selected is None:
            if require_all:
                raise ValueError("cohort does not cover output mutation: " + mutation)
            continue
        index, name = selected
        changed = deepcopy(rows)
        cap = changed[index]["after"][name]
        if mutation == "root_rebound": cap["root"] = name
        elif mutation == "parent_discarded": cap["parent"] = None
        elif mutation == "kind_changed": cap["typ"] = "readbuf" if cap["typ"] != "readbuf" else "buffer"
        elif mutation == "external_flipped": cap["external"] = not cap["external"]
        else: cap["origin"] = None
        mutations[mutation] = (changed, f"HiaCapabilityLifecycle.instruction{index}_result")
    for mutation, opcode in (("ended_loan_retained", "loan.end"), ("dropped_owner_retained", "owner.drop")):
        selected = next((i for i, row in enumerate(rows) if row["instruction"]["op"] == opcode), None)
        if selected is None:
            if require_all:
                raise ValueError("cohort does not cover release mutation: " + mutation)
            continue
        changed = deepcopy(rows)
        name = changed[selected]["instruction"]["args"][0]
        changed[selected]["after"][name] = deepcopy(changed[selected]["before"][name])
        mutations[mutation] = (changed, f"HiaCapabilityLifecycle.instruction{selected}_result")
    return mutations


def _source_identity():
    paths = list((ROOT / "hepta").glob("*.py")) + [ROOT / path for path in (
        "formal/HiaCapabilityRenaming.lean", "formal/HiaCapabilityLifecycle.lean", "formal/toolchain-lock.json",
        "formal/proof-dependencies.txt", "tools/verify_hia_capabilities.py", "tools/verify_hia_capability_lifecycle.py",
        "tools/qualify_hia_selected_formal.py", "tools/evidence_checks.py",
        "examples/hia_program/capability_lifecycle.hia")]
    paths += [ROOT / path for _, path, _, _, _ in edges.PRODUCTION_INPUTS]
    return {str(path.relative_to(ROOT)): edges.digest(path.read_bytes()) for path in sorted(set(paths))}


def _write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def verify(lean, output, *, program=None):
    """Retain kernel inputs/outputs and controls, never a safety certificate."""
    from hepta.hia_program_source import lower_source
    from hepta.hia_program import verify_program
    executable = Path(lean).resolve(strict=True)
    lock = json.loads((ROOT / "formal/toolchain-lock.json").read_bytes())
    executable_hash = edges.digest(executable.read_bytes())
    if executable_hash != lock["lean_binary_sha256"]:
        raise ValueError("Lean executable differs from pinned identity")
    support_before, source_before = _support_identity(executable), _source_identity()
    version = subprocess.run([str(executable), "--version"], capture_output=True, text=True, timeout=20)
    if version.returncode or "version 4.19.0," not in version.stdout:
        raise ValueError("pinned Lean could not execute")
    destination = Path(output)
    if destination.exists():
        raise ValueError("proof output already exists")
    destination.mkdir(parents=True)
    corpus, rows, inputs = [], [], []
    if program is None:
        for label, path, mode, _, _ in edges.PRODUCTION_INPUTS:
            raw = (ROOT / path).read_bytes()
            checked = lower_source(raw.decode(), core_schema="hepta.hia.program.v8") if mode == "source-v8" else verify_program(raw)
            inputs.append((label, raw, checked))
        raw = (ROOT / "examples/hia_program/capability_lifecycle.hia").read_bytes()
        inputs.append(("explicit_lifecycle", raw, verify_program(raw)))
    else:
        raw, checked = edges.read_primitive_program(program)
        inputs.append(("selected_primitive", raw, checked))
    for label, raw, initial in inputs:
        checked, all_rows = capture_core_instructions(initial.canonical_bytes)
        inventory = validate_instruction_coverage(checked.as_dict(), all_rows)
        selected = [row for row in all_rows if row["instruction"]["op"] in SUPPORTED]
        rows.extend(selected)
        (destination / (label + ".input")).write_bytes(raw)
        (destination / (label + ".core.json")).write_bytes(checked.canonical_bytes)
        _write_json(destination / (label + ".observed.json"), all_rows)
        corpus.append({"label": label, "input_sha256": edges.digest(raw), "core_sha256": checked.sha256,
                       "complete_instruction_inventory": inventory, "observed_instructions": len(all_rows),
                       "modelled_instructions": len(selected),
                       "unmodelled_opcodes": sorted({row["instruction"]["op"] for row in all_rows
                                                     if row["instruction"]["op"] not in SUPPORTED})})
    generated, names, mappings = export_observed_instructions(rows)
    positive_path = destination / "ObservedLifecycle.lean"
    positive_path.write_text(generated)
    positive = _run_lean(executable, positive_path.resolve())
    _write_json(destination / "positive-kernel.json", positive)
    positive_log = positive["stdout"] + positive["stderr"]
    if positive["returncode"] or "error:" in positive_log or "sorryAx" in positive_log:
        raise ValueError("Lean rejected the lifecycle witness: " + positive_log)
    dependencies = edges._observed_dependencies(positive_log, names)
    mutants = []

    def check_negative(label, text, expected_names, expected_theorem, category):
        path = destination / (label + ".lean")
        path.write_text(text)
        result = _run_lean(executable, path.resolve())
        _write_json(destination / (label + ".kernel.json"), result)
        log = result["stdout"] + result["stderr"]
        if result["returncode"] == 0 or "error:" not in log:
            raise ValueError("semantic mutation unexpectedly passed: " + label)
        bad = edges._observed_dependencies(log, expected_names, broken=True)
        if "sorryAx" not in bad[expected_theorem]:
            raise ValueError("mutation failed outside the intended theorem: " + label)
        mutants.append({"name": label, "category": category, "expected_invalid_theorem": expected_theorem,
                        "source_sha256": edges.digest(text.encode()), "kernel_output_sha256": result["output_sha256"]})

    for label, (changed, expected) in observed_mutations(rows, require_all=program is None).items():
        text, bad_names, _ = export_observed_instructions(changed)
        check_negative(label, text, bad_names, expected, "actual_output_mutation")
    model = model_source()
    model_names = NAMES | edges.NAMES
    for label, (old, new, expected) in MODEL_MUTATIONS.items():
        if model.count(old) != 1:
            raise ValueError("model mutation site is not unique: " + label)
        text = model.replace(old, new, 1) + "\n" + "".join("#print axioms " + name + "\n" for name in sorted(model_names))
        check_negative(label, text, model_names, "HiaCapabilityLifecycle." + expected, "generic_premise_mutation")
    if (source_before != _source_identity() or support_before != _support_identity(executable)
            or executable_hash != edges.digest(executable.read_bytes())):
        raise ValueError("source or proof toolchain changed during qualification")
    report = {"schema": "hepta.hia.capability-lifecycle-proof.v1", "passed": True,
        "source_identity": source_before, "lean_binary_sha256": executable_hash,
        "lean_support_identity": support_before, "lean_version": version.stdout.strip(),
        "corpus": corpus, "modelled_opcodes": sorted({row["instruction"]["op"] for row in rows}),
        "modelled_instruction_count": len(rows), "mapping": mappings,
        "checked_input_sha256": edges.digest(generated.encode()), "theorems": dependencies,
        "negative_controls": mutants,
        "scope": {"all_finite_model_states": True, "execution_length_bound": None,
            "properties": ["root and parent closure", "unique capability names", "strict parent descent",
                           "absence of positive parent cycles", "exact selected instruction resource transition"],
            "instruction_model": sorted(SUPPORTED), "finite_actual_instruction_witnesses": True,
            "all_static_instructions_inventoried": True,
            "generic_composition_with_admitted_cfg_edges": True,
            "whole_cfg_execution_trace_exported": False,
            "python_checker_or_exporter_refinement_proved": False,
            "conflicting_alias_exclusion_proved": False, "heap_execution_proved": False,
            "calls_moves_chain_transfers_proved": False, "complete_core_type_soundness_proved": False,
            "llvm_native_ffi_concurrency_proved": False}, "safety_certificate": False}
    _write_json(destination / "REPORT.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--program", help="explicit bounded primitive Core v1-v8; otherwise use the fixed cohort")
    args = parser.parse_args()
    report = verify(args.lean, args.output, program=args.program)
    print(json.dumps({"passed": report["passed"], "instructions": report["modelled_instruction_count"],
                      "theorems": len(report["theorems"]), "negative_controls": len(report["negative_controls"]),
                      "safety_certificate": False}, sort_keys=True))


if __name__ == "__main__":
    main()
