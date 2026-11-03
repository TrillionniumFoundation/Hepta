#!/usr/bin/env python3
"""Check guarded borrow/access preservation and finite actual checker witnesses.

This is a capability-graph proof, not a heap or whole-language certificate.
The production observer leaves checker bindings intact. Independently captured
instruction states and actual borrow/access calls must agree before export.
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
from tools import verify_hia_capability_lifecycle as lifecycle
from tools import verify_hia_capabilities as edges
from tools.qualify_hia_selected_formal import _run_lean, _support_identity

SUPPORTED = lifecycle.SUPPORTED | {"buffer.load", "buffer.store"}
GUARDED = {"borrow.read": ("borrow", False), "borrow.mut": ("borrow", True),
           "buffer.load": ("access", False), "buffer.store": ("access", True)}
MAX_PATH_STEPS = 8192
MAX_SOURCE_BYTES = 1_048_576
NAMES = {"HiaCapabilityBorrow." + name for name in (
    "unique_same_name", "path_mono", "path_endpoints", "path_retained", "path_rename",
    "comparable_mono", "comparable_symm", "compatible_owner", "loan_ancestor_path",
    "compatible_loan", "compatible_subgraph", "compatible_erase", "compatible_projection",
    "compatible_rename", "transfer_compatible", "child_blocks_access", "path_last_child",
    "ancestor_blocks_access", "accessible_exclusive", "borrow_suspends_source",
    "end_restores_access", "step_structural", "step_closed", "step_ranked", "step_unique",
    "step_compatible", "trace_closed", "trace_ranked", "trace_unique", "trace_compatible",
    "trace_no_parent_cycle", "trace_accessible_exclusive")}
MODEL_MUTATIONS = {
    "borrow_conflict_guard_removed": (
        "∀ other ∈ caps, other.root = source.root →\n"
        "    (kind = 3 ∨ other.kind = 3) → Ancestor caps source.name other.name",
        "True", "compatible_loan"),
    "access_child_guard_removed": ("Childless caps c.name\n", "True\n", "child_blocks_access"),
}
INSTANCE_THEOREMS = lifecycle.INSTANCE_THEOREMS + ("_compatible_before", "_compatible_after")
FIXTURE = "examples/hia_program/capability_borrow_access.hia"


def _identity(row):
    return row.get("function"), row.get("block"), row.get("operation_index")


@contextmanager
def production_guard_trace():
    """Observe real borrow/access and access->children calls in this thread."""
    from hepta import hia_program as core
    previous = sys.getprofile()
    if previous is not None and not callable(previous):
        raise ValueError("cannot safely preserve an opaque existing profiler")
    target = {core._BlockCheck.borrow.__code__: "borrow", core._BlockCheck.access.__code__: "access"}
    instruction, verifier, children = (core._BlockCheck.instruction.__code__,
        core._verify_function.__code__, core._BlockCheck.children.__code__)
    rows, active = [], {}

    def snapshot(owner):
        if type(owner.caps) is not dict or len(owner.caps) > lifecycle.MAX_CAPABILITIES:
            raise ValueError("guard capability graph exceeds budget")
        return {name: asdict(cap) for name, cap in owner.caps.items()}

    def observe(frame, event, arg):
        if previous is not None:
            previous(frame, event, arg)
        if frame.f_code is children and event == "return" and id(frame.f_back) in active:
            row = active[id(frame.f_back)]
            if row["guard"] == "access":
                if "children" in row:
                    raise ValueError("duplicate actual access child query")
                row["children"] = deepcopy(arg)
            return
        if frame.f_code not in target:
            return
        if event == "call":
            caller = frame.f_back
            if (caller is None or caller.f_code is not instruction or caller.f_back is None
                    or caller.f_back.f_code is not verifier
                    or type(frame.f_locals["self"]) is not core._BlockCheck):
                raise ValueError("guard trace is outside the actual instruction verifier")
            ins, owner = caller.f_locals["ins"], frame.f_locals["self"]
            if ins["op"] not in SUPPORTED:
                return
            occurrences = [i for i, item in enumerate(owner.block["ops"]) if item is ins]
            if len(occurrences) != 1 or len(rows) + len(active) >= lifecycle.MAX_INSTRUCTIONS:
                raise ValueError("guard occurrence is ambiguous or exceeds budget")
            kind = target[frame.f_code]
            active[id(frame)] = {"caller": "hepta.hia_program._BlockCheck.instruction",
                "function": owner.fn["name"], "block": owner.block["id"],
                "operation_index": occurrences[0], "instruction": deepcopy(ins), "guard": kind,
                "source": frame.f_locals["source" if kind == "borrow" else "name"],
                "mutable": frame.f_locals["mutable"], "before": snapshot(owner)}
            if kind == "borrow":
                active[id(frame)].update(output=frame.f_locals["output"],
                                         chain_head=frame.f_locals["chain_head"])
        elif event == "return" and id(frame) in active:
            row = active.pop(id(frame))
            row["after"] = snapshot(frame.f_locals["self"])
            if row["guard"] == "borrow":
                ancestors, others = frame.f_locals.get("allowed_ancestors"), frame.f_locals.get("others")
                # An exceptional call may return before these locals exist.
                # Preserve the rejection; successful evidence requires both.
                row["allowed_ancestors"] = sorted(ancestors) if type(ancestors) is set else None
                row["others"] = [asdict(cap) for cap in others] if type(others) is list else None
            rows.append(row)

    try:
        sys.setprofile(observe)
        yield rows
    finally:
        sys.setprofile(previous)


def validate_guard_coverage(document, instructions, guards):
    inventory = lifecycle.validate_instruction_coverage(document, instructions)
    expected = {_identity(row): row for row in instructions if row["instruction"]["op"] in GUARDED}
    observed = {}
    for row in guards:
        identity = _identity(row)
        if identity not in expected or identity in observed:
            raise ValueError("duplicate, foreign or unexpected guard occurrence")
        actual = expected[identity]
        ins, before = actual["instruction"], actual["before"]
        guard, mutable = GUARDED[ins["op"]]
        source = ins["args"][0]
        if (row.get("caller") != "hepta.hia_program._BlockCheck.instruction"
                or row.get("instruction") != ins or row.get("guard") != guard
                or row.get("source") != source or type(row.get("mutable")) is not bool
                or row["mutable"] != mutable or row.get("before") != before
                or row.get("after") != actual["after"]):
            raise ValueError("actual guard differs from its actual instruction states or arguments")
        if guard == "borrow":
            allowed, current = {source}, source
            while before[current]["parent"] is not None:
                current = before[current]["parent"]
                if current in allowed or current not in before:
                    raise ValueError("invalid guard ancestor graph")
                allowed.add(current)
            others = [cap for name, cap in before.items()
                      if cap["root"] == before[source]["root"] and name not in allowed]
            if (row.get("output") != ins["out"][0]["name"] or row.get("chain_head") is not False
                    or row.get("allowed_ancestors") != sorted(allowed) or row.get("others") != others):
                raise ValueError("actual borrow guard did not inspect its complete before-state ancestor exclusion")
            if mutable and others or not mutable and any(cap["typ"] == "mutbuf" for cap in others):
                raise ValueError("actual borrow guard admitted a conflicting capability")
        else:
            children = [name for name, cap in before.items() if cap["parent"] == source]
            if row.get("children") != children or children:
                raise ValueError("actual access guard omitted or admitted a child loan")
        observed[identity] = row
    if set(expected) != set(observed):
        raise ValueError("actual borrow/access guard coverage is incomplete")
    for row in inventory:
        row["modelled"] = row["instruction"]["op"] in SUPPORTED
    return inventory


def capture_core_instructions(document):
    from hepta.hia_program import verify_program
    canonical = verify_program(document)
    lifecycle.expected_instruction_inventory(canonical.as_dict())
    with lifecycle.production_instruction_trace() as instructions:
        with production_guard_trace() as guards:
            checked = verify_program(canonical.canonical_bytes)
    if checked.canonical_bytes != canonical.canonical_bytes:
        raise ValueError("production verification changed its canonical input")
    validate_guard_coverage(checked.as_dict(), instructions, guards)
    return checked, instructions, guards


def model_source():
    source = (ROOT / "formal/HiaCapabilityBorrow.lean").read_text()
    if re.findall(r"(?m)^import ([^\n]+)$", source) != ["HiaCapabilityLifecycle"]:
        raise ValueError("unreviewed borrow model import")
    if re.search(r"(?m)^\s*(axiom|unsafe|opaque|constant|initialize|builtin_initialize|"
                 r"run_elab|run_cmd|elab|macro|syntax|set_option|#)\b|\bsorry\b", source):
        raise ValueError("unreviewed borrow declaration or placeholder")
    if {"HiaCapabilityBorrow." + name for name in re.findall(r"(?m)^theorem (\w+)", source)} != NAMES:
        raise ValueError("borrow model theorem inventory changed")
    return lifecycle.model_source() + "\n" + source.replace("import HiaCapabilityLifecycle\n", "", 1)


def _encoding(row):
    if row["instruction"]["op"] in lifecycle.SUPPORTED:
        return lifecycle._instruction_encoding(row)
    if row["instruction"]["op"] not in {"buffer.load", "buffer.store"}:
        raise ValueError("instruction is outside the borrow/access model")
    # The existing encoder's release mode encodes a source and two unchanged
    # ordered graphs. Only that data encoding is reused; the emitted theorem
    # below is Access/identity, never a fictional release instruction.
    encoding_input = dict(row)
    encoding_input["instruction"] = {"op": "loan.end", "args": row["instruction"]["args"][:1]}
    return lifecycle._instruction_encoding(encoding_input)


def _parent_paths(graph, budget):
    paths, steps = [], 0
    for child in sorted(graph):
        chain, current = [child], child
        while graph[current]["parent"] is not None:
            current = graph[current]["parent"]
            if current in chain or current not in graph:
                raise ValueError("invalid before-state parent path")
            chain.append(current)
            steps += len(chain) - 1
            if steps > budget:
                raise ValueError("finite parent-path proof budget exceeded")
            paths.append(tuple(chain))
    return sorted(paths, key=lambda path: (len(path), path))


def export_observed_instructions(rows, *, start_index=0):
    if not 1 <= len(rows) <= lifecycle.MAX_INSTRUCTIONS or any(row["instruction"]["op"] not in SUPPORTED for row in rows):
        raise ValueError("nonempty bounded supported instruction inventory required")
    if type(start_index) is not int or not 0 <= start_index < lifecycle.MAX_INSTRUCTIONS or start_index + len(rows) > lifecycle.MAX_INSTRUCTIONS:
        raise ValueError("instruction numbering exceeds budget")
    mappings, paths, steps = [], [], 0
    for row in rows:
        mappings.append(_encoding(row))
        found = _parent_paths(row["before"], MAX_PATH_STEPS - steps)
        steps += sum(len(path) - 1 for path in found)
        paths.append(found)
    text = model_source() + "\nnamespace HiaCapabilityBorrow\nopen HiaCapabilityRenaming HiaCapabilityLifecycle\n"
    names = set(NAMES | lifecycle.NAMES | edges.NAMES)
    for index, (row, mapping, found) in enumerate(zip(rows, mappings, paths), start=start_index):
        prefix, op = "instruction" + str(index), row["instruction"]["op"]
        text += f"def {prefix}Before : List Capability := [" + ", ".join(mapping["before"]) + "]\n"
        text += f"def {prefix}After : List Capability := [" + ", ".join(mapping["after"]) + "]\n"
        text += f"def {prefix}Rank (n : Nat) : Nat :=\n  match n with\n"
        text += "".join(f"  | {name} => {rank}\n" for name, rank in mapping["parent_ranks"].items()) + "  | _ => 0\n"
        if mapping["source"] is not None:
            text += f"def {prefix}Source : Capability := {mapping['source']}\n"
        literals = dict(zip(sorted(row["before"]), mapping["before"]))
        proved_paths = {}
        for path_index, path in enumerate(found):
            label = prefix + "_path" + str(path_index)
            start, end = path[0], path[-1]
            text += f"theorem {label} : ParentPath {prefix}Before {mapping['names'][start]} {mapping['names'][end]} :=\n"
            if len(path) == 2:
                text += (f"  ParentPath.edge (child := {literals[start]}) (parent := {literals[end]}) "
                         f"(by simp [{prefix}Before]) (by simp [{prefix}Before]) rfl\n")
            else:
                text += f"  ParentPath.trans {proved_paths[(path[0], path[1])]} {proved_paths[(path[1], path[-1])]}\n"
            proved_paths[(start, end)] = label
            names.add("HiaCapabilityBorrow." + label)
        path_facts = "".join(", path" + str(i) for i in range(len(proved_paths)))
        path_bindings = "".join(f"  have path{i} := {name}\n  simp only [{prefix}Before] at path{i}\n"
                                for i, name in enumerate(proved_paths.values()))
        if op in {"buffer.new", "buffer.try_new", "chain.empty"}:
            kind = 1 if op == "chain.empty" else 0
            expected = f"owner {mapping['output']} {kind} :: {prefix}Before"
            witness = f"Step.allocate (by simp [Fresh, {prefix}Before]) (by decide)"
        elif op in {"borrow.read", "borrow.mut"}:
            kind = 2 if op == "borrow.read" else 3
            expected = f"loan {prefix}Source {mapping['output']} {kind} :: {prefix}Before"
            text += (f"theorem {prefix}_borrow_guard : BorrowGuard {prefix}Before {prefix}Source {kind} := by\n"
                     + path_bindings +
                     f"  simp [BorrowGuard, Ancestor, {prefix}Before, {prefix}Source{path_facts}]\n")
            witness = (f"Step.{'borrowRead' if kind == 2 else 'borrowMut'} "
                       f"(by simp [{prefix}Source, {prefix}Before]) (by simp [Fresh, {prefix}Before]) "
                       f"(by decide) {prefix}_borrow_guard")
            names.add("HiaCapabilityBorrow." + prefix + "_borrow_guard")
        elif op in {"buffer.load", "buffer.store"}:
            expected = prefix + "Before"
            write = str(op == "buffer.store").lower()
            text += (f"theorem {prefix}_access : Access {prefix}Before {prefix}Source {write} := by\n"
                     f"  simp [Access, Childless, {prefix}Before, {prefix}Source]\n")
            witness = f"Step.access {prefix}_access"
            names.add("HiaCapabilityBorrow." + prefix + "_access")
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
                 f"theorem {prefix}_compatible_before : Compatible {prefix}Before := by\n"
                 + path_bindings +
                 f"  simp [Compatible, Comparable, {prefix}Before{path_facts}]\n"
                 f"theorem {prefix}_closed_after : Closed {prefix}After :=\n"
                 f"  step_closed {prefix}_step {prefix}_closed_before\n"
                 f"theorem {prefix}_ranked_after : Ranked {prefix}After :=\n"
                 f"  step_ranked {prefix}_step {prefix}_closed_before {prefix}_ranked_before\n"
                 f"theorem {prefix}_unique_after : Unique {prefix}After :=\n"
                 f"  step_unique {prefix}_step {prefix}_unique_before\n"
                 f"theorem {prefix}_compatible_after : Compatible {prefix}After :=\n"
                 f"  step_compatible {prefix}_step {prefix}_closed_before {prefix}_unique_before {prefix}_compatible_before\n"
                 f"theorem {prefix}_no_parent_cycle (name : Nat) : ¬ ParentPath {prefix}After name name :=\n"
                 f"  ranked_no_parent_cycle {prefix}After {prefix}_ranked_after name\n")
        if op in {"borrow.read", "borrow.mut"}:
            text += (f"theorem {prefix}_source_suspended (write : Bool) : ¬ Access {prefix}After {prefix}Source write := by\n"
                     f"  rw [{prefix}_result]\n  exact borrow_suspends_source _ _ _ _ write\n")
            names.add("HiaCapabilityBorrow." + prefix + "_source_suspended")
        names.update("HiaCapabilityBorrow." + prefix + suffix for suffix in INSTANCE_THEOREMS)
        if len(text.encode()) > MAX_SOURCE_BYTES:
            raise ValueError("generated borrow witness exceeds byte budget")
    text += "end HiaCapabilityBorrow\n"
    text += "".join("#print axioms " + name + "\n" for name in sorted(names))
    if len(text.encode()) > MAX_SOURCE_BYTES:
        raise ValueError("generated borrow witness exceeds byte budget")
    return text, names, mappings


def counterexample_rows(rows, *, require_all=True):
    """Explicitly invalid admissions derived from observed states, not observations."""
    controls = {}
    nested = next((row for row in rows if row["instruction"]["op"] == "borrow.mut"
                   and row["before"][row["instruction"]["args"][0]]["typ"] == "mutbuf"), None)
    if nested is not None:
        source = nested["instruction"]["args"][0]
        before = deepcopy(nested["after"])
        parent = before[source]
        duplicate = deepcopy(nested)
        duplicate["before"], duplicate["after"] = before, deepcopy(before)
        name = "counterexample_mutable_sibling"
        if name in before:
            raise ValueError("counterexample name is not fresh")
        duplicate["instruction"] = {"op": "borrow.mut", "args": [source],
                                     "out": [{"name": name, "type": "mutbuf"}], "attrs": {}}
        duplicate["after"][name] = {"typ": "mutbuf", "root": parent["root"], "parent": source,
                                     "external": False, "origin": parent["origin"]}
        controls["second_mutable_sibling"] = (duplicate, "instruction0_borrow_guard")
        early = deepcopy(nested)
        early["before"], early["after"] = deepcopy(before), deepcopy(before)
        early["instruction"] = {"op": "buffer.store", "args": [source, "index", "byte"], "out": [], "attrs": {}}
        controls["parent_access_before_child_end"] = (early, "instruction0_access")
    shared_end = next((row for row in rows if row["instruction"]["op"] == "loan.end"
        and (parent := row["before"][row["instruction"]["args"][0]]["parent"]) is not None
        and row["before"][parent]["typ"] == "mutbuf"
        and any(cap["parent"] == parent for cap in row["after"].values())), None)
    if shared_end is not None:
        parent = shared_end["before"][shared_end["instruction"]["args"][0]]["parent"]
        early = deepcopy(shared_end)
        early["before"], early["after"] = deepcopy(shared_end["after"]), deepcopy(shared_end["after"])
        early["instruction"] = {"op": "buffer.store", "args": [parent, "index", "byte"], "out": [], "attrs": {}}
        controls["parent_access_with_shared_sibling_remaining"] = (early, "instruction0_access")
    if require_all and set(controls) != {"second_mutable_sibling", "parent_access_before_child_end",
                                         "parent_access_with_shared_sibling_remaining"}:
        raise ValueError("cohort omits required invalid-admission controls")
    return controls


def rejected_program_controls():
    """Each control must be rejected by the unchanged production checker."""
    from hepta.hia_program import verify_program, HIAProgramRejected
    baseline = json.loads((ROOT / FIXTURE).read_bytes())
    cases = {}
    for label, position, operation in (
            ("second_mutable_sibling", 3, {"op": "borrow.mut", "args": ["parent"],
                "out": [{"name": "second", "type": "mutbuf"}], "attrs": {}}),
            ("parent_access_before_child_end", 3, {"op": "buffer.store", "args": ["parent", "index", "byte"],
                "out": [], "attrs": {}}),
            ("shared_to_mutable_escalation", 6, {"op": "borrow.mut", "args": ["shared"],
                "out": [{"name": "escalated", "type": "mutbuf"}], "attrs": {}})):
        document = deepcopy(baseline)
        document["functions"][1]["blocks"][0]["ops"].insert(position, operation)
        if label == "second_mutable_sibling":
            document["functions"][1]["blocks"][0]["ops"].insert(position + 1,
                {"op": "loan.end", "args": ["second"], "out": [], "attrs": {}})
        if label == "shared_to_mutable_escalation":
            document["functions"][1]["blocks"][0]["ops"].insert(position + 1,
                {"op": "loan.end", "args": ["escalated"], "out": [], "attrs": {}})
        cases[label] = document
    document = deepcopy(baseline)
    ops = document["functions"][0]["blocks"][0]["ops"]
    position = next(i for i, op in enumerate(ops) if op["op"] == "loan.end" and op["args"] == ["left"])
    ops.insert(position + 1, {"op": "buffer.store", "args": ["parent", "index", "byte"], "out": [], "attrs": {}})
    cases["parent_access_with_shared_sibling_remaining"] = document
    results = []
    for label, document in cases.items():
        try:
            verify_program(document)
        except HIAProgramRejected as error:
            if error.code != "E_HIA_LOAN":
                raise ValueError("control rejected outside intended loan rule: " + label) from error
            results.append({"name": label, "code": error.code, "message": str(error),
                "input_sha256": edges.digest(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()),
                "input": document})
        else:
            raise ValueError("production admitted invalid borrow/access: " + label)
    return results


def _source_identity():
    identities = lifecycle._source_identity()
    for name in ("formal/HiaCapabilityBorrow.lean", "tools/verify_hia_capability_borrow.py", FIXTURE,
                 "tests/test_hia_capability_borrow.py"):
        identities[name] = edges.digest((ROOT / name).read_bytes())
    return dict(sorted(identities.items()))


def verify(lean, output, *, program=None):
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
        for label, path in (("explicit_lifecycle", "examples/hia_program/capability_lifecycle.hia"),
                            ("borrow_access", FIXTURE)):
            raw = (ROOT / path).read_bytes()
            inputs.append((label, raw, verify_program(raw)))
    else:
        raw, checked = edges.read_primitive_program(program)
        inputs.append(("selected_primitive", raw, checked))
    for label, raw, initial in inputs:
        checked, all_rows, guards = capture_core_instructions(initial.canonical_bytes)
        inventory = validate_guard_coverage(checked.as_dict(), all_rows, guards)
        selected = [row for row in all_rows if row["instruction"]["op"] in SUPPORTED]
        rows.extend(selected)
        (destination / (label + ".input")).write_bytes(raw)
        (destination / (label + ".core.json")).write_bytes(checked.canonical_bytes)
        lifecycle._write_json(destination / (label + ".observed.json"), all_rows)
        lifecycle._write_json(destination / (label + ".guards.json"), guards)
        corpus.append({"label": label, "input_sha256": edges.digest(raw), "core_sha256": checked.sha256,
            "complete_instruction_inventory": inventory, "observed_instructions": len(all_rows),
            "modelled_instructions": len(selected), "actual_guard_calls": len(guards),
            "borrow_calls": sum(row["guard"] == "borrow" for row in guards),
            "access_calls": sum(row["guard"] == "access" for row in guards),
            "unmodelled_opcodes": sorted({row["instruction"]["op"] for row in all_rows if row["instruction"]["op"] not in SUPPORTED})})
    generated, names, mappings = export_observed_instructions(rows)
    positive_path = destination / "ObservedBorrow.lean"
    positive_path.write_text(generated)
    positive = _run_lean(executable, positive_path.resolve())
    lifecycle._write_json(destination / "positive-kernel.json", positive)
    positive_log = positive["stdout"] + positive["stderr"]
    if positive["returncode"] or "error:" in positive_log or "sorryAx" in positive_log:
        raise ValueError("Lean rejected the guarded borrow witness: " + positive_log)
    dependencies = edges._observed_dependencies(positive_log, names)
    mutants = []

    def check_negative(label, text, expected_names, expected_theorem, category):
        path = destination / (label + ".lean")
        path.write_text(text)
        result = _run_lean(executable, path.resolve())
        lifecycle._write_json(destination / (label + ".kernel.json"), result)
        log = result["stdout"] + result["stderr"]
        if result["returncode"] == 0 or "error:" not in log:
            raise ValueError("semantic mutation unexpectedly passed: " + label)
        bad = edges._observed_dependencies(log, expected_names, broken=True)
        if "sorryAx" not in bad[expected_theorem]:
            raise ValueError("mutation failed outside the intended theorem: " + label)
        mutants.append({"name": label, "category": category, "expected_invalid_theorem": expected_theorem,
            "source_sha256": edges.digest(text.encode()), "kernel_output_sha256": result["output_sha256"]})

    # Keep all prior lifecycle corruption categories. Each independent control
    # kernel-checks its affected observed occurrence; the positive proves all.
    for label, (changed, expected) in lifecycle.observed_mutations(rows, require_all=program is None).items():
        index = int(re.fullmatch(r"HiaCapabilityLifecycle.instruction(\d+)_result", expected).group(1))
        text, bad_names, _ = export_observed_instructions([changed[index]], start_index=index)
        check_negative(label, text, bad_names, expected.replace("HiaCapabilityLifecycle.", "HiaCapabilityBorrow."),
                       "actual_output_mutation")
    model, model_names = model_source(), NAMES | lifecycle.NAMES | edges.NAMES
    for namespace, mutations in (("HiaCapabilityLifecycle", lifecycle.MODEL_MUTATIONS),
                                  ("HiaCapabilityBorrow", MODEL_MUTATIONS)):
        for label, (old, new, expected) in mutations.items():
            if model.count(old) != 1:
                raise ValueError("model mutation site is not unique: " + label)
            text = model.replace(old, new, 1) + "\n" + "".join("#print axioms " + name + "\n" for name in sorted(model_names))
            check_negative(label, text, model_names, namespace + "." + expected, "generic_premise_mutation")
    for label, (countermodel, expected) in counterexample_rows(rows, require_all=program is None).items():
        text, bad_names, _ = export_observed_instructions([countermodel])
        check_negative(label, text, bad_names, "HiaCapabilityBorrow." + expected, "invalid_admission_countermodel")
    rejections = rejected_program_controls()
    lifecycle._write_json(destination / "production-rejections.json", rejections)
    if (source_before != _source_identity() or support_before != _support_identity(executable)
            or executable_hash != edges.digest(executable.read_bytes())):
        raise ValueError("source or proof toolchain changed during qualification")
    report = {"schema": "hepta.hia.capability-borrow-proof.v1", "passed": True,
        "source_identity": source_before, "lean_binary_sha256": executable_hash,
        "lean_support_identity": support_before, "lean_version": version.stdout.strip(),
        "corpus": corpus, "modelled_opcodes": sorted({row["instruction"]["op"] for row in rows}),
        "modelled_instruction_count": len(rows), "mapping": mappings,
        "checked_input_sha256": edges.digest(generated.encode()), "theorems": dependencies,
        "negative_controls": mutants, "production_rejections": [{k: v for k, v in item.items() if k != "input"} for item in rejections],
        "scope": {"all_finite_model_states": True, "execution_length_bound": None,
            "instruction_model": sorted(SUPPORTED),
            "properties": ["root and parent closure", "unique capability names", "strict parent descent",
                "absence of positive parent cycles", "ancestor-compatible mutable borrows", "child and ancestor access suspension",
                "mutual exclusion of simultaneously accessible mutable aliases", "last-child end restores parent access"],
            "requires_initial_closed_unique_compatible": True, "acyclicity_requires_initial_ranked": True,
            "generic_composition_with_admitted_cfg_edges": True, "finite_actual_instruction_witnesses": True,
            "finite_actual_borrow_access_guard_witnesses": any(item["actual_guard_calls"] for item in corpus),
            "all_static_instructions_inventoried": True,
            "whole_cfg_execution_trace_exported": False, "source_semantics_refinement_proved": False,
            "python_checker_or_exporter_refinement_proved": False, "heap_execution_proved": False,
            "calls_moves_chain_transfers_proved": False, "complete_core_type_soundness_proved": False,
            "llvm_native_ffi_concurrency_proved": False}, "safety_certificate": False}
    lifecycle._write_json(destination / "REPORT.json", report)
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
        "production_rejections": len(report["production_rejections"]), "safety_certificate": False}, sort_keys=True))


if __name__ == "__main__":
    main()
