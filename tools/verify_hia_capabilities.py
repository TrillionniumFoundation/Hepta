#!/usr/bin/env python3
"""Check the unbounded CFG renaming model with the pinned Lean kernel.

This does not prove the Python implementation's correspondence. Its separate
executable controls call the production boundary. Keep these claims distinct.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
NAMES = {"HiaCapabilityRenaming." + name for name in (
    "name_preserved", "kind_preserved", "external_preserved", "origin_preserved",
    "name_equal_iff", "root_equal_iff", "parent_map_iff", "child_of_iff",
    "exclusive_alias_iff", "suspended_iff", "closed_preserved", "number_preserved",
    "rename_composes", "identity_rename", "projected_member", "local_retained",
    "only_external_forgotten", "local_inventory_projection", "local_inventory_rename",
    "parent_path_descends", "ranked_no_parent_cycle", "ranked_projection",
    "transported_rank_at", "ranked_rename", "transfer_closed", "transfer_local_inventory",
    "transfer_ranked", "trace_local_inventory", "trace_closed", "trace_ranked",
    "trace_no_parent_cycle")}
MUTATIONS = {
    "root_rebound_to_name": ("root := f c.root", "root := f c.name", "root_equal_iff"),
    "parent_discarded": ("parent := c.parent.map f", "parent := none", "child_of_iff"),
    "kind_changed": ("kind := c.kind", "kind := 0", "kind_preserved"),
    "origin_discarded": ("origin := c.origin", "origin := none", "origin_preserved"),
    "local_retention_removed": (
        "(∀ c ∈ caps, c.external = false → keep c.name = true) ∧ Closed",
        "True ∧ Closed", "local_retained"),
    "parent_rank_not_strict": (
        "ChildOf child parent → rank parent.name < rank child.name",
        "ChildOf child parent → rank parent.name ≤ rank child.name", "parent_path_descends"),
}


def digest(data):
    return sha256(data).hexdigest()


def theorem_dependencies(log, *, broken=False):
    rows = re.findall(r"^'([^']+)' depends on axioms: \[([^\]]*)\]$", log, re.M)
    rows += [(name, "") for name in re.findall(r"^'([^']+)' does not depend on any axioms$", log, re.M)]
    if len(rows) != len(NAMES) or {row[0] for row in rows} != NAMES:
        raise ValueError("missing or duplicate theorem dependency output")
    allowed = {"propext", "Quot.sound", "Classical.choice"} | ({"sorryAx"} if broken else set())
    result = {name: [x.strip() for x in values.split(',') if x.strip()] for name, values in rows}
    if any(set(values) - allowed for values in result.values()):
        raise ValueError("unexpected proof axiom")
    return result


def verify(lean, output):
    output = Path(output)
    if output.exists():
        raise ValueError("proof output already exists")
    executable = Path(lean).resolve(strict=True)
    lock = json.loads((ROOT/'formal/toolchain-lock.json').read_text())
    executable_hash = digest(executable.read_bytes())
    if executable_hash != lock['lean_binary_sha256']:
        raise ValueError("Lean executable differs from pinned identity")
    source_path = ROOT/'formal/HiaCapabilityRenaming.lean'
    source = source_path.read_text()
    if re.search(r'(?m)^\s*(axiom|unsafe|opaque)\s|\bsorry\b', source):
        raise ValueError("untrusted declaration or placeholder in proof")
    declared = {'HiaCapabilityRenaming.'+x for x in re.findall(r'^theorem (\w+)', source, re.M)}
    if declared != NAMES:
        raise ValueError("theorem inventory changed")
    bound = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in (
        source_path, ROOT/'formal/toolchain-lock.json', ROOT/'hepta/hia_capability_flow.py',
        ROOT/'hepta/hia_program.py', ROOT/'tests/test_hia_capability_flow.py', Path(__file__))}
    version = subprocess.run([str(executable), '--version'], capture_output=True, text=True, timeout=20)
    if version.returncode or 'version 4.19.0,' not in version.stdout:
        raise ValueError("pinned Lean could not execute")
    checks = '\n' + '\n'.join('#print axioms '+name for name in sorted(NAMES)) + '\n'
    with tempfile.TemporaryDirectory(prefix='hia-capability-proofs-') as tmp:
        proof = Path(tmp)/'Check.lean'
        proof.write_text(source+checks)
        good = subprocess.run([str(executable), str(proof)], capture_output=True, text=True, timeout=60)
        log = good.stdout+good.stderr
        if good.returncode or 'error:' in log or 'sorryAx' in log:
            raise ValueError('Lean rejected the positive proof:\n'+log)
        dependencies = theorem_dependencies(log)
        negative = []
        for name, (old, new, expected) in MUTATIONS.items():
            if source.count(old) != 1:
                raise ValueError('mutation site is not unique: '+name)
            changed = source.replace(old, new, 1)
            proof.write_text(changed+checks)
            bad = subprocess.run([str(executable), str(proof)], capture_output=True, text=True, timeout=60)
            bad_log = bad.stdout+bad.stderr
            if bad.returncode == 0 or 'error:' not in bad_log:
                raise ValueError('semantic mutation unexpectedly passed: '+name)
            bad_dependencies = theorem_dependencies(bad_log, broken=True)
            if 'sorryAx' not in bad_dependencies['HiaCapabilityRenaming.'+expected]:
                raise ValueError('mutation did not invalidate intended theorem: '+name)
            negative.append({'name': name, 'returncode': bad.returncode,
                             'expected_invalid_theorem': 'HiaCapabilityRenaming.'+expected,
                             'source_sha256': digest(changed.encode()), 'kernel_output': bad_log,
                             'kernel_output_sha256': digest(bad_log.encode())})
    if any(digest((ROOT/p).read_bytes()) != value for p, value in bound.items()):
        raise ValueError('source changed during proof qualification')
    if digest(executable.read_bytes()) != executable_hash:
        raise ValueError('proof checker changed during qualification')
    result = {
        'schema': 'hepta.hia.capability-renaming.proof.v2', 'passed': True,
        'source_sha256': bound, 'lean_version': version.stdout.strip(),
        'lean_binary_sha256': executable_hash, 'theorems': dependencies,
        'checked_input_sha256': digest((source+checks).encode()),
        'kernel_output': log, 'kernel_output_sha256': digest(log.encode()),
        'negative_mutations': negative,
        'scope': {'all_finite_capability_lists_and_injective_name_maps': True,
                  'execution_length_bound': None, 'names': 'unbounded mathematical naturals',
                  'properties': ['root identity relation', 'parent relation and suspension',
                                 'exclusive alias relation', 'graph closure', 'selected capability count',
                                 'type/external/origin fields', 'composition and identity',
                                 'only external capabilities can be forgotten',
                                 'complete local kind/origin inventory',
                                 'strict parent descent and absence of positive parent cycles',
                                 'arbitrary finite traces of admitted projection/renaming edges'],
                  'selected_domain': 'closed retained projection of a finite capability graph and finite edge-only traces',
                  'external_forgetting_and_projection_proved': True,
                  'local_inventory_preserved_on_all_admitted_finite_edge_traces': True,
                  'parent_acyclicity_preserved_given_initial_ranks': True,
                  'intervening_cfg_instructions_proved': False,
                  'python_correspondence_formally_proved': False,
                  'instruction_preservation_proved': False,
                  'complete_core_type_soundness_proved': False,
                  'complete_lowering_refinement_proved': False,
                  'concurrent_or_external_memory_proved': False},
        'safety_certificate': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True); stream.write('\n')
    return result


MAX_OBSERVED_EDGES = 512
MAX_EDGE_CAPABILITIES = 512
KINDS = {"buffer": 0, "chain": 1, "readbuf": 2, "mutbuf": 3}
EDGE_THEOREMS = (
    "_injective", "_closed", "_result", "_closed_after", "_selected_projection",
    "_projection", "_ranked_before", "_transfer", "_local_inventory", "_ranked_after",
    "_no_parent_cycle",
)
PRODUCTION_INPUTS = (
    ("stored_record", "examples/hia_program/stored_loan_record.hia", "core", "stored",
     ((False,), (True,))),
    ("returned_views", "examples/hia_returned_loans/returned_views.hepta", "source-v8", "probe",
     ((1, 42, False), (1, 42, True), (0, 42, True))),
)


@contextmanager
def production_edge_trace(*, require_cfg_caller=False):
    """Observe genuine calls on this thread without replacing checker bindings.

    An existing Python profile callback is chained and restored. Opaque C
    profilers cannot safely be chained this way and refuse before installation.
    Other threads are not observed or reconfigured by this bounded qualifier.
    """
    from hepta.hia_capability_flow import rename_capabilities
    from hepta import hia_program as core
    previous = sys.getprofile()
    if previous is not None and not callable(previous):
        raise ValueError("cannot safely preserve an opaque existing profiler")
    target = rename_capabilities.__code__
    transfer_code, verifier_code = core._BlockCheck.transfer.__code__, core._verify_function.__code__
    if require_cfg_caller and core.rename_capabilities is not rename_capabilities:
        raise ValueError("production capability helper binding is unavailable")
    rows, active = [], {}

    def observe(frame, event, arg):
        if previous is not None:
            previous(frame, event, arg)
        if frame.f_code is not target:
            return
        if event == "call":
            if len(rows) + len(active) >= MAX_OBSERVED_EDGES:
                raise ValueError("observed CFG edge budget exceeded")
            caps, remap = frame.f_locals["capabilities"], frame.f_locals["remap"]
            if len(caps) > MAX_EDGE_CAPABILITIES:
                raise ValueError("observed capability graph exceeds budget")
            caller = frame.f_back
            owner = caller.f_locals.get("self")
            context = {}
            if require_cfg_caller:
                if (caller.f_code is not transfer_code or caller.f_back.f_code is not verifier_code
                        or type(owner) is not core._BlockCheck):
                    raise ValueError("capability trace is outside the actual CFG verifier caller")
                edge, destination = caller.f_locals["edge"], caller.f_locals["target"]
                term = owner.block["term"]
                if term["op"] == "branch" and edge is term["then"]:
                    slot = "then"
                elif term["op"] == "branch" and edge is term["else"]:
                    slot = "else"
                elif term["op"] == "jump" and edge == {"target": term["target"], "args": term["args"]}:
                    slot = "jump"
                else:
                    raise ValueError("observed edge does not belong to its actual CFG terminator")
                if destination["id"] != edge["target"]:
                    raise ValueError("observed target block differs from the CFG edge")
                context = {"caller": "hepta.hia_program._BlockCheck.transfer", "edge_slot": slot,
                           "target_params": deepcopy(destination["params"])}
            active[id(frame)] = {
                "function": getattr(owner, "fn", {}).get("name"),
                "block": getattr(owner, "block", {}).get("id"),
                "edge": deepcopy(caller.f_locals.get("edge")),
                "capabilities": {name: asdict(cap) for name, cap in caps.items()},
                "remap": dict(remap),
                **context,
            }
        elif event == "return":
            row = active.pop(id(frame))
            row["result"] = None if arg is None else {name: asdict(cap) for name, cap in arg.items()}
            rows.append(row)

    try:
        sys.setprofile(observe)
        yield rows
    finally:
        sys.setprofile(previous)


def capture_core_edges(document):
    """Reverify canonical bytes while observing the real production boundary."""
    from hepta.hia_program import verify_program
    canonical = verify_program(document)
    expected_edge_inventory(canonical.as_dict())
    with production_edge_trace(require_cfg_caller=True) as rows:
        observed = verify_program(canonical.canonical_bytes)
    if observed.canonical_bytes != canonical.canonical_bytes or any(row["result"] is None for row in rows):
        raise ValueError("production verification did not complete on the same canonical Core")
    validate_edge_coverage(observed.as_dict(), rows)
    return observed, rows


def expected_edge_inventory(document):
    """Read static edge occurrences independently of the production _edges helper."""
    inventory = {}
    resources = {"buffer", "chain", "readbuf", "mutbuf"}
    for function in document["functions"]:
        blocks = {block["id"]: block for block in function["blocks"]}
        for block in function["blocks"]:
            term = block["term"]
            if term["op"] == "jump":
                edges = [("jump", {"target": term["target"], "args": term["args"]})]
            elif term["op"] == "branch":
                edges = [("then", term["then"]), ("else", term["else"])]
            elif term["op"] in {"ret", "trap"}:
                edges = []
            else:
                raise ValueError("unsupported terminator in independent edge inventory")
            for slot, edge in edges:
                identity = (function["name"], block["id"], slot)
                params = blocks[edge["target"]]["params"]
                if identity in inventory or len(inventory) >= MAX_OBSERVED_EDGES:
                    raise ValueError("duplicate or over-budget static edge occurrence")
                inventory[identity] = {"edge": edge, "target_params": params,
                    "remap": {arg: param["name"] for arg, param in zip(edge["args"], params)
                              if param["type"] in resources}}
    if not inventory:
        raise ValueError("capability witness requires a nonempty static CFG edge inventory")
    return inventory


def validate_edge_coverage(document, rows):
    expected, observed = expected_edge_inventory(document), {}
    for row in rows:
        identity = (row.get("function"), row.get("block"), row.get("edge_slot"))
        if (row.get("caller") != "hepta.hia_program._BlockCheck.transfer"
                or identity not in expected or identity in observed):
            raise ValueError("duplicate, foreign or unexpected actual CFG edge caller")
        if any(row.get(key) != expected[identity][key] for key in ("edge", "target_params", "remap")):
            raise ValueError("observed CFG edge/target/remap differs from the static Core occurrence")
        observed[identity] = row
    if set(observed) != set(expected):
        raise ValueError("actual CFG edge coverage is incomplete")
    if not any(row["remap"] for row in rows):
        raise ValueError("capability witness requires a nonempty selected capability graph")
    return [{"function": fn, "block": block, "edge_slot": slot, **expected[(fn, block, slot)]}
            for fn, block, slot in sorted(expected)]


def read_primitive_program(path):
    """Bound a regular input snapshot before parsing or whole-file allocation."""
    from hepta.hia_program import MAX_BYTES, verify_program
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_BYTES:
            raise ValueError("program must be a nonempty regular file within the Core byte budget")
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if len(raw) != before.st_size or identity(before) != identity(after):
        raise ValueError("program changed while taking its bounded snapshot")
    core = verify_program(raw)
    if core.structured_bytes is not None or core.as_dict()["schema"] not in {
            "hepta.hia.program.v" + str(version) for version in range(1, 9)}:
        raise ValueError("generic witness requires explicit primitive Core v1-v8; no source/nominal adapter")
    return raw, core


def parse_arguments(text):
    from hepta.hia_bounded_wire import checked_utf8_wire
    from hepta import hia_rust_crosscheck as transport
    raw = checked_utf8_wire(text, transport.MAX_ARGUMENT_BYTES)
    arguments = json.loads(raw)
    if (type(arguments) is not list or len(arguments) > transport.MAX_ARGUMENTS
            or any(type(value) not in (int, bool, type(None)) or type(value) is int
                   and not -(1 << 63) <= value < 1 << 64 for value in arguments)):
        raise ValueError("arguments require the existing bounded Rust scalar wire profile")
    return arguments


def _edge_encoding(row):
    """Encode one selected graph; this exporter is explicitly not proved sound."""
    caps, remap, result = row["capabilities"], row["remap"], row["result"]
    if (type(caps) is not dict or type(remap) is not dict or type(result) is not dict
            or len(caps) > MAX_EDGE_CAPABILITIES or len(remap) > MAX_EDGE_CAPABILITIES
            or any(type(k) is not str or type(v) is not str for k, v in remap.items())
            or not set(remap) <= set(caps) or len(set(remap.values())) != len(remap)
            or set(result) != set(remap.values())):
        raise ValueError("invalid selected capability/name-map inventory")
    fields = {"typ", "root", "parent", "external", "origin"}
    for graph in (caps, result):
        for name, cap in graph.items():
            if (type(name) is not str or type(cap) is not dict or set(cap) != fields
                    or type(cap["typ"]) is not str or cap["typ"] not in KINDS
                    or type(cap["root"]) is not str or type(cap["external"]) is not bool
                    or any(cap[key] is not None and type(cap[key]) is not str for key in ("parent", "origin"))):
                raise ValueError("invalid concrete capability fields")
    if any(not cap["external"] and name not in remap for name, cap in caps.items()):
        raise ValueError("selection omits a local capability")
    for name in remap:
        cap = caps[name]
        if cap["root"] not in remap or cap["parent"] is not None and cap["parent"] not in remap:
            raise ValueError("selected graph omits its root or parent")
    for name in caps:
        if caps[name]["root"] not in caps or caps[name]["parent"] is not None and caps[name]["parent"] not in caps:
            raise ValueError("full production witness graph omits a root or parent")
    parent_ranks = {}
    for name in caps:
        seen, current = set(), name
        while current is not None:
            if current in seen:
                raise ValueError("parent cycle is outside the selected production witness profile")
            seen.add(current)
            current = caps[current]["parent"]
        parent_ranks[name] = len(seen) - 1
    names = sorted(remap)
    source_names = {name: index for index, name in enumerate(sorted(caps))}
    target_names = {remap[name]: source_names[name] + len(caps) for name in names}
    origins = {name: index for index, name in enumerate(sorted({
        cap["origin"] for graph in (caps, result) for cap in graph.values() if cap["origin"] is not None}))}

    def encode(name, cap, namespace):
        if cap["root"] not in namespace or cap["parent"] is not None and cap["parent"] not in namespace:
            raise ValueError("observed graph references an absent target capability")
        option = lambda value: "none" if value is None else "(some " + str(value) + ")"
        return "⟨" + ", ".join((str(namespace[name]), str(namespace[cap["root"]]),
            option(None if cap["parent"] is None else namespace[cap["parent"]]),
            str(KINDS[cap["typ"]]), str(cap["external"]).lower(),
            option(None if cap["origin"] is None else origins[cap["origin"]]))) + "⟩"
    return {
        "source_names": source_names, "target_names": target_names, "origins": origins,
        "kind_tags": dict(KINDS), "dropped_external": sorted(set(caps) - set(remap)),
        "namespace_scope": "separate before/after SSA namespaces; target codes follow the supplied injective remap, independently of observed capability fields",
        "full_before": [encode(name, caps[name], source_names) for name in sorted(caps)],
        "selected_names": [source_names[name] for name in names],
        "parent_ranks": {source_names[name]: parent_ranks[name] for name in sorted(caps)},
        "before": [encode(name, caps[name], source_names) for name in names],
        "after": [encode(remap[name], result[remap[name]], target_names) for name in names],
    }


def export_observed_edges(rows):
    if not 1 <= len(rows) <= MAX_OBSERVED_EDGES:
        raise ValueError("nonempty bounded production edge inventory required")
    text = (ROOT / "formal/HiaCapabilityRenaming.lean").read_text() + "\nnamespace HiaCapabilityRenaming\n"
    names, mappings = set(NAMES), []
    for index, row in enumerate(rows):
        mapping = _edge_encoding(row)
        mappings.append(mapping)
        prefix = "edge" + str(index)
        text += f"def {prefix}Map (n : Nat) : Nat := n + {len(mapping['full_before'])}\n"
        text += f"def {prefix}FullBefore : List Capability := [" + ", ".join(mapping["full_before"]) + "]\n"
        text += f"def {prefix}Keep (n : Nat) : Bool := decide (n ∈ [" + ", ".join(map(str, mapping["selected_names"])) + "])\n"
        text += f"def {prefix}Rank (n : Nat) : Nat :=\n  match n with\n"
        text += "".join(f"  | {name} => {rank}\n" for name, rank in mapping["parent_ranks"].items())
        text += "  | _ => 0\n"
        text += f"def {prefix}Before : List Capability := [" + ", ".join(mapping["before"]) + "]\n"
        text += f"def {prefix}After : List Capability := [" + ", ".join(mapping["after"]) + "]\n"
        text += f"theorem {prefix}_injective : Injective {prefix}Map := by\n  intro a b h\n  exact Nat.add_right_cancel h\n"
        text += f"theorem {prefix}_closed : Closed {prefix}Before := by\n  simp [Closed, {prefix}Before]\n"
        text += f"theorem {prefix}_result : {prefix}After = {prefix}Before.map (rename {prefix}Map) := by decide\n"
        text += (f"theorem {prefix}_closed_after : Closed {prefix}After := by\n"
                 f"  rw [{prefix}_result]\n  exact closed_preserved {prefix}Map {prefix}Before {prefix}_closed\n")
        text += (f"theorem {prefix}_selected_projection : {prefix}Before = project {prefix}Keep {prefix}FullBefore := by decide\n"
                 f"theorem {prefix}_projection : AdmissibleProjection {prefix}FullBefore {prefix}Keep := by\n"
                 f"  simp [AdmissibleProjection, project, {prefix}Keep, {prefix}FullBefore, Closed]\n"
                 f"theorem {prefix}_ranked_before : Ranked {prefix}FullBefore := by\n"
                 f"  refine ⟨{prefix}Rank, ?_⟩\n"
                 f"  simp [ParentRanks, ChildOf, {prefix}FullBefore, {prefix}Rank]\n"
                 f"theorem {prefix}_transfer : Transfer {prefix}FullBefore {prefix}After := by\n"
                 f"  refine ⟨{prefix}Keep, {prefix}Map, {prefix}_projection, {prefix}_injective, ?_⟩\n"
                 f"  rw [{prefix}_result, {prefix}_selected_projection]\n"
                 f"theorem {prefix}_local_inventory : localInventory {prefix}After = localInventory {prefix}FullBefore :=\n"
                 f"  transfer_local_inventory {prefix}_transfer\n"
                 f"theorem {prefix}_ranked_after : Ranked {prefix}After :=\n"
                 f"  transfer_ranked {prefix}_transfer {prefix}_ranked_before\n"
                 f"theorem {prefix}_no_parent_cycle (name : Nat) : ¬ ParentPath {prefix}After name name :=\n"
                 f"  ranked_no_parent_cycle {prefix}After {prefix}_ranked_after name\n")
        names.update("HiaCapabilityRenaming." + prefix + suffix
                     for suffix in EDGE_THEOREMS)
    text += "end HiaCapabilityRenaming\n"
    text += "".join("#print axioms " + name + "\n" for name in sorted(names))
    if len(text.encode()) > 1_048_576:
        raise ValueError("generated concrete Lean witness exceeds byte budget")
    return text, names, mappings


def observed_mutations(rows, *, require_all=True):
    """Change only actual result fields; the original input/map remain fixed."""
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
                         for name, cap in row["result"].items() if predicate(name, cap)), None)
        if selected is None:
            if require_all:
                raise ValueError("production cohort does not cover result mutation: " + mutation)
            continue
        index, name = selected
        changed = deepcopy(rows)
        cap = changed[index]["result"][name]
        if mutation == "root_rebound": cap["root"] = name
        elif mutation == "parent_discarded": cap["parent"] = None
        elif mutation == "kind_changed": cap["typ"] = "readbuf" if cap["typ"] != "readbuf" else "buffer"
        elif mutation == "external_flipped": cap["external"] = not cap["external"]
        else: cap["origin"] = None
        mutations[mutation] = (changed, "HiaCapabilityRenaming.edge" + str(index) + "_result")
    return mutations


def proof_input_mutations(rows):
    """Break the new exported premises while retaining observed inputs/output.

    These exercise kernel checking of the selector and rank certificate. They
    are not presented as actual executions of a modified production helper.
    """
    generated, names, mappings = export_observed_edges(rows)
    mutations = {}
    local_edge = next(((i, name) for i, row in enumerate(rows)
                       for name in sorted(row["remap"])
                       if not row["capabilities"][name]["external"]), None)
    if local_edge is not None:
        index, name = local_edge
        codes = mappings[index]["selected_names"]
        lost = mappings[index]["source_names"][name]
        old = f"def edge{index}Keep (n : Nat) : Bool := decide (n ∈ [" + ", ".join(map(str, codes)) + "])"
        new = f"def edge{index}Keep (n : Nat) : Bool := decide (n ∈ [" + ", ".join(str(code) for code in codes if code != lost) + "])"
        if generated.count(old) != 1 or old == new:
            raise ValueError("concrete local-projection mutation is not unique")
        mutations["selector_drops_local"] = (generated.replace(old, new, 1), names,
            f"HiaCapabilityRenaming.edge{index}_projection")
    ranked_edge = next((i for i, row in enumerate(rows)
                        if any(cap["parent"] is not None for cap in row["capabilities"].values())), None)
    if ranked_edge is not None:
        old = f"def edge{ranked_edge}Rank (n : Nat) : Nat :=\n  match n with\n"
        old += "".join(f"  | {name} => {rank}\n" for name, rank in mappings[ranked_edge]["parent_ranks"].items())
        old += "  | _ => 0\n"
        new = f"def edge{ranked_edge}Rank (_n : Nat) : Nat := 0\n"
        if generated.count(old) != 1:
            raise ValueError("concrete parent-rank mutation is not unique")
        mutations["parent_ranks_flattened"] = (generated.replace(old, new, 1), names,
            f"HiaCapabilityRenaming.edge{ranked_edge}_ranked_before")
    return mutations


def _observed_dependencies(log, expected, *, broken=False):
    rows = re.findall(r"^'([^']+)' depends on axioms: \[([^\]]*)\]$", log, re.M)
    rows += [(name, "") for name in re.findall(r"^'([^']+)' does not depend on any axioms$", log, re.M)]
    if len(rows) != len(expected) or {name for name, _ in rows} != expected:
        raise ValueError("concrete kernel theorem inventory differs")
    allowed = {"propext", "Quot.sound", "Classical.choice"} | ({"sorryAx"} if broken else set())
    result = {name: [x.strip() for x in used.split(",") if x.strip()] for name, used in rows}
    if any(set(values) - allowed for values in result.values()):
        raise ValueError("concrete witness contains an unreviewed axiom")
    return result


def _production_source_identity():
    paths = list((ROOT / "hepta").glob("*.py")) + list((ROOT / "rust/hia-core-shadow/src").rglob("*.rs"))
    paths += [ROOT / path for path in (
        "tools/verify_hia_capabilities.py", "tools/qualify_hia_selected_formal.py", "tools/evidence_checks.py",
        "tools/qualify_hia_three_lane.py", "formal/HiaCapabilityRenaming.lean", "formal/toolchain-lock.json",
        "formal/proof-dependencies.txt", "rust/hia-core-shadow/Cargo.toml", "rust/hia-core-shadow/Cargo.lock")]
    paths += [ROOT / path for _, path, _, _, _ in PRODUCTION_INPUTS]
    return {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in sorted(set(paths))}


def verify_production(lean, output, rust_shadow, rust_sha256, *, program=None, function=None, arguments=None):
    """Finite production witnesses + generic model + independent same-Core Rust.

    The default fixed cohort or one explicitly selected primitive Core is
    checked as an artifact, never as a universal implementation theorem.
    """
    from hepta.hia_program import verify_program
    from hepta.hia_program_source import lower_source
    from hepta.hia_rust_byte_dag import execute_rust_byte_dag
    from hepta.hia_program_runtime import execute_program, HIAProgramTrap, HIAProgramBudgetExceeded
    from hepta import hia_rust_crosscheck as transport
    from tools import qualify_hia_selected_formal as support
    from tools.qualify_hia_three_lane import _verified_receipt_destination
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    before = {"head": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
              "status": git("status", "--porcelain", "--untracked-files=all")}
    if before["status"]:
        raise ValueError("production proof qualification requires a clean source checkout")
    output = _verified_receipt_destination(Path(output)).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source_identity = _production_source_identity()
    executable = Path(lean).resolve(strict=True)
    lean_binary_sha256 = digest(executable.read_bytes())
    rust_binary = Path(rust_shadow).resolve(strict=True)
    if digest(rust_binary.read_bytes()) != rust_sha256:
        raise ValueError("Rust shadow differs from the requested executable digest")
    lean_support = support._support_identity(executable)
    custom = program is not None
    report = {"schema": "hepta.hia.production-capability-witness.v3", "passed": False,
              "invocation_mode": "explicit_primitive_program" if custom else "registered_fixture_cohort",
              "source_before": before, "source_identity": source_identity,
              "corpus": [], "rust_cases": [], "actual_result_mutations": [], "proof_input_mutations": [],
              "scope": {"generic_renaming_invariants": True, "finite_actual_edge_witnesses": True,
                        "trace_scope": "current qualification thread only; existing callable profiler is chained/restored",
                        "external_projection_formally_proved": True,
                        "local_kind_origin_inventory_preserved": True,
                        "observed_input_parent_ranks_kernel_checked": True,
                        "observed_output_parent_acyclicity_proved": True,
                        "all_admitted_model_edge_traces_proved": True,
                        "intervening_production_instructions_proved": False,
                        "exclusive_alias_relation_preserved_not_excluded": True,
                        "exporter_or_python_checker_refinement_proved": False,
                        "rust_forward_implementation_formally_proved": False,
                        "rust_binary_build_source_attested": False,
                        "whole_core_type_ownership_soundness_proved": False,
                        "native_backend_or_abi_proved": False, "execution_authority": False}}
    try:
        report["generic_model"] = verify(lean, output / "generic-model.json")
        all_rows, cores = [], {}
        prepared = []
        if custom:
            if function is None or arguments is None:
                raise ValueError("explicit program requires function and arguments")
            raw, initial = read_primitive_program(program)
            arguments = parse_arguments(json.dumps(arguments, allow_nan=False))
            if type(function) is not str or function not in initial.scalar_entrypoints:
                raise ValueError("explicit function must be a declared public scalar entry")
            prepared.append(("user_program", str(Path(program).absolute()), "explicit-primitive", function,
                             (tuple(arguments),), raw, initial))
            (output / "original-program-input.json").write_bytes(raw)
        else:
            if function is not None or arguments is not None:
                raise ValueError("function/arguments require an explicit program")
            for label, path, mode, entry, cases in PRODUCTION_INPUTS:
                raw = (ROOT / path).read_bytes()
                initial = lower_source(raw.decode(), core_schema="hepta.hia.program.v8") if mode == "source-v8" else verify_program(raw)
                prepared.append((label, path, mode, entry, cases, raw, initial))
        for label, path, mode, entry, cases, raw, initial in prepared:
            core, rows = capture_core_edges(initial.canonical_bytes)
            for row in rows:
                row["cohort"] = label
            all_rows.extend(rows)
            cores[label] = core
            (output / (label + ".hia.json")).write_bytes(core.canonical_bytes)
            report["corpus"].append({"cohort": label, "input": path, "input_sha256": digest(raw),
                "producer": mode, "core_sha256": core.sha256, "edges": len(rows),
                "static_edge_inventory": validate_edge_coverage(core.as_dict(), rows),
                "all_static_edge_occurrences_observed": True})
            limits = {"max_steps": 4096, "max_heap_bytes": 4096, "max_call_depth": 32}
            static_policy = {"max_allocator_interactions": 64, "max_vm_ticks": 4096, "max_call_depth": 32}
            for arguments in cases:
                rust = execute_rust_byte_dag(core.canonical_bytes, entry, arguments, rust_shadow,
                    executable_sha256=rust_sha256, static_policy=static_policy, **limits)
                try:
                    python = execute_program(core, entry, arguments, **limits)
                except (HIAProgramTrap, HIAProgramBudgetExceeded) as stopped:
                    python = stopped.report
                runtime = rust["rust_report"]["runtime"]
                transport._validate_execution(transport._canonical(runtime) + b"\n", runtime["request"],
                                              core.as_dict(), python, protocol_version=4)
                report["rust_cases"].append({"cohort": label, "entry": entry, "arguments": list(arguments),
                    "core_sha256": core.sha256, "rust": rust, "python": python, "complete_ledger_matches": True})
        (output / "production-edges.json").write_text(json.dumps(all_rows, indent=2) + "\n")
        generated, names, mappings = export_observed_edges(all_rows)
        (output / "actual-edges.lean").write_text(generated)
        (output / "encoding-map.json").write_text(json.dumps(mappings, indent=2) + "\n")
        (output / "lean-support-files.json").write_text(json.dumps(lean_support, indent=2) + "\n")
        positive = support._run_lean(executable, output / "actual-edges.lean")
        log = positive["stdout"] + positive["stderr"]
        if positive["returncode"] or "error:" in log or "sorryAx" in log:
            raise ValueError("kernel rejected actual production edge witnesses: " + log)
        report["positive"] = positive
        report["theorems"] = _observed_dependencies(log, names)
        report["generic_theorem_count"] = len(NAMES)
        report["actual_edge_count"] = len(all_rows)
        report["concrete_theorem_count"] = len(names) - len(NAMES)
        mutants = observed_mutations(all_rows, require_all=not custom)
        if not {"kind_changed", "external_flipped"} <= set(mutants):
            raise ValueError("actual capability result mutation inventory is empty or incomplete")
        report["actual_result_mutation_coverage"] = {name: (
            "kernel_refusal_required" if name in mutants else "not_applicable_field_absent_from_this_artifact")
            for name in ("root_rebound", "parent_discarded", "kind_changed", "external_flipped", "origin_discarded")}
        for mutation, (rows, expected) in mutants.items():
            changed, changed_names, _ = export_observed_edges(rows)
            path = output / (mutation + ".lean")
            path.write_text(changed)
            negative = support._run_lean(executable, path)
            badlog = negative["stdout"] + negative["stderr"]
            dependencies = _observed_dependencies(badlog, changed_names, broken=True)
            if negative["returncode"] != 1 or "error:" not in badlog or "sorryAx" not in dependencies[expected]:
                raise ValueError("changed actual result was not rejected at its equality theorem: " + mutation)
            report["actual_result_mutations"].append({"mutation": mutation, "expected_invalid_theorem": expected,
                "generated_lean_sha256": digest(changed.encode()), "theorems": dependencies, **negative})
            report["actual_result_mutation_coverage"][mutation] = "kernel_refused_as_expected"
        premise_mutants = proof_input_mutations(all_rows)
        if not custom and set(premise_mutants) != {"selector_drops_local", "parent_ranks_flattened"}:
            raise ValueError("production cohort does not cover projection/rank proof-input mutations")
        report["proof_input_mutation_coverage"] = {
            name: "kernel_refusal_required" if name in premise_mutants else "not_applicable_field_absent_from_this_artifact"
            for name in ("selector_drops_local", "parent_ranks_flattened")}
        for mutation, (changed, changed_names, expected) in premise_mutants.items():
            path = output / (mutation + ".lean")
            path.write_text(changed)
            negative = support._run_lean(executable, path)
            badlog = negative["stdout"] + negative["stderr"]
            dependencies = _observed_dependencies(badlog, changed_names, broken=True)
            if negative["returncode"] != 1 or "error:" not in badlog or "sorryAx" not in dependencies[expected]:
                raise ValueError("changed selection/rank witness was not rejected: " + mutation)
            report["proof_input_mutations"].append({"mutation": mutation,
                "mutation_scope": "exported proof premise only; actual production observations unchanged",
                "expected_invalid_theorem": expected, "generated_lean_sha256": digest(changed.encode()),
                "theorems": dependencies, **negative})
            report["proof_input_mutation_coverage"][mutation] = "kernel_refused_as_expected"
        # Feed the SAME bad whole-Core bytes independently to both established checkers.
        bad_cores = []
        if custom:
            bad = cores["user_program"].as_dict()
            selected = next(row for row in all_rows if row["remap"])
            fn = next(fn for fn in bad["functions"] if fn["name"] == selected["function"])
            block = next(block for block in fn["blocks"] if block["id"] == selected["block"])
            edge = block["term"] if selected["edge_slot"] == "jump" else block["term"][selected["edge_slot"]]
            missing = "witness_absent_capability"
            used = {p["name"] for f in bad["functions"] for b in f["blocks"]
                    for p in b["params"] + [p for op in b["ops"] for p in op["out"]]}
            while missing in used:
                missing += "x"
            edge["args"][edge["args"].index(next(iter(selected["remap"])))] = missing
            bad_cores.append(("absent_edge_capability", bad, function, list(arguments)))
        else:
            stored = cores["stored_record"].as_dict()
            ends = [op for fn in stored["functions"] for block in fn["blocks"] for op in block["ops"] if op["op"] == "loan.end"]
            if len(ends) < 2:
                raise ValueError("stored cohort no longer has nested loan discharge controls")
            ends[0]["args"], ends[1]["args"] = ends[1]["args"], ends[0]["args"]
            bad_cores.append(("parent_ended_before_child", stored, "stored", [False]))
            returned = cores["returned_views"].as_dict()
            helper = next(fn for fn in returned["functions"] if fn["name"] == "view")
            helper["return_loans"][0] = "absent_formal"
            bad_cores.append(("forged_return_origin", returned, "probe", [1, 42, True]))
        report["whole_core_refusals"] = []
        raw_executable = transport._verified_executable_bytes(Path(rust_shadow), rust_sha256)
        for label, bad, entry, arguments in bad_cores:
            raw = transport._canonical(bad)
            try:
                verify_program(raw)
            except ValueError as error:
                python_error = {"type": type(error).__name__, "message": str(error)}
            else:
                raise ValueError("Python accepted a registered bad capability Core: " + label)
            policy = transport._execution_wire_policy({**limits, "allocation_fail_at": None}, 4)
            argv = ["--byte-dag-admit-run", entry, transport._canonical(arguments).decode(),
                    transport._canonical(static_policy).decode(), transport._canonical(policy).decode()]
            stdout, stderr, code = transport._run_pinned_shadow(raw_executable, argv, raw, 30, maximum_output=1_048_576)
            if code != 1 or stdout or not stderr.startswith(b"E_HIA_") or b"panicked" in stderr:
                raise ValueError("Rust did not independently refuse the same bad Core: " + label)
            (output / (label + ".hia.json")).write_bytes(raw)
            report["whole_core_refusals"].append({"mutation": label, "mutant_core_sha256": digest(raw),
                "python": python_error, "rust": {"argv": argv, "returncode": code,
                "stdout": stdout.decode(), "stderr": stderr.decode()}, "same_bad_bytes_rejected": True})
        after = {"head": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
                 "status": git("status", "--porcelain", "--untracked-files=all")}
        if (after != before or source_identity != _production_source_identity()
                or lean_support != support._support_identity(executable)
                or digest(executable.read_bytes()) != lean_binary_sha256
                or digest(rust_binary.read_bytes()) != rust_sha256):
            raise ValueError("production witness source or Lean support changed during qualification")
        report.update(passed=True, source_after=after, source_unchanged=True,
                      rust_executable_sha256=rust_sha256, lean_binary_sha256=lean_binary_sha256)
    except BaseException as error:
        report.update(passed=False, error={"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        (output / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        manifest = {str(path.relative_to(output)): {"bytes": path.stat().st_size, "sha256": digest(path.read_bytes())}
                    for path in sorted(output.rglob("*")) if path.is_file() and path.name != "manifest.json"}
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', required=True)
    outputs = parser.add_mutually_exclusive_group(required=True)
    outputs.add_argument('--output', type=Path)
    outputs.add_argument('--production-output-directory', type=Path)
    parser.add_argument('--rust-shadow', type=Path)
    parser.add_argument('--rust-shadow-sha256')
    parser.add_argument('--program', type=Path)
    parser.add_argument('--function')
    parser.add_argument('--arguments', help='one bounded JSON scalar argument array')
    args = parser.parse_args()
    if args.production_output_directory:
        if not args.rust_shadow or not args.rust_shadow_sha256:
            parser.error('production witnesses require the actual Rust shadow and its SHA-256')
        selected = (args.program is not None, args.function is not None, args.arguments is not None)
        if any(selected) and not all(selected):
            parser.error('--program, --function and --arguments must be supplied together')
        report = verify_production(args.lean, args.production_output_directory, args.rust_shadow, args.rust_shadow_sha256,
            program=args.program, function=args.function,
            arguments=parse_arguments(args.arguments) if args.arguments is not None else None)
        print(json.dumps({key: report[key] for key in ('passed', 'actual_edge_count', 'generic_theorem_count', 'concrete_theorem_count', 'scope')}, indent=2))
    else:
        if args.rust_shadow or args.rust_shadow_sha256 or args.program or args.function or args.arguments is not None:
            parser.error('Rust/program options require --production-output-directory')
        report = verify(args.lean, args.output)
        print(json.dumps({'passed': report['passed'], 'theorems': len(report['theorems']),
                          'negative_mutations': len(report['negative_mutations']), 'scope': report['scope']}, indent=2))
