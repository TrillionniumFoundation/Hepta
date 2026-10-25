"""Independent structural SSA verifier for bounded scalar Hepta IR.

Checks single assignments, exact expression retention, use dominance,
local definition order and predecessor-specific PHI operands. NOT an
interpreter, semantic equivalence proof, or native backend qualification.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from .cfg import CFGSnapshot
from .cfg_analysis import CFGAnalysisRejected, analyze_cfg
from .ssa import SSASnapshot


_SSA_FUNCTION_FIELDS = frozenset({
    "name", "entry", "parameters", "blocks", "scalar_types", "definitions",
    "phi_count", "declared_effects", "inferred_transitive_effects",
    "resource_contract",
})
# A verifier that ignores unreviewed nested metadata can accidentally approve
# a future source/owner/effect meaning which the current SSA model cannot
# represent. Keep this finite scalar wire format explicitly closed.
_SSA_BLOCK_FIELDS = frozenset({"id", "phis", "instructions", "terminator"})
_SSA_PHI_FIELDS = frozenset({"result", "incoming"})
_SSA_PHI_EDGE_FIELDS = frozenset({"from", "ssa_ref"})
_SSA_DEFINITION_FIELDS = frozenset({"variable", "ssa_name", "type", "defined_in"})
_SSA_INSTRUCTION_FIELDS = frozenset({"operation", "ssa_value", "span"})
# This verifier owns its expectations independently of the SSA producer.
# A valid self-resealed digest must never authorize elevated proof flags.
_SSA_TOP_FIELDS = frozenset({
    "schema", "status", "source_cfg_sha256", "source_analysis_sha256",
    "functions", "claims",
})
_SSA_EXPECTED_CLAIMS = {
    "scalar_ssa_subset_constructed": True, "phi_inputs_checked": True,
    "effect_resource_metadata_retained": True,
    "whole_language_ssa_complete": False, "for_range_implemented": False,
    "match_payloads_supported": False, "borrow_drop_proven": False,
    "pointer_provenance_proven": False,
    "semantic_equivalence_proven": False,
    "native_backend_refinement_proven": False,
}


class SSAVerificationRejected(ValueError):
    pass


@dataclass(frozen=True)
class SSAVerificationSnapshot:
    schema: str
    canonical_json: str
    sha256: str

    def as_dict(self):
        if sha256(self.canonical_json.encode()).hexdigest() != self.sha256:
            raise SSAVerificationRejected("E_SSA_VERIFY_HASH: verification snapshot altered")
        return {**json.loads(self.canonical_json), "sha256": self.sha256}


def _reject(code: str, reason: str):
    raise SSAVerificationRejected(f"{code}: {reason}")


def _canonical_contract(value) -> str:
    # JSON distinguishes the safety-critical False vs 0 and 0 vs False pairs
    # that Python equality deliberately considers equal.
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError) as exc:
        _reject("E_SSA_VERIFY_CONTRACT", "Noncanonical effect/resource metadata")


def _decode(snapshot, required_schema, status):
    if snapshot.schema != required_schema:
        _reject("E_SSA_VERIFY_SCHEMA", "wrong snapshot type")
    if sha256(snapshot.canonical_json.encode()).hexdigest() != snapshot.sha256:
        _reject("E_SSA_VERIFY_HASH", "input was modified without updating identity")
    payload = json.loads(snapshot.canonical_json)
    if payload.get("schema") != required_schema or payload.get("status") != status:
        _reject("E_SSA_VERIFY_SCHEMA", "snapshot's canonical schema/status disagrees")
    if required_schema == "hepta.ssa.scalar.v0":
        if (set(payload) != _SSA_TOP_FIELDS
                or _canonical_contract(payload.get("claims")) !=
                   _canonical_contract(_SSA_EXPECTED_CLAIMS)):
            _reject("E_SSA_VERIFY_CLAIMS", "SSA schema or safety proof claims changed")
    return payload


def _unmark(value, depth=0):
    if depth > 64:
        _reject("E_SSA_VERIFY_LIMIT", "expression nesting too deep")
    if isinstance(value, dict):
        return {k: _unmark(v, depth+1) for k, v in value.items() if k != "ssa_ref"}
    if isinstance(value, list):
        return [_unmark(v, depth+1) for v in value]
    return value


def _function(f: dict, original: dict, graph: dict) -> dict:
    if not isinstance(f, dict) or set(f) != _SSA_FUNCTION_FIELDS:
        _reject("E_SSA_VERIFY_CONTRACT", "SSA function fields differ from reviewed source contract")
    for field in ("declared_effects", "inferred_transitive_effects", "resource_contract"):
        if (field not in original or
                _canonical_contract(f[field]) != _canonical_contract(original[field])):
            _reject("E_SSA_VERIFY_CONTRACT", "SSA effect/resource metadata changed or disappeared")
    blocks = f.get("blocks")
    before = original.get("blocks")
    if not isinstance(blocks, list) or not isinstance(before, list) or len(blocks) != len(before):
        _reject("E_SSA_VERIFY_BLOCKS", "block count differs")
    expected_ids = [b["id"] for b in before]
    if (any(not isinstance(b, dict) or set(b) != _SSA_BLOCK_FIELDS for b in blocks)
            or [b["id"] for b in blocks] != expected_ids):
        _reject("E_SSA_VERIFY_BLOCKS", "SSA basic-block schema or identities differ")
    if f.get("entry") != original.get("entry"):
        _reject("E_SSA_VERIFY_ENTRY", "entry block changed")
    dom = {k: set(v) for k, v in graph["dominators"].items()}
    preds = graph["predecessors"]
    scalar_types = f.get("scalar_types")
    if not isinstance(scalar_types, dict):
        _reject("E_SSA_VERIFY_TYPES", "missing scalar symbol table")
    defs = {}
    version_numbers = {}

    def add(defn, block, order, expected_name=None, expected_type=None):
        if not isinstance(defn, dict) or set(defn) != _SSA_DEFINITION_FIELDS:
            _reject("E_SSA_VERIFY_DEF", "missing or unreviewed definition metadata")
        name, version, ty = defn.get("variable"), defn.get("ssa_name"), defn.get("type")
        if (not isinstance(name, str) or scalar_types.get(name) != ty or
                not isinstance(version, str) or re.fullmatch(re.escape(name) + r"@[0-9]+", version) is None):
            _reject("E_SSA_VERIFY_DEF", "invalid scalar definition or version")
        if expected_name is not None and name != expected_name:
            _reject("E_SSA_VERIFY_DEF", "definition variable differs from original source")
        if expected_type is not None and ty != expected_type:
            _reject("E_SSA_VERIFY_TYPE", "definition type differs from original")
        if defn.get("defined_in") != block or version in defs:
            _reject("E_SSA_VERIFY_DEF", "wrong source block or repeated SSA definition")
        defs[version] = {"variable": name, "type": ty, "block": block, "order": order}
        version_numbers.setdefault(name, []).append(int(version.rsplit("@", 1)[1]))

    params = f.get("parameters")
    old_params = original.get("param_types")
    if not isinstance(params, list) or not isinstance(old_params, list) or len(params) != len(old_params):
        _reject("E_SSA_VERIFY_PARAMS", "parameter count differs")
    for p, old in zip(params, old_params):
        if old.get("ownership") != "value":
            _reject("E_SSA_VERIFY_PARAMS", "unsupported parameter ownership")
        add(p, f["entry"], -2, old["name"], old["type"]["type"])
    for b, old in zip(blocks, before):
        bid = b["id"]
        phi = b.get("phis")
        instr = b.get("instructions")
        old_instr = old.get("instructions")
        if not isinstance(phi, list) or not isinstance(instr, list) or len(instr) != len(old_instr):
            _reject("E_SSA_VERIFY_INSTRUCTIONS", "source instruction count disagrees")
        # The entry has no predecessors. A re-sealed zero-input PHI there can
        # otherwise appear to define a value which has no source execution.
        # The producer's pruned scalar profile places PHIs only at joins.
        if phi and (bid == f["entry"] or len(preds[bid]) < 2):
            _reject("E_SSA_VERIFY_PHI", "PHI requires a real multi-predecessor join")
        phi_names = set()
        for p in phi:
            if (not isinstance(p, dict) or set(p) != _SSA_PHI_FIELDS
                    or not isinstance(p.get("incoming"), list)):
                _reject("E_SSA_VERIFY_PHI", "malformed or unreviewed PHI metadata")
            result = p["result"]
            add(result, bid, -1)
            if result["variable"] in phi_names:
                _reject("E_SSA_VERIFY_PHI", "duplicate PHI for same variable in one block")
            phi_names.add(result["variable"])
        for index, (item, before_item) in enumerate(zip(instr, old_instr)):
            if (not isinstance(item, dict)
                    or set(item) not in (_SSA_INSTRUCTION_FIELDS,
                                         _SSA_INSTRUCTION_FIELDS | {"definition"})):
                _reject("E_SSA_VERIFY_INSTRUCTIONS", "unreviewed scalar instruction metadata")
            if item.get("operation") != before_item.get("operation") or item.get("span") != before_item.get("span"):
                _reject("E_SSA_VERIFY_ORIGIN", "instruction kind/span changed")
            source_expr = before_item["fields"].get("expr")
            if not isinstance(source_expr, dict) or not isinstance(item.get("ssa_value"), dict):
                _reject("E_SSA_VERIFY_EXPRESSION", "scalar instruction must retain its typed initializer")
            if _unmark(item["ssa_value"]) != source_expr:
                _reject("E_SSA_VERIFY_ORIGIN", "instruction expression changed")
            raw_target = (before_item["fields"].get("name") if item["operation"] == "let" else
                          before_item["fields"].get("target", {}).get("value") if item["operation"] == "assign" else None)
            if raw_target is None:
                if "definition" in item:
                    _reject("E_SSA_VERIFY_DEF", "unexpected definition on expression statement")
            else:
                source_type = source_expr.get("result_type")
                if not isinstance(source_type, dict) or not isinstance(source_type.get("type"), str):
                    _reject("E_SSA_VERIFY_TYPE", "original scalar initializer has no checked type")
                # Check independently: matching the SSA symbol table is NOT
                # enough when both it and the definition were re-signed.
                add(item.get("definition"), bid, index, raw_target,
                    expected_type=source_type["type"])
        if _unmark(b.get("terminator")) != old.get("terminator"):
            _reject("E_SSA_VERIFY_ORIGIN", "terminator changed")
    if f.get("definitions") != len(defs) or f.get("phi_count") != sum(len(b["phis"]) for b in blocks):
        _reject("E_SSA_VERIFY_COUNT", "reported definition/PHI count differs")
    if set(scalar_types) != set(version_numbers):
        _reject("E_SSA_VERIFY_TYPES", "symbol table differs from actual SSA definition inventory")
    for name, versions in version_numbers.items():
        if sorted(versions) != list(range(len(versions))):
            _reject("E_SSA_VERIFY_DEF", "non-canonical or missing SSA versions")

    def read_expr(node, block, position, predecessor=None, depth=0):
        if node is None:
            return 0
        if depth > 64 or not isinstance(node, dict) or node.get("node") != "expr":
            _reject("E_SSA_VERIFY_EXPRESSION", "malformed or overly deep expression")
        if node.get("operation") == "name":
            ref = node.get("ssa_ref")
            src = defs.get(ref) if isinstance(ref, str) else None
            if src is None or src["variable"] != node.get("value") or src["type"] != node.get("result_type", {}).get("type"):
                _reject("E_SSA_VERIFY_USE", "undefined or wrongly typed SSA reference")
            site = predecessor or block
            if src["block"] not in dom[site]:
                _reject("E_SSA_VERIFY_DOMINANCE", "definition does not dominate use or incoming edge")
            if src["block"] == site and predecessor is None and src["order"] >= position:
                _reject("E_SSA_VERIFY_ORDER", "local SSA definition does not precede use")
            return 1
        if "ssa_ref" in node:
            _reject("E_SSA_VERIFY_USE", "non-name expression has a SSA reference")
        operands = node.get("operands")
        if not isinstance(operands, list):
            _reject("E_SSA_VERIFY_EXPRESSION", "missing operands")
        return sum(read_expr(op, block, position, predecessor, depth+1) for op in operands)

    reads, phis = 0, 0
    for b in blocks:
        bid = b["id"]
        for phi in b["phis"]:
            phis += 1
            incoming = phi["incoming"]
            if (any(not isinstance(x, dict) or set(x) != _SSA_PHI_EDGE_FIELDS for x in incoming)
                    or [x["from"] for x in incoming] != sorted(preds[bid])):
                _reject("E_SSA_VERIFY_PHI", "PHI predecessors or input schema do not match CFG")
            for edge in incoming:
                pred = edge["from"]
                ref = edge.get("ssa_ref")
                src = defs.get(ref) if isinstance(ref, str) else None
                if src is None or src["variable"] != phi["result"]["variable"] or src["type"] != phi["result"]["type"]:
                    _reject("E_SSA_VERIFY_PHI", "PHI input is missing or mismatched")
                if src["block"] not in dom[pred]:
                    _reject("E_SSA_VERIFY_DOMINANCE", "PHI input definition does not dominate predecessor")
                reads += 1
        for index, inst in enumerate(b["instructions"]):
            reads += read_expr(inst["ssa_value"], bid, index)
        term = b["terminator"]
        value = (term.get("condition") if term["kind"] == "branch" else
                 term.get("value") if term["kind"] == "return" else None)
        if value is not None:
            reads += read_expr(value, bid, len(b["instructions"]))
    contract = {field: f[field] for field in
                ("declared_effects", "inferred_transitive_effects", "resource_contract")}
    contract_sha256 = sha256(json.dumps(contract, sort_keys=True, ensure_ascii=False,
                                       allow_nan=False, separators=(",", ":")).encode()).hexdigest()
    return {"name": f["name"], "blocks": len(blocks), "definitions": len(defs),
            "phi_count": phis, "ssa_references_verified": reads,
            "source_effect_resource_sha256": contract_sha256}



def _verify_reaching_definitions(f: dict, original: dict, graph: dict) -> None:
    """Independently verify predecessor-specific value flow, not just dominance.

    Dominance alone is insufficient: a pre-branch definition dominates both
    successors, but is not the value produced by either successor's writes.
    This restricted verifier handles only the scalar CFG already accepted by
    the source-bound structural gate. It is not an ownership/provenance proof.
    """
    blocks = {b["id"]: b for b in f["blocks"]}
    originals = {b["id"]: b for b in original["blocks"]}
    entry = f["entry"]
    predecessors = graph["predecessors"]
    successors = graph["successors"]
    children = {name: [] for name in blocks}
    for block_id, parent in graph["immediate_dominators"].items():
        if parent is not None:
            children[parent].append(block_id)

    # Replay SSA naming over the *independent* dominator tree, taking each
    # definition only after its initializer has been evaluated.
    initial = {p["variable"]: p["ssa_name"] for p in f["parameters"]}
    before, after = {}, {}
    work = [(entry, initial)]
    while work:
        block_id, parent_values = work.pop()
        local = dict(parent_values)
        block = blocks[block_id]
        for phi in block["phis"]:
            definition = phi["result"]
            local[definition["variable"]] = definition["ssa_name"]
        before[block_id] = dict(local)
        for instruction in block["instructions"]:
            if "definition" in instruction:
                definition = instruction["definition"]
                local[definition["variable"]] = definition["ssa_name"]
        after[block_id] = local
        work.extend((child, local) for child in reversed(sorted(children[block_id])))
    if set(after) != set(blocks):
        _reject("E_SSA_VERIFY_REACHING", "Dominator traversal omitted a source block")

    def names(node, depth=0) -> set[str]:
        if node is None:
            return set()
        if depth > 64 or not isinstance(node, dict) or node.get("node") != "expr":
            _reject("E_SSA_VERIFY_REACHING", "Unreviewed source expression in reaching analysis")
        if node.get("operation") == "name":
            if not isinstance(node.get("value"), str):
                _reject("E_SSA_VERIFY_REACHING", "Missing source variable identity")
            return {node["value"]}
        operands = node.get("operands")
        if not isinstance(operands, list):
            _reject("E_SSA_VERIFY_REACHING", "Malformed expression operands")
        result = set()
        for value in operands:
            result.update(names(value, depth + 1))
        return result

    # Reconstruct source liveness, independently of the SSA producer. A
    # non-live variable can legitimately have divergent dead branch values;
    # a live variable cannot cross the join without a correct PHI.
    upward, definitions = {}, {}
    for block_id, source in originals.items():
        uses, killed = set(), set()
        for instruction in source["instructions"]:
            uses.update(names(instruction["fields"]["expr"]) - killed)
            if instruction["operation"] in {"let", "assign"}:
                name = (instruction["fields"].get("name")
                        if instruction["operation"] == "let"
                        else instruction["fields"].get("target", {}).get("value"))
                if not isinstance(name, str) or not name:
                    _reject("E_SSA_VERIFY_REACHING", "Malformed original scalar definition")
                killed.add(name)
        term = source["terminator"]
        if term["kind"] in {"return", "branch"}:
            uses.update(names(term.get("condition") if term["kind"] == "branch"
                              else term.get("value")) - killed)
        upward[block_id], definitions[block_id] = uses, killed
    live_in = {name: set() for name in blocks}
    live_out = {name: set() for name in blocks}
    # Monotone finite sets over the bounded CFG; fail closed on nonconvergence.
    for _ in range(max(1, len(blocks) * (len(f["scalar_types"]) + 1))):
        changed = False
        for block_id in reversed(list(originals)):
            out = set().union(*(live_in[succ] for succ in successors[block_id]))
            into = upward[block_id] | (out - definitions[block_id])
            if live_out[block_id] != out or live_in[block_id] != into:
                live_out[block_id], live_in[block_id] = out, into
                changed = True
        if not changed:
            break
    else:
        _reject("E_SSA_VERIFY_REACHING", "Source liveness did not converge")

    def check_reads(node, current, depth=0):
        if node is None:
            return
        if depth > 64 or not isinstance(node, dict) or node.get("node") != "expr":
            _reject("E_SSA_VERIFY_REACHING", "Unreviewed SSA expression")
        if node.get("operation") == "name":
            if current.get(node.get("value")) != node.get("ssa_ref"):
                _reject("E_SSA_VERIFY_REACHING", "SSA read skips the most recent definition")
            return
        for operand in node.get("operands", []):
            check_reads(operand, current, depth + 1)

    for block_id, block in blocks.items():
        current = dict(before[block_id])
        for instruction in block["instructions"]:
            check_reads(instruction["ssa_value"], current)
            if "definition" in instruction:
                definition = instruction["definition"]
                current[definition["variable"]] = definition["ssa_name"]
        term = block["terminator"]
        if term["kind"] in {"return", "branch"}:
            check_reads(term.get("value") if term["kind"] == "return"
                        else term.get("condition"), current)
        for phi in block["phis"]:
            var = phi["result"]["variable"]
            for edge in phi["incoming"]:
                if after[edge["from"]].get(var) != edge["ssa_ref"]:
                    _reject("E_SSA_VERIFY_REACHING", "PHI input is not the predecessor's exit definition")
        if block_id != entry:
            phi_vars = {p["result"]["variable"] for p in block["phis"]}
            for var in live_in[block_id] - phi_vars:
                inherited = before[block_id].get(var)
                if inherited is None or any(after[pred].get(var) != inherited
                                            for pred in predecessors[block_id]):
                    _reject("E_SSA_VERIFY_REACHING", "Live value crosses a join without the required PHI")


def verify_scalar_ssa(ssa: SSASnapshot, cfg: CFGSnapshot) -> SSAVerificationSnapshot:
    """Verify SSA dataflow facts against the exact original control flow."""
    if not isinstance(ssa, SSASnapshot) or not isinstance(cfg, CFGSnapshot):
        _reject("E_SSA_VERIFY_SCHEMA", "expected SSA and CFG typed snapshots")
    payload = _decode(ssa, "hepta.ssa.scalar.v0", "scalar_ssa_subset_not_backend_qualified")
    original = _decode(cfg, "hepta.cfg.v0", "structural_cfg_only_not_proved")
    if payload.get("source_cfg_sha256") != cfg.sha256:
        _reject("E_SSA_VERIFY_INPUT", "SSA has a different CFG source")
    try:
        analysis = analyze_cfg(cfg).as_dict()
    except CFGAnalysisRejected as exc:
        raise SSAVerificationRejected("E_SSA_VERIFY_CFG: " + str(exc)) from exc
    if payload.get("source_analysis_sha256") != analysis["sha256"]:
        _reject("E_SSA_VERIFY_INPUT", "SSA dominance snapshot mismatch")
    fs, originals, graphs = payload.get("functions"), original["functions"], analysis["functions"]
    if not isinstance(fs, list) or len(fs) != len(originals) or len(fs) != len(graphs):
        _reject("E_SSA_VERIFY_FUNCTIONS", "SSA has wrong function inventory")
    result = []
    for f, old, graph in zip(fs, originals, graphs):
        if f.get("name") != old.get("name") or f["name"] != graph["name"]:
            _reject("E_SSA_VERIFY_FUNCTIONS", "function order/name changed")
        verified = _function(f, old, graph)
        _verify_reaching_definitions(f, old, graph)
        result.append(verified)
    output = {"schema": "hepta.ssa.verify.v0", "status": "scalar_ssa_structurally_verified",
              "ssa_sha256": ssa.sha256, "cfg_sha256": cfg.sha256, "functions": result,
              "claims": {"single_assignment_checked": True, "ssa_edge_uses_checked": True,
                         "effect_resource_metadata_matched_to_cfg": True,
                         "ssa_origin_expression_retained": True,
                         "semantic_equivalence_proven": False,
                         "whole_language_memory_safety_proven": False,
                         "native_backend_refinement_proven": False}}
    canonical = json.dumps(output, sort_keys=True, ensure_ascii=False, allow_nan=False,
                           separators=(",", ":"))
    return SSAVerificationSnapshot("hepta.ssa.verify.v0", canonical, sha256(canonical.encode()).hexdigest())
