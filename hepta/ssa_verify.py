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
from .ssa_reaching import ReachingRejected, verify_latest_reads


_SSA_FUNCTION_FIELDS = frozenset({
    "name", "entry", "parameters", "blocks", "scalar_types", "definitions",
    "phi_count", "declared_effects", "inferred_transitive_effects",
    "resource_contract",
})
# Close the scalar wire vocabulary: owner/drop/unsafe metadata must not be
# silently ignored by a verifier that knows only scalar SSA.
_SSA_BLOCK_FIELDS = frozenset({"id", "phis", "instructions", "terminator"})
_SSA_PHI_FIELDS = frozenset({"result", "incoming"})
_SSA_PHI_EDGE_FIELDS = frozenset({"from", "ssa_ref"})
_SSA_DEFINITION_FIELDS = frozenset({"variable", "ssa_name", "type", "defined_in"})
_SSA_INSTRUCTION_FIELDS = frozenset({"operation", "ssa_value", "span"})


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


def _typed_equal(left, right) -> bool:
    """Source identity must preserve JSON literal type (False is not zero)."""
    try:
        return (json.dumps(left, sort_keys=True, ensure_ascii=False,
                           allow_nan=False, separators=(",", ":")) ==
                json.dumps(right, sort_keys=True, ensure_ascii=False,
                           allow_nan=False, separators=(",", ":")))
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SSAVerificationRejected(
            "E_SSA_VERIFY_ORIGIN: noncanonical source/SSA literal") from exc


def _decode(snapshot, required_schema, status):
    if snapshot.schema != required_schema:
        _reject("E_SSA_VERIFY_SCHEMA", "wrong snapshot type")
    if sha256(snapshot.canonical_json.encode()).hexdigest() != snapshot.sha256:
        _reject("E_SSA_VERIFY_HASH", "input was modified without updating identity")
    payload = json.loads(snapshot.canonical_json)
    if payload.get("schema") != required_schema or payload.get("status") != status:
        _reject("E_SSA_VERIFY_SCHEMA", "snapshot's canonical schema/status disagrees")
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
        # JSON scalar types are semantic: Python considers False == 0, but a
        # Boolean may not impersonate an allocation count (or vice versa).
        if (field not in original or
                json.dumps(f[field], sort_keys=True, allow_nan=False, separators=(",", ":")) !=
                json.dumps(original[field], sort_keys=True, allow_nan=False, separators=(",", ":"))):
            _reject("E_SSA_VERIFY_CONTRACT", "SSA effect/resource metadata changed or disappeared")
    blocks = f.get("blocks")
    before = original.get("blocks")
    if not isinstance(blocks, list) or not isinstance(before, list) or len(blocks) != len(before):
        _reject("E_SSA_VERIFY_BLOCKS", "block count differs")
    expected_ids = [b["id"] for b in before]
    if (any(not isinstance(b, dict) or set(b) != _SSA_BLOCK_FIELDS for b in blocks)
            or [b["id"] for b in blocks] != expected_ids):
        _reject("E_SSA_VERIFY_BLOCKS", "unreviewed block metadata or identities")
    if f.get("entry") != original.get("entry"):
        _reject("E_SSA_VERIFY_ENTRY", "entry block changed")
    dom = {k: set(v) for k, v in graph["dominators"].items()}
    preds = graph["predecessors"]
    scalar_types = f.get("scalar_types")
    if not isinstance(scalar_types, dict):
        _reject("E_SSA_VERIFY_TYPES", "missing scalar symbol table")
    defs = {}
    version_numbers = {}

    # Reconstruct local source types from the original checked CFG rather than
    # trusting independently rehashed SSA type/definition inventories. Without
    # this, an unused local may be silently retagged from i32 to u32 while all
    # dominance and source-expression checks still report success.
    def source_type(node, context):
        if (not isinstance(node, dict) or set(node) != {"type", "args", "length"}
                or not isinstance(node["type"], str)
                or node["args"] != [] or node["length"] is not None):
            _reject("E_SSA_VERIFY_SOURCE_TYPE", f"malformed source {context} type")
        return node["type"]

    source_types = {}
    for parameter in original.get("param_types", []):
        if not isinstance(parameter, dict) or not isinstance(parameter.get("name"), str):
            _reject("E_SSA_VERIFY_SOURCE_TYPE", "malformed source parameter")
        name = parameter["name"]
        if name in source_types:
            _reject("E_SSA_VERIFY_SOURCE_TYPE", "duplicate source parameter")
        source_types[name] = source_type(parameter.get("type"), "parameter")
    for old_block in before:
        for original_item in old_block["instructions"]:
            if original_item["operation"] != "let":
                continue
            fields = original_item["fields"]
            name = fields.get("name")
            ty = source_type(fields["expr"].get("result_type"), "binding initializer")
            declared = fields.get("type")
            if (not isinstance(name, str) or not name or name in source_types
                    or (declared is not None
                        and source_type(declared, "declared binding") != ty)):
                _reject("E_SSA_VERIFY_SOURCE_TYPE", "inconsistent source binding")
            source_types[name] = ty
    for old_block in before:
        for original_item in old_block["instructions"]:
            if original_item["operation"] != "assign":
                continue
            fields = original_item["fields"]
            target = fields.get("target")
            if (not isinstance(target, dict) or target.get("operation") != "name"
                    or not isinstance(target.get("value"), str)):
                _reject("E_SSA_VERIFY_SOURCE_TYPE", "unsupported source assignment")
            name = target["value"]
            value_ty = source_type(fields["expr"].get("result_type"), "assignment")
            target_ty = source_type(target.get("result_type"), "assignment target")
            if source_types.get(name) != target_ty or value_ty != target_ty:
                _reject("E_SSA_VERIFY_SOURCE_TYPE", "inconsistent source assignment type")
    if scalar_types != source_types:
        _reject("E_SSA_VERIFY_SOURCE_TYPE", "SSA scalar type inventory differs from source CFG")

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
        # Zero-input entry PHIs or single-predecessor PHIs can invent an
        # SSA definition that no path through the checked source produces.
        if phi and (bid == f["entry"] or len(preds[bid]) < 2):
            _reject("E_SSA_VERIFY_PHI", "PHI requires a multi-predecessor join")
        phi_names = set()
        for p in phi:
            if (not isinstance(p, dict) or set(p) != _SSA_PHI_FIELDS
                    or not isinstance(p.get("incoming"), list)):
                _reject("E_SSA_VERIFY_PHI", "unreviewed PHI metadata")
            result = p["result"]
            add(result, bid, -1)
            if result["variable"] in phi_names:
                _reject("E_SSA_VERIFY_PHI", "duplicate PHI for same variable in one block")
            phi_names.add(result["variable"])
        for index, (item, before_item) in enumerate(zip(instr, old_instr)):
            if (not isinstance(item, dict)
                    or set(item) not in (_SSA_INSTRUCTION_FIELDS,
                                         _SSA_INSTRUCTION_FIELDS | {"definition"})):
                _reject("E_SSA_VERIFY_INSTRUCTIONS", "unreviewed SSA instruction metadata")
            if (item.get("operation") != before_item.get("operation")
                    or not _typed_equal(item.get("span"), before_item.get("span"))):
                _reject("E_SSA_VERIFY_ORIGIN", "instruction kind/span changed")
            if not _typed_equal(_unmark(item.get("ssa_value")), before_item["fields"].get("expr")):
                _reject("E_SSA_VERIFY_ORIGIN", "instruction expression changed")
            raw_target = (before_item["fields"].get("name") if item["operation"] == "let" else
                          before_item["fields"].get("target", {}).get("value") if item["operation"] == "assign" else None)
            if raw_target is None:
                if "definition" in item:
                    _reject("E_SSA_VERIFY_DEF", "unexpected definition on expression statement")
            else:
                add(item.get("definition"), bid, index, raw_target)
        if not _typed_equal(_unmark(b.get("terminator")), old.get("terminator")):
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
            if (any(not isinstance(edge, dict) or set(edge) != _SSA_PHI_EDGE_FIELDS
                    for edge in incoming)
                    or [edge["from"] for edge in incoming] != sorted(preds[bid])):
                _reject("E_SSA_VERIFY_PHI", "PHI predecessors or edge schema differ from CFG")
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
    # Dominance alone permits an older, still-dominating version after a
    # later assignment. Independently compute reaching definitions on CFG
    # edges, including loop backedges, and reject stale PHI/read operands.
    try:
        latest_reads = verify_latest_reads(f, graph)
    except ReachingRejected as exc:
        raise SSAVerificationRejected(str(exc)) from exc
    contract = {field: f[field] for field in
                ("declared_effects", "inferred_transitive_effects", "resource_contract")}
    contract_sha256 = sha256(json.dumps(contract, sort_keys=True, ensure_ascii=False,
                                       allow_nan=False, separators=(",", ":")).encode()).hexdigest()
    return {"name": f["name"], "blocks": len(blocks), "definitions": len(defs),
            "phi_count": phis, "ssa_references_verified": reads,
            "source_effect_resource_sha256": contract_sha256,
            "latest_source_version_reads_verified": latest_reads}


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
        result.append(_function(f, old, graph))
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
