"""Deterministic structural CFG for checker-accepted HSIR v0 snapshots.

A P1 stepping stone; NOT SSA, a borrow checker, a provenance proof, or an
executable IR. Unsupported control-flow constructs reject rather than vanish.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from .hsir import HSIRSnapshot, SCHEMA as SCALAR_HSIR_SCHEMA, lower_checked_program


class CFGRejected(ValueError):
    """Structural lowerer cannot faithfully describe the source."""


@dataclass(frozen=True)
class CFGSnapshot:
    schema: str
    canonical_json: str
    sha256: str

    def as_dict(self) -> dict:
        data = json.loads(self.canonical_json)
        data["sha256"] = self.sha256
        return data


MAX_BLOCKS_PER_FUNCTION = 4096
MAX_NESTING = 128
_SIMPLE = frozenset({"let", "assign", "expr"})
_CONTROLS = frozenset({"return", "if", "while", "for", "match", "unsafe"})


def _require_expr(expr: object, label: str) -> dict:
    if not isinstance(expr, dict) or expr.get("node") != "expr" or not isinstance(expr.get("result_type"), dict):
        raise CFGRejected(f"E_CFG_UNTYPED: {label} is not a typed HSIR expression")
    return expr


def _require_statements(stmts: object) -> list[dict]:
    if not isinstance(stmts, list):
        raise CFGRejected("E_CFG_SHAPE: expected statement list")
    for stmt in stmts:
        if not isinstance(stmt, dict) or stmt.get("node") != "stmt":
            raise CFGRejected("E_CFG_SHAPE: expected a structured HSIR statement")
        if stmt.get("operation") not in _SIMPLE | _CONTROLS:
            raise CFGRejected(f"E_CFG_UNSUPPORTED: statement kind {stmt.get('operation')!r}")
        if not isinstance(stmt.get("fields"), dict):
            raise CFGRejected("E_CFG_SHAPE: statement fields must be a mapping")
    return stmts


class _Builder:
    def __init__(self, name: str):
        self.name = name
        self.blocks: list[dict] = []
        self.unreachable_source: list[dict] = []
        self.entry = self._block()

    def _block(self) -> str:
        if len(self.blocks) >= MAX_BLOCKS_PER_FUNCTION:
            raise CFGRejected("E_CFG_LIMIT: too many basic blocks")
        ident = f"b{len(self.blocks):04d}"
        self.blocks.append({"id": ident, "instructions": [], "terminator": None})
        return ident

    def _get(self, ident: str) -> dict:
        return self.blocks[int(ident[1:])]

    def _instruction(self, ident: str, operation: str, fields: dict,
                     span: dict | None, unsafe_depth: int) -> None:
        block = self._get(ident)
        if block["terminator"] is not None:
            raise CFGRejected("E_CFG_TERMINATED: instruction after terminator")
        block["instructions"].append({"operation": operation, "fields": fields,
                                      "span": span, "unsafe_depth": unsafe_depth})

    def _end(self, ident: str, terminator: dict) -> None:
        block = self._get(ident)
        if block["terminator"] is not None:
            raise CFGRejected("E_CFG_TERMINATED: duplicate terminator")
        block["terminator"] = terminator

    def _goto(self, origin: str | None, target: str) -> None:
        if origin is not None:
            self._end(origin, {"kind": "goto", "target": target})

    def _sequence(self, stmts: object, current: str | None, *, depth: int = 0,
                  unsafe_depth: int = 0) -> str | None:
        if depth > MAX_NESTING:
            raise CFGRejected("E_CFG_LIMIT: control nesting exceeded")
        for stmt in _require_statements(stmts):
            kind, fields, span = stmt["operation"], stmt["fields"], stmt.get("span")
            if current is None:
                self.unreachable_source.append({"statement": stmt, "reason": "no_fallthrough_path"})
                continue
            if kind in _SIMPLE:
                for key in ("expr", "target"):
                    if key in fields and fields[key] is not None:
                        _require_expr(fields[key], key)
                self._instruction(current, kind, fields, span, unsafe_depth)
            elif kind == "return":
                value = fields.get("expr")
                if value is not None:
                    _require_expr(value, "return")
                self._end(current, {"kind": "return", "value": value, "span": span,
                                    "unsafe_depth": unsafe_depth})
                current = None
            elif kind == "unsafe":
                self._instruction(current, "unsafe_scope", {"enter": True}, span, unsafe_depth)
                current = self._sequence(fields.get("body"), current, depth=depth+1,
                                         unsafe_depth=unsafe_depth+1)
                if current is not None:
                    self._instruction(current, "unsafe_scope", {"enter": False}, span, unsafe_depth)
            elif kind == "if":
                cond = _require_expr(fields.get("condition"), "if condition")
                if cond["result_type"].get("type") != "bool":
                    raise CFGRejected("E_CFG_CONDITION: if condition must be bool")
                then_id, else_id = self._block(), self._block()
                self._end(current, {"kind": "branch", "condition": cond, "then": then_id,
                                    "else": else_id, "span": span, "unsafe_depth": unsafe_depth})
                then_out = self._sequence(fields.get("then"), then_id, depth=depth+1,
                                          unsafe_depth=unsafe_depth)
                else_out = self._sequence(fields.get("else"), else_id, depth=depth+1,
                                          unsafe_depth=unsafe_depth)
                if then_out is None and else_out is None:
                    current = None
                else:
                    join = self._block()
                    self._goto(then_out, join)
                    self._goto(else_out, join)
                    current = join
            elif kind == "while":
                cond = _require_expr(fields.get("condition"), "while condition")
                if cond["result_type"].get("type") != "bool":
                    raise CFGRejected("E_CFG_CONDITION: while condition must be bool")
                header, body, after = self._block(), self._block(), self._block()
                self._goto(current, header)
                self._end(header, {"kind": "branch", "condition": cond, "then": body,
                                   "else": after, "span": span, "unsafe_depth": unsafe_depth})
                body_out = self._sequence(fields.get("body"), body, depth=depth+1,
                                          unsafe_depth=unsafe_depth)
                self._goto(body_out, header)
                current = after
            elif kind == "for":
                start = _require_expr(fields.get("start"), "range start")
                end = _require_expr(fields.get("end"), "range end")
                name = fields.get("name")
                if not isinstance(name, str) or not name:
                    raise CFGRejected("E_CFG_SHAPE: range iterator needs a name")
                # Abstract operation retains one-time left-to-right evaluation
                # of bounds; it is not machine lowering or an SSA phi node.
                self._instruction(current, "range_init", {"name": name, "start": start, "end": end,
                                                          "evaluation_order": ["start", "end"],
                                                          "exclusive_end": True}, span, unsafe_depth)
                header, body, after = self._block(), self._block(), self._block()
                self._goto(current, header)
                self._end(header, {"kind": "range_next", "name": name, "body": body,
                                   "exit": after, "span": span, "unsafe_depth": unsafe_depth})
                body_out = self._sequence(fields.get("body"), body, depth=depth+1,
                                          unsafe_depth=unsafe_depth)
                self._goto(body_out, header)
                current = after
            elif kind == "match":
                value = _require_expr(fields.get("expr"), "match scrutinee")
                arms = fields.get("arms")
                if not isinstance(arms, list) or not arms:
                    raise CFGRejected("E_CFG_SHAPE: match arms are required")
                edges: list[dict] = []
                tails: list[str] = []
                for arm in arms:
                    if not isinstance(arm, dict) or arm.get("node") != "match_arm":
                        raise CFGRejected("E_CFG_SHAPE: expected match_arm")
                    pattern = arm.get("pattern")
                    if not isinstance(pattern, dict) or pattern.get("node") != "pattern":
                        raise CFGRejected("E_CFG_SHAPE: missing match pattern")
                    arm_id = self._block()
                    edges.append({"pattern": pattern, "target": arm_id})
                    self._instruction(arm_id, "match_bind", {"pattern": pattern},
                                      arm.get("span"), unsafe_depth)
                    tail = self._sequence(arm.get("body"), arm_id, depth=depth+1,
                                          unsafe_depth=unsafe_depth)
                    if tail is not None:
                        tails.append(tail)
                self._end(current, {"kind": "switch", "scrutinee": value, "arms": edges,
                                    "span": span, "unsafe_depth": unsafe_depth})
                if tails:
                    join = self._block()
                    for tail in tails:
                        self._goto(tail, join)
                    current = join
                else:
                    current = None
        return current

    def build(self, function: dict) -> dict:
        final = self._sequence(function["body"], self.entry)
        if final is not None:
            # A checked Unit function may fall off the end; typing belongs to
            # the existing checker rather than this inspection-only pass.
            self._end(final, {"kind": "fallthrough", "return_type": function["return_type"]})
        ids = {block["id"] for block in self.blocks}
        edges = []
        for block in self.blocks:
            term = block["terminator"]
            if term is None:
                raise CFGRejected("E_CFG_INCOMPLETE: basic block lacks terminator")
            kind = term["kind"]
            targets = ({"goto": lambda t: [t["target"]],
                        "branch": lambda t: [t["then"], t["else"]],
                        "range_next": lambda t: [t["body"], t["exit"]],
                        "switch": lambda t: [arm["target"] for arm in t["arms"]],
                        "return": lambda t: [], "fallthrough": lambda t: []})[kind](term)
            for dest in targets:
                if dest not in ids:
                    raise CFGRejected("E_CFG_EDGE: dangling CFG successor")
                edges.append({"from": block["id"], "to": dest})
        return {"name": function["name"], "entry": self.entry, "blocks": self.blocks,
                "edges": edges, "unreachable_source": self.unreachable_source,
                "declared_effects": function["declared_effects"],
                "inferred_transitive_effects": function["inferred_transitive_effects"],
                "resource_contract": function["resource_contract"],
                "param_types": function["param_types"], "return_type": function["return_type"],
                "direction": function["direction"], "abi": function["abi"]}


def lower_hsir_cfg(snapshot: HSIRSnapshot) -> CFGSnapshot:
    """Extract typed CFG edges from an existing HSIR snapshot.

    Checksums detect changes; they do not attest a trusted compiler run.
    """
    if not isinstance(snapshot, HSIRSnapshot) or snapshot.schema != SCALAR_HSIR_SCHEMA:
        raise CFGRejected("E_CFG_INPUT: requires the versioned scalar HSIR snapshot")
    if sha256(snapshot.canonical_json.encode("utf-8")).hexdigest() != snapshot.sha256:
        raise CFGRejected("E_CFG_INPUT: HSIR snapshot digest mismatch")
    # Validation is structural as well as content-hash-bound. A directly
    # constructed HSIRSnapshot is not authority to omit new effects/fields.
    data = snapshot.as_dict()
    if data.get("schema") != snapshot.schema or data.get("status") != "checked_frontend_snapshot_not_proved":
        raise CFGRejected("E_CFG_INPUT: unexpected HSIR schema/status")
    if not isinstance(data.get("functions"), list):
        raise CFGRejected("E_CFG_SHAPE: functions must be a list")
    functions = []
    for function in data["functions"]:
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
            raise CFGRejected("E_CFG_SHAPE: malformed function")
        if function.get("body") is None:
            if function.get("direction") != "extern":
                raise CFGRejected("E_CFG_FUNCTION: missing implemented body")
            continue
        functions.append(_Builder(function["name"]).build(function))
    payload = {"schema": "hepta.cfg.v0", "status": "structural_cfg_only_not_proved",
               "source_hsir_sha256": snapshot.sha256,
               "source_sha256": data.get("source_sha256"), "functions": functions,
               "external_assumptions": data.get("external_assumptions", []),
               "claims": {"typed_hsir_input_required": True, "structural_cfg_edges_checked": True,
                          "ssa_constructed": False, "borrow_lifetimes_proved": False,
                          "pointer_provenance_proved": False,
                          "backend_semantics_refined": False,
                          "native_code_validated_by_cfg": False}}
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                           allow_nan=False, separators=(",", ":"))
    return CFGSnapshot("hepta.cfg.v0", canonical, sha256(canonical.encode("utf-8")).hexdigest())


def lower_checked_cfg(program, checked) -> CFGSnapshot:
    """Lower after the existing checker; native validation is separate."""
    return lower_hsir_cfg(lower_checked_program(program, checked))
