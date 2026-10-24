"""Source-bound descriptive CFG of *frontend checked* Hepta (not a verified MIR).

Fail closed on unknown statements, missing expression types, unreachable source,
unresolved control-flow edges, and resource limits. Loop/match instructions
remain structured; no optimizer or borrow-soundness claims are implied.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .ast import Program, Stmt
from .semantic_ir import _Encoder, _span, _stable_json

SCHEMA = "hepta.cfg.v0"
MAX_BLOCKS = 4096
MAX_OPERATIONS = 16384


class FlowLowerError(ValueError):
    """The source is outside the current descriptive CFG profile."""


class _Builder:
    def __init__(self, types: dict[int, Any]):
        self.encoder = _Encoder(types, [])
        self.blocks: list[dict[str, Any]] = []
        self.operations = 0

    def new(self) -> str:
        if len(self.blocks) >= MAX_BLOCKS:
            raise FlowLowerError("CFG block limit exceeded")
        ident = f"bb{len(self.blocks)}"
        self.blocks.append({"id": ident, "operations": [], "terminator": None})
        return ident

    def block(self, ident: str) -> dict[str, Any]:
        return self.blocks[int(ident[2:])]

    def op(self, at: str, kind: str, payload: Any, span: Any,
           depth: int) -> None:
        if self.operations >= MAX_OPERATIONS:
            raise FlowLowerError("CFG operation limit exceeded")
        if self.block(at)["terminator"] is not None:
            raise FlowLowerError("Operation after terminator")
        self.operations += 1
        self.block(at)["operations"].append({
            "kind": kind, "payload": self.encoder.value(payload),
            "span": _span(span), "unsafe_depth": depth,
        })

    def term(self, at: str, value: dict[str, Any]) -> None:
        b = self.block(at)
        if b["terminator"] is not None:
            raise FlowLowerError("Duplicate block terminator")
        b["terminator"] = value

    def go(self, at: str | None, to: str) -> None:
        if at is not None:
            self.term(at, {"kind": "goto", "target": to})

    def sequence(self, statements: list[Stmt], current: str | None,
                 depth: int = 0) -> str | None:
        for stmt in statements:
            if current is None:
                raise FlowLowerError(
                    f"Unreachable statement at {stmt.span.path}:"
                    f"{stmt.span.line}:{stmt.span.column}")
            d = stmt.data
            if stmt.kind in {"let", "assign", "expr"}:
                self.op(current, stmt.kind, d, stmt.span, depth)
            elif stmt.kind == "return":
                self.term(current, {
                    "kind": "return", "value": self.encoder.value(d["expr"]),
                    "span": _span(stmt.span), "unsafe_depth": depth,
                    "implicit": False,
                })
                current = None
            elif stmt.kind == "if":
                yes, no = self.new(), self.new()
                self.term(current, {
                    "kind": "branch",
                    "condition": self.encoder.value(d["condition"]),
                    "then": yes, "else": no, "span": _span(stmt.span),
                    "unsafe_depth": depth,
                })
                yes_end = self.sequence(d["then"], yes, depth)
                no_end = self.sequence(d["else"], no, depth)
                if yes_end is None and no_end is None:
                    current = None
                else:
                    current = self.new()
                    self.go(yes_end, current)
                    self.go(no_end, current)
            elif stmt.kind == "while":
                cond, body, done = self.new(), self.new(), self.new()
                self.go(current, cond)
                self.term(cond, {
                    "kind": "branch",
                    "condition": self.encoder.value(d["condition"]),
                    "then": body, "else": done, "span": _span(stmt.span),
                    "unsafe_depth": depth,
                })
                self.go(self.sequence(d["body"], body, depth), cond)
                current = done
            elif stmt.kind == "for":
                head, body, done = self.new(), self.new(), self.new()
                self.go(current, head)
                self.term(head, {
                    "kind": "structured_for_range", "variable": d["name"],
                    "start": self.encoder.value(d["start"]),
                    "end": self.encoder.value(d["end"]),
                    "body": body, "exit": done, "span": _span(stmt.span),
                    "unsafe_depth": depth, "iteration_semantics_lowered": False,
                })
                self.go(self.sequence(d["body"], body, depth), head)
                current = done
            elif stmt.kind == "match":
                arms = d["arms"]
                if not arms:
                    raise FlowLowerError("Empty match")
                entries = [self.new() for _ in arms]
                self.term(current, {
                    "kind": "structured_match",
                    "scrutinee": self.encoder.value(d["expr"]),
                    "arms": [{"enum": arm.pattern.enum_name,
                              "variant": arm.pattern.variant,
                              "bindings": list(arm.pattern.bindings),
                              "target": entry,
                              "span": _span(arm.pattern.span)}
                             for arm, entry in zip(arms, entries)],
                    "default": None, "span": _span(stmt.span),
                    "unsafe_depth": depth,
                    "exhaustiveness_assumed_from_frontend": True,
                })
                ends = [self.sequence(arm.body, entry, depth)
                        for arm, entry in zip(arms, entries)]
                if all(end is None for end in ends):
                    current = None
                else:
                    current = self.new()
                    for end in ends:
                        self.go(end, current)
            elif stmt.kind == "unsafe":
                self.op(current, "unsafe_enter", None, stmt.span, depth)
                current = self.sequence(d["body"], current, depth + 1)
                if current is not None:
                    self.op(current, "unsafe_exit", None, stmt.span, depth)
            else:
                raise FlowLowerError(f"Unsupported statement: {stmt.kind}")
        return current

    def validate(self) -> None:
        ids = {b["id"] for b in self.blocks}
        edges = {}
        for b in self.blocks:
            term = b["terminator"]
            if term is None:
                raise FlowLowerError(f"Unterminated block: {b['id']}")
            kind = term["kind"]
            if kind == "return":
                out = []
            elif kind == "goto":
                out = [term["target"]]
            elif kind == "branch":
                out = [term["then"], term["else"]]
            elif kind == "structured_for_range":
                out = [term["body"], term["exit"]]
            elif kind == "structured_match":
                out = [arm["target"] for arm in term["arms"]]
            else:
                raise FlowLowerError(f"Unknown terminator: {kind}")
            if any(target not in ids for target in out):
                raise FlowLowerError("Control-flow edge points outside function")
            edges[b["id"]] = out
        visited = set()
        pending = ["bb0"]
        while pending:
            at = pending.pop()
            if at not in visited:
                visited.add(at)
                pending.extend(edges[at])
        if visited != ids:
            raise FlowLowerError("Unreachable CFG blocks")
        if self.encoder.missing:
            raise FlowLowerError(
                f"{len(self.encoder.missing)} expressions without checked types")


def lower_checked_cfg(program: Program, checked: Any, *,
                      project_sha256: str | None = None) -> dict[str, Any]:
    """Return a deterministic CFG from a checked Program (not a soundness proof).

    The caller must ensure the checker result belongs to the same AST and
    source graph; this function does not independently establish that binding.
    """
    if not checked.ok:
        raise FlowLowerError("Cannot lower a rejected program")
    functions = []
    for fn in program.functions:
        signature = {"params": [{"name": p.name, "mode": p.mode, "type": str(p.type)} for p in fn.params],
                     "returns": str(fn.return_type), "return_mode": getattr(fn, "return_mode", "value")}
        if fn.body is None:
            functions.append({"name": fn.name, "path": fn.span.path,
                              "signature": signature,
                              "external": True, "effects": sorted(
                                  checked.effects.get(fn.name, ())),
                              "graph": None})
            continue
        builder = _Builder(checked.expr_types)
        entry = builder.new()
        end = builder.sequence(fn.body, entry)
        if end is not None:
            if str(fn.return_type) != "Unit":
                raise FlowLowerError(
                    f"Non-Unit function {fn.name} reaches implicit return")
            builder.term(end, {
                "kind": "return", "value": None, "implicit": True,
                "unsafe_depth": 0, "span": _span(fn.body_span),
            })
        builder.validate()
        functions.append({"name": fn.name, "path": fn.span.path,
                          "signature": signature,
                          "external": False, "effects": sorted(
                              checked.effects.get(fn.name, ())),
                          "graph": {"entry": entry, "blocks": builder.blocks}})
    payload = {
        "schema": SCHEMA,
        "profile": "typed_structured_cfg_not_ssa_or_verified_mir",
        "source_sha256": hashlib.sha256(program.source.encode("utf-8")).hexdigest(),
        "project_sha256": project_sha256,
        "functions": functions,
        "claims": {"ssa": False, "borrow_check_independent": False,
                   "machine_lowering_verified": False,
                   "semantic_equivalence_proved": False,
                   "foreign_library_soundness_proved": False},
    }
    payload["sha256"] = hashlib.sha256(_stable_json(payload)).hexdigest()
    return payload
