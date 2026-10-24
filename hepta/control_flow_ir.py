"""Source-bound, checked-AST control-flow snapshot for Hepta's P1 prototype.

Not an executable MIR, SSA representation, independent borrow checker, or a
translation-correctness proof. This module is deliberately read-only. A backend
MUST NOT consume it as a validated lowering without additional verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from typing import Any

from .ast import Expr, HeptaError, Program, Span, Stmt

SCHEMA = "hepta.hmir.cfg.v0"
EXPORT_SCHEMA = "hepta.hmir.export.v0"


def _span(span: Span) -> dict[str, Any]:
    return {"path": span.path, "start": span.start, "end": span.end,
            "line": span.line, "column": span.column}


def _sha(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                     allow_nan=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _source_value(value: Any) -> Any:
    """Encode only closed, JSON-serializable AST syntax; never stringify objects."""
    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), -float("inf")):
            raise ValueError("HMIR rejects non-finite expression literals")
        return value
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("HMIR requires string keys")
        return {key: _source_value(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_source_value(item) for item in value]
    # Types in cast expressions are typed objects, not raw arbitrary strings.
    from .ast import Type
    if isinstance(value, Type):
        return {"type": str(value)}
    raise ValueError("HMIR rejects unknown expression value type: " +
                     type(value).__name__)


def _syntactic_ownership(expr: Expr) -> list[dict[str, Any]]:
    """Record sites only. A syntax site is not a proved alias/lifetime fact."""
    events: list[dict[str, Any]] = []
    pending = [expr]
    while pending:
        node = pending.pop()
        if node.kind == "unary" and node.value in ("move", "read", "mut"):
            child = node.children[0] if node.children else None
            events.append({
                "operation": {"move": "move", "read": "borrow_shared",
                              "mut": "borrow_exclusive"}[node.value],
                "place": child.value if child is not None and child.kind == "name" else None,
                "span": _span(node.span), "proof": "syntactic_site_only",
            })
        elif node.kind == "call" and node.value == "release":
            events.append({"operation": "explicit_release_call",
                           "place": None, "span": _span(node.span),
                           "proof": "syntactic_site_only"})
        pending.extend(reversed(node.children))
    return events


class _FunctionCFG:
    """Build explicit edges for statements already accepted by the frontend."""

    def __init__(self, checked: Any) -> None:
        self.types = checked.expr_types
        self.blocks: list[dict[str, Any]] = []

    def new_block(self) -> str:
        name = f"b{len(self.blocks)}"
        self.blocks.append({"id": name, "instructions": [], "terminator": None})
        return name

    def block(self, block_id: str) -> dict[str, Any]:
        return self.blocks[int(block_id[1:])]

    def instruction(self, block_id: str, operation: str, span: Span, **fields: Any) -> None:
        self.block(block_id)["instructions"].append({
            "operation": operation, "span": _span(span), **fields,
        })

    def terminate(self, block_id: str, operation: str, span: Span,
                  targets: list[dict[str, str]] | None = None,
                  **fields: Any) -> None:
        block = self.block(block_id)
        if block["terminator"] is not None:
            raise ValueError("HMIR attempted to terminate an already terminated block")
        block["terminator"] = {
            "operation": operation, "span": _span(span),
            "targets": targets if targets is not None else [], **fields,
        }

    def expression(self, expr: Expr | None) -> dict[str, Any] | None:
        if expr is None:
            return None
        # Verify all nested nodes, not just the outermost expression's type.
        stack = [expr]
        while stack:
            node = stack.pop()
            if id(node) not in self.types:
                raise ValueError("HMIR refuses an expression without frontend type evidence")
            stack.extend(reversed(node.children))
        return {
            "kind": expr.kind,
            "value": _source_value(expr.value),
            "type": str(self.types[id(expr)]),
            "span": _span(expr.span),
            "ownership_sites": _syntactic_ownership(expr),
        }

    def sequence(self, statements: list[Stmt], start: str) -> str | None:
        current: str | None = start
        for stmt in statements:
            if current is None:
                raise ValueError("HMIR refuses statements after unconditional termination")
            d = stmt.data
            if stmt.kind == "let":
                self.instruction(current, "let", stmt.span, name=d["name"],
                                 mutable=bool(d["mutable"]),
                                 type=str(d["type"]) if d["type"] is not None else None,
                                 expression=self.expression(d["expr"]))
            elif stmt.kind == "assign":
                self.instruction(current, "assign", stmt.span,
                                 target=self.expression(d["target"]),
                                 expression=self.expression(d["expr"]))
            elif stmt.kind == "expr":
                self.instruction(current, "eval", stmt.span,
                                 expression=self.expression(d["expr"]))
            elif stmt.kind == "return":
                self.terminate(current, "return", stmt.span,
                               expression=self.expression(d["expr"]))
                current = None
            elif stmt.kind == "unsafe":
                self.instruction(current, "unsafe_scope_enter", stmt.span)
                current = self.sequence(d["body"], current)
                if current is not None:
                    self.instruction(current, "unsafe_scope_exit", stmt.span)
            elif stmt.kind == "if":
                true_id, false_id = self.new_block(), self.new_block()
                self.terminate(current, "branch", stmt.span, targets=[
                    {"to": true_id, "role": "true"},
                    {"to": false_id, "role": "false"},
                ], condition=self.expression(d["condition"]))
                true_end = self.sequence(d["then"], true_id)
                false_end = self.sequence(d["else"], false_id)
                live = [end for end in (true_end, false_end) if end is not None]
                if not live:
                    current = None
                else:
                    join = self.new_block()
                    for end in live:
                        self.terminate(end, "jump", stmt.span,
                                       targets=[{"to": join, "role": "join"}])
                    current = join
            elif stmt.kind == "match":
                arms = d["arms"]
                if not arms:
                    raise ValueError("HMIR refuses an empty match")
                targets = []
                created = []
                for arm in arms:
                    target = self.new_block()
                    created.append((target, arm))
                    targets.append({
                        "to": target,
                        "role": arm.pattern.enum_name + "::" + arm.pattern.variant,
                    })
                self.terminate(current, "switch_enum", stmt.span,
                               targets=targets, scrutinee=self.expression(d["expr"]))
                live = []
                for target, arm in created:
                    self.instruction(target, "bind_pattern", arm.pattern.span,
                                     names=list(arm.pattern.bindings),
                                     variant=arm.pattern.enum_name + "::" +
                                     arm.pattern.variant)
                    end = self.sequence(arm.body, target)
                    if end is not None:
                        live.append(end)
                if not live:
                    current = None
                else:
                    join = self.new_block()
                    for end in live:
                        self.terminate(end, "jump", stmt.span,
                                       targets=[{"to": join, "role": "join"}])
                    current = join
            elif stmt.kind == "while":
                header, body, exit_id = (self.new_block(), self.new_block(),
                                         self.new_block())
                self.terminate(current, "jump", stmt.span,
                               targets=[{"to": header, "role": "loop_entry"}])
                self.terminate(header, "branch", stmt.span, targets=[
                    {"to": body, "role": "true"},
                    {"to": exit_id, "role": "false"},
                ], condition=self.expression(d["condition"]))
                tail = self.sequence(d["body"], body)
                if tail is not None:
                    self.terminate(tail, "jump", stmt.span,
                                   targets=[{"to": header, "role": "backedge"}])
                current = exit_id
            elif stmt.kind == "for":
                # This is a *structural* range-loop record, not SSA or executable
                # instruction lowering. Endpoints are evaluated in the preheader.
                self.instruction(current, "range_init", stmt.span, name=d["name"],
                                 start=self.expression(d["start"]),
                                 end=self.expression(d["end"]))
                header, body, exit_id = (self.new_block(), self.new_block(),
                                         self.new_block())
                self.terminate(current, "jump", stmt.span,
                               targets=[{"to": header, "role": "loop_entry"}])
                self.terminate(header, "range_branch", stmt.span, targets=[
                    {"to": body, "role": "next_item"},
                    {"to": exit_id, "role": "exhausted"},
                ], induction=d["name"])
                tail = self.sequence(d["body"], body)
                if tail is not None:
                    self.instruction(tail, "range_advance", stmt.span,
                                     induction=d["name"])
                    self.terminate(tail, "jump", stmt.span,
                                   targets=[{"to": header, "role": "backedge"}])
                current = exit_id
            else:
                raise ValueError("HMIR refuses unsupported statement: " + stmt.kind)
        return current

    def validate_graph(self) -> None:
        names = {block["id"] for block in self.blocks}
        if not names or len(names) != len(self.blocks):
            raise ValueError("HMIR invalid block identifiers")
        reachable, pending = set(), ["b0"]
        while pending:
            bid = pending.pop()
            if bid not in names:
                raise ValueError("HMIR has an edge to a missing block")
            if bid in reachable:
                continue
            reachable.add(bid)
            term = self.block(bid)["terminator"]
            if term is None:
                raise ValueError("HMIR has an unterminated block")
            for target in term["targets"]:
                if target["to"] not in names:
                    raise ValueError("HMIR has an edge to a missing block")
                pending.append(target["to"])
        if reachable != names:
            raise ValueError("HMIR contains unreachable synthetic blocks")

    def lower(self, fn: Any) -> dict[str, Any]:
        if fn.extern_c or fn.body is None:
            return {"name": fn.name, "extern_c": True, "entry": None,
                    "blocks": [], "parameters": [
                        {"name": p.name, "mode": p.mode, "type": str(p.type)}
                        for p in fn.params],
                    "declared_effects": sorted(fn.effects),
                    "inferred_effects": [],
                    "resources": fn.resources}
        entry = self.new_block()
        tail = self.sequence(fn.body, entry)
        if tail is not None:
            if str(fn.return_type) != "Unit":
                # The checker should reject this first; do not synthesize values.
                raise ValueError("HMIR requires a checked return on every live exit")
            self.terminate(tail, "unit_fallthrough", fn.body_span)
        self.validate_graph()
        return {"name": fn.name, "extern_c": False, "entry": entry,
                "blocks": self.blocks,
                "parameters": [
                    {"name": p.name, "mode": p.mode, "type": str(p.type)}
                    for p in fn.params],
                "declared_effects": sorted(fn.effects),
                "resources": fn.resources}


def lower_control_flow_program(program: Program, checked: Any,
                               *, project_sha256: str | None = None) -> dict[str, Any]:
    """Export CFG snapshots only after the existing frontend has accepted input.

    No backend may interpret this as borrow-proved, SSA-verified, or ABI-qualified.
    Caller must bind checked and program to the same project/source snapshot.
    """
    if not checked.ok:
        raise ValueError("HMIR cannot lower rejected Hepta input")
    functions = []
    for fn in program.functions:
        function = _FunctionCFG(checked).lower(fn)
        function["inferred_effects"] = sorted(checked.effects.get(fn.name, set()))
        functions.append(function)
    payload = {
        "schema": SCHEMA,
        "profile": "checked_ast_structural_cfg_not_executable_mir",
        "source_sha256": hashlib.sha256(program.source.encode("utf-8")).hexdigest(),
        "project_sha256": project_sha256,
        "functions": functions,
        "foreign_assumptions": checked.assumptions,
        "claims": {
            "frontend_checked": True,
            "ssa_constructed": False,
            "independent_borrow_validation": False,
            "pointer_provenance_proved": False,
            "automatic_drop_lowering": False,
            "runtime_resource_bounds_proved": False,
            "native_codegen_validated": False,
            "translation_correctness_proved": False,
            "whole_language_soundness_proved": False,
        },
    }
    payload["sha256"] = _sha(payload)
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hepta P1 structural CFG exporter")
    parser.add_argument("source")
    parser.add_argument("--frontend-only", action="store_true",
                        help="Skip native gate; output is NOT native-qualified")
    parser.add_argument("--target")
    parser.add_argument("--locked", action="store_true")
    options = parser.parse_args(argv)
    from .pipeline import analyze_project
    try:
        result = analyze_project(options.source, target=options.target,
                                 locked=options.locked,
                                 native=not options.frontend_only)
        if not result.report["ok"]:
            output = {"schema": EXPORT_SCHEMA, "ok": False,
                      "status": result.report["status"],
                      "validation": result.report, "hmir": None}
        else:
            hmir = lower_control_flow_program(
                result.program, result.checked,
                project_sha256=result.project.identity if result.project else None)
            output = {"schema": EXPORT_SCHEMA, "ok": True,
                      "status": result.report["status"], "hmir": hmir,
                      "native_validation": result.report["checks"].get("rust_borrows_types")}
    except (HeptaError, OSError, UnicodeError, ValueError, TypeError) as exc:
        output = {"schema": EXPORT_SCHEMA, "ok": False, "status": "rejected",
                  "error": str(exc), "hmir": None}
    print(json.dumps(output, sort_keys=True, indent=2, ensure_ascii=False))
    return 0 if output["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
