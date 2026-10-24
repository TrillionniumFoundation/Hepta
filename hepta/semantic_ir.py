"""Canonical, source-bound semantic snapshot of *checked* Hepta syntax.

HSIR v0 is a typed syntax interchange format, NOT an optimizer MIR or a proof
that the checker, backends or foreign functions are sound.  Future lowering
passes may consume it only after they establish and validate their own rules.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from .ast import Expr, MatchArm, Pattern, Program, Span, Stmt, Type

SCHEMA = "hepta.hsir.v0"


def _stable_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _span(span: Span) -> dict[str, Any]:
    return {"path": span.path, "start": span.start, "end": span.end,
            "line": span.line, "column": span.column}


@dataclass
class _Encoder:
    expr_types: dict[int, Type]
    missing: list[dict[str, Any]]

    def value(self, node: Any) -> Any:
        if isinstance(node, Expr):
            typ = self.expr_types.get(id(node))
            if typ is None:
                self.missing.append({"kind": node.kind, "span": _span(node.span)})
            return {"node": "expr", "op": node.kind,
                    "type": str(typ) if typ is not None else None,
                    "value": self.value(node.value),
                    "args": [self.value(child) for child in node.children],
                    "type_args": [str(t) for t in node.type_args],
                    "span": _span(node.span)}
        if isinstance(node, Stmt):
            return {"node": "stmt", "op": node.kind,
                    "data": self.value(node.data), "span": _span(node.span)}
        if isinstance(node, MatchArm):
            return {"node": "match_arm", "pattern": self.value(node.pattern),
                    "body": self.value(node.body), "span": _span(node.span)}
        if isinstance(node, Pattern):
            return {"node": "pattern", "enum": node.enum_name,
                    "variant": node.variant, "bindings": list(node.bindings),
                    "span": _span(node.span)}
        if isinstance(node, Type):
            return {"node": "type", "name": node.name,
                    "args": [self.value(arg) for arg in node.args],
                    "length": node.length}
        if isinstance(node, Span):
            return _span(node)
        if isinstance(node, dict):
            if not all(isinstance(k, str) for k in node):
                raise TypeError("HSIR dictionaries require string keys")
            return {k: self.value(v) for k, v in sorted(node.items())}
        if isinstance(node, (list, tuple)):
            return [self.value(v) for v in node]
        if node is None or isinstance(node, (str, bool, int, float)):
            return node
        raise TypeError(f"HSIR rejects unrecognized syntax value {type(node).__name__}")


def _type_has_raw(typ: Type, nominal_fields: dict[str, tuple[Type, ...]]) -> bool:
    # This is a conservative signature inventory, not a pointer-safety proof.
    # Inspect arguments even for previously expanded nominal declarations:
    # Box<u32> and Box<raw const u8> have the same name but different boundaries.
    pending = [typ]
    expanded = set()
    while pending:
        current = pending.pop()
        if current.name in {"raw_const", "raw_mut"}:
            return True
        pending.extend(current.args)
        if current.name not in expanded:
            expanded.add(current.name)
            pending.extend(nominal_fields.get(current.name, ()))
    return False


def lower_checked_program(program: Program, checked: Any, *, project_sha256: str | None = None) -> dict[str, Any]:
    """Lower only accepted programs into a deterministic, evidence-labelled IR.

    checked must be the result of hepta.checker.check on the *same* AST;
    the caller is responsible for binding both to its source/project identity.
    No unsafe/FFI claim is discharged, and native validation is separate.
    """
    if not checked.ok:
        raise ValueError("Cannot lower a program rejected by Hepta's frontend checker")
    nominal_fields = {s.name: tuple(field.type for field in s.fields)
                      for s in program.structs}
    nominal_fields.update({e.name: tuple(field for variant in e.variants
                                      for field in variant.fields)
                           for e in program.enums})
    enc = _Encoder(checked.expr_types, [])
    functions = []
    external_obligations = []
    for fn in program.functions:
        raw_boundary = any(_type_has_raw(p.type, nominal_fields) for p in fn.params) or _type_has_raw(fn.return_type, nominal_fields)
        if fn.extern_c or raw_boundary or "unsafe" in fn.effects or "ffi" in fn.effects:
            external_obligations.append({"function": fn.name,
                "reasons": [k for k, yes in (("foreign_function", fn.extern_c),
                           ("raw_pointer_signature", raw_boundary),
                           ("unsafe_effect", "unsafe" in fn.effects),
                           ("ffi_effect", "ffi" in fn.effects)) if yes],
                "status": "caller_obligation_not_dischargeable_by_hsir"})
        functions.append({
            "name": fn.name, "path": fn.span.path,
            "declaration_span": _span(fn.span), "body_span": _span(fn.body_span),
            "public": fn.public, "extern_c": fn.extern_c, "export_c": fn.export_c,
            "type_params": list(fn.type_params),
            "params": [{"name": p.name, "mode": p.mode, "type": str(p.type),
                        "span": _span(p.span)} for p in fn.params],
            "returns": str(fn.return_type),
            "declared_effects": sorted(fn.effects),
            "inferred_effects": sorted(checked.effects.get(fn.name, ())),
            "resources": enc.value(fn.resources),
            "body": enc.value(fn.body) if fn.body is not None else None,
        })
    payload = {
        "schema": SCHEMA, "profile": "checked_typed_ast_not_verified_mir",
        "module": program.name, "path": program.path,
        "source_sha256": hashlib.sha256(program.source.encode("utf-8")).hexdigest(),
        "project_sha256": project_sha256,
        "imports": [{"name": imp.name, "alias": imp.alias} for imp in program.imports],
        "structs": [{"name": s.name, "repr_c": s.repr_c,
                     "type_params": list(s.type_params), "public": s.public,
                     "fields": [{"name": p.name, "type": str(p.type)} for p in s.fields]}
                    for s in program.structs],
        "enums": [{"name": e.name, "type_params": list(e.type_params), "public": e.public,
                   "variants": [{"name": v.name, "fields": [str(t) for t in v.fields]}
                                for v in e.variants]} for e in program.enums],
        "functions": functions,
        "untyped_expressions": enc.missing,
        "all_expressions_typed": not enc.missing,
        "external_obligations": external_obligations,
        "foreign_assumptions": enc.value(checked.assumptions),
        "resource_contracts": enc.value(checked.resource_contracts),
        "claims": {"native_borrow_validation": False,
                   "translation_correctness_proved": False,
                   "whole_language_soundness_proved": False,
                   "foreign_contracts_proved": False},
    }
    payload["sha256"] = hashlib.sha256(_stable_json(payload)).hexdigest()
    return payload
