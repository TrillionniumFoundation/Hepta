"""HSIR v0: a deterministic, *checked* typed semantic snapshot.

The canonical snapshot contains expression types, ownership parameter modes,
resource clauses, function effects and an exact structured source tree. Unlike
passing textual fragments to backends, unsupported values reject explicitly.
This is a bootstrap boundary, not a CFG, SSA, full lifetime/provenance checker,
or proof that either native backend refines this representation.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from .ast import Enum, Expr, Function, Import, MatchArm, Param, Pattern, Program, Span, Stmt, Struct, Type
from .checker import CheckResult


class HSIRRejected(ValueError):
    pass


@dataclass(frozen=True)
class HSIRSnapshot:
    schema: str
    canonical_json: str
    sha256: str

    def as_dict(self) -> dict:
        # Verify the committed identity before exporting a mutable JSON view.
        # This is an integrity check, not evidence of soundness or an attestation.
        if not isinstance(self.canonical_json, str) or not isinstance(self.sha256, str):
            raise HSIRRejected("E_HSIR_SNAPSHOT: malformed snapshot identity")
        if sha256(self.canonical_json.encode("utf-8")).hexdigest() != self.sha256:
            raise HSIRRejected("E_HSIR_SNAPSHOT: snapshot content digest mismatch")
        try:
            payload = json.loads(self.canonical_json)
        except ValueError as exc:
            raise HSIRRejected("E_HSIR_SNAPSHOT: malformed canonical JSON") from exc
        if not isinstance(payload, dict) or payload.get("schema") != self.schema:
            raise HSIRRejected("E_HSIR_SNAPSHOT: unexpected snapshot schema")
        return {**payload, "sha256": self.sha256}


class _Encoder:
    def __init__(self, checked: CheckResult):
        if not checked.ok:
            raise HSIRRejected("E_HSIR_UNCHECKED: Cannot lower a program with checker diagnostics")
        self.checked = checked
        self.expressions = 0

    def value(self, v):
        if v is None or isinstance(v, (bool, int, float, str)):
            return v
        if isinstance(v, Span):
            return {"path": v.path, "start": v.start, "end": v.end, "line": v.line, "column": v.column}
        if isinstance(v, Type):
            return {"type": v.name, "args": [self.value(t) for t in v.args], "length": v.length}
        if isinstance(v, Expr):
            typ = self.checked.expr_types.get(id(v))
            if typ is None:
                raise HSIRRejected("E_HSIR_UNTYPED: Missing checked expression type at " + str(v.span))
            self.expressions += 1
            return {"node": "expr", "operation": v.kind, "result_type": self.value(typ),
                    "value": self.value(v.value), "operands": [self.value(x) for x in v.children],
                    "type_args": [self.value(x) for x in v.type_args], "span": self.value(v.span)}
        if isinstance(v, Stmt):
            return {"node": "stmt", "operation": v.kind,
                    "fields": self.value(v.data), "span": self.value(v.span)}
        if isinstance(v, Pattern):
            return {"node": "pattern", "enum": v.enum_name, "variant": v.variant,
                    "bindings": list(v.bindings), "span": self.value(v.span)}
        if isinstance(v, MatchArm):
            return {"node": "match_arm", "pattern": self.value(v.pattern),
                    "body": self.value(v.body), "span": self.value(v.span)}
        if isinstance(v, list) or isinstance(v, tuple):
            return [self.value(x) for x in v]
        if isinstance(v, set):
            return sorted(self.value(x) for x in v)
        if isinstance(v, dict):
            if not all(isinstance(k, str) for k in v):
                raise HSIRRejected("E_HSIR_KEY: Non-string node metadata keys")
            return {k: self.value(v[k]) for k in sorted(v)}
        raise HSIRRejected("E_HSIR_UNSUPPORTED: Unknown semantic payload " + type(v).__name__)

    def param(self, p: Param) -> dict:
        if p.mode not in {"value", "read", "mut", "take"}:
            raise HSIRRejected("E_HSIR_MODE: Unknown parameter ownership mode")
        return {"name": p.name, "type": self.value(p.type), "ownership": p.mode,
                "span": self.value(p.span)}

    def function(self, f: Function) -> dict:
        if f.body is None and not f.extern_c:
            raise HSIRRejected("E_HSIR_FUNCTION: Nonextern function without body")
        return {"name": f.name, "param_types": [self.param(p) for p in f.params],
                "return_type": self.value(f.return_type), "declared_effects": sorted(f.effects),
                "inferred_transitive_effects": sorted(self.checked.effects.get(f.name, set())),
                "resource_contract": self.value(f.resources), "type_parameters": list(f.type_params),
                "abi": "C" if f.export_c or f.extern_c else "hepta_unstable",
                "direction": "extern" if f.extern_c else "export" if f.export_c else "local",
                "public": f.public, "body": self.value(f.body), "span": self.value(f.span)}

    def structure(self, s: Struct) -> dict:
        return {"name": s.name, "repr": "C" if s.repr_c else "hepta_unstable",
                "type_parameters": list(s.type_params), "public": s.public,
                "fields": [self.param(f) for f in s.fields], "span": self.value(s.span)}

    def enumeration(self, e: Enum) -> dict:
        return {"name": e.name, "type_parameters": list(e.type_params), "public": e.public,
                "variants": [{"name": v.name, "fields": self.value(v.fields),
                              "span": self.value(v.span)} for v in e.variants],
                "span": self.value(e.span)}


def lower_checked_program(program: Program, checked: CheckResult) -> HSIRSnapshot:
    """Create reproducible typed snapshots; native validation remains separate."""
    enc = _Encoder(checked)
    payload = {
        "status": "checked_frontend_snapshot_not_proved", "program": program.name,
        "source_sha256": sha256(program.source.encode("utf-8")).hexdigest(),
        "imports": [{"name": i.name, "alias": i.alias, "span": enc.value(i.span)} for i in program.imports],
        "structs": [enc.structure(s) for s in program.structs],
        "enums": [enc.enumeration(e) for e in program.enums],
        "functions": [enc.function(f) for f in program.functions],
        "external_assumptions": enc.value(checked.assumptions),
        "resource_contracts": enc.value(checked.resource_contracts),
        "claims": {"lifetimes_fully_modeled": False, "pointer_provenance_proved": False,
                   "source_semantics_refined": False, "native_backend_equivalence_proved": False},
    }
    payload["typed_expression_count"] = enc.expressions
    canonical = json.dumps({"schema": "hepta.hsir.v0", **payload}, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return HSIRSnapshot("hepta.hsir.v0", canonical, sha256(canonical.encode("utf-8")).hexdigest())
