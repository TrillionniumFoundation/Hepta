"""Conservative, deterministic control-flow and scalar SSA *pilot*.

Only lower a checked, effect-restricted scalar subset. This IR is NOT a borrow
checker, verified MIR, executable codegen input, or a translation proof. In
particular, reject FFI, raw pointers, calls, allocations and source-level
resource/borrow operations instead of silently assuming their semantics.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

SCHEMA = "hepta.hmir.cfg-ssa.v0"
SCALARS = {"bool", "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "isize", "usize", "f32", "f64"}
BINARY = {"+", "-", "*", "/", "%", "==", "!=", "<", "<=", ">", ">=", "&", "|", "^", "<<", ">>", "&&", "||"}
UNARY = {"-", "+", "!"}


class HMIRUnsupported(ValueError):
    """Feature intentionally not lowered; never treated as a passed proof."""


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _span(obj: Any) -> dict:
    s = obj.span
    return {"path": s.path, "start": s.start, "end": s.end}


class _CFG:
    def __init__(self, fn: Any, checked: Any):
        self.fn = fn
        self.checked = checked
        self.blocks: list[dict] = []
        self.defs = 0
        self.symbols = {p.name: str(p.type) for p in fn.params}
        self.params = [{"name": p.name, "type": str(p.type), "ssa": f"%arg{i}"} for i, p in enumerate(fn.params)]
        if getattr(fn, "return_mode", "value") != "value":
            raise HMIRUnsupported("returned borrows require lifetime-aware lowering")
        for p in fn.params:
            if p.mode != "value" or str(p.type) not in SCALARS:
                raise HMIRUnsupported(f"parameter {p.name}: only by-value scalar parameters supported")
        if str(fn.return_type) not in SCALARS | {"Unit"}:
            raise HMIRUnsupported("non-scalar return types require ownership-aware lowering")
        if fn.extern_c or fn.export_c or fn.type_params:
            raise HMIRUnsupported("foreign, exported ABI and generic functions are outside this pilot")
        if fn.body is None or set(fn.effects) - {"panic"} or set(checked.effects.get(fn.name, ())) - {"panic"}:
            raise HMIRUnsupported("body and effect profile must be pure scalar with optional panic")
        if fn.resources:
            raise HMIRUnsupported("resource contracts require independent resource proof")

    def block(self) -> int:
        i = len(self.blocks)
        if i >= 512:
            raise HMIRUnsupported("control-flow graph exceeds 512 basic blocks")
        self.blocks.append({"id": f"b{i}", "instructions": [], "terminator": None, "predecessors": []})
        return i

    def expr(self, node: Any) -> dict:
        typ = self.checked.expr_types.get(id(node))
        if typ is None or str(typ) not in SCALARS:
            raise HMIRUnsupported(f"missing or non-scalar expression type at {_span(node)}")
        base = {"type": str(typ), "span": _span(node)}
        if node.kind == "name":
            if node.value not in self.symbols or node.type_args:
                raise HMIRUnsupported("unresolved, generic or nonlocal name")
            return {**base, "op": "read", "symbol": node.value}
        if node.kind in {"int", "float", "bool"}:
            return {**base, "op": "constant", "value": node.value}
        if node.kind in {"binary", "unary"}:
            allowed = BINARY if node.kind == "binary" else UNARY
            if node.value not in allowed:
                raise HMIRUnsupported(f"unsupported {node.kind} operator {node.value}")
            return {**base, "op": node.kind, "operator": node.value,
                    "args": [self.expr(child) for child in node.children]}
        if node.kind == "cast":
            if str(node.value) not in SCALARS:
                raise HMIRUnsupported("cast to non-scalar type")
            return {**base, "op": "cast", "to": str(node.value), "args": [self.expr(node.children[0])]}
        raise HMIRUnsupported(f"expression {node.kind}: ownership, calls, FFI and memory operations not yet lowered")

    def assign(self, block: int, symbol: str, expr: Any, span: Any, *, is_let: bool = False, typ: str | None = None) -> None:
        if is_let:
            if symbol in self.symbols:
                raise HMIRUnsupported("shadowing requires lexical storage identity")
            self.symbols[symbol] = typ or str(self.checked.expr_types.get(id(expr), "?"))
            if self.symbols[symbol] not in SCALARS:
                raise HMIRUnsupported("local must be scalar")
        elif symbol not in self.symbols:
            raise HMIRUnsupported("assignment to unknown local")
        value = self.expr(expr)
        self.defs += 1
        self.blocks[block]["instructions"].append({"op": "define", "symbol": symbol,
            "ssa": f"%v{self.defs}", "type": self.symbols[symbol], "value": value, "span": _span(span)})

    def body(self, statements: list, current: int | None, *, nested: bool = False) -> int | None:
        for stmt in statements:
            if current is None:
                raise HMIRUnsupported("unreachable statement in CFG pilot")
            kind, d = stmt.kind, stmt.data
            if kind == "let":
                if nested:
                    raise HMIRUnsupported("block-scoped locals require lexical storage identity")
                self.assign(current, d["name"], d["expr"], stmt, is_let=True,
                            typ=str(d["type"]) if d.get("type") is not None else None)
            elif kind == "assign":
                if d["target"].kind != "name":
                    raise HMIRUnsupported("nonlocal, array and field assignment need memory SSA")
                self.assign(current, d["target"].value, d["expr"], stmt)
            elif kind == "return":
                value = self.expr(d["expr"]) if d["expr"] is not None else None
                self.blocks[current]["terminator"] = {"op": "return", "value": value}
                current = None
            elif kind == "if":
                yes, no = self.block(), self.block()
                self.blocks[current]["terminator"] = {"op": "branch", "condition": self.expr(d["condition"]),
                                                       "true": f"b{yes}", "false": f"b{no}"}
                ey = self.body(d["then"], yes, nested=True)
                en = self.body(d.get("else", []), no, nested=True)
                if ey is None and en is None:
                    current = None
                else:
                    join = self.block()
                    for end in (ey, en):
                        if end is not None:
                            self.blocks[end]["terminator"] = {"op": "jump", "target": f"b{join}"}
                    current = join
            elif kind == "while":
                header, loop, after = self.block(), self.block(), self.block()
                self.blocks[current]["terminator"] = {"op": "jump", "target": f"b{header}"}
                self.blocks[header]["terminator"] = {"op": "branch", "condition": self.expr(d["condition"]),
                                                     "true": f"b{loop}", "false": f"b{after}"}
                end = self.body(d["body"], loop, nested=True)
                if end is not None:
                    self.blocks[end]["terminator"] = {"op": "jump", "target": f"b{header}"}
                current = after
            else:
                raise HMIRUnsupported(f"statement {kind} requires semantics not in CFG/SSA scalar pilot")
        return current

    def _rename(self, expr: dict | None, env: dict[str, str]) -> dict | None:
        if expr is None:
            return None
        if expr["op"] == "read":
            sym = expr["symbol"]
            if sym not in env:
                raise HMIRUnsupported(f"SSA read of {sym} is not defined on every incoming path")
            return {**expr, "ssa": env[sym]}
        if "args" in expr:
            return {**expr, "args": [self._rename(arg, env) for arg in expr["args"]]}
        return dict(expr)

    def lower(self) -> dict:
        entry = self.block()
        exit_block = self.body(self.fn.body, entry)
        if exit_block is not None:
            if str(self.fn.return_type) != "Unit":
                raise HMIRUnsupported("non-Unit fallthrough is unsupported")
            self.blocks[exit_block]["terminator"] = {"op": "return", "value": None}
        for b in self.blocks:
            term = b["terminator"]
            if term is None:
                raise HMIRUnsupported("unterminated CFG block")
            targets = ([term["target"]] if term["op"] == "jump" else
                       [term["true"], term["false"]] if term["op"] == "branch" else [])
            for target in targets:
                self.blocks[int(target[1:])]["predecessors"].append(b["id"])
        for b in self.blocks:
            b["predecessors"].sort(key=lambda s: int(s[1:]))
            if b["id"] != "b0" and not b["predecessors"]:
                raise HMIRUnsupported("unreachable CFG node")
        env_in: dict[str, dict[str, str]] = {b["id"]: {} for b in self.blocks}
        env_out: dict[str, dict[str, str]] = {b["id"]: {} for b in self.blocks}
        params = {p["name"]: p["ssa"] for p in self.params}
        converged = False
        for _ in range(512 * 4):
            changed = False
            for block in self.blocks:
                bid = block["id"]
                if bid == "b0":
                    incoming = dict(params)
                else:
                    incoming = {}
                    for sym in self.symbols:
                        values = [env_out[pred].get(sym) for pred in block["predecessors"]]
                        known = [value for value in values if value is not None]
                        if known:
                            incoming[sym] = (known[0] if len(set(known)) == 1 else f"%phi_{bid}_{sym}")
                outgoing = dict(incoming)
                for inst in block["instructions"]:
                    outgoing[inst["symbol"]] = inst["ssa"]
                if incoming != env_in[bid] or outgoing != env_out[bid]:
                    env_in[bid], env_out[bid] = incoming, outgoing
                    changed = True
            if not changed:
                converged = True
                break
        if not converged:
            raise HMIRUnsupported("SSA dataflow did not converge")
        # SSA definitions and phi arguments must agree with the COMPLETE predecessor set.
        for block in self.blocks:
            bid = block["id"]
            phi = []
            if bid != "b0":
                for sym in self.symbols:
                    values = [env_out[pred].get(sym) for pred in block["predecessors"]]
                    if any(v is None for v in values):
                        env_in[bid].pop(sym, None)
                        continue
                    if len(set(values)) > 1:
                        phi.append({"op": "phi", "symbol": sym, "ssa": f"%phi_{bid}_{sym}",
                                    "inputs": [{"from": pred, "ssa": value} for pred, value in zip(block["predecessors"], values)]})
            block["phi"] = phi
            env = dict(env_in[bid])
            for inst in block["instructions"]:
                inst["value"] = self._rename(inst["value"], env)
                env[inst["symbol"]] = inst["ssa"]
            term = block["terminator"]
            if term["op"] == "branch":
                term["condition"] = self._rename(term["condition"], env)
            if term["op"] == "return":
                term["value"] = self._rename(term["value"], env)
        return {"name": self.fn.name, "entry": "b0", "parameters": self.params,
                "return_type": str(self.fn.return_type), "blocks": self.blocks,
                "declared_effects": sorted(self.fn.effects),
                "inferred_effects": sorted(self.checked.effects.get(self.fn.name, ())) }


def lower_checked_cfg(program: Any, checked: Any, *, project_sha256: str | None = None) -> dict:
    if not checked.ok:
        raise ValueError("HMIR requires an accepted Hepta program")
    graphs = [_CFG(fn, checked).lower() for fn in program.functions]
    payload = {"schema": SCHEMA, "profile": "scalar_cfg_ssa_pilot_not_backend_input",
               "source_sha256": hashlib.sha256(program.source.encode("utf-8")).hexdigest(),
               "project_sha256": project_sha256, "functions": graphs,
               "claims": {"scalar_cfg_structural_validation": True,
                          "native_borrow_validation": False,
                          "borrow_move_drop_semantics_proved": False,
                          "alias_provenance_proved": False,
                          "lowering_semantics_proved": False,
                          "whole_language_soundness_proved": False}}
    payload["sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    return payload


def hmir_analysis(analysis: Any) -> dict:
    result = {"schema": "hepta.hmir.export.v0", "ok": False,
              "status": analysis.report["status"], "hmir": None,
              "native_validation": analysis.report["checks"].get("rust_borrows_types", "not_run")}
    if not analysis.report["ok"] or analysis.program is None or analysis.checked is None:
        result["diagnostics"] = analysis.report["diagnostics"]
        return result
    try:
        graph = lower_checked_cfg(analysis.program, analysis.checked,
                    project_sha256=(analysis.project.identity if analysis.project else None))
    except HMIRUnsupported as exc:
        result["status"] = "unsupported_hmir_subset"
        result["diagnostics"] = [{"code": "E_HMIR_UNSUPPORTED", "message": str(exc)}]
        return result
    result.update({"ok": True, "hmir": graph})
    return result
