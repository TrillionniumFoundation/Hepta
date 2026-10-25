"""Experimental P6 HSIR v0 -> LLVM IR for a closed 32-bit scalar profile.

Unlike routing through Rust or C, this lowers a checked semantic snapshot
straight to LLVM IR. It accepts no pointer, FFI, alloc, unsafe, task or generic
operations. Input hashes identify bytes but are NOT signatures/proofs that the
snapshot came from a sound compiler. The source-to-HSIR and backend-refinement
proofs are explicitly open. A real Clang/LLVM compiler validates produced IR.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


class LLVMScalarRejected(ValueError):
    pass


@dataclass(frozen=True)
class ScalarIR:
    text: str
    sha256: str
    functions: tuple[str, ...]
    profile: str = "hepta.llvm-scalar-i32.v0"


_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_OPERATORS = {"+": "sadd", "-": "ssub", "*": "smul"}
_INTRINSICS = tuple("llvm." + kind + ".with.overflow.i32" for kind in _OPERATORS.values())


def _type_i32(value):
    return isinstance(value, dict) and value.get("type") == "i32" and value.get("args", []) == [] and value.get("length") is None


def _load_checked_snapshot(snapshot):
    if isinstance(snapshot, dict):
        obj = dict(snapshot)
    elif hasattr(snapshot, "as_dict") and callable(snapshot.as_dict):
        obj = snapshot.as_dict()
    else:
        raise LLVMScalarRejected("E_LLVM_SNAPSHOT: checked HSIR snapshot required")
    supplied = obj.pop("sha256", None)
    if not isinstance(supplied, str):
        raise LLVMScalarRejected("E_LLVM_SNAPSHOT: missing SHA-256")
    try:
        canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise LLVMScalarRejected("E_LLVM_SNAPSHOT: noncanonical payload") from exc
    if sha256(canonical.encode()).hexdigest() != supplied:
        raise LLVMScalarRejected("E_LLVM_SNAPSHOT: stale or altered semantic snapshot")
    if obj.get("schema") != "hepta.hsir.v0" or obj.get("status") != "checked_frontend_snapshot_not_proved":
        raise LLVMScalarRejected("E_LLVM_PROFILE: HSIR v0 checked-frontend marker required")
    if obj.get("structs") or obj.get("enums") or obj.get("imports") or obj.get("external_assumptions"):
        raise LLVMScalarRejected("E_LLVM_PROFILE: aggregate/import/foreign assumptions unsupported")
    return obj


class _Function:
    def __init__(self, name, params):
        self.name = name
        self.vars = {v["name"]: f"%arg{i}" for i, v in enumerate(params)}
        self.lines = []
        self.seq = 0
        self.depth = 0
        self.requires_panic = False

    def _temp(self):
        self.seq += 1
        return f"%t{self.seq}"

    def _emit_checked(self, kind: str, left: str, right: str):
        # Checked integer operations trap at runtime. Their caller's effect
        # contract must acknowledge this even for syntactically valid HSIR.
        self.requires_panic = True
        pair = self._temp()
        value = self._temp()
        overflow = self._temp()
        ok = f"ok_{self.seq}"
        fail = f"overflow_{self.seq}"
        self.lines.extend([
            f"  {pair} = call {{ i32, i1 }} @llvm.{kind}.with.overflow.i32(i32 {left}, i32 {right})",
            f"  {value} = extractvalue {{ i32, i1 }} {pair}, 0",
            f"  {overflow} = extractvalue {{ i32, i1 }} {pair}, 1",
            f"  br i1 {overflow}, label %{fail}, label %{ok}",
            f"{fail}:", "  call void @abort()", "  unreachable", f"{ok}:",
        ])
        return value

    def expr(self, expr):
        self.depth += 1
        try:
            if self.depth > 64:
                raise LLVMScalarRejected("E_LLVM_DEPTH: expression depth exceeded")
            return self._expr(expr)
        finally:
            self.depth -= 1

    def _expr(self, expr):
        if not isinstance(expr, dict) or expr.get("node") != "expr" or not _type_i32(expr.get("result_type")):
            raise LLVMScalarRejected("E_LLVM_TYPE: only checked i32 expressions supported")
        op = expr.get("operation")
        args = expr.get("operands", [])
        if op == "int" and not args:
            value = expr.get("value")
            if type(value) is not int or value < -(2**31) or value > 2**31-1:
                raise LLVMScalarRejected("E_LLVM_LITERAL: i32 constant out of range")
            return str(value)
        if op == "name" and not args:
            value = expr.get("value")
            if value not in self.vars:
                raise LLVMScalarRejected("E_LLVM_NAME: undeclared scalar variable")
            return self.vars[value]
        if op == "binary" and expr.get("value") in _OPERATORS and len(args) == 2:
            left, right = self.expr(args[0]), self.expr(args[1])
            return self._emit_checked(_OPERATORS[expr["value"]], left, right)
        if op == "unary" and expr.get("value") in {"+", "-"} and len(args) == 1:
            value = self.expr(args[0])
            return value if expr["value"] == "+" else self._emit_checked("ssub", "0", value)
        if op == "call" and expr.get("value") in {"wrapping_add", "wrapping_sub", "wrapping_mul"} and len(args) == 2:
            left, right = self.expr(args[0]), self.expr(args[1])
            result = self._temp()
            opcode = {"wrapping_add": "add", "wrapping_sub": "sub", "wrapping_mul": "mul"}[expr["value"]]
            self.lines.append(f"  {result} = {opcode} i32 {left}, {right}")
            return result
        raise LLVMScalarRejected("E_LLVM_EXPR: unsupported scalar operation " + str(op))

    def bool_expr(self, expr):
        if (not isinstance(expr, dict) or expr.get("node") != "expr"
                or not isinstance(expr.get("result_type"), dict)
                or expr["result_type"] != {"type": "bool", "args": [], "length": None}):
            raise LLVMScalarRejected("E_LLVM_CONDITION: checked bool expression required")
        op, args = expr.get("operation"), expr.get("operands", [])
        if op == "bool" and args == [] and type(expr.get("value")) is bool:
            return "true" if expr["value"] else "false"
        if op != "binary" or len(args) != 2:
            raise LLVMScalarRejected("E_LLVM_CONDITION: unsupported boolean expression")
        predicate = {"==": "eq", "!=": "ne", "<": "slt", "<=": "sle",
                     ">": "sgt", ">=": "sge"}.get(expr.get("value"))
        if predicate is None:
            raise LLVMScalarRejected("E_LLVM_CONDITION: only i32 comparisons supported")
        left, right = self.expr(args[0]), self.expr(args[1])
        result = self._temp()
        self.lines.append(f"  {result} = icmp {predicate} i32 {left}, {right}")
        return result

    def _return(self, stmt):
        if not isinstance(stmt, dict) or stmt.get("node") != "stmt" or stmt.get("operation") != "return":
            raise LLVMScalarRejected("E_LLVM_STMT: only explicit return arms supported")
        fields = stmt.get("fields")
        if not isinstance(fields, dict) or set(fields) != {"expr"}:
            raise LLVMScalarRejected("E_LLVM_STMT: return shape not accepted")
        value = self.expr(fields["expr"])
        self.lines.append(f"  ret i32 {value}")

    def build(self, body):
        if not isinstance(body, list) or len(body) != 1:
            raise LLVMScalarRejected("E_LLVM_STMT: exactly one root statement required")
        stmt = body[0]
        if not isinstance(stmt, dict) or stmt.get("node") != "stmt":
            raise LLVMScalarRejected("E_LLVM_STMT: checked statement required")
        if stmt.get("operation") == "return":
            self._return(stmt)
        elif stmt.get("operation") == "if":
            fields = stmt.get("fields", {})
            if not isinstance(fields, dict) or set(fields) != {"condition", "then", "else"}:
                raise LLVMScalarRejected("E_LLVM_STMT: if must have explicit then/else arms")
            then_arm, else_arm = fields["then"], fields["else"]
            if (not isinstance(then_arm, list) or len(then_arm) != 1
                    or not isinstance(else_arm, list) or len(else_arm) != 1):
                raise LLVMScalarRejected("E_LLVM_STMT: each if branch must return once")
            condition = self.bool_expr(fields["condition"])
            label = self._temp().removeprefix("%")
            self.lines.append(f"  br i1 {condition}, label %then_{label}, label %else_{label}")
            self.lines.append(f"then_{label}:")
            self._return(then_arm[0])
            self.lines.append(f"else_{label}:")
            self._return(else_arm[0])
        else:
            raise LLVMScalarRejected("E_LLVM_STMT: unsupported root statement")
        return self.lines


def emit_scalar_llvm(snapshot) -> ScalarIR:
    """Compile explicit HSIR i32 pure-C exports; refuse all other semantics."""
    data = _load_checked_snapshot(snapshot)
    funcs = data.get("functions")
    if not isinstance(funcs, list) or not funcs:
        raise LLVMScalarRejected("E_LLVM_PROFILE: no export functions")
    names = set()
    lines = ["; Hepta HSIR scalar LLVM prototype; NOT full language refinement",
             "declare void @abort() noreturn"]
    for intrinsic in _INTRINSICS:
        lines.append(f"declare {{ i32, i1 }} @{intrinsic}(i32, i32)")
    for fn in funcs:
        if not isinstance(fn, dict) or fn.get("direction") != "export" or fn.get("abi") != "C":
            raise LLVMScalarRejected("E_LLVM_PROFILE: export C functions only")
        name = fn.get("name")
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name.startswith("_") or name in names or name == "abort":
            raise LLVMScalarRejected("E_LLVM_SYMBOL: invalid or duplicate symbol")
        names.add(name)
        if not _type_i32(fn.get("return_type")) or fn.get("type_parameters"):
            raise LLVMScalarRejected("E_LLVM_TYPE: nongeneric i32 returns only")
        if set(fn.get("declared_effects", [])) - {"panic"} or set(fn.get("inferred_transitive_effects", [])) - {"panic"}:
            raise LLVMScalarRejected("E_LLVM_EFFECT: unsafe, ffi, alloc, io or other effects refused")
        resource = fn.get("resource_contract", {})
        if resource not in ({}, {"heap_allocations": 0, "may_block": False, "may_suspend": False, "may_spawn": False}):
            raise LLVMScalarRejected("E_LLVM_RESOURCE: unsupported resource contract")
        params = fn.get("param_types")
        if not isinstance(params, list) or len(params) > 16:
            raise LLVMScalarRejected("E_LLVM_TYPE: too many parameters")
        observed = set()
        for p in params:
            if (not isinstance(p, dict) or not _type_i32(p.get("type")) or p.get("ownership") != "value"
                    or not isinstance(p.get("name"), str) or not _NAME.fullmatch(p["name"]) or p["name"] in observed):
                raise LLVMScalarRejected("E_LLVM_TYPE: unsupported scalar parameter")
            observed.add(p["name"])
        arguments = ", ".join(f"i32 %arg{i}" for i in range(len(params)))
        emitter = _Function(name, params)
        statements = emitter.build(fn.get("body"))
        if emitter.requires_panic and ("panic" not in fn.get("declared_effects", [])
                                       or "panic" not in fn.get("inferred_transitive_effects", [])):
            raise LLVMScalarRejected("E_LLVM_EFFECT: checked arithmetic requires a declared and inferred panic effect")
        lines.extend([f"define i32 @{name}({arguments}) {{", "entry:", *statements, "}"])
    output = "\n".join(lines) + "\n"
    return ScalarIR(output, sha256(output.encode()).hexdigest(), tuple(sorted(names)))


def compile_scalar_llvm(ir: ScalarIR, *, clang: str = "clang", output: str | Path) -> dict:
    """Compile host object via real LLVM/Clang. Never call rustc or C frontend."""
    if not isinstance(ir, ScalarIR) or ir.profile != "hepta.llvm-scalar-i32.v0":
        raise LLVMScalarRejected("E_LLVM_IR_IDENTITY: unsupported scalar IR profile")
    if (not isinstance(ir.text, str) or not isinstance(ir.sha256, str)
            or sha256(ir.text.encode("utf-8")).hexdigest() != ir.sha256):
        raise LLVMScalarRejected("E_LLVM_IR_IDENTITY: modified LLVM IR rejected")
    clang_path = shutil.which(clang)
    if not clang_path:
        raise LLVMScalarRejected("E_LLVM_TOOLCHAIN: clang is unavailable")
    compiler = Path(clang_path).resolve()
    version = subprocess.run([str(compiler), "--version"], capture_output=True,
                             text=True, timeout=10, check=False)
    if version.returncode or not version.stdout.strip():
        raise LLVMScalarRejected("E_LLVM_TOOLCHAIN: compiler identity unavailable")
    target = Path(output).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    # Staging on the destination filesystem makes the final link atomic even
    # when the caller requests output on a different mount than /tmp.
    with tempfile.TemporaryDirectory(prefix=".hepta-llvm-scalar-", dir=target.parent) as directory:
        source = Path(directory) / "module.ll"
        obj = Path(directory) / "module.o"
        built = Path(directory) / "candidate.so"
        source.write_text(ir.text, encoding="utf-8")
        cmds = [[str(compiler), "-x", "ir", "-O3", "-fPIC", "-c", str(source), "-o", str(obj)],
                [str(compiler), "-shared", str(obj), "-o", str(built)]]
        for cmd in cmds:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
            if proc.returncode:
                raise LLVMScalarRejected("E_LLVM_NATIVE: " + proc.stderr[:1600])
        if not built.is_file() or not built.stat().st_size:
            raise LLVMScalarRejected("E_LLVM_ARTIFACT: no native output")
        if target.exists():
            raise LLVMScalarRejected("E_LLVM_OUTPUT: refusing to overwrite")
        # Atomic hardlink publishes a completed nonempty output or fails.
        from os import link
        link(built, target)
    return {"status": "native_host_compiled_unqualified", "schema": "hepta.llvm-scalar.v0",
            "functions": list(ir.functions), "llvm_ir_sha256": ir.sha256,
            "native_sha256": sha256(target.read_bytes()).hexdigest(),
            "native_bytes": target.stat().st_size, "output": str(target),
            "toolchain": {"version": version.stdout.splitlines()[0],
                          "compiler_sha256": sha256(compiler.read_bytes()).hexdigest()},
            "claims": {"rustc_used": False, "llvm_ir_executed": False,
                       "backend_semantics_proved": False, "whole_p6_gate_closed": False}}
