"""Strict i32 SSA/PHI-to-LLVM pilot for branch and while-loop code.

Consumes scalar SSA only after a separate structural verifier. Produces native
LLVM IR with checked signed add/sub/mul and genuine PHI nodes. LLVM compilation
and bounded differential execution are separate qualifications; no claims of
Rust soundness, general C ABI coverage or whole-language backend refinement.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .cfg import CFGSnapshot
from .ssa import SSASnapshot
from .ssa_verify import verify_scalar_ssa
from .llvm_ir_profile import LLVMProfileRejected, validate_scalar_llvm_profile


class LLVMSSARejected(ValueError):
    pass


@dataclass(frozen=True)
class SSA_LLVM_IR:
    text: str
    sha256: str
    functions: tuple[str, ...]
    source_ssa_sha256: str
    verification_sha256: str
    profile: str = "hepta.llvm-ssa-i32.v0"

    def check_identity(self) -> None:
        if (self.profile != "hepta.llvm-ssa-i32.v0" or
                not isinstance(self.text, str) or
                sha256(self.text.encode()).hexdigest() != self.sha256):
            raise LLVMSSARejected("E_LLVM_SSA_IDENTITY: altered or invalid LLVM source")
        found = re.findall(r"(?m)^define i32 @([A-Za-z_][A-Za-z0-9_]*)\(", self.text)
        if not isinstance(self.functions, tuple) or len(set(found)) != len(found) or tuple(sorted(found)) != self.functions:
            raise LLVMSSARejected("E_LLVM_SSA_IDENTITY: function inventory mismatch")
        # A freshly recomputed SHA-256 is NOT an authorization token for LLVM.
        # Reject rehashed arbitrary LLVM text before both host and target codegen.
        try:
            validate_scalar_llvm_profile(self.text, self.functions)
        except LLVMProfileRejected as exc:
            raise LLVMSSARejected("E_LLVM_SSA_PROFILE: " + str(exc)) from exc


_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_VERSION = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)@([0-9]+)\Z")
_CHECKED = {"+": "sadd", "-": "ssub", "*": "smul"}
_COMPARE = {"==": "eq", "!=": "ne", "<": "slt", "<=": "sle", ">": "sgt", ">=": "sge"}
_MAX_OUTPUT = 4 * 1024 * 1024


def _i32(typ):
    return typ == {"type": "i32", "args": [], "length": None}


def _reg(version):
    match = _VERSION.fullmatch(version) if isinstance(version, str) else None
    if match is None:
        raise LLVMSSARejected("E_LLVM_SSA_REF: invalid SSA version")
    return f"%r_{match.group(1)}_{match.group(2)}"


class _BlockEmitter:
    def __init__(self, ident, serial):
        self.ident = ident
        self.active = ident
        self.serial = serial
        self.lines = []
        self.panic_needed = False
        self.depth = 0

    def temp(self):
        self.serial[0] += 1
        return f"%t{self.serial[0]}"

    def checked(self, op, lhs, rhs):
        self.panic_needed = True
        pair, result, overflow = self.temp(), self.temp(), self.temp()
        tag = self.serial[0]
        fail, ok = f"bad_{tag}", f"cont_{tag}"
        self.lines.extend([
            f"  {pair} = call {{ i32, i1 }} @llvm.{op}.with.overflow.i32(i32 {lhs}, i32 {rhs})",
            f"  {result} = extractvalue {{ i32, i1 }} {pair}, 0",
            f"  {overflow} = extractvalue {{ i32, i1 }} {pair}, 1",
            f"  br i1 {overflow}, label %{fail}, label %{ok}",
            f"{fail}:", "  call void @abort()", "  unreachable", f"{ok}:",
        ])
        self.active = ok
        return result

    def expr(self, node):
        self.depth += 1
        try:
            if self.depth > 64 or not isinstance(node, dict) or node.get("node") != "expr":
                raise LLVMSSARejected("E_LLVM_SSA_EXPR: bad expression or depth exceeded")
            kind, args, value = node.get("operation"), node.get("operands"), node.get("value")
            ty = node.get("result_type")
            if not isinstance(args, list):
                raise LLVMSSARejected("E_LLVM_SSA_EXPR: operands required")
            if kind == "int" and not args and _i32(ty):
                if type(value) is not int or value < -(2**31) or value > 2**31-1:
                    raise LLVMSSARejected("E_LLVM_SSA_LITERAL: integer outside i32 range")
                return "i32", str(value)
            if kind == "name" and not args and _i32(ty):
                return "i32", _reg(node.get("ssa_ref"))
            if kind == "bool" and not args and ty == {"type": "bool", "args": [], "length": None} and type(value) is bool:
                return "i1", "true" if value else "false"
            if kind == "binary" and len(args) == 2:
                lty, left = self.expr(args[0])
                rty, right = self.expr(args[1])
                if lty != "i32" or rty != "i32":
                    raise LLVMSSARejected("E_LLVM_SSA_TYPE: binary requires i32 operands")
                if value in _CHECKED and _i32(ty):
                    return "i32", self.checked(_CHECKED[value], left, right)
                if value in _COMPARE and ty == {"type": "bool", "args": [], "length": None}:
                    temp = self.temp()
                    self.lines.append(f"  {temp} = icmp {_COMPARE[value]} i32 {left}, {right}")
                    return "i1", temp
            if kind == "unary" and value == "-" and len(args) == 1 and _i32(ty):
                aty, operand = self.expr(args[0])
                if aty != "i32":
                    raise LLVMSSARejected("E_LLVM_SSA_TYPE: unary minus requires i32")
                return "i32", self.checked("ssub", "0", operand)
            raise LLVMSSARejected(f"E_LLVM_SSA_UNSUPPORTED: expression {kind!r}")
        finally:
            self.depth -= 1

    def build(self, block):
        # Only the checked SSA definitions and references are lowered here.
        for instruction in block["instructions"]:
            ty, val = self.expr(instruction["ssa_value"])
            if "definition" in instruction:
                dst = instruction["definition"]
                if dst.get("type") != "i32" or ty != "i32":
                    raise LLVMSSARejected("E_LLVM_SSA_TYPE: only i32 assignments")
                self.lines.append(f"  {_reg(dst['ssa_name'])} = add i32 0, {val}")
        term = block["terminator"]
        kind = term.get("kind")
        if kind == "goto":
            self.lines.append(f"  br label %{term['target']}")
        elif kind == "branch":
            ty, cond = self.expr(term["condition"])
            if ty != "i1":
                raise LLVMSSARejected("E_LLVM_SSA_CONDITION: expected bool")
            self.lines.append(f"  br i1 {cond}, label %{term['then']}, label %{term['else']}")
        elif kind == "return":
            ty, result = self.expr(term["value"])
            if ty != "i32":
                raise LLVMSSARejected("E_LLVM_SSA_RETURN: expected i32")
            self.lines.append(f"  ret i32 {result}")
        else:
            raise LLVMSSARejected(f"E_LLVM_SSA_TERMINATOR: unsupported {kind!r}")
        return self.active


def emit_scalar_ssa_llvm(ssa: SSASnapshot, cfg: CFGSnapshot) -> SSA_LLVM_IR:
    """Emit checked i32/PHI LLVM IR after verifier validates exact CFG links."""
    verified = verify_scalar_ssa(ssa, cfg)
    s = json.loads(ssa.canonical_json)
    original = json.loads(cfg.canonical_json)
    if original.get("external_assumptions"):
        raise LLVMSSARejected("E_LLVM_SSA_FFI: any foreign contract unsupported")
    if len(s.get("functions", [])) != len(original["functions"]):
        raise LLVMSSARejected("E_LLVM_SSA_FUNCTION: inventory differs")
    if not s["functions"] or len(s["functions"]) > 32:
        raise LLVMSSARejected("E_LLVM_SSA_LIMIT: expected 1..32 functions")
    lines = ["; Hepta strict scalar SSA/PHI native-LLVM pilot, not whole-language qualified.",
             "declare void @abort() noreturn",
             "declare { i32, i1 } @llvm.sadd.with.overflow.i32(i32, i32)",
             "declare { i32, i1 } @llvm.ssub.with.overflow.i32(i32, i32)",
             "declare { i32, i1 } @llvm.smul.with.overflow.i32(i32, i32)", ""]
    names = set()
    for fn, orig in zip(s["functions"], original["functions"]):
        name = fn["name"]
        if (not isinstance(name, str) or not _NAME.fullmatch(name) or name in names or name == "abort"
                or orig.get("direction") != "export" or orig.get("abi") != "C"):
            raise LLVMSSARejected("E_LLVM_SSA_ABI: unique explicitly exported C i32 functions only")
        names.add(name)
        if not _i32(orig.get("return_type")) or any(ty != "i32" for ty in fn["scalar_types"].values()):
            raise LLVMSSARejected("E_LLVM_SSA_TYPE: only i32 locals and return supported")
        if set(orig.get("declared_effects", [])) - {"panic"} or set(orig.get("inferred_transitive_effects", [])) - {"panic"}:
            raise LLVMSSARejected("E_LLVM_SSA_EFFECT: unsupported effect declared or inferred")
        params, orig_params = fn["parameters"], orig.get("param_types", [])
        if len(params) > 16 or len(params) != len(orig_params):
            raise LLVMSSARejected("E_LLVM_SSA_PARAMETERS: unsupported parameter count")
        for p in orig_params:
            if p.get("ownership") != "value" or not _i32(p.get("type")):
                raise LLVMSSARejected("E_LLVM_SSA_PARAMETERS: only by-value i32")
        args = ", ".join("i32 " + _reg(p["ssa_name"]) for p in params)
        lines.append(f"define i32 @{name}({args}) {{")
        serial = [0]
        generated, predecessors = {}, {}
        saw_panic = False
        for block in fn["blocks"]:
            bb = _BlockEmitter(block["id"], serial)
            exit_label = bb.build(block)
            saw_panic |= bb.panic_needed
            generated[block["id"]] = bb.lines
            predecessors[block["id"]] = exit_label
        if saw_panic and "panic" not in orig.get("declared_effects", []):
            raise LLVMSSARejected("E_LLVM_SSA_EFFECT: checked arithmetic must declare panic")
        for block in fn["blocks"]:
            lines.append(block["id"] + ":")
            for phi in block["phis"]:
                result = phi["result"]
                if result.get("type") != "i32":
                    raise LLVMSSARejected("E_LLVM_SSA_PHI: only i32 PHI supported")
                parts = [f"[ {_reg(edge['ssa_ref'])}, %{predecessors[edge['from']]} ]"
                         for edge in phi["incoming"]]
                lines.append(f"  {_reg(result['ssa_name'])} = phi i32 " + ", ".join(parts))
            lines.extend(generated[block["id"]])
        lines.extend(["}", ""])
    text = "\n".join(lines) + "\n"
    if len(text.encode()) > _MAX_OUTPUT:
        raise LLVMSSARejected("E_LLVM_SSA_LIMIT: generated LLVM source exceeds budget")
    output = SSA_LLVM_IR(text, sha256(text.encode()).hexdigest(), tuple(sorted(names)),
                         ssa.sha256, verified.sha256)
    output.check_identity()
    return output


def compile_scalar_ssa_llvm(ir: SSA_LLVM_IR, *, clang: str = "clang", output: str | Path) -> dict:
    """Compile a host shared-library only; link != ABI qualification or proof."""
    ir.check_identity()
    binary = shutil.which(clang)
    if binary is None:
        raise LLVMSSARejected("E_LLVM_SSA_TOOLCHAIN: native Clang unavailable")
    compiler = Path(binary).resolve()
    version = subprocess.run([str(compiler), "--version"], capture_output=True, text=True, timeout=10)
    if version.returncode or not version.stdout.strip():
        raise LLVMSSARejected("E_LLVM_SSA_TOOLCHAIN: compiler identity unavailable")
    # Do not resolve the output leaf: a dangling symlink could publish
    # the compiled library to a different pathname.
    target = Path(output).absolute()
    if target.is_symlink() or target.exists():
        raise LLVMSSARejected("E_LLVM_SSA_OUTPUT: refusing to overwrite existing artifact")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".hepta-ssa-llvm-", dir=target.parent) as folder:
        path = Path(folder) / "module.ll"
        library = Path(folder) / "module.so"
        path.write_text(ir.text)
        cmd = [str(compiler), "-x", "ir", "-O3", "-fPIC", "-shared", str(path), "-o", str(library)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45, check=False)
        if result.returncode or not library.is_file() or library.stat().st_size == 0:
            raise LLVMSSARejected("E_LLVM_SSA_NATIVE: clang compilation failed: " + result.stderr[:1800])
        if target.is_symlink() or target.exists():
            raise LLVMSSARejected("E_LLVM_SSA_OUTPUT: destination created during build")
        os.link(library, target)
    return {"schema": "hepta.llvm-ssa-host.v0", "status": "native_host_compiled_unqualified",
            "output": str(target), "llvm_ir_sha256": ir.sha256,
            "ssa_sha256": ir.source_ssa_sha256,
            "ssa_verification_sha256": ir.verification_sha256,
            "artifact_sha256": sha256(target.read_bytes()).hexdigest(),
            "artifact_bytes": target.stat().st_size,
            "toolchain": {"version": version.stdout.splitlines()[0],
                          "compiler_sha256": sha256(compiler.read_bytes()).hexdigest()},
            "claims": {"backend_refinement_proven": False, "cross_target_abi_qualified": False,
                       "runtime_execution_qualified": False, "whole_p6_gate_closed": False}}
