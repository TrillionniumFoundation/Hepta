"""Fail-closed, Clang-AST based migration of a deliberately small C11 profile.

This is *not* a general C translator. Every accepted definition is composed of
signed 32-bit value parameters/locals, scalar expressions, returns, and if/else.
C expressions are translated only where their semantics agree on all C-defined
inputs. C signed-overflow / division UB becomes checked Hepta panic; that is a
new behavior on invalid C inputs, not source-level functional equivalence.

Never run Clang on untrusted input outside an OS-level sandbox. The subprocess
limits below bound time/output but are not a security isolation boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass


MAX_SOURCE_BYTES = 256 * 1024
MAX_AST_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
# Reject names that collide with Hepta grammar or runtime types/functions.
RESERVED = frozenset(
    "module import as fn pub extern export struct enum repr effects resources "
    "return if else for while let mut read move take unsafe match true false "
    "bool i32 i64 u32 u64 isize usize f32 f64 Unit Buffer Task TaskGroup "
    "Result main".split()
)
ARITH = frozenset({"+", "-", "*", "/", "%"})
COMPARE = frozenset({"==", "!=", "<", "<=", ">", ">="})
LOGICAL = frozenset({"&&", "||"})


class MigrationRejected(ValueError):
    """Unsupported construct (no partial source is returned)."""


@dataclass(frozen=True)
class Translation:
    source: str
    report: dict


def _reject(node: dict, message: str) -> None:
    loc = node.get("loc", node.get("range", {}).get("begin", {}))
    kind = node.get("kind", "unknown")
    raise MigrationRejected(f"E_C2HEPTA_UNSUPPORTED {kind} at {loc.get('line', '?')}:{loc.get('col', '?')}: {message}")


def _children(node: dict) -> list[dict]:
    return [x for x in node.get("inner", []) if isinstance(x, dict)]


def _one(node: dict) -> dict:
    children = _children(node)
    if len(children) != 1:
        _reject(node, "expected one child")
    return children[0]


def _ident(name: str, node: dict) -> str:
    if not isinstance(name, str) or not IDENTIFIER.fullmatch(name) or name in RESERVED or name.startswith("__"):
        _reject(node, "identifier cannot be represented safely in the bounded Hepta profile")
    return name


class _Function:
    def __init__(self, name: str, params: list[str]) -> None:
        self.name = name
        self.known = set(params)
        self.params = set(params)
        self.locals = set()
        self.depth = 0

    def expr(self, node: dict) -> tuple[str, str]:
        self.depth += 1
        try:
            if self.depth > MAX_DEPTH:
                _reject(node, "expression depth exceeds migration limit")
            return self._expr(node)
        finally:
            self.depth -= 1

    def _expr(self, node: dict) -> tuple[str, str]:
        kind = node.get("kind")
        if kind in {"ImplicitCastExpr", "ParenExpr"}:
            if kind == "ImplicitCastExpr" and node.get("castKind") != "LValueToRValue":
                _reject(node, "C implicit conversion is not proven equivalent")
            return self.expr(_one(node))
        if kind == "IntegerLiteral":
            if node.get("type", {}).get("qualType") != "int":
                _reject(node, "only C int literals are supported")
            number = int(node.get("value", ""))
            if not 0 <= number <= (2**31 - 1):
                _reject(node, "literal exceeds signed 32-bit range")
            return str(number), "i32"
        if kind == "DeclRefExpr":
            ref = node.get("referencedDecl", {})
            name = ref.get("name")
            if ref.get("kind") not in {"ParmVarDecl", "VarDecl"} or name not in self.known:
                _reject(node, "only local value bindings are supported")
            return name, "i32"
        if kind == "UnaryOperator":
            op = node.get("opcode")
            if node.get("isPostfix"):
                _reject(node, "postfix mutation is unsupported")
            value, typ = self.expr(_one(node))
            if op in {"+", "-"} and typ == "i32":
                return f"({op}{value})", "i32"
            if op == "!":
                return f"(!{self._as_bool(value, typ, node)})", "bool"
            _reject(node, "unsupported unary expression")
        if kind == "BinaryOperator":
            op = node.get("opcode")
            children = _children(node)
            if len(children) != 2:
                _reject(node, "binary expression is malformed")
            left, lt = self.expr(children[0])
            right, rt = self.expr(children[1])
            if op in ARITH | COMPARE:
                if lt != "i32" or rt != "i32":
                    _reject(node, "scalar C integer operands are required")
                return f"({left} {op} {right})", "bool" if op in COMPARE else "i32"
            if op in LOGICAL:
                return f"({self._as_bool(left, lt, node)} {op} {self._as_bool(right, rt, node)})", "bool"
            _reject(node, "operator is outside the migration subset")
        _reject(node, "expression has no semantics-preserving lowering")

    @staticmethod
    def _as_bool(value: str, typ: str, node: dict) -> str:
        if typ == "bool":
            return value
        if typ == "i32":
            return f"({value} != 0)"
        _reject(node, "condition is neither integer nor boolean")

    def _int(self, node: dict) -> str:
        text, typ = self.expr(node)
        if typ != "i32":
            _reject(node, "C comparison truth values require an explicit int conversion")
        return text

    def statements(self, stmt: dict, indent: int = 1) -> list[str]:
        if indent > MAX_DEPTH:
            _reject(stmt, "statement depth exceeds migration limit")
        prefix = "    " * indent
        kind = stmt.get("kind")
        if kind == "CompoundStmt":
            out: list[str] = []
            for child in _children(stmt):
                out.extend(self.statements(child, indent))
            return out
        if kind == "ReturnStmt":
            return [f"{prefix}return {self._int(_one(stmt))};"]
        if kind == "DeclStmt":
            children = _children(stmt)
            if len(children) != 1 or children[0].get("kind") != "VarDecl":
                _reject(stmt, "only single local declarations are supported")
            var = children[0]
            name = _ident(var.get("name"), var)
            if name in self.known or var.get("type", {}).get("qualType") != "int" or var.get("storageClass"):
                _reject(var, "only unshadowed int locals are supported")
            value = self._int(_one(var))
            self.known.add(name)
            self.locals.add(name)
            return [f"{prefix}let mut {name}: i32 = {value};"]
        if kind == "BinaryOperator" and stmt.get("opcode") == "=":
            children = _children(stmt)
            if len(children) != 2 or children[0].get("kind") != "DeclRefExpr":
                _reject(stmt, "only direct local assignments are supported")
            ref = children[0].get("referencedDecl", {})
            name = ref.get("name")
            if name not in self.locals or ref.get("kind") != "VarDecl":
                _reject(stmt, "parameters and borrowed values cannot be modified")
            value = self._int(children[1])
            return [f"{prefix}{name} = {value};"]
        if kind == "CompoundAssignOperator" and stmt.get("opcode") in {"+=", "-=", "*="}:
            children = _children(stmt)
            if len(children) != 2 or children[0].get("kind") != "DeclRefExpr":
                _reject(stmt, "compound assignment is supported only for a simple local")
            ref = children[0].get("referencedDecl", {})
            name = ref.get("name")
            if name not in self.locals or ref.get("kind") != "VarDecl":
                _reject(stmt, "compound assignment cannot mutate a parameter")
            value = self._int(children[1])
            return [f"{prefix}{name} = ({name} {stmt['opcode'][0]} {value});"]
        if kind == "UnaryOperator" and stmt.get("opcode") in {"++", "--"}:
            value = _one(stmt)
            ref = value.get("referencedDecl", {})
            name = ref.get("name")
            if value.get("kind") != "DeclRefExpr" or name not in self.locals or ref.get("kind") != "VarDecl":
                _reject(stmt, "increment/decrement must target a local int")
            op = "+" if stmt["opcode"] == "++" else "-"
            return [f"{prefix}{name} = ({name} {op} 1);"]
        if kind == "WhileStmt":
            children = _children(stmt)
            if len(children) != 2:
                _reject(stmt, "expected a condition and a body")
            cond, typ = self.expr(children[0])
            return [f"{prefix}while {self._as_bool(cond, typ, stmt)} {{",
                    *self.statements(children[1], indent + 1), f"{prefix}}}"]
        if kind == "ForStmt":
            children = _children(stmt)
            if (len(children) != 5 or children[0].get("kind") != "DeclStmt"
                    or children[1].get("kind") is not None or not children[2].get("kind")):
                _reject(stmt, "only for (int i = ...; condition; local step) loops are supported")
            setup = self.statements(children[0], indent)
            cond, typ = self.expr(children[2])
            body_lines = self.statements(children[4], indent + 1)
            step = self.statements(children[3], indent + 1)
            if not step or not setup:
                _reject(stmt, "a for loop requires a local initializer and increment")
            return [*setup, f"{prefix}while {self._as_bool(cond, typ, stmt)} {{",
                    *body_lines, *step, f"{prefix}}}"]
        if kind == "IfStmt":
            children = _children(stmt)
            if len(children) not in {2, 3} or stmt.get("hasInit") or stmt.get("hasVar"):
                _reject(stmt, "only ordinary if/else is supported")
            cond, typ = self.expr(children[0])
            header = f"{prefix}if {self._as_bool(cond, typ, stmt)} {{"
            then = self.statements(children[1], indent + 1)
            out = [header, *then, f"{prefix}}}"]
            if len(children) == 3:
                else_lines = self.statements(children[2], indent + 1)
                out[-1] = f"{prefix}}} else {{"
                out.extend([*else_lines, f"{prefix}}}"])
            return out
        _reject(stmt, "control-flow statement is not implemented")


def _clang_ast(path: Path, clang: str) -> tuple[dict, str]:
    if shutil.which(clang) is None:
        raise MigrationRejected("E_C2HEPTA_TOOLCHAIN: Clang not found")
    args = [clang, "-x", "c", "-std=c11", "-Werror", "-Werror=implicit-function-declaration", "-ferror-limit=3",
            "-fsyntax-only", "-Xclang", "-ast-dump=json", str(path)]
    try:
        with tempfile.TemporaryFile() as out:
            proc = subprocess.run(args, stdout=out, stderr=subprocess.PIPE, timeout=15, check=False)
            out.seek(0)
            payload = out.read(MAX_AST_BYTES + 1)
    except subprocess.TimeoutExpired as exc:
        raise MigrationRejected("E_C2HEPTA_TOOLCHAIN: Clang timed out") from exc
    if proc.returncode != 0:
        msg = proc.stderr[:1024].decode("utf-8", "replace")
        raise MigrationRejected("E_C2HEPTA_CLANG: C source failed Clang validation: " + msg)
    if len(payload) > MAX_AST_BYTES:
        raise MigrationRejected("E_C2HEPTA_LIMIT: Clang AST exceeds budget")
    try:
        tree = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MigrationRejected("E_C2HEPTA_AST: Invalid Clang JSON") from exc
    version_response = subprocess.run([clang, "--version"], capture_output=True, text=True, timeout=5, check=False)
    if version_response.returncode or not version_response.stdout:
        raise MigrationRejected("E_C2HEPTA_TOOLCHAIN: Could not identify Clang")
    version = version_response.stdout.splitlines()[0]
    # Query Clang's *target* macros, not ctypes.sizeof(c_int) on this process.
    macros = subprocess.run([clang, "-dM", "-E", "-x", "c", "-"], input="", capture_output=True,
                            text=True, timeout=5, check=False)
    if (macros.returncode or not re.search(r"(?m)^#define __SIZEOF_INT__ 4$", macros.stdout)
            or not re.search(r"(?m)^#define __CHAR_BIT__ 8$", macros.stdout)):
        raise MigrationRejected("E_C2HEPTA_ABI: Clang target must use 32-bit signed int and 8-bit bytes")
    if tree.get("kind") != "TranslationUnitDecl":
        raise MigrationRejected("E_C2HEPTA_AST: Unexpected translation unit")
    return tree, version


def convert_c(source_file: str | Path, *, clang: str = "clang", module: str = "c_migrated") -> Translation:
    """Return all-or-nothing L1 source for the supported C profile.

    A successful return is a *candidate*, not a proof of equivalence. The caller
    must run real Hepta native validation, C differential testing, and ABI tests.
    """
    path = Path(source_file).resolve(strict=True)
    src = path.read_bytes()
    if len(src) > MAX_SOURCE_BYTES:
        raise MigrationRejected("E_C2HEPTA_LIMIT: Source exceeds 256 KiB")
    try:
        raw = src.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MigrationRejected("E_C2HEPTA_ENCODING: UTF-8 is required") from exc
    if re.search(r"(?m)^\s*#", raw):
        raise MigrationRejected("E_C2HEPTA_PREPROCESSOR: Directives require a compile database and macro provenance")
    module = _ident(module, {"kind": "module"})
    # A target ABI proof is not implied by 'int' written in the source.
    tree, version = _clang_ast(path, clang)
    declarations = []
    for node in _children(tree):
        if "offset" not in node.get("loc", {}):
            continue  # compiler-injected builtins without source locations
        if node.get("kind") != "FunctionDecl":
            _reject(node, "global declarations and nonfunctions are unsupported")
        if node.get("storageClass") not in (None, "extern") or node.get("inline") or node.get("variadic"):
            _reject(node, "storage, inline, and varargs are unsupported")
        declarations.append(node)
    if not declarations:
        raise MigrationRejected("E_C2HEPTA_EMPTY: No source-defined C functions")

    out = [f"module {module};", "", "// Migrated C11 signed-int subset: L1, not yet equivalence certified."]
    used: set[str] = set()
    for node in declarations:
        body = next((c for c in _children(node) if c.get("kind") == "CompoundStmt"), None)
        if body is None:
            _reject(node, "prototypes and external definitions are unsupported")
        if node.get("type", {}).get("qualType") is None or not re.fullmatch(r"int \((?:void|int(?:, int)*)\)", node["type"]["qualType"]):
            _reject(node, "only int f(int, ...) signatures are supported")
        name = _ident(node.get("name"), node)
        if name in used:
            _reject(node, "duplicate symbol")
        used.add(name)
        extra = [x for x in _children(node) if x.get("kind") not in {"ParmVarDecl", "CompoundStmt"}]
        if extra:
            _reject(extra[0], "function attributes or unsupported declarations are not preserved")
        params = [x for x in _children(node) if x.get("kind") == "ParmVarDecl"]
        names: list[str] = []
        for param in params:
            # Preserve no argument default or attribute implicitly: function
            # signatures are a strict ABI/semantics boundary.
            if param.get("init") is not None or _children(param):
                _reject(param, "default arguments and parameter attributes are unsupported")
            if param.get("type", {}).get("qualType") != "int":
                _reject(param, "only signed int value parameters are supported")
            pname = _ident(param.get("name"), param)
            if pname in names:
                _reject(param, "duplicate parameter")
            names.append(pname)
        converter = _Function(name, names)
        body_lines = converter.statements(body)
        if not body_lines:
            _reject(body, "empty function is unsupported")
        arguments = ", ".join(f"{p}: i32" for p in names)
        out += [f'export "C" fn {name}({arguments}) -> i32 effects {{ panic }}',
                "resources { heap_allocations = 0; may_block = false; may_suspend = false; may_spawn = false; }", "{",
                *body_lines, "}", ""]
    migrated = "\n".join(out)
    if path.read_bytes() != src:
        raise MigrationRejected("E_C2HEPTA_RACE: Source changed during conversion")
    report = {
        "schema": "hepta.c2hepta.v1", "status": "candidate_unverified", "ok": True,
        "migration_tier": "L1", "memory_safety_proved": False,
        "semantic_equivalence_proved": False, "native_hepta_validation": "not_run",
        "independent_differential_tests": "not_run", "abi_qualified": False,
        "profile": "standalone-C11-signed-int-value-only", "source_sha256": hashlib.sha256(src).hexdigest(),
        "hepta_sha256": hashlib.sha256(migrated.encode()).hexdigest(),
        "compiler": version, "functions": sorted(used),
        "limits": {"source_bytes": MAX_SOURCE_BYTES, "ast_bytes": MAX_AST_BYTES},
        "assumptions": ["Native compiler target has signed 32-bit C int", "Inputs exercise only defined C behavior", "No macros/includes/globals/pointers or external calls", "Only standalone no-overload C symbols"],
    }
    return Translation(migrated, report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed C11 -> Hepta L1 candidate (Clang AST)")
    parser.add_argument("source")
    parser.add_argument("--output", "-o", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--module", default="c_migrated")
    args = parser.parse_args(argv)
    try:
        source = Path(args.source).resolve(strict=True)
        target = Path(args.output).resolve()
        if target == source or target.suffix != ".hepta":
            raise MigrationRejected("E_C2HEPTA_OUTPUT: A separate .hepta output is required")
        translated = convert_c(source, clang=args.clang, module=args.module)
        if hashlib.sha256(source.read_bytes()).hexdigest() != translated.report["source_sha256"]:
            raise MigrationRejected("E_C2HEPTA_RACE: Source changed during conversion")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise MigrationRejected("E_C2HEPTA_OUTPUT: Refusing to overwrite an existing target")
        # Write an invisible candidate first; a same-directory hardlink creates
        # the final filename atomically and fails if another writer got there.
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent,
                                             prefix=".c2hepta-", suffix=".tmp", delete=False) as handle:
                temp_name = handle.name
                handle.write(translated.source)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temp_name, target)
        finally:
            if temp_name is not None:
                Path(temp_name).unlink(missing_ok=True)
        print(json.dumps({**translated.report, "output": str(target)}, sort_keys=True, indent=2))
        return 0
    except (MigrationRejected, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"schema": "hepta.c2hepta.v1", "ok": False, "status": "rejected", "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
