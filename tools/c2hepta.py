"""Fail-closed Clang AST -> HSIR -> Hepta importer, scalar C subset only.

No regex source rewriting, macro expansion, pointer conversion or C++ claims.
Intentionally rejects anything outside a narrow pure-scalar, C11 subset.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hepta.migration_ir import Expr, Function, IRValidationError, Stmt, check_function, emit_function, function_hash  # noqa: E402

TYPES = {"int": "i32", "unsigned int": "u32"}
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z", re.ASCII)
RESERVED = frozenset({"module", "import", "fn", "pub", "extern", "export", "effects", "resources", "as", "let", "mut", "take", "move", "read", "unsafe", "struct", "enum", "match", "if", "else", "return", "for", "while", "true", "false", "wrapping_add", "wrapping_sub", "wrapping_mul", "len", "assert", "main"})


class UnsupportedC(ValueError):
    pass


def _scalar(node: dict) -> str:
    spelling = node.get("type", {}).get("qualType", "")
    result = TYPES.get(spelling)
    if not result:
        raise UnsupportedC(f"unsupported C scalar type: {spelling!r}")
    return result


def _identifier(name: str) -> str:
    if (not IDENTIFIER.fullmatch(name) or name in RESERVED
            or name.startswith("__") or name.startswith("_")):
        raise UnsupportedC(f"identifier cannot be represented safely: {name!r}")
    return name


def _inner(node: dict, count: int) -> list[dict]:
    children = node.get("inner", [])
    if len(children) != count:
        raise UnsupportedC(f"{node.get('kind')} has {len(children)} children, expected {count}")
    return children


def _expr(node: dict, names: dict[str, str]) -> Expr:
    kind = node.get("kind")
    if kind in {"ParenExpr", "ImplicitCastExpr"}:
        if kind == "ImplicitCastExpr" and node.get("castKind") not in {"LValueToRValue", "NoOp"}:
            raise UnsupportedC(f"implicit C conversion not modeled: {node.get('castKind')}")
        child = _expr(_inner(node, 1)[0], names)
        if not (kind == "ParenExpr" and child.ty == "bool") and _scalar(node) != child.ty:
            raise UnsupportedC("implicit type-changing conversion")
        return child
    if kind == "DeclRefExpr":
        ref = node.get("referencedDecl", {})
        name = node.get("name") or ref.get("name", "")
        if ref.get("kind") != "ParmVarDecl" or names.get(name) != _scalar(node):
            raise UnsupportedC("global or non-parameter reference")
        return Expr("var", names[name], name)
    if kind == "IntegerLiteral":
        return Expr("literal", _scalar(node), node.get("value", ""))
    if kind == "UnaryOperator":
        operand = _expr(_inner(node, 1)[0], names)
        if node.get("opcode") == "-" and operand.ty == "i32" and _scalar(node) == "i32":
            return Expr("neg", "i32", args=(operand,))
        raise UnsupportedC("unsupported unary operator")
    if kind == "BinaryOperator":
        left_node, right_node = _inner(node, 2)
        left, right = _expr(left_node, names), _expr(right_node, names)
        op = node.get("opcode", "")
        if left.ty != right.ty:
            raise UnsupportedC("mixed operand types need explicit promotion semantics")
        if op in {"+", "-", "*"}:
            if _scalar(node) != left.ty:
                raise UnsupportedC("arithmetic result type mismatch")
            return Expr("arith", left.ty, op, (left, right))
        if op in {"==", "!=", "<", "<=", ">", ">="}:
            if node.get("type", {}).get("qualType") != "int":
                raise UnsupportedC("comparison C result type mismatch")
            return Expr("compare", "bool", op, (left, right))
        raise UnsupportedC(f"unsupported binary C operator: {op}")
    raise UnsupportedC(f"unsupported C expression: {kind}")


def _body(node: dict, names: dict[str, str]) -> tuple[Stmt, ...]:
    if node.get("kind") == "CompoundStmt":
        children = _inner(node, 1)
        return _body(children[0], names)
    if node.get("kind") == "ReturnStmt":
        return (Stmt("return", _expr(_inner(node, 1)[0], names)),)
    if node.get("kind") == "IfStmt":
        if not node.get("hasElse"):
            raise UnsupportedC("if without an else is outside this terminal-only subset")
        condition, then, otherwise = _inner(node, 3)
        cond = _expr(condition, names)
        if cond.ty != "bool":
            raise UnsupportedC("C integer-as-boolean condition is not modeled")
        return (Stmt("if", cond, _body(then, names), _body(otherwise, names)),)
    raise UnsupportedC(f"unsupported C statement: {node.get('kind')}")


def _function(node: dict) -> Function:
    if node.get("storageClass") in {"static", "extern"} or node.get("variadic") or node.get("inline"):
        raise UnsupportedC("static, explicitly extern, inline, or varargs function unsupported")
    if node.get("type", {}).get("qualType", "").endswith(" ()") or "..." in node.get("type", {}).get("qualType", ""):
        raise UnsupportedC("C unprototyped or varargs function unsupported")
    name = _identifier(node.get("name", ""))
    if not node.get("type", {}).get("qualType", "").startswith(tuple(t + " (" for t in TYPES)):
        raise UnsupportedC("unsupported C function return type")
    ret = TYPES[node["type"]["qualType"].split(" (")[0]]
    params = []
    body = None
    for child in node.get("inner", []):
        if child["kind"] == "ParmVarDecl":
            params.append((_identifier(child.get("name", "")), _scalar(child)))
        elif child["kind"] == "CompoundStmt":
            if body is not None:
                raise UnsupportedC("duplicate body")
            body = child
        else:
            raise UnsupportedC(f"unexpected function child: {child['kind']}")
    if body is None:
        raise UnsupportedC("prototype without definition requires a bridge")
    names = dict(params)
    if len(names) != len(params):
        raise UnsupportedC("duplicate parameter")
    result = Function(name, tuple(params), ret, _body(body, names))
    check_function(result)
    return result


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".hepta-migration-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def migrate(source: Path, output: Path, report: Path, clang: str = "clang", verify_native: bool = False, rustc: str | None = None) -> dict:
    # main() already guards this, but direct library callers must be safe too:
    # otherwise writing the JSON report can replace the original C input or
    # replace successful generated output if two names address one path.
    if len({source.resolve(), output.resolve(), report.resolve()}) != 3:
        raise ValueError("source, output and report paths must be distinct")
    try:
        original = source.read_bytes()
        read_error = None
    except OSError as exc:
        original = None
        read_error = str(exc)
    digest = hashlib.sha256(original).hexdigest() if original is not None else None
    info = {"schema": "hepta.c2hepta.v0", "source": str(source.resolve()),
            "source_sha256": digest, "status": "rejected", "safety": "not_qualified",
            "functions": [], "frontend_validation": "not_run", "backend_validation": "not_run", "clang": "not_run"}
    converted: list[Function] = []
    try:
        if read_error is not None:
            raise UnsupportedC("cannot read C input: " + read_error)
        if len(original) > 256_000:
            raise UnsupportedC("pilot input limit is 256 KB")
        if output.is_symlink() or report.is_symlink():
            raise UnsupportedC("symlink output/report paths are not accepted")
        if source.suffix != ".c":
            raise UnsupportedC("only C11 .c translation units are supported")
        if re.search(rb"(?m)^\s*#", original):
            raise UnsupportedC("preprocessor directives/macros require a future source model")
        if not shutil.which(clang):
            raise UnsupportedC("clang executable unavailable")
        version = subprocess.run([clang, "--version"], capture_output=True, text=True, timeout=10, check=True)
        info["clang"] = version.stdout.splitlines()[0]
        target = subprocess.run([clang, "-dumpmachine"], capture_output=True, text=True, timeout=10, check=True)
        info["target"] = target.stdout.strip()
        defines = subprocess.run([clang, "-std=c11", "-dM", "-E", "-x", "c", "-"], input=b"",
                                 capture_output=True, timeout=10, check=True).stdout
        if not re.search(rb"(?m)^#define __SIZEOF_INT__ 4$", defines) or not re.search(rb"(?m)^#define __CHAR_BIT__ 8$", defines):
            raise UnsupportedC("the Clang target's int/char width is unsupported")
        run = subprocess.run([clang, "-x", "c", "-std=c11", "-Wall", "-Wextra", "-Werror",
                              "-pedantic-errors", "-Wno-newline-eof", "-fsyntax-only", "-Xclang", "-ast-dump=json",
                              "-fno-color-diagnostics", str(source.resolve())],
                             capture_output=True, timeout=20, check=False)
        if run.returncode or len(run.stdout) > 8_000_000:
            raise UnsupportedC("Clang rejected source or AST exceeds size limit: " + run.stderr.decode("utf-8", "replace")[:600])
        tree = json.loads(run.stdout)
        nodes = [node for node in tree.get("inner", []) if node.get("loc", {}).get("offset") is not None]
        if not nodes:
            raise UnsupportedC("no source definitions")
        seen: set[str] = set()
        for node in nodes:
            label = node.get("name", node.get("kind", "unknown"))
            try:
                if node.get("kind") != "FunctionDecl":
                    raise UnsupportedC(f"top-level declaration not supported: {node.get('kind')}")
                fn = _function(node)
                if fn.name in seen:
                    raise UnsupportedC("duplicate function name")
                seen.add(fn.name)
                converted.append(fn)
                info["functions"].append({"name": fn.name, "status": "converted",
                                          "safety": "static_memory_safe_scalar_subset", "hsir_sha256": function_hash(fn),
                                          "effects": sorted(check_function(fn)), "ir": asdict(fn)})
            except (UnsupportedC, IRValidationError) as exc:
                info["functions"].append({"name": label, "status": "unsupported", "reason": str(exc)})
        if any(item["status"] != "converted" for item in info["functions"]):
            raise UnsupportedC("one or more declarations unsupported; no partial source emitted")
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise UnsupportedC("source changed during conversion")
        emitted = "module c2hepta_generated;\n\n" + "\n\n".join(emit_function(fn) for fn in converted) + "\n"
        # Check syntax/types against the actual Hepta frontend when it is installed.
        # A standalone bootstrap can only claim HSIR validation.
        import importlib.util
        if importlib.util.find_spec("hepta.parser") is None:
            info["frontend_validation"] = "unavailable"
        else:
            from hepta.parser import parse
            from hepta.checker import check
            checked = check(parse(emitted, str(output)))
            if not checked.ok:
                raise UnsupportedC("Hepta frontend rejected generated source: "
                                   + repr([d.to_dict() for d in checked.diagnostics])[:1500])
            info["frontend_validation"] = "passed"
        if verify_native:
            if info["frontend_validation"] != "passed":
                raise UnsupportedC("native validation requires installed Hepta frontend")
            from hepta.pipeline import analyze
            analysis = analyze(emitted, str(output), rustc=rustc)
            if not analysis.report.get("ok"):
                raise UnsupportedC("native Hepta validation did not pass: " + repr(analysis.report.get("diagnostics", []))[:1500])
            info["backend_validation"] = "passed"
        _atomic_write(output, emitted)
        info.update(status="converted", safety="static_memory_safe_scalar_subset",
                    output_sha256=hashlib.sha256(emitted.encode()).hexdigest(),
                    note="This is a finite syntax translation, NOT a proof of semantic equivalence, native compilation, or whole-language soundness.")
    except (UnsupportedC, IRValidationError, OSError, subprocess.SubprocessError, ValueError) as exc:
        info["reason"] = str(exc)
    if report.is_symlink():
        raise ValueError("refusing to overwrite a symlink report path")
    _atomic_write(report, json.dumps(info, sort_keys=True, indent=2) + "\n")
    return info


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("-o", "--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--verify-native", action="store_true", help="require Hepta/rustc native validation")
    parser.add_argument("--rustc", default=None, help="explicit pinned rustc path for --verify-native")
    parser.add_argument("--mode", choices=["strict"], default="strict")
    args = parser.parse_args()
    if args.output.resolve() == args.report.resolve() or args.output.resolve() == args.source.resolve() or args.report.resolve() == args.source.resolve():
        parser.error("source, output and report paths must be distinct")
    result = migrate(args.source, args.output, args.report, args.clang, args.verify_native, args.rustc)
    print(json.dumps({"status": result["status"], "reason": result.get("reason", ""), "report": str(args.report)}))
    return 0 if result["status"] == "converted" else 2


if __name__ == "__main__":
    raise SystemExit(main())
