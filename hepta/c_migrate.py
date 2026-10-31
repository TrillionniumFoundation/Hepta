"""Clang-AST C scalar migration pilot. Strict subset; never silent rewriting.

Only independent pure integer functions are candidates. No pointers, global
state, casts, user-defined types or C++ are accepted. Syntax/semantic validation
of emitted Hepta is mandatory before writing. The source C semantics and target
ABI are *not* generally proven equivalent by this migration pilot.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
_TYPES = {"int32_t": "i32", "uint32_t": "u32", "int64_t": "i64", "uint64_t": "u64",
          "int": "i32", "unsigned int": "u32", "long long": "i64", "unsigned long long": "u64",
          "long": "i64", "unsigned long": "u64"}
_ARITH = {"+", "-", "*"}
_BITS = {"&", "|", "^"}
_CMP = {"==", "!=", "<", "<=", ">", ">="}
_CASTS = {"LValueToRValue", "NoOp"}


_AST_RECURSION_LIMIT = 128


class MigrationRejected(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _run(args: list[str], *, input_text: str | None = None) -> str:
    # Clang can expand a small C source into a very large AST or diagnostic
    # stream. subprocess.run(capture_output=True) first materializes the
    # *whole* output in RAM, so its post-hoc size check is not a memory bound.
    # File-backed capture limits parent-process memory before any decoding.
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            proc = subprocess.run(args, input=input_text, stdout=stdout, stderr=stderr,
                                  text=True, timeout=30, check=False)
            if proc.returncode:
                stderr.seek(0, os.SEEK_END)
                stderr.seek(max(0, stderr.tell() - 5_000))
                reason = stderr.read().decode("utf-8", errors="replace")
                raise MigrationRejected("E_CLANG_REJECT", reason or "Clang exited with failure")
            stdout.seek(0, os.SEEK_END)
            if stdout.tell() > 32_000_000:
                raise MigrationRejected("E_CLANG_SIZE", "Clang AST output exceeds 32 MB")
            stdout.seek(0)
            return stdout.read().decode("utf-8")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MigrationRejected("E_CLANG_ENV", str(exc)) from exc


def _data_model(clang: str) -> dict:
    macros = _run([clang, "-std=c11", "-dM", "-E", "-x", "c", "-"], input_text="")
    defines = dict(m.groups() for line in macros.splitlines()
                   if (m := re.fullmatch(r"#define (__SIZEOF_(?:INT|LONG|LONG_LONG|POINTER)__)(?:\s+)(\d+)", line)))
    if defines.get("__SIZEOF_INT__") != "4" or defines.get("__SIZEOF_LONG_LONG__") != "8":
        raise MigrationRejected("E_C_DATA_MODEL", "pilot requires 32-bit C int and 64-bit long long")
    return {"sizeof_int": 4, "sizeof_long": int(defines.get("__SIZEOF_LONG__", 0)),
            "sizeof_long_long": 8, "sizeof_pointer": int(defines.get("__SIZEOF_POINTER__", 0)),
            "target": _run([clang, "-dumpmachine"]).strip(),
            "clang_version": _run([clang, "--version"]).splitlines()[0]}


def _typ(qual: str, model: dict) -> str:
    qual = qual.strip()
    resolved = _TYPES.get(qual)
    if resolved is None or (qual in {"long", "unsigned long"} and model["sizeof_long"] != 8):
        raise MigrationRejected("E_C_TYPE", f"Unsupported or target-dependent C type: {qual}")
    return resolved


def _decl_type(node: dict, model: dict) -> str:
    t = node.get("type", {})
    return _typ(t.get("qualType", ""), model)


def _expr(node: dict, args: dict[str, str], model: dict, expected: str,
          *, _visit_depth: int = 0) -> tuple[str, str]:
    if _visit_depth >= _AST_RECURSION_LIMIT:
        raise MigrationRejected("E_C_AST_DEPTH", "C expression nesting exceeds migration limit")
    kind = node.get("kind")
    inner = node.get("inner", [])
    if kind in {"ImplicitCastExpr", "ParenExpr"}:
        if len(inner) != 1:
            raise MigrationRejected("E_C_AST", "Malformed Clang cast/parenthesis")
        if kind == "ImplicitCastExpr":
            cast = node.get("castKind")
            if cast == "IntegralCast" and inner[0].get("kind") == "IntegerLiteral" and _decl_type(node, model) == expected:
                # Only compile-time constants provably representable in the target
                # type may undergo automatic widening/promotion in this pilot.
                return _expr(inner[0], args, model, expected, _visit_depth=_visit_depth + 1)
            if cast not in _CASTS:
                raise MigrationRejected("E_C_CAST", "C integer/pointer casts require a checked target representation")
        return _expr(inner[0], args, model, expected, _visit_depth=_visit_depth + 1)
    if kind == "IntegerLiteral":
        try:
            value = int(node["value"])
        except (KeyError, ValueError) as exc:
            raise MigrationRejected("E_C_INTEGER", "Unsupported integer literal") from exc
        width = 32 if expected.endswith("32") else 64
        signed = expected.startswith("i")
        minimum, maximum = (-(1 << (width-1)), (1 << (width-1)) - 1) if signed else (0, (1 << width) - 1)
        if not minimum <= value <= maximum:
            raise MigrationRejected("E_C_INTEGER", "Integer literal is outside the target type")
        return str(value), expected
    if kind == "DeclRefExpr":
        decl = node.get("referencedDecl", {})
        name = decl.get("name", "")
        if decl.get("kind") != "ParmVarDecl" or name not in args:
            raise MigrationRejected("E_C_REF", "Only local scalar function parameter reads are migrated")
        if args[name] != expected:
            raise MigrationRejected("E_C_PROMOTION", "C integer promotions require a separate checked lowering")
        return name, expected
    if kind == "UnaryOperator" and node.get("opcode") in {"+", "-"} and len(inner) == 1:
        rendered, typ = _expr(inner[0], args, model, expected, _visit_depth=_visit_depth + 1)
        if node["opcode"] == "-" and expected.startswith("u"):
            raise MigrationRejected("E_C_UNSIGNED_NEG", "Unsigned negation needs modular-C semantics")
        return f"({node['opcode']}{rendered})", typ
    if kind == "BinaryOperator" and len(inner) == 2:
        op = node.get("opcode")
        if op in _CMP:
            # C comparisons yield int, whereas Hepta comparisons yield bool.
            # This expression is only consumed as a statement condition.
            lhs_type = _decl_type(inner[0], model)
            left, _ = _expr(inner[0], args, model, lhs_type, _visit_depth=_visit_depth + 1)
            right, _ = _expr(inner[1], args, model, lhs_type, _visit_depth=_visit_depth + 1)
            return f"({left} {op} {right})", "bool"
        if op not in _ARITH | _BITS:
            raise MigrationRejected("E_C_OPERATOR", f"Unsupported C operator: {op}")
        if op in _BITS and expected.startswith("i"):
            raise MigrationRejected("E_C_BITWISE", "Signed C bitwise operations require target-specific semantics")
        left, _ = _expr(inner[0], args, model, expected, _visit_depth=_visit_depth + 1)
        right, _ = _expr(inner[1], args, model, expected, _visit_depth=_visit_depth + 1)
        if op in _ARITH and expected.startswith("u"):
            builtin = {"+": "wrapping_add", "-": "wrapping_sub", "*": "wrapping_mul"}[op]
            return f"{builtin}({left}, {right})", expected
        return f"({left} {op} {right})", expected
    raise MigrationRejected("E_C_EXPRESSION", f"Unsupported C expression: {kind}")


def _stmt(node: dict, args: dict[str, str], model: dict, ret: str, depth: int = 1,
          *, _visit_depth: int = 0) -> list[str]:
    if _visit_depth >= _AST_RECURSION_LIMIT:
        raise MigrationRejected("E_C_AST_DEPTH", "C statement nesting exceeds migration limit")
    indent = "    " * depth
    kind = node.get("kind")
    children = node.get("inner", [])
    if kind == "CompoundStmt":
        return [line for child in children for line in _stmt(child, args, model, ret, depth, _visit_depth=_visit_depth + 1)]
    if kind == "ReturnStmt" and len(children) == 1:
        expression, typ = _expr(children[0], args, model, ret)
        if typ != ret:
            raise MigrationRejected("E_C_RETURN", "C comparison or implicit conversion is not a Hepta integer return")
        return [f"{indent}return {expression};"]
    if kind == "IfStmt" and len(children) in (2, 3):
        cond, typ = _expr(children[0], args, model, "bool")
        if typ != "bool":
            raise MigrationRejected("E_C_CONDITION", "C integer truthiness requires an explicit checked conversion")
        result = [f"{indent}if {cond} {{"]
        result.extend(_stmt(children[1], args, model, ret, depth + 1, _visit_depth=_visit_depth + 1))
        result.append(f"{indent}}}")
        if len(children) == 3:
            result.append(f"{indent}else {{")
            result.extend(_stmt(children[2], args, model, ret, depth + 1, _visit_depth=_visit_depth + 1))
            result.append(f"{indent}}}")
        return result
    raise MigrationRejected("E_C_STATEMENT", f"Unsupported C statement: {kind}")


_C_AST_FUNCTION_NODE_LIMIT = 4096
_C_AST_TRANSLATION_UNIT_NODE_LIMIT = 8192


def _check_function_ast_budget(decl: dict) -> int:
    """Bound AST work per C function before recursive source generation.

    The depth guard alone does not prevent a shallow AST from containing many
    siblings. Use an iterative, exact node count so a malformed or oversized
    tree cannot enter the recursive translator. This does not cap Clang's own
    CPU/RSS, the full translation-unit AST, or JSON parsing.
    """
    pending = [decl]
    remaining = _C_AST_FUNCTION_NODE_LIMIT
    while pending:
        node = pending.pop()
        if type(node) is not dict:
            raise MigrationRejected("E_C_AST", "Malformed C AST node")
        remaining -= 1
        if remaining < 0:
            raise MigrationRejected("E_C_AST_BUDGET", "C function AST node budget exceeded")
        children = node.get("inner", [])
        if type(children) is not list:
            raise MigrationRejected("E_C_AST", "Malformed C AST child collection")
        if len(children) > remaining:
            raise MigrationRejected("E_C_AST_BUDGET", "C function AST node budget exceeded")
        pending.extend(children)
    return _C_AST_FUNCTION_NODE_LIMIT - remaining


def _check_translation_unit_ast_budget(declarations: list[dict]) -> None:
    """Bound the aggregate work across all source-defined C functions.

    The per-function limit alone permits thousands of individually small
    functions to generate unbounded cumulative traversal and output. Count
    the same AST nodes, fail closed before any source generation, and do not
    count unrelated imported-system-header declarations.
    """
    total = 0
    for decl in declarations:
        total += _check_function_ast_budget(decl)
        if total > _C_AST_TRANSLATION_UNIT_NODE_LIMIT:
            raise MigrationRejected("E_C_AST_UNIT_BUDGET",
                                    "C translation unit function AST node budget exceeded")


def _function(decl: dict, model: dict) -> dict:
    _check_function_ast_budget(decl)
    name = decl.get("name", "")
    if not _IDENT.fullmatch(name) or name.startswith("__"):
        raise MigrationRejected("E_C_NAME", "Unsupported C function identifier")
    typ = decl.get("type", {}).get("qualType", "")
    if "(" not in typ:
        raise MigrationRejected("E_C_FUNCTION", "Missing C function signature")
    if typ.endswith("()") or decl.get("storageClass") or decl.get("inline") or decl.get("isImplicit"):
        raise MigrationRejected("E_C_FUNCTION", "Unprototyped, static, inline or implicit functions are unsupported")
    ret = _typ(typ.split("(", 1)[0], model)
    parts = decl.get("inner", [])
    if any(x.get("kind") not in {"ParmVarDecl", "CompoundStmt"} for x in parts):
        raise MigrationRejected("E_C_ATTRIBUTE", "Function attributes or other declarations require explicit ABI lowering")
    body = [x for x in parts if x.get("kind") == "CompoundStmt"]
    if len(body) != 1:
        raise MigrationRejected("E_C_FUNCTION", "Only functions with a single C compound body are supported")
    params = [x for x in parts if x.get("kind") == "ParmVarDecl"]
    if "..." in typ or len(params) > 32:
        raise MigrationRejected("E_C_FUNCTION", "Variadic or oversized C function signature")
    args = {}
    for p in params:
        n = p.get("name", "")
        if not _IDENT.fullmatch(n) or n in args or n.startswith("__"):
            raise MigrationRejected("E_C_NAME", "Unnamed, duplicate or reserved C parameter")
        args[n] = _decl_type(p, model)
    rendered = _stmt(body[0], args, model, ret)
    if not rendered:
        raise MigrationRejected("E_C_EMPTY", "Empty C function cannot satisfy a scalar return")
    signature = ", ".join(f"{p}: {t}" for p, t in args.items())
    source = f"export \"C\" fn {name}({signature}) -> {ret} effects {{panic}} {{\n" + "\n".join(rendered) + "\n}\n"
    return {"name": name, "source": source, "params": args, "returns": ret}


def _read_bounded_source(src: Path, *, recheck: bool) -> bytes:
    """Bound *every* source read, not just the first size check.

    Files can grow between Clang analysis, frontend validation and publication.
    A recheck of an oversize file is a source race, not an initial size error.
    """
    try:
        with src.open("rb") as stream:
            source = stream.read(256_001)
    except OSError as exc:
        raise MigrationRejected("E_C_SOURCE_RACE",
                                "C source unavailable during bounded read") from exc
    if len(source) > 256_000:
        code = "E_C_SOURCE_RACE" if recheck else "E_C_SIZE"
        message = ("C source exceeded 256 KB during conversion" if recheck
                   else "Pilot source exceeds 256 KB")
        raise MigrationRejected(code, message)
    return source


def migrate_c(path: str | Path, output: str | Path, *, clang: str = "clang") -> dict:
    """Return explicit migration evidence; never write a partial conversion."""
    src, dest = Path(path).resolve(), Path(output).absolute()
    report = {"schema": "hepta.migrate-c.v0", "ok": False, "status": "rejected",
              "profile": "strict_scalar_pilot", "source": str(src), "output": str(dest),
              "source_equivalence_proved": False, "whole_language_soundness_proved": False,
              "native_validation": "not_run", "converted": [], "rejected": []}
    try:
        if (src == dest or not src.is_file() or src.suffix != ".c"
                or dest.suffix != ".hepta" or dest.is_symlink()):
            raise MigrationRejected("E_C_PATH", "Require existing .c source and distinct non-symlink .hepta destination")
        source = _read_bounded_source(src, recheck=False)
        report["source_sha256"] = hashlib.sha256(source).hexdigest()
        model = _data_model(clang)
        report["target_model"] = model
        ast_json = _run([clang, "-std=c11", "-fsyntax-only", "-Werror",
                        "-Xclang", "-ast-dump=json", str(src)])
        try:
            root = json.loads(ast_json)
        except RecursionError as exc:
            raise MigrationRejected("E_C_AST_DEPTH", "Clang AST JSON nesting exceeds parser limit") from exc
        if root.get("kind") != "TranslationUnitDecl":
            raise MigrationRejected("E_C_AST", "Clang did not return a translation unit")
        declarations = []
        unsupported_toplevel = []
        active_file = None
        for node in root.get("inner", []):
            node_file = node.get("loc", {}).get("file")
            if node_file:
                active_file = Path(node_file).resolve()
            loc = node.get("loc", {})
            if active_file != src:
                continue
            begin = node.get("range", {}).get("begin", {}).get("offset")
            end = node.get("range", {}).get("end", {}).get("offset")
            if not isinstance(begin, int) or not isinstance(end, int) or not (0 <= begin <= end < len(source)):
                continue
            if node.get("kind") == "FunctionDecl" and any(
                    x.get("kind") == "CompoundStmt" for x in node.get("inner", [])):
                declarations.append(node)
            else:
                # The pilot claims a whole-translation-unit conversion.
                # Globals, typedefs and prototypes may carry ABI/linkage state:
                # never accept the file and silently omit those declarations.
                unsupported_toplevel.append(f"{node.get('kind')}: {node.get('name', '<anonymous>')}")
        if unsupported_toplevel:
            raise MigrationRejected("E_C_TOPLEVEL", "Unsupported source declarations: " +
                                    ", ".join(unsupported_toplevel[:12]))
        if not declarations:
            raise MigrationRejected("E_C_NO_FUNCTIONS", "No ordinary C function definitions found")
        # Reject aggregate AST expansion before rendering *any* function.
        # Independently keep the _function guard for direct callers.
        try:
            _check_translation_unit_ast_budget(declarations)
        except MigrationRejected as exc:
            report["rejected"].append({"code": exc.code, "message": str(exc)})
            report["status"] = "unsupported_source"
            return report
        translated = []
        seen = set()
        for decl in declarations:
            try:
                part = _function(decl, model)
                if part["name"] in seen:
                    raise MigrationRejected("E_C_DUPLICATE", "Duplicate function or overload")
                seen.add(part["name"])
                translated.append(part)
            except MigrationRejected as exc:
                report["rejected"].append({"name": decl.get("name"), "code": exc.code, "message": str(exc)})
        if report["rejected"]:
            report["status"] = "unsupported_source"
            return report
        program = "module c_migrated;\n\n" + "\n".join(x["source"] for x in translated)
        if _read_bounded_source(src, recheck=True) != source:
            raise MigrationRejected("E_C_SOURCE_RACE", "C source changed during Clang analysis")
        from .checker import check
        from .parser import parse
        checked = check(parse(program, str(dest)))
        if not checked.ok:
            report["rejected"] = [x.to_dict() for x in checked.diagnostics]
            report["status"] = "hepta_frontend_rejected"
            return report
        if dest.exists():
            raise MigrationRejected("E_C_EXISTS", "Refusing to overwrite an existing .hepta destination")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_symlink():
            raise MigrationRejected("E_C_SYMLINK", "Refusing a symlink destination")
        staged = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=dest.parent,
                                             prefix=".hepta-migrate-", delete=False) as f:
                staged = Path(f.name)
                f.write(program)
                f.flush()
                os.fsync(f.fileno())
            # Frontend checks may take time after the earlier source check.
            # Reject any change before publication, including same-size edits.
            # This narrows but cannot eliminate noncooperative writer races.
            if _read_bounded_source(src, recheck=True) != source:
                raise MigrationRejected("E_C_SOURCE_RACE",
                                        "C source changed before publication")
            # Atomic same-filesystem hard-link publication: the completely
            # written, fsynced staged inode becomes visible in one operation.
            # os.link fails without replacing a concurrent existing name.
            # This is NOT a multi-file transaction or proof of crash durability.
            try:
                os.link(staged, dest)
            except FileExistsError as exc:
                raise MigrationRejected("E_C_EXISTS", "Destination appeared during conversion") from exc
            except OSError as exc:
                raise MigrationRejected("E_C_PUBLISH", "Atomic publish unavailable: " + str(exc)) from exc
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)
        report.update({"ok": True, "status": "frontend_checked_not_native_qualified",
                       "converted": [{k: v for k, v in x.items() if k != "source"} for x in translated],
                       "output_sha256": hashlib.sha256(program.encode()).hexdigest(),
                       "native_validation": "not_run", "frontend": "passed"})
        return report
    except (MigrationRejected, UnicodeError, json.JSONDecodeError) as exc:
        report["rejected"].append({"code": getattr(exc, "code", "E_C_INPUT"), "message": str(exc)})
        # Whole-unit semantic rejection has the same status contract as a
        # rejected function body; keep path/environment failures distinct.
        if isinstance(exc, MigrationRejected) and exc.code == "E_C_TOPLEVEL":
            report["status"] = "unsupported_source"
        return report
