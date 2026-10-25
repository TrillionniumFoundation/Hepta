"""Clang-AST C scalar migration pilot. Strict subset; never silent rewriting.

Only independent pure integer functions are candidates. No pointers, global
state, casts, user-defined types or C++ are accepted. Syntax/semantic validation
of emitted Hepta is mandatory before writing. The source C semantics and target
ABI are *not* generally proven equivalent by this migration pilot.
"""
from __future__ import annotations

import hashlib
import json
import math
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


class MigrationRejected(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _run(args: list[str], *, input_text: str | None = None) -> str:
    try:
        proc = subprocess.run(args, input=input_text, capture_output=True, text=True,
                              timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MigrationRejected("E_CLANG_ENV", str(exc)) from exc
    if proc.returncode:
        raise MigrationRejected("E_CLANG_REJECT", proc.stderr[-5000:] or "Clang exited with failure")
    if len(proc.stdout) > 32_000_000:
        raise MigrationRejected("E_CLANG_SIZE", "Clang AST output exceeds 32 MB")
    return proc.stdout


def _load_bounded_clang_ast(raw: str, *, max_bytes: int = 32_000_000,
                            max_depth: int = 128, max_nodes: int = 250_000) -> dict:
    """Decode and size/depth-bound untrusted native Clang AST transcripts.

    The input is a single real Clang translation unit, not an arbitrary
    second AST authority. Nonfinite JSON, deeply nested structures and
    maliciously oversized node inventories must fail with diagnostics rather
    than an uncaught Python recursion/JSON exception.
    """
    if (not isinstance(raw, str) or any(type(n) is not int or n <= 0
                                       for n in (max_bytes, max_depth, max_nodes))):
        raise MigrationRejected("E_CLANG_AST_LIMIT", "Invalid AST input or capture budgets")
    if len(raw) > max_bytes or len(raw.encode("utf-8")) > max_bytes:
        raise MigrationRejected("E_CLANG_AST_LIMIT", "Clang AST JSON exceeds bounded input budget")

    def bad_constant(value: str):
        raise ValueError("Nonfinite JSON constant: " + value)

    try:
        root = json.loads(raw, parse_constant=bad_constant)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise MigrationRejected("E_CLANG_AST_FORMAT", "Malformed or too deeply nested Clang JSON AST") from exc
    if not isinstance(root, dict) or root.get("kind") != "TranslationUnitDecl":
        raise MigrationRejected("E_CLANG_AST_FORMAT", "Clang AST root must be a translation unit")
    pending = [(root, 0)]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > max_nodes or depth > max_depth:
            raise MigrationRejected("E_CLANG_AST_LIMIT", "Clang AST node/depth budget exceeded")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif not (value is None or isinstance(value, (str, int, bool))
                  or (type(value) is float and math.isfinite(value))):
            raise MigrationRejected("E_CLANG_AST_FORMAT", "Clang AST contains unsupported JSON type")
    return root


def _data_model(clang: str) -> dict:
    macros = _run([clang, "-std=c11", "-dM", "-E", "-x", "c", "-"], input_text="")
    defines = dict(m.groups() for line in macros.splitlines()
                   if (m := re.fullmatch(r"#define (__SIZEOF_(?:INT|LONG|LONG_LONG|POINTER)__)(?:\s+)(\d+)", line)))
    char_bits = re.search(r"(?m)^#define __CHAR_BIT__\s+(\d+)\s*$", macros)
    if (defines.get("__SIZEOF_INT__") != "4" or defines.get("__SIZEOF_LONG_LONG__") != "8"
            or char_bits is None or char_bits.group(1) != "8"):
        raise MigrationRejected("E_C_DATA_MODEL", "pilot requires 8-bit C bytes, 32-bit int and 64-bit long long")
    return {"char_bit": 8, "sizeof_int": 4, "sizeof_long": int(defines.get("__SIZEOF_LONG__", 0)),
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
          locals: dict[str, tuple[str, str]] | None = None) -> tuple[str, str]:
    # Locals are admitted only through the function-prefix declaration gate.
    # Clang declaration identity is checked on every read: matching by spelling
    # alone would accept unrelated or out-of-scope VarDecl nodes.
    locals = {} if locals is None else locals
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
                return _expr(inner[0], args, model, expected, locals)
            if cast not in _CASTS:
                raise MigrationRejected("E_C_CAST", "C integer/pointer casts require a checked target representation")
        return _expr(inner[0], args, model, expected, locals)
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
        if decl.get("kind") == "ParmVarDecl":
            actual = args.get(name)
        elif decl.get("kind") == "VarDecl":
            local = locals.get(name)
            actual = local[0] if (local is not None
                                  and isinstance(decl.get("id"), str)
                                  and decl["id"] == local[1]) else None
        else:
            actual = None
        if actual is None:
            raise MigrationRejected("E_C_REF", "Reference is not a checked parameter or initialized local")
        if actual != expected:
            raise MigrationRejected("E_C_PROMOTION", "C integer promotions require a separate checked lowering")
        return name, expected
    if kind == "UnaryOperator" and node.get("opcode") in {"+", "-"} and len(inner) == 1:
        rendered, typ = _expr(inner[0], args, model, expected, locals)
        if node["opcode"] == "-" and expected.startswith("u"):
            raise MigrationRejected("E_C_UNSIGNED_NEG", "Unsigned negation needs modular-C semantics")
        return f"({node['opcode']}{rendered})", typ
    if kind == "BinaryOperator" and len(inner) == 2:
        op = node.get("opcode")
        if op in _CMP:
            # C comparisons yield int, whereas Hepta comparisons yield bool.
            # This expression is only consumed as a statement condition.
            lhs_type = _decl_type(inner[0], model)
            left, _ = _expr(inner[0], args, model, lhs_type, locals)
            right, _ = _expr(inner[1], args, model, lhs_type, locals)
            return f"({left} {op} {right})", "bool"
        if op not in _ARITH | _BITS:
            raise MigrationRejected("E_C_OPERATOR", f"Unsupported C operator: {op}")
        if op in _BITS and expected.startswith("i"):
            raise MigrationRejected("E_C_BITWISE", "Signed C bitwise operations require target-specific semantics")
        left, _ = _expr(inner[0], args, model, expected, locals)
        right, _ = _expr(inner[1], args, model, expected, locals)
        if op in _ARITH and expected.startswith("u"):
            builtin = {"+": "wrapping_add", "-": "wrapping_sub", "*": "wrapping_mul"}[op]
            return f"{builtin}({left}, {right})", expected
        return f"({left} {op} {right})", expected
    raise MigrationRejected("E_C_EXPRESSION", f"Unsupported C expression: {kind}")


def _stmt(node: dict, args: dict[str, str], model: dict, ret: str, depth: int = 1,
          locals: dict[str, tuple[str, str]] | None = None) -> list[str]:
    locals = {} if locals is None else locals
    indent = "    " * depth
    kind = node.get("kind")
    children = node.get("inner", [])
    if kind == "CompoundStmt":
        return [line for child in children for line in _stmt(child, args, model, ret, depth, locals)]
    if kind == "BinaryOperator" and node.get("opcode") == "=" and len(children) == 2:
        target = children[0]
        ref = target.get("referencedDecl", {}) if target.get("kind") == "DeclRefExpr" else {}
        name = ref.get("name")
        local = locals.get(name)
        if (local is None or ref.get("kind") != "VarDecl"
                or ref.get("id") != local[1]):
            raise MigrationRejected("E_C_ASSIGN", "Only a known initialized scalar local may be assigned")
        value, value_type = _expr(children[1], args, model, local[0], locals)
        if value_type != local[0]:
            raise MigrationRejected("E_C_ASSIGN", "Assignment type conversion not in checked subset")
        return [f"{indent}{name} = {value};"]
    if kind == "UnaryOperator" and node.get("opcode") in {"++", "--"} and len(children) == 1:
        # Standalone pre/post increment/decrement has no observed value.
        # Only the exact Clang declaration ID of a validated local is admitted.
        operand = children[0]
        ref = operand.get("referencedDecl", {}) if isinstance(operand, dict) and operand.get("kind") == "DeclRefExpr" else {}
        name = ref.get("name")
        local = locals.get(name)
        if (local is None or ref.get("kind") != "VarDecl" or ref.get("id") != local[1]
                or _decl_type(node, model) != local[0]):
            raise MigrationRejected("E_C_INCREMENT", "Only increment/decrement of an initialized scalar local is supported")
        op = "+" if node["opcode"] == "++" else "-"
        if local[0].startswith("u"):
            builtin = "wrapping_add" if op == "+" else "wrapping_sub"
            result = f"{builtin}({name}, 1)"
        else:
            result = f"({name} {op} 1)"
        return [f"{indent}{name} = {result};"]
    if kind == "ForStmt":
        # Clang's five slots: initializer, condition-variable declaration,
        # condition, increment, and body. For the strict subset no continue,
        # break, goto, in-loop declaration, or observed step return exists.
        # Thus init; while (condition) { body; increment; } is equivalent
        # on the source language's defined signed-arithmetic input domain.
        if (len(children) != 5 or children[1] is not None
                or any(part is None for part in (children[0], children[2], children[3], children[4]))):
            raise MigrationRejected("E_C_FOR_SHAPE", "For requires explicit init, comparison, step and body")
        initial, _, condition, advance, loop_body = children
        if (initial.get("kind") != "BinaryOperator" or initial.get("opcode") != "="
                or loop_body.get("kind") != "CompoundStmt"
                or not ((advance.get("kind") == "BinaryOperator" and advance.get("opcode") == "=")
                        or (advance.get("kind") == "UnaryOperator"
                            and advance.get("opcode") in {"++", "--"}))):
            raise MigrationRejected("E_C_FOR_SHAPE", "For requires assignment initializer, scalar step and compound body")
        initial_lines = _stmt(initial, args, model, ret, depth, locals)
        predicate, predicate_type = _expr(condition, args, model, "bool", locals)
        if predicate_type != "bool":
            raise MigrationRejected("E_C_CONDITION", "Only Boolean comparison for conditions are supported")
        lines = initial_lines + [f"{indent}while {predicate} {{"]
        lines.extend(_stmt(loop_body, args, model, ret, depth + 1, locals))
        lines.extend(_stmt(advance, args, model, ret, depth + 1, locals))
        lines.append(f"{indent}}}")
        return lines
    if kind == "WhileStmt" and len(children) == 2:
        condition, condition_type = _expr(children[0], args, model, "bool", locals)
        if condition_type != "bool":
            raise MigrationRejected("E_C_CONDITION", "Only explicit Boolean while conditions are supported")
        body = children[1]
        if body.get("kind") != "CompoundStmt":
            raise MigrationRejected("E_C_LOOP", "While loop body requires an explicit compound statement")
        lines = [f"{indent}while {condition} {{"]
        lines.extend(_stmt(body, args, model, ret, depth + 1, locals))
        lines.append(f"{indent}}}")
        return lines
    if kind == "ReturnStmt" and len(children) == 1:
        expression, typ = _expr(children[0], args, model, ret, locals)
        if typ != ret:
            raise MigrationRejected("E_C_RETURN", "C comparison or implicit conversion is not a Hepta integer return")
        return [f"{indent}return {expression};"]
    if kind == "IfStmt" and len(children) in (2, 3):
        cond, typ = _expr(children[0], args, model, "bool", locals)
        if typ != "bool":
            raise MigrationRejected("E_C_CONDITION", "C integer truthiness requires an explicit checked conversion")
        result = [f"{indent}if {cond} {{"]
        result.extend(_stmt(children[1], args, model, ret, depth + 1, locals))
        result.append(f"{indent}}}")
        if len(children) == 3:
            result.append(f"{indent}else {{")
            result.extend(_stmt(children[2], args, model, ret, depth + 1, locals))
            result.append(f"{indent}}}")
        return result
    raise MigrationRejected("E_C_STATEMENT", f"Unsupported C statement: {kind}")


def _function(decl: dict, model: dict) -> dict:
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
    # Deliberately narrow scope recovery: initialized local declarations must
    # be a simple prefix of the function's top-level block. Nested declarations,
    # shadowing, multiple declarators and arbitrary initialization are rejected.
    # This guarantees every local use is in its declared scope without claiming
    # support for general C/C++ lexical scopes, lifetimes or definite assignment.
    locals: dict[str, tuple[str, str]] = {}
    rendered: list[str] = []
    saw_executable = False
    for item in body[0].get("inner", []):
        if item.get("kind") == "DeclStmt":
            if saw_executable:
                raise MigrationRejected("E_C_LOCAL_SCOPE", "Local declarations must precede executable statements")
            decls = item.get("inner", [])
            if len(decls) != 1 or decls[0].get("kind") != "VarDecl":
                raise MigrationRejected("E_C_LOCAL_DECL", "Only single scalar local declarations are supported")
            var = decls[0]
            # Static / thread-local / constexpr declarations are not ordinary
            # automatic mutable locals. Dropping their storage duration would
            # silently change original C or C++ program behavior.
            if (var.get("storageClass") is not None or var.get("tls") is not None
                    or var.get("constexpr") or var.get("isConstexpr")
                    or var.get("inline")):
                raise MigrationRejected("E_C_LOCAL_STORAGE", "Nonautomatic or special local storage is unsupported")
            local_name = var.get("name", "")
            local_id = var.get("id")
            if (not _IDENT.fullmatch(local_name) or local_name.startswith("__")
                    or local_name in args or local_name in locals
                    or not isinstance(local_id, str)):
                raise MigrationRejected("E_C_LOCAL_NAME", "Local is unnamed, shadowed or lacks Clang identity")
            if var.get("init") is None or len(var.get("inner", [])) != 1:
                raise MigrationRejected("E_C_LOCAL_INIT", "Locals require one explicit scalar initializer")
            local_type = _decl_type(var, model)
            initial, init_type = _expr(var["inner"][0], args, model, local_type, locals)
            if init_type != local_type:
                raise MigrationRejected("E_C_LOCAL_INIT", "Local initializer changes scalar type")
            rendered.append(f"    let mut {local_name}: {local_type} = {initial};")
            locals[local_name] = (local_type, local_id)
        else:
            saw_executable = True
            rendered.extend(_stmt(item, args, model, ret, locals=locals))
    if not rendered:
        raise MigrationRejected("E_C_EMPTY", "Empty C function cannot satisfy a scalar return")
    signature = ", ".join(f"{p}: {t}" for p, t in args.items())
    # The fully closed scalar subset contains no calls, allocation, blocking,
    # suspension or task creation. Preserve these verified limits as explicit
    # Hepta resource contracts instead of relying on a comment-level claim.
    resources = "resources {heap_allocations=0;may_block=false;may_suspend=false;may_spawn=false;}"
    source = (f"export \"C\" fn {name}({signature}) -> {ret} effects {{panic}} "
              + resources + " {\n" + "\n".join(rendered) + "\n}\n")
    return {"name": name, "source": source, "params": args, "returns": ret}


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
        source = src.read_bytes()
        if len(source) > 256_000:
            raise MigrationRejected("E_C_SIZE", "Pilot source exceeds 256 KB")
        report["source_sha256"] = hashlib.sha256(source).hexdigest()
        model = _data_model(clang)
        report["target_model"] = model
        # A strict single-file source snapshot is insufficient when included
        # headers/macros influence the actual Clang AST. Bind a real -E/-P
        # preprocessing snapshot to the same compiler/target, then compare it
        # again before publishing any generated Hepta. This is not a complete
        # compilation database or external-header provenance attestation.
        preprocess_cmd = [clang, "-std=c11", "-E", "-P", str(src)]
        preprocessed_sha256 = hashlib.sha256(_run(preprocess_cmd).encode("utf-8")).hexdigest()
        report["preprocessed_sha256"] = preprocessed_sha256
        ast_json = _run([clang, "-std=c11", "-fsyntax-only", "-Werror",
                        "-Xclang", "-ast-dump=json", str(src)])
        root = _load_bounded_clang_ast(ast_json)
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
        if src.read_bytes() != source:
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
            if src.read_bytes() != source:
                raise MigrationRejected("E_C_SOURCE_RACE", "C source changed before publication")
            if hashlib.sha256(_run(preprocess_cmd).encode("utf-8")).hexdigest() != preprocessed_sha256:
                raise MigrationRejected("E_C_PREPROCESS_RACE", "Clang preprocessed source/headers changed before publication")
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
        return report


def migrate_c_project(database: str | Path, output_directory: str | Path, *,
                      contracts: dict | None = None, clang: str = "clang",
                      rustc: str | None = None, verify_native: bool = False) -> dict:
    """Migrate the bounded project profile; see docs/C_MIGRATION.md.

    This separate entry point preserves the original fail-closed scalar pilot.
    It returns a complete declaration inventory and explicit pointer contracts.
    """
    from .c_migration_project import migrate_project
    return migrate_project(database, output_directory, contracts=contracts,
                           clang=clang, rustc=rustc, verify_native=verify_native)
