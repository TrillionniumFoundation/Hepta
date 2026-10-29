"""Fail-closed Clang AST -> HSIR -> Hepta importer, scalar C subset only.

No regex source rewriting, macro expansion, pointer conversion or C++ claims.
Intentionally rejects anything outside a narrow pure-scalar, C11 subset.
"""
from __future__ import annotations

import argparse
import contextlib
from dataclasses import asdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hepta.migration_ir import Expr, Function, IRValidationError, Stmt, check_function, emit_function, function_hash  # noqa: E402
from hepta.clang_capture import CaptureRejected, run_bounded  # noqa: E402

TYPES = {"int": "i32", "unsigned int": "u32"}
_MAX_SOURCE_BYTES = 256_000
_MAX_AST_BYTES = 8_000_000
_MAX_DIAGNOSTIC_BYTES = 64_000
_CLANG_QUERY_TIMEOUT = 10.0
_CLANG_AST_TIMEOUT = 20.0
_MAX_AST_JSON_NESTING = 128
_MAX_AST_JSON_CONTAINERS = 100_000
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z", re.ASCII)
RESERVED = frozenset({"module", "import", "fn", "pub", "extern", "export", "effects", "resources", "as", "let", "mut", "take", "move", "read", "unsafe", "struct", "enum", "match", "if", "else", "return", "for", "while", "true", "false", "wrapping_add", "wrapping_sub", "wrapping_mul", "len", "assert", "main"})


class UnsupportedC(ValueError):
    def __init__(self, reason: str, *, capture_error: str | None = None):
        super().__init__(reason)
        self.capture_error = capture_error


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


def _atomic_write(path: Path, content: str, *, directory_fd: int | None = None) -> None:
    if directory_fd is not None:
        # Both staging and replacement use the directory admitted before
        # Clang. Re-resolving even a canonical pathname here would let a
        # directory rename followed by a symlink redirect either artifact.
        temporary = ".hepta-migration-" + secrets.token_hex(16)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0),
                             0o600, dir_fd=directory_fd)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as out:
                out.write(content)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, path.name, src_dir_fd=directory_fd,
                       dst_dir_fd=directory_fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        return

    # Non-POSIX fallback is not qualified against hostile directory renames.
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


def _read_bounded_source(source: Path) -> bytes:
    """Read at most the declared source budget plus one byte.

    Open non-blocking so an untrusted FIFO path cannot stall before fstat;
    only regular files are admitted. Use the same bounded read for initial
    admission and the post-Clang source-identity recheck.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(source, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise UnsupportedC("C input must be a regular file")
        return stream.read(_MAX_SOURCE_BYTES + 1)


def _run_clang(argv: list[str], *, timeout: float, stdout_limit: int,
               input_text: str | None = None):
    """Reuse the shared live byte/time budgets and process-group cleanup.

    These bounds cover each tool query as well as AST capture. Checking the
    length of a completed ``capture_output`` result is not a process budget:
    it has already retained all emitted bytes and can wait on descendants.
    This does not sandbox the compiler's filesystem effects.
    """
    try:
        result = run_bounded(argv, timeout=timeout, input_text=input_text,
                             stdin_limit=_MAX_SOURCE_BYTES if input_text is not None else 0,
                             stdout_limit=stdout_limit, stderr_limit=_MAX_DIAGNOSTIC_BYTES)
    except CaptureRejected as exc:
        raise UnsupportedC(f"{exc.code}: {exc}", capture_error=exc.code) from exc
    if result.returncode:
        raise UnsupportedC(f"Clang rejected command (exit {result.returncode}): "
                           + result.stderr[:600])
    return result


def _run_bounded_ast(args: list[str], *, timeout: float = 20,
                     max_stdout_bytes: int = _MAX_AST_BYTES,
                     context: str = "AST", input_text: str | None = None) -> subprocess.CompletedProcess:
    """Byte-preserving adapter to the shared bounded process owner.

    Overflow on either stream, timeout and cleanup errors remain rejection.
    Process-group/job cleanup and final stream checks belong to run_bounded;
    this adapter neither bypasses that owner nor turns its errors into success.
    Unlike the old pipe reader, stderr overflow is never silently truncated.
    ``context`` retains the older helper-call interface only: capture codes,
    rather than that label, determine rejection and never relax a budget.
    """
    result = _run_clang(args, timeout=timeout, stdout_limit=max_stdout_bytes,
                        input_text=input_text)
    if type(result.raw_stdout) is not bytes or type(result.raw_stderr) is not bytes:
        raise UnsupportedC("Clang capture did not retain exact raw streams")
    return subprocess.CompletedProcess(args, result.returncode,
                                       result.raw_stdout, result.raw_stderr)


def _load_clang_ast(data: bytes) -> dict:
    """Reject ambiguous, deeply nested, or malformed bounded AST JSON.

    A bounded stdout byte count alone is not a shape/recursion budget: an
    alternate Clang executable can produce JSON that raises RecursionError
    or non-JSON object shapes that escape the normal rejection report.
    This guard runs before recursively translating Clang AST expressions.
    """
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise UnsupportedC("Clang AST JSON contains duplicate keys")
            obj[key] = value
        return obj

    def reject_nonfinite_constant(value: str) -> None:
        # json.loads accepts NaN/Infinity by default, unlike strict JSON.
        raise ValueError("non-finite Clang AST JSON constant")

    def finite_json_float(value: str) -> float:
        parsed = float(value)
        # A valid JSON number such as 1e9999 also overflows to infinity.
        if not math.isfinite(parsed):
            raise ValueError("non-finite Clang AST JSON number")
        return parsed

    try:
        tree = json.loads(data, object_pairs_hook=unique_object,
                          parse_constant=reject_nonfinite_constant,
                          parse_float=finite_json_float)
    except UnsupportedC:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise UnsupportedC("Clang AST JSON malformed or excessively nested") from exc
    if (not isinstance(tree, dict) or tree.get("kind") != "TranslationUnitDecl"
            or not isinstance(tree.get("inner"), list)):
        raise UnsupportedC("Clang AST translation unit has invalid shape")

    pending = [(tree, 0)]
    examined = 0
    while pending:
        value, depth = pending.pop()
        examined += 1
        if depth > _MAX_AST_JSON_NESTING or examined > _MAX_AST_JSON_CONTAINERS:
            raise UnsupportedC("Clang AST JSON structural budget exceeded")
        if isinstance(value, dict):
            # Syntax-valid JSON is not necessarily a Clang-shaped AST. These
            # fields are dereferenced by the recursive scalar importer; a
            # wrong container/value type must produce a rejection report,
            # not an uncaught AttributeError, TypeError or KeyError.
            if "inner" in value:
                if not isinstance(value["inner"], list):
                    raise UnsupportedC("Clang AST child array has invalid shape")
                for node in value["inner"]:
                    if not isinstance(node, dict):
                        # Preserve the public rejection reason for malformed
                        # translation-unit children from the prior gate.
                        if value is tree:
                            raise UnsupportedC("Clang AST top-level child has invalid shape")
                        raise UnsupportedC("Clang AST child node has invalid shape")
                    if not isinstance(node.get("kind"), str):
                        raise UnsupportedC("Clang AST child node has invalid shape")
            if "kind" in value and not isinstance(value["kind"], str):
                raise UnsupportedC("Clang AST node kind has invalid shape")
            if "type" in value:
                ty = value["type"]
                if not isinstance(ty, dict) or (
                        "qualType" in ty and not isinstance(ty["qualType"], str)):
                    raise UnsupportedC("Clang AST type metadata has invalid shape")
            if "referencedDecl" in value and not isinstance(value["referencedDecl"], dict):
                raise UnsupportedC("Clang AST referenced declaration has invalid shape")
            for field, label in (("name", "node name"),
                                 ("storageClass", "storage class"),
                                 ("castKind", "cast kind"),
                                 ("opcode", "opcode")):
                if field in value and not isinstance(value[field], str):
                    raise UnsupportedC("Clang AST " + label + " has invalid shape")
            children = value.values()
        else:
            children = value
        for child in children:
            if isinstance(child, (dict, list)):
                pending.append((child, depth + 1))
    return tree


def _probe_clang(args: list[str], *, label: str, max_stdout_bytes: int = 16_384) -> bytes:
    """Use the same live budgets and cleanup contract for metadata probes."""
    run = _run_bounded_ast(args, timeout=_CLANG_QUERY_TIMEOUT,
                           max_stdout_bytes=max_stdout_bytes, context="probe")
    if not run.stdout.strip():
        raise UnsupportedC("Clang returned an empty " + label)
    return run.stdout


def _pin_artifact_parent(path: Path) -> int:
    """Open the admitted canonical artifact parent before external execution."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    return os.open(path.parent, flags)


def migrate(source: Path, output: Path, report: Path, clang: str = "clang",
            verify_native: bool = False, rustc: str | None = None) -> dict:
    resolved = (source.resolve(), output.resolve(), report.resolve())
    if len(set(resolved)) != 3:
        raise UnsupportedC("source, output and report paths must be distinct")
    if os.name != "posix":
        return _migrate_impl(source, output, report, clang, verify_native, rustc,
                             admitted_paths=resolved)
    with contextlib.ExitStack() as resources:
        descriptors = []
        for destination in resolved[1:]:
            descriptor = _pin_artifact_parent(destination)
            resources.callback(os.close, descriptor)
            descriptors.append(descriptor)
        return _migrate_impl(source, output, report, clang, verify_native, rustc,
                             admitted_paths=resolved,
                             publication_fds=(descriptors[0], descriptors[1]))


def _migrate_impl(source: Path, output: Path, report: Path, clang: str,
                  verify_native: bool, rustc: str | None, *,
                  admitted_paths: tuple[Path, Path, Path],
                  publication_fds: tuple[int, int] | None = None) -> dict:
    # Enforce the CLI path-isolation gate for direct library callers as well.
    # Otherwise a rejected conversion can overwrite the original C source
    # when the report path aliases it (including through a parent symlink).
    # Keep the same admission tuple that owns publication_fds. Re-resolving
    # between directory pinning and this function would bind paths from a
    # different filesystem state to those descriptors.
    admitted_source, admitted_output, admitted_report = admitted_paths
    try:
        original = _read_bounded_source(source)
        read_error = None
    except (OSError, UnsupportedC) as exc:
        original = None
        read_error = str(exc)
    # An oversized file was sampled only up to the explicit admission cap.
    # Never publish a prefix digest as the complete source identity.
    digest = (hashlib.sha256(original).hexdigest()
              if original is not None and len(original) <= _MAX_SOURCE_BYTES else None)
    info = {"schema": "hepta.c2hepta.v0", "source": str(admitted_source),
            "source_sha256": digest, "status": "rejected", "safety": "not_qualified",
            "functions": [], "frontend_validation": "not_run", "backend_validation": "not_run", "clang": "not_run"}
    converted: list[Function] = []
    try:
        if read_error is not None:
            raise UnsupportedC("cannot read C input: " + read_error)
        if len(original) > _MAX_SOURCE_BYTES:
            raise UnsupportedC("pilot input limit is 256 KB")
        if output.is_symlink() or report.is_symlink():
            raise UnsupportedC("symlink output/report paths are not accepted")
        if source.suffix != ".c":
            raise UnsupportedC("only C11 .c translation units are supported")
        if re.search(rb"(?m)^\s*#", original):
            raise UnsupportedC("preprocessor directives/macros require a future source model")
        if not shutil.which(clang):
            raise UnsupportedC("clang executable unavailable")
        version = _probe_clang([clang, "--version"], label="version")
        version_lines = version.decode("utf-8").splitlines()
        if not version_lines or not version_lines[0].strip():
            raise UnsupportedC("Clang returned an empty version")
        info["clang"] = version_lines[0]
        target = _probe_clang([clang, "-dumpmachine"], label="target")
        info["target"] = target.decode("utf-8").strip()
        defines = _probe_clang([clang, "-std=c11", "-dM", "-E", "-x", "c", "-"],
                               label="predefined macros", max_stdout_bytes=256_000)
        # Normalize metadata line endings only; the AST and admitted source
        # keep the actual raw bytes supplied by the shared capture layer.
        defines = defines.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        if not re.search(r"(?m)^#define __SIZEOF_INT__ 4$", defines) or not re.search(r"(?m)^#define __CHAR_BIT__ 8$", defines):
            raise UnsupportedC("the Clang target's int/char width is unsupported")
        # A pre/post digest alone misses an A -> B -> A source-path swap.
        # The scalar subset excludes includes and preprocessor directives,
        # so Clang can parse the exact admitted UTF-8 bytes on bounded stdin.
        source_text = original.decode("utf-8")
        info["clang_input"] = {"transport": "captured_source_stdin",
                               "sha256": digest, "bytes": len(original)}
        run = _run_bounded_ast([clang, "-x", "c", "-std=c11", "-Wall", "-Wextra", "-Werror",
                                "-pedantic-errors", "-Wno-newline-eof", "-fsyntax-only",
                                "-Xclang", "-ast-dump=json", "-fno-color-diagnostics", "-"],
                               timeout=_CLANG_AST_TIMEOUT, max_stdout_bytes=_MAX_AST_BYTES,
                               input_text=source_text)
        tree = _load_clang_ast(run.stdout)
        nodes = []
        for node in tree["inner"]:
            loc = node.get("loc", {})
            if not isinstance(loc, dict):
                raise UnsupportedC("Clang AST source location has invalid shape")
            if loc.get("offset") is not None:
                nodes.append(node)
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
        if hashlib.sha256(_read_bounded_source(source)).hexdigest() != digest:
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
        if output.resolve() != admitted_output or report.resolve() != admitted_report:
            raise UnsupportedC("output or report path binding changed during conversion")
        _atomic_write(admitted_output, emitted,
                      directory_fd=publication_fds[0] if publication_fds else None)
        info.update(status="converted", safety="static_memory_safe_scalar_subset",
                    output_sha256=hashlib.sha256(emitted.encode()).hexdigest(),
                    note="This is a finite syntax translation, NOT a proof of semantic equivalence, native compilation, or whole-language soundness.")
    except (UnsupportedC, IRValidationError, OSError, subprocess.SubprocessError, ValueError) as exc:
        info["reason"] = str(exc)
        if isinstance(exc, CaptureRejected):
            info["capture_error"] = exc.code
        elif isinstance(exc, UnsupportedC) and exc.capture_error is not None:
            info["capture_error"] = exc.capture_error
    if report.is_symlink():
        raise ValueError("refusing to overwrite a symlink report path")
    # A rejection report must also stay inside its pinned directory, even
    # after a parent symlink or canonical directory has been rebound.
    _atomic_write(admitted_report, json.dumps(info, sort_keys=True, indent=2) + "\n",
                  directory_fd=publication_fds[1] if publication_fds else None)
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
