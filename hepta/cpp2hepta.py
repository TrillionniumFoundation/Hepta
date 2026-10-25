"""Strict C++20 noexcept-i32 function migration via the existing C lowering core.

Not a C++ compiler, full AST migration, L2/L3 proof or C++ ABI bridge.
The Clang-confirmed C++ expression subset is deliberately passed through
hepta.c_migrate._function: there is ONE scalar expression lowering authority
for both migrations rather than a forked C++ expression reimplementation.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import tempfile

from .c_migrate import MigrationRejected, _function, _run
from .checker import check
from .parser import parse

_PROFILE = "cpp20-noexcept-i32-free-functions-canonical-c-scalar-l1"
_MAX_SOURCE = 256_000
# Only explicitly modeled primitive scalar ABI forms are admitted; mixed signatures still require checked expression typing.
# Overflowing signed C++ arithmetic remains outside the defined-input domain.
_CPP_SCALAR = r"(?:int|unsigned int|long long|unsigned long long)"
_FUNCTION = re.compile(rf"{_CPP_SCALAR} \((?:{_CPP_SCALAR}(?:, {_CPP_SCALAR})*)?\) noexcept\Z")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")


def _model(clangxx: str) -> dict:
    macros = _run([clangxx, "-x", "c++", "-std=c++20", "-dM", "-E", "-"], input_text="")
    dims = dict(re.findall(r"(?m)^#define (__SIZEOF_(?:INT|LONG|LONG_LONG|POINTER)__)\s+(\d+)\s*$", macros))
    bit = re.search(r"(?m)^#define __CHAR_BIT__\s+(\d+)\s*$", macros)
    if (dims.get("__SIZEOF_INT__") != "4" or dims.get("__SIZEOF_LONG_LONG__") != "8"
            or dims.get("__SIZEOF_POINTER__") != "8"
            or dims.get("__SIZEOF_LONG__") not in {"4", "8"}
            or bit is None or bit.group(1) != "8"):
        raise MigrationRejected("E_CPP2HEPTA_MODEL", "L1 requires an 8-bit-byte, 64-bit-pointer host with 32-bit int and 64-bit long long")
    target = _run([clangxx, "-dumpmachine"]).strip()
    arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(platform.machine().lower(), platform.machine().lower())
    triple_arch = {"arm64": "aarch64", "amd64": "x86_64"}.get(target.split("-")[0], target.split("-")[0])
    system = platform.system()
    host_os = {"Windows": ("windows", "mingw"), "Darwin": ("darwin", "apple"),
               "Linux": ("linux",)}.get(system, ())
    if arch not in {"x86_64", "aarch64"} or triple_arch != arch or not any(part in target.lower() for part in host_os):
        raise MigrationRejected("E_CPP2HEPTA_TARGET", "C++ Clang target must match the actual qualified native host")
    return {"sizeof_int": 4, "sizeof_long": int(dims["__SIZEOF_LONG__"]),
            "sizeof_long_long": 8, "sizeof_pointer": 8,
            "target": target,
            "clang_version": _run([clangxx, "--version"]).splitlines()[0]}


def migrate_cpp(source_file: str | Path, destination_file: str | Path, *,
                clangxx: str = "clang++") -> dict:
    """Publish one frontend-checked candidate if and only if the full input fits L1.

    Output is never confused with the original mangled C++ ABI.
    """
    source = Path(source_file).resolve()
    # Do not dereference final output leaf symlinks (including dangling ones).
    output = Path(os.path.abspath(destination_file))
    report = {"schema": "hepta.migrate-cpp-l1.v0", "status": "rejected", "ok": False,
              "tier": "L1", "profile": _PROFILE, "source": str(source), "output": str(output),
              "converted": [], "rejected": [], "cpp_abi_preserved": False,
              "behavioral_equivalence_proved": False,
              "whole_language_memory_safety_proved": False,
              "foreign_cpp_memory_safe": False,
              "native_validation": "not_run", "differential_validation": "not_run"}
    try:
        if (source.suffix not in {".cc", ".cpp", ".cxx"} or not source.is_file()
                or source == output or output.suffix != ".hepta" or output.is_symlink()):
            raise MigrationRejected("E_CPP2HEPTA_PATH", "Require existing C++ source and distinct ordinary .hepta output")
        original = source.read_bytes()
        if len(original) > _MAX_SOURCE:
            raise MigrationRejected("E_CPP2HEPTA_SIZE", "Source is outside bounded AST pilot")
        text = original.decode("utf-8")
        # Without the actual C++ build flags, includes/conditionals/macros are
        # not a reproducible source graph and must never be silently omitted.
        # C++ digraph %: is an alternative '#' preprocessing token. Directives
        # can also appear after comments or be assembled by a line splice.
        # This bounded L1 profile does not capture preprocessor state.
        if "#" in text or "%:" in text or re.search(r"\\\r?\n", text):
            raise MigrationRejected("E_CPP2HEPTA_PREPROCESSOR", "Build-dependent preprocessing requires a real C++ project migrator")
        resolved = shutil.which(clangxx)
        if resolved is None:
            raise MigrationRejected("E_CPP2HEPTA_TOOLCHAIN", "C++ Clang compiler unavailable")
        compiler = Path(resolved).resolve(strict=True)
        compiler_digest = sha256(compiler.read_bytes()).hexdigest()
        model = _model(str(compiler))
        model["compiler_sha256"] = compiler_digest
        tree = json.loads(_run([str(compiler), "-x", "c++", "-std=c++20", "-Werror", "-fsyntax-only",
                                "-Xclang", "-ast-dump=json", str(source)]))
        if not isinstance(tree, dict) or tree.get("kind") != "TranslationUnitDecl":
            raise MigrationRejected("E_CPP2HEPTA_AST", "Clang++ AST root was not a translation unit")
        defs = []
        invalid = []
        for node in tree.get("inner", []):
            location = node.get("loc", {})
            # Builtin type declarations do not have a source offset.
            if not isinstance(location.get("offset"), int):
                continue
            start = node.get("range", {}).get("begin", {}).get("offset")
            end = node.get("range", {}).get("end", {}).get("offset")
            if not isinstance(start, int) or not isinstance(end, int) or not (0 <= start <= end < len(original)):
                raise MigrationRejected("E_CPP2HEPTA_LOCATION", "Clang source declaration cannot be accounted for")
            if node.get("kind") != "FunctionDecl":
                invalid.append({"kind": node.get("kind"), "name": node.get("name")})
                continue
            typename = node.get("type", {}).get("qualType", "")
            if not _FUNCTION.fullmatch(typename):
                invalid.append({"kind": "unsupported_function_type", "name": node.get("name")})
                continue
            if (node.get("storageClass") or node.get("inline") or node.get("constexpr")
                    or node.get("variadic") or node.get("isImplicit")):
                invalid.append({"kind": "unsupported_function_storage", "name": node.get("name")})
                continue
            children = node.get("inner", [])
            params = [ch for ch in children if ch.get("kind") == "ParmVarDecl"]
            # A default parameter changes callable arity even if its function
            # body is simple. Clang C++ attributes can have side effects or
            # restrict calling contracts; reject them rather than deleting.
            if any(p.get("init") is not None or p.get("inner") for p in params):
                invalid.append({"kind": "parameter_default_or_attribute", "name": node.get("name")})
                continue
            if len([c for c in children if c.get("kind") == "CompoundStmt"]) != 1:
                invalid.append({"kind": "missing_or_multiple_body", "name": node.get("name")})
                continue
            defs.append(node)
        if invalid:
            raise MigrationRejected("E_CPP2HEPTA_TOPLEVEL", "Unsupported active C++ declarations: "+json.dumps(invalid[:12]))
        if not defs:
            raise MigrationRejected("E_CPP2HEPTA_EMPTY", "No source-level noexcept integer function body")
        names = set()
        translated = []
        for fn in defs:
            name = fn.get("name")
            if not isinstance(name, str) or not _IDENT.fullmatch(name) or name in names:
                raise MigrationRejected("E_CPP2HEPTA_DUPLICATE", "Duplicate/unrepresentable C++ symbol")
            names.add(name)
            # _function handles only explicit scalar parameters, returns,
            # conditions and expressions. Unexpected AST features are rejected.
            # A strict C++ source uses the shared C expression lowering rules.
            converted = _function(fn, model)
            translated.append(converted)
        program = "module cpp_migrated;\n\n// L1 only; C++ mangled ABI not preserved.\n" + "\n".join(x["source"] for x in translated)
        candidate = parse(program, str(output))
        checking = check(candidate)
        if not checking.ok:
            report["rejected"] = [d.to_dict() for d in checking.diagnostics]
            report["status"] = "hepta_frontend_rejected"
            return report
        if source.read_bytes() != original:
            raise MigrationRejected("E_CPP2HEPTA_RACE", "Source changed during Clang translation")
        if sha256(compiler.read_bytes()).hexdigest() != compiler_digest:
            raise MigrationRejected("E_CPP2HEPTA_TOOLCHAIN_RACE", "C++ compiler changed during migration")
        if output.exists() or output.is_symlink():
            raise MigrationRejected("E_CPP2HEPTA_EXISTS", "Output already exists")
        if not output.parent.is_dir():
            raise MigrationRejected("E_CPP2HEPTA_PATH", "Output parent must exist")
        staged = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent,
                                             prefix=".cpp2hepta-", delete=False) as f:
                staged = Path(f.name)
                f.write(program)
                f.flush()
                os.fsync(f.fileno())
            if source.read_bytes() != original:
                raise MigrationRejected("E_CPP2HEPTA_RACE", "Source changed before publish")
            if sha256(compiler.read_bytes()).hexdigest() != compiler_digest:
                raise MigrationRejected("E_CPP2HEPTA_TOOLCHAIN_RACE", "C++ compiler changed before publication")
            try:
                os.link(staged, output)
            except FileExistsError as exc:
                raise MigrationRejected("E_CPP2HEPTA_EXISTS", "Output appeared during publication") from exc
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)
        report.update({"ok": True, "status": "frontend_checked_not_native_qualified",
                       "target_model": model, "source_sha256": sha256(original).hexdigest(),
                       "output_sha256": sha256(program.encode()).hexdigest(),
                       "converted": [{k: v for k, v in x.items() if k != "source"} for x in translated]})
        return report
    except (MigrationRejected, UnicodeError, ValueError, OSError) as exc:
        report["rejected"].append({"code": getattr(exc, "code", "E_CPP2HEPTA_INPUT"), "message": str(exc)})
        return report
