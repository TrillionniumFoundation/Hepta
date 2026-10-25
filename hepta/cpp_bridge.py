"""Experimental P4 C++ -> C ABI wrapper for unoverloaded int functions.

L0 foreign interop only: native C++ implementation is not validated as safe.
The default `noexcept_only` profile preserves the v0 wrapper contract. The
opt-in `catch_status` profile catches C++ exceptions at the C boundary, uses
an explicit out parameter and returns status, without preserving exception
identity or claiming ownership, lifetime, or general C++ ABI qualification.
Do not execute Clang on untrusted code without an OS sandbox.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .c2hepta import MAX_AST_BYTES, MAX_SOURCE_BYTES, MigrationRejected, _children, _ident


@dataclass(frozen=True)
class CppBridge:
    source: str
    c_header: str
    report: dict


def _reject(node: dict, reason: str) -> None:
    loc = node.get("loc", node.get("range", {}).get("begin", {}))
    raise MigrationRejected(f"E_CPP_BRIDGE_UNSUPPORTED {node.get('kind', 'unknown')} "
                            f"at {loc.get('line', '?')}:{loc.get('col', '?')}: {reason}")


def generate_cpp_bridge(path: str | Path, *, clangxx: str = "clang++",
                        exception_mode: str = "noexcept_only") -> CppBridge:
    """Generate C-compatible wrapper definitions for a closed source subset."""
    if exception_mode not in {"noexcept_only", "catch_status"}:
        raise MigrationRejected("E_CPP_BRIDGE_MODE: Unsupported exception mode")
    original = Path(path).resolve(strict=True)
    data = original.read_bytes()
    if len(data) > MAX_SOURCE_BYTES:
        raise MigrationRejected("E_CPP_BRIDGE_LIMIT: C++ source exceeds 256 KiB")
    try:
        raw = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MigrationRejected("E_CPP_BRIDGE_ENCODING: UTF-8 required") from exc
    if re.search(r"(?m)^\s*#", raw):
        raise MigrationRejected("E_CPP_BRIDGE_PREPROCESSOR: Includes/macros require a compilation database")
    if not shutil.which(clangxx):
        raise MigrationRejected("E_CPP_BRIDGE_TOOLCHAIN: clang++ not found")
    cmd = [clangxx, "-x", "c++", "-std=c++20", "-Werror", "-ferror-limit=3",
           "-fsyntax-only", "-Xclang", "-ast-dump=json", str(original)]
    try:
        with tempfile.TemporaryFile() as out:
            proc = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE, timeout=15, check=False)
            out.seek(0)
            ast_payload = out.read(MAX_AST_BYTES + 1)
    except subprocess.TimeoutExpired as exc:
        raise MigrationRejected("E_CPP_BRIDGE_TOOLCHAIN: clang++ timed out") from exc
    if proc.returncode:
        raise MigrationRejected("E_CPP_BRIDGE_CLANG: C++ source rejected: " + proc.stderr[:1024].decode("utf-8", "replace"))
    if len(ast_payload) > MAX_AST_BYTES:
        raise MigrationRejected("E_CPP_BRIDGE_LIMIT: AST exceeds 8 MiB")
    try:
        tree = json.loads(ast_payload)
    except ValueError as exc:
        raise MigrationRejected("E_CPP_BRIDGE_AST: Invalid JSON") from exc
    if tree.get("kind") != "TranslationUnitDecl":
        raise MigrationRejected("E_CPP_BRIDGE_AST: Unexpected AST root")
    macro_probe = subprocess.run([clangxx, "-dM", "-E", "-x", "c++", "-"], input="",
                                 capture_output=True, text=True, timeout=5, check=False)
    if (macro_probe.returncode
            or not re.search(r"(?m)^#define __SIZEOF_INT__ 4$", macro_probe.stdout)
            or not re.search(r"(?m)^#define __CHAR_BIT__ 8$", macro_probe.stdout)):
        raise MigrationRejected("E_CPP_BRIDGE_ABI: target requires 32-bit int and 8-bit bytes")
    compiler_version = subprocess.run([clangxx, "--version"], capture_output=True, text=True,
                                      timeout=5, check=False).stdout.splitlines()[0]
    source_lines = ["// Experimental L0 C++ bridge; foreign body is not verified safe."]
    prototypes = ["#pragma once", "#ifdef __cplusplus", 'extern "C" {', "#endif"]
    seen = set()
    for node in _children(tree):
        if "offset" not in node.get("loc", {}):
            continue
        if node.get("kind") != "FunctionDecl":
            _reject(node, "only top-level free functions are supported")
        typ = node.get("type", {}).get("qualType", "")
        pattern = (r"int \((?:int(?:, int)*)?\) noexcept" if exception_mode == "noexcept_only"
                   else r"int \((?:int(?:, int)*)?\)(?: noexcept)?")
        if not re.fullmatch(pattern, typ):
            _reject(node, "only signed int(int...) free functions matching selected exception mode are supported")
        if node.get("storageClass") or node.get("inline") or node.get("constexpr") or node.get("variadic"):
            _reject(node, "special storage/linkage/constexpr/variadic functions are unsupported")
        children = _children(node)
        if any(x.get("kind") not in {"ParmVarDecl", "CompoundStmt"} for x in children):
            _reject(node, "function attributes or unsupported declarations are present")
        if sum(x.get("kind") == "CompoundStmt" for x in children) != 1:
            _reject(node, "the function must be defined in this translation unit")
        name = _ident(node.get("name"), node)
        if name in seen:
            _reject(node, "overloaded/duplicate function names are unsupported")
        seen.add(name)
        params = [x for x in children if x.get("kind") == "ParmVarDecl"]
        names = []
        for param in params:
            # Preserve no argument default or attribute implicitly: function
            # signatures are a strict ABI/semantics boundary.
            if param.get("init") is not None or _children(param):
                _reject(param, "default arguments and parameter attributes are unsupported")
            if param.get("type", {}).get("qualType") != "int":
                _reject(param, "only plain signed int value parameters are supported")
            arg = _ident(param.get("name"), param)
            if arg in names:
                _reject(param, "duplicate argument")
            names.append(arg)
        formal = ", ".join("int " + n for n in names) or "void"
        actual = ", ".join(names)
        wrapper = "hepta_cxx_" + name
        extern_formal = ", ".join("int " + n for n in names) or ""
        noexcept = " noexcept" if typ.endswith(" noexcept") else ""
        if exception_mode == "catch_status":
            # Error/throw leaves *result_out untouched. Status=2 is reserved.
            with_out = (extern_formal + ", " if extern_formal else "") + "int *result_out"
            header_formal = (formal + ", " if names else "") + "int *result_out"
            source_lines.extend([f"extern int {name}({formal}){noexcept};",
                                 f'extern "C" int {wrapper}({with_out}) noexcept {{',
                                 "    if (result_out == nullptr) return -1;",
                                 "    try {",
                                 f"        int result = {name}({actual});",
                                 "        *result_out = result;",
                                 "        return 0;",
                                 "    } catch (...) {",
                                 "        return 1;",
                                 "    }",
                                 "}", ""])
            prototypes.append(f"int {wrapper}({header_formal});")
        else:
            source_lines.extend([f"extern int {name}({formal}) noexcept;",
                                 f'extern "C" int {wrapper}({extern_formal}) noexcept {{',
                                 f"    return {name}({actual});", "}", ""])
            prototypes.append(f"int {wrapper}({formal});")
    if not seen:
        raise MigrationRejected("E_CPP_BRIDGE_EMPTY: No supported functions")
    prototypes += ["#ifdef __cplusplus", "}", "#endif", ""]
    if original.read_bytes() != data:
        raise MigrationRejected("E_CPP_BRIDGE_RACE: Source changed during Clang analysis")
    result = "\n".join(source_lines)
    header = "\n".join(prototypes)
    report = {
        "schema": "hepta.cpp-bridge.v1" if exception_mode == "catch_status" else "hepta.cpp-bridge.v0",
        "status": "candidate_unverified", "ok": True,
        "interop_level": "L0", "foreign_cpp_memory_safe": False,
        "exception_translation": ("status_without_exception_payload" if exception_mode == "catch_status"
                                  else "not_implemented"),
        "exception_mode": exception_mode, "c_abi_qualified": False,
        "exception_crosses_c_abi": False if exception_mode == "catch_status" else "caller_assumed_noexcept",
        "cpp_abi_qualified": False, "runtime_performance_checked": False,
        "clangxx": compiler_version, "symbols": sorted(seen),
        "source_sha256": sha256(data).hexdigest(),
        "bridge_sha256": sha256(result.encode()).hexdigest(),
        "header_sha256": sha256(header.encode()).hexdigest(),
        "assumptions": ["Original source is built separately with a compatible target C++ ABI",
                        ("C++ exception unwinding is enabled; throw maps to status 1; null output to -1; "
                         "on failure output is untouched; exception types and values are discarded"
                         if exception_mode == "catch_status" else
                         "Every selected foreign function obeys its noexcept contract"),
                        "No classes/templates/overloads/headers or object pointers cross the bridge",
                        "Foreign C++ implementation, side effects and object lifetime remain unverified",
                        "Separate actual C and C++ compiler caller/callee tests are required"],
    }
    return CppBridge(result, header, report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate narrow L0 C++ -> C ABI wrappers")
    parser.add_argument("source")
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--exception-mode", choices=["noexcept_only", "catch_status"],
                        default="noexcept_only")
    args = parser.parse_args(argv)
    try:
        target = Path(args.output_dir).resolve()
        if target.exists():
            raise MigrationRejected("E_CPP_BRIDGE_OUTPUT: Output directory must not exist")
        target.parent.mkdir(parents=True, exist_ok=True)
        result = generate_cpp_bridge(args.source, clangxx=args.clangxx,
                                     exception_mode=args.exception_mode)
        # A no-replace rename of a nonempty directory is available via Linux
        # renameat2; this portable prototype instead requires a dedicated
        # output directory and explicitly calls out non-atomic publication.
        target.mkdir(exist_ok=False)
        try:
            (target / "bridge.cc").write_text(result.source)
            (target / "bridge.h").write_text(result.c_header)
            (target / "manifest.json").write_text(json.dumps(result.report, indent=2, sort_keys=True) + "\n")
        except OSError:
            for f in target.iterdir():
                f.unlink(missing_ok=True)
            target.rmdir()
            raise
        print(json.dumps({**result.report, "output_dir": str(target)}, indent=2, sort_keys=True))
        return 0
    except (MigrationRejected, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"schema": "hepta.cpp-bridge.v0", "ok": False,
                          "status": "rejected", "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
