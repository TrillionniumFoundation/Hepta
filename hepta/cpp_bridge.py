"""Experimental C++ opaque-handle bridge for one flat non-template class.

The generated ABI deliberately uses integer handles rather than pointers.
A mutex serializes bridge calls and rejects stale handles. Native C++ code,
callbacks and foreign thread effects remain external trust assumptions; this
module DOES NOT certify a C++ library as memory-safe or race-free.
"""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import ExitStack
from pathlib import Path
import re
import subprocess
import tempfile

from .c_migrate import MigrationRejected, _data_model, _IDENT, _run, _typ


def _class_model(clang: str) -> dict:
    # Clang++ uses the same hosted target ABI profile as C for scalar types,
    # but the version/target are measured from the selected C++ compiler.
    model = _data_model(clang)
    model["compiler"] = "clang++"
    return model


def _header_class(header: Path, class_name: str, clang: str) -> dict:
    # Filter inside Clang before serializing: modern <atomic>/<vector> headers
    # otherwise produce tens of MB of irrelevant JSON. The filter is a name
    # substring, so exact name, source and declaration-kind checks still apply.
    text = _run([clang, "-x", "c++-header", "-std=c++20", "-fsyntax-only", "-Werror",
                 "-Xclang", "-ast-dump=json", "-Xclang",
                 "-ast-dump-filter=" + class_name, str(header)])
    # A filtered dump can be several concatenated JSON documents. Do not
    # assume one TranslationUnitDecl or search nested template records.
    decoder = json.JSONDecoder()
    declarations = []
    rest = text.lstrip()
    while rest:
        decl, end = decoder.raw_decode(rest)
        declarations.append(decl)
        if len(declarations) > 4096:
            raise MigrationRejected("E_CPP_CLASS", "Too many filtered C++ declarations")
        rest = rest[end:].lstrip()
    candidates = []
    active_file = None
    for decl in declarations:
        locfile = decl.get("loc", {}).get("file")
        if locfile:
            active_file = Path(locfile).resolve()
        if (active_file == header and decl.get("kind") == "CXXRecordDecl"
                and decl.get("completeDefinition") and decl.get("name") == class_name):
            candidates.append(decl)
    if len(candidates) != 1:
        raise MigrationRejected("E_CPP_CLASS", "Expected exactly one complete, top-level, non-template class in this header")
    if candidates[0].get("bases") or candidates[0].get("definitionData", {}).get("isAbstract"):
        raise MigrationRejected("E_CPP_HIERARCHY", "Inheritance and abstract C++ classes are not in the bridge subset")
    return candidates[0]


def _class_methods(decl: dict, model: dict) -> list[dict]:
    access = "public" if decl.get("tagUsed") == "struct" else "private"
    ctor = False
    dtor = False
    methods = []
    seen = set()
    for member in decl.get("inner", []):
        kind = member.get("kind")
        if kind == "AccessSpecDecl":
            access = member.get("access", "private")
            continue
        if access != "public" or member.get("isImplicit"):
            continue
        if kind == "CXXConstructorDecl":
            if member.get("type", {}).get("qualType") == "void ()" and not member.get("inner"):
                ctor = True
            elif member.get("type", {}).get("qualType") == "void ()":
                ctor = True
            continue
        if kind == "CXXDestructorDecl":
            if "noexcept(false)" not in member.get("type", {}).get("qualType", ""):
                dtor = True
            continue
        if kind != "CXXMethodDecl":
            continue
        name = member.get("name", "")
        if not _IDENT.fullmatch(name) or name in seen or name.startswith("operator"):
            raise MigrationRejected("E_CPP_METHOD", "Overload, operator or unsupported C++ method name")
        seen.add(name)
        if (member.get("storageClass") or member.get("virtual") or member.get("isStatic")
                or member.get("constexpr") and not member.get("type", {}).get("qualType")):
            raise MigrationRejected("E_CPP_METHOD", "Static, virtual or unsupported special methods cannot be bridged")
        t = member.get("type", {}).get("qualType", "")
        if "(" not in t or "..." in t:
            raise MigrationRejected("E_CPP_METHOD", "Missing non-variadic scalar method type")
        ret = _typ(t.split("(", 1)[0], model)
        params = [p for p in member.get("inner", []) if p.get("kind") == "ParmVarDecl"]
        if len(params) > 16:
            raise MigrationRejected("E_CPP_METHOD", "Too many method arguments")
        args = []
        for index, p in enumerate(params):
            args.append((f"arg{index}", _typ(p.get("type", {}).get("qualType", ""), model),
                         p.get("type", {}).get("qualType", "")))
        methods.append({"name": name, "ret": ret,
                        "c_return": t.split("(", 1)[0].strip(), "args": args})
    if not ctor or not dtor:
        raise MigrationRejected("E_CPP_LIFETIME", "Requires an explicit public zero-argument constructor and non-throwing destructor")
    if not methods:
        raise MigrationRejected("E_CPP_METHOD", "Requires at least one public scalar instance method")
    return methods


def _generate_cpp(header: Path, cls: str, methods: list[dict]) -> str:
    name = "hepta_cpp_" + cls
    lines = [
        "// Generated opaque-handle bridge. Foreign C++ internals are unverified.",
        "// The registry lock is never held while executing foreign C++ code.",
        "#include " + json.dumps(str(header)),
        "#include <cstdint>", "#include <memory>", "#include <mutex>",
        "#include <unordered_map>", "#include <utility>",
        "namespace {",
        "struct hepta_bridge_entry {",
        "    std::recursive_mutex call_mutex;",
        f"    std::shared_ptr<{cls}> object;",
        "};",
        "std::mutex hepta_registry_mutex;",
        "std::unordered_map<std::uint64_t, std::shared_ptr<hepta_bridge_entry>> hepta_objects;",
        "std::uint64_t hepta_next_handle = 1;",
        "}",
        f'extern "C" std::int32_t {name}_new(std::uint64_t* out) noexcept {{',
        "    if (!out) return 1;",
        "    try {",
        "        auto entry = std::make_shared<hepta_bridge_entry>();",
        f"        entry->object = std::make_shared<{cls}>();",
        "        std::lock_guard<std::mutex> lock(hepta_registry_mutex);",
        "        if (hepta_next_handle == 0) return 4;",
        "        auto handle = hepta_next_handle++;",
        "        // Retain a local owner if map allocation fails: foreign destruction",
        "        // must happen after the registry lock is released, even on failure.",
        "        auto inserted = hepta_objects.emplace(handle, entry);",
        "        if (!inserted.second) return 4;",
        "        *out = handle;", "        return 0;",
        "    } catch (...) { return 3; }", "}",
        f'extern "C" std::int32_t {name}_destroy(std::uint64_t handle) noexcept {{',
        "    std::shared_ptr<hepta_bridge_entry> entry;",
        "    try {",
        "        {",
        "            std::lock_guard<std::mutex> lock(hepta_registry_mutex);",
        "            auto it = hepta_objects.find(handle);",
        "            if (it == hepta_objects.end()) return 2;",
        "            entry = std::move(it->second);",
        "            hepta_objects.erase(it);",
        "        }",
        "        // Wait for ordinary in-flight calls. Reentrant destruction retains",
        "        // the method's local shared_ptr until that method returns.",
        "        std::lock_guard<std::recursive_mutex> lock(entry->call_mutex);",
        "        entry->object.reset();", "        return 0;",
        "    } catch (...) { return 3; }", "}",
    ]
    for m in methods:
        args = ", ".join(f"{ctyp} {param}" for param, _, ctyp in m["args"])
        full = (", " + args) if args else ""
        call = ", ".join(param for param, _, _ in m["args"])
        lines.extend([
            f'extern "C" std::int32_t {name}_{m["name"]}(std::uint64_t handle{full}, {m["c_return"]}* out) noexcept {{',
            "    if (!out) return 1;",
            "    try {",
            "        std::shared_ptr<hepta_bridge_entry> entry;",
            "        {",
            "            std::lock_guard<std::mutex> lock(hepta_registry_mutex);",
            "            auto it = hepta_objects.find(handle);",
            "            if (it == hepta_objects.end()) return 2;",
            "            entry = it->second;",
            "        }",
            "        // Only calls on the *same* object serialize. The recursive",
            "        // lock permits a foreign callback to reenter this bridge.",
            "        std::lock_guard<std::recursive_mutex> lock(entry->call_mutex);",
            "        auto object = entry->object;",
            "        if (!object) return 2;",
            f"        auto result = object->{m['name']}({call});",
            "        *out = result;", "        return 0;",
            "    } catch (...) { return 3; }", "}",
        ])
    return "\n".join(lines) + "\n"


def _generate_hepta(cls: str, methods: list[dict]) -> str:
    name = "hepta_cpp_" + cls
    decls = ["module cpp_bridge;", "// Unsafe FFI: integer handles do not prove external C++ correctness.", "",
             f'extern "C" fn {name}_new(out: raw mut u64) -> i32 effects {{ffi, unsafe, write}};',
             f'extern "C" fn {name}_destroy(handle: u64) -> i32 effects {{ffi, unsafe}};']
    for m in methods:
        args = ", ".join(f"{n}: {typ}" for n, typ, _ in m["args"])
        if args:
            args = ", " + args
        decls.append(f'extern "C" fn {name}_{m["name"]}(handle: u64{args}, out: raw mut {m["ret"]}) -> i32 effects {{ffi, unsafe, write}};')
    return "\n".join(decls) + "\n"


def _publish_pair(cpp: Path, cpp_source: str, hepta: Path, hepta_source: str) -> None:
    """Stage both complete outputs, then link without overwriting either one.

    Individual links are atomic; publishing two independent paths is NOT a
    crash-atomic two-file transaction. The rollback covers ordinary errors,
    not power loss or uncooperative same-user filesystem mutation.
    """
    targets = ((cpp, cpp_source.encode("utf-8")),
               (hepta, hepta_source.encode("utf-8")))
    for dest, _ in targets:
        dest.parent.mkdir(parents=True, exist_ok=True)
    with ExitStack() as stack:
        staged = []
        for dest, content in targets:
            folder = Path(stack.enter_context(
                tempfile.TemporaryDirectory(prefix=".hepta-bridge-", dir=dest.parent)))
            stage = folder / "complete"
            with stage.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            staged.append((stage, dest))
        published = []
        try:
            for stage, dest in staged:
                # os.link fails if destination exists, including symlinks.
                # A half-written temporary file is never made public.
                os.link(stage, dest)
                published.append((stage, dest))
            if os.name == "posix":
                for directory in sorted({str(cpp.parent), str(hepta.parent)}):
                    fd = os.open(directory, os.O_RDONLY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
        except OSError:
            for stage, dest in reversed(published):
                try:
                    source_stat, dest_stat = stage.stat(), dest.lstat()
                    if (not dest.is_symlink() and
                            source_stat.st_ino == dest_stat.st_ino and
                            source_stat.st_dev == dest_stat.st_dev):
                        dest.unlink()
                except (OSError, FileNotFoundError):
                    pass
            raise


def bridge_cpp(header: str | Path, class_name: str, cpp_output: str | Path,
               hepta_output: str | Path, *, clang: str = "clang++") -> dict:
    src, cpp, hp = Path(header).resolve(), Path(cpp_output).resolve(), Path(hepta_output).resolve()
    report = {"schema": "hepta.cpp-bridge.v0", "ok": False, "status": "rejected",
              "header": str(src), "class": class_name, "cpp_output": str(cpp), "hepta_output": str(hp),
              "native_link_qualified": False, "foreign_library_soundness_proved": False,
              "thread_safety_of_foreign_internals_proved": False, "diagnostics": []}
    try:
        if (not _IDENT.fullmatch(class_name) or class_name.startswith("__") or
                not src.is_file() or src.suffix not in {".h", ".hpp", ".hh"} or
                cpp.suffix != ".cpp" or hp.suffix != ".hepta" or len({src, cpp, hp}) != 3):
            raise MigrationRejected("E_CPP_PATH", "Need a named top-level class, C++ header and distinct .cpp/.hepta outputs")
        if cpp.exists() or hp.exists() or cpp.is_symlink() or hp.is_symlink():
            raise MigrationRejected("E_CPP_EXISTS", "Refusing to overwrite an existing or symlink output")
        source = src.read_bytes()
        if len(source) > 256_000:
            raise MigrationRejected("E_CPP_SIZE", "Header exceeds 256 KB")
        model = _class_model(clang)
        cls = _header_class(src, class_name, clang)
        methods = _class_methods(cls, model)
        rendered_cpp = _generate_cpp(src, class_name, methods)
        rendered_hepta = _generate_hepta(class_name, methods)
        # Compile the actual generated C++ wrapper: AST acceptance is not enough.
        with tempfile.TemporaryDirectory(prefix="hepta-bridge-") as td:
            temp = Path(td) / "bridge.cpp"
            temp.write_text(rendered_cpp, encoding="utf-8")
            _run([clang, "-std=c++20", "-fsyntax-only", "-Werror", str(temp)])
        from .parser import parse
        from .checker import check
        checked = check(parse(rendered_hepta, str(hp)))
        if not checked.ok:
            report["diagnostics"] = [d.to_dict() for d in checked.diagnostics]
            return report
        if src.read_bytes() != source:
            raise MigrationRejected("E_CPP_SOURCE_RACE", "Header changed during bridge generation")
        # Final paths are created only after both staged files have been
        # completely written and fsynced. Ordinary failures roll back only
        # pathnames still referencing the links created by this operation.
        _publish_pair(cpp, rendered_cpp, hp, rendered_hepta)
        report.update({"ok": True, "status": "clang_and_hepta_frontend_checked",
                       "header_sha256": hashlib.sha256(source).hexdigest(), "target_model": model,
                       "cpp_sha256": hashlib.sha256(rendered_cpp.encode()).hexdigest(),
                       "hepta_sha256": hashlib.sha256(rendered_hepta.encode()).hexdigest(),
                       "methods": [m["name"] for m in methods],
                       "opaque_handle_contract": {"success": 0, "null_out": 1,
                                                  "stale_handle": 2, "cpp_exception": 3,
                                                  "handle_exhausted": 4},
                       "abi": "C_host_only", "execution": "not_run"})
        return report
    except (MigrationRejected, ValueError, OSError, json.JSONDecodeError) as exc:
        report["diagnostics"].append({
            "code": getattr(exc, "code", "E_CPP_PUBLISH" if isinstance(exc, OSError) else "E_CPP_INPUT"),
            "message": str(exc),
        })
        return report


# The declarative bridge is a separate route; the original AST class importer
# remains available with its existing schema and compatibility restrictions.
from .cpp_contracts import bridge_cpp_contracts  # noqa: E402,F401
