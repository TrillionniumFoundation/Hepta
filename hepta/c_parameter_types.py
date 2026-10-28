"""Bound original C parameter types to the captured compiler's serialized AST.

The JSON AST exposes adjusted array parameters as pointers. Their original
types can contain entry-time VLA evaluation. A separate, bounded libclang
reader consumes an AST emitted by the selected compiler with the captured
source operand, flags and cwd; it does not reparse source under another driver.
The reader is an explicit trusted frontend component, recorded by content hash.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile


SCHEMA = "hepta.c-original-parameter-types.v1"
MAX_AST_BYTES = 32_000_000
MAX_DECLARATIONS = 100_000
MAX_PARAMETERS = 1024
MAX_TYPE_DEPTH = 64


def _digest_file(path):
    path = Path(path).resolve(strict=True)
    size = path.stat().st_size
    if not path.is_file() or not 0 < size <= 1024 * 1024 * 1024:
        raise ValueError("invalid original-type tool file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "bytes": size, "sha256": digest.hexdigest()}


def _reader_library(compiler):
    executable = Path(compiler["path"])
    match = re.search(r"\bclang version (\d+)\.", compiler["version"])
    if match is None:
        raise ValueError("selected compiler has no recognized Clang version")
    major = match.group(1)
    # Only the selected installation is searched. A similarly named global
    # library or a user environment override is not an identity binding.
    names = ("libclang-" + major + ".so.1", "libclang-" + major + ".so." + major,
             "libclang.so." + major, "libclang.so", "libclang.dylib")
    candidates = [executable.parent.parent / "lib" / name for name in names]
    candidates.append(executable.parent / "libclang.dll")
    for candidate in candidates:
        if candidate.is_file():
            return _digest_file(candidate)
    raise ValueError("matching-installation libclang is required for pointer parameter admission")


def _strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate original-type receipt field")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("nonfinite original-type receipt number")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def original_parameter_types(capture, config, declarations):
    """Return a separately versioned receipt; do not change the capture schema."""
    from .c_migrate import MigrationRejected
    from .c_project import captured_source_argument, verify_capture
    from .clang_capture import CaptureRejected, run_bounded

    try:
        verify_capture(capture)
        expected = []
        for node, inventory in declarations:
            expected.append({
                "file": inventory["file"], "offset": inventory["offset"],
                "name": node["name"], "type": node["type"]["qualType"],
                "parameters": [child.get("name", "") for child in node.get("inner", [])
                               if child.get("kind") == "ParmVarDecl"],
            })
        if len(expected) > MAX_DECLARATIONS:
            raise ValueError("too many original-type declaration bindings")
        reader = _reader_library(capture["compiler"])
        request = {
            "compiler": capture["compiler"], "reader": reader,
            "capture_sha256": capture["sha256"], "unit": config["index"],
            "directory": config["directory"],
            "arguments": config["frontend_arguments"],
            "source_argument": captured_source_argument(config),
            "expected": expected,
        }
        helper = [sys.executable, "-I", str(Path(__file__).resolve())]
        with tempfile.TemporaryDirectory(prefix="hepta-original-types-") as temporary:
            ast_path = Path(temporary) / "input.ast"
            request["argv"] = [capture["compiler"]["path"], *config["frontend_arguments"],
                               "-Werror", "-emit-ast", captured_source_argument(config),
                               "-o", str(ast_path)]
            emitted = run_bounded([*helper, "--emit-ast"], cwd=config["directory"],
                                  input_text=json.dumps(request), timeout=35,
                                  stdin_limit=8_000_000, stdout_limit=1_000_000,
                                  stderr_limit=1_000_000)
            if (emitted.returncode or not ast_path.is_file()
                    or not 0 < ast_path.stat().st_size <= MAX_AST_BYTES):
                raise ValueError("serialized AST emission failed: " + emitted.stderr[-4000:])
            ast_identity = _digest_file(ast_path)
            request["serialized_ast"] = ast_identity
            run = run_bounded([*helper, "--worker"], cwd=config["directory"],
                              input_text=json.dumps(request), timeout=30,
                              stdin_limit=8_000_000, stdout_limit=8_000_000,
                              stderr_limit=1_000_000)
            if _digest_file(ast_path) != ast_identity:
                raise ValueError("serialized AST changed during original-type reading")
        if run.returncode:
            raise ValueError("original-type reader failed: " + run.stderr[-4000:])
        receipt = _strict_json(run.stdout)
        fields = {"schema", "capture_sha256", "unit", "compiler", "reader", "cwd",
                  "argv", "serialized_ast", "functions", "limits"}
        if (type(receipt) is not dict or set(receipt) != fields
                or receipt["schema"] != SCHEMA
                or receipt["capture_sha256"] != capture["sha256"]
                or type(receipt["unit"]) is not int or receipt["unit"] != config["index"]
                or receipt["compiler"] != capture["compiler"]
                or receipt["reader"] != {**reader, "version": capture["compiler"]["version"]}
                or receipt["cwd"] != config["directory"]
                or type(receipt["functions"]) is not list
                or len(receipt["functions"]) != len(expected)):
            raise ValueError("original-type reader receipt identity mismatch")
        ast = receipt["serialized_ast"]
        expected_argv = [capture["compiler"]["path"], *config["frontend_arguments"],
                         "-Werror", "-emit-ast", captured_source_argument(config), "-o"]
        if (type(ast) is not dict or set(ast) != {"path", "bytes", "sha256"}
                or type(ast["path"]) is not str or not Path(ast["path"]).is_absolute()
                or type(ast["bytes"]) is not int or not 0 < ast["bytes"] <= MAX_AST_BYTES
                or ast != ast_identity
                or receipt["argv"] != [*expected_argv, ast["path"]]
                or receipt["limits"] != {"ast_bytes": MAX_AST_BYTES, "declarations": MAX_DECLARATIONS,
                                         "parameters": MAX_PARAMETERS, "type_depth": MAX_TYPE_DEPTH,
                                         "worker_seconds": 30, "compiler_seconds": 35}):
            raise ValueError("original-type AST command/budget identity mismatch")
        for want, actual in zip(expected, receipt["functions"]):
            if (type(actual) is not dict or set(actual) != {"declaration", "parameters"}
                    or actual["declaration"] != want
                    or type(actual["parameters"]) is not list
                    or len(actual["parameters"]) != len(want["parameters"])):
                raise ValueError("original-type declaration coverage mismatch")
            for name, parameter in zip(want["parameters"], actual["parameters"]):
                if (type(parameter) is not dict
                        or set(parameter) != {"name", "spelling", "kind", "state"}
                        or parameter["name"] != name
                        or type(parameter["spelling"]) is not str
                        or type(parameter["kind"]) is not str
                        or parameter["state"] not in {"fixed", "variable", "unmodeled"}):
                    raise ValueError("malformed original parameter type result")
        if _digest_file(reader["path"]) != reader:
            raise ValueError("original-type reader changed during use")
        verify_capture(capture)
        return receipt
    except MigrationRejected:
        raise
    except (CaptureRejected, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise MigrationRejected("E_C_ORIGINAL_TYPE", str(exc)) from exc


class _String(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("flags", ctypes.c_uint)]


class _Cursor(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_uint), ("xdata", ctypes.c_int),
                ("data", ctypes.c_void_p * 3)]


class _Type(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_int), ("data", ctypes.c_void_p * 2)]


class _Location(ctypes.Structure):
    _fields_ = [("ptr_data", ctypes.c_void_p * 2), ("int_data", ctypes.c_uint)]


def _read_ast(library, ast_path, expected):
    """Clang 20 C API records original DecayedType before parameter adjustment."""
    lib = ctypes.CDLL(library)
    visit_type = ctypes.CFUNCTYPE(ctypes.c_uint, _Cursor, _Cursor, ctypes.c_void_p)
    api = {
        "clang_getCString": (ctypes.c_char_p, [_String]),
        "clang_disposeString": (None, [_String]),
        "clang_getClangVersion": (_String, []),
        "clang_createIndex": (ctypes.c_void_p, [ctypes.c_int, ctypes.c_int]),
        "clang_disposeIndex": (None, [ctypes.c_void_p]),
        "clang_createTranslationUnit2": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_char_p,
                                                       ctypes.POINTER(ctypes.c_void_p)]),
        "clang_disposeTranslationUnit": (None, [ctypes.c_void_p]),
        "clang_getTranslationUnitCursor": (_Cursor, [ctypes.c_void_p]),
        "clang_visitChildren": (ctypes.c_uint, [_Cursor, visit_type, ctypes.c_void_p]),
        "clang_getCursorSpelling": (_String, [_Cursor]),
        "clang_getCursorLocation": (_Location, [_Cursor]),
        "clang_getExpansionLocation": (None, [_Location, ctypes.POINTER(ctypes.c_void_p),
                                              ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
                                              ctypes.POINTER(ctypes.c_uint)]),
        "clang_getFileName": (_String, [ctypes.c_void_p]),
        "clang_getCursorType": (_Type, [_Cursor]),
        "clang_getTypeSpelling": (_String, [_Type]),
        "clang_getTypeKindSpelling": (_String, [ctypes.c_int]),
        "clang_getCanonicalType": (_Type, [_Type]),
        "clang_getArrayElementType": (_Type, [_Type]),
        "clang_getPointeeType": (_Type, [_Type]),
        "clang_Cursor_getNumArguments": (ctypes.c_int, [_Cursor]),
        "clang_Cursor_getArgument": (_Cursor, [_Cursor, ctypes.c_uint]),
    }
    for name, (result, arguments) in api.items():
        function = getattr(lib, name)
        function.restype, function.argtypes = result, arguments

    def string(value):
        try:
            raw = lib.clang_getCString(value)
            return "" if raw is None else raw.decode("utf-8", errors="strict")
        finally:
            lib.clang_disposeString(value)

    def type_state(typ, depth=0):
        if depth > MAX_TYPE_DEPTH:
            return "unmodeled"
        typ = lib.clang_getCanonicalType(typ)
        kind = string(lib.clang_getTypeKindSpelling(typ.kind))
        if kind == "VariableArray":
            return "variable"
        if kind in {"Pointer", "LValueReference", "RValueReference"}:
            return type_state(lib.clang_getPointeeType(typ), depth + 1)
        if kind in {"ConstantArray", "IncompleteArray"}:
            return type_state(lib.clang_getArrayElementType(typ), depth + 1)
        if kind in {"Void", "Bool", "Char_U", "UChar", "Char16", "Char32", "UShort",
                    "UInt", "ULong", "ULongLong", "UInt128", "Char_S", "SChar", "WChar",
                    "Short", "Int", "Long", "LongLong", "Int128", "Float", "Double",
                    "LongDouble", "Float128", "Half", "Float16", "BFloat16", "Record", "Enum"}:
            return "fixed"
        return "unmodeled"

    def identity(cursor):
        file, offset = ctypes.c_void_p(), ctypes.c_uint()
        lib.clang_getExpansionLocation(lib.clang_getCursorLocation(cursor), ctypes.byref(file),
                                       None, None, ctypes.byref(offset))
        filename = string(lib.clang_getFileName(file)) if file.value else ""
        return (str(Path(filename).resolve()) if filename else "", offset.value,
                string(lib.clang_getCursorSpelling(cursor)))

    wanted = {}
    for index, declaration in enumerate(expected):
        key = (declaration["file"], declaration["offset"], declaration["name"])
        if key in wanted:
            raise ValueError("ambiguous original-type declaration location")
        wanted[key] = index
    results, failures, visited = {}, [], [0]

    @visit_type
    def visit(cursor, parent, data):
        try:
            visited[0] += 1
            if visited[0] > MAX_DECLARATIONS:
                raise ValueError("original-type AST declaration budget exceeded")
            if cursor.kind != 8:  # CXCursor_FunctionDecl, stable public C API.
                return 1
            key = identity(cursor)
            if key not in wanted:
                return 1
            index = wanted[key]
            if index in results:
                raise ValueError("duplicate original-type AST declaration")
            declaration = expected[index]
            function_type = string(lib.clang_getTypeSpelling(lib.clang_getCursorType(cursor)))
            count = lib.clang_Cursor_getNumArguments(cursor)
            if (function_type != declaration["type"] or count != len(declaration["parameters"])
                    or not 0 <= count <= MAX_PARAMETERS):
                raise ValueError("serialized/JSON function signature mismatch")
            parameters = []
            for ordinal, name in enumerate(declaration["parameters"]):
                parameter = lib.clang_Cursor_getArgument(cursor, ordinal)
                if string(lib.clang_getCursorSpelling(parameter)) != name:
                    raise ValueError("serialized/JSON parameter identity mismatch")
                typ = lib.clang_getCursorType(parameter)
                parameters.append({"name": name, "spelling": string(lib.clang_getTypeSpelling(typ)),
                                   "kind": string(lib.clang_getTypeKindSpelling(typ.kind)),
                                   "state": type_state(typ)})
            results[index] = {"declaration": declaration, "parameters": parameters}
            return 1
        except BaseException as exc:
            # Exceptions cannot cross a ctypes callback. Break traversal and
            # reject after the C call returns instead of silently continuing.
            failures.append(str(exc))
            return 0

    index = lib.clang_createIndex(0, 0)
    if not index:
        raise ValueError("libclang index unavailable")
    unit = ctypes.c_void_p()
    try:
        code = lib.clang_createTranslationUnit2(index, os.fsencode(ast_path), ctypes.byref(unit))
        if code != 0 or not unit.value:
            raise ValueError("selected libclang cannot load compiler AST: " + str(code))
        lib.clang_visitChildren(lib.clang_getTranslationUnitCursor(unit), visit, None)
        if failures or len(results) != len(expected):
            raise ValueError("original-type AST coverage failed: " + "; ".join(failures))
        return [results[i] for i in range(len(expected))], string(lib.clang_getClangVersion())
    finally:
        if unit.value:
            lib.clang_disposeTranslationUnit(unit)
        lib.clang_disposeIndex(index)


def _set_process_limits():
    # Each phase is directly owned by the outer run_bounded process group.
    # No nested session can outlive its parent compiler/reader deadline.
    if os.name == "posix":
        import resource
        for kind, limit in ((resource.RLIMIT_AS, 2 * 1024 * 1024 * 1024),
                            (resource.RLIMIT_FSIZE, MAX_AST_BYTES)):
            soft, hard = resource.getrlimit(kind)
            bound = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
            if soft != resource.RLIM_INFINITY:
                bound = min(bound, soft)
            resource.setrlimit(kind, (bound, bound))


def _emit_ast(request):
    _set_process_limits()
    compiler = request["compiler"]
    argv = request["argv"]
    expected = [compiler["path"], *request["arguments"], "-Werror", "-emit-ast",
                request["source_argument"], "-o"]
    if (argv[:-1] != expected or not Path(argv[-1]).is_absolute()
            or Path(argv[-1]).exists() or Path(argv[-1]).is_symlink()
            or _digest_file(compiler["path"])["sha256"] != compiler["executable_sha256"]
            or str(Path.cwd()) != request["directory"]):
        raise ValueError("serialized AST emission input identity mismatch")
    # Replace the wrapper, retaining its process group and file-size budget.
    os.execv(compiler["path"], argv)


def _worker(request):
    _set_process_limits()
    compiler, reader = request["compiler"], request["reader"]
    ast = request["serialized_ast"]
    if (_digest_file(compiler["path"])["sha256"] != compiler["executable_sha256"]
            or _digest_file(reader["path"]) != reader
            or _digest_file(ast["path"]) != ast
            or not 0 < ast["bytes"] <= MAX_AST_BYTES
            or str(Path.cwd()) != request["directory"]):
        raise ValueError("original-type worker input identity mismatch")
    functions, version = _read_ast(reader["path"], ast["path"], request["expected"])
    if (version != compiler["version"] or _digest_file(ast["path"]) != ast
            or _digest_file(reader["path"]) != reader
            or _digest_file(compiler["path"])["sha256"] != compiler["executable_sha256"]):
        raise ValueError("original-type tool/AST identity changed or reader version differs")
    return {"schema": SCHEMA, "capture_sha256": request["capture_sha256"],
            "unit": request["unit"], "compiler": compiler,
            "reader": {**reader, "version": version}, "cwd": request["directory"],
            "argv": request["argv"], "serialized_ast": ast, "functions": functions,
            "limits": {"ast_bytes": MAX_AST_BYTES, "declarations": MAX_DECLARATIONS,
                       "parameters": MAX_PARAMETERS, "type_depth": MAX_TYPE_DEPTH,
                       "worker_seconds": 30, "compiler_seconds": 35}}


if __name__ == "__main__":
    # -I suppresses cwd/PYTHONPATH injection. Both subprocess modes use only
    # the standard library; no import is resolved from the captured C cwd.
    try:
        if sys.argv[1:] not in (["--worker"], ["--emit-ast"]):
            raise ValueError("expected original-type subprocess mode")
        payload = sys.stdin.buffer.read(8_000_001)
        if len(payload) > 8_000_000:
            raise ValueError("original-type worker input exceeds byte budget")
        request = _strict_json(payload)
        if sys.argv[1:] == ["--emit-ast"]:
            _emit_ast(request)
        else:
            print(json.dumps(_worker(request), sort_keys=True, allow_nan=False))
    except Exception as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        raise SystemExit(1)
