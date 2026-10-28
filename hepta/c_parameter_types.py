"""Bind original C result/parameter types to the captured serialized AST.

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
import shutil
import sys
import tempfile


SCHEMA = "hepta.c-original-parameter-types.v2"
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
    raise ValueError("matching-installation libclang is required for original type admission")


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


def _same(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def _bound_position(position, files, *, token_end=False):
    if type(position) is not dict:
        raise ValueError("missing original declaration location")
    position = position.get("expansionLoc", position.get("spellingLoc", position))
    filename = files.get(id(position))
    offset, length = position.get("offset"), position.get("tokLen")
    if (type(filename) is not str or not Path(filename).is_absolute()
            or type(offset) is not int or offset < 0
            or type(length) is not int or length <= 0):
        raise ValueError("unbound original declaration physical location")
    return {"file": filename, "offset": offset + (length if token_end else 0)}


def _expected_declarations(declarations, files, capture):
    dependencies = {item["path"]: item["sha256"] for item in capture["dependencies"]}
    result = []
    for node, inventory in declarations:
        parameters = []
        for child in node.get("inner", []):
            if child.get("kind") != "ParmVarDecl":
                continue
            location = _bound_position(child.get("loc"), files)
            begin = _bound_position(child.get("range", {}).get("begin"), files)
            end = _bound_position(child.get("range", {}).get("end"), files, token_end=True)
            for position in (location, begin, end):
                if position["file"] not in dependencies:
                    raise ValueError("parameter location is outside captured dependencies")
            parameters.append({"name": child.get("name", ""), "type": child["type"]["qualType"],
                               **location, "begin": begin, "end": end})
        if len(parameters) > MAX_PARAMETERS:
            raise ValueError("too many original parameters")
        result.append({"file": inventory["file"], "offset": inventory["offset"],
                       "name": node["name"], "type": node["type"]["qualType"],
                       "result_type": node["type"]["qualType"].split("(", 1)[0].strip(),
                       "parameters": parameters})
    if len(result) > MAX_DECLARATIONS:
        raise ValueError("too many original-type declaration bindings")
    return result


_FIXED_KINDS = {"Void", "Bool", "Char_U", "UChar", "Char16", "Char32", "UShort",
                "UInt", "ULong", "ULongLong", "UInt128", "Char_S", "SChar", "WChar",
                "Short", "Int", "Long", "LongLong", "Int128", "Float", "Double",
                "LongDouble", "Float128", "Half", "Float16", "BFloat16", "Record", "Enum"}
_POINTER_KINDS = {"Pointer", "LValueReference", "RValueReference"}
_ARRAY_KINDS = {"ConstantArray", "IncompleteArray", "VariableArray"}


def _shape_state(shape, depth=0):
    if type(shape) is not dict or depth > MAX_TYPE_DEPTH:
        raise ValueError("invalid or excessive original type shape")
    required = {"kind", "spelling", "const", "volatile", "restrict"}
    kind = shape.get("kind")
    if type(kind) is not str or type(shape.get("spelling")) is not str or len(shape["spelling"]) > 4096:
        raise ValueError("invalid original type spelling")
    if any(type(shape.get(key)) is not bool for key in ("const", "volatile", "restrict")):
        raise ValueError("invalid original type qualifier")
    if kind in _POINTER_KINDS:
        required |= {"pointee"}
    elif kind in _ARRAY_KINDS:
        required |= {"element", "extent"}
    if set(shape) != required:
        raise ValueError("invalid original type shape fields")
    if kind in _POINTER_KINDS:
        return _shape_state(shape["pointee"], depth + 1)
    if kind in _ARRAY_KINDS:
        element = _shape_state(shape["element"], depth + 1)
        if kind == "ConstantArray":
            if type(shape["extent"]) is not int or not 0 <= shape["extent"] <= (1 << 63) - 1:
                raise ValueError("invalid fixed array extent")
        elif shape["extent"] is not None:
            raise ValueError("nonconstant array has a fabricated extent")
        return "variable" if kind == "VariableArray" else element
    return "fixed" if kind in _FIXED_KINDS else "unmodeled"


def _check_type_info(value, *, parameter=False):
    fields = {"spelling", "kind", "state", "shape"}
    if parameter:
        fields |= {"name", "binding"}
    if (type(value) is not dict or set(value) != fields
            or type(value["spelling"]) is not str or len(value["spelling"]) > 4096
            or type(value["kind"]) is not str
            or value["state"] not in {"fixed", "variable", "unmodeled"}
            or value["state"] != _shape_state(value["shape"])):
        raise ValueError("malformed or contradictory original type result")
    # Typedef/elaborated sugar may canonicalize to another root kind. Concrete
    # primitive, pointer and array kinds cannot relabel a VLA as a fixed array.
    if (value["kind"] in _FIXED_KINDS | _POINTER_KINDS | _ARRAY_KINDS
            and value["kind"] != value["shape"]["kind"]):
        raise ValueError("original and canonical type kinds contradict")


def original_type_reader_identity(clang: str = "clang") -> dict:
    """Identify the actual compatible reader without emitting a program AST.

    The bounded identity subprocess loads the same selected-installation
    library and calls clang_getClangVersion. No synthetic --version command
    is issued for a shared library. The receipt can seed external inventories.
    """
    from .c_migrate import MigrationRejected
    from .clang_capture import CaptureRejected, run_bounded

    try:
        selected = shutil.which(clang)
        if selected is None:
            raise ValueError("selected Clang is unavailable")
        compiler_file = _digest_file(selected)
        observations = []
        for option in ("--version", "-dumpmachine"):
            result = run_bounded([compiler_file["path"], option], timeout=10,
                                 stdout_limit=1_000_000, stderr_limit=1_000_000)
            if result.returncode:
                raise ValueError("selected Clang identity command failed: " + result.stderr[-2000:])
            observations.append(result.stdout)
        compiler = {"path": compiler_file["path"], "executable_sha256": compiler_file["sha256"],
                    "version": observations[0].splitlines()[0], "target": observations[1].strip()}
        request = {"compiler": compiler, "reader": _reader_library(compiler),
                   "worker": _digest_file(__file__), "python": _digest_file(sys.executable)}
        result = run_bounded([sys.executable, "-I", str(Path(__file__).resolve()), "--identity"],
                             input_text=json.dumps(request), timeout=30,
                             stdin_limit=1_000_000, stdout_limit=1_000_000, stderr_limit=1_000_000)
        if result.returncode:
            raise ValueError("original-type reader identity failed: " + result.stderr[-2000:])
        receipt = _strict_json(result.stdout)
        expected = {"schema": "hepta.c-original-type-reader-identity.v1", **request,
                    "reader": {**request["reader"], "version": compiler["version"]}}
        if not _same(receipt, expected) or _digest_file(compiler_file["path"]) != compiler_file:
            raise ValueError("original-type identity receipt mismatch")
        for name in ("reader", "worker", "python"):
            if _digest_file(request[name]["path"]) != request[name]:
                raise ValueError("original-type identity changed during inspection")
        return receipt
    except (CaptureRejected, OSError, ValueError, KeyError, TypeError, IndexError) as error:
        raise MigrationRejected("E_C_ORIGINAL_TYPE", str(error)) from error


def original_parameter_types(capture, config, declarations, physical_source_files):
    """Capture every original result/parameter before any signature adaptation.

    A result is evidence from the pinned frontend, not a source-equivalence or
    foreign-allocation proof. All JSON identities must also match the independently
    read serialized AST's actual parameter locations and adjusted function type.
    """
    from .c_migrate import MigrationRejected
    from .c_project import captured_source_argument, verify_capture
    from .clang_capture import CaptureRejected, run_bounded

    try:
        verify_capture(capture)
        expected = _expected_declarations(declarations, physical_source_files, capture)
        reader = _reader_library(capture["compiler"])
        worker = _digest_file(__file__)
        python = _digest_file(sys.executable)
        request = {"compiler": capture["compiler"], "reader": reader,
                   "worker": worker, "python": python,
                   "capture_sha256": capture["sha256"], "unit": config["index"],
                   "directory": config["directory"], "arguments": config["frontend_arguments"],
                   "source_argument": captured_source_argument(config), "expected": expected}
        helper = [sys.executable, "-I", str(Path(__file__).resolve())]
        with tempfile.TemporaryDirectory(prefix="hepta-original-types-") as temporary:
            ast_path = Path(temporary) / "input.ast"
            request["argv"] = [capture["compiler"]["path"], *config["frontend_arguments"],
                               "-Werror", "-emit-ast", captured_source_argument(config), "-o", str(ast_path)]
            emitted = run_bounded([*helper, "--emit-ast"], cwd=config["directory"],
                                  input_text=json.dumps(request), timeout=35,
                                  stdin_limit=8_000_000, stdout_limit=1_000_000, stderr_limit=1_000_000)
            if (emitted.returncode or not ast_path.is_file()
                    or not 0 < ast_path.stat().st_size <= MAX_AST_BYTES):
                raise ValueError("serialized AST emission failed: " + emitted.stderr[-4000:])
            ast_identity = _digest_file(ast_path)
            request["serialized_ast"] = ast_identity
            run = run_bounded([*helper, "--worker"], cwd=config["directory"],
                              input_text=json.dumps(request), timeout=30,
                              stdin_limit=8_000_000, stdout_limit=8_000_000, stderr_limit=1_000_000)
            if _digest_file(ast_path) != ast_identity:
                raise ValueError("serialized AST changed during original-type reading")
        if run.returncode:
            raise ValueError("original-type reader failed: " + run.stderr[-4000:])
        receipt = _strict_json(run.stdout)
        fields = {"schema", "capture_sha256", "unit", "compiler", "reader", "worker", "python", "cwd",
                  "argv", "serialized_ast", "functions", "limits"}
        if (type(receipt) is not dict or set(receipt) != fields or receipt["schema"] != SCHEMA
                or receipt["capture_sha256"] != capture["sha256"]
                or type(receipt["unit"]) is not int or receipt["unit"] != config["index"]
                or not _same(receipt["compiler"], capture["compiler"])
                or not _same(receipt["reader"], {**reader, "version": capture["compiler"]["version"]})
                or not _same(receipt["worker"], worker) or not _same(receipt["python"], python)
                or receipt["cwd"] != config["directory"]
                or type(receipt["functions"]) is not list or len(receipt["functions"]) != len(expected)):
            raise ValueError("original-type reader receipt identity mismatch")
        expected_argv = [capture["compiler"]["path"], *config["frontend_arguments"],
                         "-Werror", "-emit-ast", captured_source_argument(config), "-o", ast_identity["path"]]
        if (not _same(receipt["serialized_ast"], ast_identity) or not _same(receipt["argv"], expected_argv)
                or not _same(receipt["limits"], _limits())):
            raise ValueError("original-type AST command/budget identity mismatch")
        for want, actual in zip(expected, receipt["functions"]):
            if (type(actual) is not dict or set(actual) != {"declaration", "result", "parameters"}
                    or not _same(actual["declaration"], want) or type(actual["parameters"]) is not list
                    or len(actual["parameters"]) != len(want["parameters"])):
                raise ValueError("original-type declaration coverage mismatch")
            _check_type_info(actual["result"])
            if actual["result"]["spelling"] != want["result_type"]:
                raise ValueError("original result type differs from captured function")
            for binding, parameter in zip(want["parameters"], actual["parameters"]):
                _check_type_info(parameter, parameter=True)
                physical = {key: value for key, value in binding.items() if key != "type"}
                if parameter["name"] != binding["name"] or not _same(parameter["binding"], physical):
                    raise ValueError("original parameter physical binding differs")
        for identity in (reader, worker, python):
            if _digest_file(identity["path"]) != identity:
                raise ValueError("original-type tool changed during use")
        verify_capture(capture)
        return receipt
    except MigrationRejected:
        raise
    except (CaptureRejected, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise MigrationRejected("E_C_ORIGINAL_TYPE", str(exc)) from exc


def _limits():
    return {"ast_bytes": MAX_AST_BYTES, "declarations": MAX_DECLARATIONS,
            "parameters": MAX_PARAMETERS, "type_depth": MAX_TYPE_DEPTH,
            "worker_seconds": 30, "compiler_seconds": 35}


class _String(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("flags", ctypes.c_uint)]


class _Cursor(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_uint), ("xdata", ctypes.c_int),
                ("data", ctypes.c_void_p * 3)]


class _Type(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_int), ("data", ctypes.c_void_p * 2)]


class _Location(ctypes.Structure):
    _fields_ = [("ptr_data", ctypes.c_void_p * 2), ("int_data", ctypes.c_uint)]


class _Range(ctypes.Structure):
    _fields_ = [("ptr_data", ctypes.c_void_p * 2), ("begin_int_data", ctypes.c_uint),
                ("end_int_data", ctypes.c_uint)]


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
        "clang_getCursorExtent": (_Range, [_Cursor]),
        "clang_getRangeStart": (_Location, [_Range]),
        "clang_getRangeEnd": (_Location, [_Range]),
        "clang_getExpansionLocation": (None, [_Location, ctypes.POINTER(ctypes.c_void_p),
                                              ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint),
                                              ctypes.POINTER(ctypes.c_uint)]),
        "clang_getFileName": (_String, [ctypes.c_void_p]),
        "clang_getCursorType": (_Type, [_Cursor]),
        "clang_getTypeSpelling": (_String, [_Type]),
        "clang_getTypeKindSpelling": (_String, [ctypes.c_int]),
        "clang_getCanonicalType": (_Type, [_Type]),
        "clang_getResultType": (_Type, [_Type]),
        "clang_getArraySize": (ctypes.c_longlong, [_Type]),
        "clang_isConstQualifiedType": (ctypes.c_uint, [_Type]),
        "clang_isVolatileQualifiedType": (ctypes.c_uint, [_Type]),
        "clang_isRestrictQualifiedType": (ctypes.c_uint, [_Type]),
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

    def type_shape(typ, depth=0):
        if depth > MAX_TYPE_DEPTH:
            raise ValueError("original type nesting budget exceeded")
        typ = lib.clang_getCanonicalType(typ)
        kind = string(lib.clang_getTypeKindSpelling(typ.kind))
        shape = {"kind": kind, "spelling": string(lib.clang_getTypeSpelling(typ)),
                 "const": bool(lib.clang_isConstQualifiedType(typ)),
                 "volatile": bool(lib.clang_isVolatileQualifiedType(typ)),
                 "restrict": bool(lib.clang_isRestrictQualifiedType(typ))}
        if kind in _POINTER_KINDS:
            shape["pointee"] = type_shape(lib.clang_getPointeeType(typ), depth + 1)
        elif kind in _ARRAY_KINDS:
            shape["element"] = type_shape(lib.clang_getArrayElementType(typ), depth + 1)
            shape["extent"] = int(lib.clang_getArraySize(typ)) if kind == "ConstantArray" else None
        return shape

    def type_info(typ):
        shape = type_shape(typ)
        return {"spelling": string(lib.clang_getTypeSpelling(typ)),
                "kind": string(lib.clang_getTypeKindSpelling(typ.kind)),
                "state": _shape_state(shape), "shape": shape}

    def position(location):
        file, offset = ctypes.c_void_p(), ctypes.c_uint()
        lib.clang_getExpansionLocation(location, ctypes.byref(file), None, None, ctypes.byref(offset))
        filename = string(lib.clang_getFileName(file)) if file.value else ""
        return {"file": str(Path(filename).resolve()) if filename else "", "offset": offset.value}

    def identity(cursor):
        location = position(lib.clang_getCursorLocation(cursor))
        return (location["file"], location["offset"], string(lib.clang_getCursorSpelling(cursor)))

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
            function_type_value = lib.clang_getCursorType(cursor)
            result = type_info(lib.clang_getResultType(function_type_value))
            if result["spelling"] != declaration["result_type"]:
                raise ValueError("serialized/JSON result type mismatch")
            for ordinal, expected_parameter in enumerate(declaration["parameters"]):
                parameter = lib.clang_Cursor_getArgument(cursor, ordinal)
                name = string(lib.clang_getCursorSpelling(parameter))
                extent = lib.clang_getCursorExtent(parameter)
                binding = {"name": name,
                    **position(lib.clang_getCursorLocation(parameter)),
                    "begin": position(lib.clang_getRangeStart(extent)),
                    "end": position(lib.clang_getRangeEnd(extent))}
                # libclang deliberately restores original array types even in
                # clang_getArgType. The complete function type above binds the
                # adjusted signature; bind each original cursor independently
                # by ordinal, physical location, full extent and name.
                expected_binding = {key: value for key, value in expected_parameter.items() if key != "type"}
                if not _same(binding, expected_binding):
                    raise ValueError("serialized/JSON parameter physical identity mismatch: "
                                     + repr((expected_parameter, binding)))
                parameters.append({"name": name, "binding": binding,
                                   **type_info(lib.clang_getCursorType(parameter))})
            results[index] = {"declaration": declaration, "result": result, "parameters": parameters}
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


def _identity_worker(request):
    _set_process_limits()
    compiler = request["compiler"]
    for name in ("reader", "worker", "python"):
        if _digest_file(request[name]["path"]) != request[name]:
            raise ValueError("reader identity input changed")
    if (_digest_file(__file__) != request["worker"]
            or _digest_file(sys.executable) != request["python"]
            or _digest_file(compiler["path"])["sha256"] != compiler["executable_sha256"]):
        raise ValueError("reader identity worker mismatch")
    lib = ctypes.CDLL(request["reader"]["path"])
    lib.clang_getClangVersion.argtypes, lib.clang_getClangVersion.restype = [], _String
    lib.clang_getCString.argtypes, lib.clang_getCString.restype = [_String], ctypes.c_char_p
    lib.clang_disposeString.argtypes, lib.clang_disposeString.restype = [_String], None
    value = lib.clang_getClangVersion()
    try:
        version = lib.clang_getCString(value).decode("utf-8", errors="strict")
    finally:
        lib.clang_disposeString(value)
    if version != compiler["version"]:
        raise ValueError("selected-installation libclang version differs from Clang")
    for name in ("reader", "worker", "python"):
        if _digest_file(request[name]["path"]) != request[name]:
            raise ValueError("reader identity changed while loaded")
    return {"schema": "hepta.c-original-type-reader-identity.v1", **request,
            "reader": {**request["reader"], "version": version}}


def _emit_ast(request):
    _set_process_limits()
    compiler = request["compiler"]
    argv = request["argv"]
    expected = [compiler["path"], *request["arguments"], "-Werror", "-emit-ast",
                request["source_argument"], "-o"]
    if (argv[:-1] != expected or not Path(argv[-1]).is_absolute()
            or Path(argv[-1]).exists() or Path(argv[-1]).is_symlink()
            or _digest_file(compiler["path"])["sha256"] != compiler["executable_sha256"]
            or str(Path.cwd()) != request["directory"]
            or _digest_file(__file__) != request["worker"]
            or _digest_file(sys.executable) != request["python"]):
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
            or str(Path.cwd()) != request["directory"]
            or _digest_file(__file__) != request["worker"]
            or _digest_file(sys.executable) != request["python"]):
        raise ValueError("original-type worker input identity mismatch")
    functions, version = _read_ast(reader["path"], ast["path"], request["expected"])
    if (version != compiler["version"] or _digest_file(ast["path"]) != ast
            or _digest_file(reader["path"]) != reader
            or _digest_file(compiler["path"])["sha256"] != compiler["executable_sha256"]
            or _digest_file(__file__) != request["worker"]
            or _digest_file(sys.executable) != request["python"]):
        raise ValueError("original-type tool/AST identity changed or reader version differs")
    return {"schema": SCHEMA, "capture_sha256": request["capture_sha256"],
            "unit": request["unit"], "compiler": compiler,
            "reader": {**reader, "version": version},
            "worker": request["worker"], "python": request["python"], "cwd": request["directory"],
            "argv": request["argv"], "serialized_ast": ast, "functions": functions,
            "limits": _limits()}


if __name__ == "__main__":
    # -I suppresses cwd/PYTHONPATH injection. Both subprocess modes use only
    # the standard library; no import is resolved from the captured C cwd.
    try:
        if sys.argv[1:] not in (["--worker"], ["--emit-ast"], ["--identity"]):
            raise ValueError("expected original-type subprocess mode")
        payload = sys.stdin.buffer.read(8_000_001)
        if len(payload) > 8_000_000:
            raise ValueError("original-type worker input exceeds byte budget")
        request = _strict_json(payload)
        if sys.argv[1:] == ["--emit-ast"]:
            _emit_ast(request)
        elif sys.argv[1:] == ["--identity"]:
            print(json.dumps(_identity_worker(request), sort_keys=True, allow_nan=False))
        else:
            print(json.dumps(_worker(request), sort_keys=True, allow_nan=False))
    except Exception as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        raise SystemExit(1)
