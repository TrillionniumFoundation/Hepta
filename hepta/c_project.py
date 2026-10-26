"""Capture C build configurations before attempting a bounded migration.

Compilation databases are data, never shell programs. Only a documented flag
allowlist is forwarded to the selected Clang executable. Capture covers every
database entry and hashes the actual compiler-discovered dependencies. It is
configuration identity, not a proof of completeness across unlisted builds.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil

from .clang_capture import CaptureRejected, run_bounded
from .c_migrate import MigrationRejected


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_MAX_COMPDB_BYTES = 2_000_000
_MAX_COMPDB_ENTRIES = 32
_MAX_COMPDB_ARGS = 256
_MAX_COMPDB_PATH_BYTES = 4096
_MAX_COMPDB_ARGUMENT_BYTES = 16384


_DATABASE_FIELDS = frozenset({"path", "sha256"})
_COMPILER_FIELDS = frozenset({"path", "executable_sha256", "version", "target"})
_CONFIGURATION_FIELDS = frozenset({
    "index", "source", "directory", "original_arguments",
    "frontend_arguments", "omitted_arguments", "all_dependencies",
    "local_dependencies", "preprocessed_sha256",
    "predefined_macros_sha256", "abi_predefined_macros_sha256",
    "abi_model_arguments", "model",
})
_DEPENDENCY_FIELDS = frozenset({"path", "sha256", "bytes", "project_input"})
_ABI_MODEL_FIELDS = frozenset({"long_bits", "char_unsigned", "pointer_bits"})


def _complete(value: object, expected: frozenset[str], label: str) -> dict:
    """Closed captured-data records cannot grow unreviewed capabilities."""
    if not isinstance(value, dict) or set(value) != expected:
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Unreviewed " + label + " metadata")
    return value



def _checked_string(value: object, label: str, limit: int) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise MigrationRejected("E_C_BUILD_JSON", f"{label} must be a nonempty string without NUL")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise MigrationRejected("E_C_BUILD_JSON", f"{label} has invalid Unicode") from exc
    if size > limit:
        raise MigrationRejected("E_C_BUILD_SIZE", f"{label} exceeds the configured UTF-8 byte budget")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise MigrationRejected("E_C_BUILD_JSON", f"Duplicate compile database field: {key!r}")
        obj[key] = value
    return obj


def _reject_nonfinite_constant(value: str):
    raise MigrationRejected("E_C_BUILD_JSON", f"Nonfinite compile database JSON constant: {value}")


def _load_compdb(database: Path) -> tuple[bytes, list[dict]]:
    """Bounded, unambiguous compilation-database intake shared by capture/replay.

    A source graph and its flags cannot be attested from ambiguous duplicate
    JSON keys or a different parse from the original capture. Neither method
    runs a database-provided command; each forwards only the reviewed flags.
    """
    try:
        with database.open("rb") as stream:
            raw = stream.read(_MAX_COMPDB_BYTES + 1)
    except OSError as exc:
        raise MigrationRejected("E_C_BUILD_DATABASE", f"Cannot read compile database: {exc}") from exc
    if len(raw) > _MAX_COMPDB_BYTES:
        raise MigrationRejected("E_C_BUILD_SIZE", "Compilation database exceeds 2 MB")
    try:
        entries = json.loads(raw.decode("utf-8"),
                             object_pairs_hook=_reject_duplicate_keys,
                             parse_constant=_reject_nonfinite_constant)
    except MigrationRejected:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise MigrationRejected("E_C_BUILD_JSON", "Invalid or unbounded compile database JSON") from exc
    if not isinstance(entries, list) or not 1 <= len(entries) <= _MAX_COMPDB_ENTRIES:
        raise MigrationRejected("E_C_BUILD_DATABASE", "Expected 1–32 compilation commands")
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise MigrationRejected("E_C_BUILD_JSON", f"Compilation command #{i} is not a record")
        keys = set(entry)
        required = {"directory", "file"}
        permitted = required | {"arguments", "command", "output"}
        if (not required <= keys or not keys <= permitted
                or ("arguments" in keys) == ("command" in keys)):
            raise MigrationRejected(
                "E_C_BUILD_JSON",
                f"Command #{i} requires exactly one of arguments/command and no unknown keys")
        _checked_string(entry["directory"], "directory", _MAX_COMPDB_PATH_BYTES)
        _checked_string(entry["file"], "file", _MAX_COMPDB_PATH_BYTES)
        if "output" in entry:
            _checked_string(entry["output"], "output", _MAX_COMPDB_PATH_BYTES)
        if "arguments" in entry:
            argv = entry["arguments"]
            if not isinstance(argv, list) or not 1 <= len(argv) <= _MAX_COMPDB_ARGS:
                raise MigrationRejected("E_C_BUILD_JSON", "Invalid or excessive arguments")
            for arg in argv:
                _checked_string(arg, "argument", _MAX_COMPDB_ARGUMENT_BYTES)
        else:
            command = _checked_string(entry["command"], "command", _MAX_COMPDB_ARGUMENT_BYTES)
            try:
                argv = shlex.split(command, posix=True)
            except ValueError as exc:
                raise MigrationRejected("E_C_BUILD_JSON", "Invalid quoted compilation command") from exc
            if not 1 <= len(argv) <= _MAX_COMPDB_ARGS:
                raise MigrationRejected("E_C_BUILD_JSON", "Invalid or excessive command tokens")
            for arg in argv:
                _checked_string(arg, "command argument", _MAX_COMPDB_ARGUMENT_BYTES)
    return raw, entries


def invoke(args: list[str], directory: Path, *, stdin: str | None = None) -> str:
    try:
        run = run_bounded(args, cwd=directory, input_text=stdin, timeout=45,
                          stdout_limit=32_000_000, stderr_limit=1_000_000)
    except CaptureRejected as exc:
        code = "E_C_BUILD_SIZE" if exc.code == "E_CAPTURE_OUTPUT_SIZE" else "E_C_BUILD_TOOL"
        raise MigrationRejected(code, f"{exc.code}: {exc}") from exc
    if run.returncode:
        raise MigrationRejected("E_C_BUILD_TOOL", run.stderr[-6000:] or "Clang failed")
    return run.stdout


def _path(value: str, directory: Path) -> Path:
    path = Path(value)
    return (directory / path).resolve() if not path.is_absolute() else path.resolve()


def _flags(argv: list[str], source: Path, directory: Path) -> tuple[list[str], list[dict]]:
    if not argv or any(not isinstance(x, str) or "\x00" in x for x in argv):
        raise MigrationRejected("E_C_BUILD_COMMAND", "Expected a nonempty argv string list")
    # The database compiler is recorded but not executed; Clang is selected by
    # the caller. Wrappers, shell syntax, response files and compiler plugins
    # are not guessed or expanded.
    if Path(argv[0]).name not in {"cc", "gcc", "clang", "clang-20", "clang-19", "clang-18"}:
        raise MigrationRejected("E_C_BUILD_COMMAND", "Unsupported database compiler or wrapper")
    forwarded, omitted = [], []
    seen_source = 0
    i = 1
    while i < len(argv):
        value = argv[i]
        i += 1
        if value in {"-I", "-isystem", "-iquote", "-D", "-U"}:
            if i >= len(argv):
                raise MigrationRejected("E_C_BUILD_FLAG", "Missing flag operand: " + value)
            operand = argv[i]
            i += 1
            if operand.startswith("@"):
                raise MigrationRejected("E_C_BUILD_FLAG", "Response files are not supported")
            forwarded.extend([value, operand])
        elif value.startswith(("-I", "-D", "-U")) and len(value) > 2:
            forwarded.append(value)
        elif value in {"-std=c99", "-std=c11", "-std=c17"}:
            forwarded.append(value)
        elif value in {"-funsigned-char", "-fsigned-char"}:
            # Plain-char signedness is semantic and enters the probed model;
            # never discard this flag as a code-generation preference.
            forwarded.append(value)
        elif value in {"-c", "-g", "-g0", "-g1", "-g2", "-g3", "-O0", "-O1", "-O2", "-O3", "-Os", "-Oz", "-Wall", "-Wextra", "-Werror", "-pedantic", "-pedantic-errors", "-fPIC", "-fpic"}:
            omitted.append({"argument": value, "reason": "driver_output_or_diagnostic_flag"})
        elif value == "-o":
            if i >= len(argv):
                raise MigrationRejected("E_C_BUILD_FLAG", "Missing output operand")
            omitted.append({"argument": value, "operand": argv[i], "reason": "object_output_not_executed"})
            i += 1
        elif not value.startswith("-") and _path(value, directory) == source:
            seen_source += 1
        else:
            raise MigrationRejected("E_C_BUILD_FLAG", "Flag or argument outside the captured C profile: " + value)
    if seen_source != 1:
        raise MigrationRejected("E_C_BUILD_COMMAND", "Each command must name its C source exactly once")
    if not any(x.startswith("-std=") for x in forwarded):
        # Never guess a compiler's default language standard.
        raise MigrationRejected("E_C_BUILD_STANDARD", "An explicit -std=c99/c11/c17 is required")
    return forwarded, omitted




def _abi_model_arguments(flags: list[str]) -> list[str]:
    """Only the reviewed frontend options can determine ABI probes.

    Rechecking this derivation on replay defeats a syntactically well-formed
    and rehashed capture that injected arbitrary compiler arguments into
    the separately recorded ABI model probe.
    """
    result: list[str] = []
    index = 0
    if not isinstance(flags, list):
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Malformed captured C frontend flags")
    while index < len(flags):
        flag = flags[index]
        if not isinstance(flag, str):
            raise MigrationRejected("E_C_BUILD_IDENTITY", "Invalid captured C flag type")
        if flag in {"-I", "-isystem", "-iquote", "-D", "-U"}:
            if index + 1 >= len(flags) or not isinstance(flags[index + 1], str):
                raise MigrationRejected("E_C_BUILD_IDENTITY", "Truncated captured C frontend flag")
            index += 2
        elif flag.startswith(("-I", "-D", "-U")) and len(flag) > 2:
            index += 1
        elif flag.startswith("-std=") or flag in {"-funsigned-char", "-fsigned-char"}:
            result.append(flag)
            index += 1
        else:
            raise MigrationRejected("E_C_BUILD_IDENTITY", "Unreviewed captured C ABI model option")
    return result


def _dependencies(clang: str, flags: list[str], source: Path, directory: Path, *, system: bool) -> list[Path]:
    text = invoke([clang, *flags, "-M" if system else "-MM", "-MT", "hepta_dependencies", str(source)], directory)
    body = text.replace("\\\n", " ").partition(":")[2]
    paths = sorted({_path(token, directory) for token in shlex.split(body)}, key=str)
    if not paths or source not in paths or len(paths) > 512:
        raise MigrationRejected("E_C_BUILD_DEPENDENCIES", "Missing source or unsupported dependency inventory")
    return paths


def verify_capture(capture: dict) -> None:
    """Fail closed on both content and *configuration* identity at replay."""
    expected_fields = {"schema", "database", "compiler", "configurations",
                       "dependencies", "scope", "sha256"}
    if (not isinstance(capture, dict) or set(capture) != expected_fields
            or capture.get("schema") != "hepta.c-build.v1"):
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Missing or unknown captured build fields")
    bound = capture["sha256"]
    try:
        serialized = json.dumps({key: value for key, value in capture.items() if key != "sha256"},
                                sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, TypeError) as exc:
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Unserializable build manifest") from exc
    if not isinstance(bound, str) or digest(serialized) != bound:
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Captured build manifest identity differs")
    if capture["scope"] != "all_listed_commands_only_not_unlisted_platforms_or_configurations":
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Unexpected capture scope")
    db_record = _complete(capture["database"], _DATABASE_FIELDS, "build database")
    compiler = _complete(capture["compiler"], _COMPILER_FIELDS, "compiler")
    if (not isinstance(db_record["path"], str)
            or not isinstance(db_record["sha256"], str)
            or not isinstance(compiler["path"], str)
            or not isinstance(compiler["version"], str)
            or not isinstance(compiler["target"], str)
            or not isinstance(compiler["executable_sha256"], str)):
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Malformed compiler/database identity")
    database = Path(db_record["path"])
    parsed_bytes, entries = _load_compdb(database)
    # The same exact bytes must supply both the parsed replay commands and
    # the captured content identity. Never attest a second unrelated read.
    if digest(parsed_bytes) != db_record["sha256"]:
        raise MigrationRejected("E_C_BUILD_CHANGED", "Parsed compilation database content changed")
    configs = capture["configurations"]
    if (not isinstance(entries, list) or not isinstance(configs, list)
            or len(entries) != len(configs) or not 1 <= len(entries) <= 32):
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Configuration denominator differs from source database")
    dependencies_seen = set()
    local_dependencies_seen = set()
    for index, (entry, config) in enumerate(zip(entries, configs)):
        if not isinstance(entry, dict):
            raise MigrationRejected("E_C_BUILD_IDENTITY", "Invalid database configuration")
        _complete(config, _CONFIGURATION_FIELDS, "C configuration")
        model = _complete(config["model"], _ABI_MODEL_FIELDS, "C target data model")
        if (type(config["index"]) is not int or type(model["long_bits"]) is not int
                or type(model["pointer_bits"]) is not int
                or type(model["char_unsigned"]) is not bool):
            raise MigrationRejected("E_C_BUILD_IDENTITY", "C model/index types differ from compiler")
        directory = _path(entry["directory"], database.parent)
        source = _path(entry["file"], directory)
        argv = entry.get("arguments")
        if argv is None:
            argv = shlex.split(entry["command"], posix=True)
        flags, omitted = _flags(argv, source, directory)
        if (config["index"] != index or config["source"] != str(source)
                or config["directory"] != str(directory)
                or config["original_arguments"] != argv
                or config["frontend_arguments"] != flags
                or config["omitted_arguments"] != omitted):
            raise MigrationRejected("E_C_BUILD_IDENTITY", "Recorded compiler invocation differs from database")
        if config.get("abi_model_arguments") != _abi_model_arguments(flags):
            raise MigrationRejected("E_C_BUILD_IDENTITY", "ABI probe flags differ from allowed frontend flags")
        all_paths, local_paths = config["all_dependencies"], config["local_dependencies"]
        if not isinstance(all_paths, list) or not isinstance(local_paths, list):
            raise MigrationRejected("E_C_BUILD_IDENTITY", "Malformed configuration dependency inventories")
        if (any(not isinstance(path, str) or not path or "\x00" in path
                for path in [*all_paths, *local_paths])
                or len(set(all_paths)) != len(all_paths)
                or len(set(local_paths)) != len(local_paths)
                or all_paths != sorted(all_paths)
                or local_paths != sorted(local_paths)
                or not set(local_paths) <= set(all_paths)):
            raise MigrationRejected("E_C_BUILD_IDENTITY", "Unreviewed dependency order or locality")
        dependencies_seen.update(all_paths)
        local_dependencies_seen.update(local_paths)
    dependencies = capture["dependencies"]
    if not isinstance(dependencies, list):
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Malformed dependency inventory")
    for item in dependencies:
        _complete(item, _DEPENDENCY_FIELDS, "dependency")
        if (not isinstance(item["path"], str) or not isinstance(item["sha256"], str)
                or type(item["bytes"]) is not int or item["bytes"] < 0
                or type(item["project_input"]) is not bool):
            raise MigrationRejected("E_C_BUILD_IDENTITY", "Invalid dependency metadata type")
        if item["project_input"] is not (item["path"] in local_dependencies_seen):
            raise MigrationRejected("E_C_BUILD_IDENTITY", "Local header provenance differs from discovered dependencies")
    recorded_paths = [item["path"] for item in dependencies]
    if (len(set(recorded_paths)) != len(recorded_paths)
            or set(recorded_paths) != dependencies_seen):
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Dependency inventory is incomplete or duplicated")
    for item in dependencies:
        path = Path(item["path"])
        if not path.is_file():
            raise MigrationRejected("E_C_BUILD_CHANGED", "Captured build input disappeared: " + str(path))
        content = path.read_bytes()
        if digest(content) != item["sha256"]:
            raise MigrationRejected("E_C_BUILD_CHANGED", "Captured build input changed: " + str(path))
        if len(content) != item["bytes"]:
            raise MigrationRejected("E_C_BUILD_IDENTITY", "Dependency byte count differs from captured content")
    if digest(Path(compiler["path"]).read_bytes()) != compiler["executable_sha256"]:
        raise MigrationRejected("E_C_BUILD_CHANGED", "Selected compiler changed")
    # The same binary may report a different driver/target identity under a
    # changed runtime environment. Do not silently replay stale target facts.
    directory = Path(capture["database"]["path"]).parent
    version = invoke([compiler["path"], "--version"], directory).splitlines()
    target = invoke([compiler["path"], "-dumpmachine"], directory).strip()
    if version[:1] != [compiler["version"]] or target != compiler["target"]:
        raise MigrationRejected("E_C_BUILD_CHANGED", "Selected compiler target or identity changed")
    # Hashing previously resolved paths alone would miss a retargeted include
    # symlink or a newly selected header. Re-resolve the dependency graph and
    # preprocess bytes as well; fail closed if either identity has changed.
    for config in capture["configurations"]:
        directory, source = Path(config["directory"]), Path(config["source"])
        flags = config["frontend_arguments"]
        actual = list(map(str, _dependencies(compiler["path"], flags, source, directory, system=True)))
        local = list(map(str, _dependencies(compiler["path"], flags, source, directory, system=False)))
        if actual != config["all_dependencies"] or local != config["local_dependencies"]:
            raise MigrationRejected("E_C_BUILD_CHANGED", "Compiler dependency graph changed")
        preprocessed = invoke([compiler["path"], *flags, "-E", str(source)], directory)
        if digest(preprocessed.encode()) != config["preprocessed_sha256"]:
            raise MigrationRejected("E_C_BUILD_CHANGED", "Preprocessed configuration changed")
        # Macro inventories and ABI model flags are distinct from a TU's
        # preprocessed bytes. A changed *unused* predefined macro can alter a
        # future translated declaration or invalidate recorded target facts.
        current_macros = invoke([compiler["path"], *flags, "-dM", "-E", "-x", "c", "-"],
                                directory, stdin="")
        current_abi_macros = invoke([compiler["path"], *config["abi_model_arguments"],
                                     "-dM", "-E", "-x", "c", "-"], directory, stdin="")
        if (digest(current_macros.encode()) != config["predefined_macros_sha256"]
                or digest(current_abi_macros.encode()) != config["abi_predefined_macros_sha256"]):
            raise MigrationRejected("E_C_BUILD_CHANGED", "Predefined or ABI macro model changed")
        observed = dict(re.findall(r"^#define (__[A-Z0-9_]+__) (\d+)$", current_abi_macros, flags=re.M))
        expected = {"long_bits": 8 * int(observed.get("__SIZEOF_LONG__", "0")),
                    "char_unsigned": "#define __CHAR_UNSIGNED__ 1" in current_abi_macros,
                    "pointer_bits": 8 * int(observed.get("__SIZEOF_POINTER__", "0"))}
        if config["model"] != expected:
            raise MigrationRejected("E_C_BUILD_CHANGED", "Captured C ABI model differs from actual compiler")


def capture_project(database: str | Path, *, clang: str = "clang") -> dict:
    """Capture all configurations; duplicate sources require a separate run/db.

    The migration profile deliberately rejects multiple configurations of the
    same source in one artifact. Their behavior can differ after preprocessing.
    Users may supply one complete compilation database per intended build.
    """
    db = Path(database).resolve()
    raw, entries = _load_compdb(db)
    executable = shutil.which(clang)
    if executable is None:
        raise MigrationRejected("E_C_BUILD_TOOL", "Clang executable unavailable")
    executable = str(Path(executable).resolve())
    compiler = {"path": executable, "executable_sha256": digest(Path(executable).read_bytes()),
                "version": invoke([executable, "--version"], db.parent).splitlines()[0],
                "target": invoke([executable, "-dumpmachine"], db.parent).strip()}
    configs, dependencies, seen = [], {}, set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str) or not isinstance(entry.get("directory"), str):
            raise MigrationRejected("E_C_BUILD_DATABASE", "Commands require file and directory strings")
        directory = _path(entry["directory"], db.parent)
        source = _path(entry["file"], directory)
        if source.suffix != ".c" or not source.is_file() or source in seen:
            raise MigrationRejected("E_C_BUILD_SOURCE", "Missing .c source or duplicate source configuration")
        seen.add(source)
        argv = entry.get("arguments")
        if argv is None:
            if not isinstance(entry.get("command"), str):
                raise MigrationRejected("E_C_BUILD_COMMAND", "Expected arguments or command")
            argv = shlex.split(entry["command"], posix=True)
        if not isinstance(argv, list):
            raise MigrationRejected("E_C_BUILD_COMMAND", "arguments must be a string list")
        flags, omitted = _flags(argv, source, directory)
        all_deps = _dependencies(executable, flags, source, directory, system=True)
        local_deps = set(_dependencies(executable, flags, source, directory, system=False))
        for path in all_deps:
            content = path.read_bytes()
            if len(content) > 8_000_000:
                raise MigrationRejected("E_C_BUILD_SIZE", "Dependency exceeds 8 MB: " + str(path))
            item = {"path": str(path), "sha256": digest(content), "bytes": len(content),
                    "project_input": path in local_deps}
            if str(path) in dependencies:
                previous = dependencies[str(path)]
                if item["sha256"] != previous["sha256"]:
                    raise MigrationRejected("E_C_BUILD_CHANGED", "Dependency changed during capture")
                item["project_input"] |= previous["project_input"]
            dependencies[str(path)] = item
        preprocessed = invoke([executable, *flags, "-E", str(source)], directory)
        macros = invoke([executable, *flags, "-dM", "-E", "-x", "c", "-"], directory, stdin="")
        # User -D/-U macros may intentionally spell predefined names. They
        # affect preprocessed source semantics, but cannot attest native ABI
        # sizes or char signedness. Probe those with the actual semantic
        # compiler options only, independently of user macro overrides.
        model_flags = _abi_model_arguments(flags)
        abi_macros = invoke([executable, *model_flags, "-dM", "-E", "-x", "c", "-"], directory, stdin="")
        numeric = dict(re.findall(r"^#define (__[A-Z0-9_]+__) (\d+)$", abi_macros, flags=re.M))
        if any(numeric.get(name) != value for name, value in {
            "__CHAR_BIT__": "8", "__SIZEOF_INT__": "4", "__SIZEOF_LONG_LONG__": "8",
            "__SIZEOF_POINTER__": "8", "__SIZEOF_FLOAT__": "4", "__SIZEOF_DOUBLE__": "8",
        }.items()):
            raise MigrationRejected("E_C_BUILD_MODEL", "Only the measured 64-bit hosted C data model is supported")
        configs.append({"index": index, "source": str(source), "directory": str(directory),
                        "original_arguments": argv, "frontend_arguments": flags,
                        "omitted_arguments": omitted,
                        "all_dependencies": list(map(str, all_deps)),
                        "local_dependencies": sorted(map(str, local_deps)),
                        "preprocessed_sha256": digest(preprocessed.encode()),
                        "predefined_macros_sha256": digest(macros.encode()),
                        "abi_predefined_macros_sha256": digest(abi_macros.encode()),
                        "abi_model_arguments": model_flags,
                        "model": {"long_bits": 8 * int(numeric.get("__SIZEOF_LONG__", "0")),
                                  "char_unsigned": "#define __CHAR_UNSIGNED__ 1" in abi_macros,
                                  "pointer_bits": 64}})
    capture = {"schema": "hepta.c-build.v1", "database": {"path": str(db), "sha256": digest(raw)},
               "compiler": compiler, "configurations": configs,
               "dependencies": sorted(dependencies.values(), key=lambda item: item["path"]),
               "scope": "all_listed_commands_only_not_unlisted_platforms_or_configurations"}
    capture["sha256"] = digest(json.dumps(capture, sort_keys=True, separators=(",", ":"),
                                          allow_nan=False).encode())
    verify_capture(capture)
    return capture
