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


_MAX_COMPDB_BYTES = 4_000_000
_MAX_COMPDB_NODES = 65_536
_MAX_COMPDB_DEPTH = 48
_MAX_COMPDB_TEXT = 65_536


def _unique_compdb_fields(pairs):
    item = {}
    for key, value in pairs:
        if key in item:
            raise MigrationRejected("E_C_BUILD_DATABASE", "Compilation database contains duplicate JSON keys")
        item[key] = value
    return item


def _reject_compdb_constant(value):
    raise MigrationRejected("E_C_BUILD_DATABASE", "Nonfinite JSON constant in compilation database: " + value)


def _read_compilation_database(path: Path) -> tuple[bytes, list[dict]]:
    """Read one bounded, strict database on capture and identity replay.

    The compilation database is untrusted data. Prevent huge files, duplicate
    keys, nonfinite constants and deeply nested fields from causing implicit
    compiler options to be ignored or consuming unbounded resources.
    """
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_COMPDB_BYTES + 1)
    except OSError as exc:
        raise MigrationRejected("E_C_BUILD_DATABASE", "Cannot read compilation database") from exc
    if not raw or len(raw) > _MAX_COMPDB_BYTES:
        raise MigrationRejected("E_C_BUILD_SIZE", "Compilation database exceeds bounded input size")
    try:
        entries = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_compdb_fields,
            parse_constant=_reject_compdb_constant)
    except MigrationRejected:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError,
            RecursionError, OverflowError) as exc:
        raise MigrationRejected("E_C_BUILD_DATABASE", "Invalid bounded compilation database JSON") from exc
    if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
        raise MigrationRejected("E_C_BUILD_DATABASE", "Expected 1–32 compilation commands")

    # Explicit iterative shape budget bounds future extension fields too.
    # Only JSON collections and strings are necessary for this build profile.
    pending = [(entries, 0)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > _MAX_COMPDB_NODES or depth > _MAX_COMPDB_DEPTH:
            raise MigrationRejected("E_C_BUILD_SIZE", "Compilation database exceeds JSON node/depth budget")
        if isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, dict):
            if any(not isinstance(key, str) or len(key) > 256 for key in value):
                raise MigrationRejected("E_C_BUILD_DATABASE", "Invalid compilation database field name")
            pending.extend((item, depth + 1) for item in value.values())
        elif not isinstance(value, str) or len(value) > _MAX_COMPDB_TEXT:
            raise MigrationRejected("E_C_BUILD_DATABASE", "Unsupported or oversized compilation database value")
    if any(not isinstance(entry, dict) for entry in entries):
        raise MigrationRejected("E_C_BUILD_DATABASE", "Compilation database entries must be records")
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
    database = Path(capture["database"]["path"])
    _, entries = _read_compilation_database(database)
    configs = capture["configurations"]
    if (not isinstance(entries, list) or not isinstance(configs, list)
            or len(entries) != len(configs) or not 1 <= len(entries) <= 32):
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Configuration denominator differs from source database")
    dependencies_seen = set()
    for index, (entry, config) in enumerate(zip(entries, configs)):
        if not isinstance(entry, dict) or not isinstance(config, dict):
            raise MigrationRejected("E_C_BUILD_IDENTITY", "Invalid database configuration")
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
        dependencies_seen.update(config["all_dependencies"])
    recorded_paths = [item["path"] for item in capture["dependencies"]]
    if (len(set(recorded_paths)) != len(recorded_paths)
            or set(recorded_paths) != dependencies_seen):
        raise MigrationRejected("E_C_BUILD_IDENTITY", "Dependency inventory is incomplete or duplicated")
    for item in [capture["database"], *capture["dependencies"]]:
        path = Path(item["path"])
        if not path.is_file() or digest(path.read_bytes()) != item["sha256"]:
            raise MigrationRejected("E_C_BUILD_CHANGED", "Captured build input changed: " + str(path))
    compiler = capture["compiler"]
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
    raw, entries = _read_compilation_database(db)
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
        model_flags = []
        flag_index = 0
        while flag_index < len(flags):
            flag = flags[flag_index]
            if flag in {"-I", "-isystem", "-iquote", "-D", "-U"}:
                flag_index += 2
                continue
            if flag.startswith("-std=") or flag in {"-funsigned-char", "-fsigned-char"}:
                model_flags.append(flag)
            flag_index += 1
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
