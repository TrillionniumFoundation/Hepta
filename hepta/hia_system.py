"""HIA system-dialect compiler staging for complete configured kernel builds.

This profile preserves LLVM system semantics through typed HIA reconstruction.
It is independent of the safe bounded HIA Core profiles. Every payload compile
must consume a retained HIA program; unsupported reconstruction is a hard error.
"""
from __future__ import annotations

import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import uuid

SYSTEM_SCHEMA = "hepta.hia.system.v1"
ASSEMBLY_SCHEMA = "hepta.hia.machine-assembly.v1"
MANIFEST_SCHEMA = "hepta.hia.system-build-environment.v1"
PROGRAM_BINDING_SCHEMA = "hepta.hia.system-program-binding.v1"


class SystemCompileError(ValueError):
    pass


def require(value, message):
    if not value:
        raise SystemCompileError(message)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def bad_constant(value):
        raise SystemCompileError("non-finite JSON constant: " + value)

    return json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def binding(path):
    path = Path(path).resolve()
    info = path.stat()
    return {"path": str(path), "bytes": info.st_size, "sha256": sha(path)}


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(value if isinstance(value, bytes) else canonical(value) + b"\n")


def replace_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    write_new(temporary, value)
    os.replace(temporary, path)


def load_manifest():
    path = Path(os.environ["HIA_SYSTEM_MANIFEST"]).resolve(strict=True)
    value = strict_json(path.read_bytes())
    require(value.get("schema") == MANIFEST_SCHEMA, "explicit HIA system build manifest required")
    require(value.get("mode") in ("import", "replay"), "explicit import/replay mode required")
    for name in ("clang", "clangxx", "llvm_dis", "codec"):
        tool = value["tools"][name]
        require(binding(tool["path"]) == tool, "bound tool changed: " + name)
    for name in ("source_root", "build_root", "program_root", "ledger_root"):
        require(Path(value[name]).is_absolute(), "absolute manifest path required: " + name)
    require(Path(value["ledger_root"]).resolve().is_dir(), "ledger must be created before dispatch")
    return path, value


# This is an argv boundary parser, not a whitelist of ordinary compiler flags.
# Every positional token is retained, even if its suffix is unfamiliar.
TAKES_VALUE = frozenset((
    "-o", "--output", "-x", "-include", "-imacros", "-I", "-isystem", "-iquote",
    "-idirafter", "-iprefix", "-iwithprefix", "-iwithprefixbefore", "--sysroot",
    "-isysroot", "-resource-dir", "-B", "-MF", "-MT", "-MQ", "-MJ", "-D", "-U",
    "-target", "--target", "-Xclang", "-mllvm", "-Xassembler", "-Xpreprocessor",
    "-Xlinker", "-include-pch", "-fmodule-file", "-imsvc", "-iframework",
    "-object-file-name", "-opt-record-file", "-opt-record-passes",
    "-opt-record-format", "-objc-isystem", "-objcxx-isystem", "-L", "-l",
    "-u", "-T", "-z", "-arch"
))
DEPENDENCY_VALUE = frozenset(("-MF", "-MT", "-MQ", "-MJ"))
DEPENDENCY_SINGLE = frozenset(("-M", "-MM", "-MD", "-MMD", "-MG", "-MP"))
PREPROCESS_VALUE = frozenset((
    "-include", "-imacros", "-I", "-isystem", "-iquote", "-idirafter", "-iprefix",
    "-iwithprefix", "-iwithprefixbefore", "-D", "-U", "-include-pch",
    "-Xpreprocessor", "-objc-isystem", "-objcxx-isystem", "-imsvc", "-iframework"
))
PREPROCESS_SINGLE = frozenset(("-nostdinc", "-nostdinc++", "-undef", "-traditional-cpp"))
JOINED_VALUE = tuple(sorted((
    "-MF", "-MT", "-MQ", "-MJ", "-D", "-U", "-I", "-L", "-l", "-B", "-x",
    "-isystem", "-iquote", "-idirafter", "-iprefix", "-iwithprefixbefore",
    "-iwithprefix", "-imacros", "-include"
), key=len, reverse=True))
# LLVM20 options sharing the '-o' prefix must win before joined '-oFILE'.
O_PREFIX_FLAGS = frozenset((
    "-object", "-objcmt-migrate-literals", "-objcmt-migrate-subscripting",
    "-objcmt-migrate-property", "-objcmt-migrate-all",
    "-objcmt-migrate-readonly-property", "-objcmt-migrate-readwrite-property",
    "-objcmt-migrate-property-dot-syntax", "-objcmt-migrate-annotation",
    "-objcmt-migrate-instancetype", "-objcmt-migrate-ns-macros",
    "-objcmt-migrate-protocol-conformance", "-objcmt-atomic-property",
    "-objcmt-returns-innerpointer-property", "-objcmt-ns-nonatomic-iosonly",
    "-objcmt-migrate-designated-init"
))
O_PREFIX_JOINED = (
    "-object-file-name=", "-objcmt-allowlist-dir-path=",
    "-objcmt-whitelist-dir-path=", "-objcmt-white-list-dir-path="
)
C_LANGUAGES = frozenset(("c", "cpp-output"))
ASM_LANGUAGES = frozenset(("assembler", "assembler-with-cpp"))
IR_LANGUAGES = frozenset(("ir", "llvm-ir"))
SUFFIX_LANGUAGES = {".c": "c", ".i": "cpp-output",
                    ".S": "assembler-with-cpp", ".s": "assembler",
                    ".bc": "ir", ".ll": "ir"}
OBJECT_SUFFIXES = frozenset((".o", ".a", ".so", ".dylib", ".lib"))
QUERY_FLAGS = frozenset((
    "--version", "-dumpversion", "-dumpfullversion", "-dumpmachine",
    "-print-libgcc-file-name", "-print-search-dirs", "-print-resource-dir",
    "-print-target-triple", "-print-effective-triple", "-print-multiarch",
    "-print-multi-directory", "-print-multi-lib", "--help", "-help", "-v",
    "-print-supported-cpus", "-print-supported-extensions"
))
QUERY_PREFIXES = ("-print-file-name=", "-print-prog-name=", "--help=")
KBUILD_PROBE_DIRECTORY = re.compile(r"\.tmp_[0-9]+\Z")


def expand_arguments(arguments, records, depth=0):
    require(depth <= 4, "nested response-file limit")
    expanded = []
    for argument in arguments:
        if argument.startswith("@"):
            path = Path(argument[1:]).resolve(strict=True)
            require(path.is_file() and path.stat().st_size <= 16 * 1024 * 1024,
                    "response file is not a bounded regular file")
            data = path.read_text()
            require("\x00" not in data, "NUL in response file")
            records.append(binding(path))
            expanded.extend(expand_arguments(shlex.split(data, posix=True), records, depth + 1))
        else:
            expanded.append(argument)
    return expanded


def argument_entries(arguments):
    entries, i, positional = [], 0, False
    while i < len(arguments):
        item = arguments[i]
        require(type(item) is str and "\x00" not in item, "invalid compiler argument")
        if not positional and item == "--":
            entries.append({"name": "--", "tokens": [item]})
            positional = True
            i += 1
            continue
        if positional or item == "-" or not item.startswith("-"):
            entries.append({"name": "input", "value": item, "tokens": [item]})
            i += 1
            continue
        if item in TAKES_VALUE:
            require(i + 1 < len(arguments), "missing argument after " + item)
            value = arguments[i + 1]
            require(type(value) is str and value and "\x00" not in value,
                    "empty or invalid argument after " + item)
            entries.append({"name": "-o" if item == "--output" else item,
                            "value": value, "tokens": [item, value]})
            i += 2
            continue
        if item.startswith("--output="):
            value = item[len("--output="):]
            require(value, "empty --output path")
            entries.append({"name": "-o", "value": value, "tokens": [item]})
        elif item in O_PREFIX_FLAGS or item.startswith(O_PREFIX_JOINED):
            entries.append({"name": item.split("=", 1)[0], "tokens": [item]})
        elif item.startswith("-o") and len(item) > 2:
            entries.append({"name": "-o", "value": item[2:], "tokens": [item]})
        elif item.startswith("-Wp,"):
            entries.append({"name": "-Wp", "value": item[4:], "tokens": [item]})
        else:
            joined = next((prefix for prefix in JOINED_VALUE
                           if item.startswith(prefix) and len(item) > len(prefix)), None)
            entries.append({"name": joined or item,
                            **({"value": item[len(joined):]} if joined else {}),
                            "tokens": [item]})
        i += 1
    return entries


def dependency_options(entries, output):
    mode, filename, targets, flags, forwarded = None, None, [], [], {}
    scan_only = False

    def consume(name, value=None):
        nonlocal mode, filename, scan_only
        if name in ("-MD", "-MMD", "-M", "-MM"):
            require(mode is None, "multiple dependency generation modes")
            mode = name
            scan_only = name in ("-M", "-MM")
        elif name == "-MF":
            require(filename is None, "duplicate dependency output")
            require(value, "empty dependency output")
            filename = value
        elif name in ("-MT", "-MQ"):
            require(value, "empty dependency target")
            targets.append([name, value])
        elif name == "-MJ":
            raise SystemCompileError("compiler database side output needs an explicit route")
        else:
            flags.append(name)

    for number, entry in enumerate(entries):
        name = entry["name"]
        if name in DEPENDENCY_SINGLE | DEPENDENCY_VALUE:
            consume(name, entry.get("value"))
        elif name == "-Wp":
            pieces, remaining, i = entry["value"].split(","), [], 0
            while i < len(pieces):
                part = pieces[i]
                if part in ("-MD", "-MMD"):
                    require(i + 1 < len(pieces) and pieces[i + 1],
                            "missing -Wp dependency filename")
                    consume(part)
                    consume("-MF", pieces[i + 1])
                    i += 2
                elif part in DEPENDENCY_VALUE:
                    require(i + 1 < len(pieces) and pieces[i + 1],
                            "missing -Wp dependency value")
                    consume(part, pieces[i + 1])
                    i += 2
                elif part in DEPENDENCY_SINGLE:
                    consume(part)
                    i += 1
                else:
                    require(part, "empty -Wp argument")
                    remaining.append(part)
                    i += 1
            forwarded[number] = remaining
    if filename is not None or targets:
        require(mode is not None, "dependency output/target without generation mode")
    if mode and not filename and not scan_only:
        require(output not in (None, "-", "/dev/null"),
                "implicit dependency path requires a named output")
        filename = str(Path(output).with_suffix(".d"))
    return {"mode": mode, "filename": filename, "targets": targets,
            "flags": flags, "scan_only": scan_only, "forwarded": forwarded}


def parse_arguments(arguments):
    entries = argument_entries(arguments)
    output, language, inputs, modes = None, None, [], []
    for entry in entries:
        name, value = entry["name"], entry.get("value")
        if name == "-o":
            require(output is None, "duplicate compiler output")
            output = value
        elif name == "-x":
            language = None if value == "none" else value
        elif name == "input":
            inferred = language or SUFFIX_LANGUAGES.get(Path(value).suffix)
            inputs.append({"path": value, "language": inferred,
                           "explicit_language": language is not None})
        elif name in ("-c", "-S", "-E"):
            if name not in modes:
                modes.append(name)
        elif name == "-Xclang" and value in (
                "-o", "-x", "-emit-obj", "-emit-llvm", "-emit-llvm-bc",
                "-E", "-S", "-dependency-file", "-MT", "-MQ"):
            raise SystemCompileError("frontend phase/output override requires an explicit route")
        elif name in ("-cc1", "-cc1as"):
            raise SystemCompileError("direct cc1 payload bypass is forbidden")
    require(len(modes) <= 1, "conflicting compiler phases")
    deps = dependency_options(entries, output)
    return {"entries": entries, "input_records": inputs, "output": output,
            "mode": modes[0] if modes else None, "dependency_options": deps}


def _probe_sink(output, mode):
    if output == "/dev/null":
        return "discard"
    if output == "-" and mode in ("-E", "-S"):
        return "stdout"
    if output is None:
        return "implicit-discard" if mode != "-E" else "stdout"
    path = Path(output)
    # The exact scripts/Makefile.compiler try-run shape. Merely containing
    # ".tmp" or living under /tmp is not authorization to bypass target HIA.
    if path.name == "tmp" and KBUILD_PROBE_DIRECTORY.fullmatch(path.parent.name):
        return "kbuild-try-run-temporary"
    return None


def classify(arguments):
    parsed = parse_arguments(arguments)
    inputs, output, mode = parsed["input_records"], parsed["output"], parsed["mode"]
    deps = parsed["dependency_options"]
    sink = _probe_sink(output, mode)
    kind, probe = None, None
    special = len(inputs) == 1 and inputs[0]["path"] in ("-", "/dev/null")
    if special and sink is not None:
        require(inputs[0]["language"] in C_LANGUAGES | ASM_LANGUAGES,
                "capability input requires explicit C/assembler language")
        kind = "compiler_capability_probe"
        probe = {"input": "stdin" if inputs[0]["path"] == "-" else "empty-device",
                 "output_boundary": sink,
                 "force_discard_output": output is None and mode != "-E",
                 "rule": "pinned Kbuild compiler probe; no target artifact"}
    elif special and inputs[0]["path"] == "-":
        raise SystemCompileError("stdin target payload needs an explicit source identity")
    elif mode == "-E" or deps["scan_only"]:
        require(inputs, "preprocessing/dependency scan requires an input")
        require(all(item["language"] in C_LANGUAGES | ASM_LANGUAGES for item in inputs),
                "unclassified preprocessor input")
        kind = "dependency_scan" if deps["scan_only"] else "preprocess"
    elif not inputs:
        require(mode is None and output is None, "compiler phase/output has no payload input")
        require(any(a in QUERY_FLAGS or a.startswith(QUERY_PREFIXES) for a in arguments),
                "unclassified invocation without inputs")
        kind = "compiler_query"
    elif all(item["language"] is None and Path(item["path"]).suffix in OBJECT_SUFFIXES
             for item in inputs):
        require(mode is None, "object-only input is not a source compilation")
        kind = "object_link"
    else:
        require(len(inputs) == 1, "multiple compiler payload inputs require an explicit route")
        language = inputs[0]["language"]
        require(language not in IR_LANGUAGES,
                "unregistered incoming LLVM payload is not HIA source")
        require(language in C_LANGUAGES | ASM_LANGUAGES,
                "unknown target input/language; explicit supported -x required")
        require(mode in ("-c", "-S"), "target compile+link must be explicitly staged")
        require(output not in (None, "-", "/dev/null"), "named target output required")
        require("-fsyntax-only" not in arguments and "-###" not in arguments,
                "non-emitting target invocation requires an explicit probe boundary")
        require(deps["filename"] != "-", "target dependencies require a named file")
        kind = "target_assembly" if language in ASM_LANGUAGES else "target_c"
        if kind == "target_assembly":
            require(mode == "-c", "assembly payload requires an object-producing phase")
    result = {"kind": kind, "inputs": [item["path"] for item in inputs],
              "input_records": inputs, "output": output,
              "language": inputs[0]["language"] if len(inputs) == 1 else None,
              "mode": mode, "dependency": deps["filename"],
              "dependency_requested": deps["mode"] is not None,
              "dependency_targets": deps["targets"]}
    if probe is not None:
        result["probe"] = probe
    return result


def change_phase(arguments, source, output, mode, *, backend=False, assembly=False,
                 dependency_output=None):
    parsed = parse_arguments(arguments)
    inputs = parsed["input_records"]
    require(len(inputs) == 1, "phase change requires exactly one source input")
    deps, result = parsed["dependency_options"], []
    for number, entry in enumerate(parsed["entries"]):
        name = entry["name"]
        if name in ("input", "--", "-o", "-x", "-c", "-S", "-E"):
            continue
        if name in DEPENDENCY_VALUE | DEPENDENCY_SINGLE:
            continue
        if name == "-Wp":
            if not backend and deps["forwarded"].get(number):
                result.append("-Wp," + ",".join(deps["forwarded"][number]))
            continue
        if backend and (
                name in PREPROCESS_SINGLE or
                (name in PREPROCESS_VALUE and not (assembly and name == "-I")) or
                name.startswith("-std=") or name == "-ansi"):
            continue
        result.extend(entry["tokens"])
    result += ["-Qunused-arguments"]
    if backend:
        result += ["-x", "assembler" if assembly else "ir"]
    else:
        language = inputs[0]["language"]
        require(language in C_LANGUAGES | ASM_LANGUAGES, "unsupported frontend language")
        result += ["-x", language]
        if deps["mode"] is not None:
            require(not deps["scan_only"], "dependency-only input is not a payload phase")
            destination = str(dependency_output) if dependency_output else deps["filename"]
            require(destination and destination != "-", "named frontend dependency file required")
            result += [deps["mode"], "-MF", destination, *deps["flags"]]
            if deps["targets"]:
                for target in deps["targets"]:
                    result.extend(target)
            else:
                # -MQ reproduces the driver's default make escaping for the
                # original output, rather than binding dependencies to frontend.bc.
                result += ["-MQ", parsed["output"]]
    return result + [mode, str(source), "-o", str(output)]

def normalize_key(arguments, cwd, manifest):
    roots = ((manifest["build_root"], "{BUILD}"), (manifest["source_root"], "{SOURCE}"))
    def norm(value):
        for before, after in roots:
            value = value.replace(before, after)
        return value
    return hashlib.sha256(canonical({"cwd": norm(str(cwd)), "argv": [norm(a) for a in arguments]})).hexdigest()


def run_command(record, directory, name, argv, *, input_bytes=None, forward=False,
                allow_failure=False):
    stem = directory / ("%02d-%s" % (len(record["commands"]), name))
    started = time.monotonic_ns()
    with Path(str(stem) + ".stdout").open("xb") as out, Path(str(stem) + ".stderr").open("xb") as err:
        completed = subprocess.run([str(x) for x in argv], input=input_bytes,
                                   stdout=out, stderr=err, timeout=600, check=False)
    item = {"name": name, "argv": [str(x) for x in argv], "exit_code": completed.returncode,
            "elapsed_ns": time.monotonic_ns() - started,
            "stdout": binding(str(stem) + ".stdout"), "stderr": binding(str(stem) + ".stderr")}
    record["commands"].append(item)
    if forward:
        sys.stdout.buffer.write(Path(item["stdout"]["path"]).read_bytes())
        sys.stdout.buffer.flush()
        sys.stderr.buffer.write(Path(item["stderr"]["path"]).read_bytes())
        sys.stderr.buffer.flush()
    if not allow_failure:
        require(completed.returncode == 0, "command failed: " + name + "; " + item["stderr"]["path"])
    return item


def canonical_ir(llvm_dis, bitcode, output, record, directory, stage):
    run_command(record, directory, stage, [llvm_dis, bitcode, "-o", output])
    lines = output.read_bytes().splitlines(keepends=True)
    require(lines and lines[0].startswith(b"; ModuleID = "), "expected LLVM disassembly header")
    # The external file/buffer name is not serialized IR semantics. Nothing else,
    # including metadata, source_filename or attributes, is discarded.
    return hashlib.sha256(b"".join(lines[1:])).hexdigest()


_ASM_TOKEN = re.compile(
    r'(?P<space>[ \t\r]+)|(?P<comment>\#[^\n]*)|(?P<quoted>"(?:\\.|[^"\\])*")'
    r'|(?P<name>[A-Za-z_.$][A-Za-z_.$0-9]*)|(?P<number>[0-9][A-Za-z_0-9.]*)'
    r'|(?P<punct>.)', re.DOTALL
)


def assembly_program(data):
    text = data.decode("utf-8", errors="strict")
    require("\x00" not in text, "NUL in assembly")
    statements = []
    for line in text.splitlines(keepends=True):
        tokens = []
        position = 0
        while position < len(line):
            match = _ASM_TOKEN.match(line, position)
            require(match is not None, "unrecognized assembly token")
            tokens.append({"kind": match.lastgroup, "text": match.group()})
            position = match.end()
        significant = [t["text"] for t in tokens if t["kind"] not in ("space", "comment") and t["text"] != "\n"]
        kind = "empty" if not significant else "directive" if significant[0].startswith(".") else "machine_statement"
        statements.append({"kind": kind, "tokens": tokens})
    return {"schema": ASSEMBLY_SCHEMA, "encoding": "utf-8", "statements": statements,
            "semantics": "explicit x86 GNU-assembler machine escape; not safe HIA Core"}


def emit_assembly(program):
    require(type(program) is dict and set(program) == {"schema", "encoding", "statements", "semantics"},
            "closed machine-assembly program fields")
    require(program["schema"] == ASSEMBLY_SCHEMA and program["encoding"] == "utf-8", "assembly profile mismatch")
    text = []
    for statement in program["statements"]:
        require(type(statement) is dict and set(statement) == {"kind", "tokens"}, "closed assembly statement fields")
        require(statement["kind"] in ("empty", "directive", "machine_statement"), "unknown machine statement")
        for token in statement["tokens"]:
            require(type(token) is dict and set(token) == {"kind", "text"}, "closed assembly token fields")
            require(type(token["text"]) is str and token["text"], "nonempty assembly token")
            match = _ASM_TOKEN.fullmatch(token["text"])
            require(match is not None and match.lastgroup == token["kind"], "assembly token kind differs")
            text.append(token["text"])
    emitted = "".join(text).encode("utf-8")
    require(assembly_program(emitted) == program, "noncanonical or inconsistent assembly token stream")
    return emitted


_ASM_DEP_TOKEN = re.compile(
    r'(?P<comment>/\*[\s\S]*?\*/|\#[^\n]*)|(?P<quoted>"(?:\\.|[^"\\])*")'
    r"|(?P<character>'(?:\\.|[^\\\n])'?)"
    r'|(?P<space>[ \t\r]+)|(?P<end>[\n;])|(?P<name>[A-Za-z_.$][A-Za-z_.$0-9]*)'
    r'|(?P<number>[0-9]+)|(?P<punct>.)', re.DOTALL
)


def assembler_search_paths(arguments):
    directories, assembler = [], []
    for entry in argument_entries(arguments):
        if entry["name"] == "-I":
            directories.append(entry["value"])
        elif entry["name"] == "-Xassembler":
            assembler.append(entry["value"])
        elif entry["tokens"][0].startswith("-Wa,"):
            assembler.extend(entry["tokens"][0][4:].split(","))
    i = 0
    while i < len(assembler):
        option = assembler[i]
        if option == "-I":
            require(i + 1 < len(assembler) and assembler[i + 1],
                    "missing assembler include search directory")
            directories.append(assembler[i + 1])
            i += 2
        elif option.startswith("-I") and len(option) > 2:
            directories.append(option[2:])
            i += 1
        else:
            i += 1
    return directories


def assembly_directives(text):
    # Ignore comments and quoted strings while finding statement boundaries.
    # Labels and semicolon-separated directives are significant to GAS.
    statement = []
    for match in _ASM_DEP_TOKEN.finditer(text):
        kind, value = match.lastgroup, match.group()
        if kind == "end":
            if statement:
                yield statement
                statement = []
        elif kind not in ("space", "comment"):
            statement.append((kind, value))
    if statement:
        yield statement


def external_assembly_inputs(text, cwd, arguments=()):
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="surrogateescape")
    cwd, result = Path(cwd).resolve(), {}
    search = [cwd] + [(cwd / item).resolve() for item in assembler_search_paths(arguments)]
    for statement in assembly_directives(text):
        while (len(statement) >= 2 and statement[0][0] in ("name", "number")
               and statement[1][1] == ":"):
            statement = statement[2:]
        if not statement:
            continue
        directive = statement[0][1].lower()
        if directive not in (".include", ".incbin"):
            continue
        require(directive != ".include",
                "nested assembler source must be explicitly translated (.include)")
        require(len(statement) >= 2 and statement[1][0] == "quoted",
                "dynamic .incbin filename needs an explicit dependency route")
        name = statement[1][1][1:-1]
        require(name and "\\" not in name and "\x00" not in name and "\n" not in name,
                "escaped/dynamic assembly filename needs an explicit dependency route")
        candidates = [Path(name)] if Path(name).is_absolute() else [base / name for base in search]
        path = next((candidate.resolve() for candidate in candidates if candidate.is_file()), None)
        require(path is not None, "unresolved machine assembly input: " + name)
        result[str(path)] = {"kind": "binary_data", **binding(path)}
    return [result[key] for key in sorted(result)]


def assembly_bytes_from_hia(program):
    """Only these two schema fields carry executable assembly in system.v1."""
    require(type(program) is dict and program.get("schema") == SYSTEM_SCHEMA,
            "system HIA schema required for assembly dependency extraction")

    def unhex(value):
        require(type(value) is str and len(value) % 2 == 0 and
                re.fullmatch(r"[0-9a-fA-F]*", value) is not None,
                "invalid HIA assembly byte string")
        return bytes.fromhex(value)

    module = program.get("module")
    require(type(module) is dict and "inline_asm_hex" in module,
            "missing module assembly field")
    yield unhex(module["inline_asm_hex"])

    def values(value):
        if type(value) is dict:
            if value.get("kind") == "inline_asm":
                require("assembly_hex" in value, "missing inline assembly bytes")
                yield unhex(value["assembly_hex"])
            for child in value.values():
                yield from values(child)
        elif type(value) is list:
            for child in value:
                yield from values(child)
    yield from values(program)


def system_assembly_inputs(program, cwd, arguments=()):
    inputs = {}
    for assembly in assembly_bytes_from_hia(program):
        for item in external_assembly_inputs(assembly, cwd, arguments):
            inputs[item["path"]] = item
    return [inputs[key] for key in sorted(inputs)]


def relocated_path(path, original_root, current_root):
    path, original_root = Path(path), Path(original_root)
    if path.is_relative_to(original_root):
        return str(Path(current_root) / path.relative_to(original_root))
    return str(path)


def validate_replay_external_inputs(meta, current_inputs, manifest):
    expected = {}
    for item in meta.get("external_inputs", []):
        require(type(item) is dict and item.get("kind") == "binary_data",
                "unsupported retained external input kind")
        path = relocated_path(item["path"], meta["original_build_root"], manifest["build_root"])
        require(path not in expected, "duplicate retained external dependency")
        expected[path] = {"kind": "binary_data", "path": path,
                          "bytes": item["bytes"], "sha256": item["sha256"]}
    actual = {item["path"]: item for item in current_inputs}
    require(len(actual) == len(current_inputs), "duplicate current external dependency")
    require(actual == expected, "replay assembly dependency set or content changed")


def replay_dependency(meta, classification, manifest):
    wanted = classification["dependency_requested"]
    require(wanted == ("dependency" in meta),
            "replay dependency sidecar presence disagrees with compiler invocation")
    if not wanted:
        return None
    dep = meta["dependency"]
    require(binding(dep["path"]) == dep, "retained dependency list changed")
    data = gzip.decompress(Path(dep["path"]).read_bytes())
    return data.replace(os.fsencode(meta["original_build_root"]),
                        os.fsencode(manifest["build_root"]))


def restore_dependency(path, data):
    require(path is not None and data is not None, "missing dependency destination/data")
    path = Path(path)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    write_new(temporary, data)
    os.replace(temporary, path)


def prune_intermediates(record, directory):
    """Successful TUs retain gzip programs/sidecars and receipts, not bulky IR."""
    names = ("program.hia.json", "frontend.bc", "lowered.bc",
             "frontend.canonical.ll", "lowered.canonical.ll",
             "frontend.s", "lowered.s", "frontend.d")
    pending = []
    for name in names:
        path = directory / name
        if path.is_file():
            item = {**binding(path), "retained_program": record["retained_program"],
                    "reconstruction": "retained HIA plus recorded compiler phases"}
            if name == "frontend.d" and record.get("retained_dependency"):
                item["retained_dependency"] = record["retained_dependency"]
            pending.append((path, item))
    record["pruned_intermediates"] = []
    for path, item in pending:
        try:
            path.unlink()
            record["pruned_intermediates"].append(item)
        except OSError as error:
            # The compile remains valid. Preserve the artifact and report the
            # cleanup failure rather than mislabel a partly pruned TU as failed.
            record.setdefault("cleanup_errors", []).append(
                {"path": str(path), "message": str(error)})

def persist_program(program, record, directory, manifest, key, canonical_hash, dependency):
    root = Path(manifest["program_root"])
    root.mkdir(parents=True, exist_ok=True)
    stored = root / (record["id"] + ".hia.json.gz")
    write_new(stored, gzip.compress(program.read_bytes(), mtime=0))
    meta = {"schema": PROGRAM_BINDING_SCHEMA, "key": key, "kind": record["classification"]["kind"],
            "program": binding(stored), "canonical_input_sha256": canonical_hash,
            "source": record["source"], "original_cwd": record["cwd"], "original_argv": record["argv"],
            "original_build_root": manifest["build_root"], "external_inputs": record.get("external_inputs", [])}
    if record["classification"]["dependency_requested"]:
        require(dependency is not None and dependency.is_file(), "frontend did not produce dependencies")
        dep = root / (record["id"] + ".d.gz")
        write_new(dep, gzip.compress(dependency.read_bytes(), mtime=0))
        meta["dependency"] = binding(dep)
        record["retained_dependency"] = meta["dependency"]
    index = root / "index"
    index.mkdir(exist_ok=True)
    with (index / (key + ".lock")).open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        path = index / (key + ".json")
        if path.exists():
            old = strict_json(path.read_bytes())
            require(old["canonical_input_sha256"] == canonical_hash and old["kind"] == meta["kind"],
                    "same compiler key produced different semantic source; freeze a new profile")
        else:
            write_new(path, meta)
    record["retained_program"] = binding(stored)
    record["program_index"] = binding(index / (key + ".json"))
    return meta


def compile_payload(arguments, classification, manifest, record, directory):
    clang = manifest["tools"]["clang"]["path"]
    codec = manifest["tools"]["codec"]["path"]
    llvm_dis = manifest["tools"]["llvm_dis"]["path"]
    cwd = Path.cwd().resolve()
    original_source = Path(classification["inputs"][0]).resolve(strict=True)
    target = Path(classification["output"]).resolve()
    require(target.is_relative_to(Path(manifest["build_root"]).resolve()),
            "payload output outside the frozen build")
    record["source"] = binding(original_source)
    key = normalize_key(arguments, cwd, manifest)
    record["program_key"] = key
    dependency = Path(classification["dependency"]).resolve() if classification["dependency"] else None
    dependency_stage = directory / "frontend.d" if classification["dependency_requested"] else None
    dependency_data = None
    is_assembly = classification["kind"] == "target_assembly"
    hia = directory / "program.hia.json"
    if manifest["mode"] == "replay":
        index = Path(manifest["program_root"]) / "index" / (key + ".json")
        require(index.is_file(), "no registered HIA program for compiler invocation")
        meta = strict_json(index.read_bytes())
        require(type(meta) is dict and meta.get("schema") == PROGRAM_BINDING_SCHEMA,
                "invalid retained program index")
        require(meta["key"] == key and meta["kind"] == classification["kind"], "replay route mismatch")
        require(binding(meta["program"]["path"]) == meta["program"], "retained HIA program changed")
        write_new(hia, gzip.decompress(Path(meta["program"]["path"]).read_bytes()))
        record["retained_program"] = meta["program"]
        record["program_index"] = binding(index)
        record["canonical_input_sha256"] = meta["canonical_input_sha256"]
        dependency_data = replay_dependency(meta, classification, manifest)
        if "dependency" in meta:
            record["retained_dependency"] = meta["dependency"]
    else:
        if is_assembly:
            original = directory / "frontend.s"
            if classification["language"] == "assembler":
                require(dependency_stage is None,
                        "raw assembler dependency generation needs an explicit route")
                write_new(original, original_source.read_bytes())
                record["assembly_frontend"] = "raw-source-bytes"
            else:
                args = change_phase(arguments, original_source, original, "-E",
                                    assembly=True, dependency_output=dependency_stage)
                run_command(record, directory, "clang-assembly-preprocess", [clang, *args], forward=True)
                record["assembly_frontend"] = "clang-preprocessor"
            write_new(hia, canonical(assembly_program(original.read_bytes())) + b"\n")
            canonical_hash = sha(original)
        else:
            original = directory / "frontend.bc"
            args = change_phase(arguments, original_source, original, "-c",
                                dependency_output=dependency_stage)
            args += ["-emit-llvm", "-Xclang", "-disable-llvm-passes"]
            run_command(record, directory, "clang-c-frontend-only", [clang, *args], forward=True)
            run_command(record, directory, "encode-typed-hia", [codec, "encode", original, hia], forward=True)
            canonical_hash = canonical_ir(
                llvm_dis, original, directory / "frontend.canonical.ll",
                record, directory, "inspect-original-ir")
        if dependency_stage is not None:
            require(dependency_stage.is_file(), "frontend did not emit the required dependency file")
            dependency_data = dependency_stage.read_bytes()
        record["canonical_input_sha256"] = canonical_hash

    program = strict_json(hia.read_bytes())
    if is_assembly:
        emitted = directory / "lowered.s"
        write_new(emitted, emit_assembly(program))
        actual_hash = sha(emitted)
        record["external_inputs"] = external_assembly_inputs(emitted.read_bytes(), cwd, arguments)
    else:
        require(type(program) is dict and program.get("schema") == SYSTEM_SCHEMA,
                "native encoder did not produce system HIA")
        emitted = directory / "lowered.bc"
        run_command(record, directory, "decode-hia-fresh-module", [codec, "decode", hia, emitted], forward=True)
        actual_hash = canonical_ir(
            llvm_dis, emitted, directory / "lowered.canonical.ll",
            record, directory, "inspect-reconstructed-ir")
        record["external_inputs"] = system_assembly_inputs(program, cwd, arguments)
    require(actual_hash == record["canonical_input_sha256"],
            "HIA reconstruction changed canonical semantics; no compiler fallback")
    record["canonical_roundtrip_equal"] = True
    record["hia_program"] = binding(hia)
    if manifest["mode"] == "import":
        persist_program(hia, record, directory, manifest, key, actual_hash, dependency_stage)
    else:
        validate_replay_external_inputs(meta, record["external_inputs"], manifest)
    args = change_phase(arguments, emitted, target, classification["mode"],
                        backend=True, assembly=is_assembly)
    # A successful no-op compiler invocation must not reuse a pre-existing
    # object as apparent HIA output.
    if target.is_file():
        target.unlink()
    run_command(record, directory, "hia-native-codegen", [clang, *args], forward=True)
    require(target.is_file(), "native compiler returned without the target output")
    record["compiler_output"] = binding(target)
    if dependency_data is not None:
        restore_dependency(dependency, dependency_data)
        record["dependency_output"] = binding(dependency)
    record["postprocessing_boundary"] = (
        "This is the CC output; Kbuild objtool/record_mcount/link derivatives are inventoried separately.")
    record["fallback_c_compilation"] = False
    record["native_input"] = binding(emitted)
    for item in record.get("external_inputs", []):
        require(binding(item["path"]) == {key: item[key] for key in ("path", "bytes", "sha256")},
                "machine data changed during native codegen")
    # Only this final successful path prunes intermediates. Every earlier
    # frontend/codec/canonical/backend failure leaves all diagnostic inputs.
    prune_intermediates(record, directory)

def capture_output(record, output):
    if output not in (None, "-", "/dev/null"):
        path = Path(output).resolve()
        if path.is_file():
            record["compiler_output"] = binding(path)


def invocation_record(manifest_path, manifest, arguments, directory, role):
    return {"schema": "hepta.hia.system-compiler-invocation.v1", "id": directory.name,
            "role": role, "source_commit": manifest["source_commit"],
            "manifest": binding(manifest_path), "cwd": str(Path.cwd().resolve()),
            "argv": arguments, "mode": manifest["mode"], "status": "RUNNING",
            "commands": [], "response_files": [], "started_ns": time.time_ns()}


def finish_record(record, directory, started):
    record["elapsed_ns"] = time.monotonic_ns() - started
    record["completed_ns"] = time.time_ns()
    replace_json(directory / "RESULT.json", record)


def main(arguments=None):
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    manifest_path, manifest = load_manifest()
    directory = Path(manifest["ledger_root"]) / uuid.uuid4().hex
    directory.mkdir(mode=0o700)
    record = invocation_record(manifest_path, manifest, arguments, directory, "target_toolchain")
    write_new(directory / "INTENT.json", record)
    started, code = time.monotonic_ns(), 1
    try:
        expanded = expand_arguments(arguments, record["response_files"])
        record["expanded_argv"] = expanded
        classification = classify(expanded)
        record["classification"] = classification
        if classification["kind"].startswith("target_"):
            record["role"] = "target_payload"
            compile_payload(expanded, classification, manifest, record, directory)
            record["status"], code = "PASS", 0
        else:
            record["role"] = "trusted_build_operation"
            data = sys.stdin.buffer.read() if "-" in classification["inputs"] else None
            if data is not None:
                write_new(directory / "stdin.bin", data)
                record["stdin"] = binding(directory / "stdin.bin")
            forwarded = list(expanded)
            if classification.get("probe", {}).get("force_discard_output"):
                forwarded += ["-o", "/dev/null"]
            item = run_command(
                record, directory, "trusted-" + classification["kind"],
                [manifest["tools"]["clang"]["path"], *forwarded],
                input_bytes=data, forward=True, allow_failure=True)
            code = item["exit_code"]
            record["trusted_build_operation"] = classification["kind"]
            record["payload_failure"] = False
            record["status"] = "PASS" if code == 0 else "COMPILER_REJECTED"
            if code == 0:
                capture_output(record, classification["output"])
    except BaseException as error:
        record["status"] = "FAIL"
        record["error"] = {"type": type(error).__name__, "message": str(error)}
        record["payload_failure"] = record.get("classification", {}).get("kind", "").startswith("target_")
        if record["commands"]:
            code = record["commands"][-1]["exit_code"] or 1
        print("HIA system compiler: " + str(error), file=sys.stderr, flush=True)
    finally:
        finish_record(record, directory, started)
    return code


def host_main(toolchain, arguments=None):
    """Explicit HOSTCC/HOSTCXX boundary: record and execute the bound compiler."""
    require(toolchain in ("clang", "clangxx"), "unsupported host toolchain")
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    manifest_path, manifest = load_manifest()
    require(toolchain in manifest["tools"], "unbound host compiler")
    directory = Path(manifest["ledger_root"]) / uuid.uuid4().hex
    directory.mkdir(mode=0o700)
    record = invocation_record(manifest_path, manifest, arguments, directory, "host_tool")
    record["host_toolchain"] = toolchain
    record["host_driver_mode"] = "g++" if toolchain == "clangxx" else "gcc"
    record["classification"] = {"kind": "host_tool", "output": None}
    write_new(directory / "INTENT.json", record)
    started, code = time.monotonic_ns(), 1
    try:
        expanded = expand_arguments(arguments, record["response_files"])
        record["expanded_argv"] = expanded
        # Classification is explanatory only for a host invocation. Host C++
        # and linking stay with the real host compiler, with the original argv.
        try:
            parsed = parse_arguments(expanded)
            output = parsed["output"]
            record["classification"]["output"] = output
            record["classification"]["parsed"] = {
                "inputs": parsed["input_records"], "mode": parsed["mode"],
                "output": output, "dependency": parsed["dependency_options"]["filename"]}
        except SystemCompileError as error:
            output = None
            # The host compiler retains its original option semantics. Even if
            # the target parser rejects repeated -o, record the effective last
            # host output when the real compiler accepts the invocation.
            try:
                outputs = [entry["value"] for entry in argument_entries(expanded)
                           if entry["name"] == "-o"]
                output = outputs[-1] if outputs else None
            except SystemCompileError:
                pass
            record["classification"]["output"] = output
            record["classification"]["parse_error"] = str(error)
        try:
            record["classification"]["target_parser"] = classify(expanded)
        except SystemCompileError as error:
            record["classification"]["target_parser_rejection"] = str(error)
        stdin = any(entry["name"] == "input" and entry["value"] == "-"
                    for entry in argument_entries(expanded))
        data = sys.stdin.buffer.read() if stdin else None
        if data is not None:
            write_new(directory / "stdin.bin", data)
            record["stdin"] = binding(directory / "stdin.bin")
        driver = ["--driver-mode=g++"] if toolchain == "clangxx" else []
        item = run_command(record, directory, "host-" + toolchain,
                           [manifest["tools"][toolchain]["path"], *driver, *arguments],
                           input_bytes=data, forward=True, allow_failure=True)
        code = item["exit_code"]
        record["status"] = "PASS" if code == 0 else "COMPILER_REJECTED"
        record["payload_failure"] = False
        if code == 0:
            capture_output(record, output)
    except BaseException as error:
        record["status"], record["payload_failure"] = "FAIL", False
        record["error"] = {"type": type(error).__name__, "message": str(error)}
        print("HIA host compiler recorder: " + str(error), file=sys.stderr, flush=True)
    finally:
        finish_record(record, directory, started)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
