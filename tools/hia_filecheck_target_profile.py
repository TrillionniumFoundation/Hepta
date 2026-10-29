"""Bind the filecheck research IR to its actual Clang C target features.

This is a finite Linux x86-64 experiment adapter. It neither verifies Core nor
selects a CPU optimization policy. The unchanged O3/full-LTO/native profile must
survive through the IR; the explicit znver4 mask is a regression control.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

SCHEMA = "hepta.hia.filecheck-native-target-profile.v1"
PROBE_NAME = "__hepta_filecheck_target_probe"
PROBE_SOURCE = ("unsigned long long " + PROBE_NAME + "(unsigned long long value) {\n"
                "    return value ^ 1ULL;\n}\n")
MAX_PROBE_IR_BYTES = 65536
_CPU = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_FEATURE = re.compile(r"[+-][a-z0-9][a-z0-9._-]{0,95}")
_TRIPLE = re.compile(r"x86_64-(?:pc|unknown)-linux-gnu")
_DISABLED_CONTROL_FEATURES = frozenset({"avx512f", "avx512dq", "avx512vl", "avx512bw", "avx512cd",
    "avx512ifma", "avx512vbmi", "avx512vbmi2", "avx512vpopcntdq", "avx512bitalg", "avx512vnni",
    "avx512bf16", "avx512vp2intersect", "avx512fp16"})


def _require(condition, message):
    if not condition:
        raise ValueError("E_HIA_FILECHECK_TARGET: " + message)


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def elf_linker_version_argv(linker):
    """Preserve argv[0] and explicitly select ELF for a generic LLD driver."""
    path = str(linker)
    flavor = ["-flavor", "gnu"] if Path(path).name in {"lld", "rust-lld"} else []
    return [path, *flavor, "--version"]


@contextmanager
def elf_linker_driver(linker):
    """Use the same selected executable under an ELF argv[0] when necessary.

    Clang passes its linker path through. LLD reads -flavor only in argv[1],
    while Clang appends -Wl flags later, so a generic driver needs an ld.lld
    spelling. The temporary symlink selects a mode, never a different binary.
    """
    selected = _file_identity(linker)
    temporary = None
    report = {"selected_before": selected, "temporary_alias": False}
    try:
        invocation = selected["invocation_path"]
        if Path(invocation).name in {"lld", "rust-lld"}:
            temporary = tempfile.TemporaryDirectory(prefix="hepta-elf-linker-")
            alias = Path(temporary.name) / "ld.lld"
            alias.symlink_to(selected["resolved_path"])
            invocation = str(alias)
            report["temporary_alias"] = True
        driver = _file_identity(invocation)
        _require(driver["resolved_path"] == selected["resolved_path"]
                 and driver["sha256"] == selected["sha256"], "ELF spelling changed the selected linker")
        report["driver_before"] = driver
        try:
            yield invocation, report
        finally:
            report["selected_after"] = _file_identity(linker)
            report["driver_after"] = _file_identity(invocation)
            report["unchanged"] = report["selected_after"] == selected and report["driver_after"] == driver
            _require(report["unchanged"], "selected linker or ELF spelling changed during execution")
    finally:
        if temporary is not None:
            temporary.cleanup()
            report["temporary_alias_removed"] = not os.path.lexists(invocation)


def _file_identity(path):
    invocation = str(Path(path).absolute())
    resolved = Path(path).resolve(strict=True)
    before = resolved.lstat()
    _require(stat.S_ISREG(before.st_mode), "regular compiler file required")
    digest = sha256()
    with resolved.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        after_fd = os.fstat(stream.fileno())
    after = resolved.lstat()
    _require(len({(item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
                  for item in (before, opened, after_fd, after)}) == 1,
             "compiler file changed while capturing identity")
    return {"invocation_path": invocation, "resolved_path": str(resolved),
            "bytes": before.st_size, "sha256": digest.hexdigest()}


def _triple(text):
    rows = re.findall(r'^target triple = "([^"\r\n]+)"$', text, re.M)
    _require(len(rows) == 1 and _TRIPLE.fullmatch(rows[0]), "one Linux x86-64 target triple required")
    return rows[0]


def _signed_features(value):
    _require(type(value) is str and 0 < len(value) <= 16384, "bounded complete target-features required")
    fields = value.split(",")
    _require(len(fields) <= 512 and all(_FEATURE.fullmatch(item) for item in fields),
             "malformed target-features")
    _require(len({item[1:] for item in fields}) == len(fields), "duplicate or conflicting target feature")
    _require(any(item.startswith("+") for item in fields) and any(item.startswith("-") for item in fields),
             "complete positive and negative target-features required")
    return fields


def _parse_frontend_profile(text):
    """Read only the actual probe function's referenced attribute group."""
    _require(type(text) is str and 0 < len(text.encode()) <= MAX_PROBE_IR_BYTES,
             "bounded LLVM probe text required")
    triple = _triple(text)
    definitions = [line for line in text.splitlines() if re.match(r"^\s*define\b", line)]
    _require(len(definitions) == 1, "exactly one compiler probe definition required")
    match = re.fullmatch(r"define [^@\r\n]+@" + PROBE_NAME +
                        r"\([^\r\n]*\)[^#{}\r\n]*#([0-9]+) \{", definitions[0])
    _require(match is not None, "probe must reference one explicit attribute group")
    group = match.group(1)
    groups = {}
    for line in text.splitlines():
        if not re.match(r"^\s*attributes\b", line):
            continue
        entry = re.fullmatch(r"attributes #([0-9]+) = \{ (.*) \}", line)
        _require(entry is not None and entry.group(1) not in groups, "malformed or duplicate attribute group")
        groups[entry.group(1)] = entry.group(2)
    _require(group in groups, "referenced probe attribute group missing")
    attributes = {}
    tokens = groups[group].split()
    for token in tokens:
        if token.startswith('"'):
            item = re.fullmatch(r'"([a-zA-Z0-9._-]+)"(?:="([^"\\\r\n]*)")?', token)
            _require(item is not None and item.group(1) not in attributes,
                     "malformed or duplicate string attribute")
            attributes[item.group(1)] = item.group(2)
        else:
            _require(re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*(?:\([a-zA-Z0-9_,:.-]+\))?", token),
                     "malformed non-string attribute")
    cpu, features = attributes.get("target-cpu"), attributes.get("target-features")
    _require(type(cpu) is str and _CPU.fullmatch(cpu), "explicit target-cpu required")
    fields = _signed_features(features)
    return {"target_triple": triple, "target_cpu": cpu, "target_features": features,
            "signed_features": fields, "probe_attribute_group": group}


def _frontend_flags(flags):
    _require(type(flags) in {list, tuple} and all(type(value) is str for value in flags),
             "explicit research argument list required")
    _require(len(flags) == len(set(flags)), "duplicate research flag")
    required = {"-O3", "-flto=full", "-fPIC", "-shared"}
    _require(required <= set(flags), "unchanged O3/full-LTO/PIC/shared research profile required")
    march = [value for value in flags if value.startswith("-march=")]
    linkers = [value for value in flags if value.startswith("-fuse-ld=")]
    _require(len(march) == 1 and march[0] in {"-march=native", "-march=znver4"},
             "native research CPU or explicit znver4 regression control required")
    _require(len(linkers) == 1 and len(linkers[0]) > len("-fuse-ld="), "one explicit LTO linker required")
    _require(Path(linkers[0][len("-fuse-ld="):]).name not in {"lld", "rust-lld"},
             "Clang LTO requires an ELF linker driver spelling")
    for value in flags:
        _require(value in required or value in march or value in linkers
                 or (value.startswith("-mno-") and value[5:] in _DISABLED_CONTROL_FEATURES),
                 "unsupported research flag: " + value)
    # These flags only select the later shared-object link. CPU, feature,
    # optimization, PIC and full-LTO selections remain on the frontend probe.
    return [value for value in flags if value != "-shared" and not value.startswith("-fuse-ld=")]


def _definition_rows(text):
    _require(type(text) is str and text and "\x00" not in text, "actual emitted LLVM text required")
    _triple(text)
    _require(not re.search(r'^\s*attributes\b|"target-(?:cpu|features)"', text, re.M),
             "research adapter requires unbound emitted IR")
    result = []
    for index, line in enumerate(text.splitlines(keepends=True)):
        if not re.match(r"^\s*define\b", line):
            continue
        plain = line.rstrip("\r\n")
        match = re.fullmatch(r"define [^@\r\n]+@([A-Za-z_][A-Za-z_0-9]*)\([^\r\n]*\) \{", plain)
        _require(match is not None, "unsupported or already attributed function definition")
        result.append((index, match.group(1)))
    _require(result and len({name for _, name in result}) == len(result), "distinct emitted function definitions required")
    return result


def _bind_attributes(text, profile):
    definitions = _definition_rows(text)
    cpu, features = profile["target_cpu"], profile["target_features"]
    _require(type(cpu) is str and _CPU.fullmatch(cpu), "malformed captured CPU")
    _signed_features(features)
    lines = text.splitlines(keepends=True)
    for index, _ in definitions:
        plain = lines[index].rstrip("\r\n")
        ending = lines[index][len(plain):]
        lines[index] = plain[:-2] + " #0 {" + ending
    bound = "".join(lines).rstrip("\r\n") + '\n\nattributes #0 = { "target-cpu"="' + cpu + \
            '" "target-features"="' + features + '" }\n'
    return bound, [name for _, name in definitions]


def bind_native_target_profile(llvm_text, *, clang, flags, directory, command):
    """Freshly capture the same C frontend policy and bind every IR definition.

    `command` is the experiment's real process recorder. This report is evidence
    about one compiler/profile capture; accepting it cannot admit any program.
    """
    _definition_rows(llvm_text)
    frontend_flags = _frontend_flags(flags)
    invocation = str(Path(shutil.which(str(clang)) or str(clang)).absolute())
    compiler_before = _file_identity(invocation)
    output = Path(directory).absolute()
    output.mkdir(parents=True, exist_ok=False)
    source = output / "target_probe.c"
    ir_path = output / "target_probe.ll"
    source.write_text(PROBE_SOURCE)
    argv = [invocation, *frontend_flags, "-S", "-emit-llvm", "-x", "c", str(source), "-o", str(ir_path)]
    # Trial later compacts its process ledger in place. Keep an independent
    # JSON snapshot so that compaction cannot rewrite this captured profile or
    # make its saved bytes disagree with the profile hash.
    execution = json.loads(_wire(command(argv, "hia_native_target_frontend", timeout=30)))
    compiler_after = _file_identity(invocation)
    capture = {"argv": argv, "execution": execution, "compiler_before": compiler_before,
               "compiler_after": compiler_after, "compiler_unchanged": compiler_before == compiler_after}
    (output / "capture.json").write_text(json.dumps(capture, indent=2, sort_keys=True) + "\n")
    _require(compiler_before == compiler_after, "compiler changed during frontend capture")
    _require(type(execution) is dict and execution.get("argv") == argv
             and type(execution.get("returncode")) is int and execution["returncode"] == 0,
             "actual recorded frontend command must succeed")
    before = ir_path.lstat()
    _require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_PROBE_IR_BYTES,
             "bounded regular compiler IR output required")
    with ir_path.open("rb") as stream:
        payload = stream.read(MAX_PROBE_IR_BYTES + 1)
    after = ir_path.lstat()
    _require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
             and len(payload) == before.st_size, "compiler IR changed during capture")
    _require(source.read_bytes() == PROBE_SOURCE.encode(), "compiler probe source changed")
    profile = _parse_frontend_profile(payload.decode("utf-8"))
    bound, definitions = _bind_attributes(llvm_text, profile)
    report = {"schema": SCHEMA, **profile, "research_flags": list(flags), "frontend_flags": frontend_flags,
              "compiler": compiler_before, "frontend_execution": execution,
              "probe_source": {"path": str(source), "bytes": len(PROBE_SOURCE.encode()),
                               "sha256": sha256(PROBE_SOURCE.encode()).hexdigest()},
              "probe_ir": {"path": str(ir_path), "bytes": len(payload), "sha256": sha256(payload).hexdigest()},
              "original_ir_sha256": sha256(llvm_text.encode()).hexdigest(),
              "bound_ir_sha256": sha256(bound.encode()).hexdigest(),
              "bound_functions": definitions, "all_defined_functions_bound": True,
              "default_backend_receipt": False, "program_admission_authority": False,
              "original_ci_host_features_reconstructed": False}
    report["profile_sha256"] = sha256(_wire(report)).hexdigest()
    (output / "profile.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return bound, report
