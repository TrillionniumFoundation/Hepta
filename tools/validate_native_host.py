#!/usr/bin/env python3
"""Execute a bidirectional C ABI matrix on the actual host compiler/linker.

The same C11 matrix has separate GCC/Clang and Microsoft cl.exe drivers. A
Clang target using the MSVC ABI is still recorded as Clang. This command never
substitutes cross compilation or QEMU for host execution. A workflow
declaration alone is not qualification evidence for another host/compiler.
The v3 evidence contract retains native files and this qualifier's C-driver
raw command streams before temporary cleanup. Rust input is the canonical
UTF-8 text passed to the backend, not its platform-materialized temporary
program.rs; Rust compiler streams remain outside this archive. Historical v2
receipt-only reports do not qualify under this stricter contract.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.backend import compile_rust, emit_header
from hepta.clang_capture import CaptureRejected, run_bounded
from hepta.pipeline import analyze, compiler_hash
from tools.abi_fuzz import Matrix
from tools.evidence_checks import command as check_command, is_sha, native_build, normalized_errors, require, strict_equal, text

SEED, SHAPES, VALUES = 20261025, 36, 3
SCHEMA = "hepta.native-host.v3"
RETENTION_SCHEMA = "hepta.native-host.retained.v1"
RETENTION_SCOPE = {"c_driver_streams": "original bounded bytes; completeness is recorded per command",
                   "rust_input_kind": "canonical UTF-8 text passed to compile_rust",
                   "rust_build_record_kind": "structured backend receipt",
                   "rust_temporary_input_bytes_retained": False,
                   "rust_compiler_argv_and_raw_streams_retained": False,
                   "native_files": "only originals actually listed in the manifest; failures can be partial"}
FAMILIES = ("gcc", "clang", "msvc")
PROFILES = ("O0", "O2")

# This file is preprocessed, not compiled or executed. Check __clang__ first:
# clang targeting Windows defines _MSC_VER too, and is not Microsoft cl.exe.
COMPILER_PROBE = """\
#if defined(__clang__)
HEPTA_CC_FAMILY clang
HEPTA_CC_VERSION __clang_major__ __clang_minor__ __clang_patchlevel__
#elif defined(_MSC_VER)
HEPTA_CC_FAMILY msvc
HEPTA_CC_VERSION _MSC_FULL_VER _MSC_BUILD
#elif defined(__GNUC__)
HEPTA_CC_FAMILY gcc
HEPTA_CC_VERSION __GNUC__ __GNUC_MINOR__ __GNUC_PATCHLEVEL__
#else
#error Unsupported native C compiler family
#endif
#if defined(_WIN32)
HEPTA_CC_SYSTEM Windows
#elif defined(__APPLE__) && defined(__MACH__)
HEPTA_CC_SYSTEM Darwin
#elif defined(__linux__)
HEPTA_CC_SYSTEM Linux
#else
#error Unsupported native C operating system
#endif
#if defined(__x86_64__) || defined(_M_X64)
HEPTA_CC_MACHINE x86_64
#elif defined(__aarch64__) || defined(_M_ARM64)
HEPTA_CC_MACHINE aarch64
#else
#error Unsupported native C architecture
#endif
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ != 201112L
#error The native matrix requires C11 mode
#endif
HEPTA_C_STANDARD __STDC_VERSION__
"""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _source_identity():
    def git(argument):
        return subprocess.check_output(["git", "rev-parse", argument], cwd=ROOT, text=True).strip()
    return {"commit": git("HEAD"), "tree": git("HEAD^{tree}"),
            "compiler_sha256": compiler_hash(), "qualifier_sha256": sha(Path(__file__).read_bytes())}


def _archive_name(name):
    require(type(name) is str and name and "\\" not in name and ":" not in name
            and not name.startswith("/") and all(p not in {"", ".", ".."} for p in name.split("/")),
            "invalid retained relative path")
    return name


class _RetainedEvidence:
    """One create-only archive. Its manifest is capture evidence, not admission."""
    def __init__(self, directory, observations):
        if directory is None:
            directory = Path(tempfile.mkdtemp(prefix="hepta-native-host-artifacts-"))
        else:
            directory = Path(directory)
            directory.mkdir(parents=True, exist_ok=False)
        self.directory = directory.resolve(strict=True)
        self.receipt = {"schema": RETENTION_SCHEMA, "directory": str(self.directory),
                        "source_identity": _source_identity(), "scope": dict(RETENTION_SCOPE), "files": {}}
        observations["retained_evidence"] = self.receipt

    def save(self, name, raw):
        name = _archive_name(name)
        require(type(raw) is bytes, "original retained bytes required")
        target = self.directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        value = {"bytes": len(raw), "sha256": sha(raw)}
        self.receipt["files"][name] = value
        return {"path": name, **value}

    def copy(self, name, source):
        require(not source.is_symlink() and stat.S_ISREG(source.stat().st_mode), "ordinary retained input required")
        name = _archive_name(name)
        target = self.directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        digest, size = hashlib.sha256(), 0
        with source.open("rb") as before, target.open("xb") as after:
            for chunk in iter(lambda: before.read(1024 * 1024), b""):
                after.write(chunk); digest.update(chunk); size += len(chunk)
        self.receipt["files"][name] = {"bytes": size, "sha256": digest.hexdigest()}

    def streams(self, index, stdout, stderr, *, complete):
        return {"complete": complete, "stdout": self.save(f"streams/{index:02d}.stdout", stdout),
                "stderr": self.save(f"streams/{index:02d}.stderr", stderr)}

    def finish(self, directory, commands):
        # Includes partial compiler outputs on failure, before temporary cleanup.
        for source in sorted(directory.rglob("*")):
            require(not source.is_symlink(), "symlink in original host artifacts")
            if not source.is_dir():
                self.copy("work/" + source.relative_to(directory).as_posix(), source)
        self.save("commands.json", (json.dumps(commands, sort_keys=True, allow_nan=False) + "\n").encode())
        raw = (json.dumps(self.receipt, sort_keys=True, allow_nan=False) + "\n").encode()
        with (self.directory / "manifest.json").open("xb") as stream:
            stream.write(raw)
        self.receipt["manifest"] = {"bytes": len(raw), "sha256": sha(raw)}


@contextmanager
def _retained_workdir(evidence, commands):
    with tempfile.TemporaryDirectory(prefix="hepta-native-host-") as td:
        directory = Path(td).resolve(strict=True)
        evidence.receipt["original_temporary_directory"] = str(directory)
        original_failure = None
        try:
            yield directory
        except BaseException as error:
            original_failure = error
            evidence.receipt["execution_failure"] = {"type": type(error).__name__, "message": str(error)[:4000]}
            raise
        finally:
            try:
                evidence.finish(directory, commands)
            except BaseException as error:
                evidence.receipt["retention_error"] = {"type": type(error).__name__, "message": str(error)[:4000]}
                if original_failure is None:
                    raise


def _validate_retained_files(receipt, artifact_directory=None):
    require(type(receipt) is dict and receipt.get("schema") == RETENTION_SCHEMA,
            "retained native originals required; receipt-only reports are historical evidence")
    require(strict_equal(receipt.get("scope"), RETENTION_SCOPE), "retained evidence scope differs")
    require(strict_equal(receipt.get("source_identity"), _source_identity()), "retained source identity differs")
    root = Path(receipt["directory"] if artifact_directory is None else artifact_directory)
    require(not root.is_symlink() and root.is_dir(), "ordinary retained artifact directory required")
    root = root.resolve(strict=True)
    files = receipt["files"]
    require(type(files) is dict and bool(files) and "manifest.json" not in files, "retained file manifest missing")
    actual = set()
    for path in root.rglob("*"):
        require(not path.is_symlink(), "retained artifact symlink refused")
        if not path.is_dir():
            require(stat.S_ISREG(path.stat().st_mode), "ordinary retained artifact required")
            actual.add(path.relative_to(root).as_posix())
    require(actual == set(files) | {"manifest.json"}, "retained artifact file set differs")
    for name, identity in {**files, "manifest.json": receipt["manifest"]}.items():
        path = root / _archive_name(name)
        require(path.resolve(strict=True).is_relative_to(root), "retained artifact outside directory")
        require(type(identity) is dict and set(identity) == {"bytes", "sha256"}
                and type(identity["bytes"]) is int and identity["bytes"] >= 0 and is_sha(identity["sha256"]),
                "invalid retained artifact identity")
        with path.open("rb") as stream:
            actual_hash = hashlib.file_digest(stream, "sha256").hexdigest()
        require(path.stat().st_size == identity["bytes"] and actual_hash == identity["sha256"],
                "retained artifact bytes differ: " + name)
    frozen = json.loads((root / "manifest.json").read_bytes())
    require(strict_equal(frozen, {k: v for k, v in receipt.items() if k != "manifest"}), "retained manifest differs")
    return root, files


def _validate_retained_bindings(report, artifact_directory=None):
    receipt = report.get("retained_evidence")
    root, files = _validate_retained_files(receipt, artifact_directory)
    require("execution_failure" not in receipt and "retention_error" not in receipt, "failed retention attempt cannot qualify")
    require("native-build.json" in files and "commands.json" in files, "retained build/command records missing")
    native, negative = report["native_object"], report["negative_control"]
    require(strict_equal(json.loads((root / "native-build.json").read_bytes()), native), "retained original native build differs")
    windows = report["host"]["system"] == "Windows"
    path_type = PureWindowsPath if windows else PurePosixPath
    require(str(path_type(native["artifact"]).parent) == receipt["original_temporary_directory"],
            "retained original execution directory differs")
    extension = ".exe" if windows else ""
    expected = {"inputs/compiler-identity.c": sha(COMPILER_PROBE.encode()),
                "work/compiler-identity.c": sha(COMPILER_PROBE.encode()),
                "inputs/matrix.hepta": report["source_sha256"], "inputs/matrix.c": report["harness_sha256"],
                "inputs/layout-probes.rs": report["layout_probes_sha256"],
                "inputs/matrix.h": report["header_sha256"], "work/matrix.h": report["header_sha256"],
                "inputs/matrix.rs": native["rust_sha256"],
                "inputs/wrong.c": negative["source_sha256"], "work/matrix.c": negative["source_sha256"],
                "work/" + path_type(native["artifact"]).name: native["artifact_sha256"],
                "work/wrong" + extension: negative["artifact_sha256"]}
    for index, profile in enumerate(PROFILES):
        expected["work/host-matrix-" + profile + extension] = report["executable_sha256s"][index]
    for control in report["type_negative_controls"]:
        expected["inputs/type-" + control["name"] + ".h"] = control["header_sha256"]
    for name, digest in expected.items():
        require(name in files and files[name]["sha256"] == digest and files[name]["bytes"] > 0,
                "retained source or native role differs: " + name)
    require(files["work/" + path_type(native["artifact"]).name]["bytes"] == native["artifact_bytes"],
            "retained native object size differs")
    commands = report["commands"]
    require(strict_equal(json.loads((root / "commands.json").read_bytes()), commands), "retained original commands differ")
    for index, command in enumerate(commands):
        streams = command.get("retained_streams", {})
        require(streams.get("complete") is True, "incomplete raw capture cannot qualify")
        for channel in ("stdout", "stderr"):
            name = f"streams/{index:02d}." + channel
            require(name in files and strict_equal(streams.get(channel), {"path": name, **files[name]}),
                    "retained command stream role differs")
            original = (root / name).read_bytes().decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
            require(original == command[channel], "raw retained command output differs")


def compiler_probe_command(compiler, driver, probe):
    if driver == "msvc":
        return [str(compiler), "/nologo", "/std:c11", "/EP", "/Tc" + str(probe)]
    return [str(compiler), "-std=c11", "-E", "-P", "-x", "c", str(probe)]


def parse_compiler_probe(stdout):
    fields = {}
    for line in stdout.splitlines():
        parts = line.split()
        if parts and parts[0].startswith("HEPTA_"):
            require(parts[0] not in fields, "duplicate C compiler identity marker")
            fields[parts[0]] = parts[1:]
    require(set(fields) == {"HEPTA_CC_FAMILY", "HEPTA_CC_VERSION", "HEPTA_CC_SYSTEM",
                            "HEPTA_CC_MACHINE", "HEPTA_C_STANDARD"}, "incomplete C compiler macro probe")
    require(len(fields["HEPTA_CC_FAMILY"]) == 1 and fields["HEPTA_CC_FAMILY"][0] in FAMILIES,
            "unsupported actual C compiler family")
    family = fields["HEPTA_CC_FAMILY"][0]
    versions = fields["HEPTA_CC_VERSION"]
    require(len(versions) == (2 if family == "msvc" else 3)
            and all(re.fullmatch(r"[0-9]{1,10}", v) for v in versions), "invalid C compiler version macros")
    require(fields["HEPTA_CC_SYSTEM"] in (["Linux"], ["Windows"], ["Darwin"])
            and fields["HEPTA_CC_MACHINE"] in (["x86_64"], ["aarch64"])
            and fields["HEPTA_C_STANDARD"] == ["201112L"], "unsupported C compiler target or language mode")
    require(family != "msvc" or fields["HEPTA_CC_SYSTEM"] == ["Windows"], "MSVC must target Windows")
    return {"family": family, "version_components": [int(v) for v in versions],
            "system": fields["HEPTA_CC_SYSTEM"][0], "machine": fields["HEPTA_CC_MACHINE"][0],
            "c_standard": 201112}


def msvc_version(identity):
    full, build = identity["version_components"]
    return f"MSVC _MSC_FULL_VER={full} _MSC_BUILD={build}"


def check_compiler_version(identity, version):
    require(text(version), "C compiler version missing")
    if identity["family"] == "msvc":
        require(version == msvc_version(identity), "MSVC version differs from compiler macros")
    else:
        numeric = ".".join(str(v) for v in identity["version_components"])
        require(re.search(r"(?<![0-9])" + re.escape(numeric) + r"(?![0-9])", version) is not None,
                "C compiler --version differs from compiler macros")


def optimization_flag(family, profile):
    require(family in FAMILIES and profile in PROFILES, "unsupported native compiler/profile")
    return ("/Od" if profile == "O0" else "/O2") if family == "msvc" else "-" + profile


def c_compile_command(compiler, family, cfile, output, *, profile="O2", rust_object=None):
    """Build/link a driver, or compile an intentionally ill-typed C control.

    /Tc names only the C source. /Fo must never overwrite the independent Rust
    matrix.obj when cl.exe compiles matrix.c as part of a link invocation.
    """
    optimization = optimization_flag(family, profile)
    if family == "msvc":
        command = [str(compiler), "/nologo", "/std:c11", optimization, "/W4", "/WX", "/MD",
                   "/DABI_LAYOUT", "/Tc" + str(cfile)]
        if rust_object is None:
            return command + ["/c", "/Fo" + str(output)]
        return command + [str(rust_object), "/Fo" + str(output.with_suffix(".c.obj")),
                          "/Fe" + str(output), "/link", "/INCREMENTAL:NO"]
    command = [str(compiler), "-std=c11", optimization, "-Wall", "-Wextra", "-Werror", "-pedantic-errors",
               "-DABI_LAYOUT", str(cfile)]
    return command + (["-c"] if rust_object is None else [str(rust_object)]) + ["-o", str(output)]


def type_oracle_controls(header):
    """Mutate valid declarations, preserving syntax, to test the C11 oracle."""
    cases = [
        ("function_parameter", "uint8_t abi_h_scalar0(uint8_t value);",
         "uint8_t abi_h_scalar0(uint16_t value);", "signature scalar0"),
        ("array_extent", "    const uint32_t *pointer_array[3];",
         "    const uint32_t *pointer_array[4];", f"field type Matrix{SHAPES - 1:02d}.pointer_array"),
        ("nested_pointer_const", "    uint32_t * const *pointer2;",
         "    uint32_t **pointer2;", f"field type Matrix{SHAPES - 1:02d}.pointer2"),
    ]
    controls = []
    for name, correct, wrong, marker in cases:
        require(header.count(correct) == 1, "Expected one C type-control declaration: " + name)
        controls.append({"name": name, "header": header.replace(correct, wrong), "diagnostic_marker": marker})
    return controls


def run_host(*, cc=None, cc_family="auto", rustc=None, expected_system=None, expected_machine=None,
             observations=None, artifact_directory=None):
    system, machine = platform.system(), platform.machine().lower()
    normalized = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    if expected_system is not None and system != expected_system:
        raise ValueError("Requested actual host system does not match")
    if expected_machine is not None and normalized != expected_machine:
        raise ValueError("Requested actual host architecture does not match")
    require(cc_family in ("auto", *FAMILIES), "unsupported requested C compiler family")
    compiler = shutil.which(cc or ("clang" if system in {"Windows", "Darwin"} else "gcc"))
    if not compiler:
        raise ValueError("An actual host C compiler is required")
    compiler = str(Path(compiler).resolve(strict=True))
    compiler_sha = sha(Path(compiler).read_bytes())
    driver = "msvc" if cc_family == "msvc" or (cc_family == "auto" and Path(compiler).name.lower() in {"cl", "cl.exe"}) else "gnu"
    commands = []
    observations = {} if observations is None else observations
    observations.update({"commands": commands, "c_compiler": {"path": compiler, "binary_sha256": compiler_sha,
                                                              "requested_family": cc_family}})
    evidence = _RetainedEvidence(artifact_directory, observations)
    def run(argv, *, positive=True):
        argv = list(map(str, argv))
        start = time.monotonic()
        # A hostile or malfunctioning tool/caller must not buffer arbitrary
        # stdout/stderr in the Python host qualifier before it can fail.
        try:
            process = run_bounded(argv, timeout=120, stdin_limit=0,
                                  stdout_limit=128_000, stderr_limit=256_000)
        except CaptureRejected as exc:
            capture = exc.capture
            entry = {"argv": argv, "returncode": capture.returncode if capture else None,
                     "seconds": time.monotonic() - start, "capture_rejection": exc.code,
                     "stdout": capture.stdout.decode("utf-8", errors="replace") if capture else "",
                     "stderr": capture.stderr.decode("utf-8", errors="replace") if capture else ""}
            commands.append(entry)
            if capture:
                entry.update({"stdout_total_bytes": capture.stdout_total_bytes,
                              "stderr_total_bytes": capture.stderr_total_bytes,
                              "retained_streams": evidence.streams(len(commands) - 1, capture.stdout, capture.stderr, complete=False)})
            raise ValueError(f"E_NATIVE_HOST_CAPTURE: {exc.code}: {exc}") from exc
        entry = {"argv": argv, "returncode": process.returncode,
                 "seconds": time.monotonic() - start,
                 "stdout": process.stdout, "stderr": process.stderr}
        commands.append(entry)
        entry["retained_streams"] = evidence.streams(len(commands) - 1, process.raw_stdout, process.raw_stderr, complete=True)
        if positive and process.returncode:
            raise RuntimeError("Host command failed: " + json.dumps(entry))
        return process
    with _retained_workdir(evidence, commands) as td:
        # Windows may return the 8.3 short-path spelling RUNNER~1 here.
        # rustc's validated artifact path uses Path.resolve(), which expands
        # that name to runneradmin. Canonicalize *before* constructing any
        # commands so the trace and the artifact receipt have exact identity.
        # This preserves strict bytewise argv comparisons in validate_report.
        directory = Path(td).resolve(strict=True)
        if driver == "gnu":
            version = run([compiler, "--version"]).stdout.strip()
            target = run([compiler, "-dumpmachine"]).stdout.strip()
        probe = directory / "compiler-identity.c"
        probe.write_text(COMPILER_PROBE, encoding="utf-8", newline="\n")
        evidence.save("inputs/compiler-identity.c", COMPILER_PROBE.encode())
        identity = parse_compiler_probe(run(compiler_probe_command(compiler, driver, probe)).stdout)
        family = identity["family"]
        require((family == "msvc") == (driver == "msvc"), "C compiler implementation differs from its requested driver")
        require(cc_family == "auto" or family == cc_family, "Actual C compiler family differs from --cc-family")
        require((identity["system"], identity["machine"]) == (system, normalized), "C compiler macros differ from actual host")
        if driver == "msvc":
            version, target = msvc_version(identity), identity["machine"] + "-pc-windows-msvc"
        check_compiler_version(identity, version)
        require(target_shape(target) == (system, normalized), "C compiler target differs from actual host")
        cc_identity = {"path": compiler, "family": family, "version": version, "target": target,
                       "target_origin": "predefined_macros" if family == "msvc" else "dumpmachine",
                       "binary_sha256": compiler_sha,
                       "identity_probe": {"source_sha256": sha(COMPILER_PROBE.encode()), "observed": identity}}
        observations["c_compiler"] = cc_identity
        source, harness, probes, denominator = Matrix(SEED, SHAPES, VALUES).generate()
        evidence.save("inputs/matrix.hepta", source.encode())
        evidence.save("inputs/matrix.c", harness.encode())
        evidence.save("inputs/layout-probes.rs", probes.encode())
        observations["source_sha256"] = sha(source.encode())
        before = compiler_hash()
        analysis = analyze(source, "<native-host-matrix>", rustc=rustc, native=True, no_std=True, crate_type="obj")
        if not analysis.report["ok"]:
            raise RuntimeError(json.dumps(analysis.report))
        header = emit_header(analysis.program)
        evidence.save("inputs/matrix.h", header.encode())
        evidence.save("inputs/matrix.rs", (analysis.rust + "\n" + probes).encode())
        header_file = directory / "matrix.h"
        header_file.write_text(header, encoding="utf-8", newline="\n")
        cfile = directory / "matrix.c"
        cfile.write_text(harness, encoding="utf-8", newline="\n")
        object_file = directory / ("matrix.obj" if system == "Windows" else "matrix.o")
        observations["native_object_artifact"] = str(object_file)
        native = compile_rust(analysis.rust + "\n" + probes, rustc=rustc, crate_type="obj", output=object_file)
        evidence.save("native-build.json", (json.dumps(native, sort_keys=True, allow_nan=False) + "\n").encode())
        if not native["ok"]:
            raise RuntimeError(json.dumps(native))
        executions = []
        observations["executions"] = executions
        executable_hashes = []
        for profile in PROFILES:
            executable = directory / ("host-matrix-" + profile + (".exe" if system == "Windows" else ""))
            run(c_compile_command(compiler, family, cfile, executable, profile=profile, rust_object=object_file))
            executed = run([executable])
            observed = json.loads(executed.stdout)
            if observed != {"status": "passed", "foreign_calls": denominator["expected_foreign_calls_per_run"]}:
                raise ValueError("Actual host ABI denominator differs")
            executions.append({"optimization": optimization_flag(family, profile), "layout_checked": True,
                               "returncode": executed.returncode, "observed": observed})
            executable_hashes.append(sha(executable.read_bytes()))
        type_controls = []
        observations["type_negative_controls"] = type_controls
        try:
            for control in type_oracle_controls(header):
                evidence.save("inputs/type-" + control["name"] + ".h", control["header"].encode())
                header_file.write_text(control["header"], encoding="utf-8", newline="\n")
                rejected_object = directory / ("type-" + control["name"] + (".obj" if system == "Windows" else ".o"))
                rejected = run(c_compile_command(compiler, family, cfile, rejected_object), positive=False)
                require(rejected.returncode != 0 and control["diagnostic_marker"] in rejected.stdout + rejected.stderr,
                        "C11 type oracle did not reject the changed declaration: " + control["name"])
                type_controls.append({"name": control["name"], "header_sha256": sha(control["header"].encode()),
                                      "diagnostic_marker": control["diagnostic_marker"], "returncode": rejected.returncode,
                                      "status": "rejected_as_expected"})
        finally:
            header_file.write_text(header, encoding="utf-8", newline="\n")
        # The same full driver must reject a genuinely compiled wrong echo.
        needle = "ExpectedType0 abi_c_scalar0(ExpectedType0 value) { ++abi_calls; return value; }"
        if harness.count(needle) != 1:
            raise ValueError("Expected exactly one independent C negative-control site")
        wrong = harness.replace(needle, needle.replace("return value;", "return (ExpectedType0)(value ^ 1);"))
        evidence.save("inputs/wrong.c", wrong.encode())
        cfile.write_text(wrong, encoding="utf-8", newline="\n")
        bad_executable = directory / ("wrong" + (".exe" if system == "Windows" else ""))
        run(c_compile_command(compiler, family, cfile, bad_executable, rust_object=object_file))
        wrong_run = run([bad_executable], positive=False)
        if wrong_run.returncode == 0:
            raise ValueError("The actual host oracle accepted the wrong C implementation")
        negative = {"name": "compiled_wrong_c_echo", "source_sha256": sha(wrong.encode()),
                    "artifact_sha256": sha(bad_executable.read_bytes()), "returncode": wrong_run.returncode,
                    "status": "rejected_as_expected"}
        observations["negative_control"] = negative
    if compiler_hash() != before:
        raise ValueError("Compiler changed while qualifying the host")
    require(sha(Path(compiler).read_bytes()) == compiler_sha, "C compiler changed while qualifying the host")
    return {"schema": SCHEMA, "status": "passed",
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "host": {"system": system, "machine": normalized, "kernel_release": platform.release(),
                     "python": platform.python_version(), "execution": "native_host_process"},
            "compiler_sha256": before, "c_compiler": cc_identity,
            "matrix": denominator, "source_sha256": sha(source.encode()),
            "harness_sha256": sha(harness.encode()), "header_sha256": sha(header.encode()),
            "layout_probes_sha256": sha(probes.encode()), "frontend": analysis.report,
            "native_object": native, "executions": executions, "executable_sha256s": executable_hashes,
            "negative_control": negative, "type_negative_controls": type_controls, "commands": commands,
            "retained_evidence": evidence.receipt,
            "claims": {"actual_reported_host_executed": True, "cross_host_results_inferred": False,
                       "physical_board_executed": False, "gpu_device_executed": False,
                       "all_abi_features_qualified": False},
            "limits": ["Finite scalar/ordinary-record/nested-array/pointer and register-spill ABI matrix only.",
                       "Every host/compiler family needs its own successful command and retained report.",
                       "A container/VM native process is not physical-board or MMIO/DMA/IRQ/GPU qualification.",
                       "Packed records, bitfields, varargs and foreign lifetime safety remain outside this matrix."]}


def target_shape(target):
    require(text(target), "native target triple missing")
    arch = {"amd64":"x86_64", "arm64":"aarch64"}.get(target.split("-")[0], target.split("-")[0])
    system = ("Windows" if any(token in target for token in ("windows", "mingw", "win32")) else
              "Darwin" if "darwin" in target else "Linux" if "linux" in target else None)
    require(arch in {"x86_64", "aarch64"} and system is not None, "unqualified host target triple")
    return system, arch


@normalized_errors
def validate_report(report, *, artifact_directory=None):
    source, harness, probes, denominator = Matrix(SEED, SHAPES, VALUES).generate()
    claims = {"actual_reported_host_executed": True, "cross_host_results_inferred": False,
              "physical_board_executed": False, "gpu_device_executed": False, "all_abi_features_qualified": False}
    if (report.get("schema") != SCHEMA or report.get("status") != "passed"
            or report.get("compiler_sha256") != compiler_hash() or not strict_equal(report.get("matrix"), denominator)
            or report.get("source_sha256") != sha(source.encode()) or report.get("harness_sha256") != sha(harness.encode())
            or report.get("layout_probes_sha256") != sha(probes.encode()) or not strict_equal(report.get("claims"), claims)):
        raise ValueError("Host qualification identity or scope differs")
    generated = analyze(source, "<native-host-matrix>", native=False, no_std=True, crate_type="obj")
    require(generated.report["ok"] is True, "frozen host source no longer checks")
    header = emit_header(generated.program)
    require(report.get("header_sha256") == sha(header.encode()), "generated ABI header differs")
    host = report.get("host", {})
    require(host.get("system") in {"Linux", "Windows", "Darwin"} and host.get("machine") in {"x86_64", "aarch64"}
            and host.get("execution") == "native_host_process" and text(host.get("kernel_release")) and text(host.get("python")),
            "actual host identity incomplete")
    cc = report.get("c_compiler", {})
    require(text(cc.get("path")) and text(cc.get("version")) and is_sha(cc.get("binary_sha256"))
            and cc.get("family") in FAMILIES, "C compiler identity incomplete")
    family = cc["family"]
    expected_host = (host["system"], host["machine"])
    require(target_shape(cc.get("target")) == expected_host, "C compiler target differs from reported host")
    frontend = report.get("frontend", {})
    require(frontend.get("ok") is True and frontend.get("compiler_sha256") == report["compiler_sha256"]
            and frontend.get("source_sha256") == sha(source.encode())
            and frontend.get("interface_sha256") == generated.report["interface_sha256"]
            and strict_equal(frontend.get("profile"), generated.report["profile"])
            and strict_equal(frontend.get("claims"), generated.report["claims"])
            and strict_equal(frontend.get("assumptions"), generated.report["assumptions"]), "host frontend identity or assumptions differ")
    require(frontend.get("checks") == {"syntax":"passed", "types_effects_resources":"passed_in_supported_subset", "rust_borrows_types":"rustc_checked"},
            "host source did not receive native reference checks")
    native_build(frontend.get("backend"), "rust", check_only=True, crate_type="obj", source_sha256=sha(generated.rust.encode()))
    native = report.get("native_object", {})
    native_build(native, "rust", check_only=False, crate_type="obj", source_sha256=sha((generated.rust + "\n" + probes).encode()))
    require(target_shape(native["target"]) == expected_host and native["target"] == native["toolchain"].get("host")
            and strict_equal(native["toolchain"], frontend["backend"]["toolchain"])
            and native["target"] == frontend["backend"]["target"], "Rust object target/toolchain differs from actual host checks")
    require({"opt-level=3", "overflow-checks=yes", "panic=abort", "codegen-units=1"}.issubset(native["flags"]), "host object compilation flags differ")
    executions = report.get("executions", [])
    if len(executions) != 2 or [e.get("optimization") for e in executions] != [optimization_flag(family, p) for p in PROFILES]:
        raise ValueError("Both native host optimization profiles must execute")
    for result in executions:
        if (type(result.get("returncode")) is not int or result["returncode"] != 0 or result.get("layout_checked") is not True
                or not strict_equal(result.get("observed"), {"status": "passed", "foreign_calls": denominator["expected_foreign_calls_per_run"]})):
            raise ValueError("Native host ABI execution did not complete")
    hashes = report.get("executable_sha256s", [])
    require(isinstance(hashes, list) and len(hashes) == 2 and all(is_sha(x) for x in hashes), "native driver artifact identities missing")
    negative = report.get("negative_control", {})
    if (negative.get("name") != "compiled_wrong_c_echo" or negative.get("status") != "rejected_as_expected"
            or type(negative.get("returncode")) is not int or negative["returncode"] == 0):
        raise ValueError("The compiled wrong host implementation was not rejected")
    needle = "ExpectedType0 abi_c_scalar0(ExpectedType0 value) { ++abi_calls; return value; }"
    wrong = harness.replace(needle, needle.replace("return value;", "return (ExpectedType0)(value ^ 1);"))
    require(negative.get("source_sha256") == sha(wrong.encode()) and is_sha(negative.get("artifact_sha256"))
            and negative["artifact_sha256"] not in hashes, "wrong-implementation source/artifact identity differs")
    commands = report.get("commands", [])
    probe_count = 1 if family == "msvc" else 3
    expected_controls = type_oracle_controls(header)
    require(isinstance(commands, list) and len(commands) == probe_count + 6 + len(expected_controls),
            "complete host compilation/execution trace required")
    for entry in commands:
        check_command(entry)
        require("capture_rejection" not in entry, "capture rejection cannot qualify as successful host evidence")
    path_type = PureWindowsPath if host["system"] == "Windows" else PurePosixPath
    directory = path_type(native["artifact"]).parent
    require(path_type(native["artifact"]).name == ("matrix.obj" if host["system"] == "Windows" else "matrix.o"), "host object path differs")
    probe = commands[probe_count - 1]
    require(probe["argv"] == compiler_probe_command(cc["path"], "msvc" if family == "msvc" else "gnu", directory / "compiler-identity.c")
            and probe["returncode"] == 0, "C compiler macro probe command differs")
    identity = parse_compiler_probe(probe["stdout"])
    require(identity["family"] == family and (identity["system"], identity["machine"]) == expected_host
            and strict_equal(cc.get("identity_probe"), {"source_sha256": sha(COMPILER_PROBE.encode()), "observed": identity}),
            "C compiler family, target or macro probe identity differs")
    check_compiler_version(identity, cc["version"])
    if family == "msvc":
        require(cc.get("target_origin") == "predefined_macros" and cc["target"] == identity["machine"] + "-pc-windows-msvc",
                "MSVC target must come from its actual predefined macros")
    else:
        require(cc.get("target_origin") == "dumpmachine", "C target probe provenance differs")
        require(commands[0]["argv"] == [cc["path"], "--version"] and commands[0]["returncode"] == 0
                and commands[0]["stdout"].strip() == cc["version"], "C compiler version command differs")
        require(commands[1]["argv"] == [cc["path"], "-dumpmachine"] and commands[1]["returncode"] == 0
                and commands[1]["stdout"].strip() == cc["target"], "C target command differs")
    cfile = directory / "matrix.c"
    extension = ".exe" if host["system"] == "Windows" else ""
    for index, profile in enumerate(PROFILES):
        executable = directory / ("host-matrix-" + profile + extension)
        expected = c_compile_command(cc["path"], family, cfile, executable, profile=profile, rust_object=native["artifact"])
        built, executed = commands[probe_count + index*2:probe_count + 2 + index*2]
        if (built["argv"] != expected or built["returncode"] != 0
                or executed["argv"] != [str(executable)] or executed["returncode"] != 0):
            # Keep exact bytes in the diagnostic. Case, separators and OS-specific
            # path identities must not be normalized without an ABI-specific
            # justification: a relaxed equality could certify the wrong binary.
            mismatch = {"profile": profile,
                        "expected_compile": expected, "actual_compile": built["argv"],
                        "expected_execute": [str(executable)], "actual_execute": executed["argv"],
                        "compile_returncode": built["returncode"],
                        "execute_returncode": executed["returncode"]}
            raise ValueError("host compile/link/run trace differs: "
                             + json.dumps(mismatch, sort_keys=True)[:4000])
        require(strict_equal(json.loads(executed["stdout"]), executions[index]["observed"]), "raw host execution observation differs")
    type_controls = report.get("type_negative_controls", [])
    require(isinstance(type_controls, list) and len(type_controls) == len(expected_controls), "C11 negative type controls missing")
    for index, control in enumerate(expected_controls):
        entry = commands[probe_count + 4 + index]
        rejected_object = directory / ("type-" + control["name"] + (".obj" if host["system"] == "Windows" else ".o"))
        require(entry["argv"] == c_compile_command(cc["path"], family, cfile, rejected_object)
                and entry["returncode"] != 0 and control["diagnostic_marker"] in entry["stdout"] + entry["stderr"],
                "C11 negative declaration must fail its actual type assertion")
        require(strict_equal(type_controls[index], {"name": control["name"], "header_sha256": sha(control["header"].encode()),
                    "diagnostic_marker": control["diagnostic_marker"], "returncode": entry["returncode"], "status": "rejected_as_expected"}),
                "C11 type-control identity or raw rejection differs")
    bad_executable = directory / ("wrong" + extension)
    require(commands[-2]["argv"] == c_compile_command(cc["path"], family, cfile, bad_executable, rust_object=native["artifact"])
            and commands[-2]["returncode"] == 0 and commands[-1]["argv"] == [str(bad_executable)]
            and commands[-1]["returncode"] == negative["returncode"] and "v_scalar0_0" in commands[-1]["stderr"],
            "wrong echo must fail its actual native assertion, not fail to launch")
    _validate_retained_bindings(report, artifact_directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc")
    parser.add_argument("--cc-family", choices=["auto", *FAMILIES], default="auto",
                        help="Require the actual compiler family; auto selects cl.exe or a GNU-style driver and verifies macros")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC"))
    parser.add_argument("--expected-system", choices=["Linux", "Windows", "Darwin"])
    parser.add_argument("--expected-machine", choices=["x86_64", "aarch64"])
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/native-host.json")
    parser.add_argument("--artifact-directory", type=Path,
                        help="Create-only persistent directory; default: <output-stem>-artifacts beside the report")
    args = parser.parse_args()
    observed = None
    attempt = {}
    try:
        report = run_host(cc=args.cc, cc_family=args.cc_family, rustc=args.rustc, expected_system=args.expected_system,
                          expected_machine=args.expected_machine, observations=attempt,
                          artifact_directory=args.artifact_directory or args.output.with_name(args.output.stem + "-artifacts"))
        observed = report
        validate_report(report)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"schema": SCHEMA, "status": "failed", "error": str(exc),
                  "host": {"system": platform.system(), "machine": platform.machine()},
                  "claims": {"cross_host_results_inferred": False}}
        if observed is not None or attempt:
            # Interrupted/failed compilation and completed-but-rejected runs
            # retain bounded raw observations without claiming qualification.
            observed = attempt if observed is None else observed
            report["unqualified_observations"] = {
                "commands": observed.get("commands", []),
                "c_compiler": observed.get("c_compiler"),
                "native_object_artifact": observed.get("native_object_artifact") or observed.get("native_object", {}).get("artifact"),
                "executions": observed.get("executions"),
                "type_negative_controls": observed.get("type_negative_controls"),
                "negative_control": observed.get("negative_control"),
                "source_sha256": observed.get("source_sha256"),
                "retained_evidence": observed.get("retained_evidence"),
            }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "output": str(args.output), "error": report.get("error")}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
