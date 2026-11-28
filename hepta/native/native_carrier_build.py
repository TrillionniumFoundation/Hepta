"""Build a closed CPython ABI around an actually compiled HIA lifecycle policy.

This explicit compatibility build is not a default native Worker qualification.
No old C lifecycle implementation or host translation of the HIA policy is used.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import resource
import shlex
import stat
import subprocess
import sys
import sysconfig
import time

from hepta.hia_carrier_build_identity import SPECS, pin, policy_header, source_path, verify_policy


def profile():
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if (sys.implementation.name != "cpython" or sys.platform != "linux"
            or not (3, 11) <= sys.version_info[:2] <= (3, 14)
            or bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
            or platform.machine() != "x86_64"
            or sysconfig.get_config_var("SIZEOF_VOID_P") != 8
            or type(suffix) is not str or not suffix.startswith(".")
            or "/" in suffix or "\\" in suffix):
        raise ValueError("closed carrier build requires CPython/GIL/Linux x86-64 LP64")
    return {"implementation": "cpython", "python": list(sys.version_info[:3]),
            "platform": sys.platform, "machine": platform.machine(),
            "soabi": sysconfig.get_config_var("SOABI"),
            "extension_suffix": suffix, "gil_disabled": False}


def read(path, maximum=16 << 20):
    path = Path(path)
    if path != path.resolve(strict=True):
        raise ValueError("carrier build input must use its canonical path")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_mode & 0o022 or before.st_uid not in (0, os.getuid())
                or not 0 < before.st_size <= maximum):
            raise ValueError("carrier build input is not an owned bounded single file")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    current = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (len(raw) != before.st_size or any(getattr(before, n) != getattr(after, n) for n in fields)
            or any(getattr(after, n) != getattr(current, n) for n in fields)
            or path != path.resolve(strict=True)):
        raise ValueError("carrier build input changed during capture")
    return raw


def build(package, compiler, expected_compiler_sha256, *, cc, output, kinds=("image", "cell")):
    package, compiler, cc, output = map(Path, (package, compiler, cc, output))
    if (type(expected_compiler_sha256) is not str or len(expected_compiler_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_compiler_sha256)
            or type(kinds) is not tuple or not kinds or len(set(kinds)) != len(kinds)
            or any(k not in SPECS for k in kinds)):
        raise ValueError("explicit carrier compiler identity and unique closed roles are required")
    for path in (package, compiler, cc):
        if path != path.resolve(strict=True):
            raise ValueError("carrier build paths must be canonical")
    selected_profile = profile()
    compiler_raw, cc_raw = read(compiler), read(cc)
    if sha256(compiler_raw).hexdigest() != expected_compiler_sha256:
        raise ValueError("native HIA compiler differs from its supplied identity")
    output.mkdir(mode=0o700)
    snapshots = {}
    def capture(path):
        path = Path(path)
        raw = read(path)
        previous = snapshots.setdefault(path, raw)
        if previous != raw:
            raise ValueError("carrier build input changed between captures")
        return raw
    inputs = {}
    for kind in kinds:
        inputs[kind] = {name: capture(source_path(package, name)) for name in SPECS[kind]["inputs"]}
    commands, terminals = [], []
    binaries = {str(compiler): {"path": str(compiler), **pin(compiler_raw)},
                str(cc): {"path": str(cc), **pin(cc_raw)}}
    written, receipts = {}, {}
    report = {"schema": "hepta.hia.closed-carrier-build.v1", "status": "HOLD",
              "default_native_or_worker_qualification_claimed": False,
              "commands": commands, "terminals": terminals}
    def stable():
        if read(compiler) != compiler_raw or read(cc) != cc_raw:
            raise ValueError("carrier compiler changed during build")
        if any(read(path) != raw for path, raw in snapshots.items()):
            raise ValueError("carrier build source or header changed")
        if any(read(path) != raw for path, raw in written.items()):
            raise ValueError("carrier build output changed before publication")
    def run(label, argv, data=None, *, timeout, cpu):
        stable()
        commands.append(list(map(str, argv)))
        (output / (label + ".intent.json")).write_text(json.dumps(
            {"argv": commands[-1], "timeout_seconds": timeout, "cpu_seconds": cpu,
             "input": pin(data) if data is not None else None}, indent=2) + "\n")
        def limits():
            os.umask(0o077)
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        begin = time.monotonic()
        try:
            result = subprocess.run(commands[-1], input=data, capture_output=True,
                                    timeout=timeout, preexec_fn=limits,
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                         "TMPDIR": str(output)}, cwd=output)
        except BaseException as error:
            (output / (label + ".observer-failure.json")).write_text(json.dumps(
                {"type": type(error).__name__, "message": str(error)}) + "\n")
            raise
        (output / (label + ".stdout")).write_bytes(result.stdout)
        (output / (label + ".stderr")).write_bytes(result.stderr)
        terminal = {"name": label, "returncode": result.returncode,
                    "seconds": time.monotonic() - begin, "stdout": pin(result.stdout),
                    "stderr": pin(result.stderr)}
        terminals.append(terminal)
        (output / (label + ".terminal.json")).write_text(json.dumps(terminal, indent=2) + "\n")
        stable()
        if result.returncode != 0:
            raise ValueError("carrier build command failed: " + label)
        return result
    def publish(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
        if read(path) != raw:
            raise ValueError("carrier output differs immediately after creation")
        written[path] = raw
    try:
        for kind in kinds:
            spec = SPECS[kind]
            begin_commands = len(commands)
            compiled = run(kind + "-native-policy", [compiler, "compile"],
                           inputs[kind][spec["inputs"][5]], timeout=20, cpu=10)
            if compiled.stderr or not 0 < len(compiled.stdout) <= 1048576:
                raise ValueError("native HIA policy compiler output differs")
            image = compiled.stdout
            header = policy_header(kind, image)
            native_dir = output / kind
            native_dir.mkdir(mode=0o700)
            for name in spec["inputs"][:2]:
                publish(native_dir / Path(name).name, inputs[kind][name])
            publish(native_dir / ("carrier_" + kind + "_policy.inc"), header)
            flags = [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                     "-O2", "-fPIC", "-I" + sysconfig.get_paths()["include"],
                     "-I" + str(native_dir)]
            source = native_dir / ("carrier_" + kind + "_abi.c")
            dependencies = run(kind + "-headers", [*flags, "-M", "-MT", "carrier-object", source],
                               timeout=30, cpu=20)
            if dependencies.stderr:
                raise ValueError("closed carrier header enumeration emitted diagnostics")
            text = dependencies.stdout.decode("utf-8").replace("\\\n", "")
            if not text.startswith("carrier-object:"):
                raise ValueError("closed carrier header dependency record differs")
            for name in shlex.split(text[len("carrier-object:"):]):
                path = Path(name).resolve(strict=True)
                if path not in written:
                    capture(path)
            binary = native_dir / (spec["basename"] + selected_profile["extension_suffix"])
            compiled_c = run(kind + "-closed-abi", [*flags, "-shared", source, "-o", binary],
                             timeout=60, cpu=45)
            if compiled_c.stdout or compiled_c.stderr:
                raise ValueError("closed ABI compilation emitted diagnostics")
            executable = read(binary, 1 << 20)
            written[binary] = executable
            source_raw = dict(inputs[kind])
            source_raw[spec["generated"][0]] = image
            source_raw[spec["generated"][1]] = header
            policy = {"schema": "hepta.hia.carrier-policy-build.v1", "abi": spec["abi"],
                      "source": pin(inputs[kind][spec["inputs"][5]]),
                      "image": pin(image), "header": pin(header), "compiler": pin(compiler_raw),
                      "returncode": compiled.returncode,
                      "stdout": pin(compiled.stdout), "stderr": pin(compiled.stderr)}
            verify_policy(kind, policy, source_raw, executable)
            receipt = {"schema": spec["schema"], "abi": spec["abi"], "profile": selected_profile,
                       "binary": {"name": binary.name, **pin(executable)},
                       "sources": {name: pin(raw) for name, raw in sorted(source_raw.items())},
                       "compiler_commands": commands[begin_commands:],
                       "compiler_executables": binaries,
                       "build_scope": "CPYTHON_CLOSED_ABI_WITH_NATIVE_HIA_POLICY",
                       "product_qualification_claimed": False, "hia_policy": policy}
            raw = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
            stable()
            for name in spec["generated"]:
                publish(source_path(package, name), source_raw[name])
            publish(package / binary.name, executable)
            publish(package / spec["receipt"], raw)
            receipts[kind] = {"path": str(package / spec["receipt"]), **pin(raw)}
        stable()
        report.update(status="PASS", receipts=receipts,
                      physical_inputs={str(p): pin(raw) for p, raw in snapshots.items()},
                      outputs={str(p): pin(raw) for p, raw in written.items()})
        return report
    finally:
        (output / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--expected-compiler-sha256", required=True)
    parser.add_argument("--cc", type=Path, default=Path("/usr/bin/cc"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--role", choices=("image", "cell"), action="append")
    args = parser.parse_args()
    result = build(args.package.resolve(strict=True), args.compiler.resolve(strict=True),
                   args.expected_compiler_sha256, cc=args.cc.resolve(strict=True),
                   output=args.output, kinds=tuple(args.role or ("image", "cell")))
    print(json.dumps({"status": result["status"], "receipts": result["receipts"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
