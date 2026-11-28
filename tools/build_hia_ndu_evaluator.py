"""Rebuild the existing complete HIA NDU leaf with its native CLI recipe.

All five policies, both ELF packing steps and both independent constructions
execute native HIA.  No Rust, assembler, host linker or Python evaluator is
launched.  Publication requires the complete fixed source and output identity.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SELF = "tools/build_hia_ndu_evaluator.py"
TEMPLATE = "docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json"
TEMPLATE_SHA256 = "9d04ec9fab8a0f0ce2d467a951793fc92a890baae8cae985ab9cbfe7476b89a2"
_SELF = Path(__file__).read_bytes()
STEP_SECONDS = 20


def _read(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("NDU build input must be a regular file: " + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    attrs = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if tuple(getattr(before, k) for k in attrs) != tuple(getattr(after, k) for k in attrs) or len(raw) != before.st_size:
        raise ValueError("NDU build input changed while captured: " + str(path))
    return raw


def _sealed(raw):
    import fcntl
    descriptor = os.memfd_create("hia-ndu-native-constructor",
                                os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(descriptor, 0o500)
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor, raw[offset:])
            if count <= 0:
                raise OSError("native constructor snapshot write made no progress")
            offset += count
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, 15)
        if (fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & 15 != 15
                or os.fstat(descriptor).st_size != len(raw)
                or os.pread(descriptor, len(raw) + 1, 0) != raw):
            raise OSError("native constructor snapshot or seals differ")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _run(directory, label, argv, raw, *, executable=None):
    (directory / (label + ".stdin")).write_bytes(raw)
    started = time.monotonic()
    record = {"argv": [str(x) for x in argv], "timeout_seconds": STEP_SECONDS,
              "stdin_bytes": len(raw), "stdin_sha256": sha256(raw).hexdigest()}
    descriptor = None
    try:
        actual = _read(argv[0])
        if executable is None:
            executable = actual
        if type(executable) is not bytes or actual != executable:
            raise OSError("native constructor path differs from captured executable")
        descriptor = _sealed(executable)
        command = ["/proc/self/fd/" + str(descriptor), *argv[1:]]
        record.update(executable_sha256=sha256(executable).hexdigest(),
                      executable_bytes=len(executable), sealed_descriptor=True)
        p = subprocess.run(command, input=raw, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=STEP_SECONDS, check=False,
                           pass_fds=(descriptor,))
    except subprocess.TimeoutExpired as error:
        out, err = error.stdout or b"", error.stderr or b""
        record.update(status="timeout", returncode=None)
    except OSError as error:
        out, err = b"", (type(error).__name__ + ": " + str(error)).encode()
        record.update(status="launch_failed", returncode=None)
    else:
        out, err = p.stdout, p.stderr
        record.update(status="exited", returncode=p.returncode)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    record.update(wall_seconds=time.monotonic() - started,
                  stdout_bytes=len(out), stdout_sha256=sha256(out).hexdigest(),
                  stderr_bytes=len(err), stderr_sha256=sha256(err).hexdigest())
    (directory / (label + ".stdout")).write_bytes(out)
    (directory / (label + ".stderr")).write_bytes(err)
    (directory / (label + ".terminal.json")).write_text(json.dumps(record, indent=2) + "\n")
    if record["status"] != "exited" or record["returncode"] != 0 or err:
        raise ValueError("native NDU build command failed: " + label)
    return out, record


def build(output, source_builder, filter_packer, *, root=ROOT):
    if sys.platform != "linux":
        raise ValueError("native NDU construction requires Linux")
    root, output = Path(root).resolve(strict=True), Path(output)
    source_builder, filter_packer = Path(source_builder).resolve(strict=True), Path(filter_packer).resolve(strict=True)
    template_raw = _read(root / TEMPLATE)
    if sha256(template_raw).hexdigest() != TEMPLATE_SHA256:
        raise ValueError("native NDU build contract differs from its fixed source")
    template = json.loads(template_raw)
    names = [SELF, TEMPLATE, *template["source_files"]]
    captured = {name: _read(root / name) for name in names}
    if captured[SELF] != _SELF or _read(Path(__file__)) != _SELF:
        raise ValueError("executed NDU builder differs from the selected source")
    if {name: sha256(captured[name]).hexdigest() for name in template["source_files"]} != template["source_files"]:
        raise ValueError("native NDU source differs from its fixed recipe")
    compiler_raw, filter_raw = _read(source_builder), _read(filter_packer)
    inputs = template["build_inputs"]
    if (len(compiler_raw) != inputs["compiler"]["bytes"]
            or sha256(compiler_raw).hexdigest() != inputs["compiler"]["sha256"]
            or sha256(filter_raw).hexdigest() != inputs["filter_root_sha256"]):
        raise ValueError("native NDU constructor differs from the fixed compiler/filter")
    output.mkdir(mode=0o700)
    started = time.monotonic()
    results = []
    before = {name: sha256(raw).hexdigest() for name, raw in captured.items()}
    (output / "source-before.json").write_text(json.dumps(before, indent=2) + "\n")
    def unchanged():
        if (_read(source_builder) != compiler_raw or _read(filter_packer) != filter_raw
                or any(_read(root / name) != raw for name, raw in captured.items())
                or _read(Path(__file__)) != _SELF):
            raise ValueError("native NDU constructor or source changed before publication")
    for number in (1, 2):
        directory = output / ("construction-" + str(number)); directory.mkdir(mode=0o700)
        flats = {}
        for role in inputs["modules"]:
            raw, record = _run(directory, role["role"], [source_builder, "compile"], captured[role["source_path"]], executable=compiler_raw)
            if len(raw) != role["flat_bytes"] or sha256(raw).hexdigest() != role["flat_sha256"]:
                raise ValueError("native NDU compile output differs: " + role["role"])
            flats[role["role"]] = raw
        wrapper, record = _run(directory, "wrap-packer", [filter_packer],
                               b"HIAFLT01" + struct.pack("<Q", len(flats["packer"])) + flats["packer"], executable=filter_raw)
        if sha256(wrapper).hexdigest() != inputs["packer_wrapper_sha256"]:
            raise ValueError("native NDU packer wrapper differs")
        packer_path = directory / "hia-ndu-evaluator-pack"
        packer_path.write_bytes(wrapper); packer_path.chmod(0o500)
        parts = [flats[name] for name in ("transport", "evaluator", "number", "debug")]
        frame = b"HIANDP01" + struct.pack("<5Q", *(len(part) for part in parts), 0) + b"".join(parts)
        image, record = _run(directory, "pack-evaluator", [packer_path.resolve()], frame, executable=wrapper)
        if len(image) != template["binary_bytes"] or sha256(image).hexdigest() != template["binary_sha256"]:
            raise ValueError("native NDU executable differs from the qualified full image")
        unchanged()
        results.append(image)
    if results[0] != results[1]:
        raise ValueError("independent native NDU constructions differ")
    unchanged()
    binary = output / "hia-ndu-evaluator"
    binary.write_bytes(results[0]); binary.chmod(0o500)
    (output / "build-receipt.json").write_bytes(template_raw)
    unchanged()
    if _read(binary) != results[0] or _read(output / "build-receipt.json") != template_raw:
        raise ValueError("published native NDU bytes changed")
    after = {name: sha256(_read(root / name)).hexdigest() for name in captured}
    (output / "source-after.json").write_text(json.dumps(after, indent=2) + "\n")
    report = {"schema": "hepta.hia.ndu-native-construction.v1", "passed": True,
              "native_execs": 14, "independent_constructions": 2,
              "source_before": before, "source_after": after,
              "source_unchanged": before == after,
              "compiler_sha256": sha256(compiler_raw).hexdigest(),
              "filter_sha256": sha256(filter_raw).hexdigest(),
              "binary_bytes": len(results[0]), "binary_sha256": sha256(results[0]).hexdigest(),
              "receipt_sha256": sha256(template_raw).hexdigest(),
              "wall_seconds": time.monotonic() - started,
              "matching_cold_qualified_here": False,
              "scope": "exact prequalified native leaf; final union cold and installation are separate"}
    (output / "construction.json").write_text(json.dumps(report, indent=2) + "\n")
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-builder", required=True, type=Path)
    parser.add_argument("--filter-packer", required=True, type=Path)
    args = parser.parse_args()
    print(build(args.output, args.source_builder, args.filter_packer))


if __name__ == "__main__":
    main()
