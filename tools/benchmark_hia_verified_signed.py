"""Fixed signed-scalar comparison, with separate preparation and functional modes.

The 33 semantic cells keep their actual signed Core signatures. HIA's verified
scalar foreign entry consumes raw SysV words, normalizes narrow inputs, and
sign-extends signed returns. The independent Rust entries implement exactly
that transport. No transport casts are inserted into the measured HIA Core.

A measurement requires a clean committed tree and explicit CPU. Every kernel
is proved from its final ELF before execution, every input is checked against
independent integer arithmetic, and invalid inputs run only in forked children.
The C driver binds and seals the exact image before loading it. All 21 samples
and the three specified warmups remain in the report and raw stdout files.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

SCHEMA = "hepta.hia.verified-signed-scalar-microbench.v1"
MASK = (1 << 64) - 1
INPUT_SEED = 0x6A09E667F3BCC909
CHECKSUM_SEED = 0x0123456789ABCDEF
ORDER_SEED = 20261120
INPUT_COUNT = 64
ITERATIONS = 1 << 20
SAMPLES = 21
WARMUPS = 3
PROOF_DEADLINE_MS = 15000
ASSETS = ROOT / "benchmarks/hia_verified_kernels"
PROTOCOL_PATH = ASSETS / "PROTOCOL_SIGNED_V1.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def case_specs():
    """Explicit inventory; a report cannot choose its own successful subset."""
    rows = []
    for operation in ("add.wrap", "sub.wrap", "mul.wrap", "add.checked", "sub.checked",
                      "mul.checked", "div.checked", "rem.checked", "neg.checked",
                      "shl.checked", "shr.checked"):
        rows.append({"id": "i64_" + operation.replace(".", "_"), "source": "i64",
                     "target": "i64", "operation": "int." + operation})
    for typ in ("i8", "i16", "i32"):
        for operation in ("identity", "add.wrap", "add.checked", "shr.checked"):
            rows.append({"id": typ + "_" + operation.replace(".", "_"), "source": typ,
                         "target": typ, "operation": operation if operation == "identity" else "int." + operation})
    for source, target in (("i64", "u64"), ("u64", "i64"), ("i64", "i8"),
                           ("i64", "u8"), ("u64", "i32")):
        for mode in ("wrap", "checked"):
            rows.append({"id": source + "_to_" + target + "_" + mode, "source": source,
                         "target": target, "operation": "int.cast", "mode": mode})
    return rows


def fixed_protocol():
    return {
        "schema": SCHEMA, "cells": case_specs(), "semantic_cells": 33,
        "implementations": ["hia", "rust"], "measurement_cases": 66,
        "inputs_per_cell": INPUT_COUNT, "input_seed_hex": f"{INPUT_SEED:016x}",
        "checksum_seed_hex": f"{CHECKSUM_SEED:016x}", "input_generator": "xorshift64-star-v1",
        "iterations": ITERATIONS, "samples_per_case": SAMPLES, "warmup_batches": WARMUPS,
        "proof_deadline_ms": PROOF_DEADLINE_MS,
        "case_order_seed": ORDER_SEED, "clock": "CLOCK_MONOTONIC_RAW",
        "transport": "two raw uint64 SysV argument registers; uint64 return word; narrow signed inputs use low bits and signed returns are sign-extended",
        "hia_source": "actual signed Core parameter/result types; no adapter casts inserted",
        "input_bytes": "64 little-endian triples (a,b,expected raw result); traps are little-endian pairs",
        "timing": "cyclic 64-input indirect calls; wrapping checksum; input lookup and call overhead included for both arms",
        "failure_behavior": "checked errors abort with SIGABRT in isolated forked children; no invalid inputs in timing",
        "image_admission": "expected SHA256 checked before dlopen; copied bytes sealed in Linux memfd; dlsym entry must belong to that exact loaded image",
        "c_flags": ["-O3", "-std=c11", "-Wall", "-Wextra", "-Werror"],
        "rust_flags": ["--crate-type", "cdylib", "--edition=2021", "-C", "opt-level=3",
                       "-C", "target-cpu=native", "-C", "panic=abort", "-C", "codegen-units=1"],
        "primary_statistic": "median nanoseconds per call from all 21 samples",
        "reruns": "no selected-cell retry, substitution or discarded samples within a campaign",
        "scope": "same-host pinned-core scalar leaves; affinity does not reserve the CPU",
    }


def width(typ):
    return int(typ[1:])


def limits(typ):
    bits = width(typ)
    return (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if typ[0] == "i" else (0, (1 << bits) - 1)


def interpret(word, typ):
    bits = width(typ)
    value = word & ((1 << bits) - 1)
    return value - (1 << bits) if typ[0] == "i" and value >= (1 << (bits - 1)) else value


def independent_result(spec, raw_a, raw_b):
    """Unbounded Python arithmetic, separate from both HIA and Rust execution."""
    source, target, op = spec["source"], spec["target"], spec["operation"]
    a, b = interpret(raw_a, source), interpret(raw_b, source)
    low, high = limits(target)
    if op == "identity":
        value = a
    elif op == "int.cast":
        value = a
        if spec["mode"] == "checked" and not low <= value <= high:
            return None, "overflow"
        value = interpret(value, target)
    elif op in {"int.div.checked", "int.rem.checked"}:
        if b == 0:
            return None, "division_by_zero"
        if a == low and b == -1:
            return None, "overflow"
        quotient = abs(a) // abs(b)
        if (a < 0) != (b < 0):
            quotient = -quotient
        value = quotient if op == "int.div.checked" else a - quotient * b
    elif op in {"int.shl.checked", "int.shr.checked"}:
        if b < 0 or b >= width(source):
            return None, "overflow"
        value = interpret(a << b, target) if op == "int.shl.checked" else a >> b
    else:
        if op.startswith("int.add."):
            value = a + b
        elif op.startswith("int.sub."):
            value = a - b
        elif op.startswith("int.mul."):
            value = a * b
        elif op == "int.neg.checked":
            value = -a
        else:
            raise ValueError("unknown fixed operation")
        if op.endswith("checked") and not low <= value <= high:
            return None, "overflow"
        value = interpret(value, target)
    return value & MASK, None


class Words:
    def __init__(self, seed):
        self.state = seed & MASK

    def next(self):
        x = self.state
        x ^= x >> 12
        x ^= (x << 25) & MASK
        x ^= x >> 27
        self.state = x & MASK
        return (self.state * 0x2545F4914F6CDD1D) & MASK


def input_matrix(spec, index):
    """At least 48 seeded rows plus applicable endpoints, with fixed dirty bits."""
    generator = Words(INPUT_SEED ^ ((index + 1) * 0x9E3779B97F4A7C15))
    typ, op = spec["source"], spec["operation"]
    low, high = limits(typ)
    bits = width(typ)
    mask = (1 << bits) - 1

    def encode(value):
        return ((generator.next() & (MASK ^ mask)) | (value & mask)) if bits < 64 else value & MASK

    endpoints = [(low, 0), (high, 0), (low, 1), (high, 1), (low, -1), (high, -1),
                 (-1, 1), (1, -1), (-7, 3), (7, -3), (-7, -3), (0, 1), (0, 0),
                 (1, 1), (1, 2), (high, high), (low, low)]
    if op in {"int.shl.checked", "int.shr.checked"}:
        endpoints = [(a, b) for a in (low, high, -1, 0) for b in (0, 1, bits - 1)]
    elif op == "int.cast":
        target_low, target_high = limits(spec["target"])
        endpoints = [(a, 0) for a in (low, high, -1, 0, 1, target_low - 1, target_low,
                                      target_high, target_high + 1, low + 1, high - 1)
                     if low <= a <= high]
    rows = []
    seen = set()

    def append(a, b, origin):
        if not low <= a <= high or (op not in {"identity", "int.cast", "int.neg.checked"} and not low <= b <= high):
            return
        raw_a, raw_b = encode(a), encode(b)
        expected, trap = independent_result(spec, raw_a, raw_b)
        if trap is None and (raw_a, raw_b) not in seen:
            seen.add((raw_a, raw_b))
            rows.append({"index": len(rows), "a": raw_a, "b": raw_b, "expected": expected,
                         "origin": origin, "a_value": interpret(raw_a, typ),
                         "b_value": interpret(raw_b, typ)})

    for a, b in endpoints:
        if len(rows) == 16:
            break
        append(a, b, "boundary")
    for _ in range(10000):
        if len(rows) == INPUT_COUNT:
            break
        a, b = interpret(generator.next(), typ), interpret(generator.next(), typ)
        if op == "int.mul.checked":
            a = generator.next() % (1 << 31) - (1 << 30)
            b = generator.next() % (1 << 31) - (1 << 30)
        elif op in {"int.shl.checked", "int.shr.checked"}:
            b = generator.next() % bits
        elif op == "int.cast" and spec["mode"] == "checked":
            target_low, target_high = limits(spec["target"])
            first, last = max(low, target_low), min(high, target_high)
            a = first + generator.next() % (last - first + 1)
        append(a, b, "seeded")
    require(len(rows) == INPUT_COUNT, "could not construct fixed valid input inventory")

    candidates = [(high, 1), (low, -1), (low, 1), (high, -1), (high, 2), (low, 2),
                  (0, 0), (1, 0), (low, -1), (low, 0), (-1, -1), (1, bits), (low, high)]
    if op == "int.cast":
        target_low, target_high = limits(spec["target"])
        candidates = [(a, 0) for a in (low, high, -1, target_low - 1, target_high + 1)
                      if low <= a <= high]
    traps, seen = [], set()
    for a, b in candidates:
        if not low <= a <= high or not low <= b <= high:
            continue
        raw_a, raw_b = encode(a), encode(b)
        _, error = independent_result(spec, raw_a, raw_b)
        if error is not None and (raw_a, raw_b) not in seen:
            seen.add((raw_a, raw_b))
            traps.append({"index": len(traps), "a": raw_a, "b": raw_b, "error": error})
    require(len(traps) <= 16, "trap inventory exceeds driver bound")
    return {"cell": spec, "cell_index": index, "valid": rows, "traps": traps}


def core_document(spec):
    operation = spec["operation"]
    unary = operation in {"identity", "int.cast", "int.neg.checked"}
    params = [{"name": "a", "type": spec["source"]},
              {"name": "b", "type": "u64" if unary else spec["source"]}]
    operations = [] if operation == "identity" else [{
        "op": operation, "args": ["a"] if unary else ["a", "b"],
        "out": [{"name": "result", "type": spec["target"]}],
        "attrs": {"mode": spec["mode"]} if operation == "int.cast" else {},
    }]
    checked = operation.endswith("checked") or (operation == "int.cast" and spec["mode"] == "checked")
    return {"schema": "hepta.hia.program.v1", "module": "signed_" + spec["id"], "functions": [{
        "name": "kernel", "params": params, "returns": [spec["target"]],
        "effects": ["trap"] if checked else [], "entry": "entry", "blocks": [{
            "id": "entry", "params": params, "ops": operations,
            "term": {"op": "ret", "values": ["a" if operation == "identity" else "result"]},
        }],
    }]}


def encoded_inputs(matrix):
    valid = b"".join(struct.pack("<QQQ", row["a"], row["b"], row["expected"]) for row in matrix["valid"])
    traps = b"".join(struct.pack("<QQ", row["a"], row["b"]) for row in matrix["traps"])
    return valid, traps


def check_core_reference(core, matrix):
    from hepta.hia_program import execute_program
    from hepta.hia_program_runtime import HIAProgramTrap
    params = core.as_dict()["functions"][0]["params"]
    for row in matrix["valid"]:
        args = [interpret(row[name], parameter["type"]) for name, parameter in zip(("a", "b"), params)]
        result = execute_program(core, "kernel", args)
        require(result.get("status") == "returned" and len(result.get("values", [])) == 1 and
                result["values"][0] & MASK == row["expected"], "Core reference differs from independent arithmetic")
    for row in matrix["traps"]:
        args = [interpret(row[name], parameter["type"]) for name, parameter in zip(("a", "b"), params)]
        try:
            result = execute_program(core, "kernel", args)
        except HIAProgramTrap as exc:
            result = exc.report
        require(result.get("status") == "trapped" and result.get("error", {}).get("code") == row["error"],
                "Core trap differs from independent arithmetic")


def parse_driver(text, *, matrix, expected_image, symbol, cpu, measuring):
    rows = [json.loads(line) for line in text.splitlines()]
    require(rows and isinstance(rows[0], dict), "missing driver binding")
    binding, tail = rows[0], rows[1:]
    valid_bytes, trap_bytes = encoded_inputs(matrix)
    require(binding.get("kind") == "binding" and binding.get("artifact_sha256") == expected_image["sha256"] and
            binding.get("artifact_bytes") == expected_image["bytes"] and binding.get("symbol") == symbol and
            binding.get("sealed") is True and binding.get("input_sha256") == sha256(valid_bytes).hexdigest() and
            binding.get("trap_sha256") == sha256(trap_bytes).hexdigest() and
            binding.get("cpu") == cpu and binding.get("affinity_count") == 1 and
            binding.get("entry_owner") == "sealed_image" and
            type(binding.get("image_base")) is int and binding["image_base"] > 0 and
            type(binding.get("symbol_address")) is int and
            type(binding.get("symbol_offset")) is int and binding["symbol_offset"] >= 0 and
            binding["symbol_address"] == binding["image_base"] + binding["symbol_offset"],
            "driver did not bind the expected image, data, symbol and CPU")
    if not measuring:
        expected = [{"kind": "input", "index": r["index"], "a": r["a"], "b": r["b"], "result": r["expected"]}
                    for r in matrix["valid"]]
        expected += [{"kind": "trap", "index": r["index"], "a": r["a"], "b": r["b"], "signal": 6}
                     for r in matrix["traps"]]
        expected.append({"kind": "functional", "inputs": INPUT_COUNT, "traps": len(matrix["traps"])})
        require(tail == expected, "functional observations differ from the complete fixed inventory")
        return {"binding": binding, "inputs": INPUT_COUNT, "traps": len(matrix["traps"])}
    require(len(tail) == WARMUPS + SAMPLES, "missing, duplicated or extra timing samples")
    checksum = (CHECKSUM_SEED + sum(r["expected"] for r in matrix["valid"]) * (ITERATIONS // INPUT_COUNT)) & MASK
    for batch, row in zip(range(-WARMUPS, SAMPLES), tail):
        require(set(row) == {"kind", "batch", "warmup", "elapsed_ns", "calls", "checksum", "cpu_before", "cpu_after"}
                and row["kind"] == "sample" and type(row["batch"]) is int and row["batch"] == batch and
                row["warmup"] is (batch < 0) and type(row["elapsed_ns"]) is int and row["elapsed_ns"] > 0 and
                type(row["calls"]) is int and row["calls"] == ITERATIONS and type(row["checksum"]) is int and
                row["checksum"] == checksum and row["cpu_before"] == cpu and row["cpu_after"] == cpu,
                "invalid sample order, checksum, CPU, clock or protocol dimensions")
    values = [row["elapsed_ns"] / ITERATIONS for row in tail if not row["warmup"]]
    return {"binding": binding, "samples": tail, "median_ns_per_call": statistics.median(values),
            "min_ns_per_call": min(values), "max_ns_per_call": max(values)}


def file_identity(path):
    path = Path(path)
    return {"sha256": sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}


def source_files():
    return sorted({Path(__file__).resolve(), *ROOT.joinpath("hepta").rglob("*.py"),
                   ASSETS / "signed_reference.rs", ASSETS / "signed_driver.c", PROTOCOL_PATH,
                   ASSETS / "SIGNED_PROTOCOL.md"})



GIT_ROUTING_ENV = (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_REPLACE_REF_BASE",
)


def committed_source_identity(root, source_identity, commit, *, git):
    """Bind executed bytes to raw committed blobs, independently of the index.

    A clean status can hide changed files behind assume-unchanged or
    skip-worktree. The index is recorded as repository context but never
    supplies the trusted source bytes. Git replacement objects are disabled.
    """
    root = Path(root).resolve(strict=True)
    require(not any(key in os.environ for key in GIT_ROUTING_ENV),
            "measured source requires ordinary Git routing without directory, index or object overrides")
    require(type(commit) is str and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit),
            "an exact source commit is required")
    git_path = Path(git)
    require(git_path.is_absolute() and git_path.is_file(), "an identified absolute Git executable is required")
    prefix = [str(git_path), "--no-replace-objects", "--no-optional-locks", "--literal-pathspecs",
              "-C", str(root)]

    def query(*args, data=None):
        completed = subprocess.run([*prefix, *args], input=data, capture_output=True, timeout=30)
        require(completed.returncode == 0, "source Git query failed: " +
                completed.stderr.decode(errors="replace")[-1000:])
        return completed.stdout

    def absolute(text):
        value = Path(text.decode().strip())
        return (value if value.is_absolute() else root / value).resolve(strict=True)

    require(absolute(query("rev-parse", "--show-toplevel")) == root,
            "source files are not at their declared Git checkout root")
    require(query("rev-parse", "HEAD").decode().strip() == commit,
            "source HEAD changed before committed source admission")
    git_directory = absolute(query("rev-parse", "--absolute-git-dir"))
    common_directory = absolute(query("rev-parse", "--git-common-dir"))
    index_path = absolute(query("rev-parse", "--git-path", "index"))
    require(index_path == git_directory / "index" and index_path.is_file(),
            "source index is outside the admitted Git directory")
    pointer = root / ".git"
    if pointer.is_file():
        checkout = {"kind": "worktree-file", "path": str(pointer), **file_identity(pointer)}
    else:
        require(pointer.is_dir() and pointer.resolve(strict=True) == git_directory,
                "source checkout has no ordinary Git directory or worktree pointer")
        checkout = {"kind": "directory", "path": str(pointer.resolve(strict=True))}
    context = {"git_directory": str(git_directory), "common_directory": str(common_directory),
               "checkout": checkout, "index": {"path": str(index_path), **file_identity(index_path)}}
    names = sorted(source_identity)
    require(names and all(type(name) is str and name and not Path(name).is_absolute() and
                         ".." not in Path(name).parts and "\0" not in name and "\n" not in name
                         for name in names), "invalid measured source inventory")
    raw_tree = query("ls-tree", "-r", "-z", "--full-tree", commit, "--", *names)
    entries = {}
    for raw in raw_tree.split(b"\0"):
        if not raw:
            continue
        header, name = raw.split(b"\t", 1)
        mode, kind, object_id = header.decode("ascii").split()
        name = name.decode("utf-8")
        require(mode in {"100644", "100755"} and kind == "blob" and name not in entries,
                "measured source must be a unique committed ordinary file")
        entries[name] = object_id
    require(set(entries) == set(names), "measured source inventory differs from the declared commit")
    # One binary batch preserves exact source bytes, including non-ASCII text.
    objects = query("cat-file", "--batch", data="".join(entries[name] + "\n" for name in names).encode("ascii"))
    cursor = 0
    bound = {}
    for name in names:
        ending = objects.find(b"\n", cursor)
        require(ending >= cursor, "truncated committed source batch")
        fields = objects[cursor:ending].split()
        require(len(fields) == 3 and fields[0].decode("ascii") == entries[name] and fields[1] == b"blob" and
                fields[2].isdigit(), "committed source object differs from its tree entry")
        size = int(fields[2])
        cursor = ending + 1
        raw = objects[cursor:cursor + size]
        cursor += size
        require(len(raw) == size and objects[cursor:cursor + 1] == b"\n", "truncated committed source blob")
        cursor += 1
        expected = sha256(raw).hexdigest()
        require(type(source_identity[name]) is str and source_identity[name] == expected and
                file_identity(root / name) == {"sha256": expected, "bytes": size},
                "executed source differs from declared commit: " + name)
        bound[name] = {"git_blob": entries[name], "sha256": expected, "bytes": size}
    require(cursor == len(objects), "extra committed source batch content")
    return {"commit": commit, "tree": query("rev-parse", commit + "^{tree}").decode().strip(),
            "git_context": context, "sources": bound}


def campaign(output, *, cpu=None, cc="gcc", rustc="rustc", linker="ld", prepare_only=False,
             functional_only=False, allow_dirty=False):
    require(not (prepare_only and functional_only), "choose one non-measuring mode")
    require(not allow_dirty or prepare_only or functional_only, "dirty trees cannot produce measurements")
    destination = Path(output).absolute()
    destination.mkdir(parents=False, exist_ok=False)
    (destination / "logs").mkdir()
    initial_affinity = sorted(os.sched_getaffinity(0))
    report = {"schema": SCHEMA, "status": "running", "complete": False, "ok": False,
              "mode": "prepare" if prepare_only else "functional" if functional_only else "measurement",
              "started_utc": datetime.now(timezone.utc).isoformat(), "protocol": fixed_protocol(),
              "host": {"node": platform.node(), "platform": platform.platform(),
                       "initial_affinity": initial_affinity, "selected_cpu": cpu,
                       "cpuinfo": Path("/proc/cpuinfo").read_text(),
                       "loadavg_before": Path("/proc/loadavg").read_text().strip()},
              "commands": [], "cells": [], "builds": {}, "binaries": {}, "functional": [], "rows": [],
              "selected_input_manifests": {key: value for key, value in sorted(os.environ.items())
                                           if key.startswith("HEPTA_HIA_") and key.endswith("_MANIFEST")},
              "relevant_environment": {key: os.environ.get(key) for key in
                  ("PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME", "Z3_LIBRARY_PATH")}}
    started = time.monotonic()

    def save():
        temporary = destination / "RESULT.json.pending"
        temporary.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        temporary.replace(destination / "RESULT.json")

    def run(command, label, timeout=120, allow_failure=False):
        stamp = time.monotonic()
        stem = f"logs/{len(report['commands']):03d}-{label}"
        receipt = {"label": label, "argv": [str(word) for word in command], "cwd": str(ROOT),
                   "stdout": stem + ".stdout", "stderr": stem + ".stderr",
                   "started_utc": datetime.now(timezone.utc).isoformat()}
        try:
            result = subprocess.run(receipt["argv"], cwd=ROOT, capture_output=True, timeout=timeout)
            stdout, stderr = result.stdout, result.stderr
            receipt.update(returncode=result.returncode, timed_out=False)
        except subprocess.TimeoutExpired as exc:
            stdout, stderr = exc.stdout or b"", exc.stderr or b""
            receipt.update(returncode=None, timed_out=True)
        for stream, data in (("stdout", stdout), ("stderr", stderr)):
            (destination / receipt[stream]).write_bytes(data)
            receipt[stream + "_sha256"] = sha256(data).hexdigest()
        receipt["elapsed_seconds"] = time.monotonic() - stamp
        report["commands"].append(receipt)
        save()
        require((receipt["returncode"] == 0 or allow_failure) and not receipt["timed_out"],
                label + " failed: " + stderr.decode(errors="replace")[-2000:])
        return stdout.decode(), receipt

    def identify_tool(label, supplied):
        found = shutil.which(supplied)
        require(found is not None, label + " is required")
        path = Path(found).absolute()  # Preserve rustup's argv[0] dispatch.
        version, _ = run([path, "--version"], label + "-version", 20)
        report.setdefault("toolchain", {})[label] = {"path": str(path), "resolved_path": str(path.resolve()),
                                                     **file_identity(path), "version": version.strip()}
        return path

    def dependencies(path, label):
        output, _ = run(["ldd", path], label + "-dependencies", 20)
        for name in re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)", output, re.MULTILINE):
            dependency = Path(name).resolve(strict=True)
            report.setdefault("runtime_dependencies", {})[str(dependency)] = file_identity(dependency)

    def check_toolchain_and_runtime():
        for label, tool in report.get("toolchain", {}).items():
            path = Path(tool["path"])
            require(str(path.resolve()) == tool["resolved_path"] and
                    file_identity(path) == {key: tool[key] for key in ("sha256", "bytes")},
                    label + " tool identity changed during campaign")
            if "compiler" in tool:
                compiler = tool["compiler"]
                require(file_identity(compiler["path"]) == {key: compiler[key] for key in ("sha256", "bytes")},
                        "actual Rust compiler identity changed during campaign")
        for name, identity in report.get("runtime_dependencies", {}).items():
            require(file_identity(name) == identity, "runtime dependency changed during campaign")

    save()
    try:
        protocol_bytes = PROTOCOL_PATH.read_bytes()
        require(json.loads(protocol_bytes) == fixed_protocol(), "protocol differs from the fixed signed-v1 inventory")
        (destination / "protocol.json").write_bytes(protocol_bytes)
        report["protocol_sha256"] = sha256(protocol_bytes).hexdigest()
        git_path = identify_tool("git", "git")
        git_command = [git_path, "--no-replace-objects", "--no-optional-locks"]
        git_probe, probe_receipt = run([*git_command, "rev-parse", "--is-inside-work-tree"], "source-git-probe", 10,
                                       allow_failure=True)
        versioned = probe_receipt["returncode"] == 0 and git_probe.strip() == "true"
        require(versioned or allow_dirty, "a committed Git source checkout is required")
        report["source_versioned"] = versioned
        report["development_only"] = bool(allow_dirty)
        report["source_commit"] = run([*git_command, "rev-parse", "HEAD"], "source-commit", 10)[0].strip() if versioned else None
        report["source_tree"] = run([*git_command, "rev-parse", "HEAD^{tree}"], "source-tree", 10)[0].strip() if versioned else None
        report["source_status_before"] = (run([*git_command, "status", "--porcelain=v1", "--untracked-files=no"],
                                              "source-status-before", 10)[0] if versioned else "UNVERSIONED_DEVELOPMENT_SOURCE")
        require(allow_dirty or not report["source_status_before"].strip(), "requires clean tracked source or explicit development functional mode")
        report["source_identity"] = {p.relative_to(ROOT).as_posix(): file_identity(p)["sha256"] for p in source_files()}
        if not prepare_only and not functional_only:
            report["source_commit_binding"] = committed_source_identity(
                ROOT, report["source_identity"], report["source_commit"], git=git_path)
            require(report["source_commit_binding"]["tree"] == report["source_tree"],
                    "measured source tree changed during admission")
        with tarfile.open(destination / "source-snapshot.tar.gz", "x:gz") as archive:
            for name in report["source_identity"]:
                archive.add(ROOT / name, arcname=name, recursive=False)
        if not prepare_only:
            require(platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"},
                    "Linux x86-64 is required")
            require(cpu is not None and cpu in initial_affinity, "choose an explicitly allowed CPU")
            os.sched_setaffinity(0, {cpu})
            report["host"]["actual_affinity"] = sorted(os.sched_getaffinity(0))
        from hepta.hia_program import verify_program
        checked = {}
        matrices = {}
        for index, spec in enumerate(case_specs()):
            name = spec["id"]
            directory = destination / name
            directory.mkdir()
            core = verify_program(core_document(spec))
            matrix = input_matrix(spec, index)
            check_core_reference(core, matrix)
            (directory / "source.core.hepta").write_bytes(core.canonical_bytes)
            (directory / "inputs.json").write_text(json.dumps(matrix, sort_keys=True, indent=2) + "\n")
            valid, traps = encoded_inputs(matrix)
            (directory / "inputs.bin").write_bytes(valid)
            (directory / "traps.bin").write_bytes(traps)
            report["cells"].append({"id": name, "core_sha256": core.sha256, "valid_inputs": INPUT_COUNT,
                                    "invalid_inputs": len(matrix["traps"]), "reference_checked": True})
            checked[name], matrices[name] = core, matrix
            save()
        if prepare_only:
            report.update(status="prepared_no_native_execution", complete=True, ok=True,
                          performance_measured=False)
        else:
            cc_path = identify_tool("cc", cc)
            rust_path = identify_tool("rustc", rustc)
            linker_path = identify_tool("linker", linker)
            sysroot, _ = run([rust_path, "--print", "sysroot"], "rust-sysroot", 20)
            actual_rust = Path(sysroot.strip()) / "bin/rustc"
            require(actual_rust.is_file(), "actual Rust compiler behind its launcher is unavailable")
            report["toolchain"]["rustc"]["compiler"] = {"path": str(actual_rust), **file_identity(actual_rust)}
            report["toolchain"]["rustc"]["verbose_version"] = run([rust_path, "-vV"], "rust-verbose-version", 20)[0]
            driver = destination / "signed-driver"
            rust_library = destination / "signed-rust.so"
            run([cc_path, *report["protocol"]["c_flags"], ASSETS / "signed_driver.c", "-ldl", "-o", driver], "build-driver")
            run([rust_path, *report["protocol"]["rust_flags"], "-C", "linker=" + str(cc_path),
                 ASSETS / "signed_reference.rs", "-o", rust_library], "build-rust")
            report["binaries"]["driver"] = {"path": "signed-driver", **file_identity(driver)}
            report["binaries"]["rust"] = {"path": "signed-rust.so", **file_identity(rust_library)}
            dependencies(driver, "driver")
            dependencies(rust_library, "rust")
            from hepta.hia_verified_kernel import build_verified_kernel
            for spec in case_specs():
                name = spec["id"]
                directory = destination / name
                artifacts = directory / "artifacts"
                artifacts.mkdir()
                library = directory / "hia.so"
                build = build_verified_kernel(checked[name], library, strategy="scalar", linker=str(linker_path),
                                              timeout_ms=PROOF_DEADLINE_MS, query_directory=directory / "queries",
                                              artifact_directory=artifacts)
                require(build.get("selected_strategy") == "scalar" and build.get("runtime_solver_calls") == 0 and
                        build.get("validation", {}).get("ok") is True and build["validation"].get("complete") is True,
                        "scalar final-image proof did not complete")
                report["builds"][name] = build
                report["binaries"]["hia:" + name] = {"path": name + "/hia.so", **file_identity(library)}
                require(report["binaries"]["hia:" + name]["sha256"] == build["artifact_sha256"],
                        "final proof and published library differ")
                save()
            dependencies(destination / case_specs()[0]["id"] / "hia.so", "hia")
            case_order = [(spec["id"], implementation) for spec in case_specs() for implementation in ("hia", "rust")]
            random.Random(ORDER_SEED).shuffle(case_order)
            report["case_order"] = [list(pair) for pair in case_order]
            # Finish every functional control before any performance case.
            for name, implementation in case_order:
                binary = report["binaries"]["rust" if implementation == "rust" else "hia:" + name]
                library = destination / binary["path"]
                symbol = "signed_" + name if implementation == "rust" else "kernel"
                command = [driver, "functional", library, symbol, binary["sha256"],
                           destination / name / "inputs.bin", destination / name / "traps.bin"]
                output_text, receipt = run(command, "functional-" + implementation + "-" + name, 60)
                parsed = parse_driver(output_text, matrix=matrices[name], expected_image=binary,
                                      symbol=symbol, cpu=cpu, measuring=False)
                report["functional"].append({"cell": name, "implementation": implementation,
                                             "stdout": receipt["stdout"], **parsed})
                save()
            check_toolchain_and_runtime()
            report["tool_runtime_identity_checked_before_measurement"] = not functional_only
            if not functional_only:
                for name, implementation in case_order:
                    binary = report["binaries"]["rust" if implementation == "rust" else "hia:" + name]
                    library = destination / binary["path"]
                    symbol = "signed_" + name if implementation == "rust" else "kernel"
                    command = [driver, "measure", library, symbol, binary["sha256"],
                               destination / name / "inputs.bin", destination / name / "traps.bin", ITERATIONS, SAMPLES]
                    output_text, receipt = run(command, "measure-" + implementation + "-" + name, 120)
                    parsed = parse_driver(output_text, matrix=matrices[name], expected_image=binary,
                                          symbol=symbol, cpu=cpu, measuring=True)
                    report["rows"].append({"cell": name, "implementation": implementation,
                                           "stdout": receipt["stdout"], **parsed})
                    save()
            check_toolchain_and_runtime()
            report["tool_runtime_identity_checked_after_measurement"] = not functional_only
            report.update(status="functional_pass_no_measurements" if functional_only else "completed",
                          complete=True, ok=True, performance_measured=not functional_only)
        report["source_commit_after"] = (run([*git_command, "rev-parse", "HEAD"], "source-commit-after", 10)[0].strip()
                                          if versioned else None)
        report["source_status_after"] = (run([*git_command, "status", "--porcelain=v1", "--untracked-files=no"],
                                             "source-status-after", 10)[0] if versioned else "UNVERSIONED_DEVELOPMENT_SOURCE")
        require(report["source_commit_after"] == report["source_commit"] and
                report["source_status_before"] == report["source_status_after"], "source tree changed during campaign")
        require(report["source_identity"] == {p.relative_to(ROOT).as_posix(): file_identity(p)["sha256"] for p in source_files()},
                "executed source inventory changed during campaign")
        if not prepare_only and not functional_only:
            report["source_commit_binding_after"] = committed_source_identity(
                ROOT, report["source_identity"], report["source_commit"], git=git_path)
            require(report["source_commit_binding_after"] == report["source_commit_binding"],
                    "committed source or Git routing/index changed during campaign")
        report["selected_input_manifests_after"] = {key: value for key, value in sorted(os.environ.items())
                                                   if key.startswith("HEPTA_HIA_") and key.endswith("_MANIFEST")}
        require(report["selected_input_manifests_after"] == report["selected_input_manifests"],
                "native input selectors changed during campaign")
        for identity in report["binaries"].values():
            require(file_identity(destination / identity["path"]) == {k: identity[k] for k in ("sha256", "bytes")},
                    "retained binary changed during campaign")
        check_toolchain_and_runtime()
        report["host"]["loadavg_after"] = Path("/proc/loadavg").read_text().strip()
        report["manifest"] = {p.relative_to(destination).as_posix(): file_identity(p)
                              for p in sorted(destination.rglob("*")) if p.is_file() and p != destination / "RESULT.json"}
        save()
        return report
    except BaseException as exc:
        report.update(status="failed", complete=False, ok=False,
                      error={"type": type(exc).__name__, "message": str(exc)})
        save()
        raise
    finally:
        os.sched_setaffinity(0, initial_affinity)
        report["elapsed_seconds"] = time.monotonic() - started
        save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--linker", default="ld")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--prepare-only", action="store_true")
    modes.add_argument("--functional-only", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true", help="development preparation/functional checks only")
    args = parser.parse_args()
    try:
        result = campaign(**vars(args))
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps({"status": result["status"], "cells": len(result["cells"]),
                      "functional_cases": len(result["functional"]), "measurement_cases": len(result["rows"]),
                      "output": str(args.output / "RESULT.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
