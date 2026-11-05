"""Bounded native scalar evaluator for historical upstream fixes.

Accepted source is never repaired. Public and terminal hidden executions use
the same sealed native image; only public observations enter model feedback.
"""
from __future__ import annotations

import fcntl
from hashlib import sha256
import os
from pathlib import Path
import re
import resource
import subprocess
import time

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramTrap, HIAProgramBudgetExceeded
from hepta.hia_program_tools import decode_json
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity

METHODS = frozenset({"wrapping_add", "wrapping_sub", "wrapping_mul", "wrapping_neg", "wrapping_div", "wrapping_rem",
                     "checked_add", "checked_sub", "checked_mul", "checked_neg", "checked_div", "checked_rem",
                     "unwrap", "unwrap_or", "rem_euclid", "div_euclid", "abs", "unsigned_abs", "min", "max"})

C_DRIVER = '''#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
extern int32_t target(int32_t,int32_t);
int main(void) {
    int32_t a,b;
    while(scanf("%" SCNd32 " %" SCNd32,&a,&b)==2) {
        printf("%" PRId32 "\\n",target(a,b)); fflush(stdout);
    }
    return 0;
}
'''
RUST_DRIVER = '''#![forbid(unsafe_code)]
#[path="target.rs"] mod api;
use std::io::{self,BufRead};
fn main() {
    let target:fn(i32,i32)->i32=api::target;
    for line in io::stdin().lock().lines() {
        let values:Vec<i32>=line.unwrap().split_whitespace().map(|v|v.parse().unwrap()).collect();
        println!("{}",target(values[0],values[1]));
    }
}
'''


def save(path, value):
    with Path(path).open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def admit_rust(source):
    if type(source) is not str or len(source.encode()) > 65536:
        raise ValueError("Rust source size/type")
    if re.search(r'[^A-Za-z0-9_\s{}();:,.+\-*/%<>=!&|^?]', source):
        raise ValueError("Rust scalar source contains an unadmitted token")
    if "/*" in source or "//" in source:
        raise ValueError("Comments are outside this scalar source protocol")
    if (re.search(r'\b(?:f32|f64)\b', source)
            or re.search(r'\b[0-9][0-9_]*(?:[eE][+-]?[0-9_]+|f(?:32|64)\b)', source)
            or re.search(r'\b[0-9][0-9_]*\.(?![A-Za-z_])', source)):
        raise ValueError("Floating-point operations are outside the integer/Boolean profile")
    if re.search(r'\b(?:unsafe|extern|use|mod|impl|trait|struct|enum|union|type|static|const|async|await|for|while|loop|match|move|dyn|fnptr)\b', source):
        raise ValueError("Rust source escapes the disclosed scalar profile")
    if re.search(r'!\s*[{([]', source):
        raise ValueError("Rust macros are outside this scalar profile")
    no_constants = re.sub(r'\b(?:i32|i64|u32|u64)::(?:MIN|MAX)\b', '0', source)
    if "::" in no_constants:
        raise ValueError("Rust external path is outside this scalar profile")
    if len(re.findall(r'\bfn\b', source)) != 1 or len(re.findall(r'\btarget\b', source)) != 1:
        raise ValueError("Exactly one nonrecursive target function is required")
    if re.search(r'\)\s*\(', source):
        raise ValueError("Indirect and closure calls are outside the scalar profile")
    if not re.match(r'\s*pub\s+fn\s+target\s*\(', source):
        raise ValueError("target must be the public scalar entry")
    for call in re.finditer(r'([A-Za-z_][A-Za-z_0-9]*)\s*\(', source):
        name = call.group(1)
        if name in {"target", "if", "return", "let"}:
            continue
        if not source[:call.start()].rstrip().endswith(".") or name not in METHODS:
            raise ValueError("unadmitted scalar call: " + name)
    return source


def parse(task, language, text):
    value = decode_json(text)
    expected = set(task["original_" + language])
    if type(value) is not dict or set(value) != {"files"} or type(value["files"]) is not dict or set(value["files"]) != expected:
        raise ValueError("exact single-file inventory required")
    source = next(iter(value["files"].values()))
    if type(source) is not str or len(source.encode()) > 65536:
        raise ValueError("source byte bound")
    if language == "rust":
        return admit_rust(source)
    checked = assemble_program(source)
    doc = checked.as_dict()
    if doc.get("exports") != ["target"] or len(doc["functions"]) != 1:
        raise ValueError("one target export and function required")
    fn = doc["functions"][0]
    if (fn["name"] != "target" or [p["type"] for p in fn["params"]] != ["i32", "i32"]
            or fn["returns"] != ["i32"] or set(fn["effects"]) - {"trap"}):
        raise ValueError("public scalar signature or effects changed")
    blocks = {b["id"]: b for b in fn["blocks"]}
    if len(blocks) > 64 or sum(len(b["ops"]) for b in blocks.values()) > 512:
        raise ValueError("scalar CFG size exceeded")
    active, done = set(), set()

    def visit(name):
        if name in active:
            raise ValueError("loops are outside the scalar maintenance profile")
        if name in done:
            return
        active.add(name)
        block = blocks[name]
        for op in block["ops"]:
            if op["op"] == "call" or any(p["type"] not in {"i32", "i64", "u8", "u32", "u64", "usize", "bool"} for p in op["out"]):
                raise ValueError("non-scalar operation")
        term = block["term"]
        for edge in ([term] if term["op"] == "jump" else [term["then"], term["else"]] if term["op"] == "branch" else []):
            visit(edge["target"])
        active.remove(name); done.add(name)

    visit(fn["entry"])
    return checked


def build(task, language, text, folder, clang, rustc):
    folder = Path(folder); folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    row = {"status": "response_rejected", "native_built": False, "language": language,
           "task_id": task["id"], "commands": []}
    try:
        parsed = parse(task, language, text)
        row["status"] = "infrastructure_failure"
        compiler = file_identity(clang if language == "assembly" else rustc)
        row["compiler"] = compiler
        binary = folder / "candidate"
        if language == "assembly":
            core = folder / "candidate.core.json"; core.write_bytes(parsed.canonical_bytes)
            row["core"] = file_identity(core)
            row["native_compilation"] = build_program_native(parsed, folder / "candidate.o", clang=clang, kind="object")
            (folder / "driver.c").write_text(C_DRIVER)
            argv = [clang, "-O2", str(folder / "driver.c"), str(folder / "candidate.o"), "-o", str(binary)]
        else:
            (folder / "target.rs").write_text(parsed); (folder / "driver.rs").write_text(RUST_DRIVER)
            argv = [rustc, "--edition=2021", "-Copt-level=2", "-Coverflow-checks=on", str(folder / "driver.rs"), "-o", str(binary)]
        then = time.monotonic_ns()
        result = subprocess.run(argv, capture_output=True, text=True, timeout=45)
        row["compile"] = {"argv": argv, "returncode": result.returncode, "stdout": result.stdout,
                          "stderr": result.stderr, "wall_ns": time.monotonic_ns()-then}
        row["status"] = "compiled" if result.returncode == 0 else "compile_rejected"
        if result.returncode == 0:
            row.update(native_built=True, artifact=file_identity(binary))
        row["compiler_unchanged"] = file_identity(compiler["path"]) == compiler
        if not row["compiler_unchanged"]:
            row.update(status="infrastructure_failure", native_built=False)
    except BaseException as error:
        row["error"] = {"type": type(error).__name__, "message": str(error)}
    row["wall_ns"] = time.monotonic_ns()-started
    save(folder / "BUILD.json", row)
    return row


def execute(built, task, cases, expected):
    started = time.monotonic_ns()
    image = Path(built["artifact"]["path"]).read_bytes()
    if sha256(image).hexdigest() != built["artifact"]["sha256"]:
        raise RuntimeError("native image changed")
    fd = os.memfd_create("hia-upstream-factorial", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(image)
        os.fchmod(fd, 0o500)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)

        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
            resource.setrlimit(resource.RLIMIT_AS, (256*1024**2, 256*1024**2))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        try:
            result = subprocess.run([f"/proc/self/fd/{fd}"], pass_fds=(fd,), preexec_fn=limits,
                input="".join(f"{a} {b}\n" for a,b in cases), capture_output=True, text=True, timeout=5)
            try:
                actual = [int(line) for line in result.stdout.splitlines()]
            except ValueError:
                actual = None
            row = {"status": "correct" if result.returncode == 0 and actual == expected else "observable_wrong",
                   "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                   "actual": actual, "cases": cases, "expected": expected}
        except subprocess.TimeoutExpired as error:
            row = {"status": "observable_timeout", "error": str(error), "cases": cases, "expected": expected}
        row.update(artifact_unchanged=file_identity(built["artifact"]["path"]) == built["artifact"],
                   sealed_image=True, seals=fcntl.fcntl(fd, fcntl.F_GET_SEALS))
        if built["language"] == "assembly" and row["status"] == "correct":
            if file_identity(built["core"]["path"]) != built["core"]:
                raise RuntimeError("Core changed")
            program = verify_program(Path(built["core"]["path"]).read_bytes())
            vm = []
            for args in cases:
                try:
                    value = execute_program(program, "target", args, max_steps=10000, max_heap_bytes=0)
                    vm.append(value["result"])
                except (HIAProgramTrap, HIAProgramBudgetExceeded):
                    vm.append(None)
            row["same_core_vm_agreement"] = vm == expected
            if not row["same_core_vm_agreement"]:
                row["status"] = "observable_wrong"
        row["wall_ns"] = time.monotonic_ns()-started
        return row
    finally:
        os.close(fd)


def feedback(build_record, observed):
    row = {"compile_status": build_record["status"], "diagnostic": build_record.get("error")}
    if "compile" in build_record:
        row["compiler_stderr"] = build_record["compile"]["stderr"][:4000]
    if observed is not None:
        row["public"] = {k: observed.get(k) for k in ("status", "cases", "expected", "actual", "returncode", "stderr")}
    return row
