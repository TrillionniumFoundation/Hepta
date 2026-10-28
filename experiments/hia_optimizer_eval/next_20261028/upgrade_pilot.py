#!/usr/bin/env python3
"""Actual two-file interface migrations, scored without hidden-test feedback.

This is a secondary upgrade pilot. It does not replace the four-task primary
maintenance comparison. References create controls only; model candidates come
exclusively from retained owned-runtime responses.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_tools import apply_program_patch, decode_json
from tools.provider_adapter.llama_cpp_engine import LlamaCppEngine, canonical, file_identity
from tools.qualify_hia_agent_holdout import bindings as base_bindings

PROTOCOL = "hepta.hia.module-upgrade.next-20261028.v1"
LIMIT = 1536
ATTEMPTS = 2
MAX64 = 2**64 - 1
FILE_NAMES = {"hia": ("api.hia.json", "client.hia.json"), "rust": ("api.rs", "client.rs")}


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def op(name, args, output, typ="u32", **attrs):
    if name == "int.cast":
        attrs.setdefault("mode", "wrap")
    return {"op": name, "args": args, "out": [{"name": output, "type": typ}], "attrs": attrs}


def function(name, params, returns, ops, values, effects=None):
    ps = [{"name": n, "type": t} for n, t in params]
    return {"name": name, "params": ps, "returns": returns, "effects": effects or [],
            "entry": "entry", "blocks": [{"id": "entry", "params": copy.deepcopy(ps),
                "ops": ops, "term": {"op": "ret", "values": values}}]}


def header_client(upgraded):
    length_type, return_type = ("u32", "u64") if upgraded else ("u16", "u32")
    operations = [op("const", [], "mask", value=255), op("bit.and", ["tag", "mask"], "tag_low"),
        op("int.cast", ["tag_low"], "tag64", "u64"),
        op("const", [], "shift", "u64", value=32 if upgraded else 16),
        op("int.shl.checked", ["tag64", "shift"], "upper", "u64"),
        op("int.cast", ["length"], "length_arg", length_type),
        op("call", ["length_arg"], "encoded_length", return_type, function="wire_length"),
        op("int.cast", ["encoded_length"], "length64", "u64"),
        op("bit.or", ["upper", "length64"], "answer", "u64")]
    return function("entrypoint", [("tag", "u32"), ("length", "u32"), ("reserved", "u32")],
                    ["u64"], operations, ["answer"], ["trap"])


def window_client(upgraded):
    if upgraded:
        call = {"op": "call", "args": ["offset", "amount", "capacity"],
                "out": [{"name": "valid", "type": "bool"}, {"name": "end", "type": "u32"}],
                "attrs": {"function": "advance"}}
        operations = [call, op("int.cast", ["end"], "end64", "u64"),
                      op("const", [], "failure", "u64", value=MAX64),
                      op("select", ["valid", "end64", "failure"], "answer", "u64")]
    else:
        operations = [op("call", ["offset", "amount"], "end", function="advance"),
                      op("int.cast", ["end"], "answer", "u64")]
    return function("entrypoint", [("offset", "u32"), ("amount", "u32"), ("capacity", "u32")],
                    ["u64"], operations, ["answer"])


def oracle(task_id, case):
    x, y, z = case
    if task_id == "wire_length_v2":
        return ((x & 255) << 32) | y
    if task_id == "bounded_window_v2":
        return x + y if x + y <= z else MAX64
    raise ValueError("unknown upgrade task")


def fixtures():
    old_header = function("wire_length", [("length", "u16")], ["u32"],
                          [op("int.cast", ["length"], "answer")], ["answer"])
    new_header = function("wire_length", [("length", "u32")], ["u64"],
                          [op("int.cast", ["length"], "answer", "u64")], ["answer"])
    old_window = function("advance", [("offset", "u32"), ("amount", "u32")], ["u32"],
                          [op("int.add.wrap", ["offset", "amount"], "answer")], ["answer"])
    new_window = function("advance", [("offset", "u32"), ("amount", "u32"), ("capacity", "u32")],
        ["bool", "u32"], [op("int.cast", ["offset"], "offset64", "u64"),
                          op("int.cast", ["amount"], "amount64", "u64"),
                          op("int.cast", ["capacity"], "capacity64", "u64"),
                          op("int.add.wrap", ["offset64", "amount64"], "end64", "u64"),
                          op("compare.le", ["end64", "capacity64"], "valid", "bool"),
                          op("int.cast", ["end64"], "end")], ["valid", "end"])
    tasks = [
        {"id": "wire_length_v2", "provider": "wire_length",
         "specification": "Upgrade the packet-header provider from wire_length(u16)->u32 to wire_length(u32)->u64, preserving every length bit. Update its consumer so the low eight tag bits occupy bits 32..39 and the complete u32 length occupies bits 0..31. The consumer must call the provider without a u16 truncation. Its public entrypoint(tag:u32,length:u32,reserved:u32)->u64 stays unchanged; reserved is ignored.",
         "provider_params": [["length", "u32"]], "provider_returns": ["u64"],
         "original_hia": {"api.hia.json": old_header, "client.hia.json": header_client(False)},
         "correct_hia": {"api.hia.json": new_header, "client.hia.json": header_client(True)},
         "original_rust": {"api.rs": "pub fn wire_length(length:u16)->u32 { length as u32 }\n",
             "client.rs": "use crate::api;\npub fn entrypoint(tag:u32,length:u32,reserved:u32)->u64 { let _ = reserved; (((tag & 255) as u64) << 16) | (api::wire_length(length as u16) as u64) }\n"},
         "correct_rust": {"api.rs": "pub fn wire_length(length:u32)->u64 { length as u64 }\n",
             "client.rs": "use crate::api;\npub fn entrypoint(tag:u32,length:u32,reserved:u32)->u64 { let _ = reserved; (((tag & 255) as u64) << 32) | api::wire_length(length) }\n"},
         "public_cases": [[0, 0, 0], [1, 7, 0], [255, 65535, 0]],
         "hidden_cases": [[tag, size, 0] for tag in (0, 1, 17, 255, 256, 4294967295)
                          for size in (0, 1, 65534, 65535, 65536, 65537, 2147483648, 4294967295)]},
        {"id": "bounded_window_v2", "provider": "advance",
         "specification": "Upgrade the window provider from advance(offset:u32,amount:u32)->u32 to advance(offset:u32,amount:u32,capacity:u32)->(bool,u32). Compute the mathematical end without u32 overflow. Valid means end <= capacity; the returned end is meaningful only when valid. Update the consumer call, tuple unpacking and failure handling. The unchanged public entrypoint(offset:u32,amount:u32,capacity:u32)->u64 returns end when valid and 18446744073709551615 otherwise. It must call the provider exactly once.",
         "provider_params": [["offset", "u32"], ["amount", "u32"], ["capacity", "u32"]],
         "provider_returns": ["bool", "u32"],
         "original_hia": {"api.hia.json": old_window, "client.hia.json": window_client(False)},
         "correct_hia": {"api.hia.json": new_window, "client.hia.json": window_client(True)},
         "original_rust": {"api.rs": "pub fn advance(offset:u32,amount:u32)->u32 { offset.wrapping_add(amount) }\n",
             "client.rs": "use crate::api;\npub fn entrypoint(offset:u32,amount:u32,capacity:u32)->u64 { let _ = capacity; api::advance(offset,amount) as u64 }\n"},
         "correct_rust": {"api.rs": "pub fn advance(offset:u32,amount:u32,capacity:u32)->(bool,u32) { let end = (offset as u64) + (amount as u64); (end <= capacity as u64, end as u32) }\n",
             "client.rs": "use crate::api;\npub fn entrypoint(offset:u32,amount:u32,capacity:u32)->u64 { let (valid,end) = api::advance(offset,amount,capacity); if valid { end as u64 } else { u64::MAX } }\n"},
         "public_cases": [[0, 1, 10], [10, 3, 10], [8, 2, 10]],
         "hidden_cases": [[offset, amount, capacity] for offset in (0, 1, 4095, 4096, 4294967294, 4294967295)
                          for amount in (0, 1, 2, 4294967295) for capacity in (0, 1, 4096, 4294967295)]},
    ]
    state = 0x20261028
    for task in tasks:
        for _ in range(64):
            row = []
            for _ in range(3):
                state = (1664525 * state + 1013904223) % 2**32
                row.append(state)
            task["hidden_cases"].append(row)
        seen = {tuple(row) for row in task["public_cases"]}
        hidden = []
        for row in task["hidden_cases"]:
            if tuple(row) not in seen:
                seen.add(tuple(row)); hidden.append(row)
        task["hidden_cases"] = hidden
        for split in ("public", "hidden"):
            task[split + "_expected"] = [oracle(task["id"], row) for row in task[split + "_cases"]]
        for label in ("original_hia", "correct_hia"):
            verify_program(document(task, task[label]))
    return tasks


def document(task, files):
    return {"schema": "hepta.hia.program.v6", "module": task["id"], "exports": ["entrypoint"],
            "functions": [files["api.hia.json"], files["client.hia.json"]]}


def prompt(task, language):
    context = task["original_" + language]
    format_rule = ("Each HIA file is one complete typed function object. Return both replacement function objects; the host binds and applies one patch.v2 with interface_policy=migrate, then verifies the whole two-function module. A call's out array has one entry per returned value. Scalar operations include const, int.cast, int.add.wrap, bit.and/or, compare.lt/le/gt/ge/eq/ne, and select. .wrap is modulo word width; .checked traps on overflow. int.cast needs attrs={\"mode\":\"wrap\"} or checked; comparison outputs bool; select args are condition,true_value,false_value."
        if language == "hia" else
        "Return both replacement Rust file strings. Keep one public function per file and the existing crate::api import. Pure scalar Rust only: no unsafe, macros, attributes, extra imports/functions, external calls or loops.")
    return ("Perform this two-file interface upgrade. Return ONLY a JSON object with one key files, mapping the two shown filenames to their complete replacement contents. No fences or explanation.\n"
        + task["specification"] + "\n" + format_rule
        + "\nPreserve the public entrypoint signature. Keep exactly one consumer call to the provider; update both files atomically.\n"
        + "Public smoke cases (arguments and expected results):\n"
        + canonical(list(zip(task["public_cases"], task["public_expected"]))).decode()
        + "\nCurrent workspace:\n" + canonical(context).decode())


RUST_SCALAR_METHODS = frozenset({
    "wrapping_add", "wrapping_sub", "wrapping_mul", "wrapping_shl", "wrapping_shr",
    "checked_add", "checked_sub", "checked_mul", "checked_shl", "checked_shr",
    "overflowing_add", "overflowing_sub", "overflowing_mul",
    "saturating_add", "saturating_sub", "saturating_mul", "min", "max", "abs_diff",
    "is_some", "is_none", "unwrap", "unwrap_or", "unwrap_or_default",
    "count_ones", "count_zeros", "leading_zeros", "trailing_zeros", "rotate_left", "rotate_right",
})


def rust_safety_check(task, files, enforce_contract):
    """Fail-closed finite scalar syntax, followed by actual Rust type checking.

    This is deliberately not a Rust parser or a general security sandbox.
    Only primitive scalar operations/checked-integer Option methods and the
    one declared provider call belong to this profile. Resource limits and
    sealed executable bytes are separate controls; there is no seccomp,
    filesystem namespace or network isolation claim.
    """
    normalized_files = {}
    for name, source in files.items():
        if type(source) is not str or len(source.encode()) > 16_384 or not source.isascii():
            raise ValueError("E_UPGRADE_RUST_SOURCE")
        if any(c in source for c in ('#', '"', "'", '`', '\\', '[', ']')):
            raise ValueError("E_UPGRADE_RUST_FORBIDDEN_SYNTAX")
        if any(comment in source for comment in ("//", "/*", "*/")):
            raise ValueError("E_UPGRADE_RUST_COMMENT_OUTSIDE_PROFILE")
        if ".." in source:
            raise ValueError("E_UPGRADE_RUST_RANGE_OUTSIDE_PROFILE")
        if re.search(r"\b(provider_call|maximum_u64)\b", source):
            raise ValueError("E_UPGRADE_RUST_RESERVED_IDENTIFIER")
        # Explicit generic types are limited to Option of one primitive.
        # Inferred checked-integer Option values remain usable; prelude owned
        # containers cannot materialize through unwrap_or_default.
        scalar_type = r"(?:bool|[ui](?:8|16|32|64|128)|usize|isize)"
        type_checked = re.sub(r"\bOption\s*<\s*" + scalar_type + r"\s*>", "", source)
        capitals = re.findall(r"\b[A-Z][A-Za-z_0-9]*\b", type_checked)
        if any(name not in {"Some", "None", "MAX"} for name in capitals):
            raise ValueError("E_UPGRADE_RUST_TYPE_OUTSIDE_PROFILE")
        if re.search(r"\b[A-Za-z_][A-Za-z_0-9]*\s*!\s*[({]", source):
            raise ValueError("E_UPGRADE_RUST_MACRO")
        if re.search(r"\b(unsafe|extern|mod|struct|enum|impl|trait|static|const|type|async|await|loop|while|for|match|move|dyn|std|core|alloc|super)\b", source):
            raise ValueError("E_UPGRADE_RUST_NOT_PURE_SCALAR")
        if len(re.findall(r"\bfn\b", source)) != 1 or source.count("{") > 12:
            raise ValueError("E_UPGRADE_RUST_FUNCTION_COUNT")
        normalized = re.sub(r"\s*::\s*", "::", source)
        remainder, imports = re.subn(r"\buse\s+crate::api\s*;", "", normalized)
        if imports != (1 if name == "client.rs" else 0) or re.search(r"\b(use|crate)\b", remainder):
            raise ValueError("E_UPGRADE_RUST_IMPORT")
        provider_path = "api::" + task["provider"]
        without_paths = re.sub(r"\b" + re.escape(provider_path) + r"\b", "provider_call", remainder)
        without_paths = re.sub(r"\bu64::MAX\b", "maximum_u64", without_paths)
        if "::" in without_paths:
            # Includes leading paths, qualified chains, turbofish and trait
            # paths: a partial ident::ident match is never enough to admit it.
            raise ValueError("E_UPGRADE_RUST_EXTERNAL_PATH")
        provider_calls = len(re.findall(r"\b" + re.escape(provider_path) + r"\s*\(", remainder))
        provider_mentions = len(re.findall(r"\b" + re.escape(provider_path) + r"\b", remainder))
        if provider_calls != provider_mentions or provider_calls != (1 if name == "client.rs" else 0):
            raise ValueError("E_UPGRADE_PROVIDER_CALL_COUNT")
        if re.search(r"[)}]\s*\(|\.\s*[0-9]+\s*\(", remainder):
            raise ValueError("E_UPGRADE_RUST_CALLABLE_VALUE")
        for call in re.finditer(r"\b([A-Za-z_][A-Za-z_0-9]*)\s*\(", without_paths):
            word, prefix = call[1], without_paths[:call.start()].rstrip()
            if re.search(r"\bfn$", prefix):
                continue
            if prefix.endswith("."):
                if word not in RUST_SCALAR_METHODS:
                    raise ValueError("E_UPGRADE_RUST_METHOD_OUTSIDE_PROFILE")
            elif word not in {"provider_call", "if", "return", "let", "Some"}:
                raise ValueError("E_UPGRADE_RUST_CALL_OUTSIDE_PROFILE")
        normalized_files[name] = normalized
    if enforce_contract:
        compact = re.sub(r"\s+", "", normalized_files["api.rs"])
        params = ",".join(n + ":" + typ for n, typ in task["provider_params"])
        returns = task["provider_returns"][0] if len(task["provider_returns"]) == 1 else "(" + ",".join(task["provider_returns"]) + ")"
        if not compact.startswith("pubfn" + task["provider"] + "(" + params + ")->" + returns + "{"):
            raise ValueError("E_UPGRADE_PROVIDER_INTERFACE")
        expected = task["original_hia"]["client.hia.json"]
        public_params = ",".join(p["name"] + ":" + p["type"] for p in expected["params"])
        client = re.sub(r"\s+", "", normalized_files["client.rs"]).replace("usecrate::api;", "")
        if not client.startswith("pubfnentrypoint(" + public_params + ")->u64{"):
            raise ValueError("E_UPGRADE_PUBLIC_INTERFACE")


def parse_files(task, language, text, *, enforce_contract=True):
    if type(text) is not str or len(text.encode()) > 64 * 1024:
        raise ValueError("E_UPGRADE_RESPONSE_SIZE")
    response = decode_json(text)
    if type(response) is not dict or set(response) != {"files"} or type(response["files"]) is not dict:
        raise ValueError("E_UPGRADE_RESPONSE_FIELDS")
    files = response["files"]
    if set(files) != set(FILE_NAMES[language]):
        raise ValueError("E_UPGRADE_WORKSPACE_FILES")
    if language == "rust":
        rust_safety_check(task, files, enforce_contract)
        return copy.deepcopy(files), None
    original = verify_program(document(task, task["original_hia"]))
    if any(type(files[name]) is not dict for name in FILE_NAMES[language]):
        raise ValueError("E_UPGRADE_HIA_FUNCTION_OBJECT")
    candidate, receipt = apply_program_patch(original, {"schema": "hepta.hia.patch.v2",
        "expected_sha256": original.sha256, "interface_policy": "migrate",
        "edits": [{"action": "replace_function", "function": task["provider"], "definition": files["api.hia.json"]},
                  {"action": "replace_function", "function": "entrypoint", "definition": files["client.hia.json"]}]})
    definition = candidate.as_dict()
    provider, consumer = definition["functions"]
    expected_consumer = task["original_hia"]["client.hia.json"]
    if consumer["params"] != expected_consumer["params"] or consumer["returns"] != ["u64"]:
        raise ValueError("E_UPGRADE_PUBLIC_INTERFACE")
    calls = []
    for fn in definition["functions"]:
        if set(fn["effects"]) - {"trap"}:
            raise ValueError("E_UPGRADE_HIA_EFFECT")
        for block in fn["blocks"]:
            for operation in block["ops"]:
                kind = operation["op"]
                if not (kind in {"const", "select", "call", "int.cast"} or kind.startswith(("int.", "bit.", "compare."))):
                    raise ValueError("E_UPGRADE_HIA_NONSCALAR")
                if kind == "call":
                    calls.append((fn["name"], operation["attrs"]["function"]))
    if calls != [("entrypoint", task["provider"])]:
        raise ValueError("E_UPGRADE_PROVIDER_CALL_COUNT")
    if enforce_contract and ([[p["name"], p["type"]] for p in provider["params"]] != task["provider_params"]
                             or provider["returns"] != task["provider_returns"]):
        raise ValueError("E_UPGRADE_PROVIDER_INTERFACE")
    return candidate, receipt


C_DRIVER = '''#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
extern uint64_t entrypoint(uint32_t,uint32_t,uint32_t);
int main(void) { uint32_t x,y,z; setbuf(stdout,0); while(scanf("%" SCNu32 " %" SCNu32 " %" SCNu32,&x,&y,&z)==3) printf("%" PRIu64 "\\n",entrypoint(x,y,z)); return 0; }
'''
RUST_DRIVER = '''#![forbid(unsafe_code)]
mod api;
mod client;
use std::io::{self,BufRead};
fn main() { let entry:fn(u32,u32,u32)->u64 = client::entrypoint; for line in io::stdin().lock().lines() { let line=line.unwrap(); let v:Vec<u32>=line.split_whitespace().map(|s|s.parse().unwrap()).collect(); println!("{}",entry(v[0],v[1],v[2])); } }
'''


def provider_arguments(task_id, case):
    return [case[1]] if task_id == "wire_length_v2" else list(case)


def provider_expected(task_id, case):
    return case[1] if task_id == "wire_length_v2" else oracle(task_id, case)


def provider_value(task_id, values):
    if task_id == "wire_length_v2":
        return values[0]
    return values[1] if values[0] else MAX64


def rust_audit_driver(task):
    """Trusted native wrapper observes calls; the submitted files stay exact."""
    name = task["provider"]
    if task["id"] == "wire_length_v2":
        signature, arguments = "(length:u32)->u64", "length"
        observed_args = "length as u64 != ARG0.load(Ordering::SeqCst)"
        expected_args = "v[1],0,0"
        direct = "api_original::wire_length(v[1])"
    elif task["id"] == "bounded_window_v2":
        signature, arguments = "(offset:u32,amount:u32,capacity:u32)->(bool,u32)", "offset,amount,capacity"
        observed_args = "offset as u64 != ARG0.load(Ordering::SeqCst) || amount as u64 != ARG1.load(Ordering::SeqCst) || capacity as u64 != ARG2.load(Ordering::SeqCst)"
        expected_args = "v[0],v[1],v[2]"
        direct = "{ let (valid,end)=api_original::advance(v[0],v[1],v[2]); if valid {end as u64} else {u64::MAX} }"
    else:
        raise ValueError("unknown provider contract")
    return f'''#![forbid(unsafe_code)]
#[path="api.rs"]
mod api_original;
mod api {{
    use std::sync::atomic::{{AtomicU64,Ordering}};
    static CALLS:AtomicU64=AtomicU64::new(0);
    static ARG0:AtomicU64=AtomicU64::new(0);
    static ARG1:AtomicU64=AtomicU64::new(0);
    static ARG2:AtomicU64=AtomicU64::new(0);
    static BAD_ARGS:AtomicU64=AtomicU64::new(0);
    pub fn reset(a:u32,b:u32,c:u32) {{
        CALLS.store(0,Ordering::SeqCst); BAD_ARGS.store(0,Ordering::SeqCst);
        ARG0.store(a as u64,Ordering::SeqCst); ARG1.store(b as u64,Ordering::SeqCst); ARG2.store(c as u64,Ordering::SeqCst);
    }}
    pub fn count()->u64 {{ CALLS.load(Ordering::SeqCst) }}
    pub fn arguments_match()->u64 {{ if BAD_ARGS.load(Ordering::SeqCst)==0 {{1}} else {{0}} }}
    pub fn {name}{signature} {{
        CALLS.fetch_add(1,Ordering::SeqCst);
        if {observed_args} {{ BAD_ARGS.store(1,Ordering::SeqCst); }}
        super::api_original::{name}({arguments})
    }}
}}
mod client;
use std::io::{{self,BufRead}};
fn main() {{
    let entry:fn(u32,u32,u32)->u64=client::entrypoint;
    for line in io::stdin().lock().lines() {{
        let line=line.unwrap();
        let v:Vec<u32>=line.split_whitespace().map(|s|s.parse().unwrap()).collect();
        api::reset({expected_args});
        let answer=entry(v[0],v[1],v[2]);
        let calls=api::count();
        let provider={direct};
        println!("{{}} {{}} {{}} {{}}",answer,provider,calls,api::arguments_match());
    }}
}}
'''


def hia_provider_audit(built, cases):
    """Observe actual calls in the same hashed Core VM, not native callbacks."""
    from hepta.hia_program import scalar_value_valid
    from hepta.hia_program_runtime import _Machine, HIAProgramTrap, HIAProgramBudgetExceeded
    data = Path(built["core_path"]).read_bytes()
    checked = verify_program(data)
    if checked.sha256 != built["core_sha256"]:
        raise RuntimeError("provider observer Core differs from the native build")
    task_id, provider = built["audit_task"], built["audit_provider"]

    class ObservedMachine(_Machine):
        def __init__(self):
            super().__init__(checked, 10_000, 0, None, 16)
            self.calls = []

        def invoke(self, fn, arguments, depth=0):
            event = {"function": fn["name"], "arguments": list(arguments),
                     "depth": depth, "returned": False}
            self.calls.append(event)
            values = super().invoke(fn, arguments, depth)
            event.update(returned=True, values=list(values))
            return values

    def observe(function, arguments):
        machine = ObservedMachine()
        fn = machine.functions[function]
        if len(arguments) != len(fn["params"]) or any(
                not scalar_value_valid(value, param["type"])
                for value, param in zip(arguments, fn["params"])):
            raise RuntimeError("invalid typed provider-observation arguments")
        try:
            values = machine.invoke(fn, list(arguments))
            if machine.owners or machine.chains or machine.loans_started != machine.loans_ended:
                raise RuntimeError("scalar provider observation retained a resource")
            result = machine.report(function, "returned", values)
        except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
            result = machine.report(function, "budget_exceeded" if isinstance(error, HIAProgramBudgetExceeded) else "trapped",
                                    error=error)
        result["calls"] = machine.calls
        return result

    rows = []
    for case in cases:
        entry = observe("entrypoint", case)
        direct = observe(provider, provider_arguments(task_id, case))
        calls = [call for call in entry["calls"] if call["function"] == provider]
        rows.append({"case": list(case), "entry_vm": entry, "provider_vm": direct,
                     "provider_calls_in_entry": len(calls),
                     "provider_arguments_match": len(calls) == 1 and calls[0]["arguments"] == provider_arguments(task_id, case),
                     "provider_result": provider_value(task_id, direct["values"]) if direct["status"] == "returned" else None})
    if verify_program(Path(built["core_path"]).read_bytes()).sha256 != built["core_sha256"]:
        raise RuntimeError("provider-observation Core changed during execution")
    return rows


def build(task, language, text, directory, clang, rustc, *, enforce_contract=True):
    folder = Path(directory); folder.mkdir(parents=True, exist_ok=False)
    start = time.monotonic_ns()
    record = {"status": "response_rejected", "native_built": False, "directory": str(folder),
              "language": language, "provider_audit": enforce_contract,
              "audit_task": task["id"], "audit_provider": task["provider"]}
    try:
        parsed, receipt = parse_files(task, language, text, enforce_contract=enforce_contract)
        record["patch_receipt"] = receipt
        record["status"] = "infrastructure_failure"
        compiler = file_identity(clang if language == "hia" else rustc)
        record["compiler_before"] = compiler
        binary = folder / "candidate"
        if language == "hia":
            (folder / "program.hia").write_bytes(parsed.canonical_bytes)
            record.update(core_path=str(folder / "program.hia"), core_sha256=parsed.sha256)
            record["native_receipt"] = build_program_native(parsed, folder / "program.o", clang=clang, kind="object")
            (folder / "driver.c").write_text(C_DRIVER)
            argv = [clang, "-O2", str(folder / "driver.c"), str(folder / "program.o"), "-o", str(binary)]
        else:
            for name, source in parsed.items():
                (folder / name).write_text(source)
            (folder / "main.rs").write_text(rust_audit_driver(task) if enforce_contract else RUST_DRIVER)
            argv = [rustc, "--edition=2021", "-Copt-level=2", "-Coverflow-checks=on", str(folder / "main.rs"), "-o", str(binary)]
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=45)
        record["compile"] = {"argv": argv, "returncode": completed.returncode,
                             "stdout": completed.stdout, "stderr": completed.stderr}
        record["status"] = "compiled" if completed.returncode == 0 else "compile_rejected"
        if completed.returncode == 0:
            record["artifact"] = file_identity(binary)
            record["native_built"] = True
        record["compiler_unchanged"] = file_identity(compiler["path"]) == compiler
        if not record["compiler_unchanged"]:
            record.update(status="infrastructure_failure", native_built=False)
    except subprocess.TimeoutExpired as error:
        record.update(status="infrastructure_failure", error=str(error),
                      partial_stdout=(error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes) else error.stdout,
                      partial_stderr=(error.stderr or b"").decode(errors="replace") if isinstance(error.stderr, bytes) else error.stderr)
    except Exception as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)}
    record["wall_ns"] = time.monotonic_ns() - start
    save(folder / "BUILD.json", record)
    return record


def execute(built, cases, expected):
    if not built["native_built"]:
        raise ValueError("unbuilt upgrade candidate")
    before = built["artifact"]
    data = Path(before["path"]).read_bytes()
    if hashlib.sha256(data).hexdigest() != before["sha256"]:
        raise ValueError("upgrade artifact drift")
    descriptor = os.memfd_create("hepta-upgrade-candidate", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(data)
        os.fchmod(descriptor, 0o500)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        start = time.monotonic_ns()
        payload = "".join(" ".join(map(str, row)) + "\n" for row in cases)
        try:
            result = subprocess.run([f"/proc/self/fd/{descriptor}"], input=payload, text=True,
                                    capture_output=True, timeout=5, pass_fds=(descriptor,), preexec_fn=limits)
        except subprocess.TimeoutExpired as error:
            def text(value):
                return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            return {"status": "observable_timeout", "returncode": None, "stdout": text(error.stdout),
                    "stderr": text(error.stderr), "actual": None, "expected": expected, "cases": cases,
                    "wall_ns": time.monotonic_ns() - start, "artifact_sha256": before["sha256"],
                    "sealed_image": True, "artifact_unchanged": file_identity(before["path"]) == before}
        elapsed = time.monotonic_ns() - start
        native_provider, call_counts, arguments_match = None, None, None
        try:
            if built.get("provider_audit") and built["language"] == "rust":
                matrix = [[int(word) for word in line.split()] for line in result.stdout.splitlines()]
                if any(len(row) != 4 or any(not 0 <= item <= MAX64 for item in row) for row in matrix):
                    raise ValueError("invalid native provider observation")
                values, native_provider, call_counts, arguments_match = ([row[index] for row in matrix] for index in range(4))
            else:
                values = [int(line) for line in result.stdout.splitlines()]
        except ValueError:
            values = None
        observed = {"status": "correct" if result.returncode == 0 and values == expected else "observable_wrong",
                "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                "actual": values, "expected": expected, "cases": cases, "wall_ns": elapsed,
                "artifact_sha256": before["sha256"], "sealed_image": True,
                "seals": fcntl.fcntl(descriptor, fcntl.F_GET_SEALS),
                "artifact_unchanged": file_identity(before["path"]) == before}
        if built.get("provider_audit"):
            audit_started = time.monotonic_ns()
            provider_wanted = [provider_expected(built["audit_task"], case) for case in cases]
            agreement = True
            if built["language"] == "hia":
                rows = hia_provider_audit(built, cases)
                native_provider = [row["provider_result"] for row in rows]
                call_counts = [row["provider_calls_in_entry"] for row in rows]
                arguments_match = [int(row["provider_arguments_match"]) for row in rows]
                agreement = values == [row["entry_vm"].get("result") for row in rows]
                observed.update(vm_provider_observations=rows,
                    provider_observation_kind="same-hashed-Core VM invokes; not a native call counter",
                    native_vm_entry_agreement=agreement)
            else:
                observed["provider_observation_kind"] = "actual native trusted API wrapper counter and direct provider call"
            contract_passed = native_provider == provider_wanted
            calls_passed = call_counts == [1] * len(cases)
            arguments_passed = arguments_match == [1] * len(cases)
            observed.update(provider_actual=native_provider, provider_expected=provider_wanted,
                provider_call_counts=call_counts, provider_contract_passed=contract_passed,
                provider_call_count_passed=calls_passed, provider_arguments_match=arguments_match,
                provider_arguments_passed=arguments_passed, provider_audit_wall_ns=time.monotonic_ns() - audit_started)
            if not contract_passed or not calls_passed or not arguments_passed or not agreement:
                observed["status"] = "observable_wrong"
        return observed
    finally:
        os.close(descriptor)


def controls(output, clang, rustc):
    root = Path(output); root.mkdir(parents=True, exist_ok=False)
    rows = []
    for task in fixtures():
        for language in ("hia", "rust"):
            names = FILE_NAMES[language]
            for mask in range(4):
                files = {name: task[("correct_" if mask & (1 << i) else "original_") + language][name]
                         for i, name in enumerate(names)}
                label = task["id"] + "_" + language + "_mask" + str(mask)
                built = build(task, language, canonical({"files": files}).decode(), root / label,
                              clang, rustc, enforce_contract=False)
                observed = execute(built, task["hidden_cases"], task["hidden_expected"]) if built["native_built"] else None
                passed = (built["native_built"] and observed["status"] == ("correct" if mask == 3 else "observable_wrong")) if mask in (0, 3) else (not built["native_built"] and built["status"] in {"response_rejected", "compile_rejected"})
                rows.append({"id": label, "mask": mask, "build": built, "execution": observed, "passed": bool(passed),
                             "scope": "trusted control; task API admission deliberately disabled to expose native partial migrations"})
    result = {"schema": PROTOCOL + ".controls", "count": len(rows), "passed": sum(row["passed"] for row in rows), "rows": rows}
    save(root / "CONTROLS.json", result)
    return result


def bindings():
    result = base_bindings()
    for path in sorted(Path(__file__).parent.glob("*.py")):
        result[str(path.relative_to(ROOT))] = file_identity(path)["sha256"]
    for name in ("PROTOCOL.json", "FIXTURES.json", "REGISTRATION.json"):
        path = Path(__file__).with_name(name)
        if path.exists():
            result[str(path.relative_to(ROOT))] = file_identity(path)["sha256"]
    return result


def public_feedback(build_record, observed):
    # The model receives only its compilation diagnostic and public smoke
    # results. Hidden cases/values never reach this function.
    result = {"compile_status": build_record["status"]}
    if "compile" in build_record:
        result["compiler_stderr"] = build_record["compile"]["stderr"][:8192]
    if "error" in build_record:
        result["diagnostic"] = build_record["error"]
    if observed is not None:
        result["public_smoke"] = {k: observed.get(k) for k in ("status", "cases", "actual", "expected", "returncode",
            "provider_actual", "provider_expected", "provider_call_counts", "provider_contract_passed", "provider_call_count_passed", "provider_arguments_passed")}
    return result


def run_model(output, *, model, binary, clang, rustc, model_index):
    root = Path(output).absolute(); root.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    tasks = fixtures()
    initial = bindings()
    tool_identities = {name: file_identity(path) for name, path in (("binary", binary), ("clang", clang), ("rustc", rustc))}
    order = []
    for index, task in enumerate(tasks):
        languages = ("hia", "rust") if (index + model_index) % 2 == 0 else ("rust", "hia")
        order.extend({"id": task["id"] + "_" + language, "task": task["id"], "language": language}
                     for language in languages)
    plan = {"schema": PROTOCOL, "model": model, "source_bindings": initial, "tools": tool_identities,
            "tasks": tasks, "scheduled_cells": order, "attempts_per_cell": ATTEMPTS,
            "max_new_tokens_per_attempt": LIMIT, "threads": 4, "seed": 0, "greedy": True,
            "feedback": "compilation and three public smoke cases only; hidden tests evaluated once after final public success",
            "response_transport": "complete two-file JSON replacement; host-bound HIA patch.v2 migrate or real Rust compilation",
            "provider_contract": "same frozen inputs check provider directly and entrypoint; actual Rust wrapper count, same-Core HIA VM dynamic-call observation; HIA native output still required",
            "native_loading": "sealed memfd executable; 2-second CPU and 256-MiB address-space ceilings",
            "execution_isolation": {"finite_scalar_admission": True, "general_rust_sandbox": False, "seccomp": False, "filesystem_namespace": False, "network_namespace": False},
            "manual_time_ns": None, "task_scope": "two finite interface migrations, not arbitrary module upgrade safety"}
    save(root / "PLAN.json", plan)
    for name, expected in initial.items():
        data = (ROOT / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("upgrade source drift while freezing")
        target = root / "source_snapshot" / name; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    report = {"schema": PROTOCOL, "status": "incomplete", "planned_cells": order, "cells": [],
              "manual_time_ns": None, "new_model_requests": 0, "responses_received": 0,
              "claims": {"general_upgrade_productivity": False, "human_labor_measured": False,
                         "unseen_external_callers_verified": False, "model_outputs_repaired_by_human": False}}
    engine = None
    try:
        controls_started = time.monotonic_ns()
        control = controls(root / "controls", clang, rustc)
        report["controls_wall_ns"] = time.monotonic_ns() - controls_started
        report["controls"] = {"passed": control["passed"], "count": control["count"]}
        if control["passed"] != 16:
            raise RuntimeError("upgrade native controls failed")
        if bindings() != initial:
            raise RuntimeError("upgrade source changed before inference")
        engine = LlamaCppEngine(binary=binary, model=model["path"], model_sha256=model["sha256"],
                                output_dir=root / "engine", threads=4, json_object=True)
        by_id = {task["id"]: task for task in tasks}
        for cell in order:
            task, language = by_id[cell["task"]], cell["language"]
            folder = root / cell["id"]; folder.mkdir()
            row = {**cell, "attempts": [], "status": "incomplete", "correct": False,
                   "hidden_tests_evaluated": False, "human_repair_rounds": 0, "manual_time_ns": None}
            report["cells"].append(row)
            messages = [{"role": "user", "content": prompt(task, language)}]
            final_build = None
            for index in range(ATTEMPTS):
                if bindings() != initial:
                    raise RuntimeError("upgrade source drift before model request")
                attempt = {"index": index, "status": "inference_started"}
                row["attempts"].append(attempt)
                save(folder / f"attempt-{index}.request.json", {"messages": messages, "limit": LIMIT})
                response = engine.generate(messages, limit=LIMIT, wall_seconds=180)
                save(folder / f"attempt-{index}.response.json", response)
                attempt.update(usage=response["usage"], inference_ns=response["wall_nanoseconds"])
                evaluation_started = time.monotonic_ns()
                built = build(task, language, response["text"], folder / f"attempt-{index}.candidate", clang, rustc)
                observed = execute(built, task["public_cases"], task["public_expected"]) if built["native_built"] else None
                attempt.update(build=built, public_validation=observed,
                               evaluation_ns=time.monotonic_ns() - evaluation_started,
                               status="public_passed" if observed and observed["status"] == "correct" else built["status"] if not built["native_built"] else observed["status"])
                save(folder / f"attempt-{index}.evaluation.json", attempt)
                if built["status"] == "infrastructure_failure" or (observed is not None and not observed["artifact_unchanged"]):
                    raise RuntimeError("upgrade native infrastructure/identity failure")
                if observed is not None and observed["status"] == "correct":
                    final_build = built
                    break
                row["status"] = "public_validation_failed"
                if index + 1 < ATTEMPTS:
                    messages.extend([{"role": "assistant", "content": response["text"]},
                        {"role": "user", "content": "The submitted upgrade failed compilation or public validation. Submit both complete replacement files again within the same interface contract. Hidden tests have not run.\n" + canonical(public_feedback(built, observed)).decode()}])
            if final_build is not None:
                hidden_started = time.monotonic_ns()
                hidden = execute(final_build, task["hidden_cases"], task["hidden_expected"])
                if not hidden["artifact_unchanged"]:
                    raise RuntimeError("upgrade native artifact changed during hidden validation")
                row.update(hidden_tests_evaluated=True, hidden_validation=hidden,
                           hidden_validation_ns=time.monotonic_ns() - hidden_started,
                           correct=hidden["status"] == "correct" and hidden["artifact_unchanged"],
                           status="correct" if hidden["status"] == "correct" else "hidden_validation_failed")
            row["automatic_repair_rounds"] = max(0, len(row["attempts"]) - 1)
            row["input_tokens"] = sum(item["usage"]["input_tokens"] for item in row["attempts"])
            row["output_tokens"] = sum(item["usage"]["output_tokens"] for item in row["attempts"])
            save(folder / "CELL.json", row)
            print(json.dumps({"upgrade": cell["id"], "model": model["id"], "status": row["status"],
                              "attempts": len(row["attempts"]), "tokens": row["input_tokens"] + row["output_tokens"]}), flush=True)
        report["status"] = "completed"
    except Exception as error:
        report["diagnostic"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if engine is not None:
            report["new_model_requests"] = engine.generation_count
            report["responses_received"] = engine.response_count
            try:
                report["model_and_runtime_identity"] = engine.verify_final_identity()
            except Exception as error:
                report.update(status="incomplete", identity_error=str(error))
            try:
                engine.close()
            except Exception as error:
                report.update(status="incomplete", shutdown_error=str(error))
        report["source_unchanged"] = bindings() == initial
        report["tools_unchanged"] = all(file_identity(path) == tool_identities[name]
            for name, path in (("binary", binary), ("clang", clang), ("rustc", rustc)))
        identities = report.get("model_and_runtime_identity", {})
        report["complete"] = (report["status"] == "completed" and len(report["cells"]) == 4
            and report["source_unchanged"] and report["tools_unchanged"]
            and identities.get("model_unchanged") is True and identities.get("runtime_unchanged") is True
            and report["new_model_requests"] == report["responses_received"])
        if not report["complete"]:
            report["status"] = "incomplete"
        report["summary"] = {}
        for language in ("hia", "rust"):
            rows = [row for row in report["cells"] if row["language"] == language]
            attempts = [attempt for row in rows for attempt in row["attempts"]]
            usage_complete = all("usage" in attempt for attempt in attempts) and len(rows) == 2
            inputs = sum(attempt.get("usage", {}).get("input_tokens", 0) for attempt in attempts)
            outputs = sum(attempt.get("usage", {}).get("output_tokens", 0) for attempt in attempts)
            successes = sum(row["correct"] for row in rows)
            report["summary"][language] = {"planned_tasks": 2, "attempted_tasks": len(rows), "successes": successes,
                "attempts": len(attempts), "input_tokens": inputs, "output_tokens": outputs, "usage_complete": usage_complete,
                "tokens_per_successful_upgrade": (inputs + outputs) / successes if successes and usage_complete else None,
                "inference_ns": sum(a.get("inference_ns", 0) for a in attempts),
                "native_validation_ns": sum(a.get("evaluation_ns", 0) for a in attempts) + sum(row.get("hidden_validation_ns", 0) for row in rows),
                "automatic_repair_rounds": sum(row.get("automatic_repair_rounds", 0) for row in rows), "manual_time_ns": None}
        report["experiment_wall_ns"] = time.monotonic_ns() - started
        save(root / "RESULT.json", report)
    return report
