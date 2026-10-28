"""Fresh generated-source tasks; references are controls, never model input."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from hepta.hia_program import verify_program
from tools.provider_adapter.llama_cpp_engine import canonical

HERE = Path(__file__).resolve().parent
PARAMS = [("a", "u32"), ("b", "u32"), ("c", "u32")]
EDITABLE = {"hia": ("api.hia.json", "client.hia.json"), "rust": ("api.rs", "client.rs")}
MAX32 = 2**32 - 1


def op(kind, args, output=None, typ="u32", **attrs):
    if kind == "int.cast":
        attrs.setdefault("mode", "wrap")
    return {"op": kind, "args": args, "out": [] if output is None else [{"name": output, "type": typ}], "attrs": attrs}


def fn(name, params, returns, operations, values, effects=()):
    ps = [{"name": n, "type": t} for n, t in params]
    return {"name": name, "params": ps, "returns": list(returns), "effects": list(effects), "entry": "entry",
            "blocks": [{"id": "entry", "params": copy.deepcopy(ps), "ops": operations,
                        "term": {"op": "ret", "values": values}}]}


def call(name, args, outputs):
    return {"op": "call", "args": args, "out": [{"name": n, "type": t} for n, t in outputs], "attrs": {"function": name}}


def basic_client(provider, *, upgraded=True, corrected=True, probe=False):
    operations = []
    args = ["a", "b"]
    if provider == "span" and not upgraded:
        operations += [op("int.cast", ["a"], "a16", "u16"), op("int.cast", ["b"], "b16", "u16")]
        args = ["a16", "b16"]
    ret = "u64" if provider == "span" and upgraded else "u32"
    operations += [call(provider, args, [("value", ret)]), op("int.cast", ["value"], "wide", "u64")]
    if probe:
        return fn("provider_probe", PARAMS, ["u64"], operations, ["wide"])
    operations += [op("const", [], "mask", value=7 if corrected or provider == "span" else 3),
                   op("bit.and", ["c", "mask"], "tag"), op("int.cast", ["tag"], "tag64", "u64")]
    if provider == "saturating_sum":
        operations += [op("const", [], "weight", "u64", value=7),
                       op("int.mul.wrap", ["wide", "weight"], "weighted", "u64"),
                       op("int.add.wrap", ["weighted", "tag64"], "answer", "u64")]
    else:
        operations += [op("const", [], "shift", "u64", value=48 if corrected else 24),
                       op("int.shl.checked", ["tag64", "shift"], "tagged", "u64"),
                       op("bit.xor", ["wide", "tagged"], "answer", "u64")]
    return fn("entrypoint", PARAMS, ["u64"], operations, ["answer"], ["trap"] if provider == "span" else [])


def owned_client(provider, *, corrected=True, probe=False):
    operations = [op("const", [], "mask", value=7), op("const", [], "one", value=1),
        op("bit.and", ["a", "mask"], "len0"), op("int.add.wrap", ["len0", "one"], "len32"),
        op("int.cast", ["len32"], "size", "usize"), op("buffer.new", ["size"], "left", "buffer")]
    if provider == "touch":
        operations += [op("int.cast", ["b"], "byte", "u8"), call("touch", ["left", "byte"], [("returned", "buffer")]),
            op("borrow.read", ["returned"], "view", "readbuf"), op("const", [], "zero", "usize", value=0),
            op("buffer.load", ["view", "zero"], "value", "u8"), op("loan.end", ["view"]),
            op("buffer.len", ["returned"], "length", "usize"), op("owner.drop", ["returned"]),
            op("int.cast", ["value"], "byte64", "u64"), op("int.cast", ["length"], "len64", "u64"),
            op("const", [], "len_weight", "u64", value=4096),
            op("int.mul.wrap", ["len64", "len_weight"], "len_part", "u64"),
            op("int.add.wrap", ["byte64", "len_part"], "base", "u64")]
        if not probe:
            operations += [op("const", [], "tag_mask", value=7 if corrected else 3),
                op("bit.and", ["c", "tag_mask"], "tag"), op("int.cast", ["tag"], "tag64", "u64"),
                op("const", [], "tag_weight", "u64", value=256),
                op("int.mul.wrap", ["tag64", "tag_weight"], "tag_part", "u64"),
                op("int.add.wrap", ["base", "tag_part"], "answer", "u64")]
    else:
        operations += [op("bit.and", ["b", "mask"], "r0"), op("int.add.wrap", ["r0", "one"], "r32"),
            op("int.cast", ["r32"], "rsize", "usize"), op("buffer.new", ["rsize"], "right", "buffer"),
            op("bit.and", ["c", "mask"], "n0"), op("int.add.wrap", ["n0", "one"], "n32"),
            op("int.cast", ["n32"], "n", "usize"), call("replace", ["left", "n"], [("returned", "buffer")]),
            op("buffer.len", ["returned"], "length", "usize"), op("buffer.len", ["right"], "rlen", "usize"),
            op("owner.drop", ["returned"]), op("owner.drop", ["right"]),
            op("int.cast", ["length"], "len64", "u64"), op("int.cast", ["rlen"], "r64", "u64"),
            op("const", [], "weight", "u64", value=16 if corrected or probe else 8),
            op("int.mul.wrap", ["len64", "weight"], "weighted", "u64"),
            op("int.add.wrap", ["weighted", "r64"], "base", "u64")]
    return fn("provider_probe" if probe else "entrypoint", PARAMS, ["u64"], operations,
              ["base" if probe or provider == "replace" else "answer"], ["alloc", "read", "write", "trap"])


def oracle(task_id, case):
    a, b, c = case
    if task_id == "saturating_score":
        p = min(a + b, MAX32)
        return p * 7 + (c & 7), p
    if task_id == "wide_span_upgrade":
        p = a + 3 * b
        return p ^ ((c & 7) << 48), p
    if task_id == "owned_byte_return":
        p = ((b & 255) ^ 90) + 4096 * ((a & 7) + 1)
        return p + 256 * (c & 7), p
    if task_id == "owner_pair_replace":
        p = (((c & 7) + 2) * 16) + ((b & 7) + 1)
        return p, p
    raise ValueError("unknown task")


def provider_arguments(task, case):
    a, b, c = case
    if task["provider"] in {"saturating_sum", "span"}:
        return [a, b]
    return [{"length": (a & 7) + 1, "first": 0}, (b & 255) if task["provider"] == "touch" else (c & 7) + 1]


def document(task, files, *, probe_contract=True):
    all_files = copy.deepcopy(task["unchanged_hia"])
    all_files.update(files)
    probe = (basic_client("span", upgraded=False, probe=True)
             if not probe_contract and task["provider"] == "span" else task["probe_hia"])
    return {"schema": "hepta.hia.program.v6", "module": task["id"], "exports": ["entrypoint", "provider_probe"],
            "functions": [all_files[n] for n in ("api.hia.json", "client.hia.json", "audit.hia.json", "utility.hia.json")] + [probe]}


def make_fixtures():
    old_sum = fn("saturating_sum", PARAMS[:2], ["u32"], [op("int.add.wrap", ["a", "b"], "answer")], ["answer"])
    good_sum = fn("saturating_sum", PARAMS[:2], ["u32"], [op("int.cast", ["a"], "a64", "u64"),
        op("int.cast", ["b"], "b64", "u64"), op("int.add.wrap", ["a64", "b64"], "sum", "u64"),
        op("const", [], "maximum", "u64", value=MAX32), op("compare.gt", ["sum", "maximum"], "large", "bool"),
        op("select", ["large", "maximum", "sum"], "bounded", "u64"), op("int.cast", ["bounded"], "answer")], ["answer"])
    def span(upgraded):
        width = "u64" if upgraded else "u32"
        return fn("span", [("a", "u32" if upgraded else "u16"), ("b", "u32" if upgraded else "u16")], [width],
            [op("int.cast", ["a"], "aw", width), op("int.cast", ["b"], "bw", width),
             op("const", [], "weight", width, value=3 if upgraded else 2),
             op("int.mul.wrap", ["bw", "weight"], "part", width), op("int.add.wrap", ["aw", "part"], "answer", width)], ["answer"])
    def touch(correct):
        ops = [op("borrow.mut", ["buf"], "view", "mutbuf"), op("const", [], "zero", "usize", value=0)]
        if correct:
            ops += [op("const", [], "mask", "u8", value=90), op("bit.xor", ["x", "mask"], "value", "u8")]
        ops += [op("buffer.store", ["view", "zero", "value" if correct else "x"]), op("loan.end", ["view"])]
        return fn("touch", [("buf", "buffer"), ("x", "u8")], ["buffer"], ops, ["buf"], ["write", "trap"])
    def replace(correct):
        ops = [op("owner.drop", ["buf"])]
        if correct:
            ops += [op("const", [], "one", "usize", value=1), op("int.add.wrap", ["n", "one"], "count", "usize")]
        ops += [op("buffer.new", ["count" if correct else "n"], "answer", "buffer")]
        return fn("replace", [("buf", "buffer"), ("n", "usize")], ["buffer"], ops, ["answer"], ["alloc", "trap"])
    utility = fn("utility", [("x", "u32")], ["u32"], [op("const", [], "mask", value=255), op("bit.and", ["x", "mask"], "answer")], ["answer"])
    audit_tag = fn("audit_tag", [("c", "u32")], ["u32"], [op("const", [], "mask", value=7), op("bit.and", ["c", "mask"], "answer")], ["answer"])
    specs = [
        ("saturating_score", "maintenance", "saturating_sum", old_sum, good_sum,
         basic_client("saturating_sum", corrected=False), basic_client("saturating_sum"),
         "Maintain the two-file score API. saturating_sum(a:u32,b:u32)->u32 returns min(a+b,4294967295), with mathematical addition. entrypoint(a:u32,b:u32,c:u32)->u64 calls it once with original a,b and returns 7*provider_result+(c AND 7). Both current files need changes; no u32 carry may be discarded.",
         "pub fn saturating_sum(a:u32,b:u32)->u32 { a.wrapping_add(b) }",
         "pub fn saturating_sum(a:u32,b:u32)->u32 { a.saturating_add(b) }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { (api::saturating_sum(a,b) as u64)*7+(c&3) as u64 }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { (api::saturating_sum(a,b) as u64)*7+(c&7) as u64 }",
         [[0, 0, 7], [MAX32, 1, 4], [13, 29, 5]]),
        ("wide_span_upgrade", "upgrade", "span", span(False), span(True),
         basic_client("span", upgraded=False, corrected=False), basic_client("span"),
         "Upgrade span(a:u16,b:u16)->u32 to span(a:u32,b:u32)->u64, now returning the mathematical value a+3*b with complete u32 operands. Update entrypoint(a:u32,b:u32,c:u32)->u64 to call span once without narrowing and XOR its result with ((c AND 7)<<48). Replace both files atomically; the old coefficient and tag placement are obsolete.",
         "pub fn span(a:u16,b:u16)->u32 { (a as u32)+2*(b as u32) }",
         "pub fn span(a:u32,b:u32)->u64 { (a as u64)+3*(b as u64) }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { (api::span(a as u16,b as u16) as u64)^(((c&7) as u64)<<24) }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::span(a,b)^(((c&7) as u64)<<48) }",
         [[0, 1, 1], [65536, 65537, 4], [MAX32, MAX32, 7]]),
        ("owned_byte_return", "ownership_return", "touch", touch(False), touch(True),
         owned_client("touch", corrected=False), owned_client("touch"),
         "Maintain owned-buffer transfer across the two files. touch(buf:buffer,x:u8)->buffer (Rust Vec<u8>) takes a nonempty zeroed owner, writes x XOR 90 to byte 0, and returns the SAME owner with unchanged length, no allocation or clone. entrypoint allocates one zeroed owner of length (a AND 7)+1, calls touch exactly once with that owner and low byte of b, reads the returned byte, releases every loan and owner, and returns byte+4096*length+256*(c AND 7). Keep both signatures. Both files need changes. At most one logical allocation; no live owners or loans on normal return.",
         "pub fn touch(mut buf:Vec<u8>,x:u8)->Vec<u8> { buf[0]=x; buf }",
         "pub fn touch(mut buf:Vec<u8>,x:u8)->Vec<u8> { buf[0]=x^90; buf }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let buf=vec![0u8;((a&7)+1) as usize]; let out=api::touch(buf,b as u8); let value=(out[0] as u64)+4096*(out.len() as u64)+256*((c&3) as u64); drop(out); value }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let buf=vec![0u8;((a&7)+1) as usize]; let out=api::touch(buf,b as u8); let value=(out[0] as u64)+4096*(out.len() as u64)+256*((c&7) as u64); drop(out); value }",
         [[0, 0, 7], [7, 255, 4], [3, 300, 5]]),
        ("owner_pair_replace", "ownership_replacement", "replace", replace(False), replace(True),
         owned_client("replace", corrected=False), owned_client("replace"),
         "Maintain replacement while two owners are live. replace(buf:buffer,n:usize)->buffer (Rust Vec<u8>) must consume/drop the input BEFORE allocating a fresh zeroed owner of length n+1. entrypoint creates left length (a AND 7)+1 and right length (b AND 7)+1, calls replace once on left with n=(c AND 7)+1, keeps right alive across that call, and returns 16*returned_length+right_length after releasing both owners and all loans. Keep both signatures; both files need changes. Three logical allocations and frees, zero live bytes/owners at return, peak <=17 bytes in these cases. No clone or in-place resize.",
         "pub fn replace(buf:Vec<u8>,n:usize)->Vec<u8> { drop(buf); vec![0u8;n] }",
         "pub fn replace(buf:Vec<u8>,n:usize)->Vec<u8> { drop(buf); vec![0u8;n+1] }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let left=vec![0u8;((a&7)+1) as usize]; let right=vec![0u8;((b&7)+1) as usize]; let out=api::replace(left,((c&7)+1) as usize); let value=8*(out.len() as u64)+(right.len() as u64); drop(out); drop(right); value }",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let left=vec![0u8;((a&7)+1) as usize]; let right=vec![0u8;((b&7)+1) as usize]; let out=api::replace(left,((c&7)+1) as usize); let value=16*(out.len() as u64)+(right.len() as u64); drop(out); drop(right); value }",
         [[0, 0, 0], [7, 7, 7], [2, 5, 3]])]
    tasks = []
    state = json.loads((HERE / "PROTOCOL.json").read_text())["hidden_seed"]
    for ident, category, name, old, good, client_old, client_good, spec, r_old, r_good, c_old, c_good, public in specs:
        audit = basic_client(name, probe=True) if name in {"saturating_sum", "span"} else owned_client(name, probe=True)
        if name in {"saturating_sum", "span"}:
            r_audit = f"use crate::api; pub fn provider_probe(a:u32,b:u32,c:u32)->u64 {{ let _=c; api::{name}(a,b) as u64 }}"
        elif name == "touch":
            r_audit = "use crate::api; pub fn provider_probe(a:u32,b:u32,c:u32)->u64 { let _=c; let buf=vec![0u8;((a&7)+1) as usize]; let out=api::touch(buf,b as u8); let value=(out[0] as u64)+4096*(out.len() as u64); drop(out); value }"
        else:
            r_audit = c_good.replace("entrypoint", "provider_probe")
        task = {"id": ident, "category": category, "provider": name, "specification": spec,
                "provider_params": [[p["name"], p["type"]] for p in good["params"]], "provider_returns": good["returns"],
                "original_hia": {"api.hia.json": old, "client.hia.json": client_old},
                "correct_hia": {"api.hia.json": good, "client.hia.json": client_good},
                "original_rust": {"api.rs": r_old, "client.rs": c_old}, "correct_rust": {"api.rs": r_good, "client.rs": c_good},
                "unchanged_hia": {"audit.hia.json": audit_tag, "utility.hia.json": utility},
                "unchanged_rust": {"audit.rs": "pub fn audit_tag(c:u32)->u32 { c & 7 }", "utility.rs": "pub fn utility(x:u32)->u32 { x & 255 }"},
                "probe_hia": audit, "probe_rust": r_audit,
                "public_cases": public}
        hidden = [[a, b, c] for a, b, c in [(MAX32, 0, MAX32), (0, MAX32, MAX32), (MAX32, MAX32, 0), (65535, 65536, 4), (7, 7, 7)]]
        for _ in range(24):
            row = []
            for _ in range(3):
                state = (1664525 * state + 1013904223) % 2**32
                row.append(state)
            hidden.append(row)
        seen = {tuple(case) for case in public}
        task["hidden_cases"] = []
        for row in hidden:
            if tuple(row) not in seen:
                seen.add(tuple(row)); task["hidden_cases"].append(row)
        for split in ("public", "hidden"):
            task[split + "_expected"] = [list(oracle(ident, case)) for case in task[split + "_cases"]]
        verify_program(document(task, task["correct_hia"]))
        verify_program(document(task, task["original_hia"], probe_contract=False))
        tasks.append(task)
    return tasks


RUST_METHODS = ("wrapping_add", "wrapping_sub", "wrapping_mul", "saturating_add", "saturating_sub", "saturating_mul", "abs_diff", "min", "max", "len")


def prompt(task, arm):
    language, interface = arm.split("_")
    source = copy.deepcopy(task["original_" + language])
    if interface == "full":
        source.update(task["unchanged_" + language])
        context = {"physical_files": source}
    else:
        context = {"editable_files": source, "unchanged_interfaces": [
            {"file": "audit.hia.json" if language == "hia" else "audit.rs", "function": "audit_tag(c:u32)->u32", "calls": [], "role": "unrelated audit helper; retained unchanged"},
            {"file": "utility.hia.json" if language == "hia" else "utility.rs", "function": "utility(x:u32)->u32", "calls": [], "role": "unrelated pure helper; retained unchanged"}],
            "reverification": "All four files and provider/caller signatures remain subject to whole-program admission and actual compilation."}
    rules = ("Each HIA file is one complete function object, preserving its name and required signature. The host atomically replaces both definitions and verifies the full Core. int.cast must use attrs {\"mode\":\"wrap\"} or checked. const has attrs.value. select args are condition,true,false; comparisons return bool. Arithmetic .wrap is modulo result width. call has attrs.function and one out per result. buffer.new takes usize length and returns buffer; borrow.mut/read return mutbuf/readbuf; buffer.store takes view,index:u-size,value:u8; buffer.load returns u8; loan.end ends a view; owner.drop consumes a buffer. End loans before moving/dropping an owner; returning buffer transfers it. No loops, recursion, extra functions, external calls or effects outside alloc/read/write/trap; max 16 blocks/128 operations per function. Only scalar, buffer, mutbuf, readbuf types."
             if language == "hia" else
             "Each Rust file is a complete string with exactly one public function. Preserve use crate::api; in client.rs; no other imports, attributes, comments, strings, loops, closures, unsafe, globals, extra functions, foreign calls or extra paths. Only bool/u8/u16/u32/u64/usize and Vec<u8> types. Allowed primitive methods: " + ",".join(RUST_METHODS) + ". Only vec![byte;length], drop(value), and the one api provider call are allowed non-method calls. Array indexing and arithmetic/if expressions are allowed. No clone/resize or other methods. These are the complete finite profile restrictions, not examples.")
    return ("Repair this four-file project. Return ONLY JSON {\"files\":{...}} with exactly "
            + ", ".join(EDITABLE[language]) + "; both complete replacement contents, no fences or explanation."
            + "\n" + task["specification"] + "\n" + rules
            + "\nOnly these two files are editable in BOTH full and query interfaces. The other two remain unchanged."
            + "\nPublic cases [arguments,[entrypoint result,independent provider probe result]]:\n"
            + canonical(list(zip(task["public_cases"], task["public_expected"]))).decode()
            + "\nCurrent context:\n" + canonical(context).decode())


def response_schema(language):
    value_type = "object" if language == "hia" else "string"
    return {"type": "object", "properties": {"files": {"type": "object", "properties": {
        name: {"type": value_type} for name in EDITABLE[language]}, "required": list(EDITABLE[language]), "additionalProperties": False}},
        "required": ["files"], "additionalProperties": False}
