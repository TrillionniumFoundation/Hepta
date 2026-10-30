"""New, finite, paired maintenance/upgrade tasks for the v3 Agent study.

Reference programs are evaluator controls. They never enter model prompts or
decoder schemas. The oracle uses mathematical Python integers independently of
the generated HIA/Rust reference implementations.
"""
from __future__ import annotations

import copy

from experiments.hia_optimizer_eval.next_20261028.upgrade_pilot import function, op, document
from hepta.hia_program import verify_program
from tools.provider_adapter.llama_cpp_engine import canonical

MAX64 = 2**64 - 1
FILE_NAMES = {"hia": ("api.hia.json", "client.hia.json"), "rust": ("api.rs", "client.rs")}
PARAMS = [("a", "u32"), ("b", "u32"), ("c", "u32")]


def client(provider, *, narrow=False, tag_shift=None, bias=False, tuple_return=False):
    operations = []
    arguments = ["a", "b"]
    if narrow:
        operations += [op("int.cast", ["a"], "a16", "u16"), op("int.cast", ["b"], "b16", "u16")]
        arguments = ["a16", "b16"]
    if tuple_return:
        operations.append({"op": "call", "args": arguments,
            "out": [{"name": "valid", "type": "bool"}, {"name": "value", "type": "u64"}],
            "attrs": {"function": provider}})
        operations += [op("const", [], "invalid", "u64", value=MAX64),
                       op("select", ["valid", "value", "invalid"], "answer", "u64")]
    else:
        operations += [op("call", arguments, "value", "u32" if narrow else "u64", function=provider),
                       op("int.cast", ["value"], "wide", "u64")]
        if tag_shift is not None:
            operations += [op("const", [], "mask", value=255), op("bit.and", ["c", "mask"], "tag"),
                op("int.cast", ["tag"], "tag64", "u64"), op("const", [], "shift", "u64", value=tag_shift),
                op("int.shl.checked", ["tag64", "shift"], "tagged", "u64"),
                op("bit.xor", ["wide", "tagged"], "answer", "u64")]
        elif bias:
            operations += [op("int.cast", ["c"], "bias64", "u64"),
                           op("int.add.wrap", ["wide", "bias64"], "answer", "u64")]
        else:
            operations += [op("int.cast", ["wide"], "answer", "u64")]
    return function("entrypoint", PARAMS, ["u64"], operations, ["answer"], ["trap"])


def provider_values(task_id, case):
    a, b, _ = case
    if task_id == "carry_sum_tag":
        return [a + b]
    if task_id == "absolute_gap_bias":
        return [abs(a - b)]
    if task_id == "wide_product_tag":
        return [a * b]
    if task_id == "rounded_tiles_v2":
        return [b != 0, (a + b - 1) // b if b else 0]
    raise ValueError("unknown registered task")


def oracle(task_id, case):
    value = provider_values(task_id, case)
    if task_id == "carry_sum_tag":
        return value[0] ^ ((case[2] & 255) << 48)
    if task_id == "absolute_gap_bias":
        return value[0] + case[2]
    if task_id == "wide_product_tag":
        return value[0] ^ ((case[2] & 255) << 56)
    if task_id == "rounded_tiles_v2":
        return value[1] if value[0] else MAX64
    raise ValueError("unknown registered task")


def make_fixtures():
    old_sum = function("total", PARAMS[:2], ["u64"],
        [op("int.add.wrap", ["a", "b"], "low"), op("int.cast", ["low"], "answer", "u64")], ["answer"])
    good_sum = function("total", PARAMS[:2], ["u64"],
        [op("int.cast", ["a"], "a64", "u64"), op("int.cast", ["b"], "b64", "u64"),
         op("int.add.wrap", ["a64", "b64"], "answer", "u64")], ["answer"])
    old_gap = function("gap", PARAMS[:2], ["u64"],
        [op("int.sub.wrap", ["a", "b"], "low"), op("int.cast", ["low"], "answer", "u64")], ["answer"])
    good_gap = function("gap", PARAMS[:2], ["u64"],
        [op("compare.ge", ["a", "b"], "ordered", "bool"),
         op("select", ["ordered", "a", "b"], "high"), op("select", ["ordered", "b", "a"], "low"),
         op("int.sub.wrap", ["high", "low"], "distance"),
         op("int.cast", ["distance"], "answer", "u64")], ["answer"])
    old_product = function("product", [("a", "u16"), ("b", "u16")], ["u32"],
        [op("int.cast", ["a"], "a32"), op("int.cast", ["b"], "b32"),
         op("int.mul.wrap", ["a32", "b32"], "answer")], ["answer"])
    good_product = function("product", PARAMS[:2], ["u64"],
        [op("int.cast", ["a"], "a64", "u64"), op("int.cast", ["b"], "b64", "u64"),
         op("int.mul.wrap", ["a64", "b64"], "answer", "u64")], ["answer"])
    old_tiles = function("tiles", [("a", "u16"), ("b", "u16")], ["u32"],
        [op("int.cast", ["a"], "a32"), op("int.cast", ["b"], "b32"),
         op("int.div.checked", ["a32", "b32"], "answer")], ["answer"], ["trap"])
    good_tiles = function("tiles", PARAMS[:2], ["bool", "u64"],
        [op("const", [], "zero", value=0), op("const", [], "one", value=1),
         op("compare.ne", ["b", "zero"], "valid", "bool"),
         op("select", ["valid", "b", "one"], "safe_b"),
         op("int.cast", ["a"], "a64", "u64"), op("int.cast", ["safe_b"], "b64", "u64"),
         op("const", [], "one64", "u64", value=1), op("const", [], "zero64", "u64", value=0),
         op("int.add.wrap", ["a64", "b64"], "sum", "u64"),
         op("int.sub.wrap", ["sum", "one64"], "numerator", "u64"),
         op("int.div.checked", ["numerator", "b64"], "count", "u64"),
         op("select", ["valid", "count", "zero64"], "answer", "u64")], ["valid", "answer"], ["trap"])
    definitions = [
        ("carry_sum_tag", "maintenance", "total", old_sum, good_sum,
         client("total", tag_shift=48), client("total", tag_shift=48),
         "Fix total(a:u32,b:u32)->u64 to return the mathematical sum without losing the carry bit. Its consumer returns total(a,b) XOR ((c AND 255) shifted left by 48 bits). Preserve both public signatures and call total exactly once with the original a,b values.",
         "pub fn total(a:u32,b:u32)->u64 { a.wrapping_add(b) as u64 }\n",
         "pub fn total(a:u32,b:u32)->u64 { (a as u64) + (b as u64) }\n",
         "use crate::api;\npub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::total(a,b) ^ (((c & 255) as u64) << 48) }\n",
         "use crate::api;\npub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::total(a,b) ^ (((c & 255) as u64) << 48) }\n",
         [[0,0,0],[4294967295,1,2],[23,41,259]]),
        ("absolute_gap_bias", "maintenance", "gap", old_gap, good_gap,
         client("gap", bias=True), client("gap", bias=True),
         "Fix gap(a:u32,b:u32)->u64 to return the nonnegative mathematical absolute difference between a and b, in either order. Its consumer returns gap(a,b) plus the complete u32 bias c, without overflow or truncation. Preserve both signatures and call gap exactly once with original a,b.",
         "pub fn gap(a:u32,b:u32)->u64 { a.wrapping_sub(b) as u64 }\n",
         "pub fn gap(a:u32,b:u32)->u64 { a.abs_diff(b) as u64 }\n",
         "use crate::api;\npub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::gap(a,b) + c as u64 }\n",
         "use crate::api;\npub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::gap(a,b) + c as u64 }\n",
         [[0,0,0],[3,19,7],[4294967295,0,4294967295]]),
        ("wide_product_tag", "upgrade", "product", old_product, good_product,
         client("product", narrow=True, tag_shift=24), client("product", tag_shift=56),
         "Upgrade product(a:u16,b:u16)->u32 to product(a:u32,b:u32)->u64. The provider must return the full mathematical product of the two complete u32 inputs. Update the consumer so it calls product once without u16 truncation and returns the product XOR ((c AND 255) shifted left by 56 bits). The public entrypoint(a:u32,b:u32,c:u32)->u64 stays unchanged. Update both files atomically.",
         "pub fn product(a:u16,b:u16)->u32 { (a as u32) * (b as u32) }\n",
         "pub fn product(a:u32,b:u32)->u64 { (a as u64) * (b as u64) }\n",
         "use crate::api;\npub fn entrypoint(a:u32,b:u32,c:u32)->u64 { (api::product(a as u16,b as u16) as u64) ^ (((c & 255) as u64) << 24) }\n",
         "use crate::api;\npub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::product(a,b) ^ (((c & 255) as u64) << 56) }\n",
         [[0,1,0],[65537,3,1],[4294967295,2,255]]),
        ("rounded_tiles_v2", "upgrade", "tiles", old_tiles, good_tiles,
         client("tiles", narrow=True), client("tiles", tuple_return=True),
         "Upgrade tiles(a:u16,b:u16)->u32 to tiles(a:u32,b:u32)->(bool,u64). Treat a as an extent and b as a tile size. For b>0 return (true,ceil(a/b)), with mathematical arithmetic and no u32 overflow. For b=0 return (false,0) without division by zero. Update the consumer to pass complete u32 inputs exactly once, unpack the pair, return the count when valid and u64::MAX when invalid. The public entrypoint(a:u32,b:u32,c:u32)->u64 stays unchanged; c is ignored. Update both files atomically.",
         "pub fn tiles(a:u16,b:u16)->u32 { (a as u32) / (b as u32) }\n",
         "pub fn tiles(a:u32,b:u32)->(bool,u64) { if b == 0 { (false,0) } else { (true,((a as u64) + (b as u64) - 1) / (b as u64)) } }\n",
         "use crate::api;\npub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let _ = c; api::tiles(a as u16,b as u16) as u64 }\n",
         "use crate::api;\npub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let _ = c; let (valid,count) = api::tiles(a,b); if valid { count } else { u64::MAX } }\n",
         [[0,7,0],[11,4,9],[17,0,0]]),
    ]
    tasks = []
    state = 0x6A37D5C1
    for task_id, stratum, provider, old, good, old_client, good_client, spec, old_rust, good_rust, old_rust_client, good_rust_client, public in definitions:
        task = {"id": task_id, "stratum": stratum, "provider": provider, "specification": spec,
            "provider_params": [[p["name"], p["type"]] for p in good["params"]],
            "provider_returns": good["returns"], "provider_argument_indices": [0,1],
            "original_hia": {"api.hia.json": old, "client.hia.json": old_client},
            "correct_hia": {"api.hia.json": good, "client.hia.json": good_client},
            "original_rust": {"api.rs": old_rust, "client.rs": old_rust_client},
            "correct_rust": {"api.rs": good_rust, "client.rs": good_rust_client},
            "public_cases": public}
        candidates = [[a,b,c] for a in (0,1,255,65535,65536,2147483648,4294967295)
                      for b in (0,1,257,65535,65536,4294967295) for c in (0,257,4294967295)]
        for _ in range(64):
            row = []
            for _ in range(3):
                state = (1103515245 * state + 12345) % 2**32
                row.append(state)
            candidates.append(row)
        seen, hidden = {tuple(case) for case in public}, []
        for row in candidates:
            if tuple(row) not in seen:
                seen.add(tuple(row)); hidden.append(row)
        task["hidden_cases"] = hidden
        for split in ("public", "hidden"):
            task[split + "_expected"] = [oracle(task_id, row) for row in task[split + "_cases"]]
        for label in ("original_hia", "correct_hia"):
            verify_program(document(task, task[label]))
        tasks.append(task)
    return tasks


def response_schema(language):
    if language not in FILE_NAMES:
        raise ValueError("unknown language")
    # Constrain only the transport envelope and declared filenames/types.
    # The decoder receives no function names, operations, constants or answers.
    return {"type": "object", "properties": {"files": {"type": "object",
        "properties": {name: {"type": "object" if language == "hia" else "string"}
                       for name in FILE_NAMES[language]},
        "required": list(FILE_NAMES[language]), "additionalProperties": False}},
        "required": ["files"], "additionalProperties": False}


def prompt(task, language):
    if language == "hia":
        profile = ("Each file is one complete typed HIA function object. The host applies an atomic patch.v2 migration and verifies the whole module. Keep the named provider and entrypoint; no extra functions. Pure scalar operations only, no loops or recursion. const: no args, attrs value; int.cast: attrs mode wrap or checked; int.add/sub/mul.wrap; int.div.checked; bit.and/or/xor; compare.lt/le/gt/ge/eq/ne returns bool; select(condition,true_value,false_value); call has attrs function and one out per returned value. Return term is {op:ret,values:[names]}. Arithmetic wraps only when .wrap is written. Checked division traps on zero. The shown typed object syntax is mandatory.")
    else:
        profile = ("Each file is one complete Rust source string. Keep exactly one public function in each file and the existing use crate::api import in client.rs. Pure scalar Rust only: no unsafe, macros, attributes, extra imports/functions, allocation, loops, recursion or external calls. Standard primitive integer operations and methods, Option from checked arithmetic, if/else and tuples are allowed.")
    return ("Maintain this two-file project. Return ONLY JSON with exactly one top-level key files, whose object contains both shown filenames and their complete replacements. The output decoder enforces only that envelope, filenames and content types; it does not supply the repair.\n"
        + task["specification"] + "\n" + profile
        + "\nThe consumer must call its provider exactly once using original a,b values. Provider output must itself satisfy the specification; a correct consumer cannot bypass an incorrect provider. Public entrypoint parameters and return type are fixed.\n"
        + "Public examples (arguments, expected entrypoint result):\n"
        + canonical(list(zip(task["public_cases"], task["public_expected"]))).decode()
        + "\nCurrent files:\n" + canonical(task["original_" + language]).decode())
