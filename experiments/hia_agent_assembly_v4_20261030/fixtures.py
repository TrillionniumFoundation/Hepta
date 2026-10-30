"""Fresh mathematical maintenance/upgrade tasks with three source views.

The assembly and JSON arms denote the exact same starting and reference Core.
Reference implementations and hidden values never enter inference prompts.
"""
from __future__ import annotations

import copy
import re

from experiments.hia_optimizer_eval.next_20261028.upgrade_pilot import (
    RUST_SCALAR_METHODS, function, op, document,
)
from experiments.hia_agent_matched_v3_20261028.fixtures import client
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import verify_program
from hepta.hia_program_tools import decode_json
from tools.provider_adapter.llama_cpp_engine import canonical

MAX64 = 2**64 - 1
ARMS = ("hia", "assembly", "rust")
FILE_NAMES = {"hia": ("api.hia.json", "client.hia.json"),
              "assembly": ("api.hiaasm", "client.hiaasm"), "rust": ("api.rs", "client.rs")}
PARAMS = [("a", "u32"), ("b", "u32"), ("c", "u32")]


def provider_values(task_id, case):
    a, b, _ = case
    if task_id == "average_floor_stamp":
        return [(a + b) // 2]
    if task_id == "clamped_delta_bias":
        return [max(a - b, 0)]
    if task_id == "stride_span_v2":
        return [a * (b + 1)]
    if task_id == "floor_multiple_v2":
        return [b != 0, (a // b) * b if b else 0]
    raise ValueError("unknown registered task")


def oracle(task_id, case):
    result = provider_values(task_id, case)
    if task_id == "average_floor_stamp":
        return result[0] ^ ((case[2] & 255) << 40)
    if task_id == "clamped_delta_bias":
        return result[0] + case[2]
    if task_id == "stride_span_v2":
        return result[0] ^ ((case[2] & 127) << 57)
    if task_id == "floor_multiple_v2":
        return result[1] if result[0] else MAX64
    raise ValueError("unknown registered task")


def assembly_files(task, files):
    """Render both functions without losing their declared module manifest."""
    source = render_assembly(document(task, files))
    lines = source.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if line.startswith("fn ")]
    if len(starts) != 2:
        raise ValueError("expected exactly the provider and consumer")
    return {name: "".join(lines[start:end])
            for name, start, end in zip(FILE_NAMES["assembly"], starts, [starts[1], len(lines)])}


def assembly_to_json(task, text):
    decoded = decode_json(text)
    if type(decoded) is not dict or set(decoded) != {"files"}:
        raise ValueError("E_ASSEMBLY_STUDY_FILES_ENVELOPE")
    files = decoded["files"]
    if type(files) is not dict or set(files) != set(FILE_NAMES["assembly"]):
        raise ValueError("E_ASSEMBLY_STUDY_FILENAMES")
    for name, function_name in zip(FILE_NAMES["assembly"], (task["provider"], "entrypoint")):
        source = files[name]
        if type(source) is not str or len(source.encode()) > 64 * 1024:
            raise ValueError("E_ASSEMBLY_STUDY_SOURCE")
        headers = [line.strip() for line in source.split("\n") if line.strip().startswith("fn ")]
        if len(headers) != 1 or re.match(r"fn\s+" + re.escape(function_name) + r"\(", headers[0]) is None:
            raise ValueError("E_ASSEMBLY_STUDY_FILE_FUNCTION")
    module = f'hia-asm.v1 hepta.hia.program.v6 {task["id"]}\nexports(entrypoint)\n'
    module += files["api.hiaasm"] + "\n" + files["client.hiaasm"]
    checked = assemble_program(module)
    functions = checked.as_dict()["functions"]
    if [fn["name"] for fn in functions] != [task["provider"], "entrypoint"]:
        raise ValueError("E_ASSEMBLY_STUDY_FUNCTION_INVENTORY")
    return canonical({"files": dict(zip(FILE_NAMES["hia"], functions))}).decode(), {
        "source_text_sha256": __import__("hashlib").sha256(module.encode()).hexdigest(),
        "core_sha256": checked.sha256, "full_module_reverified": True,
        "implicit_repairs": False, "deployment_authority": False}


def make_fixtures():
    old_average = function("average", PARAMS[:2], ["u64"], [
        op("int.add.wrap", ["a", "b"], "sum"), op("const", [], "two", value=2),
        op("int.div.checked", ["sum", "two"], "low"),
        op("int.cast", ["low"], "answer", "u64")], ["answer"], ["trap"])
    good_average = function("average", PARAMS[:2], ["u64"], [
        op("int.cast", ["a"], "a64", "u64"), op("int.cast", ["b"], "b64", "u64"),
        op("int.add.wrap", ["a64", "b64"], "sum", "u64"), op("const", [], "two", "u64", value=2),
        op("int.div.checked", ["sum", "two"], "answer", "u64")], ["answer"], ["trap"])
    old_delta = function("delta", PARAMS[:2], ["u64"], [
        op("int.sub.wrap", ["a", "b"], "low"), op("int.cast", ["low"], "answer", "u64")], ["answer"])
    good_delta = function("delta", PARAMS[:2], ["u64"], [
        op("compare.ge", ["a", "b"], "ordered", "bool"), op("int.sub.wrap", ["a", "b"], "difference"),
        op("const", [], "zero", value=0), op("select", ["ordered", "difference", "zero"], "clamped"),
        op("int.cast", ["clamped"], "answer", "u64")], ["answer"])
    old_span = function("span", [("a", "u16"), ("b", "u16")], ["u32"], [
        op("int.cast", ["a"], "a32"), op("int.cast", ["b"], "b32"), op("const", [], "one", value=1),
        op("int.add.wrap", ["b32", "one"], "stride"), op("int.mul.wrap", ["a32", "stride"], "answer")], ["answer"])
    good_span = function("span", PARAMS[:2], ["u64"], [
        op("int.cast", ["a"], "a64", "u64"), op("int.cast", ["b"], "b64", "u64"),
        op("const", [], "one", "u64", value=1), op("int.add.wrap", ["b64", "one"], "stride", "u64"),
        op("int.mul.wrap", ["a64", "stride"], "answer", "u64")], ["answer"])
    old_floor = function("multiple", [("a", "u16"), ("b", "u16")], ["u32"], [
        op("int.cast", ["a"], "a32"), op("int.cast", ["b"], "b32"),
        op("int.div.checked", ["a32", "b32"], "quotient"),
        op("int.mul.wrap", ["quotient", "b32"], "answer")], ["answer"], ["trap"])
    good_floor = function("multiple", PARAMS[:2], ["bool", "u64"], [
        op("const", [], "zero", value=0), op("const", [], "one", value=1),
        op("compare.ne", ["b", "zero"], "valid", "bool"), op("select", ["valid", "b", "one"], "safe_b"),
        op("int.div.checked", ["a", "safe_b"], "quotient"),
        op("int.mul.wrap", ["quotient", "b"], "product"),
        op("int.cast", ["product"], "answer", "u64")], ["valid", "answer"], ["trap"])
    old_span_client = client("span", narrow=True, tag_shift=16)
    good_span_client = client("span", tag_shift=57)
    good_span_client["blocks"][0]["ops"][2]["attrs"]["value"] = 127
    definitions = [
        ("average_floor_stamp", "maintenance", "average", old_average, good_average,
         client("average", tag_shift=40), client("average", tag_shift=40),
         "Repair average(a:u32,b:u32)->u64 to return floor((a+b)/2) using mathematical integers, including when a+b exceeds u32. The consumer returns average(a,b) XOR ((c AND 255) shifted left by 40 bits). Preserve both signatures and call average once with original a,b.",
         "pub fn average(a:u32,b:u32)->u64 { (a.wrapping_add(b) / 2) as u64 }\n",
         "pub fn average(a:u32,b:u32)->u64 { ((a as u64) + (b as u64)) / 2 }\n",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::average(a,b) ^ (((c & 255) as u64)<<40) }\n",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::average(a,b) ^ (((c & 255) as u64)<<40) }\n",
         [[4294967295,1,3],[19,24,257],[0,1,0]]),
        ("clamped_delta_bias", "maintenance", "delta", old_delta, good_delta,
         client("delta", bias=True), client("delta", bias=True),
         "Repair delta(a:u32,b:u32)->u64 to return max(a-b,0), using mathematical integers. When a is smaller than b the provider must return zero. The consumer returns delta(a,b) plus the complete u32 bias c without truncation. Preserve signatures and invoke delta once with original a,b.",
         "pub fn delta(a:u32,b:u32)->u64 { a.wrapping_sub(b) as u64 }\n",
         "pub fn delta(a:u32,b:u32)->u64 { a.saturating_sub(b) as u64 }\n",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::delta(a,b) + c as u64 }\n",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::delta(a,b) + c as u64 }\n",
         [[3,19,7],[4294967295,0,4294967295],[0,0,0]]),
        ("stride_span_v2", "upgrade", "span", old_span, good_span, old_span_client, good_span_client,
         "Upgrade span(a:u16,b:u16)->u32 to span(a:u32,b:u32)->u64. It must return a*(b+1) using full mathematical precision; the addition b+1 must not wrap at u32. Update the consumer to pass complete a,b exactly once and return span(a,b) XOR ((c AND 127) shifted left by 57 bits). Its public signature entrypoint(a:u32,b:u32,c:u32)->u64 is unchanged. Update both files atomically.",
         "pub fn span(a:u16,b:u16)->u32 { (a as u32) * ((b as u32)+1) }\n",
         "pub fn span(a:u32,b:u32)->u64 { (a as u64) * ((b as u64)+1) }\n",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { (api::span(a as u16,b as u16) as u64) ^ (((c & 255) as u64)<<16) }\n",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::span(a,b) ^ (((c & 127) as u64)<<57) }\n",
         [[65536,65536,1],[4294967295,4294967295,255],[0,7,0]]),
        ("floor_multiple_v2", "upgrade", "multiple", old_floor, good_floor,
         client("multiple", narrow=True), client("multiple", tuple_return=True),
         "Upgrade multiple(a:u16,b:u16)->u32 to multiple(a:u32,b:u32)->(bool,u64). For b>0 it must return (true,floor(a/b)*b), the greatest multiple of b no larger than a. For b=0 it must return (false,0) without trapping. Update the consumer to pass complete u32 a,b exactly once, unpack the result, return the multiple when valid and u64::MAX otherwise. entrypoint(a:u32,b:u32,c:u32)->u64 remains unchanged; c is ignored. Update both files atomically.",
         "pub fn multiple(a:u16,b:u16)->u32 { ((a as u32) / (b as u32)) * (b as u32) }\n",
         "pub fn multiple(a:u32,b:u32)->(bool,u64) { if b==0 { (false,0) } else { (true,((a/b)*b) as u64) } }\n",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let _=c; api::multiple(a as u16,b as u16) as u64 }\n",
         "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { let _=c; let (valid,value)=api::multiple(a,b); if valid {value} else {u64::MAX} }\n",
         [[4294967295,65536,9],[11,4,0],[7,0,5]]),
    ]
    tasks = []
    state = 0x6B4A29D3
    for task_id, stratum, provider, old, good, old_client, good_client, spec, old_rust, good_rust, old_rc, good_rc, public in definitions:
        task = {"id": task_id, "stratum": stratum, "provider": provider, "specification": spec,
                "provider_params": [[p["name"], p["type"]] for p in good["params"]],
                "provider_returns": good["returns"], "provider_argument_indices": [0, 1],
                "original_hia": dict(zip(FILE_NAMES["hia"], (old, old_client))),
                "correct_hia": dict(zip(FILE_NAMES["hia"], (good, good_client))),
                "original_rust": dict(zip(FILE_NAMES["rust"], (old_rust, old_rc))),
                "correct_rust": dict(zip(FILE_NAMES["rust"], (good_rust, good_rc))), "public_cases": public}
        candidates = [[a, b, c] for a in (0, 1, 2, 31, 65535, 65536, 2147483647, 4294967295)
                      for b in (0, 1, 2, 7, 65535, 4294967295) for c in (0, 255, 257, 4294967295)]
        for _ in range(64):
            row = []
            for _ in range(3):
                state = (1103515245 * state + 12345) % 2**32
                row.append(state)
            candidates.append(row)
        seen, hidden = {tuple(case) for case in public}, []
        for case in candidates:
            if tuple(case) not in seen:
                seen.add(tuple(case)); hidden.append(case)
        task["hidden_cases"] = hidden
        for split in ("public", "hidden"):
            task[split + "_expected"] = [oracle(task_id, case) for case in task[split + "_cases"]]
        for label in ("original", "correct"):
            checked = verify_program(document(task, task[label + "_hia"]))
            task[label + "_assembly"] = assembly_files(task, task[label + "_hia"])
            translated, _ = assembly_to_json(task, canonical({"files": task[label + "_assembly"]}).decode())
            if verify_program(document(task, decode_json(translated)["files"])).canonical_bytes != checked.canonical_bytes:
                raise RuntimeError("source representations differ")
        tasks.append(task)
    return tasks


def response_schema(language):
    if language not in ARMS:
        raise ValueError("unknown representation")
    return {"type": "object", "properties": {"files": {"type": "object",
            "properties": {name: {"type": "object" if language == "hia" else "string"}
                           for name in FILE_NAMES[language]},
            "required": list(FILE_NAMES[language]), "additionalProperties": False}},
            "required": ["files"], "additionalProperties": False}


def prompt(task, language):
    operations = ("Pure scalar: const uses attrs value; int.cast requires attrs mode wrap or checked; "
                  "int.add/sub/mul.wrap; int.div.checked; bit.and/or/xor; compare.lt/le/gt/ge/eq/ne returns bool; "
                  "select(condition,true_value,false_value); call uses attrs function and one typed output per result. "
                  "Wrapping is explicit. Checked division traps on zero. No loops, recursion, resources or extra functions.")
    if language == "hia":
        profile = "Each file is one complete typed HIA function object, with existing exact field names. " + operations
    elif language == "assembly":
        profile = ("Each file is one complete HIA function in the shown compact syntax. "
                   "The host joins the two files under this immutable module manifest: "
                   f"hia-asm.v1 hepta.hia.program.v6 {task['id']}; exports(entrypoint). "
                   "Do not emit that manifest in either file. Function header: fn name(parameters) -> (return_types) effects(effects) entry(block). "
                   "Blocks: block name(parameters). Every parameter/result is name:type. Instruction: result:type = opcode(arguments) followed by optional JSON attrs. "
                   "Multiple results are comma-separated; _ means zero results. Terminators: ret(names), jump target(names), branch condition yes_target(names) no_target(names), trap code. "
                   "Finish each function with end. No inferred casts/types/cleanup; missing attrs are {}. " + operations)
    elif language == "rust":
        profile = ("Each file is one complete Rust source string with exactly one public function; retain use crate::api in client.rs. "
                   "Pure scalar Rust: no unsafe, macros, attributes, extra imports/functions, allocation, loops, recursion or external calls. "
                   "Primitive integer operators, casts, if/else, tuples and Option from checked arithmetic are allowed. "
                   "The exact allowed primitive/Option method names are: " + ", ".join(sorted(RUST_SCALAR_METHODS)) + ".")
    else:
        raise ValueError("unknown representation")
    return ("Maintain this two-file project. Return ONLY JSON with the top-level key files and both shown filenames and complete replacements. "
            "The decoder constrains only envelope, filenames and content types; it supplies no solution.\n"
            + task["specification"] + "\n" + profile
            + "\nThe provider must independently satisfy the specification. The consumer must call it exactly once using original a,b. Public entrypoint parameters/return are fixed.\n"
            + "Public examples (arguments, expected entrypoint result):\n"
            + canonical(list(zip(task["public_cases"], task["public_expected"]))).decode()
            + "\nCurrent files:\n" + canonical(task["original_" + language]).decode())
