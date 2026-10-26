#!/usr/bin/env python3
"""Frozen four-task/four-arm single-site repair pilot, not general productivity.

Full responses and semantic edits must preserve the frozen context. Every
accepted candidate is compiled and run against independent native cases.
Restricted Rust expression slots prevent arbitrary generated host code.
"""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from hepta.hia_program import SCHEMA, verify_program
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_tools import PATCH_SCHEMA, apply_program_patch
from tools.provider_adapter.local_model_common import canonical, digest, file_digest, validate_lock, verify_assets
from tools.provider_adapter.local_model_service import TransformersEngine, runtime_identity

ARMS = ("hia_full_json", "hia_semantic_patch", "rust_full_function", "rust_semantic_expression")
RUST_EDIT_SCHEMA = "hepta.rust.expression-edit.v1"
BINDINGS = ("hepta/hia_program.py", "hepta/hia_program_runtime.py", "hepta/hia_program_llvm.py",
            "hepta/hia_program_tools.py", "tools/qualify_hia_agent_pilot.py")


def p(name, typ="u32"):
    return {"name": name, "type": typ}


def op(kind, args=(), out=(), **attrs):
    return {"op": kind, "args": list(args), "out": [p(*x) for x in out], "attrs": attrs}


def block(name, params, ops, term):
    return {"id": name, "params": [p(*x) for x in params], "ops": ops, "term": term}


def module(params, blocks):
    return {"schema": SCHEMA, "module": "repair_pilot", "functions": [{
        "name": "repair", "params": [p(*x) for x in params], "returns": ["u32"], "effects": ["trap"],
        "entry": "entry", "blocks": blocks}]}


def task_fixtures():
    boundary = module([("i", "u32"), ("n", "u32")], [
        block("entry", [("i", "u32"), ("n", "u32")], [
            op("compare.le", ["i", "n"], [("test", "bool")]),
            op("const", out=[("yes", "u32")], value=1), op("const", out=[("no", "u32")], value=0),
            op("select", ["test", "yes", "no"], [("answer", "u32")]),
        ], {"op": "ret", "values": ["answer"]})])
    constant = module([("x", "u32")], [block("entry", [("x", "u32")], [
        op("const", out=[("offset", "u32")], value=6),
        op("int.add.wrap", ["x", "offset"], [("answer", "u32")]),
    ], {"op": "ret", "values": ["answer"]})])
    wrapping = module([("x", "u32")], [block("entry", [("x", "u32")], [
        op("const", out=[("one", "u32")], value=1),
        op("int.add.checked", ["x", "one"], [("answer", "u32")]),
    ], {"op": "ret", "values": ["answer"]})])
    loop = module([("n", "u32")], [
        block("entry", [("n", "u32")], [op("const", out=[("zero", "u32")], value=0)],
              {"op": "jump", "target": "loop", "args": ["n", "zero", "zero"]}),
        block("loop", [("limit", "u32"), ("index", "u32"), ("total", "u32")], [
            op("const", out=[("one", "u32")], value=1),
            op("compare.lt", ["index", "limit"], [("more", "bool")]),
            op("int.add.wrap", ["total", "one"], [("next_total", "u32")]),
            op("int.add.wrap", ["index", "one"], [("next_index", "u32")]),
        ], {"op": "branch", "cond": "more",
            "then": {"target": "loop", "args": ["limit", "next_index", "next_total"]},
            "else": {"target": "done", "args": ["total"]}}),
        block("done", [("answer", "u32")], [], {"op": "ret", "values": ["answer"]}),
    ])
    values = [
        {"id": "boundary", "description": "Return 1 exactly when unsigned index i is strictly below length n; otherwise return 0.",
         "hia": boundary, "block": "entry", "index": 0, "field": "op", "good": "compare.lt",
         "allowed": ["compare.lt", "compare.le", "compare.gt", "compare.ge", "compare.eq", "compare.ne"],
         "rust_template": "fn repair(i:u32,n:u32)->u32{if i @SLOT@ n{1}else{0}}",
         "rust_bad": "<=", "rust_good": "<", "rust_allowed": ["<", "<=", ">", ">=", "==", "!="],
         "cases": [[0, 0], [0, 1], [1, 1], [2, 1], [17, 18], [4294967295, 4294967295]]},
        {"id": "constant", "description": "Return x plus seven modulo 2^32.",
         "hia": constant, "block": "entry", "index": 0, "field": "value", "good": 7,
         "allowed": list(range(16)), "rust_template": "fn repair(x:u32)->u32{x.wrapping_add(@SLOT@)}",
         "rust_bad": "6", "rust_good": "7", "rust_allowed": list(map(str, range(16))),
         "cases": [[0], [1], [37], [4294967290], [4294967295]]},
        {"id": "wrapping", "description": "Increment a u32 modulo 2^32; the largest u32 must become zero without trapping.",
         "hia": wrapping, "block": "entry", "index": 1, "field": "op", "good": "int.add.wrap",
         "allowed": ["int.add.checked", "int.add.wrap", "int.sub.checked", "int.sub.wrap", "int.mul.checked", "int.mul.wrap"],
         "rust_template": "fn repair(x:u32)->u32{@SLOT@}", "rust_bad": "x+1", "rust_good": "x.wrapping_add(1)",
         "rust_allowed": ["x+1", "x-1", "x*1", "x.wrapping_add(1)", "x.wrapping_sub(1)", "x.wrapping_mul(1)"],
         "cases": [[0], [1], [12345], [4294967294], [4294967295]]},
        {"id": "loop_state", "description": "Return the sum of integers 0 through n-1 modulo 2^32. Preserve the loop counter and control flow.",
         "hia": loop, "block": "loop", "index": 2, "field": "args", "good": ["total", "index"],
         "allowed": [["total", "one"], ["total", "index"], ["index", "one"], ["total", "total"]],
         "rust_template": "fn repair(n:u32)->u32{let mut i=0u32;let mut sum=0u32;while i<n{sum=@SLOT@;i=i.wrapping_add(1);}sum}",
         "rust_bad": "sum.wrapping_add(1)", "rust_good": "sum.wrapping_add(i)",
         "rust_allowed": ["sum.wrapping_add(1)", "sum.wrapping_add(i)", "i.wrapping_add(1)", "sum.wrapping_add(sum)"],
         "cases": [[0], [1], [2], [3], [7], [19]]},
    ]
    for task in values:
        task["rust"] = task["rust_template"].replace("@SLOT@", task["rust_bad"])
        task["hia_sha256"] = verify_program(task["hia"]).sha256
        task["rust_sha256"] = digest(task["rust"].encode())
    return values


def instruction(task, document):
    return next(b for b in document["functions"][0]["blocks"] if b["id"] == task["block"])["ops"][task["index"]]


def repaired_hia(task):
    result = copy.deepcopy(task["hia"])
    node = instruction(task, result)
    if task["field"] == "value":
        node["attrs"]["value"] = task["good"]
    else:
        node[task["field"]] = task["good"]
    return result


def semantic_template(task, arm, repaired=False):
    if arm == "hia_semantic_patch":
        return {"schema": PATCH_SCHEMA, "expected_sha256": task["hia_sha256"], "edits": [{
            "action": "replace_operation", "function": "repair", "block": task["block"], "index": task["index"],
            "operation": instruction(task, repaired_hia(task) if repaired else task["hia"])}]}
    return {"schema": RUST_EDIT_SCHEMA, "expected_sha256": task["rust_sha256"],
            "function": "repair", "slot": task["id"], "replacement": task["rust_good"] if repaired else task["rust_bad"]}


def reference_response(task, arm):
    if arm == "hia_full_json":
        return canonical(repaired_hia(task)).decode()
    if arm == "rust_full_function":
        return task["rust_template"].replace("@SLOT@", task["rust_good"])
    return canonical(semantic_template(task, arm, True)).decode()


def prompt(task, arm):
    common = ("Repair exactly the identified faulty operation/expression. Preserve all other code and interfaces. "
              "Return only the requested artifact, without explanation.\nSpecification: " + task["description"] + "\n")
    if arm.startswith("hia"):
        common += ("HIA: typed SSA with block parameters. int.add.wrap is modular; int.add.checked traps on overflow. "
                   "compare.lt/le mean strict/non-strict comparison.\nFault site: repair, block " + task["block"] +
                   ", operation " + str(task["index"]) + ".\nOriginal module:\n" + canonical(task["hia"]).decode() + "\n")
        if arm == "hia_full_json":
            return common + "Return the complete corrected module as JSON."
    else:
        common += ("Rust uses checked overflow compilation; wrapping_add requests modular arithmetic.\nOriginal function:\n"
                   + task["rust"] + "\nFaulty expression/operator: " + task["rust_bad"] + "\n")
        if arm == "rust_full_function":
            return common + "Return the complete corrected Rust function."
    return common + "Correct the operation/replacement in this semantic edit JSON and return it:\n" + canonical(semantic_template(task, arm)).decode()


def clean_response(text):
    if type(text) is not str:
        raise ValueError("E_PILOT_RESPONSE: text required")
    value = text.strip()
    match = re.fullmatch(r"\x60{3}(?:json|rust)?\s*\n([\s\S]*?)\n\x60{3}", value)
    return match.group(1).strip() if match else value


def parse_candidate(task, arm, text):
    text = clean_response(text)
    if arm.startswith("hia"):
        candidate = verify_program(text) if arm == "hia_full_json" else apply_program_patch(task["hia"], text)[0]
        document, base = candidate.as_dict(), copy.deepcopy(task["hia"])
        node = instruction(task, document)
        value = node["attrs"]["value"] if task["field"] == "value" else node[task["field"]]
        if not any(type(value) is type(a) and value == a for a in task["allowed"]):
            raise ValueError("E_PILOT_SITE: unsupported repair-site value")
        target = instruction(task, base)
        if task["field"] == "value":
            target["attrs"]["value"] = value
        else:
            target[task["field"]] = value
        if document != base:
            raise ValueError("E_PILOT_CONTEXT: edits outside the frozen repair site")
        return candidate
    if arm == "rust_semantic_expression":
        def unique(pairs):
            value = {}
            for key, child in pairs:
                if key in value:
                    raise ValueError("E_PILOT_RUST_EDIT: duplicate JSON field")
                value[key] = child
            return value
        edit = json.loads(text, object_pairs_hook=unique)
        if (type(edit) is not dict or set(edit) != {"schema", "expected_sha256", "function", "slot", "replacement"}
                or edit["schema"] != RUST_EDIT_SCHEMA or edit["expected_sha256"] != task["rust_sha256"]
                or edit["function"] != "repair" or edit["slot"] != task["id"]
                or edit["replacement"] not in task["rust_allowed"]):
            raise ValueError("E_PILOT_RUST_EDIT: invalid identity/site/expression")
        return task["rust_template"].replace("@SLOT@", edit["replacement"])
    squash = lambda x: re.sub(r"\s+", "", x)
    choices = [task["rust_template"].replace("@SLOT@", v) for v in task["rust_allowed"]]
    matches = [v for v in choices if squash(v) == squash(text)]
    if len(matches) != 1:
        raise ValueError("E_PILOT_RUST_CONTEXT: not an allowed single-site repair")
    return matches[0]


def expected_values(task):
    if task["id"] == "boundary":
        return [int(a < b) for a, b in task["cases"]]
    if task["id"] in {"constant", "wrapping"}:
        increment = 7 if task["id"] == "constant" else 1
        return [(a[0] + increment) % (1 << 32) for a in task["cases"]]
    return [(a[0] * (a[0] - 1) // 2) % (1 << 32) for a in task["cases"]]


def native_oracle(task, candidate, language, *, clang, rustc):
    expected = expected_values(task)
    with tempfile.TemporaryDirectory(prefix="hia-agent-oracle-") as td:
        directory = Path(td)
        if language == "hia":
            output = directory / "candidate.so"
            compiled = build_program_native(candidate, output, clang=clang)
            runner = ("import ctypes,json,sys\nlib=ctypes.CDLL(sys.argv[1])\nf=lib.repair\n"
                      "cases=json.loads(sys.argv[2])\nf.argtypes=[ctypes.c_uint32]*len(cases[0])\n"
                      "f.restype=ctypes.c_uint32\nprint(json.dumps([f(*case) for case in cases]))\n")
            command = [sys.executable, "-c", runner, str(output), json.dumps(task["cases"])]
        else:
            source, output = directory / "candidate.rs", directory / "candidate"
            calls = ",".join("repair(" + ",".join(str(v) + "u32" for v in case) + ")" for case in task["cases"])
            source.write_text("#![forbid(unsafe_code)]\n" + candidate +
                              "\nfn main(){let values=[" + calls + "];println!(\"{:?}\",values);}\n")
            command = [rustc, "--edition=2021", "-C", "opt-level=2", "-C", "overflow-checks=on",
                       str(source), "-o", str(output)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=30)
            compiled = {"command": command, "returncode": built.returncode, "stdout": built.stdout,
                        "stderr": built.stderr, "source_sha256": file_digest(source)}
            if built.returncode:
                return {"ok": False, "native_executed": False, "compile": compiled}
            command = [str(output)]
        observed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        actual = None
        if observed.returncode == 0:
            try:
                actual = json.loads(observed.stdout)
            except ValueError:
                pass
        return {"ok": observed.returncode == 0 and actual == expected, "native_executed": True,
                "compile": compiled, "artifact_sha256": file_digest(output),
                "command": command, "returncode": observed.returncode,
                "stdout": observed.stdout, "stderr": observed.stderr, "expected": expected, "actual": actual}


def bindings():
    return {name: file_digest(ROOT / name) for name in BINDINGS}


def write_new(path, value):
    with Path(path).open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def run_pilot(*, model_dir, model_lock, output_dir, clang, rustc):
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=False)
    lock = validate_lock(json.loads(Path(model_lock).read_text()))
    verify_assets(lock, model_dir)
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True, trust_remote_code=False)
    tasks = task_fixtures()
    capacity = {t["id"]: {a: len(tokenizer(reference_response(t, a), add_special_tokens=False)["input_ids"]) for a in ARMS} for t in tasks}
    longest = max(n for values in capacity.values() for n in values.values())
    token_limit = next((n for n in (512, 1024, 2048) if longest + 8 <= n), None)
    if token_limit is None:
        raise ValueError("E_PILOT_CAPACITY: full reference cannot fit a shared budget")
    original_lock = lock["lock_sha256"]
    lock = copy.deepcopy(lock)
    lock["generation"]["max_new_tokens"] = token_limit
    lock["lock_sha256"] = digest(canonical({k: v for k, v in lock.items() if k != "lock_sha256"}))
    validate_lock(lock)
    plan = {"schema": "hepta.hia.agent-pilot-plan.v1", "tasks": tasks, "arms": list(ARMS),
            "attempts_per_task_arm": 2, "max_new_tokens_per_attempt": token_limit,
            "reference_output_token_counts": capacity, "original_lock_sha256": original_lock,
            "effective_lock": lock, "initial_compiler_bindings": bindings(),
            "compiler_binding_policy": "record before and after each candidate; drift invalidates candidate",
            "arm_order": "rotate arms by task index",
            "failure_policy": "retain outputs, token IDs, parse/native failures and timeouts",
            "scope": "four frozen single-site repairs, not arbitrary coding",
            "preflight_policy": "two exact-format probes; both required before comparative tasks",
            "historical_failures": "40 local failures remain in experiments/crossfile_eval/local_study_20261026",
            "effect_established": False}
    plan["plan_sha256"] = digest(canonical(plan))
    write_new(out / "plan.json", plan)
    write_new(out / "model.lock.json", lock)
    print(json.dumps({"event": "plan_frozen", "plan_sha256": plan["plan_sha256"],
                      "max_new_tokens": token_limit, "largest_reference_tokens": longest}), flush=True)
    controls = []
    for task in tasks:
        for language in ("hia", "rust"):
            for correct in (False, True):
                candidate = verify_program(repaired_hia(task) if correct else task["hia"]) if language == "hia" else (
                    task["rust_template"].replace("@SLOT@", task["rust_good"]) if correct else task["rust"])
                result = native_oracle(task, candidate, language, clang=clang, rustc=rustc)
                controls.append({"task": task["id"], "language": language, "correct": correct,
                                 "control_passed": result["ok"] is correct, "oracle": result})
    write_new(out / "controls.json", controls)
    def finish(status, runs, **extra):
        report = {"schema": "hepta.hia.agent-pilot.v1", "status": status,
                  "plan_sha256": plan["plan_sha256"], "actual_model_runs": runs,
                  "effect_established": False, "general_coding_advantage_established": False, **extra}
        write_new(out / "report.json", report)
        return report
    if not all(c["control_passed"] for c in controls):
        return finish("native_controls_failed", 0)
    engine = TransformersEngine(lock, model_dir)
    write_new(out / "runtime.json", runtime_identity())
    generated = []
    def generate(messages, identity):
        request = {"messages": messages, "wall_seconds": 90,
                   "remaining_tokens": {"input_tokens": lock["generation"]["max_input_tokens"],
                                        "output_tokens": token_limit,
                                        "total_tokens": lock["generation"]["max_input_tokens"] + token_limit}}
        write_new(out / (identity + ".request.json"), request)
        result = engine.generate(request)
        write_new(out / (identity + ".response.json"), result)
        generated.append(identity)
        print(json.dumps({"event": "generation", "id": identity, "status": result["status"],
                          "output_tokens": (result.get("usage") or {}).get("output_tokens")}), flush=True)
        return result
    probes = [
        ("json", 'Return exactly this JSON object and no explanation: {"ok":true}', '{"ok":true}'),
        ("rust", "Return exactly this Rust function and no explanation: fn probe(x:u32)->u32{x}", "fn probe(x:u32)->u32{x}"),
    ]
    preflight = []
    for name, message, wanted in probes:
        result = generate([{"role": "user", "content": message}], "preflight_" + name)
        response = clean_response(result.get("text", ""))
        ok = re.sub(r"\s+", "", response) == re.sub(r"\s+", "", wanted)
        preflight.append({"id": name, "ok": ok, "generation_status": result["status"]})
    write_new(out / "preflight.json", preflight)
    if not all(p["ok"] for p in preflight):
        return finish("model_capability_preflight_failed", len(generated),
                      comparative_task_attempts=0, preflight=preflight)
    outcomes = []
    for tindex, task in enumerate(tasks):
        for arm in ARMS[tindex % 4:] + ARMS[:tindex % 4]:
            messages = [{"role": "user", "content": prompt(task, arm)}]
            attempts = []
            for attempt in (1, 2):
                identity = task["id"] + "_" + arm + "_" + str(attempt)
                response = generate(messages, identity)
                before = bindings()
                item = {"attempt": attempt, "response": identity + ".response.json",
                        "compiler_bindings_before": before, "accepted": False, "ok": False}
                try:
                    candidate = parse_candidate(task, arm, response.get("text", ""))
                    item["accepted"] = True
                    item["native_oracle"] = native_oracle(task, candidate, "hia" if arm.startswith("hia") else "rust", clang=clang, rustc=rustc)
                    item["ok"] = item["native_oracle"]["ok"]
                    feedback = "Independent native oracle failed. Correct the same repair site and preserve all other code."
                except Exception as error:
                    item["error"] = {"type": type(error).__name__, "message": str(error)}
                    feedback = "Candidate rejected: " + str(error)[:500] + ". Return only the requested artifact."
                item["compiler_bindings_after"] = bindings()
                if item["compiler_bindings_after"] != before:
                    item.update(ok=False, compiler_drift=True)
                attempts.append(item)
                write_new(out / (identity + ".evaluation.json"), item)
                if item["ok"]:
                    break
                messages += [{"role": "assistant", "content": response.get("text", "")}, {"role": "user", "content": feedback}]
            outcomes.append({"task": task["id"], "arm": arm, "attempts": attempts, "success": any(a["ok"] for a in attempts)})
    return finish("completed", len(generated), outcomes=outcomes, preflight=preflight,
                  summary={arm: {"tasks": 4, "successes": sum(x["success"] for x in outcomes if x["arm"] == arm),
                                 "attempts": sum(len(x["attempts"]) for x in outcomes if x["arm"] == arm)} for arm in ARMS},
                  limitations=["small locked model", "four single-site tasks", "restricted candidates",
                               "no overall productivity or causal-effect claim"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--model-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--clang", default="/usr/lib/llvm-20/bin/clang")
    parser.add_argument("--rustc", default="/tmp/hepta-ai-rust-1.90.0/bin/rustc")
    result = run_pilot(**vars(parser.parse_args()))
    print(json.dumps({k: v for k, v in result.items() if k != "outcomes"}))
    return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
