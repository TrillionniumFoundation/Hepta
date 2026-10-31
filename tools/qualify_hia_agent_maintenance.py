#!/usr/bin/env python3
"""Fresh paired maintenance pilot with two requested model tiers and real tools.

The generated answers are never repaired by the host. The hidden evaluator is
terminal, and author-written controls are explicitly separated from inference.
Freeze and commit the protocol, controls and all source identities before run.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True

from tools.hia_agent_codex_transport import (CodexEvents, EventFailure, canonical,
    identity, recover_reported_usage, run_owned, save, strict_json)

HERE = ROOT / "benchmarks/hia_agent_maintenance"
spec = importlib.util.spec_from_file_location("maintenance_tasks", HERE / "tasks.py")
TASK_MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TASK_MODULE)
TASKS = TASK_MODULE.TASKS
SCHEMA = "hepta.hia.program.v6"


def protocol():
    value = strict_json((HERE / "PROTOCOL.json").read_bytes())
    inherited = strict_json((ROOT / "benchmarks/hia_agent_public_tools/PROTOCOL.json").read_bytes())
    if (value.get("schema") != "hepta.hia.agent-maintenance.v1"
            or value.get("transport") != inherited["transport"]
            or value.get("models") != ["gpt-6.1-sol", "gpt-6-luna"]
            or value.get("tasks") != [task["id"] for task in TASKS]):
        raise ValueError("new maintenance protocol or inherited transport limits changed")
    return value


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def bindings():
    paths = list((ROOT / "hepta").glob("*.py")) + [Path(__file__),
        ROOT / "tools/hia_agent_codex_transport.py", HERE / "tasks.py", HERE / "PROTOCOL.json",
        ROOT / "tests/test_hia_agent_maintenance.py",
        ROOT / "benchmarks/hia_agent_public_tools/PROTOCOL.json",
        ROOT / "tools/fixtures/hia_agent_maintenance_resource.rs"]
    return {str(p.relative_to(ROOT)): identity(p)["sha256"] for p in sorted(paths)}


def tool_bindings():
    cfg = protocol()
    return {name: identity(cfg[name]) for name in ("codex", "clang", "rustc")}


def task_for(name):
    return next(task for task in TASKS if task["id"] == name)


def catalog(language):
    if language == "hia":
        from hepta.hia_opcodes import opcode_catalog
        from hepta.hia_schema import schema_registry
        registry = schema_registry()
        # Compatibility metadata stays available; the instruction payload is
        # exactly the selected schema, without a second latest-version catalog.
        registry.pop("instruction_catalog", None)
        return {"language": "hia", "selected_schema": SCHEMA,
                "registry": registry, "catalog": opcode_catalog(SCHEMA),
                "grammar": "A module has schema,module,exports,functions. A function has name,params,returns,effects,entry,blocks. A block has id,params,ops,term. Every value used by a block must be its own parameter or an earlier operation result. Operation fields are op,args,out,attrs; out/params are {name,type}. All successors explicitly pass arguments. Return term: {op:ret,values:[name]}; jump: {op:jump,target:block,args:[name]}; branch: {op:branch,cond:name,then:{target:block,args:[name]},else:{target:block,args:[name]}}. Use the exact catalog's names and attribute spelling; buffer owners and local loans must be consumed."}
    if language != "rust":
        raise ValueError("unsupported language")
    return {"language": "rust", "edition": "2021", "signature": "fn target(x:u32,y:u32)->u32",
            "available": "Safe Rust core language, scalar integer operations and standard prelude. wrapping_add/sub/mul, saturating_add/sub, min/max, rotate_right/left, casts, if/match, bounded loops, Vec<u8>, vec!, indexing and drop are available. unsafe is forbidden. No modules, filesystem/process/network access, external crates, include macros or inline assembly. The check tool actually invokes the registered rustc and executes all disclosed public cases.",
            "overflow": "Compile with overflow-checks=on; explicitly use wrapping methods when the specification requires modulo arithmetic.",
            "buffer_resize_only": "The driver supplies a safe audited Vec<u8> wrapper containing a real std::vec::Vec<u8>, and shadows vec![zero;length] and drop(Vec<u8>). Supported methods: len(), is_empty(), indexed read and indexed assignment. Those names must be used for the one required buffer. It checks the exact task length before allocating, then observes mutable access, matching actual indexed readback and explicit release. Other Vec methods or direct bookkeeping access are outside this selected exercise. This audits the selected API, not every allocator call or machine store instruction."}


def public_prompt(task, language):
    example = TASK_MODULE.program([TASK_MODULE.block("entry", ["x", "y"],
        [TASK_MODULE.op("bit.xor", ["x", "y"], "z")], TASK_MODULE.ret("z"))], effects=())
    result = {"task": task["id"], "contract": task["description"], "language": language,
            "previous_contract": task["previous_contract"],
            "initial_candidate": TASK_MODULE.initial(task["id"], language),
            "maintenance_scope": "Repair the supplied initial program for this new contract; submit a complete replacement through the same check/final API.",
            "public_cases": [{"args": args, "expected": TASK_MODULE.oracle(task["id"], *args)}
                             for args in task["public"]],
            "tools": {
                "catalog": {"request": {"action": "catalog"}, "result": "Complete selected HIA opcode catalog from the same source used by the checker, or Rust language/tool information."},
                "check": {"request": {"action": "check", "candidate": "HIA module object, or Rust source string"}, "result": "Actual verifier/compiler/public native results. Up to three public checks. Accepted builds return a candidate_digest usable by final."},
                "final": {"request": {"action": "final", "candidate_digest": "digest from a successful check"}, "alternative": {"action": "final", "candidate": "complete HIA object or Rust source"}, "result": "Terminal submission; no hidden feedback or retry."}},
            "budget": "At most six model responses including catalog/check/final; at most three check calls. Each response is exactly one JSON object matching a tool request. Return no Markdown. The host executes these public RPCs and returns actual feedback. You may revise only from public feedback. Do not invoke CLI tools, inspect files, browse or find reference answers. Existing user rules still apply.",
            "representation": example if language == "hia" else "fn target(x:u32,y:u32)->u32 { x ^ y }",
            "example_notice": "The example demonstrates the container/signature only and does not solve this task. Request catalog for complete operations and constraints."}
    if task["id"] == "buffer_resize" and language == "hia":
        result["resource_api"] = "The selected exercise requires actual buffer.new or buffer.try_new, buffer.store, buffer.load and owner.drop operations on the same owner, with the specified size/index/value and local loan cleanup. Public and terminal hidden VM executions observe this sequence; an uncalled helper or scalar shortcut cannot satisfy it. Repeated valid reads/writes are allowed. This is a VM resource witness, not a machine-instruction proof."
    if task["id"] == "buffer_resize" and language == "rust":
        result["resource_api"] = catalog("rust")["buffer_resize_only"]
    return result


def request_text(messages):
    return ("Solve this frozen coding task using only the complete public conversation below. "
            "Return exactly one requested JSON RPC object. Do not call any CLI tools, execute commands, "
            "read files, inspect repositories, browse, or obtain reference answers. The host will execute "
            "the catalog/check/final RPC and append its real result. Do not bypass existing rules or hooks.\n"
            + canonical(messages).decode() + "\nReturn only the next JSON RPC object.\n")


def candidate_constraints(task, language, candidate):
    if language == "hia":
        if type(candidate) is not dict or candidate.get("schema") != SCHEMA:
            raise ValueError("candidate must use selected schema " + SCHEMA)
        functions = candidate.get("functions", [])
        target = next((f for f in functions if f.get("name") == "target"), None)
        parameters = target.get("params") if target else None
        if (target is None or type(parameters) is not list or len(parameters) != 2
                or any(type(p) is not dict or p.get("type") != "u32" for p in parameters)
                or target.get("returns") != ["u32"] or candidate.get("exports") != ["target"]):
            raise ValueError("preserve exported target(x:u32,y:u32)->u32")
        ops = [op["op"] for f in functions for b in f.get("blocks", []) for op in b.get("ops", [])]
        if task["id"] == "buffer_resize" and (not {"buffer.new", "buffer.try_new"}.intersection(ops)
                or not {"buffer.store", "buffer.load", "owner.drop", "loan.end"} <= set(ops)):
            raise ValueError("buffer task requires allocation (buffer.new or buffer.try_new), store, load, loan cleanup and owner cleanup")
    else:
        if type(candidate) is not str or len(candidate.encode()) > 65536:
            raise ValueError("Rust candidate must be a bounded source string")
        # A benchmark source profile, not an OS isolation/security claim.
        if re.search(r"\b(unsafe|extern|mod|use|include|include_str|include_bytes|std|core|alloc|env|option_env|asm|global_asm)\b|::|#\s*!?\s*\[", candidate):
            raise ValueError("Rust candidate outside the registered safe scalar/Vec source profile")
        if not re.search(r"\bfn\s+target\s*\(", candidate):
            raise ValueError("missing target function")


def rust_driver(candidate, *, audit_buffer=False):
    if audit_buffer:
        return ("#![forbid(unsafe_code)]\n" + (ROOT / "tools/fixtures/hia_agent_maintenance_resource.rs").read_text() + "\n"
            "mod candidate {\nuse super::audited::{Vec, drop};\n"
            "macro_rules! vec { ($value:expr; $length:expr) => { super::audited::make_vec($value,$length) }; }\n"
            + candidate + "\npub fn invoke(x:u32,y:u32)->u32 {let target_contract:fn(u32,u32)->u32=target;target_contract(x,y)}\n}\n"
            "fn main(){use std::io::{self,Read};let mut s=String::new();io::stdin().read_to_string(&mut s).unwrap();"
            "let mut words=s.split_whitespace();while let Some(word)=words.next(){let x:u32=word.parse().unwrap();"
            "let y:u32=words.next().unwrap().parse().unwrap();audited::begin(x,y);let value=candidate::invoke(x,y);"
            "let ledger=audited::finish(value);println!(\"{}\",value);eprintln!(\"HIA_RUST_AUDIT {}\",ledger);}}\n")
    return ('#![forbid(unsafe_code)]\nuse std::io::{self,Read};\n' + candidate + '\nfn main(){let target_contract:fn(u32,u32)->u32=target;let mut s=String::new();io::stdin().read_to_string(&mut s).unwrap();let mut t=s.split_whitespace();while let Some(a)=t.next(){let x:u32=a.parse().unwrap();let y:u32=t.next().unwrap().parse().unwrap();println!("{}",target_contract(x,y));}}\n')


def execute_hia_contract(candidate, task, values):
    """Observe actual VM operations; dead source/helper declarations do not count.

    This is an execution witness for the registered cases, not machine-code
    refinement or a production-interpreter change. Original VM operations run
    unchanged inside a narrowly scoped observation wrapper.
    """
    from hepta.hia_program_runtime import _Machine, _underlying, execute_program
    events = []
    original = _Machine.operation

    def observe(machine, instruction, env, depth):
        name = instruction["op"]
        arguments = [env[n] for n in instruction["args"]]
        owner_id = (_underlying(arguments[0]).ident
                    if name in {"buffer.store", "buffer.load", "owner.drop"} else None)
        original(machine, instruction, env, depth)
        if name in {"buffer.new", "buffer.try_new"}:
            owner = env[instruction["out"][0]["name"]]
            events.append({"op": "allocate", "owner": owner.ident, "size": len(owner.data), "zeroed": not any(owner.data)})
        elif name == "buffer.store":
            events.append({"op": "store", "owner": owner_id, "index": arguments[1], "value": arguments[2]})
        elif name == "buffer.load":
            events.append({"op": "load", "owner": owner_id, "index": arguments[1], "value": env[instruction["out"][0]["name"]]})
        elif name == "owner.drop":
            events.append({"op": "drop", "owner": owner_id})

    with patch.object(_Machine, "operation", observe):
        report = execute_program(candidate, "target", values, max_steps=100000, max_heap_bytes=1048576)
    if report["result"] != TASK_MODULE.oracle(task["id"], *values):
        raise ValueError("interpreter result differs from the independent task oracle")
    resources = report["resources"]
    if resources["live_owners"] or resources["live_local_loans"]:
        raise ValueError("interpreter observed unresolved resources")
    if task["id"] == "buffer_resize":
        x, y = values
        size, value = x % 23 + 1, (x^y) % 256
        position = y % size
        allocations = [(i,e) for i,e in enumerate(events) if e["op"] == "allocate"]
        drops = [(i,e) for i,e in enumerate(events) if e["op"] == "drop"]
        if (resources["allocations"] != 1 or resources["frees"] != 1 or len(allocations) != 1 or len(drops) != 1):
            raise ValueError("buffer path must actually allocate and free exactly one owner")
        ai, allocation = allocations[0]
        di, dropped = drops[0]
        owner = allocation["owner"]
        writes = [i for i,e in enumerate(events) if e == {"op":"store","owner":owner,"index":position,"value":value}]
        reads = [i for i,e in enumerate(events) if e == {"op":"load","owner":owner,"index":position,"value":value}]
        if (allocation["size"] != size or not allocation["zeroed"] or dropped["owner"] != owner
                or not any(ai < wi < ri < di for wi in writes for ri in reads)):
            raise ValueError("buffer path lacks an actual matching allocate/store/load/drop sequence")
    return {"args": values, "result": report["result"], "resources": resources, "operation_events": events}


def evaluate_worker(args, *, tool_config=None):
    task = task_for(args.task)
    cfg = protocol() if tool_config is None else tool_config
    folder = Path(args.output)
    folder.mkdir(parents=True, exist_ok=False)
    result = {"accepted": False, "correct": False, "status": "starting", "hidden_evaluated": args.mode == "hidden"}
    try:
        if args.mode == "hidden":
            build = strict_json(Path(args.build).read_bytes())
            if identity(build["binary"]["path"]) != build["binary"]:
                raise ValueError("native artifact identity changed before hidden execution")
            binary = Path(build["binary"]["path"])
            if identity(build["candidate"]["path"]) != build["candidate"]:
                raise ValueError("candidate source changed before hidden contract execution")
            candidate = strict_json(Path(build["candidate"]["path"]).read_bytes())
            if args.language == "hia":
                result["interpreter"] = [execute_hia_contract(candidate, task, values)
                    for values in TASK_MODULE.cases(task, hidden=True)]
        else:
            from hepta.hia_program import verify_program
            from hepta.hia_program_llvm import build_program_native
            candidate = strict_json(Path(args.candidate).read_bytes())
            result["candidate"] = identity(args.candidate)
            candidate_constraints(task, args.language, candidate)
            result["candidate_profile_admitted"] = True
            binary = folder / "candidate"
            if args.language == "hia":
                verified = verify_program(candidate)
                result["structural_admitted"] = True
                resource_checks = []
                for values in task["public"]:
                    resource_checks.append(execute_hia_contract(verified, task, values))
                result["interpreter"] = resource_checks
                result["native_compile"] = build_program_native(verified, folder / "program.o", clang=cfg["clang"], kind="object")
                driver = folder / "driver.c"
                driver.write_text('#include <stdint.h>\n#include <stdio.h>\nextern uint32_t target(uint32_t,uint32_t);\nint main(void){unsigned x,y;while(scanf("%u %u",&x,&y)==2)printf("%u\\n",target(x,y));return 0;}\n')
                command = [cfg["clang"], "-O2", str(driver), str(folder / "program.o"), "-o", str(binary)]
            else:
                driver = folder / "main.rs"
                driver.write_text(rust_driver(candidate, audit_buffer=task["id"] == "buffer_resize"))
                command = [cfg["rustc"], "--edition=2021", "-C", "opt-level=2", "-C", "overflow-checks=on", "-C", "strip=symbols", "-C", "panic=abort", str(driver), "-o", str(binary)]
            compile_started = time.monotonic_ns()
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=35)
            result["compile"] = {"argv": command, "returncode": compiled.returncode, "stdout": compiled.stdout, "stderr": compiled.stderr, "wall_ns": time.monotonic_ns()-compile_started}
            if compiled.returncode:
                result["status"] = "compile_rejected"
                save(folder / "RESULT.json", result)
                return 0
        before = identity(binary)
        values = TASK_MODULE.cases(task, hidden=args.mode == "hidden")
        expected = [TASK_MODULE.oracle(task["id"], *pair) for pair in values]
        entered = time.monotonic_ns()
        execution = subprocess.run([str(binary)], input="".join(f"{x} {y}\n" for x,y in values), capture_output=True, text=True, timeout=8)
        try:
            actual = [int(line) for line in execution.stdout.splitlines()]
        except ValueError:
            actual = None
        correct = execution.returncode == 0 and actual == expected and identity(binary) == before
        if args.language == "rust" and task["id"] == "buffer_resize":
            prefix = "HIA_RUST_AUDIT "
            lines = execution.stderr.splitlines()
            ledgers = [strict_json(line[len(prefix):]) for line in lines if line.startswith(prefix)]
            valid_ledgers = len(ledgers) == len(values) and len(lines) == len(ledgers)
            for epoch, (ledger, (x,y)) in enumerate(zip(ledgers, values), 1):
                length = x % 23 + 1
                valid_ledgers &= (ledger.get("schema") == "hepta.agent.rust-vec-api-audit.v1"
                    and ledger.get("epoch") == epoch and ledger.get("length") == length
                    and ledger.get("index") == y % length and ledger.get("expected_byte") == (x^y) % 256
                    and [ledger.get(key) for key in ("allocations", "releases", "explicit_releases", "live")] == [1,1,1,0]
                    and type(ledger.get("matched_reads")) is int and ledger["matched_reads"] > 0)
            result["resource_audit"] = {"scope": "selected audited Vec API events; not whole-process allocator or machine instruction counting",
                                        "accepted": valid_ledgers, "ledgers": ledgers}
            correct &= valid_ledgers
        result.update(accepted=correct, correct=correct, status="accepted" if correct else "cases_failed", binary=before,
                      execution={"returncode": execution.returncode, "stdout": execution.stdout, "stderr": execution.stderr,
                                 "wall_ns": time.monotonic_ns()-entered, "case_count": len(values), "expected": expected, "actual": actual})
    except Exception as exc:
        result.update(status="candidate_rejected", error={"type": type(exc).__name__, "message": str(exc)})
    save(folder / "RESULT.json", result)
    return 0


class WallBudgetExhausted(TimeoutError):
    """Refuse a new owned call without claiming a child was launched."""

    def __init__(self, phase, deadline, observed):
        super().__init__(phase + " work budget exhausted before owner call")
        self.record = {"phase": phase, "work_deadline_monotonic": deadline,
                       "observed_monotonic": observed, "remaining_seconds": deadline-observed,
                       "owner_call_attempted": False}


def admitted_wall_seconds(phase, limit, deadline):
    if deadline is None:
        return limit
    observed = time.monotonic()
    remaining = deadline-observed
    if remaining <= 0:
        raise WallBudgetExhausted(phase, deadline, observed)
    return min(limit, remaining)


class CleanupUncertain(RuntimeError):
    """An owned call cannot permit another launch in this experiment."""

    def __init__(self, phase, process, output, wall_ns, transport_error=None):
        super().__init__("uncertain " + phase + " process cleanup; stop experiment")
        self.record = {"phase": phase, "process": process,
                       "transport_directory": str(output),
                       "transport_call_wall_ns": wall_ns,
                       "transport_error": transport_error}
        self.observation = None


def cleanup_confirmed(process):
    return (type(process) is dict and process.get("cleanup_confirmed") is True
            and process.get("leader_reaped") is True
            and process.get("status") != "cleanup_uncertain")


def checked_owned(phase, argv, cwd, output, *, deadline=None, **kwargs):
    # Reuse the existing owner unchanged. No outcome, including an apparently
    # successful evaluator or model response, supersedes its cleanup receipt.
    # Recheck after request/evaluator preparation, immediately before handing
    # work to the owner. This is admission, not OS preemption. A refusal here
    # never entered run_owned and must not become uncertain process cleanup.
    kwargs["wall_seconds"] = admitted_wall_seconds(phase, kwargs["wall_seconds"], deadline)
    started = time.monotonic_ns()
    try:
        process = run_owned(argv, cwd, output, **kwargs)
    except BaseException as exc:
        # The owner may have launched and retained raw evidence before its
        # receipt publication failed. Missing confirmation is never a retry.
        raise CleanupUncertain(phase, None, output, time.monotonic_ns()-started,
            {"type": type(exc).__name__, "message": str(exc)}) from exc
    if not cleanup_confirmed(process):
        raise CleanupUncertain(phase, process, output, time.monotonic_ns()-started)
    return process


def evaluate(task, language, folder, *, candidate=None, build=None, timeout=70, deadline=None):
    hidden = build is not None
    phase = "hidden" if hidden else "public"
    admitted_wall_seconds(phase, timeout, deadline)
    folder.mkdir(parents=True, exist_ok=False)
    argv = [sys.executable, str(Path(__file__).resolve()), "_evaluate", "--task", task["id"],
            "--language", language, "--mode", "hidden" if hidden else "public", "--output", str(folder / "evaluation")]
    if hidden:
        save(folder / "BUILD.json", build)
        argv.extend(["--build", str(folder / "BUILD.json")])
    else:
        save(folder / "CANDIDATE.json", candidate)
        argv.extend(["--candidate", str(folder / "CANDIDATE.json")])
    try:
        process = checked_owned(phase, argv, ROOT, folder / "transport",
                                wall_seconds=timeout, deadline=deadline)
    except CleanupUncertain as exc:
        exc.observation = {"accepted": False, "correct": False, "hidden_evaluated": hidden,
                           "status": "evaluation_cleanup_uncertain", "process": exc.record["process"],
                           "cleanup_uncertainty": exc.record}
        raise
    receipt = folder / "evaluation/RESULT.json"
    if process["status"] != "exited" or not receipt.is_file():
        return {"accepted": False, "correct": False, "hidden_evaluated": hidden,
                "status": "evaluation_runtime_failure", "process": process}
    result = strict_json(receipt.read_bytes())
    result["process"] = process
    return result


def public_feedback(result, digest):
    # No hidden data can be present: this function accepts only public results.
    if result.get("hidden_evaluated"):
        raise ValueError("hidden feedback is terminal and cannot be published")
    return {"candidate_digest": digest if result["accepted"] else None,
            "accepted": result["accepted"], "status": result["status"],
            **{key: result[key] for key in ("error", "compile", "interpreter", "resource_audit", "execution") if key in result}}


def controls(output):
    started = time.monotonic_ns()
    folder = Path(output).resolve()
    folder.mkdir(parents=True, exist_ok=False)
    result = {"schema": "hepta.hia.agent-maintenance.controls.v1", "bindings": bindings(), "tools": tool_bindings(),
              "catalogs": {lang: hashlib.sha256(canonical(catalog(lang))).hexdigest() for lang in ("hia", "rust")},
              "model_requests": 0, "reference_controls_are_model_successes": False, "rows": [], "passed": False}
    save(folder / "RESULT.json", result)
    for task in TASKS:
        for lang in ("hia", "rust"):
            cell = folder / (task["id"] + "-" + lang)
            cell.mkdir()
            good = evaluate(task, lang, cell / "good", candidate=TASK_MODULE.reference(task["id"], lang))
            hidden = evaluate(task, lang, cell / "hidden", build=good) if good["accepted"] else None
            bad_candidate = TASK_MODULE.program([TASK_MODULE.block("entry", ["x", "y"], [TASK_MODULE.const("z", 0)], TASK_MODULE.ret("z"))]) if lang == "hia" else "fn target(x:u32,y:u32)->u32 { 0 }"
            bad = evaluate(task, lang, cell / "bad", candidate=bad_candidate)
            unchanged = evaluate(task, lang, cell / "unchanged-initial", candidate=TASK_MODULE.initial(task["id"], lang))
            if lang == "rust":
                original = TASK_MODULE.reference(task["id"], lang)
                body = original[original.index("{")+1:original.rindex("}")]
                bad_signature = "fn target(x:u32,y:u32)->u64 { let value:u32={" + body + "};value as u64 }"
            else:
                bad_signature = TASK_MODULE.reference(task["id"], lang)
                bad_signature["functions"][0]["returns"] = ["u64"]
            signature = evaluate(task, lang, cell / "bad-signature", candidate=bad_signature)
            lifecycle = None
            if task["id"] == "buffer_resize":
                bad_lifecycle = TASK_MODULE.reference(task["id"], lang)
                if lang == "rust":
                    bad_lifecycle = bad_lifecycle.replace("drop(data);", "")
                else:
                    block = bad_lifecycle["functions"][0]["blocks"][0]
                    block["ops"] = [op for op in block["ops"] if op["op"] != "owner.drop"]
                lifecycle = evaluate(task, lang, cell / "bad-lifecycle", candidate=bad_lifecycle)
            row = {"task": task["id"], "language": lang, "reference_public": good["accepted"],
                   "reference_hidden": bool(hidden and hidden["correct"]), "wrong_control_rejected": not bad["accepted"],
                   "wrong_signature_rejected": not signature["accepted"],
                   "unmaintained_initial_rejected": not unchanged["accepted"],
                   "missing_explicit_release_rejected": lifecycle is None or not lifecycle["accepted"]}
            result["rows"].append(row)
            save(folder / "RESULT.json", result)
            print(json.dumps(row), flush=True)
    result["passed"] = len(result["rows"]) == 6 and all(all(row[key] for key in ("reference_public", "reference_hidden", "wrong_control_rejected", "wrong_signature_rejected", "unmaintained_initial_rejected", "missing_explicit_release_rejected")) for row in result["rows"])
    result["wall_ns"] = time.monotonic_ns()-started
    result["unchanged"] = result["bindings"] == bindings() and result["tools"] == tool_bindings()
    result["passed"] &= result["unchanged"]
    save(folder / "RESULT.json", result)
    return 0 if result["passed"] else 1


def freeze(controls_path):
    if (HERE / "FREEZE.json").exists():
        raise ValueError("freeze already exists; never replace a registered study")
    record = strict_json(Path(controls_path).read_bytes())
    source, tools = bindings(), tool_bindings()
    if not record.get("passed") or record.get("model_requests") != 0 or record.get("bindings") != source or record.get("tools") != tools:
        raise ValueError("current exact-source no-generation controls required")
    # Frozen implementation must already be tracked and committed.
    for name, digest in source.items():
        committed = subprocess.check_output(["git", "show", "HEAD:" + name], cwd=ROOT)
        if hashlib.sha256(committed).hexdigest() != digest:
            raise ValueError("uncommitted source: " + name)
    result = {"schema": "hepta.hia.agent-maintenance.freeze.v1", "code_commit": git("rev-parse", "HEAD"),
              "bindings": source, "tools": tools, "controls": identity(controls_path),
              "catalogs": record["catalogs"], "created_unix_ns": time.time_ns(), "model_requests_before_freeze": 0,
              "prompts": {t["id"] + ":" + l: hashlib.sha256(canonical(public_prompt(t,l))).hexdigest() for t in TASKS for l in ("hia", "rust")}}
    save(HERE / "FREEZE.json", result)
    print(json.dumps({"freeze": identity(HERE / "FREEZE.json"), "code_commit": result["code_commit"]}))
    return 0


def verify_freeze():
    value = strict_json((HERE / "FREEZE.json").read_bytes())
    if value["bindings"] != bindings() or value["tools"] != tool_bindings():
        raise ValueError("registered source/tool identity drift")
    if value["catalogs"] != {lang: hashlib.sha256(canonical(catalog(lang))).hexdigest() for lang in ("hia", "rust")}:
        raise ValueError("registered catalog drift")
    if identity(value["controls"]["path"]) != value["controls"]:
        raise ValueError("registered no-generation controls changed")
    return value


def parse_action(text):
    from hepta.hia_program_tools import decode_json
    action = decode_json(text)
    if (type(action) is not dict or type(action.get("action")) is not str
            or action["action"] not in {"catalog", "check", "final"}):
        raise ValueError("one catalog/check/final JSON object required")
    name = action["action"]
    allowed = [{"action"}] if name == "catalog" else [{"action", "candidate"}] if name == "check" else [{"action", "candidate"}, {"action", "candidate_digest"}]
    if set(action) not in allowed:
        raise ValueError("incorrect RPC fields; preserve exact request schema")
    if "candidate_digest" in action and (type(action["candidate_digest"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", action["candidate_digest"]) is None):
        raise ValueError("candidate_digest must be a 64-character lowercase hexadecimal digest from an accepted check")
    return action


def run_cell(task, language, folder, experiment_deadline, cfg):
    started = time.monotonic_ns()
    deadline = min(experiment_deadline, time.monotonic()+cfg["max_cell_wall_seconds"])
    work_deadline = deadline-cfg["cleanup_reserve_seconds"]
    folder.mkdir()
    messages = [{"role": "user", "content": public_prompt(task, language)}]
    row = {"task": task["id"], "language": language, "model": cfg["model"], "correct": False, "hidden_evaluated": False,
           "requests": [], "tool_calls": [], "charged_tokens": 0, "status": "starting", "human_answer_repairs": 0,
           "experiment_poisoned": False}
    approved = {}
    public_checks = 0
    for index in range(cfg["max_requests_per_cell"]):
        remaining = deadline-time.monotonic()-cfg["cleanup_reserve_seconds"]
        if remaining <= 0:
            row["status"] = "wall_budget"
            break
        request_folder = folder / f"request-{index}"
        request_folder.mkdir()
        cwd = Path(tempfile.mkdtemp(prefix="hia-agent-model-cwd-", dir="/tmp"))
        text = request_text(messages)
        save(request_folder / "REQUEST.json", {"messages": messages, "text_sha256": hashlib.sha256(text.encode()).hexdigest()})
        events = CodexEvents(cfg["registered_startup_warnings"])
        receipt = {"index": index, "usage": None, "observed_usage": None, "unknown_usage": True, "actual_generation_observed": False}
        row["requests"].append(receipt)
        save(folder / "CELL.json", row)
        try:
            command = [cfg["codex"], "exec", "--json", "--ephemeral", "--sandbox", "read-only", "--skip-git-repo-check", "-m", cfg["model"], "-"]
            receipt["process"] = checked_owned("model", command, cwd, request_folder / "transport", input_bytes=text.encode(),
                                            wall_seconds=cfg["max_request_wall_seconds"], deadline=work_deadline, on_line=events.line)
            receipt["actual_generation_observed"] = events.turn_count > 0
            receipt["observed_usage"] = recover_reported_usage(request_folder / "transport/stdout.raw") or events.usage
            if receipt["observed_usage"] is not None:
                u = receipt["observed_usage"]
                receipt["charged_tokens"] = u["input_tokens"]+u["output_tokens"]+u["reasoning_output_tokens"]
            row["charged_tokens"] = sum(r.get("charged_tokens",0) for r in row["requests"])
            if receipt["process"]["status"] != "exited":
                raise EventFailure("model transport: " + receipt["process"]["status"])
            answer = events.complete()
            if receipt["observed_usage"] != answer["usage"]:
                raise EventFailure("inconsistent full-stream usage receipt")
            receipt["usage"] = answer["usage"]
            receipt["unknown_usage"] = False
            save(request_folder / "ANSWER.json", answer)
            u = answer["usage"]
            if (u["input_tokens"] > cfg["max_reported_input_tokens_per_request"]
                    or u["output_tokens"]+u["reasoning_output_tokens"] > cfg["max_charged_output_tokens_per_request"]
                    or row["charged_tokens"] > cfg["max_charged_tokens_per_cell"]):
                raise EventFailure("observed token budget exceeded")
            messages.append({"role": "assistant", "content": answer["text"]})
            try:
                action = parse_action(answer["text"])
            except (ValueError, RecursionError) as exc:
                feedback = {"status": "rpc_rejected", "error": str(exc)}
                row["tool_calls"].append({"name": "invalid", "feedback": feedback})
                messages.append({"role": "user", "content": feedback})
                continue
            name = action["action"]
            tool_started = time.monotonic_ns()
            call = {"name": name}
            row["tool_calls"].append(call)
            if name == "catalog":
                feedback = catalog(language)
            elif name == "check" or "candidate" in action:
                if name == "check" and public_checks >= cfg["max_public_checks_per_cell"]:
                    feedback = {"status": "public_check_budget_exhausted", "error": "final an already accepted digest or submit a final candidate"}
                else:
                    public_checks += int(name == "check")
                    candidate = action["candidate"]
                    digest = hashlib.sha256(canonical(candidate)).hexdigest()
                    try:
                        observed = evaluate(task, language, request_folder / "public", candidate=candidate,
                                            timeout=70, deadline=work_deadline)
                    except CleanupUncertain as exc:
                        call["public"] = exc.observation
                        raise
                    finally:
                        call["wall_ns"] = time.monotonic_ns()-tool_started
                    call["public"] = observed
                    feedback = public_feedback(observed, digest)
                    if observed["accepted"]:
                        approved[digest] = observed
                    if name == "final":
                        action = {"action": "final", "candidate_digest": digest}
            elif name == "final":
                feedback = {"status": "final_received"}
            call["wall_ns"] = time.monotonic_ns()-tool_started
            if name == "final":
                build = approved.get(action.get("candidate_digest"))
                if build is None:
                    row["status"] = "final_not_publicly_accepted"
                    break
                hidden_started = time.monotonic_ns()
                try:
                    hidden = evaluate(task, language, request_folder / "hidden", build=build,
                                      timeout=30, deadline=work_deadline)
                except CleanupUncertain as exc:
                    row["hidden_evaluated"] = True
                    # Record poison before writing optional hidden evidence;
                    # a write failure cannot downgrade the stop condition.
                    row.update(experiment_poisoned=True, cleanup_uncertainty=exc.record)
                    save(request_folder / "HIDDEN.json", exc.observation)
                    raise
                finally:
                    row["hidden_wall_ns"] = time.monotonic_ns()-hidden_started
                row.update(hidden_evaluated=True, hidden_wall_ns=time.monotonic_ns()-hidden_started,
                           correct=hidden["correct"], status="correct" if hidden["correct"] else "hidden_failed")
                save(request_folder / "HIDDEN.json", hidden)
                # Hidden result is terminal and is not added to messages.
                break
            call["feedback_sha256"] = hashlib.sha256(canonical(feedback)).hexdigest()
            save(request_folder / "PUBLIC_FEEDBACK.json", feedback)
            messages.append({"role": "user", "content": feedback})
        except Exception as exc:
            receipt["error"] = {"type": type(exc).__name__, "message": str(exc)}
            if isinstance(exc, CleanupUncertain):
                row.update(experiment_poisoned=True, cleanup_uncertainty=exc.record)
                if exc.record["phase"] == "model" and exc.record["process"] is not None:
                    receipt["process"] = exc.record["process"]
            if isinstance(exc, WallBudgetExhausted):
                row["wall_budget_refusal"] = exc.record
                if exc.record["phase"] == "model":
                    receipt["model_launch_refused"] = True
            if row["experiment_poisoned"]:
                row["status"] = "terminal_cleanup_uncertain"
            elif isinstance(exc, WallBudgetExhausted):
                row["status"] = "wall_budget"
            else:
                row["status"] = "terminal_runtime_or_protocol_failure"
            receipt["actual_generation_observed"] = events.turn_count > 0
            if receipt.get("observed_usage") is None and not receipt.get("model_launch_refused"):
                try:
                    receipt["observed_usage"] = recover_reported_usage(request_folder / "transport/stdout.raw") or events.usage
                except Exception as usage_error:
                    receipt["usage_recovery_error"] = {"type": type(usage_error).__name__, "message": str(usage_error)}
                    receipt["observed_usage"] = events.usage
                if receipt["observed_usage"] is not None:
                    receipt["charged_tokens"] = sum(receipt["observed_usage"][k] for k in ("input_tokens", "output_tokens", "reasoning_output_tokens"))
            row["charged_tokens"] = sum(r.get("charged_tokens",0) for r in row["requests"])
            break
        finally:
            receipt["cwd_entries_after"] = sorted(p.name for p in cwd.iterdir())
            if not receipt["cwd_entries_after"] and (cleanup_confirmed(receipt.get("process"))
                                                     or receipt.get("model_launch_refused")):
                cwd.rmdir()
                receipt["empty_cwd_removed"] = True
            else:
                receipt["empty_cwd_removed"] = False
            save(request_folder / "RECEIPT.json", receipt)
            save(folder / "CELL.json", row)
    if row["status"] == "starting":
        row["status"] = "request_budget_exhausted"
    row["public_failed_checks"] = sum("public" in c and not c["public"]["accepted"] for c in row["tool_calls"])
    row["wall_ns"] = time.monotonic_ns()-started
    row["complete_usage"] = bool(row["requests"]) and all(not r["unknown_usage"] for r in row["requests"])
    save(folder / "CELL.json", row)
    return row


def summary(rows):
    grouped = {}
    for model in protocol()["models"]:
        groups = {}
        for language in ("hia", "rust"):
            selected = [r for r in rows if r["model"] == model and r["language"] == language]
            complete = len(selected) == len(TASKS) and all(r["complete_usage"] for r in selected)
            groups[language] = {"attempted": len(selected), "correct": sum(r["correct"] for r in selected),
                "requests": sum(len(r["requests"]) for r in selected),
                "charged_tokens": sum(r["charged_tokens"] for r in selected),
                "complete_usage": complete,
                "failed_public_checks": sum(r["public_failed_checks"] for r in selected),
                "wall_ns": sum(r["wall_ns"] for r in selected)}
        h, r = groups["hia"], groups["rust"]
        gate = (h["complete_usage"] and r["complete_usage"] and h["correct"] >= r["correct"] and h["correct"] > 0
                and h["charged_tokens"] < r["charged_tokens"] and h["wall_ns"] < r["wall_ns"]
                and h["failed_public_checks"] <= r["failed_public_checks"])
        grouped[model] = {"groups": groups, "descriptive_hia_advantage_gate": gate}
    return {"by_requested_model": grouped, "general_productivity_proved": False,
            "cross_model_pooling_used": False, "human_review_time_ns": None,
            "human_cost_advantage_proved": False, "full_cost_advantage_proved": False,
            "population_task_representativeness": False,
            "cpp_library_upgrade_representativeness": False,
            "provider_model_identity_independently_attested": False,
            "warm_cache_or_provider_scheduling_controlled": False}


def language_order(task_index, model, cfg):
    """Counterbalance against the model's stable registered index."""
    stable_model_index = cfg["models"].index(model)
    return ("hia", "rust") if (task_index + stable_model_index) % 2 == 0 else ("rust", "hia")


def run(output, review_path, registration_commit):
    started = time.monotonic_ns()
    cfg, frozen = protocol(), verify_freeze()
    review = strict_json(Path(review_path).read_bytes())
    if (review.get("decision") != "allow_generation" or review.get("freeze_sha256") != identity(HERE / "FREEZE.json")["sha256"]
            or review.get("controls_sha256") != frozen["controls"]["sha256"] or review.get("model_requests_by_reviewer") != 0):
        raise ValueError("independent exact-freeze review required")
    registered = subprocess.check_output(["git", "show", registration_commit+":benchmarks/hia_agent_maintenance/FREEZE.json"], cwd=ROOT)
    if registered != (HERE / "FREEZE.json").read_bytes():
        raise ValueError("registration commit does not bind current freeze")
    subprocess.run(["git", "merge-base", "--is-ancestor", registration_commit, "HEAD"], cwd=ROOT, check=True)
    folder = Path(output).resolve()
    folder.mkdir(parents=True, exist_ok=False)
    result = {"schema": "hepta.hia.agent-maintenance.result.v1", "freeze": identity(HERE / "FREEZE.json"),
              "registration_commit": registration_commit, "review": identity(review_path), "models": cfg["models"],
              "cells": [], "status": "started", "previous_negative_results_replaced": False, "human_answer_repairs": 0,
              "experiment_poisoned": False}
    save(folder / "PLAN.json", {**result, "frozen": frozen, "protocol": cfg, "model_requests_before_plan": 0})
    deadline = time.monotonic()+cfg["max_experiment_wall_seconds"]
    try:
        for index, task in enumerate(TASKS):
            models = cfg["models"] if index % 2 == 0 else list(reversed(cfg["models"]))
            for model in models:
                languages = language_order(index, model, cfg)
                for language in languages:
                    verify_freeze()
                    if time.monotonic()+cfg["cleanup_reserve_seconds"] >= deadline:
                        raise TimeoutError("experiment wall budget")
                    cell_cfg = {**cfg, "model": model}
                    row = run_cell(task, language, folder / (task["id"]+"-"+model+"-"+language), deadline, cell_cfg)
                    result["cells"].append(row)
                    if row["experiment_poisoned"]:
                        result.update(experiment_poisoned=True, cleanup_uncertainty=row["cleanup_uncertainty"])
                    result["summary"] = summary(result["cells"])
                    save(folder / "RESULT.json", result)
                    print(json.dumps({"task": task["id"], "model": model, "language": language,
                                      "correct": row["correct"], "status": row["status"],
                                      "requests": len(row["requests"])}), flush=True)
                    if result["experiment_poisoned"]:
                        raise RuntimeError("uncertain process cleanup; stop remaining cells")
                    if row["status"] == "terminal_runtime_or_protocol_failure":
                        process = row["requests"][-1].get("process", {}) if row["requests"] else {}
                        if not cleanup_confirmed(process):
                            raise RuntimeError("uncertain process cleanup; stop remaining cells")
                        # This exact cell is terminal and never rerun. Other
                        # preregistered cells remain distinct observations.
        result["status"] = "all_cells_attempted"
    except Exception as exc:
        result.update(status="incomplete", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        result["summary"] = summary(result["cells"])
        result["wall_ns"] = time.monotonic_ns()-started
        try:
            verify_freeze()
            result["identities_unchanged"] = True
        except Exception as exc:
            result["identities_unchanged"] = False
            result["identity_error"] = str(exc)
        for model_group in result["summary"]["by_requested_model"].values():
            model_group["descriptive_hia_advantage_gate"] &= bool(result["status"] == "all_cells_attempted" and result["identities_unchanged"])
        save(folder / "RESULT.json", result)
    return 0 if result["status"] == "all_cells_attempted" and result["identities_unchanged"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("controls"); p.add_argument("--output", required=True)
    p = sub.add_parser("freeze"); p.add_argument("--controls", required=True)
    p = sub.add_parser("run"); p.add_argument("--output", required=True); p.add_argument("--review", required=True); p.add_argument("--registration-commit", required=True)
    p = sub.add_parser("_evaluate")
    p.add_argument("--task", required=True); p.add_argument("--language", choices=("hia","rust"), required=True)
    p.add_argument("--mode", choices=("public","hidden"), required=True); p.add_argument("--output", required=True)
    p.add_argument("--candidate"); p.add_argument("--build")
    args = parser.parse_args(argv)
    if args.command == "controls": return controls(args.output)
    if args.command == "freeze": return freeze(args.controls)
    if args.command == "run": return run(args.output, args.review, args.registration_commit)
    return evaluate_worker(args)


if __name__ == "__main__":
    raise SystemExit(main())
