"""Matched two-file evaluator; no model response is repaired by this module.

The existing finite scalar source gate is reused unchanged. Every admitted
candidate is compiled and executed from a sealed executable snapshot. HIA
provider observations are explicitly Core-VM observations, separate from the
native entrypoint execution. Rust uses a trusted native wrapper.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import os
from pathlib import Path
import resource
import subprocess
import time

from experiments.hia_optimizer_eval.next_20261028 import upgrade_pilot as previous
from experiments.hia_agent_matched_v3_20261028.fixtures import FILE_NAMES, MAX64, provider_values
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import build_program_native
from tools.provider_adapter.llama_cpp_engine import canonical, file_identity


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def parse_files(task, language, text, *, enforce_contract=True):
    parsed, receipt = previous.parse_files(task, language, text, enforce_contract=enforce_contract)
    if language == "hia":
        for function in parsed.as_dict()["functions"]:
            blocks = {b["id"]: b for b in function["blocks"]}
            if len(blocks) > 16 or sum(len(b["ops"]) for b in blocks.values()) > 128:
                raise ValueError("E_MATCHED_HIA_SIZE: at most 16 blocks / 128 operations per function")
            active, finished = set(), set()

            def visit(name):
                if name in active:
                    raise ValueError("E_MATCHED_HIA_LOOP: acyclic scalar profile required")
                if name in finished:
                    return
                active.add(name)
                term = blocks[name]["term"]
                for edge in ([term] if term["op"] == "jump" else
                             [term["then"], term["else"]] if term["op"] == "branch" else []):
                    visit(edge["target"])
                active.remove(name); finished.add(name)

            visit(function["entry"])
    return parsed, receipt


def rust_driver(task):
    """Wrap the exact submitted API without editing either submitted file."""
    name = task["provider"]
    parameters = ",".join(n + ":" + typ for n, typ in task["provider_params"])
    names = ",".join(n for n, _ in task["provider_params"])
    returns = task["provider_returns"]
    return_type = returns[0] if len(returns) == 1 else "(" + ",".join(returns) + ")"
    direct = "api_original::" + name + "(v[0],v[1])"
    if len(returns) == 1:
        provider = "let p0=" + direct + ";"
        fmt, values = "{} {} {} {}", "answer,calls,matches,p0 as u64"
    else:
        provider = "let (p0,p1)=" + direct + ";"
        fmt, values = "{} {} {} {} {}", "answer,calls,matches,p0 as u64,p1 as u64"
    return f'''#![forbid(unsafe_code)]
#[path="api.rs"] mod api_original;
mod api {{
    use std::sync::atomic::{{AtomicU64,Ordering}};
    static CALLS:AtomicU64=AtomicU64::new(0);
    static ARG0:AtomicU64=AtomicU64::new(0);
    static ARG1:AtomicU64=AtomicU64::new(0);
    static BAD:AtomicU64=AtomicU64::new(0);
    pub fn reset(a:u32,b:u32) {{ CALLS.store(0,Ordering::SeqCst);BAD.store(0,Ordering::SeqCst);ARG0.store(a as u64,Ordering::SeqCst);ARG1.store(b as u64,Ordering::SeqCst); }}
    pub fn count()->u64 {{ CALLS.load(Ordering::SeqCst) }}
    pub fn matches()->u64 {{ if BAD.load(Ordering::SeqCst)==0 {{1}} else {{0}} }}
    pub fn {name}({parameters})->{return_type} {{
        CALLS.fetch_add(1,Ordering::SeqCst);
        if a as u64 != ARG0.load(Ordering::SeqCst) || b as u64 != ARG1.load(Ordering::SeqCst) {{ BAD.store(1,Ordering::SeqCst); }}
        super::api_original::{name}({names})
    }}
}}
mod client;
use std::io::{{self,BufRead}};
fn main() {{
    let entry:fn(u32,u32,u32)->u64=client::entrypoint;
    for line in io::stdin().lock().lines() {{
        let line=line.unwrap();let v:Vec<u32>=line.split_whitespace().map(|x|x.parse().unwrap()).collect();
        api::reset(v[0],v[1]);let answer=entry(v[0],v[1],v[2]);let calls=api::count();let matches=api::matches();
        {provider}
        println!("{fmt}",{values});
    }}
}}
'''


def hia_audit(built, task, cases):
    from hepta.hia_program_runtime import _Machine, HIAProgramTrap, HIAProgramBudgetExceeded
    checked = verify_program(Path(built["core_path"]).read_bytes())
    if checked.sha256 != built["core_sha256"]:
        raise RuntimeError("E_MATCHED_CORE_DRIFT")

    class ObservedMachine(_Machine):
        def __init__(self):
            super().__init__(checked, 10_000, 0, None, 16)
            self.calls = []

        def invoke(self, function, arguments, depth=0):
            event = {"function": function["name"], "arguments": list(arguments), "returned": False}
            self.calls.append(event)
            values = super().invoke(function, arguments, depth)
            event.update(returned=True, values=list(values))
            return values

    def run(name, arguments):
        machine = ObservedMachine()
        try:
            values = machine.invoke(machine.functions[name], arguments)
            status = "returned"
        except (HIAProgramTrap, HIAProgramBudgetExceeded):
            values, status = None, "trapped_or_budget_exceeded"
        if machine.owners or machine.chains or machine.loans_started != machine.loans_ended:
            raise RuntimeError("scalar profile leaked a resource")
        return {"status": status, "values": values, "calls": machine.calls}

    rows = []
    for case in cases:
        entry, provider = run("entrypoint", list(case)), run(task["provider"], list(case[:2]))
        calls = [c for c in entry["calls"] if c["function"] == task["provider"]]
        rows.append({"case": list(case), "entry": entry, "provider": provider,
                     "call_count": len(calls), "arguments_match": len(calls) == 1 and calls[0]["arguments"] == list(case[:2])})
    if verify_program(Path(built["core_path"]).read_bytes()).sha256 != checked.sha256:
        raise RuntimeError("E_MATCHED_CORE_DRIFT")
    return rows


def build(task, language, text, folder, clang, rustc, *, enforce_contract=True):
    folder = Path(folder); folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    record = {"language": language, "task_id": task["id"], "status": "response_rejected",
              "native_built": False, "provider_audit": enforce_contract, "folder": str(folder)}
    try:
        parsed, receipt = parse_files(task, language, text, enforce_contract=enforce_contract)
        record.update(patch_receipt=receipt, status="infrastructure_failure")
        compiler = file_identity(clang if language == "hia" else rustc)
        record["compiler"] = compiler
        binary = folder / "candidate"
        if language == "hia":
            core = folder / "candidate.hia.json"; core.write_bytes(parsed.canonical_bytes)
            record.update(core_path=str(core), core_sha256=parsed.sha256)
            record["native_receipt"] = build_program_native(parsed, folder / "candidate.o", clang=clang, kind="object")
            (folder / "driver.c").write_text(previous.C_DRIVER)
            argv = [clang, "-O2", str(folder / "driver.c"), str(folder / "candidate.o"), "-o", str(binary)]
        else:
            for name, value in parsed.items():
                (folder / name).write_text(value)
            (folder / "main.rs").write_text(rust_driver(task) if enforce_contract else previous.RUST_DRIVER)
            argv = [rustc, "--edition=2021", "-Copt-level=2", "-Coverflow-checks=on", str(folder / "main.rs"), "-o", str(binary)]
        process = subprocess.run(argv, capture_output=True, text=True, timeout=45)
        record["compile"] = {"argv": argv, "returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr}
        record["status"] = "compiled" if process.returncode == 0 else "compile_rejected"
        if process.returncode == 0:
            record.update(native_built=True, artifact=file_identity(binary))
        record["compiler_unchanged"] = file_identity(compiler["path"]) == compiler
        if not record["compiler_unchanged"]:
            record.update(status="infrastructure_failure", native_built=False)
    except subprocess.TimeoutExpired as error:
        record.update(status="infrastructure_failure", error={"type": type(error).__name__, "message": str(error)})
    except Exception as error:
        record["error"] = {"type": type(error).__name__, "message": str(error)}
    record["wall_ns"] = time.monotonic_ns() - started
    save(folder / "BUILD.json", record)
    return record


def execute(built, task, cases, expected):
    if not built["native_built"]:
        raise ValueError("unbuilt candidate")
    artifact = built["artifact"]
    data = Path(artifact["path"]).read_bytes()
    if hashlib.sha256(data).hexdigest() != artifact["sha256"]:
        raise RuntimeError("E_MATCHED_ARTIFACT_DRIFT")
    descriptor = os.memfd_create("hepta-agent-matched-v3", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(descriptor), "wb") as stream:
            stream.write(data)
        os.fchmod(descriptor, 0o500)
        required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, required)

        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (2,2))
            resource.setrlimit(resource.RLIMIT_AS, (256*1024**2,256*1024**2))
            resource.setrlimit(resource.RLIMIT_CORE, (0,0))

        started = time.monotonic_ns()
        try:
            result = subprocess.run([f"/proc/self/fd/{descriptor}"],
                input="".join(" ".join(map(str,row)) + "\n" for row in cases), text=True,
                capture_output=True, timeout=5, pass_fds=(descriptor,), preexec_fn=limits)
        except subprocess.TimeoutExpired as error:
            return {"status": "observable_timeout", "error": str(error), "wall_ns": time.monotonic_ns()-started,
                    "artifact_unchanged": file_identity(artifact["path"]) == artifact, "usage": None}
        execution_ns = time.monotonic_ns()-started
        try:
            matrix = [[int(word) for word in line.split()] for line in result.stdout.splitlines()]
            columns = 3 + len(task["provider_returns"]) if built["provider_audit"] and built["language"] == "rust" else 1
            if any(len(row) != columns or any(not 0 <= x <= MAX64 for x in row) for row in matrix):
                raise ValueError("native output shape")
            actual = [row[0] for row in matrix]
        except ValueError:
            matrix, actual = [], None
        observed = {"status": "correct" if result.returncode == 0 and actual == expected else "observable_wrong",
            "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            "cases": cases, "expected": expected, "actual": actual, "native_execution_ns": execution_ns,
            "artifact_sha256": artifact["sha256"], "artifact_unchanged": file_identity(artifact["path"]) == artifact,
            "sealed_image": True, "seals": fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)}
        if built["provider_audit"]:
            audit_started = time.monotonic_ns()
            wanted = [[int(value) for value in provider_values(task["id"],case)] for case in cases]
            if built["language"] == "rust":
                counts, arguments, providers = ([row[1] for row in matrix], [row[2] for row in matrix], [row[3:] for row in matrix])
                agreement = True
                observed["provider_observation_kind"] = "trusted native wrapper counter and independent native provider call"
            else:
                rows = hia_audit(built, task, cases)
                counts, arguments = [r["call_count"] for r in rows], [int(r["arguments_match"]) for r in rows]
                providers = [[int(x) for x in r["provider"]["values"]] if r["provider"]["status"] == "returned" else None for r in rows]
                agreement = actual == [r["entry"]["values"][0] if r["entry"]["status"] == "returned" else None for r in rows]
                observed.update(provider_observation_kind="same-hashed-Core VM calls; native entrypoint checked separately", vm_provider_observations=rows)
            provider_pass = providers == wanted
            calls_pass = counts == [1]*len(cases)
            arguments_pass = arguments == [1]*len(cases)
            observed.update(provider_actual=providers, provider_expected=wanted, provider_call_counts=counts,
                provider_argument_matches=arguments, provider_contract_passed=provider_pass, provider_calls_passed=calls_pass,
                provider_arguments_passed=arguments_pass, native_vm_agreement=agreement,
                provider_audit_ns=time.monotonic_ns()-audit_started)
            if not all((provider_pass,calls_pass,arguments_pass,agreement)):
                observed["status"] = "observable_wrong"
        observed["wall_ns"] = time.monotonic_ns()-started
        return observed
    finally:
        os.close(descriptor)


def feedback(build_record, observed):
    """Only compilation and public examples, never hidden inputs or answers."""
    result = {"compile_status": build_record["status"]}
    if "compile" in build_record:
        result["compiler_stderr"] = build_record["compile"]["stderr"][:4000]
    if "error" in build_record:
        result["diagnostic"] = build_record["error"]
    if observed is not None:
        result["public"] = {key: observed.get(key) for key in (
            "status","cases","expected","actual","provider_actual","provider_expected",
            "provider_call_counts","provider_argument_matches","returncode","stderr")}
    return result


def reference_controls(tasks, output, clang, rustc):
    root = Path(output);root.mkdir(parents=True,exist_ok=False)
    rows = []
    for task in tasks:
        for language in ("hia","rust"):
            for label in ("original","correct"):
                built = build(task,language,canonical({"files":task[label+"_"+language]}).decode(),
                              root/(task["id"]+"_"+language+"_"+label),clang,rustc,enforce_contract=label=="correct")
                observed = execute(built,task,task["hidden_cases"],task["hidden_expected"]) if built["native_built"] else None
                passed = (built["native_built"] and observed is not None and
                    observed["status"] == ("correct" if label=="correct" else "observable_wrong") and observed["artifact_unchanged"])
                rows.append({"task":task["id"],"language":language,"kind":label,"passed":passed,"build":built,"execution":observed})
            if task["stratum"]=="upgrade":
                for i in (0,1):
                    files = copy.deepcopy(task["original_"+language])
                    name = FILE_NAMES[language][i];files[name] = task["correct_"+language][name]
                    built = build(task,language,canonical({"files":files}).decode(),
                        root/(task["id"]+"_"+language+"_partial"+str(i)),clang,rustc,enforce_contract=False)
                    rows.append({"task":task["id"],"language":language,"kind":"partial_"+str(i),
                        "passed":not built["native_built"] and built["status"] in {"response_rejected","compile_rejected"},"build":built})
    result = {"model_answers":False,"rows":rows,"count":len(rows),"passed":sum(row["passed"] for row in rows)}
    save(root/"CONTROLS.json",result)
    return result
