"""Execute nominal resources and cooperative task/cancel HIA on the native host.

Structured inputs and their reloaded canonical core share verify_core and the
same direct backend. This finite gate observes actual allocator addresses,
refusals, exactly-once cleanup and invalid protocol traps. No concurrent task,
physical device or whole-language refinement claim follows from this corpus.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_program import HIAProgramRejected, VerifiedProgram, execute_program, verify_core
from hepta.hia_program_llvm import compile_program_llvm, emit_program_llvm
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.native_tool_identity import digest_executable
from tests.test_hia_program_composite import enum_owner_program, stored_loan_program, task_program
from tools.qualify_hia_program import operation, ret


WRAPS = ["-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free"]
EXPORTS = ["choose", "stored", "task_case"]


def combined_program():
    values = [stored_loan_program(), enum_owner_program(), task_program()]
    return {"schema": "hepta.hia.composite.v1", "module": "composite_qualification",
            "types": [row for value in values for row in value["types"]],
            "functions": [row for value in values for row in value["functions"]]}


def cases():
    values = [{"function": "stored", "arguments": [flag], "allocation_fail_at": None, "expected": 91}
              for flag in (False, True)]
    for flag in (False, True):
        for size, fail, actual_length in [(0, None, 0), (7, None, 7), ((1 << 64) - 1, None, 0), (7, 1, 0)]:
            values.append({"function": "choose", "arguments": [flag, size], "allocation_fail_at": fail,
                           "expected": actual_length + (0 if flag else 10)})
    for mode, value in [(0, 33), (1, 13), (2, 28), (255, 28)]:
        values.extend([{"function": "task_case", "arguments": [mode], "allocation_fail_at": None, "expected": value},
                       {"function": "task_case", "arguments": [mode], "allocation_fail_at": 1, "expected": 250}])
    return values


OBSERVER = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/resource.h>
void *__real_malloc(size_t); void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *addresses[64];
static size_t attempts,allocations,frees,live,refusals,invalid_frees;
static bool refuse_next;
static void *remember(void *p) {
  if(p){size_t i;for(i=0;i<64 && addresses[i];i++);if(i==64)exit(89);
    addresses[i]=p;allocations++;live++;}return p;
}
void *__wrap_malloc(size_t n) {
  attempts++;if(refuse_next){refuse_next=false;refusals++;return NULL;}
  return remember(__real_malloc(n));
}
void *__wrap_calloc(size_t n,size_t width) {
  attempts++;if(refuse_next){refuse_next=false;refusals++;return NULL;}
  return remember(__real_calloc(n,width));
}
void __wrap_free(void *p) {
  if(p){size_t i;for(i=0;i<64 && addresses[i]!=p;i++);
    if(i==64){invalid_frees++;exit(90);}addresses[i]=NULL;frees++;live--;}
  __real_free(p);
}
extern uint8_t stored(bool);
extern size_t choose(bool,size_t);
extern size_t task_case(uint8_t);
struct input {unsigned kind;uint64_t first,second;bool fail;};
static const struct input inputs[]={@CASES@};
int main(void) {
  struct rlimit no_core={0,0}; if(setrlimit(RLIMIT_CORE,&no_core))return 88;
  for(size_t index=0;index<sizeof(inputs)/sizeof(inputs[0]);index++) {
    struct input c=inputs[index];refuse_next=c.fail;size_t value;
    if(c.kind==0)value=stored((bool)c.first);
    else if(c.kind==1)value=choose((bool)c.first,(size_t)c.second);
    else value=task_case((uint8_t)c.first);
    if(refuse_next)return 92;
    printf("{\"index\":%zu,\"result\":%zu}\n",index,value);
  }
  printf("{\"attempts\":%zu,\"allocations\":%zu,\"frees\":%zu,\"live\":%zu,\"refusals\":%zu,\"invalid_frees\":%zu}\n",
    attempts,allocations,frees,live,refusals,invalid_frees);
  return live || invalid_frees ? 91 : 0;
}
'''


def observer_source():
    rows = []
    for row in cases():
        kind = {"stored": 0, "choose": 1, "task_case": 2}[row["function"]]
        args = [int(value) for value in row["arguments"]]
        first, second = args[0], args[1] if len(args) > 1 else 0
        rows.append("{" + f"{kind},UINT64_C({first}),UINT64_C({second})," + ("true" if row["allocation_fail_at"] else "false") + "}")
    return OBSERVER.replace("@CASES@", ",\n".join(rows))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def _run(argv, report, directory, *, expected=0):
    start = time.monotonic()
    result = run_bounded(list(map(str, argv)), timeout=90, stdout_limit=2_000_000, stderr_limit=1_000_000)
    index = len(report["processes"])
    stdout, stderr = directory / f"process-{index:02d}.stdout", directory / f"process-{index:02d}.stderr"
    stdout.write_text(result.stdout); stderr.write_text(result.stderr)
    item = {"argv": list(map(str, argv)), "returncode": result.returncode, "seconds": time.monotonic() - start,
            "stdout": str(stdout), "stdout_sha256": digest(stdout), "stderr": str(stderr), "stderr_sha256": digest(stderr)}
    report["processes"].append(item)
    if result.returncode != expected:
        raise ValueError("Native process differs from required exit: " + repr(item) + "\n" + result.stderr[-2000:])
    return index


def _observed(report, process):
    lines = Path(report["processes"][process]["stdout"]).read_text().splitlines()
    values = [json.loads(line) for line in lines]
    if len(values) != len(cases()) + 1:
        raise ValueError("Native observer case denominator differs")
    for index, (row, expected) in enumerate(zip(values[:-1], cases())):
        if row != {"index": index, "result": expected["expected"]} or type(row["result"]) is not int:
            raise ValueError("Native composite result differs from frozen case")
    return {"cases": values[:-1], "allocator": values[-1]}


def static_controls():
    result = []
    program = stored_loan_program()
    program["functions"][0]["blocks"][0]["ops"].append(operation("owner.drop", ["owner"]))
    result.append(("use_owner_after_pack", program))
    for name, bad in [("drop_owner_with_stored_loans", operation("owner.drop", ["moved"])),
                      ("end_parent_before_child", operation("loan.end", ["parent"])),
                      ("write_parent_with_live_child", operation("buffer.store", ["parent", "zero", "before"]))]:
        program = stored_loan_program(); program["functions"][0]["blocks"][1]["ops"].insert(3, bad)
        result.append((name, program))
    program = enum_owner_program(); program["functions"][0]["blocks"][3]["term"]["cases"].pop()
    result.append(("nonexhaustive_owner_enum", program))
    program = task_program(); program["functions"][1]["blocks"][0]["ops"].pop()
    result.append(("cancellation_leaks_state_owner", program))
    program = task_program(); program["types"][2]["state"] = "readbuf"
    result.append(("task_captures_local_loan", program))
    program = task_program(); program["types"][2]["cancel"] = "not_captured"
    result.append(("missing_cancel_implementation", program))
    return result


def protocol_controls():
    result = []
    for name, mode in [("double_start", 2), ("join_pending", 0), ("close_running", 1), ("poll_complete", 2)]:
        program = task_program()
        blocks = {block["id"]: block for block in program["functions"][2]["blocks"]}
        if name == "double_start":
            blocks["begin"]["ops"][1]["op"] = "task.start"
        elif name == "join_pending":
            blocks["pending_cancel"]["ops"] = [operation("task.join", ["pending_task"], [("answer", "usize")])]
            blocks["pending_cancel"]["term"] = ret("answer")
        elif name == "close_running":
            blocks["running_cancel"]["ops"] = [operation("task.close", ["live_task"]), operation("const", out=[("answer", "usize")], value=0)]
            blocks["running_cancel"]["term"] = ret("answer")
        else:
            blocks["finish"]["ops"][0]["op"] = "task.poll"
        result.append((name, program, mode))
    return result


def protocol_driver(mode):
    return ("#include <stddef.h>\n#include <stdint.h>\n#include <sys/resource.h>\n"
            "extern size_t task_case(uint8_t);int main(void){struct rlimit c={0,0};"
            "if(setrlimit(RLIMIT_CORE,&c))return 88;return (int)task_case(" + str(mode) + ");}\n")


def _source_bindings():
    files = [*sorted((ROOT / "hepta").glob("*.py")), Path(__file__).resolve(),
             ROOT / "tests/test_hia_program_composite.py", ROOT / "tests/test_hia_program.py",
             ROOT / "tools/qualify_hia_program.py"]
    return {str(path.relative_to(ROOT)): digest(path) for path in files}


def validate_composite_receipt(report):
    if report.get("schema") != "hepta.hia.composite-native-qualification.v1":
        raise ValueError("Wrong composite qualification schema")
    root, clang = Path(report["workdir"]), report["compiler"]["path"]
    if digest_executable(Path(clang)) != report["compiler"]["sha256"]:
        raise ValueError("Composite compiler identity changed")
    source = verify_core((root / "input.hia.json").read_bytes())
    normalized = verify_core((root / "normalized.hia.json").read_bytes())
    if (source.sha256 != report["core_sha256"] or source.input_sha256 != report["input_sha256"]
            or source.canonical_bytes != normalized.canonical_bytes
            or sorted(source.scalar_entrypoints) != EXPORTS or sorted(normalized.scalar_entrypoints) != EXPORTS):
        raise ValueError("Structured/core binding or public exports changed")
    if report["cases"] != cases() or (root / "observer.c").read_text() != observer_source():
        raise ValueError("Frozen composite corpus/observer changed")
    for name, core in [("structured", source), ("normalized", normalized)]:
        group = report["native"][name]
        ir = emit_program_llvm(core)
        if (ir.sha256 != group["llvm_ir_sha256"] or digest(root / (name + ".ll")) != ir.sha256
                or group["build"]["input_sha256"] != core.input_sha256
                or group["build"]["core_sha256"] != core.sha256
                or group["build"]["exports"] != EXPORTS
                or group["build"]["artifact_sha256"] != digest(root / (name + ".o"))):
            raise ValueError("Native object, LLVM, origin or exports changed")
        expected_link = [clang, "-std=c11", "-O2", "-Werror=implicit-function-declaration", str(root / "observer.c"),
                         str(root / (name + ".o")), *WRAPS, "-o", str(root / name)]
        linked = report["processes"][group["link_process"]]
        actual = report["processes"][group["run_process"]]
        if (linked["argv"] != expected_link or linked["returncode"] != 0
                or actual["argv"] != [str(root / name)] or actual["returncode"] != 0):
            raise ValueError("Target must link/run only its direct core object and frozen observer")
        observed = _observed(report, group["run_process"])
        expected_counts = {"attempts": 14, "allocations": 8, "frees": 8, "live": 0, "refusals": 6, "invalid_frees": 0}
        if group["observed"] != observed or observed["allocator"] != expected_counts:
            raise ValueError("Actual allocator cleanup/refusal trace differs")
    wrong = report["missing_free_control"]
    original_ir = (root / "structured.ll").read_text()
    transformed = "\n".join(line for line in original_ir.splitlines() if "call void @free(" not in line) + "\n"
    if (wrong["qualified_hia_artifact"] is not False or (root / "missing-free.ll").read_text() != transformed
            or transformed == original_ir or report["processes"][wrong["run_process"]]["returncode"] != 91):
        raise ValueError("Compiled missing-free negative control is invalid")
    missing = _observed(report, wrong["run_process"])
    if missing["allocator"] != {"attempts": 14, "allocations": 8, "frees": 0, "live": 8, "refusals": 6, "invalid_frees": 0}:
        raise ValueError("Missing frees were not independently observed")
    statics = static_controls()
    if [x["name"] for x in report["static_rejections"]] != [x[0] for x in statics]:
        raise ValueError("Static resource rejection denominator differs")
    for row, (name, document) in zip(report["static_rejections"], statics):
        path = root / ("reject-" + name + ".hia.json")
        if row["input"] != str(path) or json.loads(path.read_bytes()) != document or row["rejected"] is not True:
            raise ValueError("Retained static negative control differs")
        try:
            verify_core(path.read_bytes())
        except HIAProgramRejected as exc:
            if row["code"] != exc.code:
                raise ValueError("Static rejection kind differs") from exc
        else:
            raise ValueError("Unsafe static negative control was accepted")
    protocols = protocol_controls()
    if [x["name"] for x in report["protocol_traps"]] != [x[0] for x in protocols]:
        raise ValueError("Cooperative protocol control denominator differs")
    for row, (name, document, mode) in zip(report["protocol_traps"], protocols):
        folder = root / name
        expected = verify_core(document)
        actual = verify_core((folder / "input.hia.json").read_bytes())
        core = verify_core((folder / "normalized.hia.json").read_bytes())
        if (row["mode"] != mode or actual != expected or core.canonical_bytes != expected.canonical_bytes
                or (folder / "driver.c").read_text() != protocol_driver(mode)
                or digest(folder / "program.ll") != emit_program_llvm(expected).sha256
                or row["build"]["core_sha256"] != expected.sha256
                or row["build"]["input_sha256"] != expected.input_sha256
                or row["build"]["artifact_sha256"] != digest(folder / "program.o")):
            raise ValueError("Retained protocol input/core/native identity differs")
        linked = report["processes"][row["link_process"]]
        executed = report["processes"][row["run_process"]]
        allowed = [clang, "-std=c11", "-O2", "-Werror=implicit-function-declaration", str(folder / "driver.c"),
                   str(folder / "program.o"), "-o", str(folder / "program")]
        if (linked["argv"] != allowed or linked["returncode"] != 0
                or executed["argv"] != [str(folder / "program")] or executed["returncode"] != -signal.SIGABRT):
            raise ValueError("Invalid cooperative protocol transition did not actually abort")
    if report["claims"] != {"finite_composite_native_corpus_passed": True,
                             "actual_allocator_refusals_and_cleanup_observed": True,
                             "standalone_normalized_core_reloaded_and_executed": True,
                             "source_ast_required": False, "general_concurrency_qualified": False,
                             "physical_hardware_qualified": False, "whole_language_soundness_proved": False,
                             "backend_refinement_proved": False, "cleanup_after_abort_promised": False}:
        raise ValueError("Unqualified composite claim")
    for item in report["retained_files"]:
        if digest(item["path"]) != item["sha256"]:
            raise ValueError("Retained composite evidence changed")
    for process in report["processes"]:
        for stream in ("stdout", "stderr"):
            if digest(process[stream]) != process[stream + "_sha256"]:
                raise ValueError("Raw composite process evidence changed")


def qualify(workdir, *, clang="clang"):
    root = Path(workdir).absolute(); root.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.composite-native-qualification.v1", "ok": False,
              "workdir": str(root), "processes": [], "native": {}, "static_rejections": [], "protocol_traps": []}
    started = time.monotonic()
    initial = _source_bindings(); report["source_bindings_before"] = initial
    try:
        selected = shutil.which(clang)
        if selected is None:
            raise ValueError("Actual Clang 20+ required")
        compiler = Path(selected).resolve(strict=True); clang = str(compiler)
        report["compiler"] = {"path": clang, "sha256": digest_executable(compiler)}
        program = verify_core(combined_program())
        (root / "input.hia.json").write_bytes(program.structured_bytes)
        (root / "normalized.hia.json").write_bytes(program.canonical_bytes)
        normalized = verify_core((root / "normalized.hia.json").read_bytes())
        if sorted(program.scalar_entrypoints) != EXPORTS or program.canonical_bytes != normalized.canonical_bytes:
            raise ValueError("Source-free normalize/reload changed public core")
        report.update(input_sha256=program.input_sha256, core_sha256=program.sha256,
                      normalization=program.normalization_report, cases=cases())
        (root / "observer.c").write_text(observer_source())
        for name, core in [("structured", program), ("normalized", normalized)]:
            references = [execute_program(core, row["function"], row["arguments"], allocation_fail_at=row["allocation_fail_at"])
                          for row in cases()]
            if any(value["result"] != row["expected"] or value["resources"]["live_owners"]
                   or value["resources"]["live_local_loans"]
                   or value["resources"]["owners_created"] != value["resources"]["owners_dropped"]
                   for row, value in zip(cases(), references)):
                raise ValueError("Reference composite values or cleanup differ")
            ir = emit_program_llvm(core); (root / (name + ".ll")).write_text(ir.text)
            build = compile_program_llvm(ir, program=core, output=root / (name + ".o"), clang=clang, kind="object")
            linked = _run([clang, "-std=c11", "-O2", "-Werror=implicit-function-declaration", root / "observer.c",
                           root / (name + ".o"), *WRAPS, "-o", root / name], report, root)
            executed = _run([root / name], report, root)
            report["native"][name] = {"build": build, "llvm_ir_sha256": ir.sha256,
                                       "link_process": linked, "run_process": executed,
                                       "references": references, "observed": _observed(report, executed)}
        for label, document in static_controls():
            path = root / ("reject-" + label + ".hia.json"); _write(path, document)
            try:
                verify_core(path.read_bytes())
            except HIAProgramRejected as exc:
                report["static_rejections"].append({"name": label, "input": str(path), "rejected": True,
                                                     "code": exc.code, "diagnostic": str(exc)})
            else:
                raise ValueError("Unsafe composite program accepted: " + label)
        original_ir = (root / "structured.ll").read_text()
        wrong_ir = "\n".join(line for line in original_ir.splitlines() if "call void @free(" not in line) + "\n"
        if wrong_ir == original_ir:
            raise ValueError("Missing-free mutation changed no native operation")
        (root / "missing-free.ll").write_text(wrong_ir)
        built = _run([clang, "-O3", "-c", "-x", "ir", root / "missing-free.ll", "-o", root / "missing-free.o"], report, root)
        linked = _run([clang, "-std=c11", "-O2", "-Werror=implicit-function-declaration", root / "observer.c",
                       root / "missing-free.o", *WRAPS, "-o", root / "missing-free"], report, root)
        executed = _run([root / "missing-free"], report, root, expected=91)
        report["missing_free_control"] = {"qualified_hia_artifact": False, "compile_process": built,
                                           "link_process": linked, "run_process": executed,
                                           "observed": _observed(report, executed)}
        for label, document, mode in protocol_controls():
            folder = root / label; folder.mkdir()
            core = verify_core(document); (folder / "input.hia.json").write_bytes(core.structured_bytes)
            (folder / "normalized.hia.json").write_bytes(core.canonical_bytes)
            try:
                execute_program(core, "task_case", [mode])
            except HIAProgramTrap as exc:
                if exc.code != "user":
                    raise ValueError("Wrong task protocol trap") from exc
                reference = exc.report
            else:
                raise ValueError("Invalid protocol did not trap in interpreter")
            ir = emit_program_llvm(core); (folder / "program.ll").write_text(ir.text)
            build = compile_program_llvm(ir, program=core, output=folder / "program.o", clang=clang, kind="object")
            (folder / "driver.c").write_text(protocol_driver(mode))
            linked = _run([clang, "-std=c11", "-O2", "-Werror=implicit-function-declaration", folder / "driver.c", folder / "program.o",
                           "-o", folder / "program"], report, root)
            executed = _run([folder / "program"], report, root, expected=-signal.SIGABRT)
            report["protocol_traps"].append({"name": label, "mode": mode, "reference": reference,
                                              "build": build, "link_process": linked, "run_process": executed})
        forged = VerifiedProgram(program.canonical_bytes, program.structured_bytes.replace(b'"value":7', b'"value":8'))
        try:
            verify_core(forged)
        except HIAProgramRejected as exc:
            report["origin_tamper_control"] = {"rejected": True, "code": exc.code}
        else:
            raise ValueError("Changed nominal input reused stale canonical core")
        report["claims"] = {"finite_composite_native_corpus_passed": True,
                             "actual_allocator_refusals_and_cleanup_observed": True,
                             "standalone_normalized_core_reloaded_and_executed": True,
                             "source_ast_required": False, "general_concurrency_qualified": False,
                             "physical_hardware_qualified": False, "whole_language_soundness_proved": False,
                             "backend_refinement_proved": False, "cleanup_after_abort_promised": False}
        report["retained_files"] = [{"path": str(path), "sha256": digest(path)} for path in sorted(root.rglob("*")) if path.is_file()]
        report["source_bindings_after"] = _source_bindings()
        if report["source_bindings_after"] != initial:
            raise ValueError("Composite implementation changed during qualification")
        validate_composite_receipt(report)
        report.update(ok=True, status="finite_composite_native_qualification_passed", native_result_executions=36,
                      actual_null_refusal_observations=12, observed_successful_allocations=16, observed_frees=16,
                      actual_protocol_aborts=4, elapsed_seconds=time.monotonic() - started)
    except Exception as exc:
        report.update(ok=False, status="rejected", diagnostic={"type": type(exc).__name__, "message": str(exc)},
                      elapsed_seconds=time.monotonic() - started)
    _write(root / "qualification.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--clang", default=os.environ.get("CLANG", "clang"))
    args = parser.parse_args(argv)
    report = qualify(args.workdir, clang=args.clang)
    print(json.dumps({key: report.get(key) for key in ("ok", "status", "native_result_executions", "actual_protocol_aborts", "diagnostic")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
