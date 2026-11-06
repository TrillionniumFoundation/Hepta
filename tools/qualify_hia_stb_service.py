#!/usr/bin/env python3
"""Join complete stb_divide source maintenance to a costed native service study.

Uses the existing changed-body migration qualifier and existing checked Core /
LLVM route. All comparisons share one scalar result/error contract. This is a
bounded experiment, not a new compiler, safety certificate or promotion path.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from hepta.clang_capture import run_bounded
from hepta.hia_program import execute_program
from hepta.hia_program_source import lower_source
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_static_budget import qualify_bounded_resources, HIAStaticBudgetRejected
from tools import qualify_hia_stb_divide_update as update

FIXTURES = ROOT / "benchmarks/hia_stb_service"
FUNCTIONS = update.FUNCTIONS
ARMS = ("hia", "c-generic", "cpp-generic", "rust-generic", "c-native", "cpp-native", "rust-native", "rust-native-pgo")
ZERO_DIVISOR, SIGNED_OVERFLOW = 2147483648, 2147483649
MIN, MAX = update.MIN, update.MAX
ZERO_RESOURCES = dict.fromkeys(("allocations", "frees", "allocation_attempts", "owners_created", "owners_dropped",
    "live_owners", "live_bytes", "peak_bytes", "loans_started", "loans_ended", "live_local_loans"), 0)


def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_STB_SERVICE: " + message)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def identity(path):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": sha256(data).hexdigest()}


def specification():
    p = json.loads((FIXTURES / "PROTOCOL.json").read_text())
    require(p["schema"] == "hepta.hia.stb-service.protocol.v1" and p["arms"] == list(ARMS)
        and [p[k] for k in ("groups", "samples", "repeats", "evaluation_pairs", "training_pairs",
            "training_seed", "evaluation_seed", "training_repeats")] ==
            [4, 41, 128, 257, 129, 2026110601, 2026110602, 256]
        and p["bounded_resource_limits"] == {"max_allocator_interactions": 0, "max_vm_ticks": 70,
            "max_call_depth": 3, "max_live_heap_bytes": 0}
        and p["authority"] == "DENY_ALL" and p["human_maintenance_seconds"] is None,
        "frozen protocol changed")
    return p


def result(a, b):
    require(type(a) is int and type(b) is int and MIN <= a <= MAX and MIN <= b <= MAX,
            "arguments outside exact i32 domain")
    if b == 0:
        return [ZERO_DIVISOR] * 6
    if (a, b) == (MIN, -1):
        return [SIGNED_OVERFLOW] * 6
    return update.oracle(a, b)


def corpora(p=None):
    p = specification() if p is None else p
    # Explicit boundary/error witnesses are evaluation-only, never PGO training.
    edges = [MIN, MIN + 1, -7, -2, -1, 0, 1, 2, 7, MAX]
    evaluation = [(a, b) for a in edges for b in edges]
    rng = random.Random(p["evaluation_seed"])
    while len(evaluation) < p["evaluation_pairs"]:
        pair = (rng.randint(MIN, MAX), rng.randint(MIN, MAX))
        if pair not in evaluation:
            evaluation.append(pair)
    evaluation_set = set(evaluation)
    training, rng = [], random.Random(p["training_seed"])
    while len(training) < p["training_pairs"]:
        pair = (rng.randint(MIN, MAX), rng.randint(MIN, MAX))
        if pair not in evaluation_set and pair not in training:
            training.append(pair)
    return {name: [{"a": a, "b": b, "expected": result(a, b)} for a, b in pairs]
            for name, pairs in (("training", training), ("evaluation", evaluation))}


def c_source():
    wrappers = "\n".join(
        f'int64_t service_{fn}(int32_t a,int32_t b) {{'
        f'if(b==0)return INT64_C({ZERO_DIVISOR});'
        f'if(a==INT32_MIN && b==-1)return INT64_C({SIGNED_OVERFLOW});'
        f'return (int64_t){fn}(a,b);}}' for fn in FUNCTIONS)
    return '#include <stdint.h>\n#include <limits.h>\n#define STB_DIVIDE_IMPLEMENTATION\n#include "stb_divide.h"\n#ifdef __cplusplus\nextern "C" {\n#endif\n' + wrappers + '\n#ifdef __cplusplus\n}\n#endif\n'


def hia_source(translated):
    wrappers = "\n".join(
        f'export "C" fn service_{fn}(a:i32,b:i32)->i64 effects {{panic,write}} {{'
        f'if b == 0 {{ return {ZERO_DIVISOR}; }}'
        f'if a == {MIN} {{ if b == -1 {{ return {SIGNED_OVERFLOW}; }} }}'
        f'return c_{fn}(a,b) as i64;}}' for fn in FUNCTIONS)
    return translated + "\n" + wrappers + "\n"


def order(p, group):
    arms = list(ARMS[group:] + ARMS[:group])
    return list(reversed(arms)) if group % 2 else arms


def snapshot(expected_head):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    def git(*args):
        return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT, env=env)
    head = git("rev-parse", "HEAD").decode().strip()
    require(head == expected_head and re.fullmatch(r"[a-f0-9]{40}", head), "exact source commit required")
    require(not git("status", "--porcelain", "--untracked-files=all"), "clean committed tree required")
    paths = ("hepta/", "tools/", "benchmarks/hia_stb_service/", "tests/fixtures/c_migration/stb_divide/",
             "tests/fixtures/c_migration/stb_divide_v0_93/")
    singles = {"tests/test_hia_stb_service.py", "tests/test_hia_stb_divide_update.py",
               "tests/fixtures/c_migration/stb_divide_vm_readback.json"}
    files = {}
    for raw in git("ls-tree", "-rz", "--full-tree", head).split(b"\0")[:-1]:
        metadata, name = raw.split(b"\t", 1)
        name = name.decode()
        if name not in singles and not name.startswith(paths):
            continue
        mode, kind, blob = metadata.decode().split()
        path = ROOT / name
        require(not Path(name).is_absolute() and ".." not in Path(name).parts,
                "source path escapes closure")
        require(kind == "blob" and mode in {"100644", "100755"} and not any(
            (ROOT / Path(*Path(name).parts[:n])).is_symlink()
            for n in range(1, len(Path(name).parts) + 1)), "non-regular source: " + name)
        observed = path.lstat()
        require(stat.S_ISREG(observed.st_mode) and bool(observed.st_mode & stat.S_IXUSR) == (mode == "100755"),
                "source executable mode differs: " + name)
        data = path.read_bytes()
        import hashlib
        require(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == blob,
                "worktree differs from canonical Git blob: " + name)
        files[name] = {"blob": blob, "bytes": len(data), "sha256": sha256(data).hexdigest()}
    observed_files = set()
    for prefix in paths:
        directory = ROOT / prefix
        require(not directory.is_symlink(), "source directory contains symlink")
        for path in directory.rglob("*"):
            if "__pycache__" in path.relative_to(ROOT).parts:
                continue
            require(not path.is_symlink(), "source closure contains symlink")
            if path.is_file():
                observed_files.add(str(path.relative_to(ROOT)))
    require(observed_files | singles == set(files) and "tools/qualify_hia_stb_service.py" in files,
            "incomplete or injected source closure")
    return {"head": head, "tree": git("rev-parse", head + "^{tree}").decode().strip(), "files": files}


def _command(argv, output, report, stage, *, env=None, timeout=120):
    argv = list(map(str, argv))
    started = time.monotonic_ns()
    row = {"stage": stage, "argv": argv, "returncode": None}
    report["commands"].append(row)
    index = len(report["commands"]) - 1
    try:
        proc = run_bounded(argv, cwd=output, env=env, timeout=timeout,
            stdout_limit=2_000_000, stderr_limit=2_000_000, stdin_limit=0)
        row.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except Exception as error:
        row["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        row["wall_ns"] = time.monotonic_ns() - started
        for stream in ("stdout", "stderr"):
            path = output / f"command-{index:03d}.{stream}.txt"
            path.write_text(row.pop(stream, ""))
            row[stream] = identity(path)
    require(row["returncode"] == 0, "command failed: " + stage)
    return Path(row["stdout"]["path"]).read_text()


def validate_observation(observed, rows, samples, repeats):
    require(type(observed) is dict, "missing native observation")
    for key in ("cases", "samples", "repeats", "calls", "checksum", "load_ns", "first_request_ns", "cold_delivery_ns", "peak_rss_kib"):
        require(type(observed.get(key)) is int, "non-integer observation: " + key)
    require(observed["cases"] == len(rows) and observed["samples"] == samples
        and observed["repeats"] == repeats and observed["calls"] == len(rows) * 6 * samples * repeats,
        "actual call denominator differs")
    checksum = (sum(sum(r["expected"]) for r in rows) * samples * repeats) % (1 << 64)
    require(observed["checksum"] == checksum, "native checksum differs from independent arithmetic oracle")
    require(type(observed.get("batch_ns")) is list and len(observed["batch_ns"]) == samples
        and all(type(v) is int and v > 0 for v in observed["batch_ns"]), "missing/nonpositive/padded native samples")
    require(observed["load_ns"] > 0 and observed["first_request_ns"] > 0
        and observed["cold_delivery_ns"] == observed["load_ns"] + observed["first_request_ns"]
        and observed["peak_rss_kib"] > 0, "invalid cold or memory observation")
    return observed


def summary(values):
    require(values and all(type(v) is int and v > 0 for v in values), "invalid timing series")
    values = sorted(values)
    return {label: values[math.ceil(percent * len(values)) - 1]
            for label, percent in (("median_ns", .5), ("p95_ns", .95), ("p99_ns", .99))}


def rust_flags(native):
    return ["-C", "opt-level=3", "-C", "lto=fat", "-C", "codegen-units=1", "-C", "panic=abort",
            "-C", "overflow-checks=on", "-C", "target-cpu=" + ("native" if native else "x86-64")]


def qualify(output, *, source_sha, clang, cc, cxx, rustc, rust_profdata, stage="study"):
    output = Path(output).resolve()
    require(not output.is_relative_to(ROOT), "output must be outside source checkout")
    output.mkdir(exist_ok=False, parents=True)
    start = time.monotonic_ns()
    report = {"schema": "hepta.hia.stb-service.report.v1", "ok": False, "status": "started",
              "commands": [], "builds": {}, "observations": [], "stage": stage, "claims": {
                "whole_language_soundness": False, "all_input_translation_refinement": False,
                "performance_superiority": False, "native_allocation_counters_measured": False,
                "human_effort_measured": False, "production_authorized": False}}
    affinity = None
    source_before = None
    try:
        require(stage in {"qualification", "study"}, "unsupported stage")
        p = specification()
        report["protocol"] = p
        source_before = snapshot(source_sha)
        report["source_before"] = source_before
        report["host"] = {"platform": platform.platform(), "machine": platform.machine(),
            "processor": platform.processor(), "exclusive_host": False}
        require(platform.system() == "Linux" and platform.machine() in {"x86_64", "AMD64"}, "native Linux x86-64 required")
        affinity = os.sched_getaffinity(0)
        require(affinity, "CPU affinity unavailable")
        cpu = min(affinity)
        os.sched_setaffinity(0, {cpu})
        report["host"].update(initial_cpus=sorted(affinity), selected_cpu=cpu)
        tools = {k: str(Path(shutil.which(v) or v).resolve(strict=True)) for k, v in
                 {"clang": clang, "cc": cc, "cxx": cxx, "rustc": rustc, "rust_profdata": rust_profdata}.items()}
        report["tools"] = {k: identity(v) for k, v in tools.items()}
        for tool in tools:
            report["tools"][tool]["version"] = _command([tools[tool], "-vV" if tool == "rustc" else "--version"], output, report, tool + "-version")
        rust_llvm = re.search(r"LLVM version: (\d+)\.", report["tools"]["rustc"]["version"])
        prof_llvm = re.search(r"LLVM version (\d+)\.", report["tools"]["rust_profdata"]["version"])
        require(rust_llvm and prof_llvm and rust_llvm.group(1) == prof_llvm.group(1), "Rust / llvm-profdata LLVM major mismatch")
        save(output / "registration.json", {"protocol": p, "source": source_before, "tools": report["tools"], "host": report["host"]})
        started = time.monotonic_ns()
        report["upgrade"] = update.qualify(output / "upgrade", clang=tools["clang"], gcc=tools["cc"], source_sha=source_sha)
        report["upgrade_wall_ns"] = time.monotonic_ns() - started
        require(report["upgrade"]["ok"], "original changed-body upgrade gate failed")
        report["upgrade_readback"] = update.validate_qualification(output / "upgrade")
        data = corpora(p)
        require(not {(r["a"], r["b"]) for r in data["training"]} & {(r["a"], r["b"]) for r in data["evaluation"]}, "PGO / evaluation leakage")
        for name, rows in data.items():
            (output / (name + ".txt")).write_text("".join(" ".join(map(str, [r["a"], r["b"], *r["expected"]])) + "\n" for r in rows))
        report["corpora"] = {name: {"pairs": len(rows), "file": identity(output / (name + ".txt"))} for name, rows in data.items()}
        translated = (output / "upgrade/0.94/translated/source.hepta").read_text()
        source = hia_source(translated)
        (output / "service.hepta").write_text(source)
        started = time.monotonic_ns()
        program = lower_source(source)
        report["hia_lowering_wall_ns"] = time.monotonic_ns() - started
        (output / "service.hia.json").write_bytes(program.canonical_bytes)
        (output / "service.ll").write_text(emit_program_llvm(program).text)
        budget = qualify_bounded_resources(program, limits=p["bounded_resource_limits"])
        report["bounded_resources"] = budget
        save(output / "bounded-resources.json", budget)
        denied = output / "budget-denial"
        denied.mkdir()
        too_small = dict(p["bounded_resource_limits"], max_vm_ticks=69)
        try:
            build_program_native(program, denied / "must-not-exist.so", clang=tools["clang"],
                bounded_resource_limits=too_small)
        except HIAStaticBudgetRejected as error:
            require(error.code == "E_HIA_BUDGET_EXCEEDED" and not list(denied.iterdir()),
                "under-budget build did not reject before emission/publication")
            report["budget_rejection"] = {"limits": too_small, "code": error.code, "artifact_published": False}
            save(output / "budget-rejection.json", report["budget_rejection"])
        else:
            raise ValueError("E_HIA_STB_SERVICE: insufficient budget accepted")
        vm_rows = []
        for row in data["evaluation"]:
            for function, expected in zip(FUNCTIONS, row["expected"]):
                actual = execute_program(program, "service_" + function, [row["a"], row["b"]], max_heap_bytes=0,
                    bounded_resource_limits=p["bounded_resource_limits"])
                require(actual["result"] == expected and actual["resources"] == ZERO_RESOURCES
                    and actual["bounded_resources"] == budget, "VM result/resource contract differs")
                binding = actual.pop("bounded_resources")["sha256"]
                vm_rows.append({"function": function, "a": row["a"], "b": row["b"], "expected": expected,
                    "bounded_resources_sha256": binding, "actual": actual})
        save(output / "vm.json", vm_rows)
        report["vm_observations"] = len(vm_rows)
        started = time.monotonic_ns()
        receipt = build_program_native(program, output / "hia.so", clang=tools["clang"],
            bounded_resource_limits=p["bounded_resource_limits"])
        require(receipt["ok"] and receipt["core_sha256"] == program.sha256
            and receipt["bounded_resources"] == budget, "actual resource-admitted HIA image required")
        report["builds"]["hia"] = {"wall_ns": time.monotonic_ns() - started, "receipt": receipt,
            "artifact": identity(output / "hia.so")}
        (output / "stb_divide.h").write_bytes((update.SUCCESSOR / "stb_divide.h").read_bytes())
        (output / "baseline.c").write_text(c_source())
        (output / "baseline.cpp").write_text(c_source())
        shutil.copyfile(FIXTURES / "baseline.rs", output / "baseline.rs")
        shutil.copyfile(FIXTURES / "driver.c", output / "driver.c")
        _command([tools["cc"], "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror", output / "driver.c", "-ldl", "-o", output / "driver"], output, report, "build-driver")
        def compile_rust(arm, extra=()):
            before = time.monotonic_ns()
            _command([tools["rustc"], "--edition=2021", "--crate-name", "stb_service", "--crate-type=cdylib", *rust_flags("native" in arm), *extra,
                output / "baseline.rs", "-o", output / (arm + ".so")], output, report, "build-" + arm)
            report["builds"][arm] = {"wall_ns": time.monotonic_ns() - before, "artifact": identity(output / (arm + ".so"))}
        for arm in ARMS[1:-1]:
            if arm.startswith("rust"):
                compile_rust(arm)
            else:
                before = time.monotonic_ns()
                cpp = arm.startswith("cpp")
                _command([tools["cxx" if cpp else "cc"], "-std=c++17" if cpp else "-std=c11", "-DC_INTEGER_DIVISION_TRUNCATES",
                    "-O3", "-flto", "-fno-semantic-interposition", "-ftrapv", "-march=" + ("native" if arm.endswith("native") else "x86-64"),
                    "-fPIC", "-shared", output / ("baseline.cpp" if cpp else "baseline.c"), "-o", output / (arm + ".so")], output, report, "build-" + arm)
                report["builds"][arm] = {"wall_ns": time.monotonic_ns() - before, "artifact": identity(output / (arm + ".so"))}
        # Training only reaches the designated disjoint corpus. All preparation is paid.
        started = time.monotonic_ns()
        raw = output / "pgo-raw"
        raw.mkdir()
        compile_rust("rust-native-instrumented", ["-C", "profile-generate=" + str(raw)])
        pgo_env = dict(os.environ, LLVM_PROFILE_FILE=str(raw / "%m-%p.profraw"))
        training = json.loads(_command([output / "driver", output / "rust-native-instrumented.so", output / "training.txt", "1", str(p["training_repeats"])], output, report, "pgo-training", env=pgo_env))
        validate_observation(training, data["training"], 1, p["training_repeats"])
        profiles = sorted(raw.glob("*.profraw"))
        require(profiles and all(f.stat().st_size > 0 for f in profiles), "missing PGO raw profiles")
        merged = output / "pgo.profdata"
        _command([tools["rust_profdata"], "merge", "-o", merged, *profiles], output, report, "pgo-merge")
        compile_rust("rust-native-pgo", ["-C", "profile-use=" + str(merged), "-C", "llvm-args=-pgo-warn-missing-function"])
        warnings = Path(report["commands"][-1]["stderr"]["path"]).read_text()
        require(not re.search(r"warning|missing|mismatch|error", warnings, re.I), "PGO profile-use warning")
        report["pgo"] = {"preparation_wall_ns": time.monotonic_ns() - started, "training": training,
            "raw": [identity(f) for f in profiles], "profile": identity(merged), "evaluation_rows_used": 0}
        # Full functional comparison precedes every timed campaign; one sample, one pass.
        for arm in ARMS:
            observed = json.loads(_command([output / "driver", output / (arm + ".so"), output / "evaluation.txt", "1", "1"], output, report, "functional-" + arm))
            validate_observation(observed, data["evaluation"], 1, 1)
        report["native_functional_observations"] = len(ARMS) * len(data["evaluation"]) * 6
        if stage == "study":
            for group in range(p["groups"]):
                for arm in order(p, group):
                    observed = json.loads(_command([output / "driver", output / (arm + ".so"), output / "evaluation.txt", str(p["samples"]), str(p["repeats"])], output, report, f"measure-{group}-{arm}"))
                    validate_observation(observed, data["evaluation"], p["samples"], p["repeats"])
                    report["observations"].append({"group": group, "arm": arm, **observed})
            require(len(report["observations"]) == len(ARMS) * p["groups"], "missing campaign cell")
            report["summaries"] = {arm: summary([v for row in report["observations"] if row["arm"] == arm for v in row["batch_ns"]]) for arm in ARMS}
            report["comparisons"] = {arm: {key: report["summaries"]["hia"][key] / report["summaries"][arm][key]
                for key in ("median_ns", "p95_ns", "p99_ns")} for arm in ARMS if arm != "hia"}
        report["candidate_costs"] = candidate_costs(report)
        save(output / "module-candidates.json", report["candidate_costs"])
        require(all(identity(Path(row["artifact"]["path"])) == row["artifact"]
            for row in report["builds"].values()), "built artifact changed during study")
        report.update(ok=True, status="completed")
    except Exception as error:
        report.update(ok=False, status="failed", error=type(error).__name__ + ": " + str(error))
    finally:
        if affinity is not None:
            os.sched_setaffinity(0, affinity)
        if source_before is not None:
            try:
                report["source_after"] = snapshot(source_sha)
                require(report["source_after"] == source_before, "source changed during qualification")
                require(all(identity(row["path"])["sha256"] == row["sha256"] for row in report["tools"].values()), "tool changed during qualification")
            except Exception as error:
                report.update(ok=False, status="failed", postflight_error=type(error).__name__ + ": " + str(error))
        try:
            report["evidence_inventory"] = evidence_inventory(output)
            if report["ok"]:
                report["readback"] = validate_qualification(output, report)
        except Exception as error:
            report.update(ok=False, status="failed_readback", readback_error=type(error).__name__ + ": " + str(error))
        report["whole_wall_ns"] = time.monotonic_ns() - start
        report["cost_accounting"] = "whole_wall_ns includes all child commands, upgrade, postflight, inventory and readback; never add child wall costs to it; preparation reported separately for comparison, not a second bill; initial development and human time unmeasured"
        save(output / "report.json", report)
    return report




def candidate_costs(report):
    """Same-module costs for independent consumers; no controller/adoption claim."""
    candidates = []
    for arm in ARMS:
        observations = [row for row in report["observations"] if row["arm"] == arm]
        process_costs = [row["wall_ns"] for row in report["commands"]
                        if row["stage"].startswith("measure-") and row["stage"].split("-", 2)[-1] == arm]
        build = report["builds"][arm]
        candidates.append({"id": arm, "artifact": build["artifact"],
            "build_wall_ns": build["wall_ns"],
            "artifact_preparation_wall_ns": report["pgo"]["preparation_wall_ns"] if arm == "rust-native-pgo" else build["wall_ns"],
            "process_delivery_ns": summary(process_costs) if process_costs else None,
            "cold_delivery_ns": summary([row["cold_delivery_ns"] for row in observations]) if observations else None,
            "batch_ns": summary([v for row in observations for v in row["batch_ns"]]) if observations else None,
            "peak_process_rss_kib": max(row["peak_rss_kib"] for row in observations) if observations else None})
    return {"schema": "hepta.hia.stb-service.candidates.v1", "candidates": candidates,
        "core_sha256": report["bounded_resources"]["core_sha256"], "cost_role": "evaluation_only",
        "shared_upgrade_wall_ns": report["upgrade_wall_ns"],
        "hia_source_lowering_wall_ns": report["hia_lowering_wall_ns"],
        "accounting": "artifact preparation includes final build; PGO preparation includes instrumentation, training and merge; shared upgrade and HIA lowering are additional identified costs; do not add nested build cost twice",
        "machine_code_duplicates_removed": False, "independent_ndu_value_evaluated": False,
        "unseen_policy_tasks_evaluated": False, "authority": "DENY_ALL"}


def evidence_inventory(output):
    output = Path(output)
    result = {}
    for path in sorted(output.rglob("*")):
        require(not path.is_symlink(), "evidence path contains symlink")
        if path.is_file() and path != output / "report.json":
            item = identity(path)
            result[str(path.relative_to(output))] = {k: item[k] for k in ("bytes", "sha256")}
    return result


def validate_qualification(output, report=None):
    """Reconcile retained finite observations without executing archived binaries.

    This authenticates no signer. The source tree must still be the exact frozen
    checkout; evidence hashes provide consistency, not a proof of wall timing.
    """
    output = Path(output)
    r = json.loads((output / "report.json").read_text()) if report is None else report
    p = specification()
    require(r["schema"] == "hepta.hia.stb-service.report.v1" and r["ok"] is True
        and r["status"] == "completed" and r["protocol"] == p, "incomplete/foreign study report")
    require(r["claims"] == {"whole_language_soundness": False, "all_input_translation_refinement": False,
        "performance_superiority": False, "native_allocation_counters_measured": False,
        "human_effort_measured": False, "production_authorized": False}, "evidence authority widened")
    require(r["source_before"] == r["source_after"] == snapshot(r["source_before"]["head"]),
            "readback source binding differs")
    require(r["evidence_inventory"] == evidence_inventory(output), "retained artifact inventory differs")
    registration = json.loads((output / "registration.json").read_text())
    require(registration == {"protocol": p, "source": r["source_before"], "tools": r["tools"], "host": r["host"]},
            "premeasurement registration differs")
    update.validate_qualification(output / "upgrade")
    data = corpora(p)
    for name, rows in data.items():
        text = "".join(" ".join(map(str, [row["a"], row["b"], *row["expected"]])) + "\n" for row in rows)
        require((output / (name + ".txt")).read_text() == text, "retained corpus differs")
    source = hia_source((output / "upgrade/0.94/translated/source.hepta").read_text())
    require((output / "service.hepta").read_text() == source, "translated bodies/service contract changed")
    program = lower_source(source)
    budget = qualify_bounded_resources(program, limits=p["bounded_resource_limits"])
    require(r["bounded_resources"] == r["builds"]["hia"]["receipt"]["bounded_resources"] == budget
        and json.loads((output / "bounded-resources.json").read_text()) == budget, "bounded resource binding differs")
    rejected = {"limits": dict(p["bounded_resource_limits"], max_vm_ticks=69),
        "code": "E_HIA_BUDGET_EXCEEDED", "artifact_published": False}
    require(r["budget_rejection"] == json.loads((output / "budget-rejection.json").read_text()) == rejected
        and not list((output / "budget-denial").iterdir()), "under-budget rejection observation differs")
    require((output / "service.hia.json").read_bytes() == program.canonical_bytes
        and (output / "service.ll").read_text() == emit_program_llvm(program).text, "retained HIA lowering differs")
    require((output / "baseline.rs").read_bytes() == (FIXTURES / "baseline.rs").read_bytes()
        and (output / "driver.c").read_bytes() == (FIXTURES / "driver.c").read_bytes()
        and all((output / name).read_text() == c_source() for name in ("baseline.c", "baseline.cpp"))
        and (output / "stb_divide.h").read_bytes() == (update.SUCCESSOR / "stb_divide.h").read_bytes(),
        "retained baseline/harness source differs")
    expected_vm = [(function, row, expected) for row in data["evaluation"]
        for function, expected in zip(FUNCTIONS, row["expected"])]
    vm = json.loads((output / "vm.json").read_text())
    require(len(vm) == len(expected_vm) == r["vm_observations"], "VM observation denominator differs")
    for observed, (function, row, expected) in zip(vm, expected_vm):
        require(observed["function"] == function and observed["a"] == row["a"] and observed["b"] == row["b"]
            and observed["expected"] == expected and observed["actual"]["result"] == expected
            and observed["actual"]["program_sha256"] == program.sha256
            and observed["bounded_resources_sha256"] == budget["sha256"]
            and observed["actual"]["resources"] == ZERO_RESOURCES
            and all(type(v) is int for v in observed["actual"]["resources"].values()),
            "retained VM result/resource observation differs")
    commands = {}
    for index, row in enumerate(r["commands"]):
        require(row["stage"] not in commands and row["returncode"] == 0
            and type(row["wall_ns"]) is int and row["wall_ns"] > 0, "missing/duplicate/failed command")
        for stream in ("stdout", "stderr"):
            path = output / f"command-{index:03d}.{stream}.txt"
            require({k: identity(path)[k] for k in ("bytes", "sha256")} ==
                {k: row[stream][k] for k in ("bytes", "sha256")}, "retained command stream differs")
        commands[row["stage"]] = (row, json.loads((output / f"command-{index:03d}.stdout.txt").read_text())
            if row["stage"].startswith(("functional-", "measure-")) or row["stage"] == "pgo-training" else None)
    require(r["native_functional_observations"] == len(ARMS) * len(data["evaluation"]) * 6, "functional denominator differs")
    for arm in ARMS:
        command, observed = commands["functional-" + arm]
        require(Path(command["argv"][1]).name == arm + ".so" and command["argv"][-2:] == ["1", "1"], "functional target differs")
        validate_observation(observed, data["evaluation"], 1, 1)
        artifact = identity(output / (arm + ".so"))
        require({k: artifact[k] for k in ("bytes", "sha256")} ==
            {k: r["builds"][arm]["artifact"][k] for k in ("bytes", "sha256")}, "retained native image differs")
    training = commands["pgo-training"][1]
    validate_observation(training, data["training"], 1, p["training_repeats"])
    require(training == r["pgo"]["training"] and r["pgo"]["evaluation_rows_used"] == 0, "PGO training scope differs")
    require(not re.search(r"warning|missing|mismatch|error",
        (output / Path(commands["build-rust-native-pgo"][0]["stderr"]["path"]).name).read_text(), re.I), "PGO warning retained")
    observations = []
    if r["stage"] == "study":
        for group in range(p["groups"]):
            for arm in order(p, group):
                command, observed = commands[f"measure-{group}-{arm}"]
                require(Path(command["argv"][1]).name == arm + ".so"
                    and command["argv"][-2:] == [str(p["samples"]), str(p["repeats"])], "timed target differs")
                validate_observation(observed, data["evaluation"], p["samples"], p["repeats"])
                observations.append({"group": group, "arm": arm, **observed})
        summaries = {arm: summary([v for row in observations if row["arm"] == arm for v in row["batch_ns"]]) for arm in ARMS}
        require(r["summaries"] == summaries and r["comparisons"] == {arm:
            {key: summaries["hia"][key] / summaries[arm][key] for key in ("median_ns", "p95_ns", "p99_ns")}
            for arm in ARMS if arm != "hia"}, "summary differs from all raw samples")
    else:
        require(r["stage"] == "qualification", "unknown observation scope")
    require(r["observations"] == observations, "retained observation order/coverage differs")
    require(r["candidate_costs"] == json.loads((output / "module-candidates.json").read_text()) == candidate_costs(r),
        "same-module candidate costs differ")
    return {"verified": True, "scope": "finite retained source/build/VM/native observation consistency",
        "archived_native_reexecuted": False, "whole_program_refinement": False,
        "wall_time_authenticity_proved": False, "authority": "DENY_ALL"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--rust-profdata", required=True)
    parser.add_argument("--stage", choices=("qualification", "study"), default="study")
    args = parser.parse_args()
    report = qualify(args.output, source_sha=args.source_sha, clang=args.clang, cc=args.cc, cxx=args.cxx,
                     rustc=args.rustc, rust_profdata=args.rust_profdata, stage=args.stage)
    print(wire({k: report.get(k) for k in ("ok", "status", "stage", "error", "postflight_error", "vm_observations", "native_functional_observations", "comparisons", "whole_wall_ns")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
