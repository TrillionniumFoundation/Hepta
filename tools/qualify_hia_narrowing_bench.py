#!/usr/bin/env python3
"""Frozen eight-arm native comparison for the guarded modular-narrowing chain.

Registration is a separate operation and contains no workload execution. A run
requires that exact registration, fresh output path, unchanged inputs and an
external exclusive experiment lane. Negative and failed observations remain.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program_source import lower_source
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm, build_program_native
from hepta.hia_native_differential import _pin_native_artifact
from hepta.hia_guarded_optimization import propose_guarded_reduction, build_guarded_native
from hepta.hia_narrowing import propose_guarded_narrowing, build_guarded_narrowed_native
from tools.qualify_hia_optimizer_bench import (identity, wire, sha, write_new, require,
    sample_order, oracle, timed_checksum, workload_header, evaluate_samples, correctness_cases, quantile)

FIXTURES = ROOT / "experiments/hia_optimizer_eval"
STUDY = FIXTURES / "round3_20261028"
SCHEMA = "hepta.hia.optimizer-bench.round3-20261028.v1"
BACKENDS = ("hia_original", "hia_guarded", "hia_narrowed", "rust_o3_lto", "c_o3_lto",
            "cpp_o3_lto", "c_pgo_lto", "cpp_pgo_lto")
ENVIRONMENT_KEYS = ("PATH", "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT", "LIBRARY_PATH",
                    "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "RUSTFLAGS", "RUSTUP_HOME",
                    "CARGO_HOME", "SOURCE_DATE_EPOCH", "LANG", "LC_ALL", "PYTHONPATH",
                    "PYTHONHOME", "PYTHONHASHSEED", "PYTHONDONTWRITEBYTECODE")


def environment_identity():
    return {name: os.environ.get(name) for name in ENVIRONMENT_KEYS}


def runtime_identity():
    return {"executable": identity(sys.executable), "version": sys.version}


def protocol():
    result = json.loads((STUDY / "PROTOCOL.json").read_bytes())
    require(result["schema"] == SCHEMA and tuple(result["backends"]) == BACKENDS,
            "unknown study or changed arms")
    require(result["groups"] == 7 and result["candidate_backend"] == "hia_narrowed", "unsupported study shape")
    require(not set(result["training_sizes"]) & set(result["holdout_sizes"]), "PGO sizes overlap")
    require(not set(result["training_seeds"]) & set(result["holdout_seeds"]), "PGO seeds overlap")
    require(result["request_tail_probes"] == 257 and result["clock_overhead_probes"] == 65,
            "tail inventory changed")
    return result


def bindings():
    paths = {*ROOT.joinpath("hepta").glob("*.py"), Path(__file__),
             ROOT / "tools/qualify_hia_optimizer_bench.py", STUDY / "PROTOCOL.json", STUDY / "driver.c"}
    paths.update(FIXTURES / ("kernels." + ext) for ext in ("hepta", "c", "cpp", "rs"))
    return {str(path.relative_to(ROOT)): identity(path)["sha256"] for path in sorted(paths)}


def tool_identities(tools):
    return {name: identity(path) for name, path in sorted(tools.items()) if path}


def registration(path, tools):
    result = {"schema": "hepta.hia.narrowing-bench-registration.v1", "protocol": protocol(),
              "source_bindings": bindings(), "tools": tool_identities(tools),
              "environment": environment_identity(),
              "python_runtime": runtime_identity(),
              "registered_before_training_or_performance": True,
              "source_commit": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
              "source_status": subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain"], text=True),
              "epoch_ns": time.time_ns(), "manual_preparation_time_ns": None,
              "runtime_dependency_closure": "tool executables and explicit compiler-rt archive bound; complete transitive sysroot closure not proved"}
    # The pinned SMT implementation is part of the actual proof dependency set.
    import z3
    from hepta.hia_optimization import _solver_identity
    result["solver"] = _solver_identity(z3)
    result["registration_sha256"] = sha(wire(result))
    write_new(path, result)
    return result


def require_registration(path, tools):
    value = json.loads(Path(path).read_bytes())
    require(value.get("schema") == "hepta.hia.narrowing-bench-registration.v1", "invalid registration")
    expected = value["registration_sha256"]
    require(expected == sha(wire({k: v for k, v in value.items() if k != "registration_sha256"})),
            "registration digest mismatch")
    require(value["source_bindings"] == bindings() and value["protocol"] == protocol(),
            "source/protocol changed after registration")
    require(value["tools"] == tool_identities(tools), "tools changed after registration")
    require(value["environment"] == environment_identity(), "compiler/loader environment changed after registration")
    require(value["python_runtime"] == runtime_identity(), "Python interpreter changed after registration")
    import z3
    from hepta.hia_optimization import _solver_identity
    require(value["solver"] == _solver_identity(z3), "solver changed after registration")
    return value


def execute(argv, *, timeout=120, env=None, pass_fds=()):
    start = time.perf_counter_ns()
    record = {"argv": [str(x) for x in argv], "status": "started"}
    if env is not None:
        record["LLVM_PROFILE_FILE"] = env.get("LLVM_PROFILE_FILE")
    try:
        child = subprocess.run(record["argv"], capture_output=True, text=True, timeout=timeout,
                               env=env, pass_fds=pass_fds)
        record.update(returncode=child.returncode, stdout=child.stdout, stderr=child.stderr,
                      status="completed" if child.returncode == 0 else "failed")
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
        record.update(status="timeout", returncode=None, stdout=text(error.stdout), stderr=text(error.stderr))
    except OSError as error:
        record.update(status="launch_failed", returncode=None, stdout="", stderr=str(error))
    record["wall_ns"] = time.perf_counter_ns() - start
    return record


def successful(record):
    require(record["status"] == "completed" and record["returncode"] == 0, "actual command failed: " + record["status"])
    return record["stdout"]


def sealed_driver(driver, library, arguments, *, env=None):
    begin = time.perf_counter_ns()
    data, source_identity, descriptor = _pin_native_artifact(library)
    try:
        stat = os.fstat(descriptor)
        expected = {"image_device": stat.st_dev, "image_inode": stat.st_ino, "image_bytes": len(data)}
        record = execute([driver, str(descriptor), *arguments], env=env, pass_fds=(descriptor,))
        record["sealed_image_sha256"] = sha(data)
        record["source_stat_identity"] = list(source_identity)
        record["sealed_file_identity"] = expected
        try:
            observed = json.loads(successful(record))
            require(observed.get("mapping_verified") is True
                    and all(observed.get(k) == value for k, value in expected.items())
                    and type(observed.get("symbol_file_offset")) is int
                    and 0 <= observed["symbol_file_offset"] < len(data), "executed mapping is not the sealed image")
            record["observation"] = observed
        except Exception as error:
            record["validation_error"] = str(error)
        record["invocation_wall_ns"] = time.perf_counter_ns() - begin
        return record
    finally:
        os.close(descriptor)


def tail_checksum(kernel, split, profile):
    prefix = "training" if split == "train" else "holdout"
    sizes, seeds = profile[prefix + "_sizes"], profile[prefix + "_seeds"]
    value = 1469598103934665603
    answers = {(n, seed): oracle(kernel, n, seed) for n in sizes for seed in seeds}
    for index in range(profile["request_tail_probes"]):
        observed = answers[sizes[(index * 7 + 3) % len(sizes)], seeds[(index * 3 + 2) % len(seeds)]]
        value = ((value ^ observed) * 1099511628211) % 2**64
    return value


def evaluate(rows, profile):
    result = evaluate_samples(rows, profile, BACKENDS, "hia_narrowed")
    failures = result["quality_failures"]
    expected_tails = {kernel: tail_checksum(kernel, "holdout", profile) for kernel in profile["kernels"]}
    for row in rows:
        suffix = str(row["sample_index"])
        if row.get("mapping_verified") is not True:
            failures.append("unverified_loaded_mapping_" + suffix)
        for key, count in (("request_ns", profile["request_tail_probes"]), ("clock_ns", profile["clock_overhead_probes"])):
            values = row.get(key)
            if type(values) is not list or len(values) != count or any(type(v) is not int or v <= 0 for v in values):
                failures.append(key + "_inventory_" + suffix)
        if row.get("tail_checksum") != expected_tails[row["kernel"]]:
            failures.append("tail_checksum_" + suffix)
    for kernel in profile["kernels"]:
        for backend in BACKENDS:
            selected = [r for r in rows if r["kernel"] == kernel and r["backend"] == backend
                        and type(r.get("request_ns")) is list and len(r["request_ns"]) == profile["request_tail_probes"]]
            if len(selected) != profile["groups"] or backend not in result["summary"].get(kernel, {}):
                continue
            values = [v for row in selected for v in row["request_ns"]]
            clocks = [v for row in selected for v in row.get("clock_ns", [])]
            if (not values or any(type(v) is not int or v <= 0 for v in values) or not clocks
                    or any(type(v) is not int or v <= 0 for v in clocks)):
                continue
            result["summary"][kernel][backend].update(request_count=len(values),
                request_p50_ns=quantile(values, .5), request_p95_ns=quantile(values, .95), request_p99_ns=quantile(values, .99),
                median_clock_overhead_ns=statistics.median(clocks), clock_overhead_subtracted=False)
    for comparison in result["comparisons"]:
        summary = result["summary"][comparison["kernel"]]
        candidate, baseline = summary["hia_narrowed"], summary[comparison["baseline"]]
        if "request_p95_ns" not in candidate or "request_p95_ns" not in baseline:
            comparison["noninferiority_thresholds_passed"] = False
            continue
        comparison["empirical_p95_request_ratio"] = candidate["request_p95_ns"] / baseline["request_p95_ns"]
        comparison["empirical_p99_request_ratio"] = candidate["request_p99_ns"] / baseline["request_p99_ns"]
        comparison["noninferiority_thresholds_passed"] &= (
            comparison["empirical_p95_request_ratio"] <= profile["maximum_empirical_p95_request_ratio"]
            and comparison["empirical_p99_request_ratio"] <= profile["maximum_empirical_p99_request_ratio"])
    result["quality_passed"] = not failures
    result["noninferiority_passed"] = not failures and len(result["comparisons"]) == 14 and all(
        c["noninferiority_thresholds_passed"] for c in result["comparisons"])
    strong = [c for c in result["comparisons"] if c["baseline"] in profile["strong_baselines"]]
    result["strong_noninferiority_passed"] = not failures and len(strong) == 10 and all(
        c["noninferiority_thresholds_passed"] for c in strong)
    result["request_tail_claim"] = "finite observed per-call tails including timer overhead; no population confidence bound"
    return result


def run(output_dir, registered, tools):
    profile = registered["protocol"]
    out = Path(output_dir).absolute()
    out.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter_ns()
    order = sample_order(profile, BACKENDS)
    report = {"schema": SCHEMA, "status": "running", "ok": False, "registration": registered,
              "protocol": profile, "commands": [], "builds": {}, "correctness": {}, "training": [],
              "raw_samples": [], "costs": {}, "claims": profile["claims"],
              "scheduled_samples": [{"sample_index": i, "group": g, "kernel": k, "backend": arm}
                                     for i, (g, k, arm) in enumerate(order)]}
    affinity = None

    def command(argv, phase, **kwargs):
        result = execute(argv, **kwargs)
        result["phase"] = phase
        report["commands"].append(result)
        return result

    def invocation(library, arguments, phase, **kwargs):
        result = sealed_driver(out / "driver", library, arguments, **kwargs)
        result["phase"] = phase
        report["commands"].append(result)
        return result

    try:
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 required")
        affinity = os.sched_getaffinity(0)
        os.sched_setaffinity(0, {min(affinity)})
        report["environment"] = {"platform": platform.platform(), "selected_cpu": min(affinity),
            "allowed_cpus": sorted(affinity), "exclusive_cpu": False, "load_before": os.getloadavg()}
        write_new(out / "plan.json", {"registration_sha256": registered["registration_sha256"],
            "scheduled_samples": report["scheduled_samples"], "environment": report["environment"]})
        snapshot_started = time.perf_counter_ns()
        for name, digest in registered["source_bindings"].items():
            data = (ROOT / name).read_bytes()
            require(sha(data) == digest, "source changed while snapshotting")
            path = out / "source_snapshot" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        report["costs"]["source_snapshot_wall_ns"] = time.perf_counter_ns() - snapshot_started
        for extension in ("hepta", "c", "cpp", "rs"):
            shutil.copyfile(FIXTURES / ("kernels." + extension), out / ("kernels." + extension))
        shutil.copyfile(STUDY / "driver.c", out / "driver.c")
        header = workload_header(profile)
        header += "#define REQUEST_TAIL_PROBES " + str(profile["request_tail_probes"]) + "\n"
        header += "#define CLOCK_OVERHEAD_PROBES " + str(profile["clock_overhead_probes"]) + "\n"
        (out / "workload.h").write_text(header)
        for name, path in tools.items():
            if name != "profile_runtime":
                successful(command([path, "--version"], "tool_version"))
        successful(command([tools["clang"], "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror",
                            out / "driver.c", "-ldl", "-o", out / "driver"], "driver_build"))
        start = time.perf_counter_ns()
        core = lower_source((out / "kernels.hepta").read_text())
        report["costs"]["shared_hia_frontend_wall_ns"] = time.perf_counter_ns() - start
        (out / "original.hia").write_bytes(core.canonical_bytes)
        libraries = {name: out / (name + ".so") for name in BACKENDS}
        for name, propose, build in (("hia_original", None, build_program_native),
                                     ("hia_guarded", propose_guarded_reduction, build_guarded_native),
                                     ("hia_narrowed", propose_guarded_narrowing, build_guarded_narrowed_native)):
            start = time.perf_counter_ns()
            row = {"status": "started", "proposal_wall_ns": None,
                   "fresh_proof_emit_compile_publish_wall_ns": None}
            report["builds"][name] = row
            try:
                proposal_start = time.perf_counter_ns()
                try:
                    proposal = propose(core) if propose is not None else None
                finally:
                    row["proposal_wall_ns"] = time.perf_counter_ns() - proposal_start
                build_start = time.perf_counter_ns()
                try:
                    receipt = (build(core, proposal, libraries[name], clang=tools["clang"]) if proposal is not None
                               else build(core, libraries[name], clang=tools["clang"]))
                finally:
                    row["fresh_proof_emit_compile_publish_wall_ns"] = time.perf_counter_ns() - build_start
                    row["production_preparation_wall_ns"] = time.perf_counter_ns() - start
                row.update(status="compiled", receipt=receipt)
                if proposal is not None:
                    write_new(out / (name + "-proposal.json"), proposal)
                write_new(out / (name + "-receipt.json"), receipt)
            except Exception as error:
                row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
                if "production_preparation_wall_ns" not in row:
                    row["production_preparation_wall_ns"] = time.perf_counter_ns() - start
            row["whole_preparation_wall_ns"] = time.perf_counter_ns() - start
            # The non-overlapping production interval stops before writing the
            # study's independent audit copies. Both intervals are retained.
        flags = ["-O3", "-flto=full", "-fuse-ld=" + tools["linker"], "-march=x86-64", "-mtune=generic", "-fPIC", "-shared"]
        for name, compiler, extension, standard in (("c_o3_lto", "clang", "c", "c11"),
                                                     ("cpp_o3_lto", "clangxx", "cpp", "c++17")):
            result = command([tools[compiler], "-std=" + standard, *flags, out / ("kernels." + extension),
                              "-o", libraries[name]], "baseline_build")
            report["builds"][name] = {"status": "compiled" if result["returncode"] == 0 else "failed",
                "production_preparation_wall_ns": result["wall_ns"], "command_index": len(report["commands"]) - 1}
        result = command([tools["rustc"], "--edition=2021", "--crate-type=cdylib", "-Copt-level=3", "-Clto=fat",
                          "-Ccodegen-units=1", "-Cpanic=abort", "-Ctarget-cpu=x86-64", out / "kernels.rs",
                          "-o", libraries["rust_o3_lto"]], "baseline_build")
        report["builds"]["rust_o3_lto"] = {"status": "compiled" if result["returncode"] == 0 else "failed",
            "production_preparation_wall_ns": result["wall_ns"], "command_index": len(report["commands"]) - 1}
        for label, compiler, standard in (("c", tools["clang"], "c11"), ("cpp", tools["clangxx"], "c++17")):
            start = time.perf_counter_ns()
            name = label + "_pgo_lto"
            row = {"status": "started"}
            report["builds"][name] = row
            try:
                directory = out / (label + "_profiles")
                directory.mkdir()
                instrumented = out / (label + "_instrumented.so")
                source = out / ("kernels." + label)
                if tools.get("profile_runtime"):
                    obj = out / (label + "_instrumented.o")
                    compile_flags = [flag for flag in flags if flag != "-shared" and not flag.startswith("-fuse-ld=")]
                    successful(command([compiler, "-std=" + standard, *compile_flags, "-fprofile-instr-generate",
                                        "-c", source, "-o", obj], "pgo_instrumentation_build"))
                    successful(command([compiler, *flags, obj, "-Wl,-u,__llvm_profile_runtime",
                                        tools["profile_runtime"], "-o", instrumented], "pgo_instrumentation_link"))
                else:
                    successful(command([compiler, "-std=" + standard, *flags, "-fprofile-instr-generate",
                                        source, "-o", instrumented], "pgo_instrumentation_build"))
                for kernel in profile["kernels"]:
                    env = dict(os.environ, LLVM_PROFILE_FILE=str(directory / (kernel + "-%p.profraw")))
                    measured = invocation(instrumented, [kernel, "train"], "pgo_training", env=env)
                    observation = measured.get("observation", {})
                    require(observation.get("checksum") == timed_checksum(kernel, "train", profile)
                            and observation.get("tail_checksum") == tail_checksum(kernel, "train", profile),
                            "training checksum or sealed execution failed")
                    report["training"].append({"backend": name, "kernel": kernel,
                                              "command_index": len(report["commands"]) - 1})
                profiles = sorted(directory.glob("*.profraw"))
                require(len(profiles) == 2 and all(p.stat().st_size > 0 for p in profiles), "actual PGO profiles missing")
                merged = directory / "training.profdata"
                successful(command([tools["profdata"], "merge", "-o", merged, *profiles], "pgo_merge"))
                successful(command([compiler, "-std=" + standard, *flags, "-fprofile-instr-use=" + str(merged),
                    "-Werror=profile-instr-out-of-date", "-Werror=profile-instr-unprofiled", source, "-o", libraries[name]], "pgo_use_build"))
                row.update(status="compiled", profile_inputs=[identity(p) for p in profiles], training_profile=identity(merged))
            except Exception as error:
                row.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
            row["production_preparation_wall_ns"] = time.perf_counter_ns() - start
        report["driver_identity"] = identity(out / "driver")
        report["artifacts_before"] = {name: identity(libraries[name]) for name in BACKENDS
                                      if report["builds"][name]["status"] == "compiled"}
        for name in BACKENDS:
            start = time.perf_counter_ns()
            observations, errors = [], []
            if name in report["artifacts_before"]:
                for case in correctness_cases(profile):
                    record = invocation(libraries[name], [case["kernel"], "case", str(case["size"]), str(case["seed"])], "finite_correctness")
                    observed = record.get("observation", {})
                    observations.append({**case, "actual": observed.get("actual"), "mapping_verified": observed.get("mapping_verified"),
                                         "command_index": len(report["commands"]) - 1})
                    if observed.get("actual") != case["expected"] or record["sealed_image_sha256"] != report["artifacts_before"][name]["sha256"]:
                        errors.append(case)
            report["correctness"][name] = {"observations": observations, "failures": errors,
                "wall_ns": time.perf_counter_ns() - start, "ok": not errors and len(observations) == len(correctness_cases(profile))}
        for index, (group, kernel, name) in enumerate(order):
            row = {"sample_index": index, "group": group, "kernel": kernel, "backend": name, "status": "not_built"}
            report["raw_samples"].append(row)
            if name in report["artifacts_before"]:
                record = invocation(libraries[name], [kernel, "holdout"], "measurement")
                row.update(command_index=len(report["commands"]) - 1, outer_wall_ns=record["invocation_wall_ns"],
                           library_sha256=record["sealed_image_sha256"])
                if "observation" in record and record["sealed_image_sha256"] == report["artifacts_before"][name]["sha256"]:
                    row.update(record["observation"], status="measured")
                else:
                    row.update(status="failed", error=record.get("validation_error", "artifact identity mismatch"))
            write_new(out / ("sample-" + str(index).zfill(3) + ".json"), row)
            print(json.dumps({"sample": index + 1, "total": len(order), "kernel": kernel, "backend": name, "status": row["status"]}), flush=True)
        report["evaluation"] = evaluate(report["raw_samples"], profile)
        report["source_unchanged"] = bindings() == registered["source_bindings"]
        report["tools_unchanged"] = tool_identities(tools) == registered["tools"]
        report["environment_unchanged"] = environment_identity() == registered["environment"]
        report["python_runtime_unchanged"] = runtime_identity() == registered["python_runtime"]
        report["artifacts_unchanged"] = identity(out / "driver") == report["driver_identity"] and all(
            identity(libraries[name]) == item for name, item in report["artifacts_before"].items())
        report["quality_passed"] = (report["evaluation"]["quality_passed"] and report["source_unchanged"]
            and report["tools_unchanged"] and report["artifacts_unchanged"]
            and report["environment_unchanged"]
            and report["python_runtime_unchanged"]
            and all(c["ok"] for c in report["correctness"].values()))
        report["ok"] = report["quality_passed"] and report["evaluation"]["noninferiority_passed"]
        report["status"] = ("qualified_finite_host" if report["ok"] else "completed_noninferiority_failed"
                             if report["quality_passed"] else "completed_quality_failed")
        report["break_even"] = []
        extra = (report["builds"]["hia_narrowed"]["production_preparation_wall_ns"]
                 - report["builds"]["hia_original"]["production_preparation_wall_ns"])
        for kernel in profile["kernels"]:
            summaries = report["evaluation"]["summary"].get(kernel, {})
            if "hia_original" in summaries and "hia_narrowed" in summaries:
                saved = (summaries["hia_original"]["median_elapsed_ns"] - summaries["hia_narrowed"]["median_elapsed_ns"]) / (profile["batches"] * profile["calls_per_batch"])
                report["break_even"].append({"kernel": kernel, "extra_production_preparation_ns": extra,
                    "point_saved_ns_per_call": saved, "point_calls": math.ceil(max(0, extra) / saved) if saved > 0 else None,
                    "guaranteed": False})
    except Exception as error:
        report.update(status="blocked", error={"type": type(error).__name__, "message": str(error)})
    finally:
        if affinity is not None:
            os.sched_setaffinity(0, affinity)
        report["costs"].update(all_child_command_wall_ns=sum(r["wall_ns"] for r in report["commands"]),
            whole_experiment_wall_ns=time.perf_counter_ns() - started,
            interval_policy="nested command/phase times are not added to whole-experiment time",
            candidate_preparation_fresh_proofs_included=True, pgo_training_rebuild_included=True,
            dependency_acquisition_and_manual_engineering_time_ns=None, final_report_write_included=False)
        write_new(out / "report.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--register", metavar="FILE")
    mode.add_argument("--run", metavar="NEW_OUTPUT_DIR")
    parser.add_argument("--registration", metavar="FILE")
    parser.add_argument("--clang", required=True)
    parser.add_argument("--clangxx", required=True)
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--profdata", required=True)
    parser.add_argument("--linker", required=True)
    parser.add_argument("--profile-runtime")
    args = parser.parse_args()
    tools = {name: getattr(args, name) for name in ("clang", "clangxx", "rustc", "profdata", "linker", "profile_runtime")}
    if args.register:
        result = registration(args.register, tools)
        print(json.dumps({"registration_sha256": result["registration_sha256"], "performance_requests": 0}))
        return 0
    require(args.registration is not None, "run requires a prior registration")
    registered = require_registration(args.registration, tools)
    result = run(args.run, registered, tools)
    print(json.dumps({"status": result["status"], "quality_passed": result.get("quality_passed", False), "ok": result["ok"]}))
    return 0 if result.get("quality_passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
