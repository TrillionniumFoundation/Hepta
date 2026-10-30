#!/usr/bin/env python3
"""Run the preregistered finite CRC context study on one clean source commit.

All five arms execute the same bytes. Three coalesced static controls separate
process reuse from guarded specialization. Cold setup, whole native lifecycles,
host preparation and complete evaluation overhead retain different ledgers.
No NDU policy, future-demand assumption or optimization admission is implied.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.clang_capture import run_bounded
from hepta.hia_crc_kernel import POLYNOMIALS, candidates, kernel, step, validate_source_bridge
from hepta.hia_finite_context import build_bank
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_source import lower_c_multi_owner
from hepta.native_tool_identity import digest_executable
from tools.qualify_hia_filecheck import corpus
from tools.qualify_hia_integrated import _source_state

PROTOCOL_PATH = ROOT / "experiments/hia_crc_context/protocol_v1.json"
PROTOCOL_SHA256 = "75f5f0bef5b5c49020b14b83c7c1f9257f989c5f2f0b3a365f5b7ba858329948"
PREREGISTRATION = "2b2486744e0a7094e99c3d9a9d397381cc714c25"
FIXTURE = ROOT / "examples/hia_filecheck"


def require(condition, message):
    if not condition:
        raise ValueError("E_HIA_CRC_STUDY: " + message)


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def identity(path):
    path = Path(path)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": sha256(data).hexdigest()}


def protocol():
    data = PROTOCOL_PATH.read_bytes()
    require(sha256(data).hexdigest() == PROTOCOL_SHA256, "registered protocol bytes changed")
    return json.loads(data)


def schedule(p):
    for phase in ("training", "validation"):
        for trial in range(p["trials_per_phase"]):
            workloads = p["workloads"][trial % 3:] + p["workloads"][:trial % 3]
            for workload in workloads:
                shift = (trial + p["workloads"].index(workload)) % len(p["arms"])
                arms = p["arms"][shift:] + p["arms"][:shift]
                for arm in reversed(arms) if trial % 2 else arms:
                    yield phase, trial, workload, arm


def requests(p, payload, workload, arm):
    rows = []
    for index in range(p["requests_per_trace"]):
        polynomial = POLYNOMIALS[0 if workload == "ieee" else 1 if workload == "castagnoli" else index % 2]
        label = ("ieee_guard" if arm == "coalesced_ieee_only" else
                 "castagnoli_guard" if arm == "coalesced_castagnoli_only" else
                 ("ieee_guard" if polynomial == POLYNOMIALS[0] else "castagnoli_guard")
                 if arm == "coalesced_poly_dispatch" else "baseline")
        begin = index * p["bytes_per_request"]
        rows.append({"id": index, "candidate": label, "mode": "xor_fold", "parameter": polynomial,
                     "seed": p["seed_per_request"], "values": list(payload[begin:begin + p["bytes_per_request"]])})
    return rows


def analyze(samples, cold_setup_ns, codes, p=None):
    """Evidence accounting only. This function cannot publish or execute code."""
    p = protocol() if p is None else p
    require(type(cold_setup_ns) is int and cold_setup_ns > 0, "actual positive cold setup cost required")
    expected = set(schedule(p))
    require(type(samples) is list and len(samples) == p["expected_observations"], "exact complete sample list required")
    observations = {}
    for row in samples:
        require(type(row) is dict, "ordinary observation object required")
        require(all(type(row.get(k)) is str for k in ("phase", "workload", "arm", "status"))
                and type(row.get("trial")) is int and 0 <= row["trial"] < p["trials_per_phase"],
                "exact phase/trial/workload/arm types required")
        require(all(type(row.get(k)) is int for k in ("calls", "completed_requests", "context_count")),
                "exact integer invocation counts required")
        loaded = row.get("loaded_candidates")
        require(type(loaded) is list and all(type(v) is str for v in loaded)
                and len(loaded) == len(set(loaded)), "unique exact loaded-image list required")
        key = tuple(row[k] for k in ("phase", "trial", "workload", "arm"))
        require(key in expected and key not in observations, "unexpected or duplicate controlled observation")
        require(row["status"] == "completed" and type(row["native_outer_wall_ns"]) is int
                and row["native_outer_wall_ns"] > 0 and row["calls"] == p["calls_per_trace"]
                and row["completed_requests"] == p["requests_per_trace"], "incomplete controlled observation")
        require(row["context_count"] == (p["requests_per_trace"] if key[3] == "fresh_child_baseline" else 1),
                "context reuse control differs")
        expected_images = ({"baseline"} if key[3] in {"fresh_child_baseline", "coalesced_baseline"} else
            {"ieee_guard"} if key[3] == "coalesced_ieee_only" else
            {"castagnoli_guard"} if key[3] == "coalesced_castagnoli_only" else
            {"ieee_guard", "castagnoli_guard"} if key[2] == "mixed_alternating" else
            {"ieee_guard"} if key[2] == "ieee" else {"castagnoli_guard"})
        require(set(row["loaded_candidates"]) == expected_images, "static/multiversion loaded-image control differs")
        observations[key] = row["native_outer_wall_ns"]
    require(set(observations) == expected and len(samples) == p["expected_observations"], "missing registered observation")
    require(type(codes) is dict and set(codes) == {"baseline", "ieee_guard", "castagnoli_guard"}
            and all(type(v) is str and re.fullmatch(r"[0-9a-f]{64}", v) for v in codes.values()),
            "exact exported code identities required")
    distinct = len(set(codes.values())) == 3
    rows = []
    for phase in ("training", "validation"):
        for workload in p["workloads"]:
            groups = {arm: [v for (ph, _t, w, a), v in observations.items() if (ph, w, a) == (phase, workload, arm)]
                      for arm in p["arms"]}
            reuse = min(groups["fresh_child_baseline"]) - max(groups["coalesced_baseline"])
            strongest_static = min(v for arm in ("coalesced_baseline", "coalesced_ieee_only", "coalesced_castagnoli_only")
                                   for v in groups[arm])
            increment = strongest_static - max(groups["coalesced_poly_dispatch"])
            rows.append({"phase": phase, "workload": workload,
                "arm_envelopes_ns": {a: {"min": min(v), "max": max(v)} for a, v in groups.items()},
                "batching_lower_envelope_ns": reuse, "guarded_increment_lower_envelope_ns": increment,
                "cold_net_lower_envelope_ns": increment - cold_setup_ns,
                "conditional_break_even_traces": ((cold_setup_ns + increment - 1) // increment) if increment > 0 else None})
    passed = distinct and all(r["cold_net_lower_envelope_ns"] > 0 for r in rows)
    return {"rows": rows, "cold_setup_ns": cold_setup_ns, "all_three_exported_codes_distinct": distinct,
            "economic_gate_passed": passed, "NDU_incremental_value_established": False,
            "online_admission_authorized": False, "envelope_is_statistical_confidence_interval": False,
            "break_even_is_observed_profit": False}


def _command(command, report, *, input_text=None, timeout=30):
    started = time.monotonic_ns()
    row = {"command": list(map(str, command)), "status": "started"}
    report.append(row)
    try:
        result = run_bounded(list(map(str, command)), input_text=input_text, timeout=timeout,
                             stdin_limit=65536, stdout_limit=65536, stderr_limit=65536)
        row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr, status="observed")
        require(result.returncode == 0, "original C command failed")
        return result.stdout
    except Exception as error:
        row["error"] = {"type": type(error).__name__, "message": str(error)}
        capture = getattr(error, "capture", None)
        if capture is not None:
            row.update(returncode=capture.returncode, stdout=capture.stdout.decode("utf-8", "backslashreplace"),
                       stderr=capture.stderr.decode("utf-8", "backslashreplace"))
        raise
    finally:
        row["wall_ns"] = time.monotonic_ns() - started


def _capture_and_compare(out, clang, cc, report):
    database = out / "compile_commands.json"
    write(database, [{"directory": str(FIXTURE), "file": name,
        "arguments": [clang, "-std=c11", "-I.", "-c", name, "-o", name + ".o"]}
        for name in ("checksum.c", "chunk.c")])
    migration = lower_c_multi_owner(database, clang=clang)
    core = migration.pop("program")
    (out / "captured.hia.json").write_bytes(core.canonical_bytes)
    write(out / "migration.json", migration)
    report["source_bridge"] = validate_source_bridge(core, kernel_document=kernel(), timeout_ms=10000)
    require(report["source_bridge"]["status"] == "proved", "captured CRC loop/kernel bridge unproved")
    source = out / "original-c"
    source.mkdir()
    for name in ("checksum.c", "checksum.h"):
        shutil.copyfile(FIXTURE / name, source / name)
    driver = source / "driver.c"
    driver.write_text('#include <stdio.h>\n#include "checksum.h"\n'
        'int main(void) { unsigned int s,b,p; while(scanf("%u %u %u",&s,&b,&p)==3) { '
        'if(b>255) return 2; printf("%u\\n",checksum_byte(s,(unsigned char)b,p)); } return ferror(stdin)?3:0; }\n')
    compiler = Path(shutil.which(cc) or "").resolve()
    require(compiler.is_file(), "independent original C compiler unavailable")
    before = digest_executable(compiler)
    executable = source / "original-crc"
    commands = report["original_c_commands"] = []
    _command([compiler, "-std=c11", "-O3", "-Wall", "-Wextra", "-Werror", driver, source / "checksum.c", "-o", executable], commands)
    vectors = [[s, b, p] for s in (0, 0x81234567, 0xFFFFFFFF) for b in (0, 1, 127, 255)
               for p in (*POLYNOMIALS, 0, 0x12345678)]
    payload = "".join(" ".join(map(str, v)) + "\n" for v in vectors)
    (source / "cases.stdin.txt").write_text(payload)
    native = _command([executable], commands, input_text=payload)
    values = [int(line) for line in native.splitlines()]
    expected = [step(s ^ b, p) for s, b, p in vectors]
    vm = [execute_program(core, "c_checksum_byte", args)["result"] for args in vectors]
    require(values == vm == expected and len(values) == 48, "original C / captured VM / CRC oracle differ")
    require(digest_executable(compiler) == before, "original C compiler changed")
    report["original_c_differential"] = {"cases": vectors, "expected": expected, "native": values, "vm": vm,
        "compiler": str(compiler), "compiler_sha256": before, "executable": identity(executable),
        "source_files": [identity(source / name) for name in ("checksum.c", "checksum.h", "driver.c")],
        "cases_executed": len(values), "ok": True}


def qualify(*, clang, cc, output, expected_source):
    started = time.monotonic_ns()
    p = protocol()
    require(type(expected_source) is str and re.fullmatch(r"[0-9a-f]{40}", expected_source), "full source SHA required")
    out = Path(output).resolve()
    require(out != ROOT and ROOT not in out.parents, "output must be outside source tree")
    out.mkdir(parents=True, exist_ok=False)
    (out / "frozen-protocol.json").write_bytes(PROTOCOL_PATH.read_bytes())
    report = {"schema": "hepta.hia.crc-context-qualification.v1", "qualified": False, "status": "failed",
        "expected_source": expected_source, "preregistration_commit": PREREGISTRATION,
        "protocol_sha256": PROTOCOL_SHA256, "protocol": p, "observed_utc": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "machine": platform.machine(), "python": sys.version},
        "samples": [], "claims": {"NDU_incremental_value_established": False, "global_optimality": False,
            "production_trace": False, "online_adaptive_policy": False, "persistent_owner_state": False,
            "source_C_refinement_proved": False, "final_machine_code_refinement_proved": False}}
    bank = None
    serial = 0
    try:
        before = report["source_state_before"] = _source_state()
        require(before["head"] == expected_source and not before["status"], "exact clean source required")
        require(platform.system() == "Linux" and platform.machine().lower() == "x86_64", "actual native Linux x86_64 required")
        for name in ("/proc/cpuinfo", "/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/memory.max"):
            if Path(name).is_file(): report["host"][name] = Path(name).read_text()[:12000]
        _capture_and_compare(out, clang, cc, report)
        documents = candidates()
        for label, document in documents.items():
            require(verify_program(document).sha256 == p["kernel"]["canonical_sha256"][label], "registered candidate bytes differ")
        require(report["source_bridge"]["kernel_sha256"] == p["kernel"]["canonical_sha256"]["baseline"], "source bridge root differs")
        build = out / "bank"
        build.mkdir()
        bank_report = report["bank"] = {}
        cases = [[s, poly] for s in (0, 1, 0x81234567, 0xFFFFFFFF) for poly in (*POLYNOMIALS, 0, 0x12345678)]
        bank = build_bank(kernel(), documents, build, clang=clang, cases=cases, oracle=step, report=bank_report)
        data = {}
        report["inputs"] = {}
        for phase in ("training", "validation"):
            spec = p["data"][phase]
            data[phase] = corpus(spec["seed"], spec["bytes"])
            path = out / (phase + ".bin")
            path.write_bytes(data[phase])
            report["inputs"][phase] = identity(path)
        report["cold_setup_before_release_ns"] = time.monotonic_ns() - started
        logs = out / "contexts"
        logs.mkdir()
        for phase, trial, workload, arm in schedule(p):
            sample = {"phase": phase, "trial": trial, "workload": workload, "arm": arm,
                      "status": "started", "contexts": [], "native_outer_wall_ns": 0,
                      "trace_preparation_wall_ns": 0, "calls": 0, "completed_requests": 0,
                      "loaded_candidates": [], "context_count": 0}
            report["samples"].append(sample)
            sample_start = time.monotonic_ns()
            plan = requests(p, data[phase], workload, arm)
            plan_path = logs / f"sample-{len(report['samples']):03d}.plan.json"
            write(plan_path, plan)
            sample["plan"] = identity(plan_path)
            groups = [[request] for request in plan] if arm == "fresh_child_baseline" else [plan]
            loaded = set()
            for group in groups:
                require(time.monotonic_ns() - started <= p["max_study_wall_ns"], "registered study deadline exhausted")
                stage = time.monotonic_ns()
                trace = bank.prepare_trace(group)
                sample["trace_preparation_wall_ns"] += time.monotonic_ns() - stage
                serial += 1
                path = logs / f"context-{serial:04d}.json"
                observed = {}
                try:
                    bank.run(trace, report=observed)
                finally:
                    write(path, observed)
                    sample["contexts"].append(identity(path))
                sample["native_outer_wall_ns"] += observed["outer_wall_ns"]
                sample["completed_requests"] += len(observed["prefix"]["completed_requests"])
                sample["calls"] += sum(r["calls"] for r in observed["prefix"]["completed_requests"])
                loaded.update(r["candidate"] for r in observed["loaded_inventory"])
                sample["context_count"] += 1
            sample.update(status="completed", loaded_candidates=sorted(loaded),
                          arm_host_wall_ns=time.monotonic_ns() - sample_start)
        report["qualified"] = True
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if bank is not None:
            release = bank.close()
            report["release"] = release
            if not release["complete"]:
                report["qualified"] = False
                report["cleanup_error"] = "uncertain release; no retry"
            report["cold_setup_ns"] = report.get("cold_setup_before_release_ns", time.monotonic_ns() - started) + release["wall_ns"]
        try:
            report["source_state_after"] = _source_state()
            report["source_inputs_unchanged"] = report["source_state_after"] == report.get("source_state_before")
            require(report["source_inputs_unchanged"], "source identity changed")
        except Exception as error:
            report["qualified"] = False
            report["source_error"] = str(error)
        report["whole_study_wall_ns"] = time.monotonic_ns() - started
        if report["whole_study_wall_ns"] > p["max_study_wall_ns"]:
            report["qualified"] = False
            report["budget_error"] = "registered study wall deadline exhausted"
        if report["qualified"]:
            try:
                codes = {label: row["code"]["sha256"] for label, row in report["bank"]["candidates"].items()}
                report["economics"] = analyze(report["samples"], report["cold_setup_ns"], codes, p)
                report["status"] = "qualified_cold_opportunity" if report["economics"]["economic_gate_passed"] else "qualified_no_cold_opportunity"
            except Exception as error:
                report["qualified"] = False
                report["analysis_error"] = str(error)
        report["evaluation_overhead_included_in_study_ns"] = report["whole_study_wall_ns"] - report.get("cold_setup_ns", 0)
        report["cost_exclusions"] = ["tool installation", "outer interpreter startup/imports/arguments",
                                     "final analysis/report JSON encoding and writing"]
        report["contexts_attempted"] = serial
        write(out / "RESULT.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-source", required=True)
    args = parser.parse_args()
    result = qualify(clang=args.clang, cc=args.cc, output=args.output, expected_source=args.expected_source)
    print(json.dumps({k: result.get(k) for k in ("qualified", "status", "contexts_attempted", "cold_setup_ns", "whole_study_wall_ns", "error")}, sort_keys=True))
    return 0 if result["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
