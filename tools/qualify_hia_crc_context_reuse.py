#!/usr/bin/env python3
"""Run the separate source-frozen finite CRC reference-reuse protocol.

The old 120-second protocol and all its incomplete observations are unchanged.
This study supplies no NDU arm, production-demand evidence or cache-off timing.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
from hashlib import sha256, shake_256
import json
from pathlib import Path
import platform
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_crc_kernel import POLYNOMIALS, candidates, kernel, step
from hepta.hia_finite_context import (MAX_ORACLE_REFERENCE_BYTES, MAX_ORACLE_REFERENCES, build_bank)
from hepta.hia_program import verify_program
from tools import qualify_hia_crc_context as historical
from tools.qualify_hia_filecheck import corpus
from tools.qualify_hia_integrated import _source_state

PROTOCOL_PATH = ROOT / "experiments/hia_crc_context/protocol_v2.json"
PROTOCOL_SHA256 = "62fb0f94dc8a58ffc9d31137c28449162ec6847eb32937fb9b66946185b9a996"
PROTOCOL_V3_PATH = ROOT / "experiments/hia_crc_context/protocol_v3.json"
PROTOCOL_V3_SHA256 = "e3aa8c8cac5e9b6caa014660cd174232bd3dd4b84ae7206a2c2af1426888226b"
require, write, identity = historical.require, historical.write, historical.identity
schedule, requests = historical.schedule, historical.requests


def protocol(version=2):
    require(type(version) is int and version in (2, 3), "explicit supported protocol version required")
    path, digest = ((PROTOCOL_PATH, PROTOCOL_SHA256) if version == 2
                    else (PROTOCOL_V3_PATH, PROTOCOL_V3_SHA256))
    data = path.read_bytes()
    require(sha256(data).hexdigest() == digest, "new frozen protocol bytes changed")
    p = json.loads(data)
    old = p["historical_protocol"]
    require(sha256((ROOT / old["path"]).read_bytes()).hexdigest() == old["sha256"],
            "historical protocol must remain unchanged")
    require(p["reference_reuse"]["max_entries"] == MAX_ORACLE_REFERENCES
            and p["reference_reuse"]["max_canonical_bytes"] == MAX_ORACLE_REFERENCE_BYTES,
            "registered reference limits differ from implementation")
    if version == 3:
        prior = p["prior_protocol"]
        require(sha256((ROOT / prior["path"]).read_bytes()).hexdigest() == prior["sha256"],
                "v2 protocol and its disclosed all-zero study must remain unchanged")
    return p


def phase_input(p, phase):
    spec = p["data"][phase]
    if p["data"]["generator"] == "tools.qualify_hia_filecheck.corpus":
        return corpus(spec["seed"], spec["bytes"])
    require(p["data"]["generator"] == "SHAKE256-domain-phase-seed-v3", "unknown input generator")
    material = (p["data"]["domain"].encode("ascii") + b"\0" + phase.encode("ascii") + b"\0"
                + spec["seed"].to_bytes(8, "big"))
    return shake_256(material).digest(spec["bytes"])


def input_diversity(p, data):
    width = p["bytes_per_request"]
    chunks = [payload[i * width:(i + 1) * width]
              for payload in data.values() for i in range(p["requests_per_trace"])]
    record = {"phases_distinct": data["training"] != data["validation"],
              "request_chunks": len(chunks), "unique_chunks": len(set(chunks)),
              "zero_chunks": sum(chunk == bytes(width) for chunk in chunks),
              "all_chunk_lengths_exact": all(len(chunk) == width for chunk in chunks),
              "independent_statistical_confirmation": False}
    if p["data"]["generator"] == "SHAKE256-domain-phase-seed-v3":
        require(record["phases_distinct"] and record["unique_chunks"] == len(chunks)
                and record["zero_chunks"] == 0 and record["all_chunk_lengths_exact"],
                "diverse input admission failed before timing")
    return record


def analyze(samples, cold_setup_ns, codes, p=None):
    p = protocol() if p is None else p
    native = historical.analyze(samples, cold_setup_ns, codes, p)
    charged = copy.deepcopy(samples)
    for row in charged:
        require(type(row.get("arm_host_wall_ns")) is int
                and row["arm_host_wall_ns"] >= row["native_outer_wall_ns"],
                "complete positive host cost including native execution required")
        row["native_outer_wall_ns"] = row["arm_host_wall_ns"]
    full = historical.analyze(charged, cold_setup_ns, codes, p)
    full.update(observation_cost_metric="arm_host_wall_ns", native_only_diagnostic=native,
                end_to_end_cache_speedup_established=False, public_preregistration_claim=False)
    return full


def prime_references(bank, p, data):
    rows = []
    for phase in ("training", "validation"):
        for workload in ("ieee", "castagnoli"):
            started = time.monotonic_ns()
            trace = bank.prepare_trace(requests(p, data[phase], workload, "coalesced_baseline"))
            cancelled = bank.cancel(trace)
            rows.append({"phase": phase, "workload": workload, "cancellation": cancelled,
                         "wall_ns": time.monotonic_ns() - started})
    return rows


def qualify(*, clang, cc, output, expected_source, protocol_version=2):
    started = time.monotonic_ns()
    p = protocol(protocol_version)
    selected_protocol = PROTOCOL_PATH if protocol_version == 2 else PROTOCOL_V3_PATH
    selected_digest = PROTOCOL_SHA256 if protocol_version == 2 else PROTOCOL_V3_SHA256
    require(type(expected_source) is str and re.fullmatch(r"[0-9a-f]{40}", expected_source), "full source SHA required")
    out = Path(output).resolve()
    require(out != ROOT and ROOT not in out.parents, "output must be outside source tree")
    out.mkdir(parents=True, exist_ok=False)
    (out / "frozen-protocol.json").write_bytes(selected_protocol.read_bytes())
    report = {"schema": f"hepta.hia.crc-context-reference-qualification.v{protocol_version}", "qualified": False,
        "status": "failed", "expected_source": expected_source,
        "source_freeze": "local-frozen-before-run", "public_preregistration_claim": False,
        "protocol_sha256": selected_digest, "protocol": p,
        "observed_utc": datetime.now(timezone.utc).isoformat(), "samples": [],
        "host": {"platform": platform.platform(), "machine": platform.machine(), "python": sys.version},
        "claims": dict(p["claims"])}
    bank = None
    serial = 0
    try:
        before = report["source_state_before"] = _source_state()
        require(before["head"] == expected_source and not before["status"], "exact clean source required")
        require(platform.system() == "Linux" and platform.machine().lower() == "x86_64", "actual Linux x86_64 required")
        for name in ("/proc/cpuinfo", "/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/memory.max"):
            if Path(name).is_file():
                report["host"][name] = Path(name).read_text()[:12000]
        historical._capture_and_compare(out, clang, cc, report)
        documents = candidates()
        for label, document in documents.items():
            require(verify_program(document).sha256 == p["kernel"]["canonical_sha256"][label], "registered candidate differs")
        require(report["source_bridge"]["kernel_sha256"] == p["kernel"]["canonical_sha256"]["baseline"], "source bridge differs")
        build = out / "bank"
        build.mkdir()
        cases = [[s, poly] for s in (0, 1, 0x81234567, 0xFFFFFFFF) for poly in (*POLYNOMIALS, 0, 0x12345678)]
        bank = build_bank(kernel(), documents, build, clang=clang, cases=cases, oracle=step,
                          report=report.setdefault("bank", {}), reuse_oracle=True)
        data = {}
        report["inputs"] = {}
        for phase in ("training", "validation"):
            data[phase] = phase_input(p, phase)
            path = out / (phase + ".bin")
            path.write_bytes(data[phase])
            report["inputs"][phase] = identity(path)
        report["input_diversity"] = input_diversity(p, data)
        report["reference_priming"] = prime_references(bank, p, data)
        primed = report["reference_state_after_priming"] = bank.oracle_reference_statistics()
        require(primed["misses"] > 0 and primed["capacity_bypasses"] == 0 and primed["failed_computations"] == 0,
                "reference priming incomplete")
        logs = out / "contexts"
        logs.mkdir()
        report["cold_setup_before_release_ns"] = time.monotonic_ns() - started
        for phase, trial, workload, arm in schedule(p):
            require(time.monotonic_ns() - started <= p["max_study_wall_ns"], "new study deadline exhausted")
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
            groups = [[r] for r in plan] if arm == "fresh_child_baseline" else [plan]
            loaded = set()
            for group in groups:
                require(time.monotonic_ns() - started <= p["max_study_wall_ns"], "new study deadline exhausted")
                stage = time.monotonic_ns()
                trace = bank.prepare_trace(group)
                sample["trace_preparation_wall_ns"] += time.monotonic_ns() - stage
                stats = bank.oracle_reference_statistics()
                require(stats["misses"] == primed["misses"] and stats["capacity_bypasses"] == 0,
                        "an arm requested a reference outside the common primed set")
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
        require(serial == p["expected_native_contexts"], "registered native context count differs")
        report["qualified"] = True
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if bank is not None:
            report["reference_state_before_close"] = bank.oracle_reference_statistics()
            release = report["release"] = bank.close()
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
            report["budget_error"] = "new study deadline exhausted"
        if report["qualified"]:
            try:
                codes = {label: row["code"]["sha256"] for label, row in report["bank"]["candidates"].items()}
                report["economics"] = analyze(report["samples"], report["cold_setup_ns"], codes, p)
                report["status"] = ("qualified_cold_opportunity" if report["economics"]["economic_gate_passed"]
                                    else "qualified_no_cold_opportunity")
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
    parser.add_argument("--clang", required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--protocol-version", type=int, choices=(2, 3), default=2)
    args = parser.parse_args()
    result = qualify(clang=args.clang, cc=args.cc, output=args.output, expected_source=args.expected_source,
                     protocol_version=args.protocol_version)
    print(json.dumps({k: result.get(k) for k in ("qualified", "status", "contexts_attempted", "cold_setup_ns",
                                               "whole_study_wall_ns", "error")}, sort_keys=True))
    return 0 if result["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
