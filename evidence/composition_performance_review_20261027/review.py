#!/usr/bin/env python3
"""Recompute two retained performance reports without compiling or timing.

Only retained JSON/text and immutable Git objects are read. No production
qualifier, evaluate_samples, observer, compiler, driver or benchmark is invoked.
This is an arithmetic/provenance review, not authentication of a third-party run.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from copy import deepcopy
from fractions import Fraction
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import statistics
import subprocess

CANDIDATE = "3a424e427b378400802c9e3c2fef558c0a352756"
BASELINE = "bdb8690"
QUALIFIERS = {"scalar": "tools/qualify_llvm_native.py", "owned": "tools/qualify_llvm_owned.py"}
GATES = {"scalar": "llvm_native_performance", "owned": "llvm_owned_performance"}
LINUX = {"visible_cgroup_cpu_stat": "/sys/fs/cgroup/cpu.stat",
         "visible_cgroup_cpu_pressure": "/sys/fs/cgroup/cpu.pressure",
         "host_cpu_pressure": "/proc/pressure/cpu"}
CHILDREN = {"user_cpu_ns", "system_cpu_ns", "voluntary_context_switches",
            "involuntary_context_switches", "minor_page_faults", "major_page_faults"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def same(left, right):
    return wire(left) == wire(right)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def parse(data):
    def nonfinite(value):
        raise ValueError("non-finite JSON number: " + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)


def stable_read(path):
    require(path.is_file() and not path.is_symlink(), "regular retained input required")
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "retained input changed during reading")
    require(data == path.read_bytes(), "retained input bytes are not stable")
    return data


class FrozenSources:
    def __init__(self, repository):
        self.repository = repository

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repository), *args], timeout=30)

    @lru_cache(None)
    def read(self, revision, path):
        return self.git("show", revision + ":" + path)

    @lru_cache(None)
    def definitions(self, revision, path):
        text = self.read(revision, path).decode()
        definitions = {}
        for node in ast.parse(text).body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        definitions[target.id] = (node.value, ast.get_source_segment(text, node))
            elif isinstance(node, ast.FunctionDef):
                definitions[node.name] = (node, ast.get_source_segment(text, node))
        return definitions

    def value(self, revision, path, name, context=None):
        values = context or {}
        class Resolve(ast.NodeTransformer):
            def visit_Name(self, node):
                return ast.parse(repr(values[node.id]), mode="eval").body if node.id in values else node
        return ast.literal_eval(Resolve().visit(deepcopy(self.definitions(revision, path)[name][0])))

    def protocol(self, revision, kind):
        path = QUALIFIERS[kind]
        context = {}
        if kind == "owned":
            context["PROFILE"] = self.value(revision, "hepta/llvm_owned_backend.py", "PROFILE")
            context.update({name: self.value(revision, path, name) for name in ("CALLS", "SIZES")})
        return self.value(revision, path, "PROTOCOL", context)

    @lru_cache(None)
    def compiler_hash(self):
        names = self.git("ls-tree", "--name-only", CANDIDATE + ":hepta").decode().splitlines()
        digest = hashlib.sha256()
        for name in sorted(name for name in names if name.endswith(".py")):
            digest.update(name.encode() + b"\0" + self.read(CANDIDATE, "hepta/" + name) + b"\0")
        return digest.hexdigest()

    def unchanged_protocol_evidence(self):
        result = {"baseline_commit": self.git("rev-parse", BASELINE).decode().strip(),
                  "candidate_commit": CANDIDATE, "definitions": {}, "files": {}}
        for kind, path in QUALIFIERS.items():
            names = ["PROTOCOL", "KERNELS", "evaluate_samples"]
            names += ["SOURCE", "DRIVER"] if kind == "scalar" else ["sample_order", "CALLS", "SIZES", "BACKENDS"]
            for name in names:
                old = self.definitions(BASELINE, path)[name][1].encode()
                new = self.definitions(CANDIDATE, path)[name][1].encode()
                require(old == new, "changed frozen definition: " + path + ":" + name)
                result["definitions"][path + ":" + name] = {"exact_bytes_equal": True, "sha256": sha(new)}
            require(same(self.protocol(BASELINE, kind), self.protocol(CANDIDATE, kind)), "expanded protocol changed")
            result[kind + "_protocol_sha256"] = sha(wire(self.protocol(CANDIDATE, kind)))
        for name in ("owned.hepta", "qualification.hepta", "reference.rs", "driver.c", "observe.c"):
            path = "examples/llvm_owned/" + name
            old, new = self.read(BASELINE, path), self.read(CANDIDATE, path)
            require(old == new, "changed frozen workload: " + path)
            result["files"][path] = {"exact_bytes_equal": True, "sha256": sha(new)}
        path = "docs/LLVM_OWNED_PERFORMANCE_PROTOCOL.md"
        require(self.read(BASELINE, path) == self.read(CANDIDATE, path), "owned protocol document changed")
        result["files"][path] = {"exact_bytes_equal": True, "sha256": sha(self.read(CANDIDATE, path))}
        return result


def schedule(kind, kernels, backends, groups):
    result = []
    for group in range(groups):
        for position in range(len(kernels)):
            kernel = kernels[(group + position) % len(kernels)]
            order = list(backends)
            if kind == "scalar":
                if (group + position) % 2:
                    order.reverse()
            else:
                offset = (group + position) % len(backends)
                order = order[offset:] + order[:offset]
                if group % 2:
                    order.reverse()
            result.extend((group, kernel, backend) for backend in order)
    return result


def recompute(report, kind, frozen):
    protocol, rows = report["protocol"], report["raw_samples"]
    kernels = frozen.value(CANDIDATE, QUALIFIERS[kind], "KERNELS")
    backends = ("rust", "llvm") if kind == "scalar" else ("rust", "llvm", "handwritten_rust")
    order = schedule(kind, kernels, backends, protocol["paired_groups"])
    require(len(rows) == len(order) == (42 if kind == "scalar" else 63), "incomplete sample inventory")
    observations = {}
    for index, (row, expected) in enumerate(zip(rows, order)):
        require(same([row[key] for key in ("group", "kernel", "backend", "sample_index")], [*expected, index]),
                "sample sequence differs from independently reconstructed frozen schedule")
        require(type(row["elapsed_ns"]) is int and row["elapsed_ns"] > 0, "invalid native duration")
        require(type(row["checksum"]) is int and 0 <= row["checksum"] < 2**64, "invalid checksum")
        observations[expected] = row
    quality, performance, summary = [], [], {}
    baselines = ("rust",) if kind == "scalar" else ("rust", "handwritten_rust")
    ratio_medians = {baseline: [] for baseline in baselines}
    for kernel in kernels:
        implementations, comparisons = {}, {}
        require(len({row["checksum"] for row in rows if row["kernel"] == kernel}) == 1,
                "timed input checksum differs across groups/backends")
        for backend in backends:
            values = [observations[(group, kernel, backend)]["elapsed_ns"] for group in range(7)]
            median = sorted(values)[3]
            mad = sorted(abs(value - median) for value in values)[3]
            relative = Fraction(mad, median)
            implementations[backend] = {"samples_ns": values, "median_ns": median, "mad_ns": mad,
                "relative_mad": float(relative), "relative_mad_fraction": str(relative),
                "minimum_ns": min(values), "maximum_ns": max(values),
                "quality_pass": min(values) >= 50_000_000 and relative <= Fraction(1, 20)
                    and (kind == "scalar" or max(values) <= 30_000_000_000)}
            if min(values) < 50_000_000:
                quality.append(kernel + "/" + backend + ": sample shorter than fixed minimum")
            if kind == "owned" and max(values) > 30_000_000_000:
                quality.append(kernel + "/" + backend + ": sample longer than fixed maximum")
            if relative > Fraction(1, 20):
                quality.append(kernel + "/" + backend + ": relative MAD above fixed maximum")
            retained = report["evaluation"]["summary"][kernel]["implementations"][backend]
            for key in ("samples_ns", "median_ns", "relative_mad", "minimum_ns", "maximum_ns"):
                require(same(implementations[backend][key], retained[key]), "retained sample statistics differ")
        for baseline in baselines:
            values = [Fraction(observations[(group, kernel, "llvm")]["elapsed_ns"],
                               observations[(group, kernel, baseline)]["elapsed_ns"]) for group in range(7)]
            median = sorted(values)[3]
            comparisons[baseline] = {"paired_time_ratios": list(map(float, values)),
                "paired_time_ratio_fractions": list(map(str, values)), "median_paired_time_ratio": float(median),
                "median_paired_time_ratio_fraction": str(median), "threshold_pass": median <= Fraction(6, 5)}
            ratio_medians[baseline].append(median)
            if median > Fraction(6, 5):
                performance.append((kernel + ": median paired LLVM/Rust ratio exceeds fixed maximum") if kind == "scalar"
                    else kernel + "/" + baseline + ": paired ratio exceeds fixed maximum")
            retained = report["evaluation"]["summary"][kernel]
            if kind == "owned":
                retained = retained["comparisons"][baseline]
            for key in ("paired_time_ratios", "median_paired_time_ratio"):
                require(same(comparisons[baseline][key], retained[key]), "retained paired ratios differ")
        summary[kernel] = {"implementations": implementations, "comparisons": comparisons}
    geometric = {}
    for baseline, medians in ratio_medians.items():
        product = math.prod(medians)
        value = float(product) ** (1 / len(medians))
        passed = product <= Fraction(11, 10) ** len(medians)
        geometric[baseline] = {"ratio": value, "product_fraction": str(product), "threshold_pass": passed}
        retained = (report["evaluation"]["geometric_mean_paired_time_ratio"] if kind == "scalar"
                    else report["evaluation"]["geometric_mean_paired_time_ratios"][baseline])
        require(math.isclose(value, retained, rel_tol=1e-14, abs_tol=1e-15), "retained geometric mean differs")
        if not passed:
            performance.append("geometric mean LLVM/Rust ratio exceeds fixed maximum" if kind == "scalar"
                               else baseline + ": geometric mean exceeds fixed maximum")
    status = "measurement_inconclusive" if quality else "performance_failed" if performance else "passed"
    require(same(quality, report["evaluation"]["measurement_quality_failures"])
            and same(performance, report["evaluation"]["performance_threshold_failures"]), "retained failure conditions differ")
    require(report["status"] == report["evaluation"]["status"] == status
            and report["ok"] is report["evaluation"]["ok"] is (status == "passed"), "outer status differs")
    return {"status": status, "performance_qualified": status == "passed", "sample_count": len(rows),
            "kernel_order": list(kernels), "backend_order": list(backends), "summary": summary,
            "geometric_means": geometric, "measurement_quality_failures": quality,
            "performance_threshold_failures": performance, "all_retained_evaluation_fields_match": True,
            "geometric_comparison_tolerance": {"relative": 1e-14, "absolute": 1e-15},
            "threshold_decisions": "exact rational comparisons; cube of geometric threshold compared with exact ratio product"}


def linux_counters(name, text):
    result = {}
    for line in text.splitlines():
        parts = line.split()
        if name == "visible_cgroup_cpu_stat":
            require(len(parts) == 2 and re.fullmatch(r"[A-Za-z0-9_.]+", parts[0])
                    and parts[1].isascii() and parts[1].isdigit(), "invalid cpu.stat row")
            key, value = parts[0], int(parts[1])
        else:
            require(parts and parts[0] in ("some", "full"), "invalid PSI row")
            fields = pairs(tuple(item.split("=", 1)) for item in parts[1:])
            require(set(fields) == {"avg10", "avg60", "avg300", "total"}, "PSI fields differ")
            require(fields["total"].isascii() and fields["total"].isdigit(), "PSI total invalid")
            require(all(math.isfinite(float(fields[key])) and float(fields[key]) >= 0
                        for key in ("avg10", "avg60", "avg300")), "PSI averages invalid")
            key, value = parts[0] + ".total_us", int(fields["total"])
        require(key not in result, "duplicate kernel counter")
        result[key] = value
    require(bool(result), "empty kernel counters")
    return result


def snapshot(value, name):
    keys = {"status", "counters", "error"} | ({"path", "raw", "raw_sha256"} if name != "children" else set())
    require(type(value) is dict and set(value) == keys, "snapshot schema differs")
    if name != "children":
        require(value["path"] == LINUX[name], "kernel counter path differs")
        raw = value["raw"]
        require((raw is None and value["raw_sha256"] is None) or
                (type(raw) is str and len(raw.encode("ascii")) <= 16384 and sha(raw.encode("ascii")) == value["raw_sha256"]),
                "raw counter hash differs")
    if value["status"] == "unavailable":
        require(value["counters"] is None, "unavailable counters were replaced with measured values")
        error = value["error"]
        require(type(error) is dict and set(error) == {"type", "errno"} and type(error["type"]) is str
                and error["type"] and (error["errno"] is None or type(error["errno"]) is int), "availability error missing")
        if name != "children" and value["raw"] is not None:
            try:
                linux_counters(name, value["raw"])
            except ValueError:
                pass
            else:
                raise ValueError("valid raw counters marked unavailable")
    else:
        require(value["status"] == "observed" and value["error"] is None
                and type(value["counters"]) is dict and value["counters"]
                and all(type(n) is int and n >= 0 for n in value["counters"].values()), "invalid observed counters")
        if name == "children":
            require(set(value["counters"]) == CHILDREN, "rusage counter inventory differs")
        else:
            require(value["raw"] is not None and same(value["counters"], linux_counters(name, value["raw"])),
                    "raw kernel counters differ from parsed counters")


def associate_observations(report, kind, frozen):
    records, rows = report["process_observations"], report["raw_samples"]
    require(type(records) is list and len(records) == len(rows), "observation inventory incomplete")
    scope = frozen.value(CANDIDATE, "tools/performance_observation.py", "SCOPE")
    expected_schema = frozen.value(CANDIDATE, "tools/performance_observation.py", "SCHEMA")
    directory = PurePosixPath(report["reference_validation"]["path"]).parent
    counts = {name: Counter() for name in ("children", *LINUX)}
    errors = {name: Counter() for name in counts}
    sums = {name: None for name in counts}
    linked, previous_end = [], None
    for index, (row, observation) in enumerate(zip(rows, records)):
        require(set(observation) == {"schema", "scope", "sample", "command", "state", "capture_exception",
                "clock", "children", "linux"}, "observation schema differs")
        expected_sample = {key: row[key] for key in ("sample_index", "group", "kernel", "backend")}
        command = [str(directory / "driver"), str(directory / (row["backend"] + ".so")), row["kernel"]]
        if kind == "scalar":
            command += [str(report["protocol"][key]) for key in
                        ("kernel_iterations", "native_calls_per_sample", "warmup_calls_per_process")]
        else:
            execution = row["execution"]
            require(same(execution["command"], command) and type(execution["returncode"]) is int
                    and execution["returncode"] == 0, "owned retained execution differs")
            require(same(parse(execution["stdout"]), {key: row[key] for key in
                    ("elapsed_ns", "checksum", "clock_resolution_ns", "process_peak_rss_kib")}), "owned driver output differs")
        require(same(observation["sample"], expected_sample) and same(observation["command"], command)
                and observation["schema"] == expected_schema and same(observation["scope"], scope)
                and observation["state"] == "complete" and observation["capture_exception"] is None,
                "observation sample, scope or command mismatch")
        clock = observation["clock"]
        require(set(clock) == {"start_monotonic_ns", "end_monotonic_ns", "wall_ns"}
                and all(type(n) is int and n >= 0 for n in clock.values())
                and clock["wall_ns"] == clock["end_monotonic_ns"] - clock["start_monotonic_ns"]
                and (previous_end is None or clock["start_monotonic_ns"] >= previous_end), "clock order/difference differs")
        previous_end = clock["end_monotonic_ns"]
        require(set(observation["linux"]) == set(LINUX), "Linux source inventory differs")
        sources = {}
        for name, item in {"children": observation["children"], **observation["linux"]}.items():
            require(set(item) == {"before", "after", "status", "delta", "decreased_counters"}, "counter difference schema differs")
            before, after = item["before"], item["after"]
            snapshot(before, name); snapshot(after, name)
            status, delta, decreased = "unavailable", None, []
            if before["status"] == after["status"] == "observed":
                if set(before["counters"]) != set(after["counters"]):
                    status = "counter_set_changed"
                else:
                    decreased = sorted(key for key in before["counters"] if before["counters"][key] > after["counters"][key])
                    status = "counter_reset" if decreased else "observed"
                    if not decreased:
                        delta = {key: after["counters"][key] - value for key, value in before["counters"].items()}
            require(item["status"] == status and same(item["delta"], delta)
                    and same(item["decreased_counters"], decreased), "delta/reset/missing counters differ")
            counts[name][status] += 1
            for value in (before, after):
                if value["error"] is not None:
                    errors[name][value["error"]["type"] + ":" + str(value["error"]["errno"])] += 1
            if delta is not None:
                if sums[name] is None:
                    sums[name] = dict(delta)
                elif set(sums[name]) == set(delta):
                    sums[name] = {key: sums[name][key] + value for key, value in delta.items()}
                else:
                    raise ValueError("available delta sets differ across samples; no implicit missing-counter zeros")
            sources[name] = {"status": status, "delta": delta,
                "before_sha256": sha(wire(before)), "after_sha256": sha(wire(after)),
                "before_error": before["error"], "after_error": after["error"], "decreased_counters": decreased}
        linked.append({"sample": expected_sample, "native_elapsed_ns": row["elapsed_ns"],
            "observation_sha256": sha(wire(observation)), "command": command, "clock": clock,
            "wall_encloses_native_elapsed": clock["wall_ns"] >= row["elapsed_ns"], "sources": sources})
    return {"count": len(linked), "scope": scope, "records": linked,
        "availability": {name: {"status_counts": dict(counts[name]), "snapshot_error_counts": dict(errors[name]),
            "sum_over_available_deltas": sums[name], "complete_delta_sum": sums[name] if counts[name]["observed"] == len(rows) else None}
            for name in counts}, "sample_filtering_performed": False, "native_elapsed_adjusted": False,
        "exclusive_host_proved": False, "contention_cause_proved": False}


def review(path, kind, frozen):
    data = stable_read(path)
    report = parse(data)
    require(report["git_commit"] == CANDIDATE and report["phase"] == "complete"
            and report["finished_utc"] and "diagnostic" not in report, "report is not a complete frozen execution")
    protocol = frozen.protocol(CANDIDATE, kind)
    require(same(protocol, report["protocol"]) and sha(wire(protocol)) == report["protocol_sha256"], "report protocol differs")
    require(protocol["paired_groups"] == 7 and protocol["minimum_sample_seconds"] == 0.05
            and protocol["maximum_relative_mad"] == 0.05 and protocol["maximum_kernel_paired_time_ratio"] == 1.2
            and protocol["maximum_geometric_mean_paired_time_ratio"] == 1.1, "review thresholds differ from frozen protocol")
    require(report["compiler_tree_sha256"] == frozen.compiler_hash(), "compiler tree differs from frozen Git objects")
    observer_sha = sha(frozen.read(CANDIDATE, "tools/performance_observation.py"))
    if kind == "scalar":
        require(report["qualifier_sha256"] == sha(frozen.read(CANDIDATE, QUALIFIERS[kind]))
                and report["process_observer_sha256"] == observer_sha, "scalar qualifier/observer identity differs")
        for key, name in (("source_sha256", "SOURCE"), ("driver_source_sha256", "DRIVER")):
            require(report[key] == sha(frozen.value(CANDIDATE, QUALIFIERS[kind], name).encode()), "scalar input identity differs")
    else:
        require(protocol["maximum_sample_seconds"] == 30.0, "owned maximum duration changed")
        paths = [QUALIFIERS[kind], "tools/evidence_checks.py", "tools/performance_observation.py"]
        paths += ["examples/llvm_owned/" + name for name in
                  ("owned.hepta", "qualification.hepta", "reference.rs", "driver.c", "observe.c")]
        require(same(report["inputs"], {name: sha(frozen.read(CANDIDATE, name)) for name in paths}), "owned input identities differ")
    log_path = path.parent / (GATES[kind] + ".log")
    log_data = stable_read(log_path)
    terminal = parse(log_data)
    require(terminal["status"] == report["status"] and terminal["ok"] is report["ok"], "completed collector log differs")
    # release_check writes this log only after the producer subprocess returns.
    evaluation = recompute(report, kind, frozen)
    observations = associate_observations(report, kind, frozen)
    require(stable_read(path) == data, "report changed during review")
    return {"input": {"path": str(path.resolve()), "sha256": sha(data), "bytes": len(data),
                      "producer_log_path": str(log_path.resolve()), "producer_log_sha256": sha(log_data)},
        "source_identity": {"git_commit": CANDIDATE, "compiler_tree_sha256": report["compiler_tree_sha256"],
            "protocol_sha256": report["protocol_sha256"], "process_observer_sha256": observer_sha,
            "qualifier_sha256": sha(frozen.read(CANDIDATE, QUALIFIERS[kind])),
            "driver_source_sha256": report["driver_source_sha256"], "source_sha256": report["source_sha256"]},
        "producer_started_utc": report["started_utc"], "producer_finished_utc": report["finished_utc"],
        "environment": report["environment"], "evaluation": evaluation, "process_observations": observations,
        "review_scope": "arithmetic, frozen input identities, complete sample order and retained observation association; no native rerun or complete compiler-correctness validation"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--scalar", type=Path, required=True)
    parser.add_argument("--owned", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    frozen = FrozenSources(args.repository)
    result = {"schema": "hepta.independent-retained-performance-review.v1", "candidate_commit": CANDIDATE,
        "reviewer_source_sha256": sha(Path(__file__).read_bytes()),
        "review_status": "recomputed_without_native_execution", "benchmarks_executed": 0,
        "production_evaluate_samples_called": False, "samples_removed_or_retried": 0,
        "external_concurrent_native_work_reported_by_parent": True,
        "exclusive_host_proved": False, "arbitrary_third_party_execution_authenticated": False,
        "protocol_comparison": frozen.unchanged_protocol_evidence(),
        "reports": {"scalar": review(args.scalar, "scalar", frozen), "owned": review(args.owned, "owned", frozen)}}
    with args.output.open("xb") as output:
        output.write(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False).encode() + b"\n")
    print(json.dumps({kind: {"status": value["evaluation"]["status"], "samples": value["evaluation"]["sample_count"],
        "quality_failures": value["evaluation"]["measurement_quality_failures"],
        "performance_threshold_failures": value["evaluation"]["performance_threshold_failures"]}
        for kind, value in result["reports"].items()}, sort_keys=True))


if __name__ == "__main__":
    main()
