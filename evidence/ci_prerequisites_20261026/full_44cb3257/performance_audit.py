#!/usr/bin/env python3
"""Independent arithmetic/receipt review of three retained CI performance profiles.

Only standard-library data processing occurs here. No production module,
compiler, benchmark, native program, Git process or network is invoked.
"""
from collections import Counter
from fractions import Fraction
from functools import lru_cache
import hashlib
import json
import math
from pathlib import PurePosixPath
import re

CANDIDATE = "44cb32576f0ee8b0d9f01aa5a4fa44ea0848c314"
COMPILER = "baa9c71bf65c590b23598635012989ac2f07242803b1a876b13a28eec2848bd7"
QUALIFIERS = {"scalar":"tools/qualify_llvm_native.py", "owned":"tools/qualify_llvm_owned.py", "hia":"tools/qualify_hia_program_perf.py"}
PROTOCOLS = {"scalar":"4e688e468819eb317043fb94db6834ec790c4da98c1956d60bc7ec357d65ed89",
             "owned":"af27b7f8758bd95623f4748e356dff542e063141669e586205d295b6d65dda51",
             "hia":"df1df380d1ddc84836093ac0e83824d907b9341d31b6e8c00ad230089a6f9891"}
KERNELS = ("full_lifecycle", "constructor_error", "two_stage")
BACKENDS = ("rust", "llvm", "handwritten_rust")
CALLS = {"full_lifecycle":1048576,"constructor_error":8388608,"two_stage":1048576}
LINUX = {"visible_cgroup_cpu_stat":"/sys/fs/cgroup/cpu.stat", "visible_cgroup_cpu_pressure":"/sys/fs/cgroup/cpu.pressure", "host_cpu_pressure":"/proc/pressure/cpu"}
CHILDREN = {"user_cpu_ns", "system_cpu_ns", "voluntary_context_switches", "involuntary_context_switches", "minor_page_faults", "major_page_faults"}
SCOPE = {
    "wall":"monotonic_ns around the complete capture call; startup, warmup, timed loop, shutdown and output capture",
    "children":"RUSAGE_CHILDREN cumulative differences; may include other children reaped by this process",
    "cpu_time_units":"nanoseconds converted from getrusage timeval seconds; units do not imply nanosecond resolution",
    "linux":"visible cgroup mount-root and host PSI snapshots; can include unrelated processes and are not per-driver counters",
    "native_elapsed_replaced":False,"sample_selection_or_threshold_adjustment":False,
    "exclusive_cpu_access_proved":False,"measurement_cause_proved":False}

class FrozenData:
    def value(self, commit, path, name):
        require(commit == CANDIDATE, "frozen source commit differs")
        if name == "KERNELS" and path in QUALIFIERS.values():
            return ("signed_walk", "unsigned_walk", "branch_accumulate") if path == QUALIFIERS["scalar"] else KERNELS
        require(path == "tools/performance_observation.py", "unexpected frozen input")
        if name == "SCOPE": return SCOPE
        if name == "SCHEMA": return "hepta.driver-process-observation.v1"
        raise ValueError("unexpected frozen constant")

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
                offset = (group + (kernels.index(kernel) if kind == "hia" else position)) % len(backends)
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
            if kind != "scalar" and max(values) > 30_000_000_000:
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
            if kind != "scalar":
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
                require(error == {"type": "ValueError", "errno": None},
                        "retained malformed raw counters require the actual parse-failure type")
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
            require(row["checksum"] == checksum(row["kernel"]),
                    "owned timed checksum differs from the independent formula digest")
            require(same(execution["command"], command) and type(execution["returncode"]) is int
                    and execution["returncode"] == 0, "owned retained execution differs")
            require(same(parse(execution["stdout"]), {key: row[key] for key in
                    ("elapsed_ns", "checksum", "clock_resolution_ns", "process_peak_rss_kib")}), "owned driver output differs")
            driver = report["artifacts"]["driver_binary"]
            library = report["artifacts"][row["backend"] + "_library"]
            require(row["driver_sha256"] == driver["sha256"]
                    and row["library_sha256"] == library["sha256"]
                    and command[:2] == [driver["path"], library["path"]],
                    "owned timing sample is not bound to the recorded driver/library")
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


def process(row, expected_returncode=0):
    require(type(row) is dict and type(row.get("returncode")) is int
            and row["returncode"] == expected_returncode, "recorded process exit differs")
    require(set(row) == {"command", "returncode", "stdout", "stderr", "stdout_sha256", "stderr_sha256"},
            "complete process record has extra capture failure or unexpected fields")
    require(type(row.get("command")) is list and all(type(x) is str for x in row["command"]),
            "recorded process command malformed")
    for channel in ("stdout", "stderr"):
        require(type(row[channel]) is str and sha(row[channel].encode()) == row[channel + "_sha256"],
                "recorded process output hash differs")


def oracle(kernel, size, seed):
    if kernel == "two_alloc":
        return 1 if size >= 2**63 else 2 if seed else size + 19
    if size >= 2**63:
        return 1001 + (seed if kernel == "constructor_error" else 0)
    if kernel == "constructor_error":
        return 1002 + seed
    if kernel == "two_stage":
        return size * ((seed % 256) ^ 90)
    require(kernel == "full_lifecycle", "unknown kernel")
    blocks, tail = divmod(size, 256)
    return blocks * sum(range(256)) + sum((index + seed) % 256 for index in range(tail))


@lru_cache(maxsize=3)
def checksum(kernel):
    # This is integer digest arithmetic over formula values, never a native run
    # or a timing experiment. All three results are cached for negative tests.
    values = [oracle(kernel, 4093, (index * 17 + 13) % 97 + 1) for index in range(64)]
    result = 1469598103934665603
    for _ in range(CALLS[kernel] // 64):
        for value in values:
            result = ((result ^ value) * 1099511628211) % 2**64
    return result


def correctness(report):
    cases = []
    for kernel in KERNELS:
        cases.extend((kernel, size, seed) for size in (0, 1, 2, 7, 255, 256, 257, 4093, 65519)
                     for seed in (0, 1, 90, 255, 256, 2**32 - 1))
    cases.extend((kernel, size, seed) for kernel in (*KERNELS, "two_alloc")
                 for size in (2**63, 2**64 - 1) for seed in (0, 2**32 - 1))
    cases.extend(("two_alloc", size, seed) for size in (0, 1, 3, 5, 17, 4093)
                 for seed in (0, 1, 2**32 - 1))
    expected = [{"backend": backend, "kernel": kernel, "size": size, "seed": seed,
                 "expected": oracle(kernel, size, seed), "actual": oracle(kernel, size, seed)}
                for backend in BACKENDS for kernel, size, seed in cases]
    row = report["correctness"]
    process(row["process"])
    observed = [parse(line) for line in row["process"]["stdout"].splitlines()]
    require(same(observed, expected) and same(row["observations"], expected),
            "finite native correctness receipts differ from independent formulas")
    require(row["native_calls"] == len(expected) == 588 and row["status"] == "passed_finite_domain"
            and row["observations_sha256"] == sha(wire(expected)), "finite correctness denominator")
    return {"cases_per_backend": len(cases), "backends": list(BACKENDS), "native_calls": len(expected),
            "recorded_outputs_match_independent_formulas": True}


def source_correctness(report, kind):
    cases = []
    if kind == "scalar":
        for kernel in ("signed_walk", "unsigned_walk", "branch_accumulate"):
            unsigned = kernel == "unsigned_walk"
            counts = (0, 1, 2, 7, 31, 127, 257, 1024) + (() if unsigned else (-7, -1))
            seeds = ((0, 1, 97, 65535, 65536, 196606, 2**32 - 1) if unsigned else
                     (-2**31, -1, 0, 1, 97, 2**31 - 1) if kernel == "signed_walk" else
                     (-7, -1, 0, 1, 6, 7, 97))
            for iterations in counts:
                for seed in seeds:
                    state, total = seed, 0
                    for _ in range(max(0, iterations)):
                        if kernel == "signed_walk":
                            state += 31 if state < 0 else -19
                        elif kernel == "unsigned_walk":
                            state = state * 3 + 1 if state < 65536 else state - 65535
                        elif state < 7:
                            total, state = total + state, state + 1
                        else:
                            total, state = total - 3, 0
                    cases.append({"kernel": kernel, "iterations": iterations, "seed": seed,
                                  "expected": total if kernel == "branch_accumulate" else state})
        backends = ("rust", "llvm")
    else:
        inputs = [(kernel, size, seed) for kernel in KERNELS
                  for size in (0, 1, 2, 7, 255, 256, 257, 4093, 65519)
                  for seed in (0, 1, 90, 255, 256, 2**32 - 1)]
        inputs += [(kernel, size, seed) for kernel in (*KERNELS, "two_alloc")
                   for size in (2**63, 2**64 - 1) for seed in (0, 2**32 - 1)]
        inputs += [("two_alloc", size, seed) for size in (0, 1, 3, 5, 17, 4093)
                   for seed in (0, 1, 2**32 - 1)]
        cases = [{"kernel": kernel, "size": size, "seed": seed, "expected": oracle(kernel, size, seed)}
                 for kernel, size, seed in inputs]
        backends = ("rust", "llvm", "handwritten_rust", "c")
    retained = report["correctness"]
    require(retained["status"] == "passed_finite_domain" and same(cases, retained["cases"])
            and retained["case_count"] == len(cases) and retained["native_calls"] == len(cases) * len(backends),
            "finite source correctness formula/domain differs")
    if kind == "owned":
        digest = sha(wire([{**row, "actual": row["expected"]} for row in cases]))
        require(retained["observations_sha256"] == {name: digest for name in backends},
                "owned formula observation digest differs")
    return {"case_count": len(cases), "reported_native_calls": len(cases) * len(backends),
            "correctness_backends": list(backends), "formula_domain_recomputed": True,
            "actual_per_case_native_outputs_retained": False,
            "scope": "original qualifier asserts actual ABI checks; this report retains formula cases/digests, not individual actual outputs"}


def process_rows(value):
    if type(value) is dict:
        fields = {"command", "returncode", "stdout", "stderr", "stdout_sha256", "stderr_sha256"}
        if fields <= set(value):
            yield value
        for child in value.values():
            yield from process_rows(child)
    elif type(value) is list:
        for child in value:
            yield from process_rows(child)


def hia_observations(report):
    rows = report["raw_samples"]
    counter_fields = ("voluntary_context_switches", "involuntary_context_switches", "minor_page_faults", "major_page_faults")
    native_fields = {"elapsed_ns", "checksum", "clock_resolution_ns", "process_peak_rss_kib", "process_cpu_ns", *counter_fields}
    linked = []
    for row in rows:
        require(all(type(row[field]) is int for field in native_fields)
                and row["process_cpu_ns"] > 0 and all(row[field] >= 0 for field in counter_fields),
                "native HIA counter unavailable or malformed")
        execution = row["execution"]
        process(execution)
        require(same(parse(execution["stdout"]), {name: row[name] for name in native_fields})
                and execution["stderr"] == "", "HIA stdout observation association")
        artifacts = report["artifacts"]
        require(execution["command"] == [artifacts["driver"]["path"], artifacts[row["backend"]]["path"], row["kernel"]]
                and row["driver_sha256"] == artifacts["driver"]["sha256"]
                and row["library_sha256"] == artifacts[row["backend"]]["sha256"], "HIA measured command/artifact association")
        require(row["checksum"] == checksum(row["kernel"]), "HIA checksum differs from independent formula digest")
        linked.append({key: row[key] for key in ("sample_index", "group", "kernel", "backend", *sorted(native_fields),
                                                "driver_sha256", "library_sha256")}
                      | {"stdout_sha256": execution["stdout_sha256"], "stderr_sha256": execution["stderr_sha256"]})
    ratios = [Fraction(row["process_cpu_ns"], row["elapsed_ns"]) for row in rows]
    observation = {"sample_count": len(rows), "cpu_to_wall_ratio": {
        "minimum": float(min(ratios)), "median": float(sorted(ratios)[len(ratios) // 2]), "maximum": float(max(ratios))},
        "totals": {key: sum(row[key] for row in rows) for key in counter_fields},
        "scope": "CPU interval brackets the wall interval; overhead and host interference are not isolated",
        "samples_excluded": 0, "acceptance_thresholds_adjusted": False}
    require(same(observation, report["interference_observations"]), "HIA observation summary differs")
    require(report["environment"]["scheduler"]["exclusive_cpu_ownership"] is False, "exclusive HIA CPU scope enlarged")
    return {"schema": "native-driver-observations", "count": len(rows), "summary": observation, "records": linked,
            "exclusive_host_proved": False, "contention_cause_proved": False}


def resource_control(report, kind):
    if kind == "scalar":
        return {"scope": "scalar profile has no owned allocator cleanup observer"}
    row = report["resource_observation"]
    require(row["status"] == "passed" and row["rehashed_llvm_rejected" if kind == "hia"
            else "origin_mutation_rejected_before_native_build"] is True, "resource/origin control incomplete")
    positive, negative = row["positive"], row["negative"]
    process(positive, 0)
    process(negative, 1)
    good = {"allocations": 7, "frees": 7, "live": 0, "refusals": 1}
    bad = parse(negative["stdout"])
    allocations = bad.get("allocations") if isinstance(bad, dict) else None
    require(type(allocations) is int and allocations > 0
            and (kind != "hia" or allocations == 7)
            and same(parse(positive["stdout"]), good)
            and same(bad, {"allocations": allocations, "frees": 0, "live": allocations, "refusals": 1}),
            "actual allocator/refusal/missing-free control differs")
    return {"positive": good, "missing_free_negative": bad, "negative_exit_code": 1,
            "scope": "untimed LLVM cleanup/refusal control, not Rust allocator traces or the uninstrumented timed binaries"}


def audit_performance(report, kind):
    require(kind in QUALIFIERS and report["git_commit"] == CANDIDATE
            and report["compiler_tree_sha256"] == COMPILER, "performance candidate source differs")
    require(report["schema"] == {"scalar": "hepta.llvm-native-qualification.v1",
        "owned": "hepta.llvm-owned-qualification.v1", "hia": "hepta.hia.program-perf-qualification.v1"}[kind],
        "performance schema/profile differs")
    require(report["phase"] == "complete" and report.get("finished_utc")
            and not any(key in report for key in ("diagnostic", "failed_command", "failed_sample")),
            "incomplete report cannot receive complete arithmetic review")
    require(report["protocol_sha256"] == PROTOCOLS[kind] == sha(wire(report["protocol"])),
            "frozen profile protocol differs")
    result = recompute(report, kind, FrozenData())
    for kernel, group in result["summary"].items():
        for backend, values in group["implementations"].items():
            key = "median_ns_per_kernel_iteration" if kind == "scalar" else "median_ns_per_native_call"
            divisor = 1024 * 1048576 if kind == "scalar" else CALLS[kernel]
            calculated = values["median_ns"] / divisor
            require(calculated == report["evaluation"]["summary"][kernel]["implementations"][backend][key],
                    "native call/iteration denominator differs")
            values[key] = calculated
    complete_processes = list(process_rows(report))
    require(len(complete_processes) == {"scalar": 0, "owned": 70, "hia": 71}[kind], "complete process record denominator")
    for row in complete_processes:
        require(type(row["returncode"]) is int and row["returncode"] in (0, 1), "unrecognized native process result")
        process(row, row["returncode"])
    outcomes = dict(Counter(row["returncode"] for row in complete_processes))
    if kind != "scalar":
        require(outcomes == ({0: 69, 1: 1} if kind == "owned" else {0: 70, 1: 1}), "native process returncode inventory")
    claims = report.get("claims", {})
    if kind == "hia":
        require(claims["host_performance_gate_passed"] is result["performance_qualified"]
                and all(claims[key] is False for key in ("backend_refinement_proved", "physical_device_qualified",
                    "universal_rust_superiority_proved", "whole_language_performance_qualified")), "HIA performance scope enlarged")
    return {"profile": kind, "source_commit": CANDIDATE, "compiler_sha256": COMPILER,
            "protocol_sha256": PROTOCOLS[kind], "started_utc": report["started_utc"], "finished_utc": report["finished_utc"],
            "evaluation": result, "correctness": correctness(report) if kind == "hia" else source_correctness(report, kind),
            "observations": hia_observations(report) if kind == "hia" else associate_observations(report, kind, FrozenData()),
            "process_streams": {"complete_records": len(complete_processes), "returncode_counts": {str(k):v for k,v in outcomes.items()},
                "stdout_stderr_hash_pairs_checked": len(complete_processes),
                "scope": "scalar does not retain complete per-sample stdout/stderr records; telemetry hashes are distinct"},
            "resource_control": resource_control(report, kind), "native_execution_repeated": False,
            "production_evaluate_samples_called": False, "arbitrary_third_party_execution_authenticated": False}
