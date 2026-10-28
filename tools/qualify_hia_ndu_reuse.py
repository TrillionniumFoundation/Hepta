#!/usr/bin/env python3
"""Measure registered exact advisory reuse against equally reusable controls.

This is a controller-only study. The existing compiler consumer is exercised,
but old calibrated costs are model inputs, not new HIA runtime samples. No code
publication or application speedup is claimed by this qualifier.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_ndu import (FINITE_RUSTC_VERSION, FINITE_SOURCE_PIN, MAX_REQUEST_BYTES,
                          NduBridge, NduBridgeError, _read_json)
from hepta.hia_ndu_cache import NduDecisionCache, _wire
from tools.qualify_hia_ndu_graph import (arithmetic_choice, choose_native_graph_plan,
                                       graph_bundle, light_bundle)

PROTOCOL_PATH = ROOT / "experiments/hia_ndu_reuse/PROTOCOL_20261028.json"
ARMS = ["fixed-plan-reuse", "complete-dp-reuse", "enumeration-reuse", "native-uncached", "native-exact-reuse"]


def save(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def digest(value):
    return sha256(_wire(value)).hexdigest()


def validate_protocol(protocol):
    if (type(protocol) is not dict
            or protocol.get("schema") != "hepta.hia.ndu.exact-request-reuse.protocol.v1"
            or protocol.get("arms") != ARMS
            or protocol.get("trace_profiles") != ["identical-retries", "changed-generation"]):
        raise ValueError("unsupported controller protocol or control arms")
    for name, lower, upper in (("groups", 1, 8), ("keys_per_trace", 1, 128),
        ("repetitions_per_key", 2, 64), ("cache_entries", 1, 128),
        ("cache_payload_bytes", 1, 64 * 1024 * 1024),
        ("episode_budget_ns", 1, 120_000_000_000),
        ("graph_remaining_budget_ns", 1, 1_000_000_000_000),
        ("graph_completion_value_ns", 1, 1_000_000_000_000),
        ("graph_forecast_decision_ns", 1, 1_000_000_000_000)):
        if type(protocol.get(name)) is not int or not lower <= protocol[name] <= upper:
            raise ValueError("invalid protocol integer: " + name)
    if protocol["keys_per_trace"] > protocol["cache_entries"]:
        raise ValueError("registered exact-retry trace must fit every control's equal capacity")
    if protocol.get("native_source_pin") != FINITE_SOURCE_PIN or protocol.get("native_rustc") != FINITE_RUSTC_VERSION:
        raise ValueError("unsupported native profile")
    if protocol.get("batch_sizes") != [64, 4096, 16384]:
        raise ValueError("registered frozen-bank sizes changed")
    if protocol.get("sample_exclusion") != "none; failed, refused and timed-out attempts remain in the result":
        raise ValueError("all attempted observations must be retained")
    return protocol


class RecordedFiniteBridge(NduBridge):
    """Original native executable/protocol, with original command streams saved.

    Recording costs belong to the native strategy. This subclass changes only
    subprocess evidence retention; source identity and response admission use
    the production NduBridge checks. It does not implement NDU arithmetic.
    """
    def __init__(self, identity, directory, *, timeout=10):
        self.directory, self.command_count = Path(directory), 0
        self.directory.mkdir()
        manifest = _read_json(Path(identity).read_bytes())
        native = manifest.get("identity", {})
        if (native.get("source_commit") != FINITE_SOURCE_PIN
                or not str(native.get("rustc", "")).startswith("rustc " + FINITE_RUSTC_VERSION + " ")):
            raise NduBridgeError("recorded finite bridge requires its exact source/tool profile")
        super().__init__(manifest["binary"], identity, timeout=timeout)
        if self.manifest != manifest:
            raise NduBridgeError("recorded finite identity changed during admission")

    def _invoke(self, arguments, payload):
        self.command_count += 1
        stem = self.directory / f"{self.command_count:04d}"
        command = [str(self.executable), *arguments]
        started, error, code = time.monotonic_ns(), None, None
        try:
            completed = subprocess.run(command, input=payload, capture_output=True,
                                       timeout=self.timeout, check=False)
            stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
        except subprocess.TimeoutExpired as failure:
            stdout, stderr = failure.stdout or b"", failure.stderr or b""
            error = str(failure)
        except OSError as failure:
            stdout, stderr, error = b"", b"", str(failure)
        row = {"argv": command, "returncode": code, "error": error,
               "wall_ns_before_record_write": time.monotonic_ns() - started}
        for name, raw in (("stdin", payload), ("stdout", stdout), ("stderr", stderr)):
            path = stem.with_suffix("." + name)
            with path.open("xb") as stream:
                stream.write(raw)
            row[name] = {"file": path.name, "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
        save(stem.with_suffix(".json"), row)
        if error:
            raise NduBridgeError("recorded native NDU execution failed: " + error)
        if len(stdout) > 4 * MAX_REQUEST_BYTES:
            raise NduBridgeError("native response exceeds bound")
        result = _read_json(stdout)
        if code != 0 or result.get("status") == "error":
            raise NduBridgeError(str(result.get("error", "native NDU failed")))
        if result.get("authority") != "DENY_ALL" or result.get("safety_certificate") is not False:
            raise NduBridgeError("native transport attempted to confer authority")
        return result


class PlanReuseControl:
    """Equal-capacity exact-input reuse for the nonnative strong controls."""
    def __init__(self, protocol):
        self.limit, self.byte_limit = protocol["cache_entries"], protocol["cache_payload_bytes"]
        self.rows, self.bytes = OrderedDict(), 0
        self.hits, self.misses, self.evictions = 0, 0, 0

    def evaluate(self, bank, arguments, construct):
        payload = _wire({"bank": bank, "arguments": arguments})
        key = sha256(payload).hexdigest()
        row = self.rows.get(key)
        if row is not None:
            if row[0] != payload or sha256(row[1]).hexdigest() != row[2]:
                raise RuntimeError("control cached input or plan changed")
            self.hits += 1
            self.rows.move_to_end(key)
            return json.loads(row[1]), True
        self.misses += 1
        plan = construct()
        raw = _wire(plan)
        cost = len(payload) + len(raw)
        if cost <= self.byte_limit:
            while self.rows and (len(self.rows) >= self.limit or self.bytes + cost > self.byte_limit):
                _, old = self.rows.popitem(last=False)
                self.bytes -= len(old[0]) + len(old[1])
                self.evictions += 1
            self.rows[key] = (payload, raw, sha256(raw).hexdigest())
            self.bytes += cost
        return json.loads(raw), False

    def close(self):
        previous = {"hits": self.hits, "misses": self.misses, "evictions": self.evictions}
        self.rows.clear()
        self.bytes = 0
        return {**previous, "closed": True, "entries": 0, "retained_payload_bytes": 0}


def load_bank(protocol):
    path = (ROOT / protocol["training_bank_path"]).resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("training bank must be a repository input")
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != protocol["training_bank_sha256"]:
        raise RuntimeError("registered training bank changed")
    original = json.loads(raw)
    result = {"bank_sha256": original["bank_sha256"], "candidates": {}}
    for name, row in original["candidates"].items():
        result["candidates"][name] = {"source_sha256": row["source_sha256"],
            "verification": {"status": row["status"], "verification_sha256": row["verification_sha256"]},
            "setup_ns": row["setup_ns"], "latency_ns": row["latency_ns"]}
    return result


def make_trace(protocol, profile, group):
    if profile not in {"identical-retries", "changed-generation"}:
        raise ValueError("unknown trace profile")
    keys = protocol["keys_per_trace"]
    trace = []
    for repetition in range(protocol["repetitions_per_key"]):
        for key in range(keys):
            serial = repetition * keys + key
            generation = group * 1000 + (key if profile == "identical-retries" else serial) + 1
            arguments = dict(current="base", remaining_sizes=protocol["batch_sizes"], observations=[],
                remaining_ns=protocol["graph_remaining_budget_ns"] - key * 1_000_000,
                decision_ns=protocol["graph_forecast_decision_ns"],
                protocol={"completion_value_ns": protocol["graph_completion_value_ns"]},
                snapshot=digest({"protocol": digest(protocol), "group": group, "profile": profile, "key": key}),
                generation=generation)
            trace.append({"serial": serial, "key": key, "repetition": repetition,
                          "arguments": arguments})
    return trace


def run_episode(root, arm, profile, group, bank, trace, expected, protocol, identity):
    folder = root / f"{profile}-{group}-{arm}"
    folder.mkdir()
    started = time.monotonic_ns()
    deadline = started + protocol["episode_budget_ns"]
    native, cache, control = None, None, None
    result = {"arm": arm, "profile": profile, "group": group, "status": "running",
              "samples": [], "trace_sha256": digest(trace), "candidate_publication_attempted": False}

    def remaining():
        left = deadline - time.monotonic_ns()
        if left <= 0:
            raise TimeoutError("registered episode controller budget exhausted")
        return left

    try:
        if arm.startswith("native-"):
            native = RecordedFiniteBridge(identity, folder / "native-commands",
                                          timeout=min(10, remaining() / 1e9))
            if arm == "native-exact-reuse":
                cache = NduDecisionCache(native, max_entries=protocol["cache_entries"],
                                         max_bytes=protocol["cache_payload_bytes"])
        else:
            control = PlanReuseControl(protocol)
        with (folder / "samples.jsonl").open("x") as stream:
            for item, expected_actions in zip(trace, expected):
                remaining()
                request_start = time.monotonic_ns()
                arguments = item["arguments"]
                if native:
                    native.timeout = min(10, remaining() / 1e9)
                    bundle = graph_bundle(bank, **arguments)
                    selected, response, reuse = choose_native_graph_plan(bundle, native,
                                                                         decision_cache=cache)
                    evidence = {"native_response": response, "reuse_receipt": reuse,
                                "request_sha256": digest(bundle["request"])}
                    hit = reuse["reused_exact_response"] if reuse else False
                else:
                    def construct():
                        bundle = (graph_bundle if arm == "enumeration-reuse" else light_bundle)(bank, **arguments)
                        return arithmetic_choice(bundle, remaining_ns=arguments["remaining_ns"],
                                                 completion_ns=protocol["graph_completion_value_ns"])
                    selected, hit = control.evaluate(bank, arguments, construct)
                    evidence = {"control": arm, "reused_exact_input": hit}
                if selected is None or not selected["verified"] or selected["actions"] != expected_actions:
                    raise RuntimeError("controller disagrees with the complete graph's admitted plan")
                remaining()
                sample = {"serial": item["serial"], "generation": arguments["generation"],
                    "input_sha256": digest(arguments), "selected_plan": selected["id"],
                    "actions_sha256": digest(selected["actions"]), "correct": True,
                    "reused": hit, "wall_ns_before_evidence_write": time.monotonic_ns() - request_start,
                    **evidence}
                stream.write(json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n")
                stream.flush()
                result["samples"].append({k: sample[k] for k in ("serial", "generation", "input_sha256",
                    "selected_plan", "actions_sha256", "correct", "reused", "wall_ns_before_evidence_write")})
                remaining()
        result["status"] = "completed"
    except Exception as error:
        result.update(status="failed-or-refused", error=f"{type(error).__name__}: {error}")
    finally:
        result["reuse_close"] = cache.close() if cache else control.close() if control else None
        result["actual_native_command_count"] = native.command_count if native else 0
    result["wall_ns_before_result_write"] = time.monotonic_ns() - started
    save(folder / "RESULT.json", result)
    result["episode_wall_ns"] = time.monotonic_ns() - started
    result["actual_budget_passed"] = result["episode_wall_ns"] <= protocol["episode_budget_ns"]
    result["completion_admitted"] = (result["status"] == "completed" and result["actual_budget_passed"]
                                     and len(result["samples"]) == len(trace))
    return result


def qualify(output, *, identity, protocol_path=PROTOCOL_PATH):
    started = time.monotonic_ns()
    root = Path(output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    protocol_raw = Path(protocol_path).read_bytes()
    protocol = validate_protocol(json.loads(protocol_raw))
    bank = load_bank(protocol)
    manifest_raw = Path(identity).read_bytes()
    manifest = json.loads(manifest_raw)
    if (manifest["identity"]["source_commit"] != protocol["native_source_pin"]
            or not manifest["identity"]["rustc"].startswith("rustc " + protocol["native_rustc"] + " ")):
        raise ValueError("native profile differs from registered protocol")
    build = manifest.get("build_cost", {})
    if build.get("target_cache") != "empty" or type(build.get("wall_ns")) is not int:
        raise ValueError("recorded original empty-target build cost is required")
    paths = [ROOT / p for p in ("hepta/hia_ndu.py", "hepta/hia_ndu_cache.py",
        "tools/qualify_hia_ndu_graph.py", "tools/qualify_hia_ndu_reuse.py",
        "tests/test_hia_ndu_cache.py", "tests/test_hia_ndu_graph.py",
        protocol["training_bank_path"], "experiments/hia_ndu_reuse/README.md")]
    protocol_path = Path(protocol_path).resolve()
    if not protocol_path.is_relative_to(ROOT):
        raise ValueError("protocol must be committed in the source repository before measurement")
    paths.append(protocol_path)
    sources = {str(p.relative_to(ROOT)): sha256(p.read_bytes()).hexdigest() for p in paths}
    source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source_status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    if source_status:
        raise RuntimeError("controller timing requires a clean, committed source/protocol worktree")
    for relative, expected_digest in sources.items():
        raw = subprocess.check_output(["git", "cat-file", "blob", source_commit + ":" + relative], cwd=ROOT)
        if sha256(raw).hexdigest() != expected_digest:
            raise RuntimeError("source input differs from its committed Git blob: " + relative)
    save(root / "SOURCE_IDENTITY.json", {"commit": source_commit, "status": source_status, "files": sources})
    (root / "PROTOCOL.json").write_bytes(protocol_raw)
    (root / "NATIVE_BUILD_IDENTITY.json").write_bytes(manifest_raw)
    save(root / "TRAINING_BANK.json", bank)
    for relative in sources:
        path = root / "sources" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
    traces, expected = {}, {}
    for profile in protocol["trace_profiles"]:
        for group in range(protocol["groups"]):
            trace = make_trace(protocol, profile, group)
            traces[profile, group] = trace
            expected[profile, group] = []
            for item in trace:
                bundle = graph_bundle(bank, **item["arguments"])
                oracle = arithmetic_choice(bundle, remaining_ns=item["arguments"]["remaining_ns"],
                                           completion_ns=protocol["graph_completion_value_ns"])
                if oracle is None:
                    raise RuntimeError("registered finite model has no executable complete plan")
                expected[profile, group].append(oracle["actions"])
            save(root / f"trace-{profile}-{group}.json", trace)
    common_preparation_ns = time.monotonic_ns() - started
    episodes = []
    arms = protocol["arms"]
    for group in range(protocol["groups"]):
        for profile_index, profile in enumerate(protocol["trace_profiles"]):
            shift = (group + profile_index) % len(arms)
            order = arms[shift:] + arms[:shift]
            if group % 2:
                order = order[::-1]
            for arm in order:
                episodes.append(run_episode(root, arm, profile, group, bank, traces[profile, group],
                    expected[profile, group], protocol, identity))
    unchanged = (sources == {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in sources}
                 and Path(protocol_path).read_bytes() == protocol_raw
                 and Path(identity).read_bytes() == manifest_raw)
    totals = {arm: sum(e["episode_wall_ns"] for e in episodes if e["arm"] == arm) for arm in arms}
    warm = {arm: total + common_preparation_ns for arm, total in totals.items()}
    cold = {arm: total + (build["wall_ns"] if arm.startswith("native-") else 0) for arm, total in warm.items()}
    passed = unchanged and all(e["completion_admitted"] for e in episodes)
    expected_hits = protocol["keys_per_trace"] * (protocol["repetitions_per_key"] - 1)
    cache_behavior = all(sum(s["reused"] for s in e["samples"]) ==
        (expected_hits if e["profile"] == "identical-retries" and e["arm"] != "native-uncached" else 0)
        for e in episodes if e["completion_admitted"])
    controls = [arm for arm in arms if not arm.startswith("native-")]
    result = {"schema": "hepta.hia.ndu.exact-request-reuse.result.v1",
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "python": sys.version, "cpu_count": os.cpu_count(),
                 "affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None},
        "source_commit": source_commit, "source_status": source_status, "source_unchanged": unchanged,
        "protocol_sha256": sha256(protocol_raw).hexdigest(), "protocol": protocol,
        "native_binary_sha256": manifest["binary_sha256"], "native_build_cost": build,
        "all_episodes_completed": passed, "registered_cache_behavior": cache_behavior,
        "episodes": episodes, "episode_count": len(episodes),
        "common_preparation_ns_once_per_standalone_strategy": common_preparation_ns,
        "episode_total_ns": totals, "standalone_warm_total_ns": warm, "standalone_cold_total_ns": cold,
        "descriptive_reuse_saving_ns_vs_uncached": warm["native-uncached"] - warm["native-exact-reuse"],
        "descriptive_cached_ndu_lower_than_every_strong_control": passed and all(warm["native-exact-reuse"] < warm[a] for a in controls),
        "claims": {**protocol["claims"], "statistical_superiority_established": False,
                   "old_48_episode_result_replaced": False, "fresh_application_runtime_gain": False},
        "authority": "DENY_ALL", "safety_certificate": False}
    save(root / "RESULT.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, default=PROTOCOL_PATH)
    args = parser.parse_args()
    result = qualify(args.output, identity=args.identity, protocol_path=args.protocol)
    print(json.dumps({key: result[key] for key in ("all_episodes_completed", "episode_count",
        "registered_cache_behavior", "standalone_warm_total_ns", "standalone_cold_total_ns",
        "descriptive_reuse_saving_ns_vs_uncached", "descriptive_cached_ndu_lower_than_every_strong_control")}, indent=2))
    if not result["all_episodes_completed"] or not result["registered_cache_behavior"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
