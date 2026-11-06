#!/usr/bin/env python3
"""Preregister, plan, execute and evaluate a complete-kernel eight-arm study.

Import is inert. Only calibrate and execute-next can call the bound guest
collector. No kernel is built here, and no parser fixture is performance data.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
from fractions import Fraction
import fcntl
import gzip
import hashlib
import importlib.util
import itertools
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "experiments/hia_linux_full_20261106/COMPARISON_PROTOCOL.json"
Q32 = 1 << 32
LIMIT = 1_000_000 * Q32
UPSTREAM_NDU = "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d"
NATIVE_SOURCE_COMMIT = "1d3c58fb6ecc32d38f3bdaa10dafd9088f9b6862"
ORDINARY_SOURCE_COMMIT = "32ad663457f30d39dca793aaf218c24cee1891b8"
COLLECTOR_SOURCE_COMMIT = "e3d2deac454993c8f70fd9182eff7f379d9375d1"
COLLECTOR_BLOB = "a3e3b5a5755137abcf1b394a5618a2c9575af2ce"
PHASES = ("syscall_process_pipe", "anonymous_memory", "tmpfs_files", "unix_tcp")
IMAGES = ("stock", "hia-original", "hia-o3", "hia-os")
HIA_IMAGES = IMAGES[1:]
ARMS = ("stock", "hia-static", "best-fixed", "greedy", "ordinary-mpc",
        "independent-same-objective", "fixed-ndu", "dynamic-ndu")
ADAPTIVE = ARMS[3:]
NATIVE_ARMS = ("fixed-ndu", "dynamic-ndu")
SCHEMA = "hepta.hia.kernel-comparison"
NATIVE_SOURCE_BLOBS = {
    "rust/hia-kernel-ndu/Cargo.lock": "b971976a3ac9dfa9e74ee6a3685c32eb29625913",
    "rust/hia-kernel-ndu/Cargo.toml": "27e71b69650d74d29b9a7b1ad7056f76a02675b3",
    "rust/hia-kernel-ndu/src/main.rs": "9ae11044ca22309a7f46c92de4cd645c7b177646",
    "rust/hia-kernel-ndu/upstream.json": "d1a151a3e1c4b3c9936f20cc702486931968691c",
    "tools/build_hia_kernel_ndu_bridge.py": "e4b4fa0481da38ef98c301e4d6f853c696440591",
    "tests/test_hia_kernel_ndu.py": "cf1ef8128f97b5b6ef777c524cefaeeafaa8d812",
    "docs/HIA_KERNEL_NDU.md": "0dee1b72ab7dee179afc1fc08edf53bfcb7d9635",
}
OWN_FILES = ("tools/qualify_hia_kernel_comparison.py",
             "tests/test_hia_kernel_comparison.py",
             "experiments/hia_linux_full_20261106/COMPARISON_PROTOCOL.json",
             "docs/HIA_KERNEL_COMPARISON.md")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    def bad(value):
        raise ValueError("non-finite JSON constant: " + value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=bad)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(wire(value)).hexdigest()


def load(path):
    return strict_json(Path(path).read_bytes())


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(value if isinstance(value, bytes) else wire(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return identity(path)


def replace_state(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + "." + str(os.getpid()) + ".next")
    write_new(temporary, value)
    os.replace(temporary, path)


def identity(path):
    path = Path(path).resolve(strict=True)
    require(path.is_file(), "required regular file missing: " + str(path))
    with path.open("rb") as stream:
        value = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": value}


def check_binding(row):
    require(type(row) is dict and all(k in row for k in ("path", "bytes", "sha256")),
            "complete file binding required")
    actual = identity(row["path"])
    require(type(row["path"]) is str and Path(row["path"]).is_absolute() and
            all(actual[k] == row[k] and type(actual[k]) is type(row[k]) for k in ("bytes", "sha256")),
            "bound file changed: " + str(row.get("path")))
    if "git_blob_sha1" in row:
        data = Path(actual["path"]).read_bytes()
        require(hashlib.sha1(("blob " + str(len(data)) + "\0").encode() + data).hexdigest()
                == row["git_blob_sha1"], "Git blob changed: " + actual["path"])
    # Baseline/static receipts may retain the invoked symlink spelling, such as
    # ld.lld -> lld. Validate its actual bytes while preserving that argv path.
    return {"path": row["path"], "bytes": actual["bytes"], "sha256": actual["sha256"]}


def read_utf8_bound_log(binding):
    check_binding(binding)
    return Path(binding["path"]).read_bytes().decode("utf-8", errors="strict")


def bind_nested(value, *, skip_keys=()):
    """Check explicit file identities; directory and descriptive records are not files."""
    if isinstance(value, dict):
        if all(key in value for key in ("path", "bytes", "sha256")):
            check_binding(value)
        for key, item in value.items():
            if key not in skip_keys:
                bind_nested(item, skip_keys=skip_keys)
    elif isinstance(value, list):
        for item in value:
            bind_nested(item, skip_keys=skip_keys)


def utc_ns(value):
    require(type(value) is str, "timestamp missing")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, "timezone missing")
    delta = parsed.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def integer(value, label, lower=0, upper=(1 << 63) - 1):
    require(type(value) is int and lower <= value <= upper, "invalid integer: " + label)
    return value


def round_even_ratio(numerator, denominator):
    require(type(numerator) is int and type(denominator) is int and denominator > 0,
            "integer numerator and positive denominator required")
    quotient, remainder = divmod(abs(numerator), denominator)
    if remainder * 2 > denominator or (remainder * 2 == denominator and quotient & 1):
        quotient += 1
    return -quotient if numerator < 0 else quotient


def mul_q32(a, b):
    integer(a, "Q32 operand", -(1 << 63), (1 << 63) - 1)
    integer(b, "Q32 operand", -(1 << 63), (1 << 63) - 1)
    value = round_even_ratio(a * b, Q32)
    return integer(value, "Q32 product", -(1 << 63), (1 << 63) - 1)


def ratio_q32(numerator, denominator):
    numerator, denominator = Fraction(numerator), Fraction(denominator)
    require(numerator >= 0 and denominator > 0, "positive measured ratio required")
    fraction = numerator * Q32 / denominator
    result = round_even_ratio(fraction.numerator, fraction.denominator)
    return integer(result, "registered utility", 0, LIMIT)


def fraction_record(value):
    value = Fraction(value)
    return {"numerator": value.numerator, "denominator": value.denominator}


def as_fraction(value):
    require(type(value) is dict and set(value) == {"numerator", "denominator"},
            "exact rational record required")
    integer(value["numerator"], "rational numerator", -(1 << 127), (1 << 127) - 1)
    integer(value["denominator"], "rational denominator", 1, (1 << 127) - 1)
    return Fraction(value["numerator"], value["denominator"])


def median_fraction(values):
    values = sorted(Fraction(value) for value in values)
    require(values, "median has no independent observations")
    middle = len(values) // 2
    return values[middle] if len(values) % 2 else (values[middle - 1] + values[middle]) / 2


def axis_list(values):
    return [{"axis": key, "value_q32": values[key]} for key in sorted(values)]


def axis_map(values):
    require(type(values) is list and values, "axes missing")
    result = {}
    for row in values:
        require(type(row) is dict and set(row) == {"axis", "value_q32"},
                "axis record fields")
        key = row["axis"]
        require(type(key) is str and key not in result, "duplicate/invalid axis")
        result[key] = integer(row["value_q32"], "axis", -LIMIT, LIMIT)
    return result


def preference_reference(initial, target, *, mode="dynamic", eta=Q32 // 4):
    """Independent signed ties-even damping; no native response is an input."""
    require(mode in ("fixed", "dynamic") and eta == Q32 // 4, "unregistered preference rule")
    require(set(initial) == set(target) == {"latency", "image_size"}, "preference axes differ")
    current = {key: integer(value, "preference", -Q32, Q32)
               for key, value in initial.items()}
    target = {key: integer(value, "target", -Q32, Q32) for key, value in target.items()}
    if mode == "fixed":
        target = current.copy()
    steps = []
    residual = max(abs(current[key] - target[key]) for key in current)
    while residual > 4096 and len(steps) < 64:
        current = {key: max(-Q32, min(Q32, value + mul_q32(target[key] - value, eta)))
                   for key, value in current.items()}
        residual = max(abs(current[key] - target[key]) for key in current)
        steps.append({"iteration": len(steps) + 1, "residual_raw": residual,
                      "values": current.copy()})
    require(residual <= 4096, "registered preference solver exhausted 64 iterations")
    return {"values": current, "iterations": steps, "residual_raw": residual}


def evaluate_paths(candidates, weights, *, budget=4 * Q32, risk_ceiling=0, terminal=0):
    """Ordinary arithmetic reference, retaining every term and complete path."""
    require(set(weights) == {"latency", "image_size"}, "reference axes mismatch")
    require(type(candidates) is list and candidates, "candidate inventory missing")
    results, feasible = {}, {}
    for candidate in candidates:
        cid = candidate["id"]
        require(cid not in results, "duplicate candidate id")
        phase_results = []
        if cid == "abstain":
            require(candidate["path"] == [] and candidate["resource_cost_q32"] == 0,
                    "abstain must keep its zero controller effect")
            values = [0, 0]
        else:
            for phase in candidate["path"]:
                components = axis_map(phase["components"])
                require(set(components) == set(weights), "component axes mismatch")
                terms = {key: mul_q32(weights[key], components[key]) for key in weights}
                instant = sum(terms.values()) - phase["cost_q32"]
                integer(instant, "instant utility", -LIMIT, LIMIT)
                phase_results.append({"image_id": phase["image_id"], "terms": terms,
                                      "instant_q32": instant})
            values = [terminal]
            for phase, term in zip(reversed(candidate["path"]), reversed(phase_results)):
                total = term["instant_q32"] + mul_q32(phase["discount_q32"], values[0])
                integer(total, "unclipped recursive utility", -LIMIT, LIMIT)
                values.insert(0, total)
        admitted = (candidate["verified"] is True and
                    0 <= candidate["resource_cost_q32"] <= budget and
                    0 <= candidate["risk_q32"] <= risk_ceiling)
        results[cid] = {"phases": phase_results, "values_q32": values, "feasible": admitted}
        if admitted:
            feasible[cid] = values[0]
    require(feasible, "no feasible candidate, including incumbent continuation")
    maximum = max(feasible.values())
    frontier = sorted(key for key, value in feasible.items() if value == maximum)
    first = {candidate["path"][0]["image_id"] for candidate in candidates
             if candidate["id"] in frontier and candidate["path"]}
    selected = next(iter(first)) if len(first) == 1 and "abstain" not in frontier else None
    return {"paths": results, "frontier": frontier, "selected_image": selected,
            "executed_image": selected or "hia-original",
            "abstain": selected is None, "maximum_q32": maximum}


def check_native_response(request, response, reference, preference):
    """Audit native results against already computed independent values."""
    require(type(response) is dict and
            response.get("schema") == "hepta.hia.kernel-ndu.response.v1" and response.get("status") == "advisory",
            "native response schema")
    require(response.get("request_sha256") == hashlib.sha256(wire(request)).hexdigest(),
            "native request binding mismatch")
    for key in ("objective_digest", "snapshot_digest", "action_registry_digest", "generation"):
        require(response.get(key) == request[key], "native binding changed: " + key)
    require(response.get("upstream_commit") == UPSTREAM_NDU and
            response.get("authority") == "DENY_ALL", "different native owner")
    require(all(response.get(key) is False for key in
                ("safety_certificate", "production_activation_allowed", "measurements_created",
                 "kernel_image_verified_by_adapter")), "native authority/scope changed")
    require(response.get("entry_points") == [
        "codex_hepta_ndu::solve_preference_target",
        "codex_hepta_ndu::evaluate_recursive_utility",
        "codex_hepta_ndu::evaluate_candidates_with_policy"], "native production entry points changed")
    require(response.get("complete_image_paths") == 81, "native complete path count changed")
    native = response["preference"]
    prior = request["preference"]["previous_state"]
    initial_values = axis_map(prior["values"] if prior else request["preference"]["genesis_values"])
    require(axis_map(native["initial"]["values"]) == initial_values, "native initial values differ")
    if prior:
        for key in ("revision", "predecessor_digest", "state_digest", "values"):
            require(native["initial"][key] == prior[key], "native state lineage changed: " + key)
    require(axis_map(native["state"]["values"]) == preference["values"],
            "native preference differs from independent arithmetic")
    steps = preference["iterations"]
    require(len(native["iterations"]) == len(steps) and
            native["termination"]["iterations"] == len(steps), "native iteration count")
    initial_revision = integer(native["initial"]["revision"], "initial revision")
    for expected, actual in zip(steps, native["iterations"]):
        require(actual["iteration"] == expected["iteration"] and
                actual["residual_raw"] == expected["residual_raw"] and
                actual["predecessor_revision"] == initial_revision + expected["iteration"] - 1 and
                actual["next_revision"] == initial_revision + expected["iteration"] and
                actual["projection_count"] == 0, "native iteration/revision mismatch")
    require(native["state"]["revision"] == initial_revision + len(steps),
            "native final revision mismatch")
    require(native["termination"]["terminal_residual_raw"] == preference["residual_raw"] and
            native["termination"]["projection_count"] == 0 and
            native["termination"]["terminal_state_digest"] == native["state"]["state_digest"],
            "native terminal preference receipt")
    expected_next = {key: native["state"][key] for key in
                     ("revision", "predecessor_digest", "state_digest", "values")}
    require(native["next_request_state"] == expected_next, "native next-request state altered")
    paths = {path["id"]: path for path in response["paths"]}
    require(len(paths) == len(response["paths"]) == len(request["candidates"]) == 82,
            "native path omission or duplicate")
    for candidate in request["candidates"]:
        actual, expected = paths[candidate["id"]], reference["paths"][candidate["id"]]
        require(actual["values_q32"] == expected["values_q32"] and
                actual["projection_count"] == 0, "native recursion/clipping mismatch")
        for key in ("verified", "verification_digest", "support_digest",
                    "resource_cost_q32", "risk_q32", "uncertainty_q32"):
            require(actual[key] == candidate[key], "native candidate changed: " + key)
        require(len(actual["phases"]) == len(expected["phases"]), "native phase count")
        for phase, observed, term in zip(candidate["path"], actual["phases"], expected["phases"]):
            components = axis_map(phase["components"])
            require(observed["image_id"] == phase["image_id"] and
                    observed["instant_q32"] == term["instant_q32"] and
                    observed["cost_q32"] == phase["cost_q32"] and
                    observed["discount_q32"] == phase["discount_q32"], "native phase mismatch")
            observed_terms = {item["axis"]: item for item in observed["terms"]}
            require(len(observed_terms) == len(observed["terms"]) and
                    set(observed_terms) == set(components), "native term axes")
            for key in components:
                item = observed_terms[key]
                require(item["weight_q32"] == preference["values"][key] and
                        item["component_q32"] == components[key] and
                        item["weighted_q32"] == term["terms"][key], "native weighted term mismatch")
    expected_rejected = sorted(key for key, value in reference["paths"].items()
                               if not value["feasible"])
    require(sorted(item["id"] for item in response["rejected"]) == expected_rejected,
            "native feasibility differs")
    require(sorted(response["pareto_candidate_ids"]) == reference["frontier"] and
            response["selected_first_image_id"] == reference["selected_image"],
            "native frontier/first action differs")
    integer(response["service_before_output_ns"], "native service nanoseconds")
    integer(native["solve_ns"], "native solve nanoseconds")
    return {"checked_candidates": 82, "checked_preference_steps": len(steps),
            "selected_image": reference["selected_image"], "status": "PASS"}


def make_schedule(protocol, campaign_id):
    require(type(campaign_id) is str and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", campaign_id),
            "invalid campaign id")
    rows = []
    for block in range(5):
        for position, phase in enumerate(PHASES):
            index = block * 4 + position
            seed = protocol["heldout_seed_start"] + index
            require(seed not in protocol["training_seeds"] and seed != protocol["qualification_seed"],
                    "training/qualification and heldout seeds overlap")
            order = sorted(ARMS, key=lambda arm: (
                digest([protocol["randomization_seed"], block, phase, arm]), arm))
            run_ids = {arm: digest([campaign_id, "heldout", block, phase, arm, seed])[:24]
                       for arm in ARMS}
            rows.append({"index": index, "block": block, "phase": phase, "seed": seed,
                         "iterations": protocol["iterations"], "arm_order": order,
                         "run_ids": run_ids})
    require(len({row["run_ids"][arm] for row in rows for arm in ARMS}) == 160,
            "run id collision")
    return rows


def protocol():
    value = load(PROTOCOL_PATH)
    require(value.get("schema") == SCHEMA + ".protocol.v1" and
            tuple(value["arms"]) == ARMS and tuple(value["phases"]) == PHASES and
            value["blocks"] == 5 and value["heldout_boots"] == 160 and
            value["prediction"]["window_boots"] == 9 and
            value["objective"]["horizon"] == 4 and
            value["objective"]["discount_q32"] == Q32 * 7 // 8 and
            value["objective"]["switch_cost_q32"] == 0 and
            value["objective"]["terminal_q32"] == 0 and
            value["runtime"]["profile"] == "kvm" and
            value["runtime"]["host_cpus"] == [0, 1],
            "registered comparison protocol changed")
    require(len(set(value["training_seeds"])) == 3, "exactly three training seeds required")
    return value


def assert_training_partition(training, protocol_value):
    require(type(training) is list and len(training) == 4 * 3 * 4,
            "calibration must contain three separate all-boots for each image")
    expected_seeds = set(protocol_value["training_seeds"])
    seen = {}
    for row in training:
        require(row.get("partition") == "calibration", "qualification/heldout is not training")
        require(row["image_id"] in IMAGES and row["phase"] in PHASES, "unknown calibration cell")
        require(row["seed"] in expected_seeds, "unregistered training seed")
        integer(row["median_ns"], "calibration median ns", 1)
        seen.setdefault((row["image_id"], row["phase"]), []).append(row)
    for image in IMAGES:
        for phase in PHASES:
            rows = seen.get((image, phase), [])
            require(len(rows) == 3 and {row["seed"] for row in rows} == expected_seeds and
                    len({row["run_id"] for row in rows}) == 3,
                    "within-boot repeats cannot stand in for independent calibration boots")
    for image in IMAGES:
        groups = {}
        for row in training:
            if row["image_id"] == image:
                groups.setdefault(row["run_id"], []).append(row)
        require(len(groups) == 3 and
                all({row["phase"] for row in rows} == set(PHASES) and len(rows) == 4
                    for rows in groups.values()), "calibration all-boot phase grouping differs")
    all_ids = {(row["image_id"], row["run_id"]) for row in training}
    require(len(all_ids) == len({run_id for _, run_id in all_ids}) == 12,
            "calibration reuses a run across images")


def build_model(training, history, *, current_phase, episode_index, protocol_value):
    assert_training_partition(training, protocol_value)
    require(current_phase in PHASES and len(history) == episode_index,
            "model input contains a missing or future episode")
    observations = {(image, phase): [] for image in IMAGES for phase in PHASES}
    for row in sorted(training, key=lambda row: (row["completed_unix_ns"], row["run_id"])):
        observations[row["image_id"], row["phase"]].append(row)
    transition = {a: {b: 1 for b in PHASES} for a in PHASES}
    for _ in {row["run_id"] for row in training}:
        for a, b in zip(PHASES, PHASES[1:]):
            transition[a][b] += 1
    run_ids = {row["run_id"] for row in training}
    previous_phase = None
    for index, episode in enumerate(history):
        require(episode.get("status") == "PASS" and episode.get("index") == index,
                "partial, failed or non-prefix history cannot inform a policy")
        phase = episode["phase"]
        require(phase in PHASES and type(episode.get("observations")) is list and
                len(episode["observations"]) == 8 and
                {row.get("arm") for row in episode["observations"]} == set(ARMS),
                "completed history must contain all eight real arm observations")
        if previous_phase is not None:
            transition[previous_phase][phase] += 1
        previous_phase = phase
        for row in episode["observations"]:
            require(row.get("partition") == "heldout" and row.get("case_index") == index and
                    row["phase"] == phase and row["image_id"] in IMAGES and
                    row["run_id"] not in run_ids, "history partition or boot reuse")
            integer(row["median_ns"], "observed median", 1)
            run_ids.add(row["run_id"])
            observations[row["image_id"], phase].append(row)
    window = protocol_value["prediction"]["window_boots"]
    cells, references = {}, {}
    for phase in PHASES:
        references[phase] = median_fraction(
            row["median_ns"] for row in training
            if row["image_id"] == "stock" and row["phase"] == phase)
    for image in IMAGES:
        cells[image] = {}
        for phase in PHASES:
            rows = observations[image, phase][-window:]
            cells[image][phase] = {
                "median_ns": fraction_record(median_fraction(row["median_ns"] for row in rows)),
                "observation_run_ids": [row["run_id"] for row in rows],
                "independent_boots": len(rows)}
    probabilities = [{phase: Fraction(int(phase == current_phase)) for phase in PHASES}]
    for _ in range(3):
        previous = probabilities[-1]
        probabilities.append({
            b: sum(previous[a] * Fraction(transition[a][b], sum(transition[a].values()))
                   for a in PHASES) for b in PHASES})
    return {"schema": SCHEMA + ".past-only-model.v1", "current_phase": current_phase,
            "completed_episode_count": episode_index, "window_boots": window,
            "cells": cells, "stock_training_medians_ns": {
                phase: fraction_record(value) for phase, value in references.items()},
            "transition_counts": transition, "phase_distributions": [
                {phase: fraction_record(value) for phase, value in row.items()}
                for row in probabilities],
            "qualification_observations_used": False, "future_observations_used": False}


def measured_components(stock_reference, stock_bytes, image_bytes, duration_ns):
    integer(stock_bytes, "stock image bytes", 1)
    integer(image_bytes, "image bytes", 1)
    return {"latency": ratio_q32(100 * Fraction(stock_reference), Fraction(duration_ns)),
            "image_size": ratio_q32(100 * stock_bytes, image_bytes)}


def make_candidates(model, image_registry, snapshot_digest, objective_digest):
    require(tuple(row["id"] for row in image_registry) == HIA_IMAGES,
            "registered image order must be complete and fixed")
    image_map = {row["id"]: row for row in image_registry}
    expected, resource = {}, {}
    for image in HIA_IMAGES:
        per_phase = {}
        for phase in PHASES:
            per_phase[phase] = measured_components(
                as_fraction(model["stock_training_medians_ns"][phase]),
                image_map[image]["stock_image_bytes"], image_map[image]["image_bytes"],
                as_fraction(model["cells"][image][phase]["median_ns"]))
        expected[image], resource[image] = [], []
        for distribution in model["phase_distributions"]:
            weighted = sum(as_fraction(distribution[phase]) * per_phase[phase]["latency"]
                           for phase in PHASES)
            expected[image].append({
                "latency": round_even_ratio(weighted.numerator, weighted.denominator),
                "image_size": per_phase[PHASES[0]]["image_size"]})
            duration = sum(as_fraction(distribution[phase]) *
                           as_fraction(model["cells"][image][phase]["median_ns"])
                           for phase in PHASES)
            raw = duration * Q32 / 1000
            resource[image].append(integer(round_even_ratio(raw.numerator, raw.denominator),
                                            "predicted stage microseconds Q32", 1))
    result = []
    for number, sequence in enumerate(itertools.product(HIA_IMAGES, repeat=4)):
        path = []
        for stage, image in enumerate(sequence):
            support = digest({"snapshot": snapshot_digest, "image": image, "stage": stage,
                              "distribution": model["phase_distributions"][stage],
                              "prediction": model["cells"][image]})
            path.append({"image_id": image, "event_digest": digest(
                [objective_digest, snapshot_digest, number, stage, image]),
                "support_digest": support, "components": axis_list(expected[image][stage]),
                "cost_q32": 0, "discount_q32": Q32 * 7 // 8})
        result.append({"id": f"path-{number:03d}", "verified": True,
                       "verification_digest": digest(
                           [image_map[image]["verification_digest"] for image in sequence]),
                       "support_digest": digest([snapshot_digest, list(sequence)]),
                       "resource_cost_q32": integer(sum(resource[image][stage]
                           for stage, image in enumerate(sequence)), "predicted path microseconds Q32", 1),
                       "risk_q32": 0,
                       "uncertainty_q32": 0, "path": path})
    result.append({"id": "abstain", "verified": True,
                   "verification_digest": digest([objective_digest, "incumbent-qualified"]),
                   "support_digest": digest([snapshot_digest, "incumbent-continuation"]),
                   "resource_cost_q32": 0, "risk_q32": 0, "uncertainty_q32": 0, "path": []})
    require(len(result) == 82 and len({tuple(p["image_id"] for p in c["path"])
                                    for c in result if c["path"]}) == 81,
            "complete path inventory missing")
    return result


def incumbent_budget(candidates):
    matching = [row for row in candidates if
                tuple(phase["image_id"] for phase in row["path"]) == ("hia-original",) * 4]
    require(len(matching) == 1, "exact incumbent path required for predicted time budget")
    return integer(matching[0]["resource_cost_q32"], "incumbent four-stage budget", 1)


def native_request(registry, snapshot, candidates, generation, *, mode, previous_state):
    p = registry["protocol"]["objective"]
    images = [{key: row[key] for key in ("id", "backend", "artifact_sha256", "verification_digest")}
              for row in registry["native_images"]]
    return {"schema": "hepta.hia.kernel-ndu.request.v1",
            "objective_digest": digest(p), "snapshot_digest": digest(snapshot),
            "action_registry_digest": digest(images), "generation": generation,
            "horizon": 4, "utility_unit": p["utility_unit"], "resource_unit": "microseconds",
            "resource_budget_q32": incumbent_budget(candidates), "risk_ceiling_q32": 0,
            "terminal_utility_q32": 0,
            "preference": {"mode": mode, "previous_state": previous_state,
                           "genesis_values": [] if previous_state else axis_list(p["genesis_q32"]),
                           "target": axis_list(p["public_targets_q32"][snapshot["current_phase"]]),
                           "eta_q32": Q32 // 4},
            "images": images, "candidates": candidates}


def greedy_reference(candidates, weights, *, budget):
    scores = {}
    for candidate in candidates:
        if candidate["path"] and candidate["verified"] is True and candidate["risk_q32"] == 0 and 0 <= candidate["resource_cost_q32"] <= budget:
            phase = candidate["path"][0]
            image = phase["image_id"]
            value = sum(mul_q32(weights[key], component)
                        for key, component in axis_map(phase["components"]).items())
            if image in scores:
                require(scores[image] == value, "stage-zero forecast depends on a future path")
            scores[image] = value
    maximum = max([0, *scores.values()])
    frontier = sorted(image for image, value in scores.items() if value == maximum)
    selected = frontier[0] if maximum > 0 and len(frontier) == 1 else None
    return {"scores_q32": scores, "selected_image": selected,
            "executed_image": selected or "hia-original", "abstain": selected is None,
            "feasible_first_images": sorted(scores), "suffix_feasibility_checked": True}


def quantile(values, numerator, denominator):
    values = sorted(Fraction(value) for value in values)
    require(values, "empty percentile distribution")
    position = Fraction((len(values) - 1) * numerator, denominator)
    left = position.numerator // position.denominator
    fraction = position - left
    return values[left] if left + 1 == len(values) else (
        values[left] * (1 - fraction) + values[left + 1] * fraction)


def number(value):
    value = Fraction(value)
    result = float(value)
    require(math.isfinite(result), "non-finite statistical result")
    return {"value": result, "exact": fraction_record(value)}


def paired_cluster_bootstrap(pairs):
    """Each pair is one whole block, never one within-boot timing sample."""
    require(len(pairs) == 5, "exactly five independent registered block clusters required")
    pairs = [(Fraction(a), Fraction(b)) for a, b in pairs]
    require(all(a > 0 and b >= 0 for a, b in pairs), "invalid paired measurement")
    baseline, treatment = (sum(row[index] for row in pairs) / 5 for index in (0, 1))
    differences, relative = [], []
    for indices in itertools.product(range(5), repeat=5):
        a = sum(pairs[index][0] for index in indices) / 5
        b = sum(pairs[index][1] for index in indices) / 5
        differences.append(b - a)
        relative.append(100 * (b - a) / a)
    return {"independent_block_clusters": 5, "bootstrap_replicates": len(relative),
            "method": "exhaustive paired block bootstrap; percentile 95% interval",
            "baseline_mean": number(baseline), "arm_mean": number(treatment),
            "difference": number(treatment - baseline),
            "difference_ci95": [number(quantile(differences, 1, 40)),
                                number(quantile(differences, 39, 40))],
            "relative_change_percent": number(100 * (treatment - baseline) / baseline),
            "relative_change_ci95_percent": [number(quantile(relative, 1, 40)),
                                             number(quantile(relative, 39, 40))],
            "lower_is_better": True, "within_boot_samples_used_as_clusters": False}


def cost_requirements(arm):
    require(arm in ARMS, "unknown cost owner")
    if arm == "stock":
        return {"images": ["stock"], "calibration": False, "native_adapter": False,
                "ordinary_control": False, "shared_feedback": False}
    if arm == "hia-static":
        return {"images": ["hia-original"], "calibration": False, "native_adapter": False,
                "ordinary_control": False, "shared_feedback": False}
    return {"images": list(IMAGES), "calibration": True,
            "native_adapter": arm in NATIVE_ARMS,
            "ordinary_control": arm == "independent-same-objective",
            "shared_feedback": arm in ADAPTIVE}


def break_even(setup_delta_ns, baseline_cycle_ns, arm_cycle_ns):
    difference = Fraction(setup_delta_ns)
    saving = Fraction(baseline_cycle_ns) - Fraction(arm_cycle_ns)
    if saving <= 0:
        return {"reachable": False, "reason": "no positive observed per-cycle saving",
                "per_cycle_saving_ns": number(saving)}
    minimum = max(1, math.ceil(difference / saving))
    return {"reachable": True, "minimum_four_phase_cycles": minimum,
            "per_cycle_saving_ns": number(saving),
            "assumption": "conditional repetition of the measured workload/cost regime; not a guarantee"}


def import_file(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "cannot load bound module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def gzip_value(binding):
    check_binding(binding)
    data = gzip.decompress(Path(binding["path"]).read_bytes())
    require(hashlib.sha256(data).hexdigest() == binding["uncompressed_sha256"],
            "compressed inventory content changed")
    return strict_json(data)


def success_command(row, *, expected_name=None):
    require(type(row) is dict and type(row.get("exit_code")) is int and row.get("exit_code") == 0 and
            row.get("timed_out") is False, "actual successful process receipt required")
    if expected_name is not None:
        require(row.get("name") == expected_name, "different command role")
    require(not any(row.get(key) for key in
                    ("cancelled", "interrupted", "interruption", "spawn_error", "incomplete_process_group")),
            "incomplete/cancelled process")
    cleanup = row.get("process_group_cleanup", {})
    require(type(row.get("process_group")) is int and row["process_group"] > 1 and
            cleanup.get("group") == row["process_group"] and
            cleanup.get("scope") == "owned_linux_process_group" and cleanup.get("drained") is True and
            cleanup.get("signals") == [] and cleanup.get("live_members_after") == [] and
            cleanup.get("errors") == [], "owned process group was not completely drained")
    integer(cleanup["elapsed_ns"], "process group cleanup duration")
    integer(row["elapsed_ns"], "command elapsed ns", 1)
    for stream in ("stdout", "stderr"):
        check_binding(row[stream])
    return row["elapsed_ns"]


def build_gate_header(value, image_id, protocol_value):
    require(image_id in IMAGES and type(value) is dict, "unknown build image")
    stock = image_id == "stock"
    require(value.get("schema") == ("hepta.hia.linux.stock-baseline.v1" if stock else
                                    "hepta.hia.linux.full-system-build.v1"),
            "unrecognized whole-build receipt")
    require(all(value.get(key) == "PASS" for key in ("status", "build_status", "boot_status")),
            "four complete build AND boot PASS receipts required")
    require(value.get("kernel_version") == protocol_value["kernel"]["version"] and
            value.get("upstream_commit") == protocol_value["kernel"]["upstream_commit"] and
            value.get("linux_source_unchanged") is True,
            "different or changed Linux source")
    require(value.get("source_before") == value.get("source_after") and
            value.get("source_before", {}).get("clean") is True,
            "build execution source is not frozen")
    if not stock:
        require(value.get("scope") == "complete_frozen_x86_64_configuration" and
                value.get("all_configured_target_units_rewritten") is True and
                type(value.get("fallback_c_units")) is int and value["fallback_c_units"] == 0 and
                value.get("mode") == "import", "incomplete HIA or C fallback/reused import")
        require(value.get("backend_optimization") == {
            "hia-original": "original", "hia-o3": "O3", "hia-os": "Os"}[image_id],
            "wrong independently imported backend variant")


def audit_build(path, image_id, p, audit_directory, *, deep=True):
    """Expensive closure: called at admission and final evaluation only."""
    receipt = identity(path)
    value = load(path)
    build_gate_header(value, image_id, p)
    for key in ("config", "kernel_image", "vmlinux", "source_archive"):
        check_binding(value[key])
    require(value["config"]["sha256"] == value["config_sha256"], "config receipt mismatch")
    before = gzip_value(value["linux_source_inventory"])
    after = gzip_value(value["linux_source_after_inventory"])
    require(before == after, "whole Linux inventory differs after build")
    command_name = "full-kbuild" if image_id == "stock" else "full-hia-kbuild"
    commands = [row for row in value["commands"] if row.get("name") == command_name]
    require(len(commands) == 1, "one actual whole Kbuild command required")
    compile_ns = success_command(commands[0], expected_name=command_name)
    integer(value["elapsed_ns"], "whole build pipeline elapsed ns", compile_ns)
    result = {"id": image_id, "build_receipt": receipt, "kernel": value["kernel_image"],
              "config": value["config"], "linux_inventory_digest": digest(before),
              "linux_archive": value["source_archive"],
              "whole_build_wall_ns": value["elapsed_ns"], "kbuild_wall_ns": compile_ns,
              "started_unix_ns": utc_ns(value["started_at_utc"]),
              "completed_unix_ns": utc_ns(value["completed_at_utc"]),
              "kbuild_child_cpu_ns": round((commands[0]["child_user_seconds"] +
                                             commands[0]["child_system_seconds"]) * 1_000_000_000),
              "all_recorded_commands_child_cpu_ns": sum(round((row.get("child_user_seconds", 0) +
                    row.get("child_system_seconds", 0)) * 1_000_000_000) for row in value["commands"]),
              "cpu_cost_scope": "recorded child commands; Python parent/audit CPU not inferred",
              "source_identity": value["source_before"]}
    if image_id == "stock":
        check_binding(value["build_environment"])
        check_binding(value["compiler"])
        bind_nested(value["llvm_tools"])
        require("20.1.8" in value["compiler"]["version"], "different stock LLVM version")
        inventory = gzip_value(value["build_inventory"])
        if deep:
            bind_nested(inventory["objects"])
            bind_nested([row.get("source") for row in inventory["compile_commands"]])
            check_binding(inventory["kbuild_command_archive"])
        result.update(compiler={k: value["compiler"][k] for k in ("path", "bytes", "sha256")},
                      build_environment=value["build_environment"],
                      inventory=value["build_inventory"], inventory_digest=digest(inventory))
        check_binding(value["compile_commands"])
        require(value.get("active_compile_units", 0) > 0, "empty stock target denominator")
    else:
        check_binding(value["stock_baseline"])
        check_binding(value["system_manifest"])
        check_binding(value["codec_build_receipt"])
        manifest = load(value["system_manifest"]["path"])
        require(manifest.get("schema") == "hepta.hia.system-build-environment.v1" and
                manifest["mode"] == "import" and
                manifest["backend_optimization"] == value["backend_optimization"],
                "different HIA manifest/import policy")
        bind_nested(manifest["tools"])
        original = gzip_value(value["full_build_inventory"])
        # Use the actual frozen full-build collector, not a PASS-only summary.
        sys.path.insert(0, str(ROOT))
        try:
            from tools import hia_linux_full_inventory as inventory_tool
        finally:
            sys.path.pop(0)
        wrappers = {}
        for key, prefix in (("target", "CC="), ("host_c", "HOSTCC="), ("host_cxx", "HOSTCXX=")):
            values = [arg[len(prefix):] for arg in commands[0]["argv"] if arg.startswith(prefix)]
            require(len(values) == 1, "explicit host/target compiler boundary missing")
            wrappers[key] = values[0]
        new_binding, rebuilt = None, original
        if deep:
            audit_directory = Path(audit_directory)
            audit_directory.mkdir(parents=True, exist_ok=False)
            new_binding, rebuilt = inventory_tool.collect(
                Path(manifest["build_root"]), Path(manifest["source_root"]),
                Path(manifest["ledger_root"]), Path(value["system_manifest"]["path"]),
                wrappers, audit_directory)
        require(rebuilt == original and rebuilt["counts"] == value["coverage"],
                "whole target/host/object/program closure changed")
        require(rebuilt.get("all_target_payloads_reconstructed_from_hia") is True and
                rebuilt.get("fallback_c_units") == 0, "incomplete all-target closure")
        optimization_counts = Counter()
        for entry in rebuilt["compiler_invocations"]:
            record = entry["value"]
            if record["classification"]["kind"] in ("target_c", "target_assembly"):
                require(record.get("mode") == "import", "variant reuses prior imported programs")
                if deep:
                    check_binding(record["program_index"])
                expected = (value["backend_optimization"] if
                            record["classification"]["kind"] == "target_c" else "original")
                require(record.get("backend_optimization") == expected,
                        "TU backend differs from registered image variant")
                if record["classification"]["kind"] == "target_c":
                    native_commands = [row for row in record["commands"] if row["name"] == "hia-native-codegen"]
                    require(len(native_commands) == 1, "one actual native code generation stage required")
                    flags = [arg for arg in native_commands[0]["argv"]
                             if re.fullmatch(r"-O(?:[0123szg]|fast)", arg)]
                    last = flags[-1] if flags else "implicit-O0"
                    optimization_counts[last] += 1
                    if expected != "original":
                        require(last == "-" + expected, "effective backend argv differs from policy")
        result.update(compiler=manifest["tools"]["clang"], manifest=value["system_manifest"],
                      stock_baseline=value["stock_baseline"], codec=manifest["tools"]["codec"],
                      program_root=manifest["program_root"], build_root=manifest["build_root"],
                      ledger_root=manifest["ledger_root"], inventory=value["full_build_inventory"],
                      inventory_digest=digest(rebuilt), audit_inventory=new_binding,
                      coverage=rebuilt["counts"], actual_target_c_optimization_counts=dict(optimization_counts))
    return result


def bind_code(spec):
    require(re.fullmatch(r"[0-9a-f]{40}", spec.get("driver_source_commit", "")),
            "exact comparison source commit required")
    files = {name: identity(ROOT / name) for name in (*OWN_FILES,
             "tools/hia_linux_full_inventory.py", "tools/qualify_hia_linux_baseline.py")}
    for row in files.values():
        data = Path(row["path"]).read_bytes()
        row["git_blob_sha1"] = hashlib.sha1(("blob " + str(len(data)) + "\0").encode() + data).hexdigest()
    # Materialized source manifests can be used without a .git directory; all
    # six exact blobs must be committed in the independently supplied manifest.
    origin = load(spec["driver_source_manifest"])
    require(origin.get("commit") == spec["driver_source_commit"] and
            all(origin.get("files", {}).get(name) == row["git_blob_sha1"]
                for name, row in files.items()), "comparison source manifest/blob mismatch")
    return {"commit": spec["driver_source_commit"], "files": files,
            "materialization_manifest": identity(spec["driver_source_manifest"])}


def native_summary(path, *, ordinary=False):
    binding, summary = identity(path), load(path)
    prefix = "hepta.hia.kernel-ordinary-control" if ordinary else "hepta.hia.kernel-ndu"
    require(summary.get("schema") == prefix + ".native-summary.v1" and
            summary.get("status") == "PASS" and summary.get("build_inputs_unchanged") is True,
            "native compiler/binary qualification missing")
    require(summary.get("qualification", {}).get("status") == "PASS" and
            summary["qualification"].get("checks", 0) > 0, "native arithmetic qualification missing")
    bind_nested(summary)
    require("rustc 1.95.0" in summary["rustc_version"], "native Rust toolchain differs")
    require("cargo 1.95.0" in summary["cargo_version"], "native Cargo toolchain differs")
    if ordinary:
        require(summary.get("no_hepta_dependencies") is True and
                summary.get("source_commit") == ORDINARY_SOURCE_COMMIT, "different control or Hepta/NDU dependency")
    else:
        require(summary.get("original_upstream_commit") == UPSTREAM_NDU and
                summary.get("source_commit") == NATIVE_SOURCE_COMMIT and
                summary.get("original_rust_sources_unchanged") is True and
                summary.get("all_original_non_manifest_inputs_unchanged") is True,
                "native NDU production source differs")
        require(all(summary["sources"].get(name, {}).get("git_blob_sha1") == blob
                    for name, blob in NATIVE_SOURCE_BLOBS.items()), "native adapter source differs")
    integer(summary["build_cost"]["wall_ns"], "actual native preparation wall ns", 1)
    return {"summary": binding, "executable": summary["executable"],
            "rustc_version": summary["rustc_version"], "cargo_version": summary["cargo_version"],
            "preparation_wall_ns": summary["build_cost"]["wall_ns"],
            "source_commit": summary["source_commit"]}


def load_collector(binding):
    check_binding(binding["source"])
    check_binding(binding["helper"])
    return import_file(binding["source"]["path"], "comparison_bound_collector")


def expected_argv(collector, request, taskset):
    command = collector.qemu_argv(
        qemu=Path(request["qemu"]).resolve(), qemu_data=Path(request["qemu_data"]).resolve(),
        bios=Path(request["bios"]).resolve(), kernel=Path(request["kernel"]).resolve(),
        initramfs=Path(request["output"]).resolve() / "initramfs.cpio.gz",
        profile="kvm", run_id=request["run_id"], expected_release=request["expected_release"],
        seed=request["seed"], iterations=request["iterations"], selection=request["selection"])
    return [taskset["path"], "--cpu-list", ",".join(map(str, request["host_cpus"])), *command]


def make_guest_request(registry, image_id, output, *, run_id, seed, selection):
    image, env = registry["images"][image_id], registry["runtime"]
    return {"kernel": image["kernel"]["path"], "kernel_sha256": image["kernel"]["sha256"],
            "config": image["config"]["path"], "config_sha256": image["config"]["sha256"],
            "guest_build_receipt": env["guest_build_receipt"]["path"],
            "qemu": env["qemu"]["path"], "qemu_data": env["qemu_data"]["path"],
            "qemu_modules": env["qemu_modules"]["path"], "bios": env["bios"]["path"],
            "output": str(Path(output).resolve()), "collector_source_commit": env["collector"]["commit"],
            "expected_release": registry["protocol"]["kernel"]["version"],
            "seed": seed, "iterations": registry["protocol"]["iterations"],
            "selection": selection, "profile": "kvm", "run_id": run_id,
            "timeout": registry["protocol"]["runtime"]["timeout_seconds"],
            "host_cpus": registry["protocol"]["runtime"]["host_cpus"]}


def admit_guest(path, registry, image_id, collector, *, partition, expected=None):
    """Reparse real serial bytes through the sole bound collector implementation."""
    value, binding = load(path), identity(path)
    require(value.get("schema") == "hepta.hia.linux.system-benchmark-run.v1" and
            value.get("status") == "PASS" and value.get("profile") == "kvm" and
            value.get("guest_executed_on_host") is False and value.get("inputs_unchanged") is True,
            "actual correct KVM benchmark result required")
    if expected is None:
        expected = make_guest_request(registry, image_id, Path(path).parent,
            run_id=value["run_id"], seed=value["seed"], selection=value["selection"])
    for key in ("run_id", "seed", "iterations", "selection", "profile", "expected_release",
                "collector_source_commit"):
        require(value[key] == expected[key], "guest request/receipt mismatch: " + key)
    require(Path(expected["output"]).resolve() == Path(path).resolve().parent,
            "receipt was copied out of its preplanned boot output")
    env, image = registry["runtime"], registry["images"][image_id]
    require(value["collector_source"] == env["collector"]["source"] and
            value["execution_helper"] == env["collector"]["helper"] and
            value["static_build_receipt"] == env["guest_build_receipt"] and
            value["inputs"][0] == image["kernel"] and value["inputs"][1] == image["config"],
            "guest source/image/config identity differs")
    for key in ("qemu", "bios", "qemu_data", "qemu_modules"):
        require(value[key] == env[key], "different QEMU environment: " + key)
    require(value["host_affinity"]["requested_cpus"] == [0, 1] and
            value["host_affinity"]["effective_inherited_cpus"] == [0, 1] and
            value["host_affinity"]["enforcement"] == "taskset before QEMU exec" and
            value["host_affinity_program"] == env["taskset"], "different CPU placement")
    for key in ("inputs", "qemu", "bios", "static_build_receipt", "collector_source",
                "execution_helper", "initramfs", "preexecution_manifest", "trace",
                "host_affinity_program"):
        bind_nested(value[key])
    command = value["command_receipt"]
    require(value.get("commands") == [command], "guest command receipt differs from command ledger")
    wall = success_command(command, expected_name="boot-system-benchmark-kvm")
    argv = expected_argv(collector, expected, env["taskset"])
    manifest = load(value["preexecution_manifest"]["path"])
    require(manifest.get("schema") == "hepta.hia.benchmark-preexecution-manifest.v1" and
            manifest.get("argv") == command["argv"] == argv and
            manifest.get("qemu_argv") == value["qemu_argv"] == argv[3:],
            "preexecution/full command changed")
    for key in ("run_id", "profile", "seed", "iterations", "selection", "expected_release",
                "collector_source_commit"):
        require(manifest[key] == expected[key], "preexecution identifier differs")
    for key, required in (("kernel", image["kernel"]), ("config", image["config"]),
                          ("guest", env["guest_binary"]), ("qemu", env["qemu"]),
                          ("bios", env["bios"]), ("collector_source", env["collector"]["source"])):
        require(manifest[key] == required, "preexecution input differs: " + key)
    require(manifest["initramfs"] == value["initramfs"] and
            value["initramfs"]["sha256"] == env["guest_initramfs_sha256"] and
            manifest["protocol"] == env["guest_protocol"] and
            manifest["guest_source_commit"] == value["guest_source_commit"] == env["guest_source_commit"] and
            manifest["host_affinity"] == value["host_affinity"] and
            manifest["host_affinity_program"] == env["taskset"] and
            manifest["qemu_data_inventory_sha256"] == env["qemu_data"]["inventory_sha256"] and
            manifest["qemu_modules_inventory_sha256"] == env["qemu_modules"]["inventory_sha256"],
            "preexecution guest/initramfs/environment closure differs")
    expected_environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                            "PYTHONDONTWRITEBYTECODE": "1", "QEMU_MODULE_DIR": env["qemu_modules"]["path"]}
    require(manifest["environment"] == value["environment"] == expected_environment and
            manifest["timeout_seconds"] == expected["timeout"], "execution environment/deadline differs")
    stdout = read_utf8_bound_log(command["stdout"])
    stderr = read_utf8_bound_log(command["stderr"])
    verdict = collector.parse_serial(
        stdout, run_id=expected["run_id"], seed=expected["seed"], iterations=expected["iterations"],
        selection=expected["selection"], expected_release=expected["expected_release"],
        config_text=Path(image["config"]["path"]).read_text(), command_receipt=command,
        expected_argv=argv, stderr_text=stderr)
    require(verdict.get("status") == "PASS" and verdict == value["verdict"] ==
            load(value["trace"]["path"]), "serial parser/TRACE verdict mismatch")
    started, ended = value["started_unix_ns"], value["completed_unix_ns"]
    require(type(started) is int and type(ended) is int and ended > started > 0,
            "guest boot chronology missing")
    observations = []
    phases = PHASES if expected["selection"] == "all" else (expected["selection"],)
    for phase in phases:
        samples = verdict["measured_samples"][phase]
        require(len(samples) == 5, "five measured repeats required per boot")
        durations = [row["duration_ns"] for row in samples]
        median = median_fraction(durations)
        require(median.denominator == 1 and median == verdict["within_boot_median_ns"][phase],
                "stored within-boot statistic differs")
        counts = {row["operation_count"] for row in samples}
        require(len(counts) == 1, "operation denominator varies within a boot")
        observations.append({"partition": partition, "image_id": image_id, "phase": phase,
            "run_id": expected["run_id"], "seed": expected["seed"],
            "iterations": expected["iterations"], "median_ns": int(median),
            "operation_count": next(iter(counts)), "ns_per_op": fraction_record(median / next(iter(counts))),
            "raw_measured_samples": samples, "image_bytes": image["kernel"]["bytes"],
            "correctness": True, "qemu_wall_ns": wall, "collector_wall_ns": ended - started,
            "started_unix_ns": started, "completed_unix_ns": ended,
            "result": binding, "stdout": command["stdout"]})
    return {"result": binding, "run_id": value["run_id"], "output": str(Path(path).resolve().parent),
            "stdout_sha256": command["stdout"]["sha256"], "qemu_wall_ns": wall,
            "started_unix_ns": started, "completed_unix_ns": ended, "observations": observations}


def require_independent_boots(boots, *, forbidden=()):
    require(boots, "no independent boots")
    for key in ("run_id", "output", "stdout_sha256"):
        values = [row[key] for row in boots]
        require(len(values) == len(set(values)) and
                not set(values).intersection(row[key] for row in forbidden),
                "boot reused across partitions: " + key)


def cpu_profile_gate(profile, expected_cpus):
    require(profile.get("schema") == "hepta.hia.kernel.host-observation.v1" and
            profile.get("kvm_accessible") is True and
            profile.get("selected_host_cpus") == expected_cpus and
            profile.get("cpu_clock_locked") is False and
            profile.get("exclusive_host_claim") is False, "unregistered host profile")
    topology = {row["cpu"]: row for row in profile["topology"]}
    selected = [topology[cpu] for cpu in expected_cpus]
    require(len({(row["physical_package_id"], row["core_id"]) for row in selected}) == 2 and
            len({row["physical_package_id"] for row in selected}) == 1 and
            selected[0]["numa_nodes"] == selected[1]["numa_nodes"],
            "host placement is not two distinct cores on the same socket/NUMA")


def prepare_admission(spec, output, *, deep):
    """Qualifiers may have build load; their timing never enters the model."""
    started = time.monotonic_ns()
    require(spec.get("schema") == SCHEMA + ".input.v1", "comparison input schema")
    p = protocol()
    make_schedule(p, spec["campaign_id"])
    source = bind_code(spec)
    require(set(spec["images"]) == set(IMAGES), "all four image registrations required")
    images = {name: audit_build(spec["images"][name]["build_receipt"], name, p,
                                Path(output) / "build-audit" / name, deep=deep) for name in IMAGES}
    stock = images["stock"]
    for image in images.values():
        require(image["config"]["sha256"] == stock["config"]["sha256"] and
                image["compiler"] == stock["compiler"] and
                image["linux_inventory_digest"] == stock["linux_inventory_digest"] and
                image["linux_archive"]["sha256"] == stock["linux_archive"]["sha256"],
                "different Linux/config/LLVM across complete images")
    for name in HIA_IMAGES:
        require(images[name]["stock_baseline"] == stock["build_receipt"],
                "HIA build used a different stock baseline")
    for key in ("program_root", "build_root", "ledger_root"):
        require(len({images[name][key] for name in HIA_IMAGES}) == 3,
                "three variants must independently import into distinct " + key)
    require(len({images[name]["codec"]["sha256"] for name in HIA_IMAGES}) == 1,
            "different HIA semantic codecs")
    collector_source = identity(spec["collector"]["path"])
    collector_bytes = Path(collector_source["path"]).read_bytes()
    require(spec["collector"]["source_commit"] == COLLECTOR_SOURCE_COMMIT and
            hashlib.sha1(("blob " + str(len(collector_bytes)) + "\0").encode() + collector_bytes).hexdigest() ==
            COLLECTOR_BLOB, "collector differs from qualified strict implementation")
    collector = import_file(collector_source["path"], "comparison_bound_collector")
    baseline, helper = collector._baseline()
    require(re.fullmatch(r"[0-9a-f]{40}", spec["collector"]["source_commit"]),
            "exact collector source commit required")
    static_binding, static = identity(spec["guest_build_receipt"]), load(spec["guest_build_receipt"])
    require(static.get("status") == "PASS" and static.get("source_unchanged") is True and
            static.get("guest_executed_on_host") is False, "static guest qualification missing")
    bind_nested(static)
    protocol_files = [row for row in static["files"] if row.get("repository_path", "").endswith("/PROTOCOL.json")]
    require(len(protocol_files) == 1, "exact guest protocol source required")
    regenerated_initramfs = Path(output) / "guest-initramfs-reference.cpio.gz"
    baseline.create_initramfs(Path(static["guest_binary"]["path"]), regenerated_initramfs)
    host = identity(spec["host_profile"])
    cpu_profile_gate(load(host["path"]), p["runtime"]["host_cpus"])
    taskset = shutil.which("taskset", path="/usr/bin:/bin")
    require(taskset is not None, "taskset unavailable")
    runtime = {"collector": {"source": collector_source, "helper": helper,
                              "commit": spec["collector"]["source_commit"]},
               "guest_build_receipt": static_binding, "guest_binary": static["guest_binary"],
               "guest_sources": static["files"], "guest_protocol": protocol_files[0],
               "guest_source_commit": static["source_commit"],
               "guest_initramfs_sha256": identity(regenerated_initramfs)["sha256"], "host_profile": host,
               "qemu": identity(spec["qemu"]), "bios": identity(spec["bios"]),
               "qemu_data": collector.tree_identity(spec["qemu_data"]),
               "qemu_modules": collector.tree_identity(spec["qemu_modules"]),
               "taskset": identity(taskset)}
    native = native_summary(spec["native_summary"])
    ordinary = native_summary(spec["ordinary_control_summary"], ordinary=True)
    require(native["rustc_version"] == ordinary["rustc_version"] and
            native["cargo_version"] == ordinary["cargo_version"],
            "NDU and independent control use different compiler toolchains")
    base = {"schema": SCHEMA + ".registration.v1", "campaign_id": spec["campaign_id"],
            "protocol": p, "source": source, "images": images, "runtime": runtime,
            "native": native, "ordinary_control": ordinary, "qualifications": {},
            "spec": identity(spec["_spec_path"]),
            "source_binding_is_execution_attestation": False}
    for name in IMAGES:
        accepted = admit_guest(spec["images"][name]["qualification"], base, name, collector,
                               partition="qualification")
        v = load(accepted["result"]["path"])
        require(v["seed"] == p["qualification_seed"] and v["selection"] == "all",
                "qualification must be the registered all-phase seed")
        base["qualifications"][name] = accepted
    require_independent_boots(list(base["qualifications"].values()))
    base["native_images"] = [{"id": name, "backend": p["native_backend_slots"][name],
        "artifact_sha256": images[name]["kernel"]["sha256"],
        "verification_digest": digest([images[name]["build_receipt"],
                                        base["qualifications"][name]["result"]]),
        "image_bytes": images[name]["kernel"]["bytes"],
        "stock_image_bytes": stock["kernel"]["bytes"]} for name in HIA_IMAGES]
    base["admission_wall_ns"] = time.monotonic_ns() - started
    base["admission_whole_build_closure_audited"] = deep
    return base, collector


def quiet_host_observation():
    """A bounded visible-/proc gate, not a claim of exclusive machine ownership."""
    forbidden = re.compile(r"^(?:clang(?:\+\+)?(?:-\d+)?|gcc|g\+\+|cc1|cc1plus|make|ninja|"
                           r"cargo|rustc|ld(?:\.lld|\.bfd|\.gold)?|lld|qemu-system-.*)$")
    found = []
    for path in Path("/proc").glob("[0-9]*/comm"):
        try:
            name = path.read_text().strip()
            if forbidden.fullmatch(name):
                found.append({"pid": int(path.parent.name), "comm": name})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return {"observed_unix_ns": time.time_ns(), "visible_build_or_qemu_processes": found,
            "exclusive_host_claim": False, "cpu_clock_locked": False,
            "host_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "loadavg": Path("/proc/loadavg").read_text().strip()}


def require_quiet_host(observation):
    require(observation.get("visible_build_or_qemu_processes") == [],
            "calibration/heldout requires all visible builds and other QEMU runs to have ended")


def lightweight_inputs(registry, collector, image_id=None):
    """Per-boot input closure, deliberately excluding TU/program/object scans."""
    bind_nested(registry["source"])
    runtime = registry["runtime"]
    for key in ("guest_build_receipt", "guest_binary", "guest_sources", "host_profile",
                "qemu", "bios", "taskset", "collector"):
        bind_nested(runtime[key])
    for key in ("qemu_data", "qemu_modules"):
        require(collector.tree_identity(runtime[key]["path"]) == runtime[key],
                "bound QEMU dependency tree changed")
    for key in ("native", "ordinary_control"):
        check_binding(registry[key]["summary"])
        check_binding(registry[key]["executable"])
    if image_id is not None:
        check_binding(registry["images"][image_id]["kernel"])
        check_binding(registry["images"][image_id]["config"])


def calibration_schedule(registry, output, collector):
    rows = []
    p = registry["protocol"]
    for index, seed in enumerate(p["training_seeds"]):
        order = sorted(IMAGES, key=lambda image: digest([p["randomization_seed"], "training", seed, image]))
        for image in order:
            run_id = digest([registry["campaign_id"], "calibration", index, "all", image, seed])[:24]
            request = make_guest_request(registry, image, Path(output) / "boots" / run_id,
                                        run_id=run_id, seed=seed, selection="all")
            rows.append({"image_id": image, "request": request,
                         "expected_argv": expected_argv(collector, request, registry["runtime"]["taskset"])})
    require(len({row["request"]["run_id"] for row in rows}) == 12, "calibration run id collision")
    return rows


def calibrate(spec_path, output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    spec = load(spec_path)
    spec["_spec_path"] = str(Path(spec_path).resolve())
    intent = write_new(output / "INTENT.json", {"schema": SCHEMA + ".calibration-intent.v1",
        "partition": "calibration", "spec": identity(spec_path), "started_unix_ns": time.time_ns()})
    result = {"schema": SCHEMA + ".calibration-result.v1", "status": "FAIL", "intent": intent,
              "boots": [], "observations": [], "started_unix_ns": time.time_ns()}
    try:
        registry, collector = prepare_admission(spec, output, deep=False)
        admission = write_new(output / "ADMISSION.json", registry)
        schedule = calibration_schedule(registry, output, collector)
        plan = {"schema": SCHEMA + ".calibration-plan.v1", "partition": "calibration",
                "admission": admission, "protocol_digest": digest(registry["protocol"]),
                "created_unix_ns": time.time_ns(), "runs": schedule}
        result["plan"] = write_new(output / "PLAN.json", plan)
        finished_builds = max(row["completed_unix_ns"] for row in registry["images"].values())
        require(plan["created_unix_ns"] > finished_builds, "calibration plan predates completed images")
        for row in schedule:
            lightweight_inputs(registry, collector, row["image_id"])
            observation = quiet_host_observation()
            write_new(output / "host-before" / (row["request"]["run_id"] + ".json"), observation)
            require_quiet_host(observation)
            require(not Path(row["request"]["output"]).exists(), "calibration output already exists; no rerun")
            value = collector.run_guest(**row["request"])
            require(value.get("status") == "PASS", "actual calibration boot failed; campaign cannot retry")
            accepted = admit_guest(Path(row["request"]["output"]) / "RESULT.json", registry,
                                   row["image_id"], collector, partition="calibration", expected=row["request"])
            require(accepted["started_unix_ns"] >= plan["created_unix_ns"] > finished_builds,
                    "calibration boot chronology differs from precommitted plan")
            result["boots"].append(accepted)
            result["observations"].extend(accepted["observations"])
        require_independent_boots(result["boots"], forbidden=registry["qualifications"].values())
        assert_training_partition(result["observations"], registry["protocol"])
        result["status"] = "PASS"
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    result["completed_unix_ns"] = time.time_ns()
    write_new(output / "RESULT.json", result)
    return result


def admit_calibration(path, registry, collector):
    value = load(path)
    require(value.get("schema") == SCHEMA + ".calibration-result.v1" and
            value.get("status") == "PASS", "twelve actual preplanned calibration boots required")
    check_binding(value["intent"])
    check_binding(value["plan"])
    plan = load(value["plan"]["path"])
    require(plan.get("schema") == SCHEMA + ".calibration-plan.v1" and
            plan.get("partition") == "calibration" and
            plan["protocol_digest"] == digest(registry["protocol"]), "calibration plan protocol differs")
    check_binding(plan["admission"])
    prior = load(plan["admission"]["path"])
    for key in ("campaign_id", "runtime", "native_images", "qualifications", "source"):
        require(prior[key] == registry[key], "calibration registration changed: " + key)
    require({k: row["build_receipt"] for k, row in prior["images"].items()} ==
            {k: row["build_receipt"] for k, row in registry["images"].items()}, "calibration build set changed")
    expected = calibration_schedule(registry, Path(path).parent, collector)
    require(plan["runs"] == expected and len(value["boots"]) == 12, "calibration inventory differs")
    finished_builds = max(row["completed_unix_ns"] for row in registry["images"].values())
    require(plan["created_unix_ns"] > finished_builds, "calibration preceded completed builds")
    boots, observations = [], []
    for planned, claimed in zip(expected, value["boots"]):
        check_binding(claimed["result"])
        accepted = admit_guest(claimed["result"]["path"], registry, planned["image_id"], collector,
                               partition="calibration", expected=planned["request"])
        require(accepted == claimed and accepted["started_unix_ns"] >= plan["created_unix_ns"],
                "calibration receipt/chronology changed")
        before = load(Path(path).parent / "host-before" / (accepted["run_id"] + ".json"))
        require_quiet_host(before)
        require(before["observed_unix_ns"] <= accepted["started_unix_ns"], "host gate recorded after boot")
        boots.append(accepted)
        observations.extend(accepted["observations"])
    require_independent_boots(boots, forbidden=registry["qualifications"].values())
    require(observations == value["observations"], "training statistics differ from actual boot samples")
    assert_training_partition(observations, registry["protocol"])
    return {"result": identity(path), "plan": value["plan"], "boots": boots,
            "observations": observations, "qemu_wall_ns": sum(row["qemu_wall_ns"] for row in boots),
            "pipeline_wall_ns": value["completed_unix_ns"] - value["started_unix_ns"]}


def training_best_fixed(registry):
    model = build_model(registry["training"], [], current_phase=PHASES[0],
                        episode_index=0, protocol_value=registry["protocol"])
    scores = {}
    for image in HIA_IMAGES:
        total = 0
        for phase in PHASES:
            components = measured_components(
                as_fraction(model["stock_training_medians_ns"][phase]),
                registry["images"]["stock"]["kernel"]["bytes"],
                registry["images"][image]["kernel"]["bytes"],
                as_fraction(model["cells"][image][phase]["median_ns"]))
            target = registry["protocol"]["objective"]["public_targets_q32"][phase]
            total += sum(mul_q32(target[key], components[key]) for key in target)
        scores[image] = total
    best = max(HIA_IMAGES, key=lambda image: (scores[image], -HIA_IMAGES.index(image)))
    return {"image_id": best, "sum_four_training_phase_utility_q32": scores,
            "holdout_observations_used": False, "selection_frozen_before_holdout": True}


def register(spec_path, calibration_result, output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic_ns()
    write_new(output / "INTENT.json", {"schema": SCHEMA + ".registration-intent.v1",
        "spec": identity(spec_path), "calibration_result": identity(calibration_result),
        "started_unix_ns": time.time_ns()})
    try:
        spec = load(spec_path)
        spec["_spec_path"] = str(Path(spec_path).resolve())
        registry, collector = prepare_admission(spec, output, deep=True)
        registry["calibration"] = admit_calibration(calibration_result, registry, collector)
        registry["training"] = registry["calibration"]["observations"]
        registry["best_fixed"] = training_best_fixed(registry)
        registry["schedule"] = make_schedule(registry["protocol"], registry["campaign_id"])
        registry["artifact_equivalence_groups"] = {}
        for name in IMAGES:
            registry["artifact_equivalence_groups"].setdefault(registry["images"][name]["kernel"]["sha256"], []).append(name)
        registry["external_runtime_evidence"] = [identity(path) for path in spec.get("external_runtime_evidence", [])]
        registry["created_unix_ns"] = time.time_ns()
        registry["registration_wall_ns"] = time.monotonic_ns() - started
        registry["status"] = "REGISTERED"
        binding = write_new(output / "REGISTRY.json", registry)
        state = {"schema": SCHEMA + ".state.v1", "registry": binding, "status": "READY",
                 "next_index": 0, "completed": [], "pending": None}
        write_new(output / "STATE.json", state)
        return {"status": "PASS", "registry": binding, "heldout_boots_started": 0,
                "registration_wall_ns": registry["registration_wall_ns"]}
    except BaseException as error:
        value = {"status": "FAIL", "error": {"type": type(error).__name__, "message": str(error)},
                 "whole_build_pass_fabricated": False, "heldout_boots_started": 0}
        write_new(output / "REGISTRATION_FAILURE.json", value)
        return value


@contextmanager
def campaign_lock(output):
    output = Path(output).resolve(strict=True)
    with (output / "LOCK").open("a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield output


def read_campaign(output):
    state = load(Path(output) / "STATE.json")
    require(state.get("schema") == SCHEMA + ".state.v1", "campaign state schema")
    check_binding(state["registry"])
    registry = load(state["registry"]["path"])
    require(registry.get("status") == "REGISTERED" and state.get("status") != "FAIL",
            "campaign failed or was not admitted")
    require(registry["protocol"] == protocol(), "protocol changed since registration")
    require(registry["schedule"] == make_schedule(registry["protocol"], registry["campaign_id"]),
            "precommitted randomized schedule changed")
    require(len(state["completed"]) == state["next_index"], "history length differs from state")
    return registry, state


def past_history(registry, state):
    history = []
    for index, binding in enumerate(state["completed"]):
        check_binding(binding)
        value = load(binding["path"])
        require(value.get("status") == "PASS" and value["index"] == index and
                value["phase"] == registry["schedule"][index]["phase"] and
                value["registry"] == state["registry"], "history is not the complete registered prefix")
        check_binding(value["plan"])
        for observation in value["observations"]:
            check_binding(observation["result"])
        history.append(value)
    return history


def fail_campaign(output, state, error, stage):
    failure = {"schema": SCHEMA + ".failure.v1", "status": "FAIL", "stage": stage,
               "error": {"type": type(error).__name__, "message": str(error)},
               "observed_unix_ns": time.time_ns(), "retry_allowed": False,
               "retained_pending": state.get("pending")}
    destination = Path(output) / ("FAILURE-" + str(time.time_ns()) + ".json")
    state.update(status="FAIL", failure=write_new(destination, failure))
    replace_state(Path(output) / "STATE.json", state)
    return failure


def child_cpu_ns():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return round((usage.ru_utime + usage.ru_stime) * 1_000_000_000)


def native_call(binding, request, directory):
    """One actual cold native process with complete raw JSON request/response."""
    total_started, total_cpu, total_children = time.monotonic_ns(), time.process_time_ns(), child_cpu_ns()
    check_binding(binding)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    payload = wire(request)
    require(len(payload) <= 1_048_576, "native input frame exceeds frozen bound")
    request_binding = write_new(directory / "request.json", payload)
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    started, cpu, children = time.monotonic_ns(), time.process_time_ns(), child_cpu_ns()
    record = {"argv": [binding["path"]], "environment": env, "stdin": request_binding,
              "started_unix_ns": time.time_ns(), "cold_process": True}
    try:
        completed = subprocess.run(record["argv"], input=payload, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env, timeout=30, check=False)
        record.update(exit_code=completed.returncode, timed_out=False)
        stdout, stderr = completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as error:
        record.update(exit_code=None, timed_out=True)
        stdout, stderr = error.stdout or b"", error.stderr or b""
    finally:
        record.update(elapsed_ns=time.monotonic_ns() - started,
                      parent_cpu_ns=time.process_time_ns() - cpu,
                      child_cpu_ns=child_cpu_ns() - children, completed_unix_ns=time.time_ns())
    record["stdout"] = write_new(directory / "stdout.json", stdout)
    record["stderr"] = write_new(directory / "stderr.txt", stderr)
    record_binding = write_new(directory / "COMMAND.json", record)
    require(record["exit_code"] == 0 and record["timed_out"] is False and not stderr,
            "native controller failed; no fallback decision")
    require(len(stdout) <= 1_048_576, "native output frame exceeds frozen bound")
    response = strict_json(stdout)
    integer(response["service_before_output_ns"], "native measured service ns")
    return response, {"request": request_binding, "response": record["stdout"],
                      "command": record_binding, "wall_ns": time.monotonic_ns() - total_started,
                      "parent_cpu_ns": time.process_time_ns() - total_cpu,
                      "child_cpu_ns": child_cpu_ns() - total_children,
                      "cold_process_io_wall_ns": record["elapsed_ns"],
                      "request_bytes": len(payload), "response_bytes": len(stdout),
                      "cost_scope": "binary binding, JSON serialization, durable request/response/command logs, cold process I/O and JSON parsing; excludes independent arithmetic audit",
                      "service_ns": response["service_before_output_ns"]}


def check_ordinary_response(envelope, response, reference, preference):
    request = envelope["request"]
    require(response.get("schema") == "hepta.hia.kernel-ordinary-control.response.v1" and
            response.get("status") == "advisory" and
            response.get("input_sha256") == hashlib.sha256(wire(envelope)).hexdigest() and
            response.get("request_sha256") == hashlib.sha256(wire(request)).hexdigest(),
            "independent native request identity mismatch")
    require(request["preference"]["previous_state"] is None and
            response.get("implementation") == "independent-rust-integer-control" and
            all(response.get(key) is False for key in (
                "native_ndu_linked_or_called", "native_state_digests_created", "measurements_created",
                "kernel_image_verified_by_adapter", "production_activation_allowed")) and
            response.get("authority") == "DENY_ALL", "ordinary control scope/independence changed")
    for key in ("objective_digest", "snapshot_digest", "action_registry_digest", "generation"):
        require(response[key] == request[key], "ordinary request binding differs")
    native = response["preference"]
    initial = axis_map(envelope["previous_weights"] or request["preference"]["genesis_values"])
    require(axis_map(native["initial_weights"]) == initial and
            axis_map(native["weights"]) == preference["values"] and
            axis_map(native["target"]) == axis_map(request["preference"]["target"]),
            "ordinary preference differs from independent Python calculation")
    require(len(native["iterations"]) == len(preference["iterations"]), "ordinary step count")
    for actual, expected in zip(native["iterations"], preference["iterations"]):
        require(actual["iteration"] == expected["iteration"] and
                actual["residual_raw"] == expected["residual_raw"] and
                axis_map(actual["values"]) == expected["values"] and actual["projection_count"] == 0,
                "ordinary preference step differs")
    require(native["termination"]["terminal_residual_raw"] == preference["residual_raw"] and
            native["termination"]["iterations"] == len(preference["iterations"]) and
            native["termination"]["projection_count"] == 0, "ordinary terminal certificate differs")
    paths = {row["id"]: row for row in response["paths"]}
    require(len(paths) == len(response["paths"]) == 82 and response["complete_image_paths"] == 81,
            "ordinary path omission/duplicate")
    for candidate in request["candidates"]:
        actual, expected = paths[candidate["id"]], reference["paths"][candidate["id"]]
        require(actual["values_q32"] == expected["values_q32"] and
                actual["feasible"] is expected["feasible"] and actual["projection_count"] == 0 and
                len(actual["phases"]) == len(expected["phases"]), "ordinary values/feasibility differ")
        for key in ("verified", "resource_cost_q32", "risk_q32", "uncertainty_q32"):
            require(actual[key] == candidate[key], "ordinary candidate fields differ")
        for source, phase, term in zip(candidate["path"], actual["phases"], expected["phases"]):
            require(phase["image_id"] == source["image_id"] and
                    phase["instant_q32"] == term["instant_q32"] and
                    phase["discount_q32"] == source["discount_q32"] and
                    phase["cost_q32"] == source["cost_q32"], "ordinary phase differs")
            terms = {row["axis"]: row for row in phase["terms"]}
            components = axis_map(source["components"])
            require(len(terms) == len(phase["terms"]) and set(terms) == set(components),
                    "ordinary term dimensions differ")
            for axis in terms:
                require(terms[axis]["weighted_q32"] == term["terms"][axis] and
                        terms[axis]["weight_q32"] == preference["values"][axis] and
                        terms[axis]["component_q32"] == components[axis], "ordinary weighted term differs")
    require(response["pareto_candidate_ids"] == reference["frontier"] and
            response["selected_first_image_id"] == reference["selected_image"],
            "ordinary native action differs from independent arithmetic")
    return {"status": "PASS", "checked_candidates": 82,
            "checked_preference_steps": len(preference["iterations"])}


def prior_controller_values(history, arm):
    if not history:
        return None
    plan = load(history[-1]["plan"]["path"])
    controller = plan["arms"][arm]["native_call"]
    check_binding(controller["response"])
    response = load(controller["response"]["path"])
    return (response["preference"]["weights"] if arm == "independent-same-objective" else
            response["preference"]["next_request_state"])


def plan_next(output, *, phase, seed):
    with campaign_lock(output) as output:
        registry, state = read_campaign(output)
        try:
            require(state["status"] == "READY" and state["pending"] is None and
                    state["next_index"] < 20, "pending, interrupted, or finished campaign cannot be replanned")
            case = registry["schedule"][state["next_index"]]
            require(phase == case["phase"] and seed == case["seed"], "current public phase/seed differs from registration")
            directory = output / "episodes" / f'{case["index"]:03d}'
            directory.mkdir(parents=True, exist_ok=False)
            planning_started = time.monotonic_ns()
            intent = write_new(directory / "INTENT.json", {"registry": state["registry"],
                "index": case["index"], "phase": phase, "seed": seed, "started_unix_ns": time.time_ns(),
                "history": state["completed"], "partition": "heldout"})
            state.update(status="PLANNING", pending={"intent": intent})
            replace_state(output / "STATE.json", state)
            collector = load_collector(registry["runtime"]["collector"])
            lightweight_inputs(registry, collector)
            history = past_history(registry, state)
            model_started, model_cpu = time.monotonic_ns(), time.process_time_ns()
            model = build_model(registry["training"], history, current_phase=phase,
                                episode_index=case["index"], protocol_value=registry["protocol"])
            snapshot = {"schema": SCHEMA + ".snapshot.v1", "current_phase": phase,
                "current_seed": seed, "iterations": case["iterations"], "model": model,
                "complete_past_history": state["completed"], "training": registry["calibration"]["result"],
                "qualification_used": False, "future_outcomes_used": False}
            common_model = {"wall_ns": time.monotonic_ns() - model_started,
                            "cpu_ns": time.process_time_ns() - model_cpu}
            snapshot_binding = write_new(directory / "SNAPSHOT.json", snapshot)
            start, cpu = time.monotonic_ns(), time.process_time_ns()
            candidates = make_candidates(model, registry["native_images"], digest(snapshot),
                                         digest(registry["protocol"]["objective"]))
            common_paths = {"wall_ns": time.monotonic_ns() - start, "cpu_ns": time.process_time_ns() - cpu}
            budget = incumbent_budget(candidates)
            target = registry["protocol"]["objective"]["public_targets_q32"][phase]
            genesis = registry["protocol"]["objective"]["genesis_q32"]
            arms = {}
            for arm, image in (("stock", "stock"), ("hia-static", "hia-original"),
                               ("best-fixed", registry["best_fixed"]["image_id"])):
                start, cpu = time.monotonic_ns(), time.process_time_ns()
                arms[arm] = {"selected_image": image, "image_id": image, "abstain": False,
                             "decision": "registered fixed image"}
                arms[arm]["cost"] = {"decision_wall_ns": time.monotonic_ns() - start,
                                     "decision_cpu_ns": time.process_time_ns() - cpu,
                                     "service_ns": 0, "audit_wall_ns": 0}
            for arm in ("greedy", "ordinary-mpc"):
                start, cpu = time.monotonic_ns(), time.process_time_ns()
                decision = (greedy_reference(candidates, target, budget=budget) if arm == "greedy" else
                            evaluate_paths(candidates, target, budget=budget))
                arms[arm] = {"selected_image": decision["selected_image"],
                    "image_id": decision["executed_image"], "abstain": decision["abstain"],
                    "reference": decision, "cost": {"decision_wall_ns": time.monotonic_ns() - start,
                    "decision_cpu_ns": time.process_time_ns() - cpu, "service_ns": 0, "audit_wall_ns": 0}}
            # Independent Rust action is fixed before either NDU response exists.
            arm = "independent-same-objective"
            decision_start, decision_cpu, decision_children = time.monotonic_ns(), time.process_time_ns(), child_cpu_ns()
            previous = prior_controller_values(history, arm)
            request = native_request(registry, snapshot, candidates, case["index"] + 1,
                                     mode="dynamic", previous_state=None)
            envelope = {"schema": "hepta.hia.kernel-ordinary-control.request.v1",
                        "request": request, "previous_weights": previous}
            response, call = native_call(registry["ordinary_control"]["executable"], envelope, directory / arm)
            decision_wall = time.monotonic_ns() - decision_start
            decision_cpu_used = time.process_time_ns() - decision_cpu + child_cpu_ns() - decision_children
            start = time.monotonic_ns()
            pref = preference_reference(axis_map(previous) if previous else genesis, target)
            reference = evaluate_paths(candidates, pref["values"], budget=budget)
            checked = check_ordinary_response(envelope, response, reference, pref)
            arms[arm] = {"selected_image": response["selected_first_image_id"],
                "image_id": response["selected_first_image_id"] or "hia-original",
                "abstain": response["selected_first_image_id"] is None, "native_call": call,
                "independent_audit": checked, "cost": {"decision_wall_ns": decision_wall,
                "decision_cpu_ns": decision_cpu_used,
                "service_ns": call["service_ns"], "audit_wall_ns": time.monotonic_ns() - start}}
            for arm, mode in (("fixed-ndu", "fixed"), ("dynamic-ndu", "dynamic")):
                decision_start, decision_cpu, decision_children = time.monotonic_ns(), time.process_time_ns(), child_cpu_ns()
                previous = prior_controller_values(history, arm)
                request = native_request(registry, snapshot, candidates, case["index"] + 1,
                                         mode=mode, previous_state=previous)
                response, call = native_call(registry["native"]["executable"], request, directory / arm)
                decision_wall = time.monotonic_ns() - decision_start
                decision_cpu_used = time.process_time_ns() - decision_cpu + child_cpu_ns() - decision_children
                start = time.monotonic_ns()
                pref = preference_reference(axis_map(previous["values"]) if previous else genesis,
                                            target, mode=mode)
                reference = evaluate_paths(candidates, pref["values"], budget=budget)
                checked = check_native_response(request, response, reference, pref)
                arms[arm] = {"selected_image": response["selected_first_image_id"],
                    "image_id": response["selected_first_image_id"] or "hia-original",
                    "abstain": response["selected_first_image_id"] is None, "native_call": call,
                    "independent_audit": checked, "cost": {"decision_wall_ns": decision_wall,
                    "decision_cpu_ns": decision_cpu_used,
                    "service_ns": call["service_ns"], "solve_ns": response["preference"]["solve_ns"],
                    "audit_wall_ns": time.monotonic_ns() - start}}
            for arm, row in arms.items():
                shared_wall = common_model["wall_ns"] + common_paths["wall_ns"] if arm in ADAPTIVE else 0
                shared_cpu = common_model["cpu_ns"] + common_paths["cpu_ns"] if arm in ADAPTIVE else 0
                row["cost"].update(standalone_planning_wall_ns=row["cost"]["decision_wall_ns"] + shared_wall,
                                   standalone_planning_cpu_ns=row["cost"]["decision_cpu_ns"] + shared_cpu,
                                   common_construction_charged_wall_ns=shared_wall)
                row["request"] = make_guest_request(registry, row["image_id"], directory / "boots" / arm,
                    run_id=case["run_ids"][arm], seed=seed, selection=phase)
                row["expected_argv"] = expected_argv(collector, row["request"], registry["runtime"]["taskset"])
            plan = {"schema": SCHEMA + ".plan.v1", "registry": state["registry"], "intent": intent,
                "snapshot": snapshot_binding, "case": case, "arms": arms,
                "candidate_count": 82, "resource_unit": "microseconds", "resource_budget_q32": budget,
                "feasible_candidate_count": sum(row["resource_cost_q32"] <= budget for row in candidates),
                "resource_rejected_candidate_count": sum(row["resource_cost_q32"] > budget for row in candidates),
                "common_model_cost": common_model, "common_paths_cost": common_paths,
                "planned_unix_ns": time.time_ns(), "no_boot_started": True,
                "actual_total_planning_wall_ns": time.monotonic_ns() - planning_started}
            binding = write_new(directory / "PLAN.json", plan)
            state.update(status="PLANNED", pending={"plan": binding, "executed": [], "inflight": None})
            replace_state(output / "STATE.json", state)
            return {"status": "PASS", "plan": binding, "next_arm": case["arm_order"][0],
                    "all_eight_actions_frozen": True, "boots_started": 0}
        except BaseException as error:
            return fail_campaign(output, state, error, "plan-next")


def execute_next(output):
    with campaign_lock(output) as output:
        registry, state = read_campaign(output)
        try:
            require(state["status"] == "PLANNED" and state["pending"] and
                    state["pending"]["inflight"] is None, "unplanned/interrupted boot cannot be retried")
            pending = state["pending"]
            check_binding(pending["plan"])
            plan = load(pending["plan"]["path"])
            case = registry["schedule"][state["next_index"]]
            require(plan["case"] == case and plan["registry"] == state["registry"] and
                    set(plan["arms"]) == set(ARMS) and plan["no_boot_started"] is True,
                    "complete precommitted eight-arm plan required")
            position = len(pending["executed"])
            require(position < 8, "all planned arms already executed")
            for index, prior in enumerate(pending["executed"]):
                check_binding(prior)
                require(load(prior["path"])["arm"] == case["arm_order"][index], "randomized execution order changed")
            arm = case["arm_order"][position]
            chosen = plan["arms"][arm]
            collector = load_collector(registry["runtime"]["collector"])
            audit_start = time.monotonic_ns()
            lightweight_inputs(registry, collector, chosen["image_id"])
            request = make_guest_request(registry, chosen["image_id"], chosen["request"]["output"],
                run_id=case["run_ids"][arm], seed=case["seed"], selection=case["phase"])
            require(chosen["request"] == request and chosen["expected_argv"] ==
                    expected_argv(collector, request, registry["runtime"]["taskset"]),
                    "planned boot arguments changed")
            require(not Path(request["output"]).exists(), "boot output already exists; reruns forbidden")
            if chosen["abstain"]:
                require(chosen["image_id"] == "hia-original", "abstention skipped or changed incumbent workload")
            host = quiet_host_observation()
            host_binding = write_new(Path(pending["plan"]["path"]).parent / "host-before" /
                                     (arm + ".json"), host)
            require_quiet_host(host)
            require(os.access("/dev/kvm", os.R_OK | os.W_OK), "actual KVM unavailable")
            pre_audit_ns = time.monotonic_ns() - audit_start
            pending["inflight"] = {"arm": arm, "request": request, "host_before": host_binding,
                                   "started_unix_ns": time.time_ns()}
            state["status"] = "EXECUTING"
            replace_state(output / "STATE.json", state)
            started = time.monotonic_ns()
            value = collector.run_guest(**request)
            execution_wall = time.monotonic_ns() - started
            require(value.get("status") == "PASS", "actual heldout boot failed; retain and stop")
            audit_start = time.monotonic_ns()
            accepted = admit_guest(Path(request["output"]) / "RESULT.json", registry,
                chosen["image_id"], collector, partition="heldout", expected=request)
            require(accepted["started_unix_ns"] >= plan["planned_unix_ns"], "outcome predates frozen actions")
            past = past_history(registry, state)
            forbidden = list(registry["qualifications"].values()) + registry["calibration"]["boots"]
            for complete in past:
                forbidden.extend({"run_id": row["run_id"], "output": str(Path(row["result"]["path"]).parent),
                                  "stdout_sha256": row["stdout"]["sha256"]} for row in complete["observations"])
            for binding in pending["executed"]:
                prior = load(binding["path"])
                forbidden.append({"run_id": prior["run_id"], "output": str(Path(prior["result"]["path"]).parent),
                                  "stdout_sha256": prior["stdout"]["sha256"]})
            require_independent_boots([accepted], forbidden=forbidden)
            require(len(accepted["observations"]) == 1, "heldout must be one registered phase")
            row = accepted["observations"][0]
            row.update(arm=arm, case_index=case["index"], block=case["block"], plan=pending["plan"],
                       host_before=host_binding, planning=chosen["cost"], abstain=chosen["abstain"],
                       execute_call_wall_ns=execution_wall, pre_execution_audit_wall_ns=pre_audit_ns,
                       post_execution_audit_wall_ns=time.monotonic_ns() - audit_start)
            row["net_delivery_wall_ns"] = row["qemu_wall_ns"] + chosen["cost"]["standalone_planning_wall_ns"]
            binding = write_new(Path(pending["plan"]["path"]).parent / "observations" / (arm + ".json"), row)
            pending["executed"].append(binding)
            pending["inflight"] = None
            if len(pending["executed"]) == 8:
                complete = {"schema": SCHEMA + ".complete-cell.v1", "status": "PASS",
                    "registry": state["registry"], "index": case["index"], "block": case["block"],
                    "phase": case["phase"], "seed": case["seed"], "plan": pending["plan"],
                    "observation_files": pending["executed"],
                    "observations": [load(item["path"]) for item in pending["executed"]],
                    "completed_unix_ns": time.time_ns()}
                complete_binding = write_new(Path(pending["plan"]["path"]).parent / "COMPLETE.json", complete)
                state["completed"].append(complete_binding)
                state.update(next_index=state["next_index"] + 1, pending=None,
                             status="COMPLETE" if state["next_index"] == 19 else "READY")
            else:
                state["status"] = "PLANNED"
            replace_state(output / "STATE.json", state)
            return {"status": "PASS", "observed": binding, "campaign_status": state["status"],
                    "completed_cells": state["next_index"], "boots_in_pending_cell": 0 if not state["pending"] else
                    len(state["pending"]["executed"])}
        except BaseException as error:
            return fail_campaign(output, state, error, "execute-next")


def setup_cost(registry, arm):
    needed = cost_requirements(arm)
    builds = [registry["images"][image] for image in needed["images"]]
    intervals = sorted((row["started_unix_ns"], row["started_unix_ns"] + row["whole_build_wall_ns"])
                       for row in builds)
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    union = sum(end - start for start, end in merged)
    window = max(end for _, end in intervals) - min(start for start, _ in intervals)
    events = sorted((when, delta) for start, end in intervals for when, delta in ((start, 1), (end, -1)))
    current = maximum = 0
    for _, change in events:
        current += change
        maximum = max(maximum, current)
    details = {"whole_builds_observed_window_ns": window,
               "image_qualification_qemu_ns": sum(registry["qualifications"][image]["qemu_wall_ns"]
                                                  for image in needed["images"]),
               "calibration_qemu_ns": registry["calibration"]["qemu_wall_ns"] if needed["calibration"] else 0,
               "native_ndu_preparation_ns": registry["native"]["preparation_wall_ns"] if needed["native_adapter"] else 0,
               "ordinary_control_preparation_ns": registry["ordinary_control"]["preparation_wall_ns"]
                                                  if needed["ordinary_control"] else 0}
    return {"required": needed, "details": details, "total_ns": sum(details.values()),
            "build_concurrency": {"maximum_overlapping_pipelines": maximum,
                "sum_individual_pipeline_wall_ns": sum(row["whole_build_wall_ns"] for row in builds),
                "active_pipeline_union_wall_ns": union, "observed_pipeline_window_ns": window,
                "idle_gaps_inside_observed_window_ns": window - union,
                "kbuild_child_cpu_ns": sum(row["kbuild_child_cpu_ns"] for row in builds),
                "all_recorded_commands_child_cpu_ns": sum(row["all_recorded_commands_child_cpu_ns"] for row in builds),
                "isolated_build_speed_benchmark": False,
                "interpretation": "actual observed pipeline window, including gaps; overlaps counted once. Sum wall is work accounting, not parallel makespan."},
            "scope": "observed build pipeline window plus necessary qualification/calibration QEMU time and native preparation"}


def summarize_statistics(rows, registry):
    require(len(rows) == 160 and len({row["run_id"] for row in rows}) == 160,
            "exactly 160 unique independent heldout boots required")
    cells = {(row["block"], row["phase"], row["arm"]): row for row in rows}
    require(len(cells) == 160 and set(cells) == set(itertools.product(range(5), PHASES, ARMS)),
            "missing or duplicate registered block/phase/arm observation")
    per_phase, overall = {}, {}
    for arm in ARMS:
        per_phase[arm] = {}
        for phase in PHASES:
            comparisons = {}
            for metric in ("guest_ns_per_op", "qemu_wall_ns", "net_delivery_wall_ns"):
                pairs = []
                for block in range(5):
                    base, treatment = cells[block, phase, "stock"], cells[block, phase, arm]
                    get = (lambda row: as_fraction(row["ns_per_op"])) if metric == "guest_ns_per_op" else (
                        lambda row, key=metric: row[key])
                    pairs.append((get(base), get(treatment)))
                comparisons[metric] = paired_cluster_bootstrap(pairs)
            per_phase[arm][phase] = comparisons
        overall[arm] = {}
        for metric in ("median_ns", "qemu_wall_ns", "net_delivery_wall_ns"):
            pairs = [(sum(cells[block, phase, "stock"][metric] for phase in PHASES),
                      sum(cells[block, phase, arm][metric] for phase in PHASES)) for block in range(5)]
            overall[arm]["four_phase_cycle_" + metric] = paired_cluster_bootstrap(pairs)
    # Targets are the same public QoS for all arms, not their private current preference.
    training_model = build_model(registry["training"], [], current_phase=PHASES[0], episode_index=0,
                                 protocol_value=registry["protocol"])
    utility = {}
    for arm in ARMS:
        per_boot = []
        for block in range(5):
            for phase in PHASES:
                row = cells[block, phase, arm]
                components = measured_components(
                    as_fraction(training_model["stock_training_medians_ns"][phase]),
                    registry["images"]["stock"]["kernel"]["bytes"], row["image_bytes"], row["median_ns"])
                target = registry["protocol"]["objective"]["public_targets_q32"][phase]
                score = sum(mul_q32(target[key], components[key]) for key in target)
                per_boot.append({"block": block, "phase": phase, "run_id": row["run_id"],
                                 "public_target": target, "components_q32": components, "utility_q32": score})
        utility[arm] = per_boot
    utility_stats = {}
    for arm in ARMS:
        pairs = [(sum(row["utility_q32"] for row in utility["stock"] if row["block"] == block),
                  sum(row["utility_q32"] for row in utility[arm] if row["block"] == block)) for block in range(5)]
        value = paired_cluster_bootstrap(pairs)
        value["lower_is_better"] = False
        utility_stats[arm] = value
    setup = {arm: setup_cost(registry, arm) for arm in ARMS}
    baseline_cycle = Fraction(sum(cells[block, phase, "stock"]["net_delivery_wall_ns"]
                                 for block in range(5) for phase in PHASES), 5)
    amortization = {}
    all_feedback_cycle = Fraction(sum(row["qemu_wall_ns"] for row in rows), 5)
    for arm in ARMS:
        direct = Fraction(sum(row["net_delivery_wall_ns"] for row in rows if row["arm"] == arm), 5)
        extra_feedback = (all_feedback_cycle - Fraction(sum(row["qemu_wall_ns"] for row in rows
                                                            if row["arm"] == arm), 5)
                          if arm in ADAPTIVE else Fraction(0))
        scenarios = {}
        for label, cost in (("provided_past_feedback", direct), ("all_shared_feedback_charged", direct + extra_feedback)):
            scenarios[label] = {"observed_four_phase_cycle_ns": number(cost),
                "feedback_extra_cycle_ns": number(extra_feedback if label == "all_shared_feedback_charged" else 0),
                "deployment_counts": [{"four_phase_cycles": count,
                    "total_ns": number(setup[arm]["total_ns"] + count * cost),
                    "amortized_cycle_ns": number(Fraction(setup[arm]["total_ns"], count) + cost)}
                    for count in registry["protocol"]["costs"]["deployment_counts"]],
                "break_even_vs_stock": break_even(setup[arm]["total_ns"] - setup["stock"]["total_ns"],
                                                  baseline_cycle, cost)}
        amortization[arm] = scenarios
    same = sum(cells[block, phase, "independent-same-objective"]["image_id"] ==
               cells[block, phase, "dynamic-ndu"]["image_id"] for block in range(5) for phase in PHASES)
    return {"per_phase": per_phase, "four_phase_block_cycles": overall,
        "public_objective_observations": utility, "public_objective_block_statistics": utility_stats,
        "setup_costs": setup, "amortization": amortization,
        "same_objective_and_dynamic_ndu_matching_actions": same, "action_comparisons": 20,
        "mechanism_equivalent_on_observed_actions": same == 20,
        "mechanism_interpretation": ("All same-objective/native actions coincide; no NDU-specific decision gain is established. Compare real implementation overhead."
            if same == 20 else "Actions differ; inspect bound requests, state and all candidate audits before interpreting performance."),
        "independent_block_clusters": 5, "within_boot_repeats_as_independent_samples": False,
        "online_seamless_kernel_switching_measured": False, "image_bytes_are_runtime_ram": False}


def evaluate(output):
    with campaign_lock(output) as output:
        registry, state = read_campaign(output)
        try:
            require(state["status"] == "COMPLETE" and state["next_index"] == 20 and state["pending"] is None,
                    "all 160 original scheduled boots must complete before evaluation")
            require(not (output / "EVALUATION.json").exists(), "evaluation already frozen")
            started = time.monotonic_ns()
            collector = load_collector(registry["runtime"]["collector"])
            lightweight_inputs(registry, collector)
            history = past_history(registry, state)
            rows, actual_planning_ns, native_records, budgets = [], 0, [], []
            for complete in history:
                plan = load(complete["plan"]["path"])
                require(plan["case"] == registry["schedule"][complete["index"]], "planned schedule differs")
                actual_planning_ns += plan["actual_total_planning_wall_ns"]
                budgets.append({"index": complete["index"], "phase": complete["phase"],
                    "resource_budget_q32": plan["resource_budget_q32"],
                    "feasible_candidates": plan["feasible_candidate_count"],
                    "resource_rejected_candidates": plan["resource_rejected_candidate_count"]})
                for binding, row in zip(complete["observation_files"], complete["observations"]):
                    check_binding(binding)
                    require(load(binding["path"]) == row, "completed observation changed")
                    planned = plan["arms"][row["arm"]]
                    accepted = admit_guest(row["result"]["path"], registry, row["image_id"], collector,
                        partition="heldout", expected=planned["request"])
                    raw = accepted["observations"][0]
                    require(all(row[key] == value for key, value in raw.items()), "stored measurement differs from raw serial data")
                    require(row["planning"] == planned["cost"] and row["image_id"] == planned["image_id"] and
                            row["abstain"] is planned["abstain"], "executed arm differs from frozen decision")
                    if "native_call" in planned:
                        bind_nested(planned["native_call"])
                        native_records.append(planned["native_call"])
                    require_quiet_host(load(row["host_before"]["path"]))
                    rows.append(row)
            require_independent_boots([{"run_id": row["run_id"], "output": str(Path(row["result"]["path"]).parent),
                "stdout_sha256": row["stdout"]["sha256"]} for row in rows],
                forbidden=[*registry["qualifications"].values(), *registry["calibration"]["boots"]])
            validation_ns = time.monotonic_ns() - started
            statistics_started = time.monotonic_ns()
            statistics = summarize_statistics(rows, registry)
            statistics_ns = time.monotonic_ns() - statistics_started
            audit_started = time.monotonic_ns()
            closure = {}
            for name in IMAGES:
                check_binding(registry["images"][name]["build_receipt"])
                current = audit_build(registry["images"][name]["build_receipt"]["path"], name,
                    registry["protocol"], output / "final-build-closure" / name, deep=True)
                require(current["inventory_digest"] == registry["images"][name]["inventory_digest"] and
                        current["kernel"] == registry["images"][name]["kernel"], "final whole-build closure changed")
                closure[name] = current
            final_audit_ns = time.monotonic_ns() - audit_started
            raw = write_new(output / "HELDOUT_OBSERVATIONS.json", rows)
            result = {"schema": SCHEMA + ".evaluation.v1", "status": "PASS", "registry": state["registry"],
                "scope": "registered complete-image cold-boot comparison", "heldout_boots": 160,
                "correct_boots": 160, "failed_boots": 0, "excluded_outliers": 0,
                "raw_observations": raw, "statistics": statistics, "final_closure": closure,
                "validation_wall_ns": validation_ns, "statistics_wall_ns": statistics_ns,
                "final_whole_build_audit_wall_ns": final_audit_ns,
                "actual_campaign_planning_wall_ns": actual_planning_ns,
                "actual_heldout_qemu_wall_ns": sum(row["qemu_wall_ns"] for row in rows),
                "actual_controller_native_calls": native_records,
                "registration_wall_ns": registry["registration_wall_ns"],
                "calibration_pipeline_wall_ns": registry["calibration"]["pipeline_wall_ns"],
                "artifact_equivalence_groups": registry["artifact_equivalence_groups"],
                "prediction_budget_observations": budgets,
                "cells_with_active_prediction_budget": sum(row["resource_rejected_candidates"] > 0 for row in budgets),
                "external_runtime_evidence": registry["external_runtime_evidence"],
                "files_alone_are_execution_attestation": False,
                "claims": registry["protocol"]["claims"], "completed_unix_ns": time.time_ns()}
            result_binding = write_new(output / "EVALUATION.json", result)
            return {"status": "PASS", "evaluation": result_binding,
                    "matching_same_objective_dynamic_actions": statistics["same_objective_and_dynamic_ndu_matching_actions"]}
        except BaseException as error:
            return fail_campaign(output, state, error, "evaluate")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    calibration = sub.add_parser("calibrate", help="freeze then execute the twelve distinct training boots")
    calibration.add_argument("--spec", required=True, type=Path)
    calibration.add_argument("--output", required=True, type=Path)
    registration = sub.add_parser("register", help="admit four whole images and real independent calibration")
    registration.add_argument("--spec", required=True, type=Path)
    registration.add_argument("--calibration-result", required=True, type=Path)
    registration.add_argument("--output", required=True, type=Path)
    planning = sub.add_parser("plan-next", help="freeze all eight actions before any current-cell boot")
    planning.add_argument("--output", required=True, type=Path)
    planning.add_argument("--phase", choices=PHASES, required=True)
    planning.add_argument("--seed", type=int, required=True)
    for name in ("execute-next", "evaluate"):
        child = sub.add_parser(name)
        child.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "calibrate":
            result = calibrate(args.spec, args.output)
        elif args.command == "register":
            result = register(args.spec, args.calibration_result, args.output)
        elif args.command == "plan-next":
            result = plan_next(args.output, phase=args.phase, seed=args.seed)
        elif args.command == "execute-next":
            result = execute_next(args.output)
        else:
            result = evaluate(args.output)
    except Exception as error:
        result = {"status": "FAIL", "error": {"type": type(error).__name__, "message": str(error)}}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())



