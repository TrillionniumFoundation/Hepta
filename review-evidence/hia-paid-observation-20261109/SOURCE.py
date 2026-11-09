#!/usr/bin/env python3
"""Separate paid-READ mechanism study; never a trained/native NDU result.

Policies accept a closed public state, not task/database handles. Actual READ
and REPAIR effects run in child processes; only post-terminal evaluation sees
the private fixture. This is trusted-host separation, not a security boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import sqlite3
import subprocess
import sys
import tempfile
import time
from fractions import Fraction

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "benchmarks/hia_paid_observation/PROTOCOL.json"
ARMS = ("fixed", "voi", "mpc")
ACTIONS = ("STOP", "REPAIR_A", "REPAIR_B", "READ")
FIELDS = {"p_a", "read_fee_units", "repair_fee_units", "remaining_units",
          "reward_units", "failure_penalty_units", "observation"}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def checked_state(state):
    if type(state) is not dict or set(state) != FIELDS:
        raise ValueError("closed public policy state required")
    probability = state["p_a"]
    if (type(probability) is not list or len(probability) != 2
            or any(type(x) is not int for x in probability)
            or not 0 <= probability[0] <= probability[1] or probability[1] <= 0):
        raise ValueError("rational probability required")
    for key in FIELDS - {"p_a", "observation"}:
        if type(state[key]) is not int or state[key] < 0:
            raise ValueError("known nonnegative tariff and payoff required")
    if state["read_fee_units"] <= 0 or state["repair_fee_units"] <= 0:
        raise ValueError("paid actions require positive fees")
    if state["observation"] not in (None, "a", "b"):
        raise ValueError("unrecognized observation")
    return Fraction(*probability)


def no_read_values(state):
    probability = checked_state(state)
    if state["observation"] is not None:
        probability = Fraction(state["observation"] == "a")
    values = {"STOP": Fraction(0)}
    if state["remaining_units"] >= state["repair_fee_units"]:
        for action, success in (("REPAIR_A", probability), ("REPAIR_B", 1 - probability)):
            values[action] = (success * state["reward_units"]
                              - (1 - success) * state["failure_penalty_units"]
                              - state["repair_fee_units"])
    return values


def select(values):
    return max(values, key=lambda action: (values[action], -ACTIONS.index(action)))


def voi_plan(state):
    """One optional paid perfect observation, with no realized-label access."""
    probability = checked_state(state)
    values = no_read_values(state)
    if state["observation"] is None and state["remaining_units"] >= state["read_fee_units"]:
        remaining = state["remaining_units"] - state["read_fee_units"]
        after_read = max(0, state["reward_units"] - state["repair_fee_units"]) \
            if remaining >= state["repair_fee_units"] else 0
        # Perfect observation yields the same attainable payoff in either mode;
        # write the expectation explicitly to retain the public prior boundary.
        values["READ"] = -state["read_fee_units"] + probability * after_read + (1 - probability) * after_read
    return {"action": select(values), "values": {k: str(v) for k, v in values.items()},
            "no_read_action": select(no_read_values(state))}


def mpc_plan(state):
    """Independent finite-tree enumeration under the same known model."""
    probability = checked_state(state)
    if state["observation"] is not None:
        probability = Fraction(state["observation"] == "a")
    values = {"STOP": Fraction(0)}
    if state["remaining_units"] >= state["repair_fee_units"]:
        for action, target in (("REPAIR_A", "a"), ("REPAIR_B", "b")):
            expected = Fraction(0)
            for mode, chance in (("a", probability), ("b", 1 - probability)):
                payoff = state["reward_units"] if target == mode else -state["failure_penalty_units"]
                expected += chance * (payoff - state["repair_fee_units"])
            values[action] = expected
    if state["observation"] is None and state["remaining_units"] >= state["read_fee_units"]:
        expected = Fraction(-state["read_fee_units"])
        for mode, chance in (("a", probability), ("b", 1 - probability)):
            child = {**state, "observation": mode,
                     "remaining_units": state["remaining_units"] - state["read_fee_units"]}
            continuation = mpc_plan(child)
            expected += chance * Fraction(continuation["values"][continuation["action"]])
        values["READ"] = expected
    return {"action": select(values), "values": {k: str(v) for k, v in values.items()},
            "no_read_action": select({k: v for k, v in values.items() if k != "READ"})}


def fixed_plan(state, strategy):
    checked_state(state)
    if state["remaining_units"] < state["repair_fee_units"]:
        action = "STOP"
    elif state["observation"] is not None:
        action = "REPAIR_" + state["observation"].upper()
    elif (state["read_fee_units"] <= strategy["read_fee_threshold_units"]
          and state["remaining_units"] >= state["read_fee_units"] + state["repair_fee_units"]):
        action = "READ"
    else:
        action = "REPAIR_" + strategy["default_mode"].upper()
    return {"action": action, "strategy": strategy,
            "no_read_action": "REPAIR_" + strategy["default_mode"].upper()}


def public_state(case, protocol):
    state = {key: case[key] for key in ("p_a", "read_fee_units")}
    state.update(remaining_units=case["budget_units"], observation=None)
    state.update({key: protocol[key] for key in ("repair_fee_units", "reward_units", "failure_penalty_units")})
    checked_state(state)
    return state


def fixture(database, mode, values):
    column = "counter_" + mode if mode in ("a", "b") else "invalid_counter"
    with sqlite3.connect(database) as connection:
        connection.execute(f"CREATE TABLE items (id INTEGER PRIMARY KEY, {column} INTEGER NOT NULL)")
        connection.executemany(f"INSERT INTO items (id, {column}) VALUES (?, ?)", enumerate(values))


def worker(database, action, delta):
    # No shell, model, network or other subprocess is available to this worker.
    uri = Path(database).resolve().as_uri() + ("?mode=ro" if action == "READ" else "?mode=rw")
    with sqlite3.connect(uri, uri=True) as connection:
        if action == "READ":
            columns = [row[1] for row in connection.execute("PRAGMA table_info(items)")]
            modes = [mode for mode in ("a", "b") if "counter_" + mode in columns]
            if len(modes) != 1 or columns != ["id", "counter_" + modes[0]]:
                raise ValueError("schema observation unavailable")
            return {"schema": "hepta.hia.paid-schema-observation.v1", "mode": modes[0]}
        if action not in ("REPAIR_A", "REPAIR_B"):
            raise ValueError("worker action refused")
        column = "counter_" + action[-1].lower()
        connection.execute("BEGIN IMMEDIATE")
        changed = connection.execute(f"UPDATE items SET {column} = {column} + ?", (delta,)).rowcount
        connection.commit()
        return {"schema": "hepta.hia.paid-repair-effect.v1", "rows_changed": changed}


def invoke(database, action, delta, timeout_seconds):
    started = time.perf_counter_ns()
    command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()),
               "--worker", str(database), action, str(delta)]
    record = {"action": action, "status": "unknown", "returncode": None,
              "stdout": "", "stderr": "", "response": None}
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout_seconds, check=False)
        record.update(returncode=result.returncode, stdout=result.stdout.decode("utf-8", "replace"),
                      stderr=result.stderr.decode("utf-8", "replace"),
                      status="completed" if result.returncode == 0 else "failed")
        if record["status"] == "completed":
            response = json.loads(record["stdout"])
            required = {"schema", "mode"} if action == "READ" else {"schema", "rows_changed"}
            if type(response) is not dict or set(response) != required:
                raise ValueError("worker response shape differs")
            if action == "READ" and (response["schema"] != "hepta.hia.paid-schema-observation.v1"
                                     or response["mode"] not in ("a", "b")):
                raise ValueError("invalid schema observation")
            if action != "READ" and (response["schema"] != "hepta.hia.paid-repair-effect.v1"
                                     or type(response["rows_changed"]) is not int or response["rows_changed"] < 0):
                raise ValueError("invalid effect response")
            record["response"] = response
    except subprocess.TimeoutExpired as error:
        record.update(status="unknown", reason="timeout_no_retry",
                      stdout=(error.stdout or b"").decode("utf-8", "replace"),
                      stderr=(error.stderr or b"").decode("utf-8", "replace"))
    except (OSError, ValueError) as error:
        record.update(status="unknown", reason=str(error))
    record["wall_ns"] = time.perf_counter_ns() - started
    return record


def evaluate(database, mode, initial, delta):
    """Read actual rows after termination; policy never receives this result."""
    column = "counter_" + mode if mode in ("a", "b") else "invalid_counter"
    with sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True) as connection:
        actual = [row[0] for row in connection.execute(f"SELECT {column} FROM items ORDER BY id")]
    expected = [value + delta for value in initial]
    return {"actual": actual, "expected": expected, "goal_observed": mode in ("a", "b") and actual == expected,
            "mode_released_after_terminal": mode}


def fit_fixed(calibration, protocol):
    candidates = []
    for threshold in protocol["fixed_read_fee_thresholds"]:
        for default in ("a", "b"):
            strategy = {"read_fee_threshold_units": threshold, "default_mode": default}
            score = 0
            for row in calibration:
                state = row["public_state"]
                advice = fixed_plan(state, strategy)
                action = advice["action"]
                if action == "STOP":
                    continue
                fee = state["repair_fee_units"]
                if action == "READ":
                    fee += state["read_fee_units"]
                    target = row["observed_mode"]
                else:
                    target = action[-1].lower()
                score += (state["reward_units"] if target == row["observed_mode"]
                          else -state["failure_penalty_units"]) - fee
            candidates.append({"strategy": strategy, "calibration_score_units": score})
    selected = min(candidates, key=lambda row: (-row["calibration_score_units"],
                   row["strategy"]["read_fee_threshold_units"], row["strategy"]["default_mode"]))
    return {"selected": selected["strategy"], "candidates": candidates,
            "scope": "replay of observed calibration schemas under known effect model; not extra executed policy trials",
            "dataset_sha256": digest(calibration)}


def run_cell(database, case, mode, initial, arm, protocol, strategy):
    if arm not in ARMS:
        raise ValueError("unregistered controller")
    started = time.perf_counter_ns()
    fixture(database, mode, initial)
    input_database_sha = hashlib.sha256(Path(database).read_bytes()).hexdigest()
    setup_wall = time.perf_counter_ns() - started
    state = public_state(case, protocol)
    original = json.loads(json.dumps(state))
    decisions, events = [], []
    terminal = "stopped"
    for step in range(2):
        decision_started = time.perf_counter_ns()
        advice = (fixed_plan(state, strategy) if arm == "fixed" else
                  voi_plan(state) if arm == "voi" else mpc_plan(state))
        decisions.append({"public_state": json.loads(json.dumps(state)), "advice": advice,
                          "wall_ns": time.perf_counter_ns() - decision_started})
        action = advice["action"]
        if action == "STOP":
            break
        fee = state["read_fee_units"] if action == "READ" else state["repair_fee_units"]
        remaining_wall = protocol["wall_budget_ns"] - (time.perf_counter_ns() - started)
        if fee > state["remaining_units"] or remaining_wall <= 0:
            terminal = "refused_budget"
            break
        # Charge exactly once, before dispatch, including failure or timeout.
        state["remaining_units"] -= fee
        record = invoke(database, action, protocol["delta"], remaining_wall / 1e9)
        record.update(fee_units=fee, remaining_units=state["remaining_units"])
        events.append(record)
        if record["status"] != "completed":
            terminal = "unknown" if record["status"] == "unknown" else "failed"
            break
        if action == "READ":
            state["observation"] = record["response"]["mode"]
        else:
            terminal = "effect_completed"
            break
    evaluation_started = time.perf_counter_ns()
    evaluation = evaluate(database, mode, initial, protocol["delta"])
    final_database_sha = hashlib.sha256(Path(database).read_bytes()).hexdigest()
    evaluation_wall = time.perf_counter_ns() - evaluation_started
    outer_wall = time.perf_counter_ns() - started
    spent = original["remaining_units"] - state["remaining_units"]
    within = outer_wall <= protocol["wall_budget_ns"] and spent <= original["remaining_units"]
    delivered = evaluation["goal_observed"] and terminal == "effect_completed" and within
    repair_events = [event for event in events if event["action"].startswith("REPAIR")]
    payoff = protocol["reward_units"] if delivered else -protocol["failure_penalty_units"] if repair_events else 0
    changed = bool(len(decisions) == 2 and events and events[0]["action"] == "READ"
                   and decisions[1]["advice"]["action"] != decisions[0]["advice"]["no_read_action"])
    return {"task_id": case["id"], "arm": arm, "original_public_state": original,
            "public_state_sha256": digest(original), "private_fixture_sha256": digest({"mode": mode, "initial": initial}),
            "input_database_sha256": input_database_sha, "final_database_sha256": final_database_sha,
            "decisions": decisions, "events": events, "terminal": terminal, "evaluation": evaluation,
            "delivered": delivered, "within_original_budget": within, "tariff_spent_units": spent,
            "score_units": payoff - spent, "paid_read_changed_later_action": changed,
            "setup_wall_ns": setup_wall, "evaluation_wall_ns": evaluation_wall, "outer_cell_wall_ns": outer_wall,
            "wall_includes_setup_controller_dispatch_effect_evaluation": True,
            "nested_durations_added_again": False, "ndu_evaluations": 0}


def run(output):
    started = time.perf_counter_ns()
    raw_protocol = PROTOCOL_PATH.read_bytes()
    protocol = json.loads(raw_protocol)
    if protocol["schema"] != "hepta.hia.paid-observation.protocol.v1" or tuple(protocol["arms"]) != ARMS:
        raise ValueError("unsupported protocol")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "PROTOCOL.json").write_bytes(raw_protocol)
    raw_script = Path(__file__).read_bytes()
    (output / "SOURCE.py").write_bytes(raw_script)
    script_sha = hashlib.sha256(raw_script).hexdigest()
    rng = random.Random(protocol["calibration_seed"])
    calibration = []
    calibration_started = time.perf_counter_ns()
    with tempfile.TemporaryDirectory(prefix="hia-paid-read-") as temp:
        temporary = Path(temp)
        for index in range(protocol["shared_calibration_count"]):
            mode = "a" if rng.random() < 0.5 else "b"
            database = temporary / f"calibration-{index}.sqlite"
            fixture(database, mode, [2, 5, 11])
            case = {"p_a": [1, 2], "read_fee_units": 1, "budget_units": 12}
            record = invoke(database, "READ", protocol["delta"], protocol["wall_budget_ns"] / 1e9)
            calibration.append({"id": f"calibration-{index}", "public_state": public_state(case, protocol),
                                "read": record, "fee_units": 1,
                                "database_sha256": hashlib.sha256(database.read_bytes()).hexdigest(),
                                "observed_mode": record["response"]["mode"] if record["status"] == "completed" else None})
        calibration_wall = time.perf_counter_ns() - calibration_started
        if any(row["observed_mode"] is None for row in calibration):
            report = {"schema": "hepta.hia.paid-observation.result.v1", "status": "BLOCKED_CALIBRATION",
                      "calibration": calibration, "protocol_sha256": hashlib.sha256(raw_protocol).hexdigest(),
                      "claims": protocol["claims"], "rows": []}
            (output / "RESULT.json").write_bytes(encoded(report) + b"\n")
            return report
        fit_started = time.perf_counter_ns()
        fit = fit_fixed(calibration, protocol)
        fit_wall = time.perf_counter_ns() - fit_started
        rng = random.Random(protocol["heldout_seed"])
        rows = []
        for index, case in enumerate(protocol["heldout_cases"]):
            normal_mode = "a" if rng.random() < float(Fraction(*case["p_a"])) else "b"
            mode = "invalid" if case.get("invalid_schema") else normal_mode
            initial = [index, index + 3, index * 11 + 5]
            order = ARMS[index % len(ARMS):] + ARMS[:index % len(ARMS)]
            for arm in order:
                rows.append(run_cell(temporary / f"holdout-{index}-{arm}.sqlite", case, mode, initial,
                                     arm, protocol, fit["selected"]))
        retained = output / "databases"
        retained.mkdir()
        for database in temporary.glob("*.sqlite"):
            (retained / database.name).write_bytes(database.read_bytes())
    sources_unchanged = (raw_protocol == PROTOCOL_PATH.read_bytes()
                         and raw_script == Path(__file__).read_bytes())
    accounting = all(row["tariff_spent_units"] == sum(event["fee_units"] for event in row["events"])
                     and row["tariff_spent_units"] <= row["original_public_state"]["remaining_units"]
                     and sum(event["action"] == "READ" for event in row["events"]) <= 1
                     and sum(event["action"].startswith("REPAIR") for event in row["events"]) <= 1 for row in rows)
    paired = all(len({row["public_state_sha256"] for row in rows if row["task_id"] == case["id"]}) == 1
                 and len({row["private_fixture_sha256"] for row in rows if row["task_id"] == case["id"]}) == 1
                 for case in protocol["heldout_cases"])
    changed = [row["task_id"] + ":" + row["arm"] for row in rows
               if row["paid_read_changed_later_action"] and row["delivered"]]
    summaries = {arm: {"planned": len(protocol["heldout_cases"]), "observed": sum(row["arm"] == arm for row in rows),
                      "delivered": sum(row["delivered"] for row in rows if row["arm"] == arm),
                      "failed_or_unknown": sum(row["terminal"] in ("failed", "unknown") for row in rows if row["arm"] == arm),
                      "score_units": sum(row["score_units"] for row in rows if row["arm"] == arm),
                      "tariff_spent_units": sum(row["tariff_spent_units"] for row in rows if row["arm"] == arm),
                      "all_cell_wall_ns": sum(row["outer_cell_wall_ns"] for row in rows if row["arm"] == arm)} for arm in ARMS}
    ready = (sources_unchanged and accounting and paired and bool(changed)
             and len(rows) == len(protocol["heldout_cases"]) * len(ARMS))
    report = {"schema": "hepta.hia.paid-observation.result.v1", "status": "PASS_MECHANISM" if ready else "FAIL_MECHANISM",
              "protocol_sha256": hashlib.sha256(raw_protocol).hexdigest(), "runner_sha256": script_sha,
              "python": {"executable": sys.executable, "version": sys.version},
              "calibration": calibration, "calibration_wall_ns": calibration_wall, "fixed_fit": fit,
              "fixed_fit_wall_ns": fit_wall, "shared_calibration_cost_added_per_arm": False,
              "calibration_available_identically_to_all_controls": True, "fixed_fit_frozen_before_heldout": True,
              "rows": rows, "arm_summaries": summaries,
              "mechanism": {"paired_public_inputs_and_private_fixtures": paired, "paid_action_accounting": accounting,
                            "runner_and_protocol_unchanged_during_campaign": sources_unchanged,
                            "read_changed_delivered_action_cells": changed},
              "ndu": {"status": "NOT_RUN", "reason": "No trained/native NDU paid-information policy is assembled",
                      "policy_calls": 0, "incremental_benefit_established": False},
              "claims": protocol["claims"], "monetary_cost": None,
              "score_scope": "known synthetic reward minus actual dispatched synthetic tariffs; not wall-time or monetary benefit",
              "evidence_scope": "real child-process SQLite observations/effects with trusted-host fixture/evaluator separation",
              "outer_campaign_wall_ns": time.perf_counter_ns() - started,
              "campaign_wall_excludes": ["outer interpreter startup/imports", "final result encoding/write"],
              "limits": protocol["limits"]}
    (output / "RESULT.json").write_bytes(encoded(report) + b"\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", nargs=3, metavar=("DATABASE", "ACTION", "DELTA"))
    args = parser.parse_args()
    if args.worker:
        database, action, delta = args.worker
        print(json.dumps(worker(database, action, int(delta)), sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--output is required")
    report = run(args.output)
    print(json.dumps({"status": report["status"], "arms": report.get("arm_summaries"), "ndu": "NOT_RUN"}, sort_keys=True))
    return 0 if report["status"] == "PASS_MECHANISM" else 1


if __name__ == "__main__":
    raise SystemExit(main())
