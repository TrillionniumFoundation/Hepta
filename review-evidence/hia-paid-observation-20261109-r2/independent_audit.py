#!/usr/bin/env python3
"""Read-only reconciliation of retained P5 evidence; no producer imports/runs."""
import hashlib
import json
from pathlib import Path
import sqlite3


ROOT = Path(__file__).resolve().parent
PUBLIC_FIELDS = {"p_a", "read_fee_units", "repair_fee_units", "remaining_units",
                 "reward_units", "failure_penalty_units", "observation"}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def inspect_database(path):
    # resolve() is required before as_uri(); no caller working-directory assumption.
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(items)")]
        assert columns in (["id", "counter_a"], ["id", "counter_b"], ["id", "invalid_counter"])
        mode = columns[1][-1] if columns[1] in ("counter_a", "counter_b") else "invalid"
        actual = [row[0] for row in connection.execute(f"SELECT {columns[1]} FROM items ORDER BY id")]
    return mode, actual


def main():
    raw_report = (ROOT / "RESULT.json").read_bytes()
    raw_protocol = (ROOT / "PROTOCOL.json").read_bytes()
    raw_source = (ROOT / "SOURCE.py").read_bytes()
    report, protocol = json.loads(raw_report), json.loads(raw_protocol)
    assert sha(raw_protocol) == report["protocol_sha256"]
    assert sha(raw_source) == report["runner_sha256"]
    assert report["schema"] == "hepta.hia.paid-observation.result.v1"
    assert report["claims"] == protocol["claims"]
    assert all(value is False for key, value in report["claims"].items() if key != "ndu_status")
    assert report["ndu"]["status"] == "NOT_RUN" and report["ndu"]["policy_calls"] == 0
    assert report["ndu"]["incremental_benefit_established"] is False
    assert report["monetary_cost"] is None

    calibration = report["calibration"]
    assert len(calibration) == protocol["shared_calibration_count"] == 8
    for index, row in enumerate(calibration):
        path = ROOT / "databases" / f"calibration-{index}.sqlite"
        mode, actual = inspect_database(path)
        assert sha(path.read_bytes()) == row["database_sha256"]
        assert mode == row["observed_mode"] and actual == [2, 5, 11]
        event = row["read"]
        assert event["action"] == "READ" and event["status"] == "completed" and event["returncode"] == 0
        assert json.loads(event["stdout"]) == event["response"]
        assert event["response"] == {"schema": "hepta.hia.paid-schema-observation.v1", "mode": mode}
        assert row["fee_units"] == row["public_state"]["read_fee_units"] == 1
    assert sha(encoded(calibration)) == report["fixed_fit"]["dataset_sha256"]
    fit_rows = []
    for threshold in protocol["fixed_read_fee_thresholds"]:
        for default in ("a", "b"):
            total = 0
            for row in calibration:
                state = row["public_state"]
                if state["remaining_units"] < state["repair_fee_units"]:
                    continue
                will_read = (state["read_fee_units"] <= threshold
                             and state["remaining_units"] >= state["read_fee_units"] + state["repair_fee_units"])
                success = will_read or default == row["observed_mode"]
                total += ((state["reward_units"] if success else -state["failure_penalty_units"])
                          - state["repair_fee_units"] - (state["read_fee_units"] if will_read else 0))
            fit_rows.append({"strategy": {"read_fee_threshold_units": threshold, "default_mode": default},
                             "calibration_score_units": total})
    assert fit_rows == report["fixed_fit"]["candidates"]
    chosen = min(fit_rows, key=lambda row: (-row["calibration_score_units"],
                 row["strategy"]["read_fee_threshold_units"], row["strategy"]["default_mode"]))
    assert chosen["strategy"] == report["fixed_fit"]["selected"]

    rows = report["rows"]
    assert len(rows) == len(protocol["heldout_cases"]) * len(protocol["arms"]) == 30
    changed, total_events = [], 0
    summaries = {arm: {"planned": len(protocol["heldout_cases"]), "observed": 0, "delivered": 0,
                       "failed_or_unknown": 0, "score_units": 0, "tariff_spent_units": 0,
                       "all_cell_wall_ns": 0} for arm in protocol["arms"]}
    for index, case in enumerate(protocol["heldout_cases"]):
        paired = [row for row in rows if row["task_id"] == case["id"]]
        assert sorted(row["arm"] for row in paired) == sorted(protocol["arms"])
        assert len({row["input_database_sha256"] for row in paired}) == 1
        assert len({row["private_fixture_sha256"] for row in paired}) == 1
        assert len({row["public_state_sha256"] for row in paired}) == 1
        for row in paired:
            path = ROOT / "databases" / f"holdout-{index}-{row['arm']}.sqlite"
            assert sha(path.read_bytes()) == row["final_database_sha256"]
            mode, actual = inspect_database(path)
            assert mode == row["evaluation"]["mode_released_after_terminal"]
            initial = [index, index + 3, index * 11 + 5]
            expected = [value + protocol["delta"] for value in initial]
            assert sha(encoded({"mode": mode, "initial": initial})) == row["private_fixture_sha256"]
            assert row["evaluation"]["expected"] == expected
            assert row["evaluation"]["actual"] == actual
            goal = mode in ("a", "b") and actual == expected
            assert row["evaluation"]["goal_observed"] == goal
            original = row["original_public_state"]
            assert set(original) == PUBLIC_FIELDS and original["observation"] is None
            assert original["p_a"] == case["p_a"]
            assert original["read_fee_units"] == case["read_fee_units"]
            assert original["remaining_units"] == case["budget_units"]
            assert sha(encoded(original)) == row["public_state_sha256"]
            remaining = case["budget_units"]
            observation = None
            assert len(row["events"]) <= len(row["decisions"]) <= 2
            for decision_index, decision in enumerate(row["decisions"]):
                state = decision["public_state"]
                assert set(state) == PUBLIC_FIELDS
                assert state == {**original, "remaining_units": remaining, "observation": observation}
                if decision_index == len(row["events"]):
                    assert decision["advice"]["action"] == "STOP" or row["terminal"] == "refused_budget"
                    continue
                event = row["events"][decision_index]
                assert decision["advice"]["action"] == event["action"]
                fee = case["read_fee_units"] if event["action"] == "READ" else protocol["repair_fee_units"]
                assert event["fee_units"] == fee
                remaining -= fee
                assert remaining >= 0 and event["remaining_units"] == remaining
                assert event["wall_ns"] >= 0 and decision["wall_ns"] >= 0
                if event["status"] == "completed":
                    assert event["returncode"] == 0 and json.loads(event["stdout"]) == event["response"]
                    if event["action"] == "READ":
                        assert event["response"] == {"schema": "hepta.hia.paid-schema-observation.v1", "mode": mode}
                        observation = mode
                    else:
                        assert event["response"] == {"schema": "hepta.hia.paid-repair-effect.v1", "rows_changed": 3}
                else:
                    assert event["status"] in ("failed", "unknown") and event["returncode"] != 0
                    assert decision_index == len(row["events"]) - 1
            events = row["events"]
            total_events += len(events)
            assert sum(event["action"] == "READ" for event in events) <= 1
            repairs = [event for event in events if event["action"].startswith("REPAIR")]
            assert len(repairs) <= 1
            if events and events[0]["action"] == "READ" and events[0]["status"] != "completed":
                assert len(events) == 1
            spent = sum(event["fee_units"] for event in events)
            assert row["tariff_spent_units"] == case["budget_units"] - remaining == spent
            within = row["outer_cell_wall_ns"] <= protocol["wall_budget_ns"] and spent <= case["budget_units"]
            assert within == row["within_original_budget"]
            delivered = goal and row["terminal"] == "effect_completed" and within
            assert delivered == row["delivered"]
            score = (protocol["reward_units"] if delivered else -protocol["failure_penalty_units"] if repairs else 0) - spent
            assert score == row["score_units"]
            change = bool(len(row["decisions"]) == 2 and events and events[0]["action"] == "READ"
                          and row["decisions"][1]["advice"]["action"] != row["decisions"][0]["advice"]["no_read_action"])
            assert change == row["paid_read_changed_later_action"]
            if change and delivered:
                changed.append(case["id"] + ":" + row["arm"])
            assert row["ndu_evaluations"] == 0 and row["nested_durations_added_again"] is False
            summary = summaries[row["arm"]]
            summary["observed"] += 1
            summary["delivered"] += delivered
            summary["failed_or_unknown"] += row["terminal"] in ("failed", "unknown")
            summary["score_units"] += score
            summary["tariff_spent_units"] += spent
            summary["all_cell_wall_ns"] += row["outer_cell_wall_ns"]
    assert summaries == report["arm_summaries"]
    assert changed == report["mechanism"]["read_changed_delivered_action_cells"]
    all_within = all(row["within_original_budget"] for row in rows)
    assert all_within == report["mechanism"]["all_cells_within_original_budget"]
    assert report["mechanism"]["paid_action_accounting"] is True
    assert report["mechanism"]["paired_public_inputs_and_private_fixtures"] is True
    assert report["status"] == "PASS_MECHANISM" and all_within and changed
    assert report["fixed_fit_frozen_before_heldout"] is True
    result = {"schema": "hepta.hia.paid-observation.independent-readonly-audit.v1", "status": "PASS",
              "result_sha256": sha(raw_report), "protocol_sha256": sha(raw_protocol), "runner_sha256": sha(raw_source),
              "auditor_sha256": sha(Path(__file__).read_bytes()), "calibration_databases_checked": len(calibration),
              "heldout_rows_and_databases_checked": len(rows), "raw_worker_events_checked": total_events,
              "paired_initial_database_hashes_checked": True, "retained_final_database_rows_checked": True,
              "calibration_fit_arithmetic_checked": True, "fees_and_budget_arithmetic_checked": True,
              "arm_summary_and_change_arithmetic_checked": True, "closed_public_state_fields_checked": True,
              "producer_imports": 0, "producer_executions": 0, "subprocess_invocations": 0,
              "claims": {"authenticated_timing": False, "independent_custody": False,
                         "adversarial_capability_isolation": False, "ndu_benefit_established": False},
              "scope": "Retained bytes, read-only SQLite inspection and independently recomputed arithmetic; original timing/provenance trusted"}
    (ROOT / "independent-audit.json").write_bytes(encoded(result) + b"\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
