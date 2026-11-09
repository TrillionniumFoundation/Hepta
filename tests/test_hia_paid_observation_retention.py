"""Real local-effect interruption controls, not an NDU value experiment."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("paid_retention", ROOT / "tools/qualify_hia_paid_observation.py")
pilot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot)


class PaidObservationRetentionTests(unittest.TestCase):
    def test_effect_completed_then_evaluator_failure_retains_db_and_prior_cells(self):
        original = pilot.evaluate
        count = 0
        injected = False
        def unavailable_once(*args):
            nonlocal count, injected
            count += 1
            evaluation = original(*args)
            if count == 2:
                self.assertTrue(evaluation["goal_observed"], "post-effect fault precondition was not reached")
                injected = True
                raise RuntimeError("injected post-effect evaluator unavailability")
            return evaluation
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "original"
            with patch.object(pilot, "evaluate", side_effect=unavailable_once):
                result = pilot.run(output)
            self.assertTrue(injected, "post-effect evaluator fault was not injected")
            self.assertEqual(result["status"], "FAILED_EXECUTION")
            self.assertEqual(len(result["rows"]), 1)
            self.assertTrue(result["rows"][0]["delivered"])
            self.assertEqual(len(list((output / "databases").glob("*.sqlite"))), 10)
            retained = pilot.inspect_retained(output)
            affected = next(x for x in retained["journals"] if x["journal"] == "holdout-0-voi.jsonl")
            self.assertEqual(affected["recorded_charged_fee_units"], 3)
            self.assertFalse(affected["completed_cell"])
            self.assertEqual(affected["unresolved_operation_ids"], [])
            self.assertEqual(result["incomplete_cell_goal_status"], "UNKNOWN")
            self.assertEqual(result["ndu"]["status"], "NOT_RUN")
            before = (output / "databases/holdout-0-voi.sqlite").read_bytes()
            with self.assertRaises(FileExistsError):
                pilot.run(output)
            with patch.object(pilot.subprocess, "run", side_effect=AssertionError("inspection dispatched")):
                self.assertEqual(pilot.inspect_retained(output), retained)
            self.assertEqual((output / "databases/holdout-0-voi.sqlite").read_bytes(), before)

    def test_lost_effect_ack_keeps_original_owner_and_pending_operation(self):
        original = pilot.invoke
        injected = False
        def lose_ack(database, action, delta, timeout):
            nonlocal injected
            response = original(database, action, delta, timeout)
            if action.startswith("REPAIR"):
                self.assertEqual(response["status"], "completed", "post-commit fault precondition was not reached")
                injected = True
                raise RuntimeError("injected missing acknowledgement after SQLite commit")
            return response
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "original"
            with patch.object(pilot, "invoke", side_effect=lose_ack):
                result = pilot.run(output)
            self.assertTrue(injected, "post-commit acknowledgement fault was not injected")
            self.assertEqual(result["status"], "FAILED_EXECUTION")
            self.assertEqual(result["rows"], [])
            inspected = pilot.inspect_retained(output)
            journal = next(x for x in inspected["journals"] if x["journal"] == "holdout-0-fixed.jsonl")
            self.assertEqual(journal["unresolved_operation_ids"], [journal["owner"] + "/step-1"])
            self.assertEqual(journal["recorded_charged_fee_units"], 3)
            self.assertFalse(journal["automatic_replay_allowed"])
            database = output / "databases/holdout-0-fixed.sqlite"
            with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True) as connection:
                column = connection.execute("PRAGMA table_info(items)").fetchall()[1][1]
                self.assertEqual([r[0] for r in connection.execute("SELECT " + column + " FROM items ORDER BY id")], [7, 10, 12])
            protocol = json.loads(pilot.PROTOCOL_PATH.read_bytes())
            with self.assertRaises(FileExistsError):
                pilot.run_cell(database, protocol["heldout_cases"][0], "a", [0, 3, 5], "fixed", protocol,
                               {"read_fee_threshold_units": 1, "default_mode": "a"},
                               journal_path=output / "journals/holdout-0-fixed.jsonl", owner=journal["owner"])

    def test_calibration_exception_preserves_all_original_databases_and_fee_intents(self):
        original = pilot.invoke
        count = 0
        def stop_second(*args):
            nonlocal count
            count += 1
            if count == 2:
                raise RuntimeError("injected calibration interruption")
            return original(*args)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "original"
            with patch.object(pilot, "invoke", side_effect=stop_second):
                result = pilot.run(output)
            self.assertEqual(result["status"], "FAILED_EXECUTION")
            self.assertEqual(len(result["calibration"]), 1)
            inspected = pilot.inspect_retained(output)
            self.assertEqual(len(inspected["databases"]), 2)
            second = next(j for j in inspected["journals"] if j["journal"] == "calibration-1.jsonl")
            self.assertEqual(second["recorded_charged_fee_units"], 1)
            self.assertEqual(second["unresolved_operation_ids"], [second["owner"] + "/step-0"])

    def test_source_binding_cannot_change_during_read_only_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "original"
            with patch.object(pilot, "invoke", side_effect=RuntimeError("stop before calibration")):
                pilot.run(output)
            (output / "SOURCE.py").write_bytes(b"different source")
            with self.assertRaisesRegex(ValueError, "owner/source/protocol"):
                pilot.inspect_retained(output)

    def test_durable_intent_exhausting_deadline_never_dispatches_worker(self):
        protocol = json.loads(pilot.PROTOCOL_PATH.read_bytes())
        case = {"id": "deadline", "p_a": [1, 2], "read_fee_units": 1, "budget_units": 12}
        strategy = {"read_fee_threshold_units": 1, "default_mode": "a"}
        elapsed = 0
        append = pilot.append_journal
        def delayed_intent(path, value):
            nonlocal elapsed
            append(path, value)
            if value["event"] == "action_intent":
                elapsed += protocol["wall_budget_ns"] + 1
        with tempfile.TemporaryDirectory() as temp:
            journal = Path(temp) / "deadline.jsonl"
            database = Path(temp) / "deadline.sqlite"
            with patch.object(pilot.time, "perf_counter_ns", side_effect=lambda: elapsed), \
                    patch.object(pilot, "append_journal", side_effect=delayed_intent), \
                    patch.object(pilot, "invoke", side_effect=AssertionError("worker dispatch attempted after original wall budget expired")) as dispatch:
                with self.assertRaisesRegex(TimeoutError, "E_PAID_DISPATCH_DEADLINE"):
                    pilot.run_cell(database, case, "a", [4, 8], "voi", protocol, strategy,
                                   journal_path=journal, owner="original-owner/deadline")
                dispatch.assert_not_called()
            records = [json.loads(line) for line in journal.read_text().splitlines()]
            intents = [row for row in records if row["event"] == "action_intent"]
            self.assertEqual(len(intents), 1)
            self.assertEqual(intents[0]["operation_id"], "original-owner/deadline/step-0")
            self.assertEqual(intents[0]["fee_units"], 1)
            self.assertEqual(intents[0]["effect_status"], "UNKNOWN")
            self.assertEqual(records[-1]["event"], "cell_interrupted")
            self.assertFalse(any(row["event"] == "action_result" for row in records))
            with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True) as connection:
                self.assertEqual(connection.execute("SELECT counter_a FROM items ORDER BY id").fetchall(), [(4,), (8,)])


if __name__ == "__main__":
    unittest.main()
