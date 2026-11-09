"""Decision-value and actual subprocess boundaries of the separate P5 pilot."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("paid_observation", ROOT / "tools/qualify_hia_paid_observation.py")
pilot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot)


class PaidObservationTests(unittest.TestCase):
    def setUp(self):
        self.protocol = json.loads(pilot.PROTOCOL_PATH.read_bytes())
        self.case = {"id": "case", "p_a": [1, 2], "read_fee_units": 1, "budget_units": 12}
        self.strategy = {"read_fee_threshold_units": 1, "default_mode": "a"}

    def test_voi_matches_independent_complete_tree_including_budget_and_stop(self):
        for numerator in range(5):
            for read_fee in range(1, 4):
                for budget in range(7):
                    for reward in (0, 2, 10):
                        for penalty in (0, 2):
                            state = {"p_a": [numerator, 4], "read_fee_units": read_fee,
                                     "repair_fee_units": 2, "remaining_units": budget,
                                     "reward_units": reward, "failure_penalty_units": penalty,
                                     "observation": None}
                            self.assertEqual(pilot.voi_plan(state), pilot.mpc_plan(state))

    def test_expensive_or_unaffordable_information_is_not_free(self):
        state = pilot.public_state(self.case, self.protocol)
        self.assertEqual(pilot.voi_plan(state)["action"], "READ")
        self.assertEqual(pilot.voi_plan({**state, "read_fee_units": 8})["action"], "REPAIR_A")
        self.assertEqual(pilot.voi_plan({**state, "remaining_units": 1})["action"], "STOP")
        with self.assertRaises(ValueError):
            pilot.voi_plan({**state, "private_mode": "b"})
        with self.assertRaises(ValueError):
            pilot.voi_plan({**state, "read_fee_units": 0})

    def test_actual_paid_schema_read_changes_real_effect_without_label_input(self):
        with tempfile.TemporaryDirectory() as directory:
            a = pilot.run_cell(Path(directory) / "a.sqlite", self.case, "a", [1, 4, 9],
                               "voi", self.protocol, self.strategy)
            b = pilot.run_cell(Path(directory) / "b.sqlite", self.case, "b", [1, 4, 9],
                               "voi", self.protocol, self.strategy)
        self.assertEqual(a["public_state_sha256"], b["public_state_sha256"])
        self.assertEqual([row["action"] for row in a["events"]], ["READ", "REPAIR_A"])
        self.assertEqual([row["action"] for row in b["events"]], ["READ", "REPAIR_B"])
        self.assertTrue(a["delivered"] and b["delivered"])
        self.assertTrue(b["paid_read_changed_later_action"])
        self.assertEqual(b["tariff_spent_units"], 3)
        self.assertEqual(b["evaluation"]["actual"], [8, 11, 16])
        self.assertEqual(b["ndu_evaluations"], 0)

    def test_failed_read_is_charged_and_does_not_authorize_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            row = pilot.run_cell(Path(directory) / "invalid.sqlite", self.case, "invalid", [1, 2],
                                 "mpc", self.protocol, self.strategy)
        self.assertEqual(row["terminal"], "failed")
        self.assertEqual(len(row["events"]), 1)
        self.assertEqual(row["events"][0]["action"], "READ")
        self.assertEqual(row["events"][0]["fee_units"], 1)
        self.assertNotEqual(row["events"][0]["returncode"], 0)
        self.assertFalse(row["delivered"])
        self.assertEqual(row["evaluation"]["actual"], [1, 2])

    def test_wrong_repair_failure_and_exhausted_budget_stay_in_results(self):
        with tempfile.TemporaryDirectory() as directory:
            case = {**self.case, "read_fee_units": 8}
            wrong = pilot.run_cell(Path(directory) / "wrong.sqlite", case, "b", [1, 2],
                                   "fixed", self.protocol, self.strategy)
            stopped = pilot.run_cell(Path(directory) / "stopped.sqlite", {**case, "budget_units": 1},
                                     "b", [1, 2], "voi", self.protocol, self.strategy)
        self.assertEqual(wrong["terminal"], "failed")
        self.assertEqual(wrong["tariff_spent_units"], 2)
        self.assertEqual(wrong["score_units"], -4)
        self.assertFalse(wrong["delivered"])
        self.assertEqual(stopped["events"], [])
        self.assertEqual(stopped["tariff_spent_units"], 0)

    def test_timed_out_observation_remains_unknown_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "timeout.sqlite"
            pilot.fixture(database, "a", [3])
            record = pilot.invoke(database, "READ", 7, 0)
        self.assertEqual(record["status"], "unknown")
        self.assertEqual(record["reason"], "timeout_no_retry")

    def test_full_registered_matrix_keeps_failure_control_and_ndu_not_run(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new-evidence"
            result = pilot.run(output)
            retained = json.loads((output / "RESULT.json").read_bytes())
            self.assertEqual(retained, result)
            self.assertEqual((output / "PROTOCOL.json").read_bytes(), pilot.PROTOCOL_PATH.read_bytes())
            with self.assertRaises(FileExistsError):
                pilot.run(output)
        self.assertEqual(result["status"], "PASS_MECHANISM")
        self.assertEqual(len(result["rows"]), 30)
        fault_rows = [row for row in result["rows"] if row["task_id"] == "read-failure-control"]
        self.assertEqual(len(fault_rows), 3)
        self.assertTrue(all(row["terminal"] == "failed" for row in fault_rows))
        self.assertEqual(result["ndu"]["status"], "NOT_RUN")
        self.assertFalse(result["claims"]["economic_benefit_established"])
        self.assertFalse(result["claims"]["incremental_ndu_benefit_established"])


if __name__ == "__main__":
    unittest.main()
