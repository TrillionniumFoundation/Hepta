"""External model delivery never supplies its own native correctness label."""
from pathlib import Path
import json
import tempfile
from unittest import TestCase
from unittest.mock import patch

from tools import qualify_hia_agent_frontier_factorial as study


class FrontierFactorialTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.record = {"schedule": study.base.schedule(study.PROTOCOL), "source": {},
                       "protocol": study.PROTOCOL,
                       "tools": {"clang": {"path": "fixture"}, "rustc": {"path": "fixture"}},
                       "preparation_wall_ns": 1}
        (self.root / "REGISTRATION.json").write_text(json.dumps(self.record))
        for i in range(16):
            (self.root / f"cell-{i:02d}").mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_full_factorial_denominator_and_unknown_costs_are_retained(self):
        with patch.object(study, "validate", return_value=self.record):
            result = study.summarize(self.root)
        self.assertEqual((result["planned_cells"], result["observed_cells"]), (16, 0))
        self.assertEqual(len(result["missing_cells"]), 16)
        self.assertFalse(result["complete"])
        for arm in result["arms"]:
            self.assertEqual(arm["planned"], 4)
            self.assertIsNone(arm["token_usage"])
            self.assertFalse(arm["total_cost_advantage_proved"])

    def test_begin_is_ordered_and_cannot_be_repeated(self):
        with patch.object(study, "validate", return_value=self.record):
            with self.assertRaisesRegex(ValueError, "previous scheduled"):
                study.begin(self.root, 1)
            study.begin(self.root, 0)
            with self.assertRaises(FileExistsError):
                study.begin(self.root, 0)

    def test_upstream_cohort_keeps_its_own_tasks_and_full_denominator(self):
        self.record.update(protocol=study.UPSTREAM_PROTOCOL,
                           schedule=study.upstream.schedule(study.UPSTREAM_PROTOCOL))
        with patch.object(study, "validate", return_value=self.record):
            result = study.summarize(self.root)
        self.assertEqual(result["planned_cells"], 8)
        self.assertEqual(len(result["missing_cells"]), 8)
        self.assertTrue(all(arm["planned"] == 2 for arm in result["arms"]))
        self.assertFalse(result["population_productivity_proved"])
        task = study.upstream.fixtures.make_fixtures()[0]
        response = json.loads(study.upstream.answer(task, "assembly", "full"))
        response["expected_sha256"] = "0" * 64
        with patch.object(study, "validate", return_value=self.record), patch.object(
                study.upstream.evaluator, "build") as build:
            study.begin(self.root, 0)
            (self.root / "cell-00/RESPONSE.json").write_text(json.dumps(response))
            row = study.evaluate(self.root, 0)
        self.assertFalse(row["correct"])
        self.assertIn("STALE_SOURCE", row["error"]["message"])
        build.assert_not_called()

    def test_cohort_cannot_be_replaced_or_relabelled(self):
        for changed in ({**study.PROTOCOL, "cohort": "upstream"},
                        {**study.PROTOCOL, "attempts_per_cell": True}):
            with self.assertRaisesRegex(ValueError, "unregistered"):
                study.cohort(changed)

    def test_stale_response_rejects_without_compile_or_second_scoring(self):
        task = study.base.fixtures.make_fixtures()[0]
        response = json.loads(study.base.answer(task, "assembly", "full"))
        response["expected_sha256"] = "0" * 64
        with patch.object(study, "validate", return_value=self.record), patch.object(study.base.evaluator, "build") as build:
            study.begin(self.root, 0)
            (self.root / "cell-00/RESPONSE.json").write_text(json.dumps(response))
            result = study.evaluate(self.root, 0)
            self.assertFalse(result["correct"])
            self.assertIn("STALE_SOURCE", result["error"]["message"])
            build.assert_not_called()
            with self.assertRaises(FileExistsError):
                study.evaluate(self.root, 0)

    def test_hidden_scoring_is_terminal_and_follows_public_acceptance(self):
        task = study.base.fixtures.make_fixtures()[0]
        response = study.base.answer(task, "assembly", "full")
        with patch.object(study, "validate", return_value=self.record), patch.object(
                study.base.evaluator, "build", return_value={"native_built": True, "status": "compiled"}), patch.object(
                study.base.evaluator, "execute", side_effect=[
                    {"status": "correct", "artifact_unchanged": True},
                    {"status": "observable_wrong", "artifact_unchanged": True}]) as execute:
            study.begin(self.root, 0)
            (self.root / "cell-00/RESPONSE.json").write_text(response)
            result = study.evaluate(self.root, 0)
            self.assertEqual(execute.call_count, 2)
            self.assertFalse(result["correct"])
            self.assertEqual(result["status"], "hidden_wrong")
            self.assertIsNone(result["token_usage"])
            with self.assertRaises(FileExistsError):
                study.evaluate(self.root, 0)

    def test_result_cannot_move_to_a_different_arm(self):
        row = {**self.record["schedule"][0], "language": "rust"}
        (self.root / "cell-00/CELL.json").write_text(json.dumps(row))
        with patch.object(study, "validate", return_value=self.record):
            with self.assertRaisesRegex(ValueError, "result identity"):
                study.summarize(self.root)

    def test_final_source_failure_cannot_retain_prior_hidden_success(self):
        task = study.base.fixtures.make_fixtures()[0]
        with patch.object(study, "validate", return_value=self.record):
            study.begin(self.root, 0)
        (self.root / "cell-00/RESPONSE.json").write_text(study.base.answer(task, "assembly", "full"))
        with patch.object(study, "validate", side_effect=[self.record, ValueError("source drift")]), patch.object(
                study.base.evaluator, "build", return_value={"native_built": True, "status": "compiled"}), patch.object(
                study.base.evaluator, "execute", return_value={"status": "correct", "artifact_unchanged": True}):
            result = study.evaluate(self.root, 0)
        self.assertFalse(result["correct"])
        self.assertEqual(result["status"], "rejected_or_infrastructure_failure")
        with patch.object(study, "validate", return_value=self.record):
            summary = study.summarize(self.root)
        self.assertEqual(sum(arm["correct"] for arm in summary["arms"]), 0)

    def test_rejected_terminal_cannot_be_counted_as_correct(self):
        row = {**self.record["schedule"][0], "correct": True, "status": "rejected_or_infrastructure_failure"}
        (self.root / "cell-00/CELL.json").write_text(json.dumps(row))
        with patch.object(study, "validate", return_value=self.record):
            with self.assertRaisesRegex(ValueError, "terminal native evidence"):
                study.summarize(self.root)
