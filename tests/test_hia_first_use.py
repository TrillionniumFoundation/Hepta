"""First-use broker controls do not count a scripted solve as Agent evidence."""
from pathlib import Path
import tempfile
import unittest

from tools import qualify_hia_first_use as trial
from tools.hia_agent_native_qualification import Session, ToolClient, add_program, exhaustive_u8_workload


def task():
    return {"id": "fixture_maintenance", "instruction": "Preserve all u8 results while strictly reducing the native image.",
            "source": add_program(increment=23, redundant_additions=128, module="first_use_fixture"),
            "workload": exhaustive_u8_workload(increment=23),
            "provenance": {"kind": "scripted_test_fixture", "real_agent": False}}


class FirstUseTests(unittest.TestCase):
    def prepared(self, folder, **budget):
        root = Path(folder) / "trial"
        trial.prepare(root, "first_use_fixture", task(), **budget)
        return root

    def test_fresh_directory_original_public_input_and_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.prepared(folder, max_calls=1)
            with self.assertRaises(FileExistsError):
                trial.prepare(root, "first_use_fixture", task())
            result = trial.invoke(root, {"method": "tools/list"})
            self.assertEqual({t["name"] for t in result["response"]["tools"]}, trial.EXPECTED_TOOLS)
            self.assertFalse(result["response"]["formal_mcp_discovery"])
            with self.assertRaisesRegex(trial.TrialRejected, "call allowance"):
                trial.invoke(root, {"method": "tools/list"})
            self.assertEqual(len(trial.recorded_events(root)), 1)
            public = root / "public/task.json"
            public.write_bytes(public.read_bytes() + b"\n")
            with self.assertRaisesRegex(trial.TrialRejected, "public input changed"):
                trial.check_registration(root)

    def test_failed_namespaces_retained_and_pending_intent_never_replayed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.prepared(folder)
            result = trial.invoke(root, {"method": "tools/call", "params": {"name": "hia_artifact",
                "arguments": {"request_key": "another-trial/call"}}})
            self.assertEqual(result["status"], "failed")
            self.assertIn("registered campaign", result["failure"]["message"])
            self.assertIsNone(result["model_tokens"])
            before = len(trial.recorded_events(root))
            trial.put(root / "events/0001.intent.json", {"index": 1, "request": {"method": "tools/list"}})
            with self.assertRaisesRegex(trial.TrialRejected, "uncertain prior invocation"):
                trial.invoke(root, {"method": "tools/list"})
            self.assertFalse((root / "events/0001.outcome.json").exists())
            self.assertEqual(before, 1)

    def test_raw_requests_and_malformed_attempt_are_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.prepared(folder)
            original = b'{ "method" : "tools/list" }\n'
            result = trial.invoke(root, raw_request=original)
            self.assertEqual(result["status"], "returned")
            intent, _ = trial.recorded_events(root)[0]
            self.assertEqual((root / "objects" / intent["request_wire_sha256"]).read_bytes(), original)
            self.assertEqual(intent["request_origin"], "stdin_original")
            failed = trial.invoke(root, raw_request=b'{bad-json')
            self.assertEqual(failed["status"], "failed")
            self.assertIn("malformed request JSON", failed["failure"]["message"])
            self.assertEqual(len(trial.recorded_events(root)), 2)

    def test_actual_native_control_still_has_unknown_model_cost_and_hold(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.prepared(folder, max_calls=128, wall_seconds=120)
            trial.invoke(root, {"method": "tools/list"})
            client = ToolClient(lambda name, args: trial.invoke(root,
                {"method": "tools/call", "params": {"name": name, "arguments": args}})["response"])
            session = Session(client, prefix="first_use_fixture")
            registered = trial.read(root / "public/task.json")
            workload, objective = registered["workload"], registered["objective"]
            session.freeze(workload)
            baseline = session.import_program(registered["source"])
            session.freeze(workload, baseline=baseline, objective=objective)
            candidate = session.import_program(add_program(increment=23, optimized=True, module="first_use_fixture"))
            base_check = session.verify(baseline)
            check = session.verify(candidate, base=baseline, claims=["core_admission", "behavior_equivalence"])
            base_build = session.emit(baseline, receipts=[base_check["verification_receipt"]])
            build = session.emit(candidate, receipts=[check["verification_receipt"]])
            encoded = session.encoding(candidate, build)
            receipts = [check["verification_receipt"], encoded["verification_receipt"]]
            evaluation = session.evaluate(base_build, build, receipts=receipts)
            client.result("hia_adopt", session.arguments(target_slot="first_use_fixture",
                expected_current={"generation": "0", "epoch": "0"}, candidate_artifact=build["native_artifact"],
                evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts))
            judged = trial.judge(root)
            self.assertTrue(judged["task_success"], judged["failure"])
            self.assertEqual(judged["independent_native_cases"], 256)
            self.assertLess(judged["candidate_artifact_bytes"], judged["baseline_artifact_bytes"])
            self.assertEqual(judged["p1_acceptance"], "HOLD")
            self.assertIsNone(judged["model_tokens"])
            self.assertFalse(judged["fresh_agent_session_attested"])
            self.assertFalse(judged["full_cost_complete"])
            self.assertTrue(trial.verify(root)["original_tool_evidence_valid"])
            outcome_path = root / "events/0000.outcome.json"
            outcome = trial.read(outcome_path)
            outcome["response"]["formal_mcp_discovery"] = True
            outcome_path.write_bytes(trial.wire(outcome))
            with self.assertRaisesRegex(trial.TrialRejected, "original bytes changed"):
                trial.verify(root)
            with self.assertRaisesRegex(trial.TrialRejected, "already closed"):
                trial.invoke(root, {"method": "tools/list"})
            with self.assertRaisesRegex(trial.TrialRejected, "already exists"):
                trial.judge(root)

    def test_no_adoption_cannot_be_success(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.prepared(folder)
            judged = trial.judge(root)
            self.assertFalse(judged["task_success"])
            self.assertEqual(judged["p1_acceptance"], "HOLD")
            self.assertIn("catalog observation", judged["failure"]["message"])


if __name__ == "__main__":
    unittest.main()
