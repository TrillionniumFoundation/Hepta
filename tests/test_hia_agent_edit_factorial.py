"""Factorial edit admission, matching information and complete denominators."""
import copy
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import json
import unittest
from experiments.hia_agent_assembly_v4_20261030 import fixtures
from tools import qualify_hia_agent_edit_factorial as campaign
from tools.qualify_hia_agent_edit_factorial import (ARMS, answer, digest, materialize,
                                             prompt, protocol, schedule, summarize)


class FactorialProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = fixtures.make_fixtures()

    def test_all_references_reach_identical_language_sources(self):
        for task in self.tasks:
            for language in ("assembly", "rust"):
                full = materialize(task, language, "full", answer(task, language, "full"))
                patch = materialize(task, language, "patch", answer(task, language, "patch"))
                self.assertEqual(full, patch)
                self.assertEqual(json.loads(full)["files"], task["correct_" + language])

    def test_public_information_is_identical_across_interfaces(self):
        for task in self.tasks:
            for language in ("assembly", "rust"):
                first = prompt(task, language, "full").split("\n", 2)[2]
                second = prompt(task, language, "patch").split("\n", 2)[2]
                self.assertEqual(first, second)
                self.assertEqual(first, fixtures.prompt(task, language).split("\n", 1)[1])

    def test_stale_source_denied_in_both_interfaces(self):
        for language, interface in ARMS:
            value = json.loads(answer(self.tasks[0], language, interface))
            value["expected_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "STALE_SOURCE"):
                materialize(self.tasks[0], language, interface, json.dumps(value))

    def test_patch_cannot_discover_paths_or_guess_missing_context(self):
        task = self.tasks[0]
        value = json.loads(answer(task, "rust", "patch"))
        for key, bad in (("path", "../hidden.rs"), ("old", ""), ("old", "absent source context")):
            changed = copy.deepcopy(value)
            changed["patches"][0][key] = bad
            with self.assertRaisesRegex(ValueError, "EXACT_EDIT"):
                materialize(task, "rust", "patch", json.dumps(changed))

    def test_patch_rejects_duplicate_ambiguous_context_and_budget(self):
        task = copy.deepcopy(self.tasks[0])
        name = next(iter(task["original_rust"]))
        task["original_rust"][name] = "aa aa"
        value = {"expected_sha256": digest(task["original_rust"]),
                 "patches": [{"path": name, "old": "aa", "new": "bb"}]}
        with self.assertRaisesRegex(ValueError, "EXACT_EDIT"):
            materialize(task, "rust", "patch", json.dumps(value))
        value["patches"] = []
        with self.assertRaisesRegex(ValueError, "PATCH_BUDGET"):
            materialize(task, "rust", "patch", json.dumps(value))

    def test_schedule_has_full_paired_grid(self):
        configuration = protocol()
        rows = schedule(configuration)
        self.assertEqual(len(rows), 32)
        self.assertEqual(len({r["id"] for r in rows}), 32)
        for model in configuration["models"]:
            for task in configuration["tasks"]:
                self.assertEqual({(r["language"], r["interface"]) for r in rows
                                  if r["model_id"] == model["id"] and r["task"] == task}, set(ARMS))

    def test_incomplete_evidence_cannot_be_success(self):
        registration = {"schedule": schedule(protocol()), "observed_preparation_wall_ns": 7}
        result = summarize(registration, [], 10, True)
        self.assertFalse(result["completed"])
        self.assertEqual(len(result["missing_cells"]), 32)
        self.assertFalse(result["stable_productivity_advantage"])
        self.assertTrue(all(a["cost_per_correct_ns"] is None for a in result["arms"]))
        self.assertTrue(all(not a["usage_complete"] for a in result["arms"]))
        self.assertTrue(all(a["total_input_tokens"] is None for a in result["arms"]))


class FactorialAccountingFaultTests(unittest.TestCase):
    """Fault fixtures never launch an inference server or a compiler."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="factorial-fault-tests-")
        self.root = Path(self.temp.name)
        self.task = fixtures.make_fixtures()[0]
        self.configuration = protocol()
        self.descriptor = schedule(self.configuration)[0]
        self.registration = {"source_bindings": {},
                             "tools": {"clang": {"path": "unused-clang"}, "rustc": {"path": "unused-rustc"}}}

    def tearDown(self):
        self.temp.cleanup()

    def engine(self, *, usage=True, error=None, known_input=11):
        task, descriptor = self.task, self.descriptor
        root = self.root / "engine"
        root.mkdir()
        counts = {"input_tokens": known_input, "output_tokens": 7, "total_tokens": known_input + 7} if usage else None

        class ReceiptEngine:
            output = root
            attempt_count = 0

            def generate(self, messages, **kwargs):
                self.attempt_count += 1
                receipt = {"schema": "hepta.gguf-attempt-observation.v1",
                           "attempt": self.attempt_count, "input_tokens": known_input,
                           "usage": counts, "status": "failed" if error else "completed"}
                (root / ("attempt-" + str(self.attempt_count).zfill(3) + ".json")).write_bytes(campaign.canonical(receipt))
                if error is not None:
                    raise error
                return {"usage": counts, "text": answer(task, descriptor["language"], descriptor["interface"])}
        return ReceiptEngine()

    def observe_cell(self, engine, *, built=None, executions=None, environment=None):
        with patch.object(campaign, "check_cell_environment", side_effect=environment), \
             patch.object(campaign.evaluator, "build", return_value=built) as build, \
             patch.object(campaign.evaluator, "execute", side_effect=executions) as execute:
            row, usable = campaign.cell(self.task, self.descriptor, self.root / "cell", engine,
                                        self.registration, self.configuration)
        saved = json.loads((self.root / "cell/CELL.json").read_text())
        self.assertEqual(saved, row)
        self.assertGreater(row["cell_wall_ns"], 0)
        return row, usable, build, execute

    def test_late_complete_response_keeps_known_usage_despite_timeout(self):
        row, usable, build, execute = self.observe_cell(self.engine(error=TimeoutError("late complete response")))
        self.assertFalse(usable)
        self.assertEqual(row["status"], "budget_timeout")
        self.assertIsNone(row["fatal_error"])
        self.assertEqual((row["known_input_tokens"], row["known_output_tokens"]), (11, 7))
        self.assertTrue(row["usage_complete"])
        self.assertEqual(row["attempts"][0]["usage"]["total_tokens"], 18)
        evidence = row["attempts"][0]["engine_attempt"]
        self.assertEqual(campaign.file_identity(evidence["file"]["path"]), evidence["file"])
        build.assert_not_called(); execute.assert_not_called()

    def test_known_input_and_unknown_output_are_not_both_zeroed(self):
        row, usable, _, _ = self.observe_cell(self.engine(usage=False, error=TimeoutError("no completion"), known_input=23))
        self.assertFalse(usable)
        self.assertEqual(row["known_input_tokens"], 23)
        self.assertEqual(row["known_output_tokens"], 0)  # known subtotal, not an asserted total
        self.assertEqual(row["total_input_tokens"], 23)
        self.assertIsNone(row["total_output_tokens"])
        self.assertFalse(row["usage_complete"])
        self.assertIsNone(row["attempts"][0]["output_tokens"])

    def test_infrastructure_failure_retains_cell_and_charges_its_arm(self):
        failed = {"status": "infrastructure_failure", "native_built": False, "error": "injected compiler timeout"}
        row, usable, _, execute = self.observe_cell(self.engine(), built=failed)
        self.assertFalse(usable)
        self.assertEqual(row["status"], "infrastructure_failure")
        self.assertFalse(row["correct"])
        self.assertIsNotNone(row["fatal_error"])
        self.assertEqual(row["attempts"][0]["build"], failed)
        execute.assert_not_called()
        registration = {"schedule": schedule(protocol()), "observed_preparation_wall_ns": 7}
        result = summarize(registration, [row], row["cell_wall_ns"] + 23, False)
        own = next(a for a in result["arms"] if (a["language"], a["interface"]) ==
                   (row["language"], row["interface"]))
        self.assertEqual(result["common_observed_runner_and_model_overhead_ns"], 23)
        self.assertEqual(own["observed_shared_cost_solo_allocation_ns"], row["cell_wall_ns"] + 30)
        self.assertEqual(own["requests"], 1)
        self.assertEqual(own["known_input_tokens"], 11)
        self.assertIsNone(own["total_input_tokens"])  # remaining seven cells are unobserved
        self.assertFalse(own["usage_complete"])
        self.assertEqual(result["expected_cells"], 32)
        self.assertEqual(len(result["missing_cells"]), 31)

    def test_hidden_exception_keeps_public_attempt_and_never_grants_success(self):
        built = {"status": "compiled", "native_built": True}
        public = {"status": "correct", "artifact_unchanged": True}
        row, usable, _, execute = self.observe_cell(
            self.engine(), built=built, executions=[public, RuntimeError("hidden infrastructure unavailable")])
        self.assertFalse(usable)
        self.assertFalse(row["correct"])
        self.assertEqual(row["status"], "infrastructure_failure")
        self.assertEqual(row["attempts"][0]["public"], public)
        self.assertEqual(row["known_output_tokens"], 7)
        self.assertEqual(execute.call_count, 2)
        self.assertTrue((self.root / "cell/attempt-0.json").is_file())

    def test_runtime_drift_after_generation_stops_before_hidden(self):
        built = {"status": "compiled", "native_built": True}
        public = {"status": "correct", "artifact_unchanged": True}
        row, usable, _, execute = self.observe_cell(
            self.engine(), built=built, executions=[public],
            environment=[None, RuntimeError("runtime drift"), None])
        self.assertFalse(usable)
        self.assertFalse(row["correct"])
        self.assertIn("runtime drift", row["fatal_error"]["message"])
        self.assertEqual(row["known_input_tokens"], 11)
        self.assertEqual(execute.call_count, 1)

    def test_runtime_inventory_rejects_library_change_addition_deletion_and_session_drift(self):
        binary, library = self.root / "server", self.root / "libllama.so"
        binary.write_bytes(b"fixed executable"); library.write_bytes(b"fixed library")
        frozen = campaign.runtime_inventory(binary)
        registration = {"tools": {"binary": campaign.file_identity(binary)},
                        "runtime_files": frozen, "models": {"m": {"path": "fixed-model"}}}
        campaign.validate_runtime(registration)
        for mutation in ("content", "addition", "deletion"):
            with self.subTest(mutation=mutation):
                library.write_bytes(b"fixed library")
                added = self.root / "libggml.so"
                if added.exists(): added.unlink()
                if mutation == "content": library.write_bytes(b"changed library")
                elif mutation == "addition": added.write_bytes(b"new library")
                else: library.unlink()
                with self.assertRaisesRegex(RuntimeError, "inventory drift"):
                    campaign.validate_runtime(registration)
        library.write_bytes(b"fixed library")
        fake = SimpleNamespace(runtime_identity=[], model_identity={"path": "fixed-model"})
        with self.assertRaisesRegex(RuntimeError, "session differs"):
            campaign.check_engine_registration(fake, registration, "m")

    @staticmethod
    def row(descriptor, *, fatal=False):
        return {**descriptor, "status": "infrastructure_failure" if fatal else "correct",
                "correct": not fatal, "attempts": [{"usage": {"input_tokens": 3, "output_tokens": 2}}],
                "cell_wall_ns": 1, "known_input_tokens": 3, "known_output_tokens": 2,
                "input_tokens_complete": True, "output_tokens_complete": True, "usage_complete": True,
                "fatal_error": {"stage": "cell", "type": "RuntimeError", "message": "injected cell failure"} if fatal else None}

    def run_fixture(self, *, final_fault=None, fatal_cell=False, suffix="run"):
        output = self.root / suffix
        output.mkdir()
        configuration = protocol()
        registration = {"schedule": schedule(configuration), "source_bindings": {},
                        "observed_preparation_wall_ns": 7, "source_commit": "frozen-source",
                        "source_tree": "frozen-tree", "tools": {"binary": {"path": "unused-server"}},
                        "models": {m["id"]: {"path": "unused-" + m["id"]} for m in configuration["models"]}}
        campaign.save(output / "REGISTRATION.json", registration)

        class CleanupEngine:
            process = SimpleNamespace(poll=lambda: 0)

            def __init__(self, fault=None): self.fault = fault
            def close(self):
                if self.fault == "close": raise RuntimeError("injected close failure")
            def verify_final_identity(self):
                if self.fault == "identity": raise OSError("injected final identity read failure")
                return {"model_unchanged": True, "runtime_unchanged": True}

        engines = [CleanupEngine(final_fault)] if fatal_cell else [CleanupEngine(), CleanupEngine(final_fault)]

        def observe(task, descriptor, *args):
            return self.row(descriptor, fatal=fatal_cell), not fatal_cell

        with patch.dict(os.environ, {"LLAMA_ARG_REPACK": "0"}), \
             patch.object(campaign, "validate", return_value=registration), \
             patch.object(campaign, "validate_runtime"), \
             patch.object(campaign, "check_engine_registration"), \
             patch.object(campaign.prior, "check_bindings", return_value=True), \
             patch.object(campaign, "LlamaCppEngine", side_effect=engines), \
             patch.object(campaign, "cell", side_effect=observe), redirect_stdout(io.StringIO()):
            result = campaign.run(output)
        self.assertEqual(json.loads((output / "RESULT.json").read_text()), result)
        return result

    def test_cleanup_exceptions_still_save_complete_denominator_result(self):
        for fault in ("close", "identity"):
            with self.subTest(fault=fault):
                result = self.run_fixture(final_fault=fault, suffix="run-" + fault)
                self.assertFalse(result["completed"])
                self.assertEqual(result["observed_cells"], 32)
                self.assertEqual(result["expected_cells"], 32)
                self.assertEqual(result["missing_cells"], [])
                self.assertTrue(result["session_cleanup"][-1]["errors"])
                self.assertEqual(result["errors"][0]["stage"], "cleanup")

    def test_partial_fatal_cell_is_appended_before_cleanup_failure(self):
        result = self.run_fixture(final_fault="close", fatal_cell=True)
        self.assertFalse(result["completed"])
        self.assertEqual(result["observed_cells"], 1)
        self.assertEqual(result["expected_cells"], 32)
        self.assertEqual(len(result["missing_cells"]), 31)
        self.assertEqual(result["cells"][0]["known_input_tokens"], 3)
        self.assertEqual([e["stage"] for e in result["errors"]], ["cell", "cleanup"])
        own = result["arms"][0]
        self.assertEqual(own["requests"], 1)
        self.assertEqual(own["known_output_tokens"], 2)


if __name__ == "__main__":
    unittest.main()
