"""Task provenance and candidate-admission controls; no model success fixtures."""
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from benchmarks.hia_upstream_factorial import tasks, evaluator
from tools import qualify_hia_upstream_factorial as study
from tools.provider_adapter.llama_cpp_engine import canonical


class RetainedSourceBindingTests(unittest.TestCase):
    def test_current_and_frontier_bind_the_retained_sources_without_capture_frontend(self):
        from tools import qualify_hia_agent_frontier_factorial as frontier

        metadata = {name: (tasks.HERE / name).read_bytes()
                    for name in ('PROTOCOL.json', 'UPSTREAM_TASKS.json', 'UPSTREAM_FIX.json')}
        provenance = json.loads(metadata['UPSTREAM_TASKS.json'])
        required = {
            'benchmarks/hia_upstream_factorial/tasks.py',
            'benchmarks/hia_upstream_factorial/evaluator.py',
            'tools/qualify_hia_upstream_ports.py',
        }
        for version in provenance['versions'].values():
            for selected in version['selected'].values():
                source = tasks.HERE / selected['path']
                self.assertEqual(source.suffix, '.hepta')
                self.assertEqual(sha256(source.read_bytes()).hexdigest(), selected['sha256'])
                required.add(source.relative_to(study.ROOT).as_posix())
        for consumer in (study.source_bindings, frontier.bindings):
            binding = consumer()
            with self.subTest(consumer=consumer.__module__):
                self.assertNotIn('tools/capture_hia_upstream_tasks.py', binding)
                for name in required:
                    self.assertEqual(binding[name], sha256((study.ROOT / name).read_bytes()).hexdigest())
        for name, original in metadata.items():
            self.assertEqual((tasks.HERE / name).read_bytes(), original)

    def test_missing_selected_hia_source_cannot_disappear_from_a_glob_inventory(self):
        with tempfile.TemporaryDirectory(prefix='hia-upstream-source-') as temporary:
            captured = Path(temporary) / 'fixtures'
            shutil.copytree(tasks.HERE, captured)
            missing = captured / 'floor_reference.hepta'
            missing.unlink()
            with patch.object(tasks, 'HERE', captured), self.assertRaises(FileNotFoundError) as caught:
                study.source_bindings()
            self.assertEqual(caught.exception.filename, str(missing))

    def test_changed_selected_hia_source_is_refused_against_retained_provenance(self):
        with tempfile.TemporaryDirectory(prefix='hia-upstream-source-') as temporary:
            captured = Path(temporary) / 'fixtures'
            shutil.copytree(tasks.HERE, captured)
            changed = captured / 'c_stb_mod_eucl-after.hepta'
            changed.write_bytes(changed.read_bytes() + b'\n')
            with patch.object(tasks, 'HERE', captured), self.assertRaisesRegex(
                    ValueError, 'captured upstream fixture changed'):
                study.source_bindings()


class UpstreamFactorialTests(unittest.TestCase):
    def test_fixed_real_origin_and_independent_mathematical_oracle(self):
        fixtures = tasks.make_fixtures()
        self.assertEqual([t["id"] for t in fixtures], study.protocol()["tasks"])
        self.assertEqual(len(study.schedule(study.protocol())), 16)
        for task in fixtures:
            self.assertEqual(task["provenance"]["fix_commit"], "c38ec91d229cbe56167f8af865c05b3d92db705f")
            self.assertFalse(task["provenance"]["whole_upstream_repository_maintenance"])
            self.assertGreater(len(task["hidden_cases"]), 400)
            for args, value in zip(task["hidden_cases"], task["hidden_expected"]):
                a, b = args
                if task["id"] == "stb_floor_overflow":
                    # Independent floor interval, including negative divisor.
                    if b > 0:
                        self.assertLessEqual(value * b, a)
                        self.assertGreater((value + 1) * b, a)
                    else:
                        self.assertGreaterEqual(value * b, a)
                        self.assertLess((value + 1) * b, a)
                else:
                    self.assertGreaterEqual(value, 0)
                    self.assertLess(value, abs(b))
                    self.assertEqual((a - value) % b, 0)

    def test_full_patch_same_reference_stale_or_ambiguous_edits_refused(self):
        for task in tasks.make_fixtures():
            for language in ("assembly", "rust"):
                full = study.materialize(task, language, "full", study.answer(task, language, "full"))
                patch = study.materialize(task, language, "patch", study.answer(task, language, "patch"))
                self.assertEqual(full, patch)
                evaluator.parse(task, language, full)
                source = task["original_" + language]
                bad = {"expected_sha256": "0"*64, "files": source}
                with self.assertRaisesRegex(ValueError, "STALE"):
                    study.materialize(task, language, "full", canonical(bad).decode())
                bad = {"expected_sha256": study.digest(source), "patches": [
                    {"path": next(iter(source)), "old": "", "new": ""}]}
                with self.assertRaisesRegex(ValueError, "EXACT_EDIT"):
                    study.materialize(task, language, "patch", canonical(bad).decode())

    def test_rust_public_subset_refuses_external_capabilities_and_recursion(self):
        for source in (tasks.OLD_FLOOR, tasks.NEW_FLOOR, tasks.OLD_MOD, tasks.NEW_MOD):
            evaluator.admit_rust(source)
        for body in ("std::process::exit(0)", "unsafe {a}", 'println!("x"); a',
                     "target(a,b)", "(target)(a,b)", "(|x|x)(a)", "(drop)(a); b",
                     "let x=[0; 999999999]; x[0]", "loop { }", "a.to_string().len() as i32",
                     "((a as f64)/(b as f64)) as i32", "1.5 as i32", "1e3 as i32",
                     "1_f32 as i32", "1. as i32"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                evaluator.admit_rust("pub fn target(a:i32,b:i32)->i32 {" + body + "}")

    def test_hia_candidate_cannot_add_effects_or_change_export(self):
        task = tasks.make_fixtures()[1]
        source = task["correct_assembly"]["target.hepta"]
        for changed in (source.replace("exports(target)", "exports()"),
                        source.replace("effects(trap)", "effects(alloc,trap)")):
            with self.assertRaises(ValueError):
                evaluator.parse(task, "assembly", canonical({"files": {"target.hepta": changed}}).decode())

    def test_actual_owned_context_is_checked_independently_of_requested_argv(self):
        expected = {"runtime_files": [], "models": {"m": {}}, "context_tokens": 32768, "threads": 4}
        properties = {"default_generation_settings": {"n_ctx": 32768}, "total_slots": 1}
        engine = SimpleNamespace(runtime_identity=[], model_identity={}, context=32768,
                                 identity={"properties": properties, "threads": 4})
        study.check_engine_registration(engine, expected, "m")
        for wrong in (8192, True, 32768.0, None):
            properties["default_generation_settings"]["n_ctx"] = wrong
            with self.assertRaisesRegex(RuntimeError, "actual owned server"):
                study.check_engine_registration(engine, expected, "m")
        properties["default_generation_settings"]["n_ctx"] = 32768
        properties["total_slots"] = 2
        with self.assertRaisesRegex(RuntimeError, "actual owned server"):
            study.check_engine_registration(engine, expected, "m")


class PublicEditFeedbackTests(unittest.TestCase):
    def rejected(self, task, language, interface, answer):
        text = canonical(answer).decode()
        with self.assertRaises(ValueError) as rejected:
            study.materialize(task, language, interface, text)
        feedback = study.edit_contract_feedback(task, language, interface, text, rejected.exception)
        self.assertEqual(feedback["edit_rejected"], str(rejected.exception))
        return feedback["details"]

    def test_file_names_and_value_types_are_public_and_symmetric(self):
        for language, name in (("assembly", "target.hepta"), ("rust", "target.rs")):
            # No oracle, expected results or hidden-case fields are available.
            original = {name: "PUBLIC SOURCE\n"}
            task = {"original_" + language: original}
            details = self.rejected(task, language, "full", {
                "expected_sha256": study.digest(original), "files": {"wrong.name": "PUBLIC SOURCE\n"}})
            self.assertEqual(details["expected_files"], [name])
            self.assertEqual(details["received_files"], ["wrong.name"])
            self.assertEqual(details["base_sha256"], study.digest(original))
            details = self.rejected(task, language, "full", {
                "expected_sha256": study.digest(original), "files": {name: {"nested": "not source text"}}})
            self.assertEqual(details["received_value_types"], [{"path": name, "type": "dict"}])
            self.assertNotIn("PUBLIC SOURCE", canonical(details).decode())
            self.assertNotIn("not source text", canonical(details).decode())

    def test_patch_counts_use_each_ordered_step_and_reset_to_original(self):
        for language, name in (("assembly", "target.hepta"), ("rust", "target.rs")):
            original = {name: "one two"}
            task = {"original_" + language: original}
            answer = {"expected_sha256": study.digest(original), "patches": [
                {"path": name, "old": "one", "new": "two"},
                {"path": name, "old": "two", "new": "three"}]}
            details = self.rejected(task, language, "patch", answer)
            self.assertEqual(details["patch_index"], 1)
            self.assertEqual(details["old_occurrences"], 2)
            self.assertEqual(task["original_" + language], {name: "one two"})
            answer["patches"] = [{"path": name, "old": "previous answer only", "new": "replacement"}]
            self.assertEqual(self.rejected(task, language, "patch", answer)["old_occurrences"], 0)
            answer["patches"][0]["path"] = "module.header"
            details = self.rejected(task, language, "patch", answer)
            self.assertEqual(details["path"], "module.header")
            self.assertIsNone(details["old_occurrences"])

    def test_diagnostics_are_bounded_and_never_echo_file_contents(self):
        original = {"target.rs": "public original"}
        task = {"original_rust": original}
        files = {str(i) + "x" * 200: "source content is not a diagnostic" for i in range(64)}
        details = self.rejected(task, "rust", "full", {
            "expected_sha256": study.digest(original), "files": files})
        self.assertEqual(details["received_file_count"], 64)
        self.assertEqual(len(details["received_files"]), 8)
        self.assertTrue(all(len(name) <= 120 for name in details["received_files"]))
        self.assertNotIn("source content is not a diagnostic", canonical(details).decode())

    def test_non_contract_decoder_errors_keep_the_original_public_message(self):
        feedback = study.edit_contract_feedback({}, "rust", "full", "{", ValueError("E_JSON_SYNTAX"))
        self.assertEqual(feedback, {"edit_rejected": "E_JSON_SYNTAX"})
        feedback = study.edit_contract_feedback({}, "rust", "full", "x" * 65537,
                                                ValueError("E_FACTORIAL_RESPONSE_BOUND"))
        self.assertEqual(feedback, {"edit_rejected": "E_FACTORIAL_RESPONSE_BOUND"})


if __name__ == "__main__":
    unittest.main()
