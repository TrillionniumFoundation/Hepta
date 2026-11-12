"""Public catalogue coverage, untrusted edits, stale bindings and old defaults."""
import copy
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.hia_agent_structured_v7_20261029 import contracts, editing
from experiments.hia_agent_toolstudy_v8_20261029 import references
from experiments.hia_agent_toolstudy_v8_20261029.engine import ToolStudyEngine as OriginalEngine, response_schema as old_schema
from experiments.hia_agent_toolstudy_v11_20261030 import prompts, support as previous
from experiments.hia_agent_toolstudy_v12_20261030 import study, support
from experiments.hia_agent_toolstudy_v12_20261030.engine import ToolStudyEngine, response_schema
from experiments.hia_agent_toolstudy_v11_20261030.engine import ToolStudyEngine as PreviousEngine


class PublicNodeContractTests(unittest.TestCase):
    def queries(self):
        for stage in ("calibration", "main"):
            for task, arm in support.cells(stage):
                session = support.session_for(task, arm)
                yield task, arm, session, session.query()

    def test_all_public_editable_ids_and_fields_are_present_without_reference_selection(self):
        for task, arm, session, query in self.queries():
            with self.subTest(task=task["id"], arm=arm):
                schema = contracts.response_schema(query)
                item = schema["properties"]["edits"]["items"]
                variants = item.get("oneOf", [item])
                represented = {}
                for variant in variants:
                    properties = variant["properties"]
                    changes = properties["changes"]
                    options = changes.get("anyOf", [changes])
                    for ident in properties["node"]["enum"]:
                        self.assertNotIn(ident, represented)
                        represented[ident] = set(options[0]["properties"])
                        for option in options:
                            self.assertEqual(set(option["properties"]), represented[ident])
                expected = {n["id"]: set(n["fields"]) for n in query["edit_query"]["nodes"] if n["fields"]}
                self.assertEqual(represented, expected)
                self.assertFalse(contracts.binding(query)["answer_values_embedded"])
        for module in (contracts, __import__(ToolStudyEngine.__module__, fromlist=["_"])):
            source = inspect.getsource(module)
            self.assertNotIn("import references", source)
            self.assertNotIn('task[', source)
            self.assertNotIn('correct_', source.replace('correct_operations_or_values_embedded', ''))

    def test_all_19_reference_shapes_remain_representable_and_initial_prompts_unchanged(self):
        count = 0
        for task, arm, session, query in self.queries():
            language, interface = support.language_interface(arm)
            answer = (references.reference(session, query, task) if interface == "node"
                      else {"files": task["correct_" + language]})
            control = study.decoder_control(query, language, interface, answer)
            self.assertTrue(control["public_contract_reference_valid"])
            self.assertFalse(control["answer_used_for_decoder"])
            self.assertEqual(query, previous.session_for(task, arm).query())
            self.assertIs(study.prompts.prompt, prompts.prompt)
            count += 1
        self.assertEqual(count, 19)

    def test_readonly_ids_empty_changes_extra_fields_and_wrong_field_types_reject(self):
        task, arm = support.cells("calibration")[0]
        query = support.session_for(task, arm).query()
        schema = response_schema("rust", "node", query)
        nodes = query["edit_query"]["nodes"]
        ident = next(n["id"] for n in nodes if n["fields"])
        readonly = next(n["id"] for n in nodes if not n["fields"])
        for edits in ([], [{"node": ident, "changes": {}}],
                      [{"node": ident, "changes": {"text": "a", "node": ident}}],
                      [{"node": ident, "changes": {"text": 3}}],
                      [{"node": readonly, "changes": {"text": "u64"}}],
                      [{"node": "invented", "changes": {"text": "a"}}]):
            with self.subTest(edits=edits):
                self.assertFalse(study._accepts(schema, {"edits": edits}))

    def test_decoder_keeps_values_open_and_does_not_admit_duplicate_overlapping_or_whole_function_edits(self):
        task, arm = support.cells("calibration")[0]
        session = support.session_for(task, arm); query = session.query()
        ident = next(n["id"] for n in query["edit_query"]["nodes"] if n["fields"] and n["category"] == "expression")
        for text in ("a", "wrong_name", "pub fn invented() -> u64 { 0 }"):
            answer = {"edits": [{"node": ident, "changes": {"text": text}}]}
            self.assertTrue(study._accepts(response_schema("rust", "node", query), answer))
        duplicates = [{"node": ident, "changes": {"text": "a"}}] * 2
        inner = query["edit_query"]
        with self.assertRaisesRegex(editing.EditRejected, "duplicate node"):
            editing.checked_edits(inner, inner, editing.response_for(inner, duplicates))
        # Existing source parser, not decoder syntax, rejects a whole function.
        with self.assertRaises(ValueError):
            editing.propose_rust(session.files, inner,
                editing.response_for(inner, [{"node": ident, "changes": {"text": "pub fn invented()->u64 {0}"}}]),
                editable_symbols=inner["editable_symbols"])

    def test_diagnostic_reports_only_received_and_allowed_public_fields(self):
        task, arm = support.cells("calibration")[0]
        query = support.session_for(task, arm).query()["edit_query"]
        node = next(n for n in query["nodes"] if n["fields"])
        with self.assertRaises(editing.EditRejected) as caught:
            editing.checked_edits(query, query, editing.response_for(query,
                [{"node": node["id"], "changes": {"text": "DO_NOT_ECHO_REPLACEMENT", "node": "x"}}]))
        message = str(caught.exception)
        self.assertIn(node["id"], message)
        self.assertIn("allowed=['text']", message)
        self.assertIn("received=['node', 'text']", message)
        self.assertNotIn("DO_NOT_ECHO_REPLACEMENT", message)

    def test_stale_or_altered_query_and_language_mismatch_fail_before_generation(self):
        task, arm = support.cells("calibration")[0]
        query = support.session_for(task, arm).query()
        altered = copy.deepcopy(query); altered["edit_query"]["nodes"][0]["fields"] = ["text"]
        with self.assertRaisesRegex(ValueError, "QUERY_DIGEST"):
            contracts.response_schema(altered)
        with self.assertRaisesRegex(ValueError, "QUERY_LANGUAGE"):
            response_schema("hia", "node", query)
        engine = ToolStudyEngine.__new__(ToolStudyEngine)
        with self.assertRaisesRegex(ValueError, "CAPTURED_QUERY_REQUIRED"):
            engine.decoder_schema("rust", "node")

    def test_legacy_decoder_defaults_and_full_grammars_are_unchanged(self):
        old = OriginalEngine.__new__(OriginalEngine)
        for task, arm, session, query in self.queries():
            language, interface = support.language_interface(arm)
            self.assertEqual(old.decoder_schema(language, interface), old_schema(language, interface))
            with self.assertRaisesRegex(ValueError, "UNREGISTERED"):
                old.decoder_schema(language, interface, query)
            if interface == "full":
                self.assertEqual(response_schema(language, interface, query), old_schema(language, interface))

    def test_protocol_retains_model_generation_budgets_tasks_and_all_admission_requirements(self):
        new, old = support.protocol(), previous.protocol()
        for key in ("model", "runtime", "generation", "history", "budget", "arms", "tasks", "capacity_gate", "advantage_gate"):
            self.assertEqual(new[key], old[key])
        self.assertEqual(new["qualification"]["tasks"], old["qualification"]["tasks"])
        self.assertTrue(new["qualification"]["main_forbidden_without_qualification"])
        self.assertFalse(new["prospective_amendment"]["old_results_reclassified"])
        original = Path.read_text
        def changed(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if path == support.HERE / "PROTOCOL.json":
                item = json.loads(value); item["generation"]["attempts_per_cell"] = 4
                return json.dumps(item)
            return value
        with patch.object(Path, "read_text", changed), self.assertRaisesRegex(ValueError, "UNAUTHORIZED"):
            support.protocol()

    def test_decoder_metadata_write_failure_closes_started_owner_before_constructor_escapes(self):
        for failure in (OSError("disk full"), KeyboardInterrupt("cancelled")):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory:
                def initialized(owner, **_):
                    owner.process = object()
                    owner.identity = {}
                    owner.output = Path(directory)
                with patch.object(PreviousEngine, "__init__", initialized), patch.object(ToolStudyEngine, "close") as closed:
                    with patch.object(Path, "write_bytes", side_effect=failure), self.assertRaises(type(failure)):
                        ToolStudyEngine()
                    closed.assert_called_once()


if __name__ == "__main__":
    unittest.main()
