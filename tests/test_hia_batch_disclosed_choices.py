"""Public batch-study choices must match the unchanged closed candidate parser.

These are prompt/contract checks, not model or native execution results.
"""
import copy
import hashlib
import itertools
import json
from pathlib import Path
import unittest

from tools import qualify_hia_batch_study as study


CHOICE_HEADER = "Allowed replacements (closed set):\n"
CHOICE_INSTRUCTION = (
    "For each site, select one exact JSON value from allowed_values for changes[field]. "
    "Preserve its JSON type and structure; other values are rejected."
)
FROZEN_FIXTURES_SHA256 = "078b0f8f8766bdf2bd7d993a7f354d4e6c92661174806fe0b7e8d80361ca0583"
FROZEN_MODEL_LOCK_SHA256 = "3b50a0c25ac2a0f8c9ac7ef8cdfbddff37ed534524babb8b6d120c222d3b2be3"
COUNTS = {"capacity_roundup": [6, 3], "tagged_octet": [3, 3],
          "epoch_delta": [3, 3], "weighted_minimum": [8, 6]}


class DisclosedBatchChoiceTests(unittest.TestCase):
    def choices(self, text):
        self.assertEqual(text.count(CHOICE_HEADER), 1, "exact candidate inventory must be public")
        self.assertIn(CHOICE_INSTRUCTION, text)
        value, end = json.JSONDecoder().raw_decode(text.split(CHOICE_HEADER, 1)[1])
        self.assertTrue(text.split(CHOICE_HEADER, 1)[1][end:].startswith("\nContext:\n"))
        self.assertIs(type(value), list)
        self.assertEqual(len(value), 2)
        return value

    def test_all_sixteen_prompts_disclose_exact_typed_parser_choices(self):
        checked = 0
        for task in study.fixtures():
            for arm in study.ARMS:
                with self.subTest(task=task["id"], arm=arm):
                    entries = self.choices(study.prompt(task, arm))
                    hia = arm.startswith("hia")
                    self.assertEqual([len(entry["allowed_values"]) for entry in entries], COUNTS[task["id"]])
                    for index, (entry, part) in enumerate(zip(entries, task["parts"])):
                        self.assertEqual(set(entry), {"site", "field", "allowed_values"})
                        self.assertIs(type(entry["site"]), int)
                        self.assertEqual(entry["site"], index)
                        self.assertEqual(entry["field"], part["field"] if hia else "replacement")
                        wanted = part["allowed"] if hia else part["rust_allowed"]
                        # Canonical bytes preserve bool/int/float/string/object distinctions.
                        self.assertEqual([study.canonical(value) for value in entry["allowed_values"]],
                                         sorted(study.canonical(value) for value in wanted))
                    checked += 1
        self.assertEqual(checked, 16)

    def test_object_values_numeric_strings_and_embedded_quotes_remain_exact(self):
        tasks = {task["id"]: task for task in study.fixtures()}
        for suffix in ("full_context", "edit_query"):
            hia = self.choices(study.prompt(tasks["weighted_minimum"], "hia_" + suffix))
            rust = self.choices(study.prompt(tasks["weighted_minimum"], "rust_" + suffix))
            self.assertEqual(hia[0]["field"], "attrs")
            self.assertTrue(all(type(value) is dict and set(value) == {"value"}
                                and type(value["value"]) is int for value in hia[0]["allowed_values"]))
            self.assertEqual(rust[0]["allowed_values"], [str(value) for value in range(8)])
            epoch = self.choices(study.prompt(tasks["epoch_delta"], "rust_" + suffix))
            self.assertIn('x.checked_add(1).expect("overflow")', epoch[1]["allowed_values"])

    def test_full_and_query_share_order_independent_of_inventory_order_without_mutation(self):
        for task in study.fixtures():
            before = study.canonical(task)
            for language in ("hia", "rust"):
                full = study.prompt(task, language + "_full_context")
                query = study.prompt(task, language + "_edit_query")
                self.assertEqual(study.canonical(self.choices(full)), study.canonical(self.choices(query)))
                reordered = copy.deepcopy(task)
                for part in reordered["parts"]:
                    part["allowed"].reverse()
                    part["rust_allowed"].reverse()
                self.assertEqual(full, study.prompt(reordered, language + "_full_context"))
                self.assertEqual(query, study.prompt(reordered, language + "_edit_query"))
            self.assertEqual(study.canonical(task), before)

    def test_oracle_labels_cases_and_expected_values_do_not_affect_prompts(self):
        for task in study.fixtures():
            hidden = copy.deepcopy(task)
            hidden["cases"] = [["PRIVATE_CASE_SENTINEL"]]
            hidden["expected"] = ["PRIVATE_EXPECTED_SENTINEL"]
            for part in hidden["parts"]:
                part["good"] = {"PRIVATE_GOLD_LABEL": True}
                part["rust_good"] = "PRIVATE_RUST_GOLD_LABEL"
                part["cases"] = [["PRIVATE_HELPER_CASE_SENTINEL"]]
            for arm in study.ARMS:
                with self.subTest(task=task["id"], arm=arm):
                    text = study.prompt(task, arm)
                    self.choices(text)
                    self.assertEqual(text, study.prompt(hidden, arm))
                    self.assertNotIn(study.canonical(task["cases"]).decode(), text)
                    self.assertNotIn(study.canonical(task["expected"]).decode(), text)
                    language = "hia" if arm.startswith("hia") else "rust"
                    self.assertTrue(text.endswith(study.canonical(study.response_for(task, language, 0)).decode()))

    def test_every_disclosed_candidate_pair_is_admitted_by_the_existing_parser(self):
        admitted = 0
        for task in study.fixtures():
            for arm in study.ARMS:
                entries = self.choices(study.prompt(task, arm))
                for values in itertools.product(*(entry["allowed_values"] for entry in entries)):
                    response = {"edits": [
                        {"site": entry["site"], "changes": {entry["field"]: value}}
                        for entry, value in zip(entries, values)]}
                    with self.subTest(task=task["id"], arm=arm, values=values):
                        study.parse_response(task, arm, study.canonical(response).decode())
                    admitted += 1
        self.assertEqual(admitted, 336)  # (18 + 9 + 9 + 48) pairs times all four arms.

    def test_disclosure_does_not_broaden_or_coerce_the_closed_parser(self):
        for task in study.fixtures():
            for arm in study.ARMS:
                language = "hia" if arm.startswith("hia") else "rust"
                for site in (0, 1):
                    response = study.response_for(task, language, 3)
                    field = next(iter(response["edits"][site]["changes"]))
                    response["edits"][site]["changes"][field] = "outside.the.inventory"
                    with self.assertRaisesRegex(ValueError, "E_BATCH_STUDY_ALTERNATIVE"):
                        study.parse_response(task, arm, study.canonical(response).decode())
        task = study.fixtures()[3]
        for language, value in (("hia", {"value": 3.0}), ("hia", {"value": True}), ("rust", 3)):
            response = study.response_for(task, language, 3)
            field = "attrs" if language == "hia" else "replacement"
            response["edits"][0]["changes"][field] = value
            # Floats may be refused by the existing JSON preflight before
            # the closed-list check; no input kind may be coerced to a choice.
            with self.assertRaises(ValueError):
                study.parse_response(task, language + "_edit_query", study.canonical(response).decode())

    def test_frozen_corpus_models_and_output_budget_are_unchanged(self):
        self.assertEqual(hashlib.sha256(study.canonical(study.fixtures())).hexdigest(), FROZEN_FIXTURES_SHA256)
        lock = Path(__file__).resolve().parents[1] / "experiments/hia_atomic_maintenance_20261027/models.lock.json"
        self.assertEqual(hashlib.sha256(lock.read_bytes()).hexdigest(), FROZEN_MODEL_LOCK_SHA256)
        self.assertEqual(study.LIMIT, 512)

    def test_protocol_revision_records_prospective_contract_repair(self):
        self.assertEqual(study.PROTOCOL, "hepta.hia.atomic-maintenance-study.v2")
        policy = getattr(study, "CHOICE_DISCLOSURE_POLICY", None)
        self.assertIs(type(policy), dict)
        self.assertEqual(policy["previous_protocol"], "hepta.hia.atomic-maintenance-study.v1")
        self.assertEqual(policy["ordering"], "lexicographic canonical JSON bytes; independent of gold labels")
        self.assertFalse(policy["candidate_inventories_changed"])
        self.assertFalse(policy["prior_attempts_rescored"])


if __name__ == "__main__":
    unittest.main()
