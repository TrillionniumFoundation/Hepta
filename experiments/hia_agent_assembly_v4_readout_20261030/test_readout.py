"""Pure in-memory readout controls; never model answers or native executions.

These fixtures deliberately duplicate no recorded successful model submission.
They exercise the independently retained evidence relations, including negative
observations. Running this module imports only the standard-library readout.
"""
from __future__ import annotations

import copy
import unittest

from experiments.hia_agent_assembly_v4_readout_20261030 import readout


ARTIFACT = "a" * 64


def observation(language, *, multiple=False):
    if multiple:
        task = {"id": "floor_multiple_v2", "provider": "floor_multiple",
                "provider_returns": ["bool", "u64"],
                "public_cases": [[13, 5, 0], [7, 0, 0]],
                "public_expected": [10, (1 << 64) - 1]}
        providers = [[1, 10], [0, 0]]
    else:
        task = {"id": "average_floor_stamp", "provider": "average",
                "provider_returns": ["u64"],
                "public_cases": [[2, 4, 0], [(1 << 32) - 1, (1 << 32) - 1, 0], [1, 2, 1]],
                "public_expected": [3, (1 << 32) - 1, (1 << 40) + 1]}
        providers = [[3], [(1 << 32) - 1], [1]]
    cases = task["public_cases"]
    expected = task["public_expected"]
    columns = [[value, 1, 1, *provider] if language == "rust" else [value]
               for value, provider in zip(expected, providers)]
    record = {"status": "correct", "artifact_sha256": ARTIFACT,
        "returncode": 0, "stdout": "".join(" ".join(map(str, row)) + "\n" for row in columns),
        "stderr": "", "cases": copy.deepcopy(cases), "expected": list(expected), "actual": list(expected),
        "artifact_unchanged": True, "sealed_image": True, "seals": 15,
        "provider_expected": copy.deepcopy(providers), "provider_actual": copy.deepcopy(providers),
        "provider_call_counts": [1] * len(cases), "provider_argument_matches": [1] * len(cases),
        "native_vm_agreement": True}
    if language != "rust":
        rows = []
        for case, value, provider in zip(cases, expected, providers):
            values = list(provider)
            if multiple:
                values[0] = bool(values[0])
            event = {"function": task["provider"], "arguments": case[:2],
                     "returned": True, "values": values}
            entry = {"status": "returned", "values": [value], "calls": [
                {"function": "entrypoint", "arguments": list(case), "returned": True, "values": [value]},
                copy.deepcopy(event)]}
            direct = {"status": "returned", "values": list(values), "calls": [copy.deepcopy(event)]}
            rows.append({"case": list(case), "entry": entry, "provider": direct,
                         "call_count": 1, "arguments_match": True})
        record["vm_provider_observations"] = rows
    return task, record


class ReadoutExecutionControls(unittest.TestCase):
    def evaluate(self, record, task, language):
        return readout.execution_correct(record, task, "public", ARTIFACT, language)

    def test_exact_positive_rust_json_and_assembly_with_single_and_multiple_returns(self):
        for language in ("rust", "hia", "assembly"):
            for multiple in (False, True):
                with self.subTest(language=language, multiple=multiple):
                    task, record = observation(language, multiple=multiple)
                    self.assertTrue(self.evaluate(record, task, language))

    def test_wrong_native_stdout_cannot_be_masked_by_correct_derived_values(self):
        for language in ("rust", "hia", "assembly"):
            task, good = observation(language)
            for replacement in ("999 1 1 3" if language == "rust" else "999", "garbage", "-1", str(1 << 64)):
                with self.subTest(language=language, replacement=replacement):
                    bad = copy.deepcopy(good)
                    lines = bad["stdout"].splitlines()
                    lines[0] = replacement
                    bad["stdout"] = "\n".join(lines) + "\n"
                    with self.assertRaises(ValueError):
                        self.evaluate(bad, task, language)

    def test_rust_raw_provider_counter_and_arguments_cannot_borrow_pass_flags(self):
        task, good = observation("rust")
        for first_line in ("3 2 1 3", "3 1 0 3", "3 1 1 999", "3 1 1"):
            with self.subTest(first_line=first_line):
                bad = copy.deepcopy(good)
                bad["stdout"] = first_line + "\n" + "\n".join(good["stdout"].splitlines()[1:]) + "\n"
                with self.assertRaises(ValueError):
                    self.evaluate(bad, task, "rust")

    def test_hia_direct_provider_values_and_events_must_match(self):
        for language in ("hia", "assembly"):
            task, good = observation(language)
            for mode in ("run_only", "event_only", "run_and_event"):
                with self.subTest(language=language, mode=mode):
                    bad = copy.deepcopy(good)
                    provider = bad["vm_provider_observations"][0]["provider"]
                    if mode != "event_only":
                        provider["values"] = [999]
                    if mode != "run_only":
                        provider["calls"][0]["values"] = [999]
                    with self.assertRaises(ValueError):
                        self.evaluate(bad, task, language)

    def test_hia_nested_provider_return_must_match_direct_same_argument_execution(self):
        for language in ("hia", "assembly"):
            task, good = observation(language)
            for field, value in (("values", [999]), ("returned", False)):
                with self.subTest(language=language, field=field):
                    bad = copy.deepcopy(good)
                    bad["vm_provider_observations"][0]["entry"]["calls"][1][field] = value
                    with self.assertRaises(ValueError):
                        self.evaluate(bad, task, language)

    def test_hia_wrong_argument_or_call_inventory_cannot_borrow_true_summary(self):
        for language in ("hia", "assembly"):
            task, good = observation(language)
            for mode in ("wrong_arguments", "missing_call", "duplicate_call", "wrong_top_level_arguments"):
                with self.subTest(language=language, mode=mode):
                    bad = copy.deepcopy(good)
                    calls = bad["vm_provider_observations"][0]["entry"]["calls"]
                    if mode == "wrong_arguments":
                        calls[1]["arguments"] = [99, 4]
                    elif mode == "missing_call":
                        calls.pop()
                    elif mode == "duplicate_call":
                        calls.append(copy.deepcopy(calls[1]))
                    else:
                        calls[0]["arguments"] = [99, 4, 0]
                    with self.assertRaises(ValueError):
                        self.evaluate(bad, task, language)

    def test_hia_entry_values_cannot_borrow_native_vm_agreement_flag(self):
        for language in ("hia", "assembly"):
            task, good = observation(language)
            for mode in ("run_only", "run_and_event", "false_return_status"):
                with self.subTest(language=language, mode=mode):
                    bad = copy.deepcopy(good)
                    entry = bad["vm_provider_observations"][0]["entry"]
                    if mode == "false_return_status":
                        entry["status"] = "trapped_or_budget_exceeded"
                    else:
                        entry["values"] = [999]
                        if mode == "run_and_event":
                            entry["calls"][0]["values"] = [999]
                    with self.assertRaises(ValueError):
                        self.evaluate(bad, task, language)

    def test_artifact_and_success_flags_cannot_replace_evidence(self):
        for language in ("rust", "hia", "assembly"):
            task, good = observation(language)
            for field, value in (("artifact_sha256", "b" * 64), ("artifact_unchanged", False),
                                 ("sealed_image", False), ("native_vm_agreement", False)):
                with self.subTest(language=language, field=field):
                    bad = copy.deepcopy(good)
                    bad[field] = value
                    with self.assertRaises(ValueError):
                        self.evaluate(bad, task, language)

    def test_consistent_wrong_native_result_stays_a_negative_observation(self):
        task, record = observation("rust")
        record["stdout"] = "999 1 1 3\n" + "\n".join(record["stdout"].splitlines()[1:]) + "\n"
        record["actual"][0] = 999
        record["status"] = "observable_wrong"
        self.assertFalse(self.evaluate(record, task, "rust"))

    def test_consistent_wrong_hia_arguments_remain_a_negative_observation(self):
        for language in ("hia", "assembly"):
            with self.subTest(language=language):
                task, record = observation(language)
                row = record["vm_provider_observations"][0]
                row["arguments_match"] = False
                row["entry"]["values"] = [51]
                row["entry"]["calls"][0]["values"] = [51]
                row["entry"]["calls"][1].update(arguments=[99, 4], values=[51])
                record["provider_argument_matches"][0] = 0
                record["actual"][0] = 51
                record["stdout"] = "51\n" + "\n".join(record["stdout"].splitlines()[1:]) + "\n"
                record["status"] = "observable_wrong"
                self.assertFalse(self.evaluate(record, task, language))

    def test_consistent_malformed_native_output_remains_a_negative_observation(self):
        task, record = observation("rust")
        record.update(stdout="not-an-integer\n", actual=None, provider_actual=[],
                      provider_call_counts=[], provider_argument_matches=[], status="observable_wrong")
        self.assertFalse(self.evaluate(record, task, "rust"))

    def test_native_timeout_stays_negative_with_unknown_usage(self):
        task, _ = observation("rust")
        record = {"status": "observable_timeout", "artifact_unchanged": True,
                  "wall_ns": 5_000_000_000, "usage": None}
        self.assertFalse(self.evaluate(record, task, "rust"))
        self.assertIsNone(record["usage"])
        record["artifact_unchanged"] = False
        with self.assertRaises(ValueError):
            self.evaluate(record, task, "rust")


class ReadoutUsageControls(unittest.TestCase):
    def test_complete_model_usage_is_derived_from_all_twelve_cells(self):
        rows = [{"usage_complete": True} for _ in range(12)]
        self.assertTrue(readout.validated_model_usage({"usage_complete": True}, rows))
        with self.assertRaises(ValueError):
            readout.validated_model_usage({"usage_complete": False}, rows)

    def test_timeout_unknown_cannot_be_upgraded_by_model_summary_bool(self):
        rows = [{"usage_complete": True} for _ in range(12)]
        rows[-1] = {"usage_complete": False, "output_tokens": None, "total_tokens": None}
        self.assertFalse(readout.validated_model_usage({"usage_complete": False}, rows))
        with self.assertRaises(ValueError):
            readout.validated_model_usage({"usage_complete": True}, rows)

    def test_incomplete_coverage_never_has_complete_model_usage(self):
        for count in (0, 11, 13):
            with self.subTest(count=count):
                rows = [{"usage_complete": True} for _ in range(count)]
                self.assertFalse(readout.validated_model_usage({"usage_complete": False}, rows))
                with self.assertRaises(ValueError):
                    readout.validated_model_usage({"usage_complete": True}, rows)

    def test_nonboolean_model_and_cell_usage_flags_are_not_completion(self):
        for value in (1, "true", None):
            rows = [{"usage_complete": True} for _ in range(12)]
            with self.subTest(model_flag=value), self.assertRaises(ValueError):
                readout.validated_model_usage({"usage_complete": value}, rows)
            rows[0]["usage_complete"] = value
            self.assertFalse(readout.validated_model_usage({"usage_complete": False}, rows))


class ReadoutCompilerControls(unittest.TestCase):
    def tools(self):
        return {"clang": {"path": "/qualified/clang", "bytes": 100, "sha256": "c" * 64},
                "rustc": {"path": "/qualified/rustc", "bytes": 200, "sha256": "d" * 64}}

    def built(self, language):
        tools = self.tools()
        compiler = tools["rustc" if language == "rust" else "clang"]
        return {"compiler": copy.deepcopy(compiler), "compiler_unchanged": True,
                "native_built": True, "compile": {"argv": [compiler["path"], "source", "-o", "candidate"]}}

    def test_exact_compiler_identity_for_each_arm(self):
        for language in ("hia", "assembly", "rust"):
            with self.subTest(language=language):
                readout.verify_compiler_binding(self.built(language), language, self.tools())

    def test_source_rejection_needs_no_fictional_compiler(self):
        readout.verify_compiler_binding({"status": "response_rejected", "native_built": False}, "assembly", self.tools())
        for built in ({"native_built": True}, {"native_built": False, "compile": {"argv": ["/unbound/compiler"]}}):
            with self.subTest(built=built), self.assertRaises(ValueError):
                readout.verify_compiler_binding(built, "assembly", self.tools())

    def test_changed_cross_arm_or_unverified_compiler_never_passes(self):
        for mode in ("hash", "cross_arm", "unchanged", "command"):
            with self.subTest(mode=mode):
                built = self.built("assembly")
                if mode == "hash":
                    built["compiler"]["sha256"] = "e" * 64
                elif mode == "cross_arm":
                    built["compiler"] = self.tools()["rustc"]
                elif mode == "unchanged":
                    built["compiler_unchanged"] = False
                else:
                    built["compile"]["argv"][0] = "/foreign/clang"
                with self.assertRaises(ValueError):
                    readout.verify_compiler_binding(built, "assembly", self.tools())

    def test_registered_compiler_alias_works_without_filesystem_resolution(self):
        built = self.built("assembly")
        built["compile"]["argv"][0] = "/qualified/bin/clang-20"
        invocations = {"clang": {"/qualified/bin/clang-20"}, "rustc": {"/qualified/rustc"}}
        readout.verify_compiler_binding(built, "assembly", self.tools(), qualified_invocations=invocations)

    def test_unregistered_or_cross_arm_alias_cannot_claim_bound_compiler(self):
        for language, command in (("assembly", "/foreign/bin/clang-20"), ("assembly", "/qualified/rustc"),
                                  ("rust", "/qualified/bin/clang-20")):
            with self.subTest(language=language, command=command):
                built = self.built(language)
                built["compile"]["argv"][0] = command
                invocations = {"clang": {"/qualified/bin/clang-20"}, "rustc": {"/qualified/rustc"}}
                with self.assertRaises(ValueError):
                    readout.verify_compiler_binding(built, language, self.tools(), qualified_invocations=invocations)


class ReadoutEngineControls(unittest.TestCase):
    def protocol(self):
        return {"threads": 4, "context_tokens": 8192}

    def engine(self):
        return {"threads": 4, "context": 8192,
            "argv": ["/qualified/server", "--threads", "4", "--threads-batch", "4",
                     "--ctx-size", "8192", "--parallel", "1"],
            "properties": {"default_generation_settings": {"n_ctx": 8192}, "total_slots": 1}}

    def test_registered_thread_context_and_slot_settings(self):
        readout.verify_engine_settings(self.engine(), self.protocol())

    def test_engine_summary_or_reported_properties_drift_refused(self):
        for mode in ("threads", "context", "reported_context", "reported_slots"):
            with self.subTest(mode=mode):
                engine = self.engine()
                if mode == "threads":
                    engine["threads"] = 8
                elif mode == "context":
                    engine["context"] = 4096
                elif mode == "reported_context":
                    engine["properties"]["default_generation_settings"]["n_ctx"] = 4096
                else:
                    engine["properties"]["total_slots"] = 2
                with self.assertRaises(ValueError):
                    readout.verify_engine_settings(engine, self.protocol())

    def test_changed_missing_or_duplicate_actual_engine_flags_refused(self):
        for flag in ("--threads", "--threads-batch", "--ctx-size", "--parallel"):
            for mode in ("changed", "missing", "duplicate"):
                with self.subTest(flag=flag, mode=mode):
                    engine = self.engine()
                    argv = engine["argv"]
                    index = argv.index(flag)
                    if mode == "changed":
                        argv[index + 1] = "99"
                    elif mode == "missing":
                        del argv[index:index + 2]
                    else:
                        argv.extend([flag, argv[index + 1]])
                    with self.assertRaises(ValueError):
                        readout.verify_engine_settings(engine, self.protocol())


if __name__ == "__main__":
    unittest.main()
