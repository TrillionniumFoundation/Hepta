"""Independent bounded metadata controls; never start a model or compiler."""
from __future__ import annotations

import copy
import hashlib
import io
import importlib.util
import json
import os
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
RECOVERY = HERE.parent
SPEC = importlib.util.spec_from_file_location("reviewed_recovery", RECOVERY / "run_recovery.py")
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
PROTOCOL = json.loads((RECOVERY / "PROTOCOL.json").read_bytes())
HEAD = "a" * 40


def run_record(identifier=202, number=2, event="push", marker=True):
    return {
        "id": identifier,
        "run_number": number,
        "run_attempt": 1,
        "head_sha": HEAD,
        "head_branch": PROTOCOL["branch"],
        "event": event,
        "head_commit": {"message": PROTOCOL["launch_marker"] if marker else "evidence only"},
        "workflow_id": 77,
        "path": PROTOCOL["execution"]["workflow"],
        "status": "in_progress",
        "conclusion": None,
    }


def launch_environment():
    return {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_REPOSITORY": PROTOCOL["repository"],
        "GITHUB_REF_NAME": PROTOCOL["branch"],
        "GITHUB_SHA": HEAD,
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_RUN_ID": "202",
    }


def event_payload():
    return {"head_commit": {"id": HEAD, "message": PROTOCOL["launch_marker"]}}


def launch_record():
    return recovery.validate_launch(PROTOCOL, launch_environment(), event_payload(), HEAD)


class IndependentLaunchReview(unittest.TestCase):
    def test_current_push_and_explicit_dispatch_are_qualified(self):
        self.assertEqual(launch_record()["run_id"], 202)
        environment = launch_environment()
        environment["GITHUB_EVENT_NAME"] = "workflow_dispatch"
        result = recovery.validate_launch(PROTOCOL, environment,
            {"inputs": {"launch_marker": PROTOCOL["launch_marker"]}}, HEAD)
        self.assertEqual(result["event"], "workflow_dispatch")

    def test_other_events_never_launch(self):
        for event in ("pull_request", "pull_request_target", "schedule", "workflow_run"):
            with self.subTest(event=event):
                environment = launch_environment()
                environment["GITHUB_EVENT_NAME"] = event
                with self.assertRaises(ValueError):
                    recovery.validate_launch(PROTOCOL, environment, event_payload(), HEAD)

    def test_repeated_workflow_attempt_is_refused(self):
        for attempt in ("2", "01", None):
            with self.subTest(attempt=attempt):
                environment = launch_environment()
                environment["GITHUB_RUN_ATTEMPT"] = attempt
                with self.assertRaises(ValueError):
                    recovery.validate_launch(PROTOCOL, environment, event_payload(), HEAD)

    def test_old_commit_marker_does_not_qualify_current_push(self):
        payload = event_payload()
        payload["head_commit"]["message"] = "ordinary evidence"
        payload["commits"] = [{"message": PROTOCOL["launch_marker"]}]
        with self.assertRaises(ValueError):
            recovery.validate_launch(PROTOCOL, launch_environment(), payload, HEAD)

    def test_current_head_or_repeated_marker_mismatch_is_refused(self):
        for changes in ({"id": "b" * 40}, {"message": PROTOCOL["launch_marker"] * 2},
                        {"message": None}):
            with self.subTest(changes=changes):
                payload = event_payload()
                payload["head_commit"].update(changes)
                with self.assertRaises(ValueError):
                    recovery.validate_launch(PROTOCOL, launch_environment(), payload, HEAD)

    def test_earlier_nonmarker_push_does_not_consume_launch(self):
        current = run_record()
        result = recovery.select_unique_launch(PROTOCOL, current,
            [current, run_record(101, 1, marker=False)])
        self.assertEqual(result["first_eligible_run_id"], current["id"])

    def test_earlier_failed_or_queued_marker_is_consumed(self):
        for status, conclusion in (("completed", "failure"), ("queued", None),
                                   ("completed", "cancelled")):
            with self.subTest(status=status, conclusion=conclusion):
                prior = run_record(101, 1)
                prior.update(status=status, conclusion=conclusion)
                with self.assertRaises(ValueError):
                    recovery.select_unique_launch(PROTOCOL, run_record(), [run_record(), prior])

    def test_earlier_dispatch_is_conservatively_consumed(self):
        prior = run_record(101, 1, event="workflow_dispatch", marker=False)
        with self.assertRaises(ValueError):
            recovery.select_unique_launch(PROTOCOL, run_record(), [run_record(), prior])

    def test_unknown_prior_push_metadata_refuses_launch(self):
        for commit in (None, {}, {"message": None}):
            with self.subTest(commit=commit):
                prior = run_record(101, 1, marker=False)
                prior["head_commit"] = commit
                with self.assertRaises(ValueError):
                    recovery.select_unique_launch(PROTOCOL, run_record(), [run_record(), prior])

    def _verify_history(self, current, rows, total=None):
        replies = [(current, "c" * 64),
                   ({"total_count": len(rows) if total is None else total,
                     "workflow_runs": rows}, "d" * 64)]
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"HEPTA_RECOVERY_GITHUB_TOKEN": "review-only-not-a-token"}):
                with mock.patch.object(recovery, "github_json", side_effect=replies) as api:
                    result = recovery.verify_launch_history(PROTOCOL, launch_record(), Path(directory))
                    saved = json.loads((Path(directory) / "LAUNCH_QUALIFICATION.json").read_bytes())
                    self.assertEqual(result, saved)
                    self.assertNotIn("review-only-not-a-token", json.dumps(saved))
                    self.assertEqual(api.call_count, 2)
                    return result

    def test_complete_mock_api_history_admits_once_and_saves_evidence(self):
        result = self._verify_history(run_record(),
            [run_record(), run_record(101, 1, marker=False)])
        self.assertEqual(result["eligible_run_ids"], [202])

    def test_current_api_identity_and_workflow_are_bound(self):
        for changes in ({"id": 999}, {"head_sha": "b" * 40}, {"head_branch": "elsewhere"},
                        {"event": "workflow_dispatch"}, {"path": ".github/workflows/different.yml"}):
            with self.subTest(changes=changes):
                current = run_record()
                current.update(changes)
                with self.assertRaises(ValueError):
                    self._verify_history(current, [run_record()])

    def test_current_actions_api_rerun_is_refused(self):
        current = run_record()
        current["run_attempt"] = 2
        with self.assertRaises(ValueError):
            self._verify_history(current, [run_record()])

    def test_incomplete_pagination_is_refused(self):
        with self.assertRaises(ValueError):
            self._verify_history(run_record(), [run_record()], total=2)

    def test_api_search_cap_is_refused_before_assuming_history_complete(self):
        rows = [run_record()] + [run_record(1000 + index, 10 + index, marker=False)
                                 for index in range(99)]
        with self.assertRaises(ValueError):
            self._verify_history(run_record(), rows, total=1000)

    def test_duplicate_history_identity_is_refused(self):
        with self.assertRaises(ValueError):
            self._verify_history(run_record(), [run_record(), copy.deepcopy(run_record())])

    def test_current_run_missing_from_history_is_refused(self):
        with self.assertRaises(ValueError):
            self._verify_history(run_record(), [run_record(101, 1, marker=False)])

    def test_api_failure_has_no_automatic_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"HEPTA_RECOVERY_GITHUB_TOKEN": "review-only-not-a-token"}):
                with mock.patch.object(recovery, "github_json", side_effect=TimeoutError("bounded fake API timeout")) as api:
                    with self.assertRaises(TimeoutError):
                        recovery.verify_launch_history(PROTOCOL, launch_record(), Path(directory))
                    self.assertEqual(api.call_count, 1)


class IndependentFrozenStudyReview(unittest.TestCase):
    def test_new_protocol_budgets_match_original_bytes(self):
        original = json.loads((recovery.ROOT / recovery.STUDY / "PROTOCOL.json").read_bytes())
        frozen = PROTOCOL["frozen_execution"]
        for old, new in (("model_order", "model_order"), ("threads", "threads"),
                         ("context_tokens", "context_tokens"),
                         ("max_output_tokens", "maximum_output_tokens"),
                         ("request_wall_seconds", "entire_generate_wall_seconds"),
                         ("attempts_per_cell", "attempts_per_cell")):
            with self.subTest(field=old):
                self.assertEqual(frozen[new], original[old])

    def test_all_original_31_source_hashes_remain_exact(self):
        path = recovery.ROOT / recovery.STUDY / "REGISTRATION.json"
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         PROTOCOL["original_registration_sha256"])
        original = json.loads(path.read_bytes())
        self.assertEqual(len(original["sources"]), 31)
        for name, digest in original["sources"].items():
            with self.subTest(source=name):
                self.assertEqual(hashlib.sha256((recovery.ROOT / name).read_bytes()).hexdigest(), digest)

    def test_original_partial_cohort_identity_and_denominators_are_preserved(self):
        path = recovery.ROOT / "experiments/hia_agent_assembly_v4_readout_20261030/FROZEN_COHORT_RESULT.json"
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), PROTOCOL["original_cohort_sha256"])
        cohort = json.loads(path.read_bytes())
        models = {row["model"]["id"]: row for row in cohort["models"]}
        self.assertEqual(len(models["qwen_coder1_5b"]["cells"]), 12)
        self.assertTrue(models["qwen_coder1_5b"]["valid_observation"])
        self.assertEqual(sum(row["correct"] for row in models["qwen_coder1_5b"]["cells"]), 0)
        self.assertEqual(len(models["granite2b"]["cells"]), 3)
        self.assertFalse(models["granite2b"]["valid_observation"])
        self.assertFalse(cohort["complete_valid_coverage"])
        self.assertEqual(PROTOCOL["original_status"]["granite_unattempted_cells"], 9)
        self.assertEqual(PROTOCOL["original_status"]["attempted_cells"], 15)

    def test_new_study_neither_pools_old_cells_nor_claims_unseen_tasks(self):
        interpretation = PROTOCOL["interpretation"]
        self.assertTrue(interpretation["tasks_and_previous_results_already_seen"])
        for field in ("original_observations_replaced_or_rescored", "original_and_replication_cells_pooled",
                      "unseen_tasks_or_projects", "causal_memory_effect_claim", "general_agent_advantage_claim"):
            with self.subTest(field=field):
                self.assertFalse(interpretation[field])


class IndependentCohortControlFlow(unittest.TestCase):
    """All child results are tiny fakes; this tests only wrapper decisions."""

    def _fake_run(self, *, invalid_first=False, first_infrastructure_failure=False,
                  registration_drift=None, protocol_drift=False, resource_failure_label=None):
        calls = []
        original_identity = recovery.identity
        original_registration = json.loads(
            (recovery.ROOT / recovery.STUDY / "REGISTRATION.json").read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            evidence = temporary / "evidence"
            event = temporary / "event.json"
            event.write_text(json.dumps(event_payload()))
            tools = temporary / "fake-tools"
            tools.mkdir()
            for name in ("clang", "rustc", "llama-server"):
                (tools / name).write_bytes(b"bounded mock only; never executable\n")
            environment = {**launch_environment(), "RUNNER_TEMP": str(temporary),
                           "GITHUB_EVENT_PATH": str(event)}

            def copied_snapshot(folder, protocol, original, head):
                snapshot = folder / "source-snapshot"
                (snapshot / recovery.STUDY).mkdir(parents=True)
                return snapshot

            def download(folder, cache, item):
                calls.append("download:" + item["id"])
                target = cache / (item["id"] + ".fake")
                target.write_bytes(b"not a model; bounded fake bytes\n")
                return target

            def identity(path):
                actual = original_identity(path)
                if protocol_drift and Path(path) == recovery.ROOT / recovery.STUDY / "PROTOCOL.json":
                    return {**actual, "sha256": "f" * 64}
                return actual

            def install(folder):
                calls.append("install")
                return str(tools / "clang"), str(tools / "rustc")

            def resource_admit(folder, label):
                calls.append("resource:" + label)
                if label == resource_failure_label:
                    raise ValueError("bounded fake resource threshold rejection")
                return {"eligible": True}

            def command(folder, name, argv, **_kwargs):
                calls.append(name)
                study = folder / "source-snapshot" / recovery.STUDY
                suite = folder / "raw-suite"
                if name == "checkout-head":
                    (folder / "checkout-head.stdout.txt").write_text(HEAD + "\n")
                elif name == "checkout-status":
                    (folder / "checkout-status.stdout.txt").write_text("")
                elif name == "capacity":
                    recovery.save(folder / "capacity/RESULT.json", {"passed": True, "model_requests": 0})
                elif name == "register":
                    registration = copy.deepcopy(original_registration)
                    if registration_drift == "sources":
                        registration["sources"].pop(next(iter(registration["sources"])))
                    elif registration_drift is not None:
                        registration[registration_drift] = {"fake": "changed"}
                    recovery.save(study / "REGISTRATION.json", registration)
                elif name.startswith("model-"):
                    model_id = name.removeprefix("model-")
                    if model_id == "qwen_coder1_5b" and first_infrastructure_failure:
                        raise RuntimeError("bounded fake transport infrastructure failure")
                    invalid = invalid_first if model_id == "qwen_coder1_5b" else False
                    recovery.save(suite / model_id / "MODEL_RESULT.json", {
                        "valid_observation": invalid != "validity",
                        "status": "incomplete" if invalid == "status" else "all_cells_attempted",
                        "coverage_complete": invalid != "coverage",
                        "cells": [{"fake_cell": index} for index in range(3 if invalid == "count" else 12)],
                    })
                elif name == "summarize":
                    recovery.save(suite / "RESULT.json", {
                        "complete_valid_coverage": True,
                        "cross_family_gates": {"maintenance": False, "upgrade": False},
                        "cross_family_assembly_vs_json_gates": {"maintenance": False, "upgrade": False},
                    })
                return {"returncode": 0, "bounded_mock_only": True}

            with ExitStack() as patches:
                patches.enter_context(mock.patch.dict(os.environ, environment))
                patches.enter_context(mock.patch.object(recovery, "verify_launch_history", return_value={"bounded_mock_only": True}))
                patches.enter_context(mock.patch.object(recovery, "helper_bindings", return_value={}))
                patches.enter_context(mock.patch.object(recovery, "retain_definitions", return_value=None))
                patches.enter_context(mock.patch.object(recovery, "resource_admit", side_effect=resource_admit))
                patches.enter_context(mock.patch.object(recovery.resource_gate, "observe", return_value={"eligible": True}))
                patches.enter_context(mock.patch.object(recovery, "identity", side_effect=identity))
                patches.enter_context(mock.patch.object(recovery, "install_toolchains", side_effect=install))
                patches.enter_context(mock.patch.object(recovery, "download_fixed", side_effect=download))
                patches.enter_context(mock.patch.object(recovery, "extract_runtime", return_value=tools / "llama-server"))
                patches.enter_context(mock.patch.object(recovery, "prepare_snapshot", side_effect=copied_snapshot))
                patches.enter_context(mock.patch.object(recovery, "verify_bindings", return_value=True))
                patches.enter_context(mock.patch.object(recovery, "run_command", side_effect=command))
                with redirect_stdout(io.StringIO()):
                    code = recovery.run(evidence)
            terminal = json.loads((evidence / "TERMINAL.json").read_bytes())
            return code, terminal, calls

    def test_complete_fake_cohort_schedules_both_full_families_without_upgrade_of_false_gates(self):
        code, terminal, calls = self._fake_run()
        self.assertEqual(code, 0)
        self.assertEqual([name for name in calls if name.startswith("model-")],
                         ["model-qwen_coder1_5b", "model-granite2b"])
        self.assertEqual(terminal["completed_models"], ["qwen_coder1_5b", "granite2b"])
        self.assertEqual([name for name in calls if name.startswith("resource:")],
                         ["resource:before_preparation", "resource:before_capacity",
                          "resource:before_qwen_coder1_5b", "resource:before_granite2b"])
        self.assertTrue(terminal["complete_valid_coverage"])
        self.assertFalse(any(terminal["descriptive_cross_family_gates"].values()))
        self.assertFalse(any(terminal["descriptive_assembly_vs_json_gates"].values()))

    def test_incomplete_first_family_halts_without_second_family_or_resumption(self):
        for mode in ("validity", "status", "coverage", "count", "infrastructure"):
            with self.subTest(mode=mode):
                code, terminal, calls = self._fake_run(invalid_first=mode,
                    first_infrastructure_failure=mode == "infrastructure")
                self.assertEqual(code, 1)
                self.assertEqual(terminal["status"], "incomplete")
                self.assertFalse(terminal["complete_valid_coverage"])
                self.assertEqual(terminal["completed_models"], [])
                self.assertEqual([name for name in calls if name.startswith("model-")], ["model-qwen_coder1_5b"])
                self.assertNotIn("summarize", calls)

    def test_registration_inventory_drift_stops_before_any_fake_model(self):
        for field in ("sources", "prompts_and_schemas", "fixtures_canonical_sha256", "fixtures_sha256"):
            with self.subTest(field=field):
                code, terminal, calls = self._fake_run(registration_drift=field)
                self.assertEqual(code, 1)
                self.assertEqual(terminal["stage"], "new_registration")
                self.assertFalse(any(name.startswith("model-") for name in calls))

    def test_original_protocol_identity_drift_stops_before_installation_or_download(self):
        code, terminal, calls = self._fake_run(protocol_drift=True)
        self.assertEqual(code, 1)
        self.assertFalse(terminal["complete_valid_coverage"])
        self.assertNotIn("install", calls)
        self.assertFalse(any(name.startswith("download:") for name in calls))

    def test_second_family_resource_failure_keeps_first_family_and_stops(self):
        code, terminal, calls = self._fake_run(resource_failure_label="before_granite2b")
        self.assertEqual(code, 1)
        self.assertFalse(terminal["complete_valid_coverage"])
        self.assertEqual(terminal["completed_models"], ["qwen_coder1_5b"])
        self.assertEqual([name for name in calls if name.startswith("model-")], ["model-qwen_coder1_5b"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
