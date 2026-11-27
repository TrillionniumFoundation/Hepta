"""Ordinary callers and installed pinned-worker execution of the complete query owner.

These controls require the separately reviewed caller/resource/bundle patch.
An unmerged route is an error, never a skip or an emulated native selection.
"""
from __future__ import annotations
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from hepta.hia_agent_query_native import NativeAgentQuery, SCHEMA, SOURCE
from tests.test_hia_agent_query_native import (
    AgentQueryFixture, COLD, DEVELOPMENT, EVIDENCE, SELECTOR,
    clean_environment, json_wire, original_query, record,
)

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_CALLER_IDS = [
    "tests.test_hia_edit_query.EditQueryTests.test_real_execution_and_unmodified_caller",
    "tests.test_hia_edit_query.EditQueryTests.test_transitive_slice_includes_producer",
    "tests.test_hia_edit_query.EditQueryTests.test_consumer_other_inputs_are_closed_and_rendered_in_original_order",
    "tests.test_hia_edit_query.EditQueryTests.test_stale_base_and_forged_context_reject",
    "tests.test_hia_edit_query.EditQueryTests.test_illegal_opcode_and_type_reject",
    "tests.test_hia_edit_query.EditQueryTests.test_equal_python_numbers_cannot_forge_json_query_identity",
    "tests.test_hia_edit_query.EditQueryTests.test_outputs_and_unknown_fields_cannot_change",
    "tests.test_hia_edit_query.EditQueryTests.test_duplicate_json_and_oversize_reject",
    "tests.test_hia_edit_query.EditQueryTests.test_json_roundtrip_and_multiple_results_identity",
    "tests.test_hia_edit_query.EditQueryTests.test_effect_addition_is_rechecked",
    "tests.test_hia_edit_query.EditQueryTests.test_invalid_fields_and_identities_reject",
    "tests.test_hia_edit_query.EditQueryTests.test_reverified_forged_base",
    "tests.test_hia_edit_transitive_context.TransitiveSSAContextTests.test_transitive_consumers_are_included_without_unrelated_operations",
    "tests.test_hia_edit_transitive_context.TransitiveSSAContextTests.test_multi_output_and_all_transitive_branches_are_visible",
    "tests.test_hia_edit_transitive_context.TransitiveSSAContextTests.test_batch_deduplicates_shared_transitive_context_and_verifies_result",
    "tests.test_hia_edit_transitive_context.TransitiveSSAContextTests.test_large_transitive_slice_refuses_instead_of_lying_by_truncation",
    "tests.test_hia_edit_cfg_context.CFGEditContextTests.test_cross_block_transitive_slice_and_reverified_patch",
    "tests.test_hia_edit_cfg_context.CFGEditContextTests.test_branches_and_join_are_closed_without_guessing_selected_path",
    "tests.test_hia_edit_cfg_context.CFGEditContextTests.test_crossblock_batch_displays_once_and_atomic_patch_replays",
    "tests.test_hia_edit_cfg_context.CFGEditContextTests.test_source_block_backedge_refuses_compact_view_not_core_execution",
    "tests.test_hia_edit_cfg_context.CFGEditContextTests.test_downstream_loop_reaches_monotone_fixpoint_once",
    "tests.test_hia_edit_cfg_context.CFGEditContextTests.test_large_downstream_slice_refuses_without_truncation",
    "tests.test_hia_edit_control_context.ControlContextTests.test_condition_without_forwarded_value_shows_both_execution_outcomes",
    "tests.test_hia_edit_control_context.ControlContextTests.test_control_region_retains_no_result_resource_cleanup",
    "tests.test_hia_edit_control_context.ControlContextTests.test_unaffected_selected_terminator_inputs_are_closed",
    "tests.test_hia_edit_control_context.ControlContextTests.test_downstream_terminator_inputs_are_closed_even_when_independent",
    "tests.test_hia_edit_control_context.ControlContextTests.test_batch_deduplicates_control_region_and_applies_all_changes",
    "tests.test_hia_edit_control_context.ControlContextTests.test_old_schema_and_forged_control_flags_refuse",
    "tests.test_hia_edit_control_context.ControlContextTests.test_changed_successor_invalidates_the_original_query",
    "tests.test_hia_edit_control_context.ControlContextTests.test_control_only_cycle_back_to_selected_block_refuses",
    "tests.test_hia_edit_control_context.ControlContextTests.test_control_only_large_region_refuses_instead_of_hiding_operations",
    "tests.test_hia_edit_control_context.ControlContextTests.test_operation_free_control_region_has_a_block_budget",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_atomic_borrow_swap_succeeds_while_each_intermediate_is_rejected",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_invalid_batch_preserves_input_and_does_not_admit_partial_result",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_distinct_functions_are_reverified_with_their_callers",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_dependency_rendering_is_deduplicated_and_in_program_order",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_render_rejects_two_sites_for_one_instruction",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_render_rejects_mixed_snapshot_bindings",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_render_rejects_agreeing_nonstring_snapshot_metadata",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_render_rejects_conflicting_shared_context",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_render_accepts_distinct_composite_input_and_core_hashes",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_duplicate_sites_including_multivalue_aliases_reject",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_stale_or_forged_query_rejects_including_python_number_aliases",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_exact_sites_and_fields_cannot_be_forged",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_json_duplicates_and_response_budget_reject",
    "tests.test_hia_edit_batch.HIAEditBatchTests.test_selection_limit_and_unknown_fields_reject",
    "tests.test_hia_edit_batch_identity.BatchIdentityTests.test_duplicate_instruction_cannot_silently_erase_the_first_edit_marker",
    "tests.test_hia_edit_batch_identity.BatchIdentityTests.test_different_real_snapshots_cannot_share_one_batch_display",
    "tests.test_hia_edit_batch_identity.BatchIdentityTests.test_source_and_downstream_metadata_must_agree_in_either_selection_order",
    "tests.test_hia_edit_batch_identity.BatchIdentityTests.test_no_result_resource_callee_remains_visible_and_conflicts_refuse",
    "tests.test_hia_edit_batch_identity.BatchIdentityTests.test_reversed_legal_selection_order_keeps_both_sites_and_complete_region",
    "tests.test_hia_edit_snapshot_race.EditSnapshotRaceTests.test_single_rejects_new_query_attached_to_old_frozen_input",
    "tests.test_hia_edit_snapshot_race.EditSnapshotRaceTests.test_batch_rejects_new_query_attached_to_old_frozen_input",
    "tests.test_hia_edit_snapshot_race.EditSnapshotRaceTests.test_single_applies_only_the_original_consistent_snapshot",
    "tests.test_hia_edit_snapshot_race.EditSnapshotRaceTests.test_batch_applies_only_the_original_consistent_snapshot",
    "tests.test_hia_agent_entry.AgentEntryTests.test_capabilities_help_and_verify_do_not_load_frozen_frontend",
    "tests.test_hia_agent_entry.AgentEntryTests.test_assembly_roundtrip_uses_only_core",
    "tests.test_hia_agent_entry.AgentEntryTests.test_local_edit_executes_changed_result_and_preserves_caller",
    "tests.test_hia_agent_entry.AgentEntryTests.test_stale_and_invalid_edits_publish_nothing",
    "tests.test_hia_agent_entry.AgentEntryTests.test_real_native_object_without_external_compiler_or_fallback",
    "tests.test_hia_agent_entry.AgentEntryTests.test_source_routes_and_foreign_backend_switches_refuse_before_output",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_inspection_has_versioned_normalized_contracts",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_function_and_callee_context_expose_origin",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_local_edit_executes_and_receipt_keeps_query_v3",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_source_reconstruction_rejects_structurally_plausible_origin_forgery",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_render_rejects_malformed_and_permission_escalating_contracts",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_single_query_downgrade_never_becomes_an_apply_authority",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_batch_keeps_contracts_and_executes_atomic_value_edits",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_batch_conflicting_origin_downgrade_and_forged_consensus_reject",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_interface_preservation_includes_loan_origin",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_migration_impact_tracks_direct_and_transitive_callers",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_explicit_and_implicit_null_contracts_have_one_interface",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_old_versions_retain_their_wire_protocols",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_v8_does_not_inherit_existing_optimization_proof_qualification",
    "tests.test_hia_returned_loan_interfaces.ReturnedLoanInterfaceTests.test_routes_show_current_admission_and_distinct_proof_boundary"
]


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def runtime_environment():
    result = clean_environment()
    for key in list(result):
        if key.startswith("HEPTA_HIA_") and key.endswith(
                ("_COLD_REPORT", "_DEVELOPMENT_COMPILER", "_EVIDENCE")):
            result.pop(key)
    return result


def make_bundle(path, manifest):
    from hepta.hia_native_helpers import SCHEMA as BUNDLE_SCHEMA, TARGET, ABI
    record(path, {"schema": BUNDLE_SCHEMA, "target": TARGET, "abi": ABI,
        "helpers": [{"selector": SELECTOR, "manifest_path": str(manifest),
                     "manifest_sha256": sha256(manifest.read_bytes()).hexdigest()}]})
    return sha256(path.read_bytes()).hexdigest()


@contextmanager
def trace_transitions(directory):
    original = NativeAgentQuery.transition
    observations = []
    def observed(self, request):
        result = original(self, request)
        ordinal = len(observations)
        prefix = directory / ("native-" + str(ordinal))
        prefix.with_suffix(".request").write_bytes(request)
        prefix.with_suffix(".header").write_bytes(result.raw_header)
        prefix.with_suffix(".query").write_bytes(result.query_wire)
        observations.append({"ordinal": ordinal, "request_sha256": sha256(request).hexdigest(),
            "status": result.status, "query_sha256": sha256(result.query_wire).hexdigest(),
            "query_bytes": len(result.query_wire)})
        return result
    with patch.object(NativeAgentQuery, "transition", observed):
        yield observations


def call_checked(command, *, cwd, environment, directory, name, timeout, input=None):
    result = subprocess.run(command, cwd=cwd, env=environment, input=input,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    (directory / (name + ".stdout")).write_bytes(result.stdout)
    (directory / (name + ".stderr")).write_bytes(result.stderr)
    record(directory / (name + ".command.json"), {"argv": list(map(str, command)),
        "cwd": str(cwd), "timeout_seconds": timeout, "returncode": result.returncode,
        "stdin_sha256": sha256(input).hexdigest() if input is not None else None,
        "stdout_sha256": sha256(result.stdout).hexdigest(),
        "stderr_sha256": sha256(result.stderr).hexdigest()})
    if result.returncode != 0:
        raise AssertionError((name, result.returncode, result.stderr.decode(errors="replace")))
    return result


class AgentQueryIntegrationTests(AgentQueryFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import hepta.hia_edit_query as query
        from hepta.hia_native_helpers import HELPERS
        if not hasattr(query, "_reference_prepare_edit"):
            raise RuntimeError("complete-query ordinary-caller patch has not been applied")
        if HELPERS.get(SELECTOR) != ("hia_agent_query_native", "NativeAgentQuery"):
            raise RuntimeError("exact complete-query worker bundle registration is missing")
        super().setUpClass()

    def test_original_75_caller_ids_selected_without_hosted_query_fallback(self):
        directory = self.directory()
        suite = unittest.defaultTestLoader.loadTestsFromNames(ORIGINAL_CALLER_IDS)
        loaded = [item.id() for item in flatten(suite)]
        self.assertEqual(loaded, ORIGINAL_CALLER_IDS)
        events = []
        class ObservedResult(unittest.TextTestResult):
            def startTest(self, test):
                events.append(("start", test.id()))
                return super().startTest(test)
            def stopTest(self, test):
                events.append(("stop", test.id()))
                return super().stopTest(test)
            def addSuccess(self, test):
                events.append(("success", test.id()))
                return super().addSuccess(test)
        stream = io.StringIO()
        with (patch.dict(os.environ, {**clean_environment(), SELECTOR: str(self.manifest)}, clear=True),
              patch("hepta.hia_edit_query._reference_prepare_edit",
                    side_effect=AssertionError("retained whole hosted query owner")),
              trace_transitions(directory) as calls):
            result = unittest.TextTestRunner(stream=stream, verbosity=2,
                                             resultclass=ObservedResult).run(suite)
        (directory / "nested-original.log").write_text(stream.getvalue())
        record(directory / "nested-original.json", {
            "scope": "nested selected-query caller controls, not extra full-discovery IDs",
            "retained_original_total": 84, "nested_original_count": 75,
            "old_slice_native_9_remain_in_full_suite": True,
            "loaded": loaded, "events": events, "tests_run": result.testsRun,
            "failures": [(test.id(), message) for test, message in result.failures],
            "errors": [(test.id(), message) for test, message in result.errors],
            "skipped": [(test.id(), reason) for test, reason in result.skipped],
            "expected_failures": len(result.expectedFailures),
            "unexpected_successes": len(result.unexpectedSuccesses),
            "actual_parent_process_native_calls": calls,
            "child_native_calls_not_inferred_from_parent_trace": True})
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertEqual(result.testsRun, 75)
        self.assertFalse(result.skipped or result.expectedFailures or result.unexpectedSuccesses)
        self.assertEqual([test for event, test in events if event == "start"], loaded)
        self.assertEqual([test for event, test in events if event == "stop"], loaded)
        self.assertEqual([test for event, test in events if event == "success"], loaded)
        self.assertTrue(calls)

    def test_cli_service_batch_and_apply_share_actual_complete_query_owner(self):
        from hepta.cli import hia_main
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_native_helpers import native_helpers_scope
        from hepta.hia_edit_batch import prepare_batch
        from hepta.hia_edit_query import apply_edit
        from tools.hia_agent_native_qualification import Session, ToolClient, exhaustive_u8_workload
        from tests.test_hia_edit_query import fixture
        directory = self.directory()
        source = fixture()
        selection = dict(function="calculate", block="entry", output="y", fields=["op", "args", "attrs"])
        expected = original_query(source, **selection)
        source_path = directory / "source.core.hepta"
        source_path.write_bytes(json_wire(source))
        bundle = directory / "bundle.json"
        pin = make_bundle(bundle, self.manifest)
        files = directory / "files"
        files.mkdir()
        replies = {}
        with (patch.dict(os.environ, clean_environment(), clear=True),
              native_helpers_scope(str(bundle), pin),
              patch("hepta.hia_edit_query._reference_prepare_edit",
                    side_effect=AssertionError("hosted whole query owner")),
              trace_transitions(directory) as calls):
            stdout = io.StringIO()
            with patch("sys.stdout", stdout):
                self.assertEqual(hia_main(["edit-query", str(source_path), "--function", "calculate",
                    "--block", "entry", "--value", "y", "--fields", "op,args,attrs"]), 0)
            replies["cli"] = json.loads(stdout.getvalue())
            self.assertEqual(replies["cli"], expected)
            batch = prepare_batch(source, [selection])
            self.assertEqual(batch["schema"], "hepta.hia.edit-batch-query.v2")
            revised, receipt = apply_edit(source, expected, {"op": "int.sub.wrap"})
            self.assertTrue(receipt["edit_query"]["context_reconstructed"])
            self.assertNotEqual(revised.sha256, expected["base_sha256"])
            replies["batch"] = batch
            replies["apply"] = receipt
            service = HIAAgentService(directory / "state", artifact_roots=(files,))
            try:
                session = Session(ToolClient(service.call), prefix="complete-query")
                session.freeze(exhaustive_u8_workload())
                program = session.import_program(source)
                arguments = session.arguments(mutable=False, program=program, view="dependencies",
                                              selector={key: selection[key] for key in ("function", "block", "output")})
                response = session.client.result("hia_inspect", arguments)
                replies["service"] = session.read_json(response["query_artifact"])
                self.assertEqual(replies["service"], expected)
            finally:
                service.close()
        self.assertGreaterEqual(len(calls), 4)
        self.assertTrue(all(call["status"] == 0 for call in calls))
        record(directory / "ordinary-routes.json", {"replies": replies, "actual_native_calls": calls,
            "native_helpers_sha256": pin, "source_checkout_without_bundle_is_not_claimed_native": True})

    def test_empty_selection_unknown_factory_and_ambient_bundle_refuse_before_effects(self):
        from hepta.hia_agent_query_native import selected_agent_query
        from hepta.hia_native_helpers import native_helpers_scope
        from hepta.hia_json_preflight_native import _installed_json_image
        directory = self.directory()
        with patch.dict(os.environ, {**clean_environment(), SELECTOR: ""}, clear=True):
            with self.assertRaises(ValueError):
                selected_agent_query()
        bundle = directory / "bundle.json"
        pin = make_bundle(bundle, self.manifest)
        class UnregisteredView(NativeAgentQuery):
            def __init__(self, *args, **kwargs):
                raise AssertionError("unregistered factory must be refused before mapping")
        with patch.dict(os.environ, clean_environment(), clear=True), native_helpers_scope(str(bundle), pin):
            with self.assertRaisesRegex(ValueError, "outside the pinned worker bundle"):
                _installed_json_image(str(self.manifest), SOURCE, SCHEMA, UnregisteredView)
        state = directory / "must-not-exist"
        with patch.dict(os.environ, {**clean_environment(), "HEPTA_HIA_UNKNOWN_MANIFEST": "untrusted"}, clear=True):
            with self.assertRaises(ValueError), native_helpers_scope(str(bundle), pin):
                from hepta.hia_agent_service import HIAAgentService
                HIAAgentService(state)
        self.assertFalse(state.exists())

    def test_actual_sdist_wheel_and_worker_bundle_need_no_per_call_environment(self):
        from hepta.hia_agent_contract import (
            DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES,
            COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES,
        )
        from tests.test_hia_edit_query import fixture
        from tools.hia_agent_native_qualification import exhaustive_u8_workload
        directory = self.directory()
        stage = directory / "staged"
        stage.mkdir()
        shutil.copytree(ROOT / "hepta", stage / "hepta",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "_data"))
        for filename in ("setup.py", "pyproject.toml", "MANIFEST.in", "README.md", "LICENSE"):
            if (ROOT / filename).is_file():
                shutil.copy2(ROOT / filename, stage / filename)
        resources = (*('docs/' + name for name in DISCOVERY_FILES),
                     *NATIVE_SOURCE_FILES, *SOURCE_BUILD_FILES,
                     *COMPILER_BUILD_FILES, *PUBLICATION_BUILD_FILES)
        self.assertIn("examples/hia_bootstrap/agent_query.hepta", NATIVE_SOURCE_FILES)
        for relative in resources:
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)
        oracle = "tests/fixtures/hia_compiler_rename_reference.json.gz"
        oracle_bytes = (ROOT / oracle).read_bytes()
        self.assertEqual(sha256(oracle_bytes).hexdigest(),
                         "0bfb03e219dc31352ae92e22288139e66e1c00ab4a4861648b54712c8e213069")
        (stage / oracle).parent.mkdir(parents=True, exist_ok=True)
        (stage / oracle).write_bytes(oracle_bytes)
        environment = runtime_environment()
        dist = directory / "dist"
        wheels = directory / "wheels"
        installed = directory / "installed"
        call_checked([sys.executable, "-B", "setup.py", "sdist", "--dist-dir", str(dist)],
                     cwd=stage, environment=environment, directory=directory, name="sdist", timeout=90)
        sdists = list(dist.glob("*.tar.gz"))
        self.assertEqual(len(sdists), 1)
        with tarfile.open(sdists[0], "r:gz") as archive:
            names = archive.getnames()
            prefix = names[0].split("/", 1)[0]
            member = archive.extractfile(prefix + "/" + oracle)
            self.assertIsNotNone(member)
            self.assertEqual(member.read(), oracle_bytes)
            source = archive.extractfile(prefix + "/examples/hia_bootstrap/agent_query.hepta")
            self.assertEqual(source.read(), SOURCE.read_bytes())
        call_checked([sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps",
                      "--no-build-isolation", "--wheel-dir", str(wheels), str(sdists[0])],
                     cwd=directory, environment=environment, directory=directory, name="wheel", timeout=90)
        wheel_files = list(wheels.glob("*.whl"))
        self.assertEqual(len(wheel_files), 1)
        with zipfile.ZipFile(wheel_files[0]) as wheel:
            self.assertEqual(wheel.read("hepta/_data/examples/hia_bootstrap/agent_query.hepta"), SOURCE.read_bytes())
            self.assertFalse(any(name.endswith("hia_compiler_rename_reference.json.gz") for name in wheel.namelist()))
        call_checked([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
                      "--target", str(installed), str(wheel_files[0])],
                     cwd=directory, environment=environment, directory=directory, name="install", timeout=60)
        self.assertFalse(list((installed / "hepta/_data").rglob("hia_compiler_rename_reference.json.gz")))
        bundle = directory / "bundle.json"
        pin = make_bundle(bundle, self.manifest)
        source = fixture()
        selection = dict(function="calculate", block="entry", output="y", fields=["op", "args", "attrs"])
        program = directory / "source.core.hepta"
        program.write_bytes(json_wire(source))
        expected = directory / "expected.json"
        expected.write_bytes(json_wire(original_query(source, **selection)))
        workload = directory / "workload.json"
        workload.write_bytes(json_wire(exhaustive_u8_workload()))
        result = call_checked([sys.executable, "-I", "-B", "-c", INSTALLED_CHILD,
                              str(installed), str(bundle), pin, str(program), str(expected),
                              str(workload), str(directory)],
                             cwd=directory, environment=environment, directory=directory,
                             name="installed-calls", timeout=60)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "INSTALLED_COMPLETE_QUERY_CALLERS_PASS")
        self.assertEqual(report["runtime_query_selectors_before_bundle"], [])
        self.assertTrue(report["worker_report"]["complete"])
        self.assertEqual(report["worker_report"]["native_helpers_sha256"], pin)
        self.assertEqual(report["worker_native_calls"], 1)
        self.assertGreaterEqual(report["installed_native_calls"], 2)
        self.assertEqual(report["reference_owner_calls"], 0)
        self.assertFalse(report["whole_native_closure"])
        # A private installed resource can be changed for a negative control;
        # no checked-out source or historical evidence is edited.
        installed_source = installed / "hepta/_data/examples/hia_bootstrap/agent_query.hepta"
        original_source = installed_source.read_bytes()
        installed_source.write_bytes(original_source + b"\n")
        rejection_state = directory / "rejected-state"
        bad = subprocess.run([sys.executable, "-I", "-B", "-c",
            "import sys;sys.path.insert(0,sys.argv.pop(1));from hepta.hia_agent_worker import main;raise SystemExit(main())",
            str(installed), "--state-root", str(rejection_state), "--request-json-stdin",
            "--native-helpers-manifest", str(bundle), "--expected-native-helpers-sha256", pin],
            cwd=directory, env=environment, input=b"{}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        (directory / "tampered-resource.stdout").write_bytes(bad.stdout)
        (directory / "tampered-resource.stderr").write_bytes(bad.stderr)
        self.assertEqual(bad.returncode, 2)
        self.assertFalse(bad.stdout)
        self.assertIn(b"native helper source identity mismatch", bad.stderr)
        self.assertFalse(rejection_state.exists())
        record(directory / "installed-summary.json", report)


INSTALLED_CHILD = r'''
from hashlib import sha256
import importlib.abc
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

installed, bundle, pin, program_file, expected_file, workload_file, output = sys.argv[1:]
sys.path.insert(0, installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".", 1)[0] in {"tools", "tests"}:
            raise ImportError("authoring/test package forbidden in installed runtime")
sys.meta_path.insert(0, NoAuthoring())
from hepta.hia_agent_query_native import NativeAgentQuery, SOURCE
from hepta.hia_native_helpers import native_helpers_scope
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_store import wire
from hepta.cli import hia_main

out = Path(output)
files = out / "installed-files"
files.mkdir()
state = out / "installed-state"
program = json.loads(Path(program_file).read_bytes())
expected = json.loads(Path(expected_file).read_bytes())
workload = json.loads(Path(workload_file).read_bytes())
selectors = [key for key in os.environ if key.startswith("HEPTA_HIA_")
             and key.endswith(("_MANIFEST", "_COLD_REPORT", "_DEVELOPMENT_COMPILER", "_EVIDENCE"))]
assert selectors == [], selectors
calls = []
transition = NativeAgentQuery.transition
def observed(self, request):
    receipt = transition(self, request)
    ordinal = len(calls)
    (out / ("installed-native-" + str(ordinal) + ".request")).write_bytes(request)
    (out / ("installed-native-" + str(ordinal) + ".query")).write_bytes(receipt.query_wire)
    calls.append({"status": receipt.status, "input_sha256": sha256(request).hexdigest(),
                  "output_sha256": sha256(receipt.query_wire).hexdigest()})
    return receipt
NativeAgentQuery.transition = observed
records = []
with native_helpers_scope(bundle, pin), patch(
        "hepta.hia_edit_query._reference_prepare_edit",
        side_effect=AssertionError("hosted whole-query owner")) as reference:
    service = HIAAgentService(state, artifact_roots=(files,))
    try:
        def call(tool, arguments):
            response = service.call(tool, arguments)
            records.append({"tool": tool, "arguments": arguments, "response": response})
            assert response["status"] == "completed", response
            return response["result"]
        discovery = call("hia_describe", {"section": "manifest"})
        catalog = discovery["catalog_sha256"]
        def read_json(artifact):
            chunks = []
            cursor = None
            while True:
                arguments = {"catalog_sha256": catalog, "artifact": artifact, "max_bytes": 65536}
                if cursor is not None:
                    arguments["cursor"] = cursor
                page = call("hia_read", arguments)
                assert page["encoding"] == "utf8"
                chunks.append(page["content"])
                cursor = page["next_cursor"]
                if cursor is None:
                    return json.loads("".join(chunks))
        manifest = read_json(discovery["manifest"])
        profiles = manifest["profiles"]
        sequence = 0
        def mutable(**arguments):
            global sequence
            sequence += 1
            return dict(catalog_sha256=catalog, request_key="query-installed/" + str(sequence), **arguments)
        def artifact(value):
            return call("hia_artifact", mutable(artifact_profile=profiles["artifact"],
                source={"kind": "utf8", "text": json.dumps(value, separators=(",", ":"), sort_keys=True)}))["artifact"]
        cost = {"schema": "hepta.hia.agent.cost-policy.v1", "external_costs": {
            "model_tokens": None, "model_wall_ns": None, "discovery_wall_ns": None},
            "external_costs_complete": False, "expected_invocations": "0"}
        objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
            "required_claims": ["core_admission", "encoding_check"], "allow_unchanged": True,
            "min_improvement_ratio": 0.0}
        context = call("hia_context", mutable(compiler_profile=profiles["compiler"],
            target_profile=profiles["target"], baseline_program=None, workload=artifact(workload),
            objective=artifact(objective), budget={"max_candidates": 128, "max_model_tokens": 0,
            "max_total_wall_ms": 600000, "max_native_wall_ms": 10000, "max_memory_bytes": "536870912",
            "cost_policy": artifact(cost)}))["context"]
        candidate = call("hia_candidate", mutable(context=context, change={
            "kind": "import", "format": "core-json", "source": artifact(program)}))["candidate"]
        inspect_args = {"catalog_sha256": catalog, "context": context, "program": candidate,
            "view": "dependencies", "selector": {"function": "calculate", "block": "entry", "output": "y"}}
        inspection = call("hia_inspect", inspect_args)
        assert read_json(inspection["query_artifact"]) == expected
        stream = io.StringIO()
        with patch("sys.stdout", stream):
            code = hia_main(["edit-query", program_file, "--function", "calculate",
                "--block", "entry", "--value", "y", "--fields", "op,args,attrs"])
        assert code == 0 and json.loads(stream.getvalue()) == expected
        identity = installation_manifest()
        reference_calls = reference.call_count
    finally:
        service.close()
assert reference_calls == 0
environment = {key: value for key, value in os.environ.items()
               if not (key.startswith("HEPTA_HIA_") and key.endswith(
                    ("_MANIFEST", "_COLD_REPORT", "_DEVELOPMENT_COMPILER", "_EVIDENCE")))}
body = {"schema": "hia-agent-worker-request-v1", "tool": "hia_inspect",
    "arguments": inspect_args, "profile_sha256": profiles["compiler"]["sha256"], "catalog_sha256": catalog}
body["request_sha256"] = sha256(wire(body)).hexdigest()
worker_script = r"""
from hashlib import sha256
import importlib.abc
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch
installed, evidence = sys.argv[1:3]
sys.argv = [sys.argv[0], *sys.argv[3:]]
sys.path.insert(0, installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".", 1)[0] in {"tools", "tests"}:
            raise ImportError("authoring forbidden in actual worker")
sys.meta_path.insert(0, NoAuthoring())
assert not [key for key in os.environ if key.startswith("HEPTA_HIA_") and key.endswith(
    ("_MANIFEST", "_COLD_REPORT", "_DEVELOPMENT_COMPILER", "_EVIDENCE"))]
from hepta.hia_agent_query_native import NativeAgentQuery
from hepta.hia_agent_worker import main
original = NativeAgentQuery.transition
calls = []
def observed(self, request):
    result = original(self, request)
    base = Path(evidence) / ("worker-native-" + str(len(calls)))
    base.with_suffix(".request").write_bytes(request)
    base.with_suffix(".query").write_bytes(result.query_wire)
    calls.append({"status": result.status, "query_sha256": sha256(result.query_wire).hexdigest()})
    return result
NativeAgentQuery.transition = observed
with patch("hepta.hia_edit_query._reference_prepare_edit",
           side_effect=AssertionError("hosted query in actual worker")) as reference:
    code = main()
    assert reference.call_count == 0
(Path(evidence) / "worker-native-calls.json").write_text(json.dumps(calls))
raise SystemExit(code)
"""
worker = subprocess.run([sys.executable, "-I", "-B", "-c", worker_script, installed, output,
    "--state-root", str(state), "--artifact-root", str(files), "--request-json-stdin",
    "--native-helpers-manifest", bundle, "--expected-native-helpers-sha256", pin,
    "--expected-worker-sha256", identity["worker_sha256"],
    "--expected-backend-sha256", identity["backend_sha256"],
    "--expected-catalog-sha256", identity["catalog_sha256"]],
    env=environment, cwd=out, input=wire(body), stdout=subprocess.PIPE,
    stderr=subprocess.PIPE, timeout=60)
(out / "actual-worker.stdout").write_bytes(worker.stdout)
(out / "actual-worker.stderr").write_bytes(worker.stderr)
assert worker.returncode == 0 and not worker.stderr, (worker.returncode, worker.stderr)
report = json.loads(worker.stdout)
assert report["complete"] and report["response"]["status"] == "completed", report
assert report["native_helpers_sha256"] == pin
worker_calls = json.loads((out / "worker-native-calls.json").read_bytes())
assert len(worker_calls) == 1 and worker_calls[0]["status"] == 0, worker_calls
assert json.loads((out / "worker-native-0.query").read_bytes()) == expected
(out / "installed-tool-records.json").write_text(json.dumps(records, sort_keys=True, indent=2))
print(json.dumps({"status": "INSTALLED_COMPLETE_QUERY_CALLERS_PASS",
    "runtime_query_selectors_before_bundle": selectors, "installed_native_calls": len(calls),
    "worker_native_calls": len(worker_calls), "worker_report": report,
    "reference_owner_calls": reference_calls, "whole_native_closure": False}, sort_keys=True))
'''
