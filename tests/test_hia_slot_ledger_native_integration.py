"""Real ordinary slot effects, journal atomicity and native helper composition.

Every native observation uses an admitted HIA image.  Development builds are
explicit and never supply matching-source cold evidence.  The retained ten
test IDs below keep their original methods and budgets.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import select
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import AgentRejected, wire
from tests.test_hia_agent_native_tools import AgentToolCase
from tools.hia_agent_native_qualification import Session, ToolClient, add_program, exhaustive_u8_workload

ROOT = Path(__file__).resolve().parents[1]
COLD = "HEPTA_HIA_SLOT_LEDGER_COLD_REPORT"
DEVELOPMENT = "HEPTA_HIA_SLOT_LEDGER_DEVELOPMENT_COMPILER"
EVIDENCE = "HEPTA_HIA_SLOT_LEDGER_EVIDENCE"
SELECTOR = "HEPTA_HIA_SLOT_LEDGER_MANIFEST"
COLD_SELECTORS = (
    COLD,
    "HEPTA_HIA_AGENT_JOURNAL_COLD_REPORT",
    "HEPTA_HIA_EXECUTION_BUDGET_COLD_REPORT",
    "HEPTA_HIA_CANDIDATE_BUDGET_COLD_REPORT",
    "HEPTA_HIA_WORKER_HELPERS_COLD_REPORT",
    "HEPTA_HIA_RETIREMENT_STATE_COLD_REPORT",
)
REFERENCE_SLOT_METHODS = (
    "_reference_adoption_evaluation", "_reference_adoption_net_benefit",
    "_reference_slot_snapshot", "_reference_slot_conditional",
    "_reference_slot_adopt", "_reference_slot_rollback",
    "_reference_slot_acquire", "_reference_slot_lease",
    "_reference_slot_release",
)
ORIGINAL_IDS = (
    "tests.test_hia_agent_native_tools.NativeLifecycleTests.test_published_version_lease_survives_rollback_and_release_is_checked",
    "tests.test_hia_agent_native_tools.NativeLifecycleTests.test_fresh_context_can_advance_existing_slot_and_stale_error_is_readable",
    "tests.test_hia_agent_native_tools.NativeLifecycleTests.test_u64_generation_boundary_rejects_out_of_range_strings",
    "tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_adoption_consumer_bytes_survive_rollback_and_release_fences",
    "tests.test_hia_agent_buffer_lifecycle.BufferLifecycleTests.test_cold_consumer_processes_preserve_lease_and_release_across_rollback",
    "tests.test_hia_agent_native_lease_snapshot.LeaseSnapshotTests.test_caller_mutation_during_native_call_cannot_relabel_result_or_buffers",
    "tests.test_hia_agent_journal_native.JournalNativeTests.test_real_SQL_commit_fault_preserves_ack_before_commit_semantics",
    "tests.test_hia_agent_journal_native.JournalNativeTests.test_native_protocol_failure_cannot_journal_a_rolled_back_success",
    "tests.test_hia_agent_journal_native.JournalNativeTests.test_real_process_kill_after_effect_preserves_running_intent",
    "tests.test_hia_agent_journal_native.JournalNativeTests.test_real_artifact_restart_replay_alias_and_no_effect_cost_or_update",
)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
                    encoding="utf-8")


def file_identity(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {"path": str(path), "sha256": sha256(raw).hexdigest(), "byte_length": len(raw)}


def source_map():
    from tools.hia_selfhost_contract import SOURCE_FILES, CONTRACT_PATH
    paths = set(SOURCE_FILES) | {CONTRACT_PATH, str(Path(__file__).relative_to(ROOT)),
        "tools/generate_hia_slot_ledger.py", "tools/build_hia_slot_ledger.py",
        "examples/hia_bootstrap/slot_ledger.hepta", "hepta/hia_slot_ledger_native.py",
        "tests/test_hia_slot_ledger_native.py"}
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(paths)}


def connection_rows(connection):
    orders = {"slots": "name", "versions": "slot,generation", "leases": "id",
              "requests": "key", "artifacts": "id", "costs": "sequence",
              "contexts": "id", "execution_budgets": "context_id"}
    return {table: [list(row) for row in connection.execute(
        "SELECT * FROM " + table + " ORDER BY " + order)] for table, order in orders.items()}


def database_rows(service):
    return connection_rows(service.store.db)


def persisted_rows(path):
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        return connection_rows(connection)
    finally:
        connection.close()


def state_rows(service):
    all_rows = database_rows(service)
    return {name: all_rows[name] for name in ("slots", "versions", "leases", "artifacts")}


def suite_ids(suite):
    result = []
    for item in suite:
        result.extend(suite_ids(item) if isinstance(item, unittest.TestSuite) else [item.id()])
    return result


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed_ids = []

    def startTest(self, test):
        self.executed_ids.append(test.id())
        super().startTest(test)


class SlotLedgerNativeIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta import hia_slot_ledger_native as slot
        from tools.build_hia_json_preflight import admit_cold_build

        cold = os.environ.get(COLD)
        development = os.environ.get(DEVELOPMENT)
        if COLD in os.environ and not cold:
            raise AssertionError("an explicitly selected slot cold report cannot be empty")
        if DEVELOPMENT in os.environ and not development:
            raise AssertionError("an explicitly selected development compiler cannot be empty")
        if cold and development:
            raise AssertionError("development compiler cannot override a requested cold report")
        if not cold and not development:
            raise AssertionError("slot integration requires explicit matching cold or development compiler")
        cls.cold = Path(cold).resolve(strict=True) if cold else None
        cls.bindings = {}
        if cls.cold:
            raw = cls.cold.read_bytes()
            report = json.loads(raw)
            nested_path = Path(report["nested_report"]).resolve(strict=True)
            nested_raw = nested_path.read_bytes()
            nested = json.loads(nested_raw)
            cls.compiler = Path(nested["generations"][-1]["produced_image"]).resolve(strict=True)
            admit_cold_build(cls.compiler.read_bytes(), raw)
            for name in COLD_SELECTORS:
                if name in os.environ:
                    value = os.environ[name]
                    if not value or Path(value).read_bytes() != raw:
                        raise AssertionError("slot composition cold reports must bind the same original bytes: " + name)
            cls.bindings[cls.cold] = raw
            cls.bindings[nested_path] = nested_raw
        else:
            if any(os.environ.get(name) for name in COLD_SELECTORS):
                raise AssertionError("development slot build cannot compose with a requested cold report")
            cls.compiler = Path(development).resolve(strict=True)
        cls.bindings[cls.compiler] = cls.compiler.read_bytes()
        cls.temporary = None
        if os.environ.get(EVIDENCE):
            cls.folder = Path(os.environ[EVIDENCE]) / "integration"
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="hia-slot-integration-")
            cls.folder = Path(cls.temporary.name)
            cls.addClassCleanup(cls.temporary.cleanup)
        cls.before_sources = source_map()
        write_json(cls.folder / "source-before.json", cls.before_sources)
        cls.manifests = {}
        cls.helper_modules = {"slot": slot}
        cls.addClassCleanup(cls.finish_custody)
        cls.manifest = cls.build_helper("slot")
        write_json(cls.folder / "fixture.json", {
            "scope": "MATCHING_CURRENT_SOURCE_COLD_BUILD" if cls.cold else "EXPLICIT_DEVELOPMENT_ONLY",
            "matching_current_source_cold_qualified": bool(cls.cold),
            "compiler": file_identity(cls.compiler),
            "cold_report": file_identity(cls.cold) if cls.cold else None,
            "slot_manifest": file_identity(cls.manifest),
            "retained_exact_ids": list(ORIGINAL_IDS),
            "nested_coverage_is_not_added_to_top_level_discovery_count": True,
            "nested_retirement_id": "tests.test_hia_multiversion.MultiversionNativeTests.test_rollback_changes_future_calls_and_retains_old_lease",
            "budget_sources": {
                "packaging_each_90_seconds": "tests/test_hia_candidate_budget_native.py:715-733",
                "worker_60_seconds": "tests/test_hia_worker_native_helpers.py:232-241",
                "installed_native_60_seconds": "tests/test_hia_worker_native_helpers.py:867-869",
                "child_checkpoint_15_cleanup_5_seconds": "tests/test_hia_agent_journal_native.py:657-665",
                "retained_test_budgets": "original methods are loaded and run without edits",
            },
            "fixture_abi": {"factory": "hepta.hia_slot_ledger_native.NativeSlotLedger",
                "source": "examples/hia_bootstrap/slot_ledger.hepta",
                "schema": "hepta.hia.slot-ledger-native.v1",
                "request_header_bytes": 128, "response_header_bytes": 64, "state_bytes": 128,
                "observer": "transition(request, state=None) calls original and records receipt.raw",
                "reference_policy_methods": list(REFERENCE_SLOT_METHODS)},
            "implicit_bootstrap": False,
        })

    @classmethod
    def finish_custody(cls):
        after = source_map()
        write_json(cls.folder / "source-after.json", after)
        if cls.before_sources != after:
            raise AssertionError("slot integration changed bound source")
        drift = [str(path) for path, raw in cls.bindings.items() if path.read_bytes() != raw]
        write_json(cls.folder / "final-custody.json", {
            "sources_preserved": cls.before_sources == after, "changed_bound_files": drift,
            "bound_files": [file_identity(path) for path in sorted(cls.bindings, key=str)],
            "matching_current_source_cold_qualified": bool(cls.cold),
        })
        if drift:
            raise AssertionError("slot integration changed selected cold/compiler/image inputs")

    @classmethod
    def build_helper(cls, name):
        if name in cls.manifests:
            return cls.manifests[name]
        if name == "slot":
            from hepta import hia_slot_ledger_native as module
            from tools.build_hia_slot_ledger import build
        elif name == "journal":
            from hepta import hia_agent_journal_native as module
        elif name == "execution":
            from hepta import hia_execution_budget_native as module
        elif name == "candidate":
            from hepta import hia_candidate_budget_native as module
            from tools.build_hia_candidate_budget import build
        elif name == "retirement":
            from hepta import hia_retirement_state_native as module
            from tools.build_hia_retirement_state import build
        else:
            raise AssertionError("unknown integration helper")
        if cls.cold:
            output = cls.folder / ("qualified-" + name)
            if name in {"journal", "execution"}:
                from tools.build_hia_json_preflight import build
                candidate = "agent-journal" if name == "journal" else "execution-budget"
                manifest_path = build(output, cls.compiler, cls.cold, candidate=candidate)
            else:
                manifest_path = build(output, cls.compiler, cls.cold)
        else:
            from tools.qualify_hia_selfhost import compile_stage
            output = cls.folder / ("development-" + name)
            output.mkdir(mode=0o700)
            image, receipt = compile_stage(output, name, cls.compiler, module.SOURCE.read_bytes())
            manifest_path = output / "manifest.json"
            write_json(manifest_path, {"schema": module.SCHEMA,
                "source_sha256": sha256(module.SOURCE.read_bytes()).hexdigest(),
                "image_path": image.name, "image_sha256": sha256(image.read_bytes()).hexdigest(),
                "compiler_sha256": sha256(cls.compiler.read_bytes()).hexdigest()})
            write_json(output / "development-observation.json", {
                "matching_current_source_cold_qualified": False, "native_compile_receipt": receipt,
                "compiler": file_identity(cls.compiler), "source": file_identity(module.SOURCE)})
        manifest_path = Path(manifest_path).resolve(strict=True)
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw)
        image = (manifest_path.parent / manifest["image_path"]).resolve(strict=True)
        cls.bindings[manifest_path] = raw
        cls.bindings[image] = image.read_bytes()
        if sha256(cls.bindings[image]).hexdigest() != manifest["image_sha256"]:
            raise AssertionError("compiled integration image identity differs")
        cls.manifests[name] = manifest_path
        cls.helper_modules[name] = module
        return manifest_path

    def setUp(self):
        self.root = self.folder / self._testMethodName
        self.root.mkdir(mode=0o700)
        self.transitions = []
        self.observations = []
        self.stack = ExitStack()
        self.addCleanup(self.finish_case)
        self.environment_before = dict(os.environ)
        clean = {name: value for name, value in os.environ.items()
                 if not (name.startswith("HEPTA_HIA_") and name.endswith("_MANIFEST"))}
        self.clean_environment = clean
        self.stack.enter_context(patch.dict(os.environ, {**clean, SELECTOR: str(self.manifest)}, clear=True))
        for name in REFERENCE_SLOT_METHODS:
            self.stack.enter_context(patch.object(HIAAgentService, name,
                side_effect=AssertionError("selected slot entered retained policy: " + name)))
        from hepta.hia_slot_ledger_native import NativeSlotLedger
        original = NativeSlotLedger.transition
        mapping_identities = {}
        def observed(image, request, state=None):
            captured = bytes(request)
            previous = bytes(state) if state is not None else None
            if id(image) not in mapping_identities:
                mapping_identities[id(image)] = sha256(bytes(image._mapping)).hexdigest()
            identity = mapping_identities[id(image)]
            record = {"request_hex": captured.hex(), "image_sha256": identity,
                "thread": threading.get_ident(),
                "state_before_sha256": sha256(previous).hexdigest() if previous is not None else None,
                "state_before_length": len(previous) if previous is not None else None}
            try:
                receipt = original(image, request, state)
            except BaseException as error:
                record["raised"] = {"type": type(error).__name__, "message": str(error)}
                self.transitions.append(record)
                raise
            following = bytes(state) if state is not None else None
            record.update({"status": receipt.status, "action": receipt.action,
                "values": list(receipt.values), "fields_hex": [value.hex() for value in receipt.fields],
                "raw_output_hex": receipt.raw.hex(),
                "state_after_sha256": sha256(following).hexdigest() if following is not None else None,
                "state_after_length": len(following) if following is not None else None})
            self.transitions.append(record)
            return receipt
        self.stack.enter_context(patch.object(NativeSlotLedger, "transition", observed))
        self.services = []

    def finish_case(self):
        failures = []
        for service in reversed(getattr(self, "services", [])):
            try:
                service.close()
            except BaseException as error:
                failures.append(type(error).__name__ + ": " + str(error))
        if hasattr(self, "stack"):
            self.stack.close()
        write_json(self.root / "native-transitions.json", self.transitions)
        write_json(self.root / "observations.json", self.observations)
        if dict(os.environ) != self.environment_before:
            raise AssertionError("slot integration leaked environment")
        if failures:
            raise AssertionError("slot fixture cleanup failed: " + repr(failures))

    def service(self, name="state"):
        directory = self.root / name
        files = self.root / (name + "-files")
        files.mkdir(mode=0o700)
        service = HIAAgentService(directory, artifact_roots=(files,))
        self.services.append(service)
        session = Session(ToolClient(service.call), prefix=self._testMethodName + "/" + name)
        return service, session

    def pair(self, service, session, *, same=False):
        case = AgentToolCase()
        case.service, case.session = service, session
        document = add_program(optimized=True) if same else None
        base, candidate, baseline, built, receipts = AgentToolCase.build_pair(
            case, document=document, candidate=document)
        evaluation = session.evaluate(baseline, built, receipts=receipts)
        self.assertIn(evaluation["outcome"], ("improved", "unchanged"))
        self.assertTrue(evaluation["termination_confirmed"])
        self.assertTrue(evaluation["planned_workload_complete"])
        return {"base": base, "candidate": candidate, "baseline": baseline, "built": built,
                "receipts": receipts, "evaluation": evaluation}

    def adopt_arguments(self, session, pair, slot, expected):
        return session.arguments(target_slot=slot, expected_current=expected,
            candidate_artifact=pair["built"]["native_artifact"],
            evaluation_receipt=pair["evaluation"]["evaluation_receipt"],
            verification_receipts=pair["receipts"])

    def adopt(self, service, session, pair, slot, expected):
        arguments = self.adopt_arguments(session, pair, slot, expected)
        response = service.call("hia_adopt", arguments)
        self.assertEqual(response["status"], "completed", response)
        return response, arguments

    def rollback(self, service, session, slot, expected, generation):
        arguments = session.arguments(target_slot=slot, expected_current=expected,
            retained_generation=generation, reason="independent native slot integration")
        response = service.call("hia_rollback", arguments)
        self.assertEqual(response["status"], "completed", response)
        return response, arguments

    @contextmanager
    def journal(self, native):
        selector = "HEPTA_HIA_AGENT_JOURNAL_MANIFEST"
        if native:
            with patch.dict(os.environ, {selector: str(self.build_helper("journal"))}), \
                    patch.object(HIAAgentService, "_reference_call",
                                 side_effect=AssertionError("native journal entered hosted policy")):
                yield
        else:
            if selector in os.environ:
                raise AssertionError("ordinary journal control unexpectedly selected a native journal")
            yield

    def test_retained_exact_ten_original_cases_under_native_slot_selection(self):
        output = io.StringIO()
        loader = unittest.TestLoader()
        suite = unittest.TestSuite(loader.loadTestsFromName(name) for name in ORIGINAL_IDS)
        loaded = suite_ids(suite)
        self.assertFalse(loader.errors, loader.errors)
        self.assertEqual(loaded, list(ORIGINAL_IDS))
        environment = {"HEPTA_HIA_AGENT_JOURNAL_COLD_REPORT": str(self.cold)} if self.cold else {
            "HEPTA_HIA_AGENT_JOURNAL_DEVELOPMENT_MANIFEST": str(self.build_helper("journal"))}
        with patch.dict(os.environ, environment):
            result = unittest.TextTestRunner(stream=output, verbosity=2,
                                             resultclass=RecordingResult).run(suite)
        (self.root / "retained-original-tests.log").write_text(output.getvalue())
        write_json(self.root / "retained-original-tests.json", {
            "loaded_ids": loaded, "executed_ids": result.executed_ids,
            "tests_run": result.testsRun, "errors": [case.id() for case, _ in result.errors],
            "failures": [case.id() for case, _ in result.failures],
            "skips": [case.id() for case, _ in result.skipped],
            "expected_failures": [case.id() for case, _ in result.expectedFailures],
            "unexpected_successes": [case.id() for case in result.unexpectedSuccesses],
            "matching_current_source_cold_qualified": bool(self.cold)})
        self.assertEqual(result.executed_ids, list(ORIGINAL_IDS), output.getvalue())
        self.assertEqual(result.testsRun, 10, output.getvalue())
        self.assertTrue(result.wasSuccessful(), output.getvalue())
        self.assertFalse(result.errors or result.failures or result.skipped or
                         result.expectedFailures or result.unexpectedSuccesses, output.getvalue())
        self.assertTrue(self.transitions, "retained real slot callers did not enter native image")

    def test_real_evaluation_acceptance_and_refusal_replay_keep_original_state(self):
        objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
            "required_claims": ["core_admission", "encoding_check"],
            "allow_unchanged": True, "min_improvement_ratio": 0.0}
        same = add_program(optimized=True)
        cases = (
            ("unchanged-accepted", same, same, objective, None, "unchanged", None),
            ("unchanged-refused", same, same, objective | {"allow_unchanged": False},
             None, "unchanged", "E_HIA_EVALUATION_REQUIRED"),
            ("net-benefit-refused", same, same, objective | {"require_net_benefit": True},
             None, "unchanged", "E_HIA_COST_INCOMPLETE"),
            ("incorrect-refused", add_program(), add_program(optimized=True, increment=8),
             objective, None, "incorrect", "E_HIA_EVALUATION_REQUIRED"),
            ("incomplete-refused", add_program(), same, objective,
             {"max_native_wall_ms": 1}, "budget_exceeded", "E_HIA_EVALUATION_REQUIRED"),
        )
        for native_journal in (False, True):
            with self.journal(native_journal):
                for label, source, candidate, goal, budget, outcome, error in cases:
                    with self.subTest(native_journal=native_journal, case=label):
                        name = label + ("-native-journal" if native_journal else "-journal")
                        service, session = self.service(name)
                        case = AgentToolCase()
                        case.service, case.session = service, session
                        _base, _candidate, baseline, built, receipts = case.build_pair(
                            document=source, candidate=candidate, objective=goal, budget=budget)
                        evaluation = session.evaluate(baseline, built, receipts=receipts)
                        self.assertEqual(evaluation["outcome"], outcome)
                        pair = {"built": built, "receipts": receipts, "evaluation": evaluation}
                        arguments = self.adopt_arguments(session, pair, "evaluation",
                                                        {"generation": "0", "epoch": "0"})
                        before = state_rows(service)
                        at = len(self.transitions)
                        response = service.call("hia_adopt", arguments)
                        operations = [int.from_bytes(bytes.fromhex(row["request_hex"])[8:16], "little")
                                      for row in self.transitions[at:]]
                        self.assertTrue(operations)
                        self.assertEqual(operations[0], 17)
                        if error is None:
                            self.assertEqual(response["status"], "completed", response)
                            self.assertEqual(response["result"]["current"], {"generation": "1", "epoch": "1"})
                            self.assertEqual(operations[:5], [17, 17, 17, 18, 19])
                            lease = service.acquire_slot("evaluation")
                            invoked = service.invoke_lease(lease, "transform", [250])
                            self.assertEqual(invoked["values"], [1])
                            self.assertEqual(invoked["artifact"], built["native_artifact"])
                            service.release_slot(lease)
                        else:
                            self.assertEqual(response["error"]["code"], error, response)
                            self.assertEqual(state_rows(service), before)
                            self.assertNotIn(12, operations, "rejected evaluation reached adoption mutation")
                            if label == "incomplete-refused":
                                self.assertEqual(operations, [17, 17])
                            elif error == "E_HIA_COST_INCOMPLETE":
                                self.assertEqual(operations, [17, 17, 17, 18, 19])
                            else:
                                self.assertEqual(operations, [17, 17, 17, 18])
                        service.close()
                        self.services.remove(service)
                        restarted = HIAAgentService(self.root / name,
                                                   artifact_roots=(self.root / (name + "-files"),))
                        self.services.append(restarted)
                        before_replay = database_rows(restarted)
                        at = len(self.transitions)
                        self.assertEqual(restarted.call("hia_adopt", arguments), response)
                        self.assertEqual(database_rows(restarted), before_replay)
                        self.assertEqual(len(self.transitions), at, "replay repeated native admission or effects")
                        self.observations.append({"case": label, "native_journal": native_journal,
                            "actual_evaluation": evaluation, "adoption": response,
                            "native_operations": operations, "restart_rows": before_replay})

    def test_all_retained_numeric_generations_stream_and_u64_exhaustion_is_atomic(self):
        service, session = self.service()
        pair = self.pair(service, session)
        adopted, _ = self.adopt(service, session, pair, "history", {"generation": "0", "epoch": "0"})
        rolled, _ = self.rollback(service, session, "history", adopted["result"]["current"], "0")
        # Synthetic persisted history uses real issued artifact descriptors.  It
        # is setup data, never a substituted policy result or fake receipt.
        descriptor = wire(pair["built"]["native_artifact"]).decode()
        with service.store.transaction():
            service.store.db.executemany("INSERT INTO versions VALUES (?,?,?)",
                [("history", str(value), descriptor) for value in range(2, 4098)])
            service.store.db.execute("INSERT INTO versions VALUES (?,?,?)",
                ("history", "18446744073709551614", descriptor))
        self.observations.append({"synthetic_retained_history_rows": 4097,
                                  "artifact": pair["built"]["native_artifact"]})
        advanced, _ = self.adopt(service, session, pair, "history", rolled["result"]["current"])
        self.assertEqual(advanced["result"]["current"], {"generation": "18446744073709551615", "epoch": "3"})
        retained = list(service.store.db.execute("SELECT generation FROM versions WHERE slot=?", ("history",)))
        self.assertEqual(len(retained), 4100)
        restored, _ = self.rollback(service, session, "history", advanced["result"]["current"], "0")
        before = state_rows(service)
        arguments = self.adopt_arguments(session, pair, "history", restored["result"]["current"])
        refused = service.call("hia_adopt", arguments)
        self.assertEqual(refused["error"]["code"], "E_HIA_GENERATION_EXHAUSTED", refused)
        self.assertEqual(state_rows(service), before)
        self.observations.append({"success": advanced, "overflow": refused, "rows": database_rows(service)})
        with service.store.transaction():
            service.store.db.execute("UPDATE slots SET epoch=? WHERE name=?",
                                     ("18446744073709551615", "history"))
        before = state_rows(service)
        arguments = session.arguments(target_slot="history",
            expected_current={"generation": "0", "epoch": "18446744073709551615"},
            retained_generation="0", reason="retained u64 epoch exhaustion")
        refused = service.call("hia_rollback", arguments)
        self.assertEqual(refused["error"]["code"], "E_HIA_GENERATION_EXHAUSTED", refused)
        self.assertEqual(state_rows(service), before)

    def test_arbitrary_retained_generation_and_current_generation_rollback_increment_epoch(self):
        service, session = self.service()
        pair = self.pair(service, session)
        current = {"generation": "0", "epoch": "0"}
        adopted = []
        for generation in ("1", "2", "3"):
            response, _ = self.adopt(service, session, pair, "arbitrary", current)
            self.assertEqual(response["result"]["current"]["generation"], generation)
            adopted.append(response)
            current = response["result"]["current"]
            if generation != "3":
                restored, _ = self.rollback(service, session, "arbitrary", current, "0")
                current = restored["result"]["current"]
        older, _ = self.rollback(service, session, "arbitrary", current, "1")
        self.assertEqual(older["result"]["current"], {"generation": "1", "epoch": "6"})
        same, arguments = self.rollback(service, session, "arbitrary", older["result"]["current"], "1")
        self.assertEqual(same["result"]["current"], {"generation": "1", "epoch": "7"})
        self.assertFalse(same["result"]["past_effects_reversed"])
        self.assertEqual(same["result"]["active_artifact"], pair["built"]["native_artifact"])
        before = database_rows(service)
        count = len(self.transitions)
        self.assertEqual(service.call("hia_rollback", arguments), same)
        self.assertEqual(database_rows(service), before)
        self.assertEqual(len(self.transitions), count)
        self.observations.append({"adoptions": adopted, "arbitrary_rollback": older,
                                  "same_generation_rollback": same, "rows": before})

    def test_cross_generation_leases_keep_complete_descriptor_and_real_native_result(self):
        service, session = self.service()
        pair = self.pair(service, session)
        adopted, _ = self.adopt(service, session, pair, "leased", {"generation": "0", "epoch": "0"})
        old = service.acquire_slot("leased")
        rolled, _ = self.rollback(service, session, "leased", adopted["result"]["current"], "0")
        new = service.acquire_slot("leased")
        self.assertNotEqual(old["generation"], new["generation"])
        self.assertEqual(service.inspect_slot("leased")["in_flight_leases"], 2)
        for lease in (old, new):
            actual = service.invoke_lease(lease, "transform", [250])
            self.assertEqual(actual["status"], "returned", actual)
            self.assertEqual(actual["values"], [1])
            self.assertEqual(actual["generation"], lease["generation"])
            self.assertEqual(actual["artifact"], lease["artifact"])
            self.observations.append({"lease": deepcopy(lease), "native_observation": actual})
        reordered = dict(reversed(tuple(old.items())))
        reordered["artifact"] = dict(reversed(tuple(old["artifact"].items())))
        equivalent = service.invoke_lease(reordered, "transform", [250])
        self.assertEqual(equivalent["values"], [1])
        self.assertEqual(equivalent["artifact"], old["artifact"])
        self.assertEqual(equivalent["generation"], old["generation"])
        bad_leases = []
        for name, replacement in (("id", "a-forged"), ("uri", "hia://artifacts/forged"), ("sha256", "0" * 64)):
            forged = deepcopy(old)
            forged["artifact"][name] = replacement
            bad_leases.append(("changed artifact " + name, forged, "E_HIA_LEASE"))
        extra = deepcopy(old)
        extra["artifact"]["unissued"] = "must not be discarded"
        bad_leases.append(("extra artifact field", extra, "E_HIA_LEASE"))
        for name in ("id", "sha256", "uri"):
            missing = deepcopy(old)
            del missing["artifact"][name]
            bad_leases.append(("missing artifact " + name, missing, "E_HIA_LEASE"))
        for name, value in (("id", 1), ("sha256", False), ("uri", None)):
            wrong_type = deepcopy(old)
            wrong_type["artifact"][name] = value
            bad_leases.append(("wrong artifact type " + name, wrong_type, "E_HIA_LEASE"))
        for value in (None, [], "not a descriptor", 1, True, b"not a descriptor"):
            wrong_type = deepcopy(old)
            wrong_type["artifact"] = value
            bad_leases.append(("non-object artifact " + type(value).__name__, wrong_type, "E_HIA_LEASE"))
        for value in (1, True, 1.0, None, [], {}, b"1"):
            wrong_type = deepcopy(old)
            wrong_type["generation"] = value
            bad_leases.append(("non-string generation " + type(value).__name__, wrong_type, "E_HIA_LEASE"))
        missing_outer = deepcopy(old)
        del missing_outer["artifact"]
        bad_leases.append(("missing outer key", missing_outer, "E_HIA_FIELDS"))
        extra_outer = {**deepcopy(old), "unissued": "must not be discarded"}
        bad_leases.append(("extra outer key", extra_outer, "E_HIA_FIELDS"))
        before_bad_lease = state_rows(service)
        def reject_lease(label, value, expected):
            with self.subTest(lease_case=label), patch("hepta.hia_agent_runner.run_native_batch",
                       side_effect=AssertionError("foreign descriptor reached native runner")):
                with self.assertRaises(AgentRejected) as raised:
                    service.invoke_lease(value, "transform", [250])
                self.assertEqual(raised.exception.code, expected)
                self.observations.append({"lease_refusal": label, "caller_repr": repr(value),
                                          "code": raised.exception.code})
        for label, value, expected in bad_leases:
            reject_lease(label, value, expected)
        self.assertEqual(state_rows(service), before_bad_lease)
        stored = service.store.db.execute("SELECT artifact FROM leases WHERE id=?", (old["id"],)).fetchone()[0]
        blob = wire(old["artifact"])
        retained_payloads = (
            ("malformed TEXT", "not-json", "text"),
            ("valid JSON BLOB", sqlite3.Binary(blob), "blob"),
            ("invalid JSON BLOB", sqlite3.Binary(b"not-json"), "blob"),
            ("non-UTF8 BLOB", sqlite3.Binary(b"\xff"), "blob"),
        )
        try:
            # SQLite TEXT affinity still permits BLOB values.  The original
            # decoder accepts valid JSON bytes, so the selected owner must too.
            service.store.db.execute("UPDATE leases SET artifact=? WHERE id=?",
                                     (sqlite3.Binary(blob), old["id"]))
            stored_blob, storage_type = service.store.db.execute(
                "SELECT artifact,typeof(artifact) FROM leases WHERE id=?", (old["id"],)).fetchone()
            self.assertEqual(storage_type, "blob")
            self.assertIs(type(stored_blob), bytes)
            self.assertEqual(stored_blob, blob)
            count = len(self.transitions)
            from_blob = service.invoke_lease(old, "transform", [250])
            self.assertEqual(from_blob["status"], "returned")
            self.assertEqual(from_blob["values"], [1])
            self.assertEqual(from_blob["artifact"], old["artifact"])
            self.assertEqual(from_blob["generation"], old["generation"])
            self.assertGreater(len(self.transitions), count)
            self.assertEqual(service.store.db.execute(
                "SELECT artifact FROM leases WHERE id=?", (old["id"],)).fetchone()[0], blob)
            self.observations.append({"fixture": "real SQLite valid JSON BLOB artifact",
                                      "stored_type": storage_type,
                                      "stored_sha256": sha256(blob).hexdigest(),
                                      "native_observation": from_blob})
            for payload_label, payload, expected_type in retained_payloads:
                service.store.db.execute("UPDATE leases SET artifact=? WHERE id=?", (payload, old["id"]))
                self.assertEqual(service.store.db.execute(
                    "SELECT typeof(artifact) FROM leases WHERE id=?", (old["id"],)).fetchone()[0], expected_type)
                for label, value, expected in (
                    ("unknown row before nested fields", {**deepcopy(old), "id": "lease-not-issued", "artifact": None}, "E_HIA_LEASE"),
                    ("slot mismatch before stored decoder", {**deepcopy(old), "slot": "foreign-slot", "artifact": None}, "E_HIA_LEASE"),
                    ("generation type before stored decoder", {**deepcopy(old), "generation": 1, "artifact": None}, "E_HIA_LEASE"),
                    ("generation mismatch before stored decoder", {**deepcopy(old), "generation": "0", "artifact": None}, "E_HIA_LEASE"),
                    ("outer missing before stored decoder", missing_outer, "E_HIA_FIELDS"),
                    ("outer extra before stored decoder", extra_outer, "E_HIA_FIELDS")):
                    reject_lease(payload_label + ": " + label, value, expected)
        finally:
            service.store.db.execute("UPDATE leases SET artifact=? WHERE id=?", (stored, old["id"]))
        self.assertEqual(state_rows(service), before_bad_lease)
        self.assertEqual(service.release_slot(old),
                         {"released": True, "generation": "1", "artifact_retained": True})
        self.assertEqual(service.inspect_slot("leased")["in_flight_leases"], 1)
        with self.assertRaises(AgentRejected) as raised:
            service.release_slot(old)
        self.assertEqual(raised.exception.code, "E_HIA_LEASE")
        # The original inactive-row check precedes artifact decoding.  This
        # deliberately damaged inactive row must keep that refusal order.
        retained_row = service.store.db.execute("SELECT artifact FROM leases WHERE id=?", (old["id"],)).fetchone()[0]
        try:
            for payload_label, payload, expected_type in retained_payloads:
                service.store.db.execute("UPDATE leases SET artifact=? WHERE id=?", (payload, old["id"]))
                self.assertEqual(service.store.db.execute(
                    "SELECT typeof(artifact) FROM leases WHERE id=?", (old["id"],)).fetchone()[0], expected_type)
                reject_lease("inactive row before decoder: " + payload_label, old, "E_HIA_LEASE")
                with self.subTest(inactive_release_payload=payload_label), self.assertRaises(AgentRejected) as raised:
                    service.release_slot(old)
                self.assertEqual(raised.exception.code, "E_HIA_LEASE")
                self.observations.append({"fixture": "inactive " + payload_label,
                                          "release_refusal_code": raised.exception.code})
        finally:
            service.store.db.execute("UPDATE leases SET artifact=? WHERE id=?", (retained_row, old["id"]))
        service.release_slot(new)
        self.assertEqual(service.inspect_slot("leased")["in_flight_leases"], 0)
        self.assertTrue(service.store.get(old["artifact"])[0])
        self.assertTrue(service.store.get(new["artifact"])[0])
        self.observations.append({"rollback": rolled, "rows": database_rows(service)})

    def test_same_service_serial_cross_thread_acquire_and_release_keeps_original_contract(self):
        service, session = self.service()
        pair = self.pair(service, session)
        self.adopt(service, session, pair, "threaded", {"generation": "0", "epoch": "0"})
        result, errors = [], []
        def consumer():
            try:
                lease = service.acquire_slot("threaded")
                acquired = service.inspect_slot("threaded")
                release = service.release_slot(lease)
                result.append({"lease": lease, "acquired": acquired, "release": release})
            except BaseException as error:
                errors.append(error)
        child = threading.Thread(target=consumer, name="ordinary-slot-consumer")
        child.start()
        child.join(timeout=15)
        self.assertFalse(child.is_alive(), "ordinary service serial consumer did not finish")
        self.assertFalse(errors, errors)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["acquired"]["in_flight_leases"], 1)
        self.assertTrue(result[0]["release"]["released"])
        self.assertEqual(service.inspect_slot("threaded")["in_flight_leases"], 0)
        self.observations.extend(result)

    def request_row(self, service, tool, arguments):
        identity = sha256(wire({"tool": tool, "arguments": arguments})).hexdigest()
        rows = list(service.store.db.execute("SELECT * FROM requests WHERE digest=? AND tool=?",
                                             (identity, tool)))
        self.assertLessEqual(len(rows), 1)
        return dict(rows[0]) if rows else None

    @contextmanager
    def commit_fault(self, service, committed):
        original = service.store.transaction
        calls = 0
        @contextmanager
        def transaction():
            nonlocal calls
            calls += 1
            target = calls == 2
            with original():
                yield
                if target and not committed:
                    # The real original context manager executes ROLLBACK.
                    raise sqlite3.OperationalError("slot effect commit acknowledgement lost")
            if target and committed:
                # The real original context manager has completed COMMIT.
                raise sqlite3.OperationalError("slot effect commit acknowledgement lost")
        with patch.object(service.store, "transaction", transaction):
            yield
        self.assertEqual(calls, 2, "reservation and effect must use the original two transactions")

    def test_actual_slot_effect_and_exact_response_share_commit_ack_outcome(self):
        for native in (False, True):
            for committed in (False, True):
                with self.subTest(native_journal=native, committed=committed), self.journal(native):
                    service, session = self.service("commit-%s-%s" % (native, committed))
                    pair = self.pair(service, session)
                    arguments = self.adopt_arguments(session, pair, "atomic", {"generation": "0", "epoch": "0"})
                    before = state_rows(service)
                    sql = []
                    service.store.db.set_trace_callback(sql.append)
                    try:
                        with self.commit_fault(service, committed):
                            first = service.call("hia_adopt", arguments)
                    finally:
                        service.store.db.set_trace_callback(None)
                    self.assertEqual(first["status"], "rejected", first)
                    row = self.request_row(service, "hia_adopt", arguments)
                    self.assertIsNotNone(row)
                    count = len(self.transitions)
                    if committed:
                        self.assertEqual(row["state"], "completed")
                        stored = json.loads(row["response"])
                        self.assertEqual(stored["status"], "completed")
                        self.assertEqual(stored["result"]["current"], {"generation": "1", "epoch": "1"})
                        self.assertEqual(service.inspect_slot("atomic")["active_artifact"],
                                         pair["built"]["native_artifact"])
                        session.read_json(stored["result"]["adoption_receipt"])
                        unchanged = database_rows(service)
                        count = len(self.transitions)
                        replay = service.call("hia_adopt", arguments)
                        self.assertEqual(replay, stored)
                        self.assertEqual(database_rows(service), unchanged)
                        self.assertEqual(len(self.transitions), count)
                        self.assertEqual([statement for statement in sql if statement in
                            ("BEGIN IMMEDIATE", "COMMIT", "ROLLBACK")],
                            ["BEGIN IMMEDIATE", "COMMIT", "BEGIN IMMEDIATE", "COMMIT"])
                    else:
                        self.assertEqual(state_rows(service), before)
                        self.assertEqual((row["state"], row["response"]), ("running", None))
                        replay = service.call("hia_adopt", arguments)
                        self.assertEqual(replay["error"]["code"], "E_HIA_REQUEST_UNKNOWN")
                        self.assertEqual(replay["error"]["retry_action"], "observe_original")
                        self.assertEqual(len(self.transitions), count)
                        self.assertEqual(state_rows(service), before)
                        self.assertEqual([statement for statement in sql if statement in
                            ("BEGIN IMMEDIATE", "COMMIT", "ROLLBACK")],
                            ["BEGIN IMMEDIATE", "COMMIT", "BEGIN IMMEDIATE", "ROLLBACK"])
                    self.observations.append({"native_journal": native, "committed": committed,
                        "first": first, "replay": replay, "request": row, "sql": sql,
                        "rows": database_rows(service)})

    def test_actual_slot_native_journal_ack_failure_rolls_back_without_terminal_success(self):
        from hepta.hia_agent_journal_native import JournalSession
        with self.journal(True):
            service, session = self.service()
            pair = self.pair(service, session)
            for operation in ("reserved", "inline", "committed_inline"):
                for after in (False, True):
                    for exception in (RuntimeError, KeyboardInterrupt, SystemExit, MemoryError):
                        with self.subTest(operation=operation, after=after, exception=exception.__name__):
                            slot = "ack-%s-%s-%s" % (operation, after, exception.__name__)
                            arguments = self.adopt_arguments(session, pair, slot,
                                                             {"generation": "0", "epoch": "0"})
                            before = database_rows(service)
                            original = getattr(JournalSession, operation)
                            def fail(journal, *args):
                                if after:
                                    original(journal, *args)
                                raise exception("actual slot native acknowledgement failure")
                            with patch.object(JournalSession, operation, fail):
                                with self.assertRaisesRegex(exception, "native acknowledgement failure"):
                                    service.call("hia_adopt", arguments)
                            observed = database_rows(service)
                            for table in ("slots", "versions", "leases", "artifacts", "costs"):
                                self.assertEqual(observed[table], before[table], table)
                            row = self.request_row(service, "hia_adopt", arguments)
                            if operation == "reserved":
                                self.assertIsNone(row)
                                self.assertEqual(observed["requests"], before["requests"])
                                replay = None
                            else:
                                self.assertEqual((row["state"], row["response"]), ("running", None))
                                count = len(self.transitions)
                                replay = service.call("hia_adopt", arguments)
                                self.assertEqual(replay["error"]["code"], "E_HIA_REQUEST_UNKNOWN")
                                self.assertEqual(len(self.transitions), count)
                                self.assertEqual(state_rows(service),
                                    {table: before[table] for table in ("slots", "versions", "leases", "artifacts")})
                            self.observations.append({"operation": operation, "after_ack": after,
                                "exception": exception.__name__, "request": row,
                                "replay": replay, "rows_after_failure": observed})

    def child_environment(self, native):
        result = dict(self.clean_environment)
        result[SELECTOR] = str(self.manifest)
        result["PYTHONDONTWRITEBYTECODE"] = "1"
        if native:
            result["HEPTA_HIA_AGENT_JOURNAL_MANIFEST"] = str(self.build_helper("journal"))
        return result

    def child_script(self, purpose):
        # Both subprocess controls call the real service and real image.  Only
        # the original transaction boundary or post-effect checkpoint is held.
        script = r"""
import json, pathlib, signal, sys
from contextlib import contextmanager
from hashlib import sha256
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_slot_ledger_native import NativeSlotLedger
from hepta.hia_agent_store import wire
REFERENCE = @REFERENCE@
def forbidden(*args, **kwargs):
    raise AssertionError("child entered retained slot policy")
for name in REFERENCE:
    setattr(HIAAgentService, name, forbidden)
mode, root, request_path, marker_path, native, *artifact_roots = sys.argv[1:]
if native == "True":
    HIAAgentService._reference_call = forbidden
request = json.loads(pathlib.Path(request_path).read_bytes())
frames = []
original_transition = NativeSlotLedger.transition
def observed(image, raw, state=None):
    receipt = original_transition(image, raw, state)
    frames.append({"request_hex": bytes(raw).hex(), "output_hex": receipt.raw.hex(),
        "fields_hex": [value.hex() for value in receipt.fields],
        "image_sha256": sha256(bytes(image._mapping)).hexdigest()})
    return receipt
NativeSlotLedger.transition = observed
service = HIAAgentService(root, artifact_roots=artifact_roots)
def checkpoint(value):
    record = {"mode": mode, "in_transaction": service.store.db.in_transaction,
        "value": value, "native_frames": frames,
        "artifact_roots": [str(path) for path in service.artifact_roots],
        "requests": [list(row) for row in service.store.db.execute("SELECT * FROM requests ORDER BY key")],
        "slots": [list(row) for row in service.store.db.execute("SELECT * FROM slots ORDER BY name")],
        "versions": [list(row) for row in service.store.db.execute("SELECT * FROM versions ORDER BY slot,generation")]}
    pathlib.Path(marker_path).write_bytes(wire(record) + b"\n")
    print("slot-checkpoint", flush=True)
if mode == "kill-before-commit":
    original_adopt = service._hia_adopt
    def stopped(arguments):
        result = original_adopt(arguments)
        checkpoint(result)
        signal.pause()
        return result
    service._hia_adopt = stopped
else:
    original_transaction = service.store.transaction
    count = 0
    @contextmanager
    def transaction():
        global count
        count += 1
        target = count == 2
        if target and mode == "cas":
            print("slot-ready", flush=True)
            if sys.stdin.buffer.readline() != b"go\n":
                raise AssertionError("CAS coordinator did not release original transaction")
        with original_transaction():
            yield
        if target and mode == "kill-after-commit":
            checkpoint(None)
            signal.pause()
    service.store.transaction = transaction
try:
    response = service.call("hia_adopt", request)
    pathlib.Path(marker_path).write_bytes(wire({"response": response, "native_frames": frames}) + b"\n")
    print(json.dumps(response, sort_keys=True), flush=True)
finally:
    service.close()
"""
        script = script.replace("@REFERENCE@", repr(REFERENCE_SLOT_METHODS))
        (self.root / (purpose + ".py")).write_text(script)
        return script

    def spawn_owned(self, command, environment, prefix, *, input_pipe=False):
        write_json(prefix.with_suffix(".command.json"), {"command": command,
            "selected_images": {name: value for name, value in environment.items()
                if name.startswith("HEPTA_HIA_") and name.endswith("_MANIFEST")}})
        child = subprocess.Popen(command, cwd=ROOT, env=environment,
            stdin=subprocess.PIPE if input_pipe else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child._slot_prefix, child._slot_consumed, child._slot_collected = prefix, b"", False
        self.addCleanup(self.cleanup_owned, child)
        return child

    def collect_owned(self, child, timeout):
        prefix = child._slot_prefix
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            prefix.with_suffix(".timeout.stdout").write_bytes(child._slot_consumed + (error.stdout or b""))
            prefix.with_suffix(".timeout.stderr").write_bytes(error.stderr or b"")
            write_json(prefix.with_suffix(".timeout.json"), {"timeout_seconds": timeout,
                "child_pid": child.pid, "native_result_not_confirmed": True})
            raise
        child._slot_collected = True
        prefix.with_suffix(".stdout").write_bytes(child._slot_consumed + stdout)
        prefix.with_suffix(".stderr").write_bytes(stderr)
        write_json(prefix.with_suffix(".process.json"), {"returncode": child.returncode,
            "child_pid": child.pid, "complete_output": True})
        return stdout, stderr

    def cleanup_owned(self, child):
        if child._slot_collected:
            return
        if child.poll() is None:
            child.kill()
        self.collect_owned(child, 5)

    def await_line(self, child, expected):
        ready, _, _ = select.select([child.stdout], [], [], 15)
        self.assertTrue(ready, "owned child did not reach original transaction checkpoint")
        line = child.stdout.readline()
        child._slot_consumed += line
        child._slot_prefix.with_suffix(".checkpoint.stdout").write_bytes(child._slot_consumed)
        self.assertEqual(line, expected, "owned child missed checkpoint")
        return line

    def test_two_real_connections_compete_on_original_transaction_and_loser_has_readable_snapshot(self):
        for native in (False, True):
            with self.subTest(native_journal=native), self.journal(native):
                service, session = self.service("cas-" + str(native))
                pair = self.pair(service, session)
                arguments = [self.adopt_arguments(session, pair, "contended",
                             {"generation": "0", "epoch": "0"}) for _ in range(2)]
                script = self.child_script("cas-" + str(native))
                children, results = [], []
                try:
                    for index, request in enumerate(arguments):
                        request_path = self.root / ("cas-%s-%s-request.json" % (native, index))
                        marker = self.root / ("cas-%s-%s-result.json" % (native, index))
                        write_json(request_path, request)
                        command = [sys.executable, "-B", "-E", "-s", "-c", script, "cas",
                            str(service.store.root), str(request_path), str(marker), str(native),
                            *[str(path) for path in service.artifact_roots]]
                        prefix = self.root / ("cas-%s-%s" % (native, index))
                        child = self.spawn_owned(command, self.child_environment(native), prefix, input_pipe=True)
                        children.append((child, marker, command, index))
                    for child, _, _, _ in children:
                        self.await_line(child, b"slot-ready\n")
                    for child, _, _, _ in children:
                        child.stdin.write(b"go\n")
                        child.stdin.flush()
                    for child, marker, command, index in children:
                        stdout, stderr = self.collect_owned(child, 15)
                        self.assertEqual(child.returncode, 0, stderr.decode(errors="replace"))
                        result = json.loads(marker.read_bytes())
                        self.assertTrue(result["native_frames"])
                        self.assertEqual(json.loads(stdout), result["response"])
                        results.append(result)
                finally:
                    for child, _, _, _ in children:
                        self.cleanup_owned(child)
                successes = [row["response"] for row in results if row["response"]["status"] == "completed"]
                refusals = [row["response"] for row in results if row["response"]["status"] == "rejected"]
                self.assertEqual(len(successes), 1, results)
                self.assertEqual(len(refusals), 1, results)
                self.assertEqual(successes[0]["result"]["current"], {"generation": "1", "epoch": "1"})
                self.assertEqual(refusals[0]["error"]["code"], "E_HIA_GENERATION_STALE")
                self.assertEqual(refusals[0]["error"]["retry_action"], "refresh_context")
                diagnostic = session.read_json(refusals[0]["error"]["details_artifact"])
                self.assertEqual(diagnostic["current"], successes[0]["result"]["current"])
                self.assertEqual(diagnostic["active_artifact"], pair["built"]["native_artifact"])
                self.assertFalse(diagnostic["snapshot_is_adoption_authority"])
                self.assertEqual([row[0] for row in service.store.db.execute(
                    "SELECT generation FROM versions WHERE slot=? ORDER BY generation", ("contended",))],
                    ["0", "1"])
                self.assertEqual(service.inspect_slot("contended")["current"], {"generation": "1", "epoch": "1"})
                self.observations.append({"native_journal": native, "child_results": results,
                    "diagnostic": diagnostic, "rows": database_rows(service)})

    def preserve_table_comparison(self, label, before, after, artifact_directory):
        # Preserve complete original rows before any equality assertion.  A
        # newly issued artifact remains evidence even when that assertion fails.
        additions = []
        previous = before.get("artifacts", [])
        for row in after.get("artifacts", []):
            if row in previous:
                continue
            raw = (Path(artifact_directory) / row[1]).read_bytes()
            path = self.root / ("%s-added-artifact-%03d.bin" % (label, len(additions)))
            path.write_bytes(raw)
            additions.append({"row": list(row), "original_content": file_identity(path),
                "content_matches_row_sha256": sha256(raw).hexdigest() == row[1]})
        write_json(self.root / (label + "-tables.json"), {
            "before": before, "after": after, "added_artifacts": additions})

    def test_real_process_death_before_and_after_atomic_slot_commit_observes_original_intent(self):
        for native in (False, True):
            for committed in (False, True):
                with self.subTest(native_journal=native, committed=committed), self.journal(native):
                    name = "kill-%s-%s" % (native, committed)
                    service, session = self.service(name)
                    pair = self.pair(service, session)
                    request = self.adopt_arguments(session, pair, "killed", {"generation": "0", "epoch": "0"})
                    request_path = self.root / (name + "-request.json")
                    marker = self.root / (name + "-checkpoint.json")
                    write_json(request_path, request)
                    before = state_rows(service)
                    before_database = database_rows(service)
                    write_json(self.root / (name + "-before-tables.json"), before_database)
                    script = self.child_script(name)
                    mode = "kill-after-commit" if committed else "kill-before-commit"
                    command = [sys.executable, "-B", "-E", "-s", "-c", script, mode,
                        str(service.store.root), str(request_path), str(marker), str(native),
                        *[str(path) for path in service.artifact_roots]]
                    child = self.spawn_owned(command, self.child_environment(native), self.root / name)
                    try:
                        line = self.await_line(child, b"slot-checkpoint\n")
                        checkpoint = json.loads(marker.read_bytes())
                        self.assertTrue(checkpoint["native_frames"])
                        self.assertEqual(checkpoint["in_transaction"], not committed)
                        self.assertEqual(checkpoint["artifact_roots"],
                                         [str(path) for path in service.artifact_roots])
                        self.preserve_table_comparison(name + "-checkpoint", before_database,
                            database_rows(service), service.store.artifacts)
                        if committed:
                            self.assertEqual(service.inspect_slot("killed")["current"],
                                             {"generation": "1", "epoch": "1"})
                        else:
                            self.assertEqual(state_rows(service), before)
                        child.kill()
                        stdout, stderr = self.collect_owned(child, 5)
                        self.assertEqual(child.returncode, -9)
                    finally:
                        self.cleanup_owned(child)
                    restarted = HIAAgentService(service.store.root,
                                                artifact_roots=service.artifact_roots)
                    self.services.append(restarted)
                    before_replay = database_rows(restarted)
                    self.preserve_table_comparison(name + "-reopened", before_database,
                        before_replay, service.store.artifacts)
                    count = len(self.transitions)
                    replay = restarted.call("hia_adopt", request)
                    self.assertEqual(len(self.transitions), count)
                    row = self.request_row(restarted, "hia_adopt", request)
                    self.preserve_table_comparison(name + "-replay", before_replay,
                        database_rows(restarted), service.store.artifacts)
                    if committed:
                        self.assertEqual(row["state"], "completed")
                        self.assertEqual(replay, json.loads(row["response"]))
                        self.assertEqual(replay["status"], "completed")
                        self.assertEqual(database_rows(restarted), before_replay)
                    else:
                        self.assertEqual((row["state"], row["response"]), ("running", None))
                        self.assertEqual(replay["error"]["code"], "E_HIA_REQUEST_UNKNOWN")
                        self.assertEqual(replay["error"]["retry_action"], "observe_original")
                        self.assertEqual(state_rows(restarted), before)
                    self.observations.append({"native_journal": native, "committed": committed,
                        "command": command, "returncode": child.returncode, "checkpoint": checkpoint,
                        "request": row, "replay": replay, "rows": database_rows(restarted)})

    def bundle(self):
        from hepta.hia_native_helpers import ABI, SCHEMA, TARGET
        entries = []
        for name in ("slot", "journal", "execution", "candidate", "retirement"):
            manifest = self.build_helper(name)
            module = self.helper_modules[name]
            entries.append({"selector": module.SELECTOR, "manifest_path": str(manifest),
                            "manifest_sha256": sha256(manifest.read_bytes()).hexdigest()})
        path = self.root / "native-state-owners.json"
        write_json(path, {"schema": SCHEMA, "target": TARGET, "abi": ABI, "helpers": entries})
        return path, sha256(path.read_bytes()).hexdigest()

    @contextmanager
    def no_hosted_state_policy(self):
        from hepta import hia_execution_budget as budget, hia_native_retirement as retirement
        with ExitStack() as stack:
            for owner, names in (
                (HIAAgentService, ("_reference_call", "_reference_consume_attempt")),
                (budget._ReferenceExecutionBudgetStore, ("__init__", "create", "claim", "observe")),
                (budget._ReferenceBudgetClaim, ("__init__", "run", "complete")),
                (retirement._ReferencePathIdentityPin, ("__init__",)),
                (retirement._ReferenceNativeRetirement, ("__init__",)),
                (retirement, ("_reference_observe_directory", "_reference_remove_directory"))):
                for name in names:
                    stack.enter_context(patch.object(owner, name,
                        side_effect=AssertionError("native state bundle entered hosted policy")))
            yield

    def run_recorded(self, name, command, *, cwd=None, environment=None, raw_input=None, timeout=60):
        prefix = self.root / name
        write_json(prefix.with_suffix(".command.json"), {"command": [str(value) for value in command],
            "timeout_seconds": timeout, "cwd": str(cwd or self.root)})
        if raw_input is not None:
            prefix.with_suffix(".stdin").write_bytes(raw_input)
        try:
            result = subprocess.run(command, cwd=cwd or self.root, env=environment,
                input=raw_input, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            prefix.with_suffix(".stdout").write_bytes(error.stdout or b"")
            prefix.with_suffix(".stderr").write_bytes(error.stderr or b"")
            write_json(prefix.with_suffix(".process.json"), {"timed_out": True,
                "timeout_seconds": timeout, "complete_output": False})
            raise
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        write_json(prefix.with_suffix(".process.json"), {
            "returncode": result.returncode, "timed_out": False, "complete_output": True})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_single_pinned_bundle_runs_original_budgets_slot_leases_retirement_and_worker_replay(self):
        from hepta.hia_native_helpers import native_helpers_scope, native_helpers_identity
        from hepta.hia_agent_runner import run_native_batch
        bundle, digest = self.bundle()
        native_runs = []
        def observed_run(*args, **kwargs):
            result = run_native_batch(*args, **kwargs)
            path = self.root / ("actual-native-run-%02d.json" % len(native_runs))
            write_json(path, result)
            native_runs.append({"result": file_identity(path), "wall_ns": result["wall_ns"],
                                "termination_confirmed": result["termination_confirmed"]})
            return result
        before_environment = dict(os.environ)
        with patch.dict(os.environ, self.clean_environment, clear=True), \
                native_helpers_scope(str(bundle), digest), self.no_hosted_state_policy(), \
                patch("hepta.hia_agent_runner.run_native_batch", observed_run):
            service, session = self.service()
            pair = self.pair(service, session)
            self.assertTrue(native_runs)
            adopted, arguments = self.adopt(service, session, pair, "bundle", {"generation": "0", "epoch": "0"})
            lease = service.acquire_slot("bundle")
            rolled, _ = self.rollback(service, session, "bundle", adopted["result"]["current"], "0")
            actual = service.invoke_lease(lease, "transform", [250])
            self.assertEqual(actual["values"], [1])
            self.assertEqual(actual["artifact"], pair["built"]["native_artifact"])
            self.assertEqual(actual["generation"], "1")
            service.release_slot(lease)
            row = service.store.db.execute("SELECT attempts FROM contexts WHERE id=?",
                                            (session.context["id"],)).fetchone()
            self.assertEqual(row[0], 1)
            budget = service.store.execution_budgets.observe(session.context["id"])
            self.assertGreater(int(budget["used_native_ns"]), 0)
            self.assertIsNone(budget["owner"])
            self.assertEqual(native_helpers_identity()["native_helpers_sha256"], digest)
            before_replay = database_rows(service)
            count = len(self.transitions)
            self.assertEqual(service.call("hia_adopt", arguments), adopted)
            self.assertEqual(database_rows(service), before_replay)
            self.assertEqual(len(self.transitions), count)

            # Retirement has a separate real runtime consumer.  The SQL lease
            # test above does not pretend to close that mapped-code owner.
            original = "tests.test_hia_multiversion.MultiversionNativeTests.test_rollback_changes_future_calls_and_retains_old_lease"
            loader = unittest.TestLoader()
            suite = loader.loadTestsFromName(original)
            self.assertFalse(loader.errors)
            output = io.StringIO()
            result = unittest.TextTestRunner(stream=output, verbosity=2,
                                             resultclass=RecordingResult).run(suite)
            (self.root / "actual-retirement.log").write_text(output.getvalue())
            self.assertEqual(result.executed_ids, [original], output.getvalue())
            self.assertEqual(result.testsRun, 1, output.getvalue())
            self.assertTrue(result.wasSuccessful(), output.getvalue())
            self.assertFalse(result.errors or result.failures or result.skipped or
                result.expectedFailures or result.unexpectedSuccesses, output.getvalue())
            pins = dict(service.identities)
            envelope = {"schema": "hia-agent-worker-request-v1", "tool": "hia_adopt",
                "arguments": arguments, "profile_sha256": session.profiles["compiler"]["sha256"],
                "catalog_sha256": pins["catalog_sha256"]}
            envelope["request_sha256"] = sha256(wire(envelope)).hexdigest()
            self.observations.append({"bundle": file_identity(bundle), "native_runs": native_runs,
                "adopted": adopted, "rolled_back": rolled, "native_invocation": actual,
                "attempts": row[0], "execution_budget": budget, "rows": before_replay})
            database = service.store.database
            service.close()
            self.services.remove(service)
        self.assertEqual(dict(os.environ), before_environment)
        script = r"""
import sys
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_worker import main
def forbidden(*args, **kwargs):
    raise AssertionError("worker replay entered hosted policy or repeated adoption")
for name in @REFERENCE@:
    setattr(HIAAgentService, name, forbidden)
HIAAgentService._reference_call = forbidden
HIAAgentService._reference_consume_attempt = forbidden
HIAAgentService._hia_adopt = forbidden
raise SystemExit(main(sys.argv[1:]))
""".replace("@REFERENCE@", repr(REFERENCE_SLOT_METHODS))
        (self.root / "worker-replay.py").write_text(script)
        command = [sys.executable, "-B", "-E", "-s", "-c", script,
            "--state-root", str(service.store.root), "--request-json-stdin",
            *[argument for path in service.artifact_roots
              for argument in ("--artifact-root", str(path))],
            "--native-helpers-manifest", str(bundle), "--expected-native-helpers-sha256", digest,
            "--expected-worker-sha256", pins["worker_sha256"],
            "--expected-backend-sha256", pins["backend_sha256"],
            "--expected-catalog-sha256", pins["catalog_sha256"]]
        actual = self.run_recorded("worker-replay", command, cwd=ROOT,
                                  environment=self.clean_environment, raw_input=wire(envelope), timeout=60)
        report = json.loads(actual.stdout)
        self.assertIs(report["complete"], True)
        self.assertEqual(report["response"], adopted)
        self.assertEqual(report["request_sha256"], envelope["request_sha256"])
        self.assertEqual(report["native_helpers_sha256"], digest)
        after_replay = persisted_rows(database)
        self.preserve_table_comparison("worker-replay", before_replay, after_replay,
                                       service.store.artifacts)
        self.assertEqual(after_replay, before_replay)
        self.observations.append({"worker_report": report})

    def test_bundle_unknown_factory_and_changed_selection_refuse_before_effect(self):
        from hepta.hia_native_helpers import native_helpers_scope
        from hepta.hia_json_preflight_native import _installed_json_image
        from hepta.hia_slot_ledger_native import NativeSlotLedger, SOURCE, SCHEMA
        bundle, digest = self.bundle()
        class UnregisteredSlotView(NativeSlotLedger):
            pass
        with patch.dict(os.environ, self.clean_environment, clear=True), native_helpers_scope(str(bundle), digest), \
                patch("hepta.hia_json_preflight_native._load_manifest",
                      side_effect=AssertionError("unlisted slot factory reached general loader")):
            with self.assertRaisesRegex(ValueError, "outside the pinned"):
                _installed_json_image(str(self.manifest), SOURCE, SCHEMA, UnregisteredSlotView)
            self.assertFalse((self.root / "unissued-state").exists())
        original = json.loads(bundle.read_bytes())
        unknown = deepcopy(original)
        unknown["helpers"][0]["selector"] = "HEPTA_HIA_UNKNOWN_SLOT_MANIFEST"
        path = self.root / "unknown-helper.json"
        write_json(path, unknown)
        with patch.dict(os.environ, self.clean_environment, clear=True):
            with self.assertRaises(ValueError):
                with native_helpers_scope(str(path), sha256(path.read_bytes()).hexdigest()):
                    HIAAgentService(self.root / "unissued-state")
        self.assertFalse((self.root / "unissued-state").exists())

    def test_installed_sdist_wheel_uses_packaged_slot_owner_for_actual_service_and_refuses_source_drift(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES
        from hepta.hia_native_helpers import native_helpers_scope
        bundle, digest = self.bundle()
        with patch.dict(os.environ, self.clean_environment, clear=True), \
                native_helpers_scope(str(bundle), digest), self.no_hosted_state_policy():
            service, session = self.service()
            pair = self.pair(service, session)
            arguments = self.adopt_arguments(session, pair, "installed", {"generation": "0", "epoch": "0"})
            payload = {"adopt_arguments": arguments, "context": session.context,
                "catalog_sha256": session.catalog_sha256, "identities": service.identities,
                "expected_artifact": pair["built"]["native_artifact"]}
            before = database_rows(service)
            database = service.store.database
            service.close()
            self.services.remove(service)
        payload_path = self.root / "installed-request.json"
        write_json(payload_path, payload)
        source = self.root / "source"
        source.mkdir()
        shutil.copytree(ROOT / "hepta", source / "hepta", ignore=shutil.ignore_patterns("__pycache__"))
        resources = (tuple("docs/" + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES + ENTRY_BUILD_FILES
        self.assertIn("examples/hia_bootstrap/slot_ledger.hepta", resources)
        for name in (*resources, "setup.py", "pyproject.toml", "MANIFEST.in"):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        packaging = os.environ.get("HEPTA_HIA_TEST_PACKAGING_PYTHON", sys.executable)
        self.run_recorded("sdist", [packaging, "-B", "setup.py", "sdist", "--dist-dir", str(self.root / "sdist")],
                          cwd=source, timeout=90)
        archive, = (self.root / "sdist").glob("*.tar.gz")
        with tarfile.open(archive) as tar:
            prefix = tar.getnames()[0].split("/")[0] + "/"
            for name in resources:
                self.assertEqual(tar.extractfile(prefix + name).read(), (ROOT / name).read_bytes(), name)
        self.run_recorded("wheel", [packaging, "-B", "-m", "pip", "wheel", "--no-deps", "--no-index",
            "--no-build-isolation", "--wheel-dir", str(self.root / "wheels"), str(archive)], timeout=90)
        wheel, = (self.root / "wheels").glob("*.whl")
        installed = self.root / "installed"
        self.run_recorded("install", [packaging, "-B", "-m", "pip", "install", "--no-deps", "--no-index",
            "--target", str(installed), str(wheel)], timeout=90)
        script = r"""
import importlib.abc, json, os, sys
from pathlib import Path
from hashlib import sha256
sys.path.insert(0, sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {"tools", "tests"} or fullname.startswith(("tools.", "tests.")):
            raise AssertionError("installed slot owner imported authoring/test code")
sys.meta_path.insert(0, NoAuthoring())
from hepta.hia_native_helpers import native_helpers_scope, native_helpers_identity
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import AgentRejected
from hepta.hia_slot_ledger_native import NativeSlotLedger, SOURCE
from hepta import hia_execution_budget as budget
from hepta import hia_native_retirement as retirement
def forbidden(*args, **kwargs):
    raise AssertionError("installed selected state owner entered hosted policy")
for name in @REFERENCE@:
    setattr(HIAAgentService, name, forbidden)
for owner, names in (
    (HIAAgentService, ("_reference_call", "_reference_consume_attempt")),
    (budget._ReferenceExecutionBudgetStore, ("__init__", "create", "claim", "observe")),
    (budget._ReferenceBudgetClaim, ("__init__", "run", "complete")),
    (retirement._ReferencePathIdentityPin, ("__init__",)),
    (retirement._ReferenceNativeRetirement, ("__init__",)),
    (retirement, ("_reference_observe_directory", "_reference_remove_directory"))):
    for name in names:
        setattr(owner, name, forbidden)
assert Path(sys.argv[1]).resolve() in Path(SOURCE).resolve().parents, SOURCE
assert Path(sys.argv[1]).resolve() in Path(sys.modules["hepta.hia_slot_ledger_native"].__file__).resolve().parents
payload = json.loads(Path(sys.argv[5]).read_bytes())
frames = []
original = NativeSlotLedger.transition
def observed(image, raw, state=None):
    receipt = original(image, raw, state)
    frames.append({"request_hex": bytes(raw).hex(), "output_hex": receipt.raw.hex(),
        "fields_hex": [value.hex() for value in receipt.fields],
        "image_sha256": sha256(bytes(image._mapping)).hexdigest()})
    return receipt
NativeSlotLedger.transition = observed
before_env = dict(os.environ)
with native_helpers_scope(sys.argv[2], sys.argv[3]):
    service = HIAAgentService(sys.argv[4])
    assert service.identities == payload["identities"], (service.identities, payload["identities"])
    adopted = service.call("hia_adopt", payload["adopt_arguments"])
    assert adopted["status"] == "completed", adopted
    assert adopted["result"]["current"] == {"generation": "1", "epoch": "1"}, adopted
    lease = service.acquire_slot("installed")
    rollback_arguments = {"catalog_sha256": payload["catalog_sha256"], "context": payload["context"],
        "request_key": "installed-slot-rollback", "target_slot": "installed",
        "expected_current": adopted["result"]["current"], "retained_generation": "0",
        "reason": "installed native policy restores retained generation"}
    rolled = service.call("hia_rollback", rollback_arguments)
    assert rolled["status"] == "completed", rolled
    actual = service.invoke_lease(lease, "transform", [250])
    assert actual["status"] == "returned" and actual["values"] == [1], actual
    assert actual["artifact"] == payload["expected_artifact"] and actual["generation"] == "1", actual
    released = service.release_slot(lease)
    try:
        service.invoke_lease(lease, "transform", [250])
    except AgentRejected as error:
        assert error.code == "E_HIA_LEASE", error.code
    else:
        raise AssertionError("released installed lease executed")
    assert frames
    assert native_helpers_identity()["native_helpers_sha256"] == sys.argv[3]
    service.close()
assert dict(os.environ) == before_env
with native_helpers_scope(sys.argv[2], sys.argv[3]):
    service = HIAAgentService(sys.argv[4])
    count = len(frames)
    assert service.call("hia_adopt", payload["adopt_arguments"]) == adopted
    assert service.call("hia_rollback", rollback_arguments) == rolled
    assert len(frames) == count, "restart replay entered native slot effect"
    assert service.inspect_slot("installed")["current"] == {"generation": "0", "epoch": "2"}
    service.close()
assert dict(os.environ) == before_env
source = SOURCE.read_bytes()
source_controls = []
for index, replacement in enumerate((None, b"changed installed slot source")):
    target = sys.argv[4] + "-refused-" + str(index)
    try:
        if replacement is None:
            SOURCE.unlink()
        else:
            SOURCE.write_bytes(replacement)
        try:
            with native_helpers_scope(sys.argv[2], sys.argv[3]):
                HIAAgentService(target)
        except (ValueError, OSError) as error:
            source_controls.append({"type": type(error).__name__, "message": str(error)})
        else:
            raise AssertionError("installed source drift used checkout or hosted policy")
        assert not Path(target).exists()
    finally:
        SOURCE.write_bytes(source)
assert dict(os.environ) == before_env
assert not any(name in {"tools", "tests"} or name.startswith(("tools.", "tests.")) for name in sys.modules)
print(json.dumps({"adopted": adopted, "rollback": rolled, "native_invocation": actual,
    "released": released, "frames": frames, "source_controls": source_controls,
    "source": str(SOURCE), "source_sha256": sha256(SOURCE.read_bytes()).hexdigest(),
    "authoring_imported": False, "native_helpers_sha256": sys.argv[3]}, sort_keys=True))
""".replace("@REFERENCE@", repr(REFERENCE_SLOT_METHODS))
        (self.root / "installed-control.py").write_text(script)
        result = self.run_recorded("installed-control", [sys.executable, "-I", "-S", "-B", "-c", script,
            str(installed), str(bundle), digest, str(service.store.root), str(payload_path)],
            environment={**self.clean_environment, "PATH": ""}, timeout=60)
        report = json.loads(result.stdout)
        self.assertEqual(report["native_helpers_sha256"], digest)
        self.assertEqual(len(report["source_controls"]), 2)
        self.assertIs(report["authoring_imported"], False)
        self.assertTrue(report["frames"])
        after = persisted_rows(database)
        self.assertEqual(after["contexts"], before["contexts"])
        self.assertEqual(after["execution_budgets"], before["execution_budgets"])
        self.assertEqual(after["slots"][0][2:4], ["0", "2"])
        self.observations.append({"installed_report": report, "rows_before": before, "rows_after": after})


if __name__ == "__main__":
    unittest.main()
