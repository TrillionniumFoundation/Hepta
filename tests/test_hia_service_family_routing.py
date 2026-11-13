"""Semantic routing controls for the isolated main/a733 family merge.

These controls exercise Python entry ordering and delegation only. They do not
qualify a compiled HIA image or replace either family's original native suite.
"""
from __future__ import annotations

from contextlib import ExitStack
from types import MethodType, SimpleNamespace
import os
import unittest
from unittest.mock import patch

from hepta.hia_agent_service import HIAAgentService
from hepta import hia_agent_service as service_module
from hepta import hia_native_helpers as helpers


class ServiceFamilyRoutingSourceTests(unittest.TestCase):
    def context_fixture(self):
        calls = []
        class Database:
            def execute(self, statement, arguments):
                calls.append((statement, arguments))
                return SimpleNamespace(fetchone=lambda: {"created_ns": "0"}, rowcount=1)
        context = {"ref": {"id": "ctx"}, "budget": {
            "max_total_wall_ms": 1000, "max_candidates": 2}}
        service = SimpleNamespace(store=SimpleNamespace(db=Database()), _candidate_budget=None)
        service._reference_consume_attempt = MethodType(HIAAgentService._reference_consume_attempt, service)
        service._consume_attempt = MethodType(HIAAgentService._consume_attempt, service)
        return service, context, calls

    def test_published_snapshot_and_independent_slot_selectors_keep_distinct_factories(self):
        self.assertEqual(helpers.HELPERS["HEPTA_HIA_AGENT_SNAPSHOT_MANIFEST"],
                         ("hia_agent_snapshot_native", "NativeAgentSnapshot"))
        self.assertEqual(helpers.HELPERS["HEPTA_HIA_SLOT_LEDGER_MANIFEST"],
                         ("hia_slot_ledger_native", "NativeSlotLedger"))
        self.assertEqual(helpers.HELPERS["HEPTA_HIA_SLOT_LEDGER_CONTINUATION_MANIFEST"],
                         ("hia_slot_ledger_continuation_native", "NativeSlotLedgerImage"))

    def test_default_candidate_budget_retains_public_delegation_point(self):
        service, context, calls = self.context_fixture()
        observed = []
        service._consume_attempt = lambda value: observed.append(value)
        with patch.object(service_module.time, "time_ns", return_value=0):
            HIAAgentService._budget_main_reference(service, context, candidate=True)
        self.assertEqual(observed, [context])
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].startswith("SELECT"))
        self.assertIs(observed[0], context)

    def test_default_candidate_attempt_has_one_sql_update(self):
        service, context, calls = self.context_fixture()
        with patch.object(service_module.time, "time_ns", return_value=0):
            HIAAgentService._budget_main_reference(service, context, candidate=True)
        self.assertEqual(sum(statement.startswith("UPDATE") for statement, _ in calls), 1)
        self.assertEqual(calls[-1][1], ("ctx", 2))

    def test_selected_candidate_attempt_has_one_delegate_and_no_sql_update(self):
        service, context, calls = self.context_fixture()
        effects = []
        service._candidate_budget = SimpleNamespace(
            consume=lambda identifier, maximum: effects.append((identifier, maximum)))
        with patch.object(service_module.time, "time_ns", return_value=0):
            HIAAgentService._budget_main_reference(service, context, candidate=True)
        self.assertEqual(effects, [("ctx", 2)])
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].startswith("SELECT"))

    def test_non_candidate_budget_never_consumes_attempt(self):
        service, context, calls = self.context_fixture()
        service._consume_attempt = lambda value: self.fail("noncandidate consumed an attempt")
        with patch.object(service_module.time, "time_ns", return_value=0):
            HIAAgentService._budget_main_reference(service, context, candidate=False)
        self.assertEqual(len(calls), 1)

    def test_main_statement_snapshot_does_not_enter_continuation(self):
        calls = []
        expected = object()
        service = SimpleNamespace(
            _slot_ledger=SimpleNamespace(snapshot=lambda name: calls.append(name) or expected),
            store=SimpleNamespace(slot_ledger=SimpleNamespace(
                direct=lambda *args, **kwargs: self.fail("wrong ledger family"))))
        self.assertIs(HIAAgentService._slot_snapshot(service, "slot"), expected)
        self.assertEqual(calls, ["slot"])
        with self.assertRaisesRegex(ValueError, "cannot borrow"):
            HIAAgentService._slot_snapshot(service, "slot", _connection=object())
        self.assertEqual(calls, ["slot"])

    def test_continuation_snapshot_remains_its_original_explicit_connection(self):
        calls = []
        connection = object()
        expected = object()
        service = SimpleNamespace(
            _slot_ledger=None,
            store=SimpleNamespace(slot_ledger=SimpleNamespace(
                direct=lambda *args, **kwargs: calls.append((args, kwargs)) or expected)))
        self.assertIs(HIAAgentService._slot_snapshot(
            service, "slot", _connection=connection), expected)
        self.assertEqual(calls, [((8, service, "slot"), {"connection": connection})])

    def test_published_journal_route_and_cross_family_refusal_precede_effect(self):
        service = SimpleNamespace(store=SimpleNamespace(request_journal=None))
        effects = []
        expected = object()
        def effect(*arguments):
            effects.append(arguments)
            return expected
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ,
                {"HEPTA_HIA_AGENT_JOURNAL_MANIFEST": "main-journal.json"}))
            stack.enter_context(patch("hepta.hia_agent_journal_native.call_with_native_journal",
                                      new=effect))
            self.assertIs(HIAAgentService.call(service, "tool", {"x": 1}), expected)
            self.assertEqual(effects, [(service, "tool", {"x": 1}, "main-journal.json")])
            service.store.request_journal = object()
            with self.assertRaisesRegex(ValueError, "both native request-journal"):
                HIAAgentService.call(service, "tool", {"x": 2})
            self.assertEqual(len(effects), 1)


if __name__ == "__main__":
    unittest.main()
