"""Independent extension controls for the native execution budget."""
import tempfile
import unittest
from unittest.mock import patch

from tests import test_hia_execution_budget_native as original

CONTEXT = original.CONTEXT


class ExecutionBudgetExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original.ExecutionBudgetNativeTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        original.ExecutionBudgetNativeTests.tearDownClass.__func__(cls)

    selected = original.ExecutionBudgetNativeTests.selected

    def test_context_and_native_budget_publication_is_one_transaction(self):
        from hepta.hia_agent_store import AgentStore
        from hepta.hia_execution_budget import INSERT_CONTEXT

        context = CONTEXT.decode()
        record = ('a' * 64, '{}', '12345678')
        with tempfile.TemporaryDirectory() as directory, self.selected():
            store = AgentStore(directory)
            try:
                budget = store.execution_budgets
                execute = budget._execute

                def fail_context_insert(sql, parameters=()):
                    if sql == INSERT_CONTEXT:
                        self.assertTrue(budget.db.in_transaction)
                        self.assertFalse(budget.official.in_transaction)
                        raise OSError('context write interrupted')
                    return execute(sql, parameters)

                with patch.object(budget, '_execute', side_effect=fail_context_insert), \
                        self.assertRaisesRegex(OSError, 'context write interrupted'):
                    budget.create(context, context_record=record)
                self.assertFalse(budget.observe(context)['record_exists'])
                self.assertIsNone(store.db.execute('SELECT * FROM contexts WHERE id=?', (context,)).fetchone())
                budget.create(context, context_record=record)
            finally:
                store.close()
            reopened = AgentStore(directory)
            try:
                row = reopened.db.execute('SELECT * FROM contexts WHERE id=?', (context,)).fetchone()
                self.assertEqual(tuple(row), (context, *record, 0))
                observation = reopened.execution_budgets.observe(context)
                self.assertEqual(observation['used_native_ns'], '0')
                self.assertIsNone(observation['owner'])
            finally:
                reopened.close()
