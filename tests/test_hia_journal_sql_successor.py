"""Adversarial source controls for the typed HIA journal SQL successor."""
from __future__ import annotations

import ast
from pathlib import Path
import shutil
import tempfile
import unittest

from tools.qualify_hia_journal_sql_successor import (
    ROOT, admit_journal_sql_successor, qualify,
)


class JournalSqlSuccessorTests(unittest.TestCase):
    def test_five_frozen_sql_effects_preserved_in_typed_native_store(self):
        summary = qualify(ROOT)
        self.assertEqual(summary['frozen_sql_calls'], 5)
        self.assertEqual(summary['typed_journal_calls'], 5)

    def test_each_typed_write_and_guard_rejects_argument_or_method_substitution(self):
        source = (ROOT / 'hepta/hia_agent_journal_native.py').read_text()
        changes = (
            ('service.store.journal_lookup(session.key)',
             'service.store.journal_lookup(request_id)'),
            ('service.store.journal_reserve, session.key',
             'service.store.journal_reserve, request_id'),
            ("service.store.journal_complete, session.key",
             "service.store.journal_complete, request_id"),
            ('service.store.journal_cost_observed(*_delivery_guard',
             'service.store.journal_cost_observed(*tuple'),
            ('service.store.journal_complete(*_delivery_guard',
             'service.store.journal_complete(*tuple'),
        )
        for old, new in changes:
            with self.subTest(change=old):
                self.assertEqual(source.count(old), 1)
                with self.assertRaisesRegex(AssertionError, 'journal typed SQL successor'):
                    admit_journal_sql_successor(ROOT, ast.parse(source.replace(old, new, 1)))

    def test_frozen_inventory_and_fallback_or_native_dispatch_mutations_refuse(self):
        paths = ('tests/fixtures/native_delivery_original_9c46166.json',
                 'hepta/hia_agent_journal_native.py',
                 'hepta/hia_agent_store.py',
                 'hepta/hia_agent_store_native.py')
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            for name in paths:
                output = scratch / name
                output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, output)

            cases = (
                ('tests/fixtures/native_delivery_original_9c46166.json',
                 b'"base_commit"', b'"base_comMit"', 'frozen native-delivery evidence'),
                ('hepta/hia_agent_store.py',
                 b'SELECT * FROM requests WHERE key=?',
                 b'SELECT * FROM requests WHERE key IS ?', 'original journal SQL literal'),
                ('hepta/hia_agent_store_native.py',
                 b'_JOURNAL_RESERVE = _write_plan(6, _INSERTS',
                 b'_JOURNAL_RESERVE = _write_plan(5, _INSERTS', 'native journal typed operation index'),
                ('hepta/hia_agent_store_native.py',
                 b"INSERT INTO requests VALUES (?,?,?,?,?,?)",
                 b"INSERT INTO requests VALUES (?,?,?,?,?)", 'native journal indexed SQL query'),
                ('hepta/hia_agent_store_native.py',
                 b'_JOURNAL_RESERVE, (key, digest, tool',
                 b'_JOURNAL_COMPLETE, (key, digest, tool', 'native journal SQL opcode'),
                ('hepta/hia_agent_store_native.py',
                 b'_descriptor_unique_transaction(18,',
                 b'_descriptor_unique_transaction(17,', 'native journal cost atomic'),
            )
            for name, old, new, message in cases:
                path = scratch / name
                raw = path.read_bytes()
                self.assertEqual(raw.count(old), 1, (name, old))
                try:
                    path.write_bytes(raw.replace(old, new, 1))
                    with self.subTest(source=name, mutation=old):
                        with self.assertRaisesRegex(AssertionError, message):
                            qualify(scratch)
                finally:
                    path.write_bytes(raw)


if __name__ == '__main__':
    unittest.main()
