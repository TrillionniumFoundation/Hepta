"""Package assembly bridge checks kept outside frozen original caller modules."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import HIAAssemblyRejected, assemble_program, render_assembly
from hepta.hia_program import HIAProgramRejected
from tests.test_hia_agent_assembly import SOURCE
from tests.test_hia_program import arithmetic


class HIADefaultAssemblyBridgeTests(unittest.TestCase):
    def test_package_syntax_document_still_requires_whole_core_admission(self):
        from hepta import hia_agent_assembly as assembly
        data = assembly._parse_assembly_document(SOURCE)
        data["functions"][0]["blocks"][0]["term"]["values"] = ["unbound"]
        with patch('hepta.hia_default_native.default_assembly_document', return_value=data) as syntax:
            with self.assertRaises(HIAAssemblyRejected) as caught:
                assemble_program(SOURCE)
            syntax.assert_called_once_with(SOURCE)
        self.assertEqual(caught.exception.phase, 'core_verification')
        self.assertIsNone(caught.exception.line)
        self.assertIsInstance(caught.exception.__cause__, HIAProgramRejected)

    def test_package_renderer_keeps_independent_roundtrip_and_profile_errors(self):
        checked = assemble_program(SOURCE)
        with patch('hepta.hia_default_native.default_assembly_text', return_value=SOURCE) as owner:
            self.assertEqual(render_assembly(checked), SOURCE)
            owner.assert_called_once_with(checked.canonical_bytes)
        with patch('hepta.hia_default_native.default_assembly_text', return_value=SOURCE.replace('sums', 'changed')):
            with self.assertRaisesRegex(HIAAssemblyRejected, 'renderer changed canonical Core'):
                render_assembly(checked)
        with patch('hepta.hia_default_native.default_assembly_text', side_effect=AssertionError('image entered')):
            with self.assertRaisesRegex(HIAAssemblyRejected, 'requires explicit primitive'):
                render_assembly(arithmetic('int.add.checked', 'u8'))

