"""Exact JSON admission and complete alpha witnesses under cheaper authoring."""
from __future__ import annotations

import json
import random
import tracemalloc
import unittest
from unittest.mock import patch

from hepta import hia_program
from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_program import HIAProgramRejected, VerifiedProgram, verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_schema import SCHEMA_V8
from tests.test_hia_program import arithmetic, resource_program
from tools.hia_selfhost_names import (nonfirst_entry_source, renamed_blocks,
    renamed_compiler_source as renamed_compiler_identifiers, renamed_source, renamed_values)


class BoundedJSONStringAdmissionTests(unittest.TestCase):
    def test_exact_lengths_match_independent_encoder_at_both_budget_edges(self):
        rng = random.Random(0x4A534F4E)
        alphabet = ''.join(map(chr, range(128))) + 'é中🌊\u2028'
        values = ['', 'simple_Core.opcode_123', 'x' * 32768, 'a"b\\c',
                  ''.join(map(chr, range(128))), 'é中🌊', '\x00\b\t\n\f\r']
        values += [''.join(rng.choice(alphabet) for _ in range(rng.randrange(128)))
                   for _ in range(200)]
        for value in values:
            expected = len(json.dumps(value, ensure_ascii=False).encode('utf-8'))
            with self.subTest(prefix=repr(value[:20]), size=expected):
                self.assertEqual(hia_program._json_string_bytes(value, expected), expected)
                with self.assertRaises(HIAProgramRejected) as caught:
                    hia_program._json_string_bytes(value, expected - 1)
                self.assertEqual(caught.exception.code, 'E_HIA_LIMIT')

    def test_surrogates_and_escaped_expansion_still_refuse_before_encoding(self):
        for value, expected_code in [('prefix\ud800tail', 'E_HIA_FORMAT'),
                                     ('\udfff', 'E_HIA_FORMAT'),
                                     ('\x00' * 80, 'E_HIA_LIMIT'),
                                     ('plain' * 80, 'E_HIA_LIMIT')]:
            with self.subTest(value=repr(value[:20])), patch.object(hia_program, 'MAX_BYTES', 256):
                with patch.object(hia_program.json, 'dumps',
                                  side_effect=AssertionError('encoder before admission')):
                    with self.assertRaises(HIAProgramRejected) as caught:
                        hia_program._decode({'value': value})
                self.assertEqual(caught.exception.code, expected_code)

    def test_plain_ascii_byte_count_does_not_allocate_an_encoded_copy(self):
        value = 'x' * (hia_program.MAX_BYTES - 2)
        tracemalloc.start()
        try:
            self.assertEqual(hia_program._json_string_bytes(value, hia_program.MAX_BYTES),
                             hia_program.MAX_BYTES)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 512 * 1024)

    def test_public_verified_program_constructor_does_not_bypass_reverification(self):
        original = arithmetic()
        checked = verify_program(original)
        damaged = checked.as_dict()
        damaged['functions'][0]['blocks'][0]['ops'][0]['args'][0] = 'undefined'
        forged = VerifiedProgram(json.dumps(damaged, sort_keys=True,
            separators=(',', ':')).encode())
        for observe in (lambda: verify_program(forged),
                        lambda: execute_program(forged, 'calculate', [1, 2])):
            with self.assertRaises(HIAProgramRejected):
                observe()
        self.assertEqual(execute_program(checked, 'calculate', [1, 2])['result'], 3)


class ComposedCompilerRenamingTests(unittest.TestCase):
    def test_composition_keeps_the_exact_previous_text_and_resource_execution(self):
        for document, arguments, expected in [(arithmetic(), [17, -9], 8),
                                               (resource_program(), [2, 73], 73)]:
            document['schema'] = SCHEMA_V8
            source = render_assembly(document).encode()
            names = {fn['name']: 'renamed_' + str(i) for i, fn in enumerate(document['functions'])}
            previous = renamed_blocks(renamed_values(renamed_source(source, names)))
            composed = renamed_compiler_identifiers(source, names)
            self.assertEqual(composed, previous)
            before = execute_program(assemble_program(source), document['functions'][0]['name'], arguments)
            after = execute_program(assemble_program(composed), names[document['functions'][0]['name']], arguments)
            self.assertEqual(before['values'], after['values'])
            self.assertEqual(after['result'], expected)
            self.assertEqual(before['resources'], after['resources'])

    def test_forward_edges_calls_and_returned_loan_origins_keep_exact_text(self):
        from tools.hia_selfhost_returned_loans import cases
        inputs = [nonfirst_entry_source().encode()]
        inputs.extend(row['source'].encode() for row in cases()
                      if row['program'] in {'loan-read-forward', 'loan-mut-cfg', 'loan-mut-tail'})
        self.assertGreater(len(inputs), 1)
        for source in inputs:
            document = assemble_program(source).as_dict()
            names = {fn['name']: 'renamed_' + str(i) for i, fn in enumerate(document['functions'])}
            previous = renamed_blocks(renamed_values(renamed_source(source, names)))
            composed = renamed_compiler_identifiers(source, names)
            self.assertEqual(composed, previous)
            self.assertEqual(assemble_program(composed).canonical_bytes,
                             assemble_program(previous).canonical_bytes)

    def test_invalid_original_and_colliding_final_names_are_fully_rejected(self):
        source = nonfirst_entry_source().encode()
        with self.assertRaises(HIAProgramRejected):
            renamed_compiler_identifiers(source.replace(b'jump earlier()', b'jump absent()'),
                                         {'f0': 'entry'})
        with self.assertRaises(HIAProgramRejected):
            renamed_compiler_identifiers(source, {'f0': '__hia_reserved'})


if __name__ == '__main__':
    unittest.main()
