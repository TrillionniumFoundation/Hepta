"""Preserve source refusals and exact reference fixtures while reducing work."""
from copy import deepcopy
from hashlib import sha256
import json
import unittest
from unittest.mock import patch

from hepta import hia_agent_assembly as assembly
from tools import hia_selfhost_names as names


class SourceControlEquivalenceTests(unittest.TestCase):
    def test_forbidden_set_is_exact_over_all_unicode_codepoints(self):
        text = ''.join(chr(value) for value in range(0x110000))
        expected = [chr(value) for value in range(32) if value not in (9, 10, 13)]
        expected.append('\ufeff')
        self.assertEqual(assembly._SOURCE_CONTROL.findall(text), expected)

    def test_utf8_allowed_control_and_non_ascii_bytes_are_unchanged(self):
        for text in ('', '\t', 'a\r\nb\n', 'a\r', 'a\u0085b\u2028c\u2029d',
                     '汉字\u007f\ufffe\U0010ffff', 'a' * assembly.MAX_LINE_BYTES):
            raw = text.encode('utf-8')
            for value in (text, raw):
                with self.subTest(value=repr(value)[:80]):
                    self.assertEqual(assembly._source(value), (raw, text.split('\n')))

    def assert_rejected(self, source, message, *, line=None, code='E_HIA_ASSEMBLY'):
        with self.assertRaises(assembly.HIAAssemblyRejected) as result:
            assembly._source(source)
        self.assertEqual(str(result.exception), code + ': ' + message)
        self.assertEqual(result.exception.code, code)
        self.assertEqual(result.exception.line, line)
        self.assertEqual(result.exception.phase, 'syntax')

    def test_control_refusals_and_order_relative_to_other_source_gates(self):
        forbidden = [chr(value) for value in range(32) if value not in (9, 10, 13)] + ['\ufeff']
        for char in forbidden:
            # Invalid CRLF earlier in the same source must not win over the
            # original whole-source control-character refusal.
            text = 'a\rb\n' + char
            for value in (text, text.encode('utf-8')):
                with self.subTest(codepoint=ord(char), kind=type(value).__name__):
                    self.assert_rejected(value, 'unsupported control character or byte-order mark')
        self.assert_rejected('\x00\ud800', 'source is not valid UTF-8')
        self.assert_rejected(b'\x00\xff', 'source is not valid UTF-8')
        self.assert_rejected('a\rb', 'line 1: carriage return must be part of CRLF', line=1)
        with patch.object(assembly, 'MAX_SOURCE_BYTES', 1):
            self.assert_rejected('\x00a', 'source exceeds byte budget', code='E_HIA_ASSEMBLY_LIMIT')
            self.assert_rejected('é', 'source exceeds byte budget', code='E_HIA_ASSEMBLY_LIMIT')
        with patch.object(assembly, 'MAX_LINES', 1):
            self.assert_rejected('a\n\x00', 'unsupported control character or byte-order mark')
            self.assert_rejected('a\nb', 'source exceeds line budget', code='E_HIA_ASSEMBLY_LIMIT')
        with patch.object(assembly, 'MAX_LINE_BYTES', 1):
            self.assert_rejected('aa\x00', 'unsupported control character or byte-order mark')
            self.assert_rejected('a\r', 'line 1: line exceeds byte budget', line=1,
                                 code='E_HIA_ASSEMBLY_LIMIT')


class ReferenceFixturePreservationTests(unittest.TestCase):
    def test_complete_changed_fixture_outputs_match_prior_reference_bytes(self):
        # Captured from bfea47b before changing construction. The SHA covers
        # every source, input, output, case name, refusal expectation and order;
        # no qualification result or VerifiedProgram is reused by the builder.
        expected = {
            'cases': (34, '765368987b8b0718e3bf60552698c9c4a4b8256f33f795271952e5cb46befc8f'),
            'value_cases': (28, '563e9a9dfef86adfd1658592d2f1b65666951a3dc6d9700cd83862f8d63a05ca'),
            'value_refusals': (10, '81618ca2cc4edb95ce7c597d3477e49eb6acc05fbfecd59667bc949bbbcc6160'),
            'block_cases': (24, 'bb385be6ec8d3b1e9cd7162b51366b95add3ce2be4af5bea6a34e6494ab2e61a'),
            'block_refusals': (9, '6740abddc19e0c970251d6cf04cf3b312edfb431095f6a1b376eed38742db828'),
        }
        for name, (count, digest) in expected.items():
            with self.subTest(builder=name):
                rows = getattr(names, name)()
                self.assertEqual(len(rows), count)
                self.assertEqual(len({row['id'] for row in rows}), count)
                encoded = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
                self.assertEqual(sha256(encoded).hexdigest(), digest)


class AssemblyConstructionBoundaryTests(unittest.TestCase):
    def test_private_syntax_documents_are_fresh_and_grant_no_admission(self):
        from tests.test_hia_agent_assembly import SOURCE
        from hepta.hia_program import VerifiedProgram
        source = SOURCE.replace('ret(answer)', 'ret(missing)').encode()
        with patch.object(assembly, 'verify_program', side_effect=AssertionError('construction admitted Core')):
            first = assembly._parse_assembly_document(source)
            second = assembly._parse_assembly_document(source)
            before = deepcopy(first)
            text = assembly._render_assembly_document(first)
            self.assertEqual(first, before)
        self.assertIs(type(first), dict)
        self.assertNotIsInstance(first, VerifiedProgram)
        self.assertEqual(text.encode(), source)
        first['functions'][0]['params'][0]['name'] = 'changed'
        first['functions'][0]['blocks'][0]['ops'][0]['attrs']['mode'] = 'checked'
        self.assertEqual(second, before)
        self.assertEqual(source, SOURCE.replace('ret(answer)', 'ret(missing)').encode())
        with self.assertRaises(assembly.HIAAssemblyRejected) as caught:
            assembly.assemble_program(text)
        self.assertEqual((caught.exception.code, caught.exception.phase), ('E_HIA_SSA', 'core_verification'))
        with self.assertRaises(assembly.HIAProgramRejected):
            assembly.render_assembly(second)
        forged = VerifiedProgram(json.dumps(second).encode())
        with self.assertRaises(assembly.HIAProgramRejected):
            assembly.render_assembly(forged)

    def test_public_assemble_and_render_keep_each_complete_admission(self):
        from tests.test_hia_agent_assembly import SOURCE
        reference = assembly.verify_program
        with patch.object(assembly, 'verify_program', wraps=reference) as verifier:
            checked = assembly.assemble_program(SOURCE)
            self.assertEqual(verifier.call_count, 1)
        for value in (checked, checked.as_dict()):
            with self.subTest(kind=type(value).__name__), patch.object(
                    assembly, 'verify_program', wraps=reference) as verifier:
                self.assertEqual(assembly.render_assembly(value), SOURCE)
                self.assertEqual(verifier.call_count, 2)
        changed = SOURCE.replace('ret(answer)', 'ret(a64)')
        with patch.object(assembly, '_render_assembly_document', return_value=changed), patch.object(
                assembly, 'verify_program', wraps=reference) as verifier:
            with self.assertRaises(assembly.HIAAssemblyRejected) as caught:
                assembly.render_assembly(checked)
            self.assertEqual(verifier.call_count, 2)
        self.assertEqual((caught.exception.code, caught.exception.phase),
                         ('E_HIA_ASSEMBLY_ROUNDTRIP', 'representation'))

    def test_public_render_keeps_detached_input_during_spelling(self):
        from tests.test_hia_agent_assembly import SOURCE
        document = assembly._parse_assembly_document(SOURCE)
        # Caller-owned aliases cannot become the representation being emitted.
        document['functions'][0]['blocks'][0]['params'] = document['functions'][0]['params']
        render = assembly._render_assembly_document
        def mutate_caller(data):
            document['functions'][0]['params'][0]['name'] = 'changed_after_admission'
            self.assertEqual(data['functions'][0]['params'][0]['name'], 'a')
            return render(data)
        with patch.object(assembly, '_render_assembly_document', side_effect=mutate_caller):
            self.assertEqual(assembly.render_assembly(document), SOURCE)

    def test_fixture_transformations_do_not_issue_verified_authority(self):
        from tests.test_hia_agent_assembly import SOURCE
        source = SOURCE.replace('exports(total)\n', '').encode()
        original = bytes(source)
        mapping = {'total': 'renamed'}
        spellings = ['left', 'right', 'wide_left', 'wide_right', 'answer']
        with patch.object(assembly, 'verify_program', side_effect=AssertionError('fixture admitted Core')):
            function = names.renamed_source(source, mapping)
            values = names.renamed_values(source, spellings)
            blocks = names.renamed_blocks(source, ['start'])
            reordered = names.reordered_blocks(source)
        self.assertEqual((source, mapping, spellings),
            (original, {'total': 'renamed'}, ['left', 'right', 'wide_left', 'wide_right', 'answer']))
        for result in (function, values, blocks, reordered):
            self.assertIs(type(result), bytes)
            assembly.assemble_program(result)


if __name__ == '__main__':
    unittest.main()
