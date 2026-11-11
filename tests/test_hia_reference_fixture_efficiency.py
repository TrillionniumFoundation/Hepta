"""Preserve source refusals and exact reference fixtures while reducing work."""
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
    def test_complete_compiler_renames_keep_original_and_modified_bytes(self):
        # Captured from the original c80eb2e three-pass transformation, before
        # composing its fixture edits. These identities include all functions,
        # SSA uses, formal return origins, blocks, entries and explicit edges.
        from tools.generate_hia_selfhost import document
        from tools.qualify_hia_selfhost import SOURCE, mutate_compiler
        _, table = document()
        mapping = {number: name for name, number in table.items()}
        source = SOURCE.read_bytes()
        cases = (
            (source, 'b9fab42fc7ab22ff19525cf0bc0b3dc7e92511ac12d51df038a608412902a7f1',
             'bbd534f4799bc2fc76e787e21ba7a8cab79b4d3e38e2b41bbd22a1decb316063'),
            (mutate_compiler(source), '25dd7b4753da78c3ee0f04a8f98e87e04859f2d67d9255c562e17a7ef406cb96',
             'b99ab525232bc54a6919ae057ae0da8745ab47f576e3d9435c6b98b4dfb59d6d'),
        )
        for actual, source_hash, core_hash in cases:
            with self.subTest(source=source_hash):
                rendered = names.renamed_compiler(actual, mapping)
                self.assertEqual(len(rendered), 769584)
                self.assertEqual(sha256(rendered).hexdigest(), source_hash)
                self.assertEqual(assembly.assemble_program(rendered).sha256, core_hash)

    def test_composed_renames_cannot_admit_an_invalid_final_program(self):
        source = (b'hia-asm.v1 hepta.hia.program.v8 fixture\n'
                  b'fn first() -> (u32) effects() entry(start)\nblock start()\n'
                  b'  result:u32 = call() {"function":"second"}\n  ret(result)\nend\n'
                  b'fn second() -> (u32) effects() entry(start)\nblock start()\n'
                  b'  result:u32 = const() {"value":7}\n  ret(result)\nend\n')
        for mapping in ({'first': 'same', 'second': 'same'},
                        {'first': 'valid', 'second': '__hia_reserved'},
                        {'first': 'valid', 'second': 'invalid-name'}):
            with self.subTest(mapping=mapping), self.assertRaises(assembly.HIAProgramRejected):
                names.renamed_compiler(source, mapping)

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


if __name__ == '__main__':
    unittest.main()
