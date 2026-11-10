"""Independent JSON UTF-8 oracle for pre-allocation Core byte accounting."""
import json
import random
import unittest
from unittest.mock import patch
from hepta import hia_program as core


class CanonicalStringBudgetTests(unittest.TestCase):
    def check_wire(self, text):
        expected=len(json.dumps(text,ensure_ascii=False,separators=(',',':')).encode('utf-8'))
        self.assertEqual(core._json_string_bytes(text,expected),expected)
        self.assertEqual(core._json_string_bytes(text,expected+17),expected)
        with self.assertRaises(core.HIAProgramRejected) as refused:
            core._json_string_bytes(text,expected-1)
        self.assertEqual(refused.exception.code,'E_HIA_LIMIT')

    def test_every_ascii_pair_and_escape_boundary_matches_actual_stdlib_wire(self):
        for a in range(128):
            for b in range(128):self.check_wire(chr(a)+chr(b))
        for n in (0,1,127,128,4095,4096,4097):
            for text in ('a'*n,'x'*n+'"','\\'+'x'*n,'\x00'*n,'\n'*n):self.check_wire(text)

    def test_unicode_width_edges_and_mixed_random_payloads_have_exact_unchanged_budgets(self):
        points=[0,8,9,10,12,13,31,32,34,92,127,128,0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff]
        for point in points:self.check_wire(chr(point)*3)
        rng=random.Random(840615)
        for _ in range(500):
            text=''.join(chr(rng.choice(points)) for i in range(rng.randrange(80)))
            self.check_wire(text)
        for text in ('e\u0301','\u00e9','\u2028\u2029','汉字\U0001f4dc'):
            self.check_wire(text)

    def test_surrogates_and_too_small_lower_bound_refuse_with_original_error_categories(self):
        for point in (0xd800,0xdbff,0xdc00,0xdfff):
            text='safe'+chr(point)+'tail'
            with self.assertRaises(core.HIAProgramRejected) as error:core._json_string_bytes(text,1024)
            self.assertEqual(error.exception.code,'E_HIA_FORMAT')
            with self.assertRaises(core.HIAProgramRejected) as error:core._json_string_bytes(text,len(text))
            self.assertEqual(error.exception.code,'E_HIA_LIMIT')

    def test_actual_structure_byte_gate_refuses_before_canonical_encoder_allocates(self):
        value={'identifier':'a'*300}
        with patch.object(core,'MAX_BYTES',128),patch.object(core.json,'dumps',side_effect=AssertionError('encoder allocation reached')):
            with self.assertRaises(core.HIAProgramRejected) as error:core._decode(value)
        self.assertEqual(error.exception.code,'E_HIA_LIMIT')
        # ASCII DEL does not need an escape; embedded NUL does. Both counts
        # must come from the complete object, including keys and punctuation.
        for value in ({'x':'\x7f'*10},{'x':'\x00'*10},{'x':['a',None,False,3]}):
            wire=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
            self.assertEqual(core._structure(value),len(wire))


if __name__=='__main__':unittest.main()
