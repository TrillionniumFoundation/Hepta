"""Exact-byte keyword semantics and real compiler capacity, not hash agreement."""
import unittest

from tools.generate_hia_selfhost import W, document
from tools.hia_selfhost_keywords import independent_reference, keyword_source
from tools.hia_selfhost_limits import MAX_BLOCKS, MAX_INSTRUCTIONS


class SelfhostKeywordTests(unittest.TestCase):
    def test_length_guard_retains_every_occupied_byte_and_rejects_zero_padding_aliases(self):
        # Independent table oracle across every packed-word boundary. This
        # executes the authoring function, not a replacement native compiler;
        # the retained Core/native lookup gates qualify the actual HIA body.
        words = {'A' * (size - 1) + 'B': size for size in (1, 8, 9, 16, 17, 24, 25, 32)}
        namespace = {'readbuf': bytes, 'u64': int, 'byte': lambda s, i: s[i],
                     'choose': lambda condition, yes, no: yes if condition else no}
        exec(keyword_source(words), namespace)
        lookup = namespace['keyword']
        expected = {word.encode(): token for word, token in words.items()}
        values = {b'', b'\0', b'A' * 33}
        for word in expected:
            values.update((word, word + b'\0', word + b'X', word[:-1]))
            for at in {0, len(word) // 2, len(word) - 1}:
                for byte in range(256):
                    values.add(word[:at] + bytes([byte]) + word[at + 1:])
        for value in values:
            for offset in (0, 3):
                with self.subTest(value=value, offset=offset):
                    self.assertEqual(lookup(b'?!?'[:offset] + value, offset, len(value)),
                                     expected.get(value, 0))

    def test_known_unknown_long_nul_and_offset_inputs_match_the_independent_vm(self):
        reference = independent_reference()
        self.assertEqual(len(reference["keyword_cases"]), 2 * (3 * len(W) + 6))
        observations=[item for bank in reference["cases"] for item in bank["input_cases"]]
        self.assertEqual({item["id"] for item in observations},{item["id"] for item in reference["keyword_cases"]})
        self.assertEqual(len(observations),len(reference["keyword_cases"]))
        for bank in reference["cases"]:
            self.assertLessEqual(len(bank["input_cases"]),31)
            self.assertEqual(bank["reference_result"]["values"],[0,*bytes.fromhex(bank["expected_hex"])])
        self.assertTrue(reference["before_B0"])
        self.assertFalse(reference["all_input_correctness_proved"])
        expected = {token for token in W.values()} | {0}
        for offset in (0, 3):
            cases = [r for r in reference["keyword_cases"] if r["program"] == "keyword-offset-" + str(offset)]
            self.assertEqual({r["expected_result"] for r in cases}, expected)
            for row in cases:
                self.assertEqual(row["reference_result"]["values"], [row["expected_result"], 165])

    def test_full_compiler_fits_unchanged_caps_with_reclaimed_cfg_space(self):
        doc, names = document()
        blocks = sum(len(fn["blocks"]) for fn in doc["functions"])
        operations = sum(len(b["ops"]) for fn in doc["functions"] for b in fn["blocks"])
        self.assertLessEqual(blocks, MAX_BLOCKS)
        self.assertLessEqual(operations, MAX_INSTRUCTIONS)
        keyword = next(fn for fn in doc["functions"] if fn["name"] == names["keyword"])
        # The authoring strategy now has one branch per distinct byte length;
        # physical per-function/global Core caps above remain unchanged.
        self.assertLessEqual(len(keyword["blocks"]), 16 + 2 * len({len(word) for word in W}))
        self.assertTrue(any(op["op"] == "select" for b in keyword["blocks"] for op in b["ops"]))
        for fn in doc["functions"]:
            self.assertLessEqual(len(fn["blocks"]), 256)
            for b in fn["blocks"]:
                names = [p["name"] for p in b["params"]]
                names += [p["name"] for op in b["ops"] for p in op["out"]]
                self.assertTrue(all(int(name[1:]) < 2048 for name in names))

    def test_fixture_keyword_function_is_exactly_the_live_compiler_body(self):
        from tools.hia_selfhost_keywords import keyword_function
        full, names = document()
        original = next(fn for fn in full["functions"] if fn["name"] == names["keyword"])
        self.assertEqual(keyword_function(), {**original, "name": "f1"})

    def test_outside_the_packed_grammar_fails_at_authoring_time(self):
        for word in ("", "x" * 33, "f\0n", "汉"):
            with self.subTest(word=word), self.assertRaises((ValueError, UnicodeError)):
                keyword_source({word: 1})


if __name__ == "__main__":
    unittest.main()
