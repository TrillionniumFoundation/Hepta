"""Independent controls for post-terminal Bootstrap business comparison."""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from tests import hia_service_bootstrap_support as support
from tools import qualify_hia_service_bootstrap_finite as producer
from tools import read_hia_service_bootstrap as reader

ROOT = Path(__file__).resolve().parents[1]


class BootstrapTerminalBusinessTests(unittest.TestCase):
    def test_candidate_pending_state_cannot_claim_equality(self):
        observed = {
            "schema": "hepta.hia.service-bootstrap-finite-observations.v3",
            "status": "CHECKPOINT_CANDIDATE_OBSERVED",
            "differences": None,
            "business_comparison": "PENDING_PARENT_PROCESS_TERMINAL",
        }
        for lane in ("unselected", "vm", "native"):
            producer._checkpoint_business_state(observed, lane)
            reader._read_checkpoint_business_state(observed, lane)
            for field, value in (
                ("schema", "hepta.hia.service-bootstrap-finite-observations.v2"),
                ("status", "CHECKPOINT_CANDIDATE_COMPLETE"),
                ("status", "PASS_FINITE_ONLY"),
                ("differences", 0), ("differences", False),
                ("business_comparison", "COMPLETE"),
                ("business_comparison", None),
            ):
                changed = deepcopy(observed); changed[field] = value
                with self.subTest(lane=lane, field=field, value=value):
                    with self.assertRaises(ValueError):
                        producer._checkpoint_business_state(changed, lane)
                    with self.assertRaises(ValueError):
                        reader._read_checkpoint_business_state(changed, lane)
        for check in (producer._checkpoint_business_state, reader._read_checkpoint_business_state):
            with self.assertRaises(ValueError):
                check(observed, "undeclared")

    def test_original_checkpoint_remains_complete_and_strict(self):
        original = {
            "schema": "hepta.hia.service-bootstrap-finite-observations.v2",
            "status": "CHECKPOINT_ORIGINAL_COMPLETE", "differences": 0,
        }
        for check in (producer._checkpoint_business_state, reader._read_checkpoint_business_state):
            check(original, "original")
            for value in (False, None, -1, 1, "0"):
                changed = {**original, "differences": value}
                with self.subTest(check=check.__name__, value=value), self.assertRaises(ValueError):
                    check(changed, "original")

    def compare(self, left, right, *, late=False):
        with TemporaryDirectory() as directory:
            root = Path(directory); expected = root / "expected"; actual = root / "actual"
            output = root / "differences"
            expected.write_bytes(left); actual.write_bytes(right)
            compare = producer._compare_terminal_late if late else producer._compare_terminal_rows
            count, pin = compare(actual, expected, support.file_pin(actual), support.file_pin(expected), output)
            self.assertEqual(pin, support.file_pin(output))
            self.assertEqual(expected.read_bytes(), left); self.assertEqual(actual.read_bytes(), right)
            rows = [json.loads(line) for line in output.read_bytes().splitlines()]
            self.assertEqual(count, len(rows))
            return count, rows

    def test_every_identical_raw_row_is_retained(self):
        raw = b'{"id":"one","obj":{"identity":7},"name":"store"}\n{"id":"two","active":null}\n'
        self.assertEqual(self.compare(raw, raw), (0, []))
        self.assertEqual(self.compare(b"", b""), (0, []))

    def test_same_length_attribute_difference_is_not_normalized(self):
        expected = b'{"id":"program","name":"store","obj":{"identity":7}}\n'
        actual = b'{"id":"program","name":"other","obj":{"identity":7}}\n'
        self.assertEqual(len(expected), len(actual))
        count, rows = self.compare(expected, actual)
        self.assertEqual(count, 1)
        self.assertEqual(rows[0]["expected"]["name"], "store")
        self.assertEqual(rows[0]["actual"]["name"], "other")
        self.assertEqual(rows[0]["actual"]["obj"], {"identity":7})

    def test_late_exception_context_is_compared_without_normalization(self):
        expected = b'{"id":"throw","active":{"type":"OuterError","same_outer":false}}\n'
        actual = b'{"id":"throw","active":null}\n'
        count, rows = self.compare(expected, actual, late=True)
        self.assertEqual(count, 1)
        self.assertIs(rows[0]["expected"]["active"]["same_outer"], False)
        self.assertIsNone(rows[0]["actual"]["active"])

    def test_missing_extra_and_reordered_rows_are_rejected(self):
        one, two = b'{"id":"one"}\n', b'{"id":"two"}\n'
        for expected, actual, count in ((one+two, one, 1), (one, one+two, 1), (one+two, two+one, 2)):
            with self.subTest(expected=expected, actual=actual):
                self.assertEqual(self.compare(expected, actual)[0], count)

    def test_equal_json_values_do_not_replace_raw_byte_equality(self):
        expected, actual = b'{"id":"one","n":1}\n', b'{ "n":1, "id":"one" }\n'
        self.assertEqual(json.loads(expected), json.loads(actual))
        count, rows = self.compare(expected, actual)
        self.assertEqual(count, 1)
        self.assertEqual(rows[0]["expected"], rows[0]["actual"])

    def test_incomplete_duplicate_and_wrong_pin_fail(self):
        complete = b'{"id":"one","n":1}\n'
        with TemporaryDirectory() as directory:
            root = Path(directory); left = root / "left"; right = root / "right"
            left.write_bytes(complete)
            for index, raw in enumerate((complete[:-1], b'{"id":"one","n":1,"n":2}\n')):
                right.write_bytes(raw)
                with self.subTest(index=index), self.assertRaises(ValueError):
                    producer._compare_terminal_rows(right, left, support.file_pin(right),
                        support.file_pin(left), root / ("difference-"+str(index)))
            right.write_bytes(complete)
            changed = {**support.file_pin(right), "sha256": "0"*64}
            with self.assertRaises(ValueError):
                producer._compare_terminal_rows(right, left, changed,
                    support.file_pin(left), root / "difference-pin")

    def test_original_source_test_files_are_unchanged(self):
        pins = {
            "tests/test_hia_service_bootstrap_sources.py": "7c8ffcc54036efb075ef4e2fd49de5f3737261eddd2b6b4fe7110aafb90b4281",
            "tests/test_hia_service_bootstrap_qualification.py": "d2f288df90a84d8d1fbf54cab8eee547995f7e0faafc0ac3b76dc4e56583894c",
            "tests/test_hia_service_bootstrap_fixed_words.py": "c6aedd94bef469797d2a199cd9c70cafb0482f478c8b36c5e753c6399f5544db",
        }
        for name, expected in pins.items():
            with self.subTest(path=name):
                self.assertEqual(sha256((ROOT/name).read_bytes()).hexdigest(), expected)


if __name__ == "__main__":
    unittest.main()
