"""Real byte-ABI producer/replay controls adapted from Hepta PR #891.

The independent 24-byte image is an ABI fixture, not a compiler-produced image.
Original fix source: 7c20b6cfc792f0147b5418968f94734b8890fcca.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import platform
import struct
import sys
import tempfile
import unittest

from tools.qualify_hia_original_select_fragments import (
    digest, validate_complete_output_observation, replay_complete_output_observation,
)


@unittest.skipUnless(sys.platform == "linux" and platform.machine() == "x86_64",
                     "actual byte-ABI observations require Linux x86-64")
class CompleteOutputObservationTests(unittest.TestCase):
    def observe(self, *, status=0, expected=0xfedcba9876543210):
        from tools.qualify_hia_selfhost import invoke
        temporary = tempfile.TemporaryDirectory(prefix="hia-complete-output-")
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        # Independent hand-written machine fixture, not a compiler output:
        # store the expected eight bytes, then return status:u32/value:u32.
        image_bytes = (b"\x48\xb8" + struct.pack("<Q", expected) + b"\x48\x89\x02"
                       + b"\x48\xb8" + struct.pack("<Q", (status << 32) | (expected & 0xffffffff))
                       + b"\xc3")
        image = directory / "independent-byte-abi-fixture.bin"
        image.write_bytes(image_bytes)
        data, label = b"finite input identity", "whole-output-case-0"
        receipt, actual = invoke(directory, label, image, data, capacity=8, workspace_size=0)
        witness = {"receipt": receipt, "observed_output_sha256": digest(actual),
                   "finite_observation_only": True}
        kwargs = {"image_bytes": image_bytes, "input_bytes": data, "expected": expected}
        return directory, label, receipt, actual, witness, kwargs

    def test_real_success_binds_wide_output_and_low_u32_return_in_producer_and_replay(self):
        directory, label, receipt, actual, witness, kwargs = self.observe()
        self.assertEqual(receipt["abi_status"], 0)
        self.assertEqual(receipt["result_u64"], 0x76543210)
        self.assertEqual(actual.hex(), "1032547698badcfe")
        validate_complete_output_observation(receipt, actual, **kwargs)
        replay_complete_output_observation(directory, label, witness, **kwargs)

    def test_real_nonzero_abi_status_cannot_hide_behind_correct_low_return_and_output(self):
        directory, label, receipt, actual, witness, kwargs = self.observe(status=1, expected=7)
        self.assertEqual(receipt["abi_status"], 1)
        self.assertEqual(receipt["result_u64"], 0x100000007)
        # This is the exact former acceptance condition, exercised against
        # genuine native execution rather than a fabricated receipt.
        self.assertTrue(receipt.get("status") == "returned" and receipt.get("core_u32") == 7
                        and actual == (7).to_bytes(8, "little") and receipt.get("source_unchanged"))
        with self.assertRaisesRegex(ValueError, "ABI or byte identities"):
            validate_complete_output_observation(receipt, actual, **kwargs)
        with self.assertRaisesRegex(ValueError, "ABI or byte identities"):
            replay_complete_output_observation(directory, label, witness, **kwargs)

    def test_receipt_drift_cannot_substitute_image_input_output_or_call_contract(self):
        _, _, receipt, actual, _, kwargs = self.observe()
        mutations = {"status": "unknown", "abi_status": False, "result_u64": 7,
            "core_u32": 7, "return_encoding": "packed-ABI-status-and-u32", "format": "seed-shared",
            "source_unchanged": False, "forbidden_compiler_modules_loaded": ["hepta.hia_program_native"],
            "image_sha256": "a" * 64, "artifact_sha256": "b" * 64,
            "source_sha256": "c" * 64, "input_sha256": "d" * 64,
            "input_bytes": 0, "output_sha256": "e" * 64,
            "limits": {"output_capacity": 16, "workspace_bytes": 0}}
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = {**receipt, field: value}
                with self.assertRaises(ValueError):
                    validate_complete_output_observation(changed, actual, **kwargs)
        with self.assertRaises(ValueError):
            validate_complete_output_observation(receipt, b"\0" * 8, **kwargs)

    def test_replay_requires_original_raw_receipt_and_witness_to_agree(self):
        directory, label, receipt, _, witness, kwargs = self.observe()
        stdout = directory / (label + ".stdout.log")
        original = stdout.read_bytes()
        raw = json.loads(original)
        for field, value in (("abi_status", 1), ("abi_status", False), ("image_sha256", "a" * 64),
                             ("source_sha256", "b" * 64), ("output_sha256", "c" * 64)):
            with self.subTest(field=field):
                stdout.write_text(json.dumps({**raw, field: value}))
                with self.assertRaisesRegex(ValueError, "raw output, receipt or witness"):
                    replay_complete_output_observation(directory, label, witness, **kwargs)
        missing = dict(raw)
        del missing["abi_status"]
        stdout.write_text(json.dumps(missing))
        with self.assertRaisesRegex(ValueError, "raw output, receipt or witness"):
            replay_complete_output_observation(directory, label, witness, **kwargs)
        stdout.write_bytes(original)
        substituted = copy.deepcopy(witness)
        substituted["receipt"]["case"] = "whole-output-case-1"
        with self.assertRaisesRegex(ValueError, "raw output, receipt or witness"):
            replay_complete_output_observation(directory, label, substituted, **kwargs)
        replay_complete_output_observation(directory, label, witness, **kwargs)



if __name__ == "__main__":
    unittest.main()
