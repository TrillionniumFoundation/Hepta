"""Actual captured C contracts and exact signed-shift admission boundaries."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.c_migrate import migrate_c_project
from hepta.c_translation import CTranslator, MAX_FIXED_SLICE_ELEMENTS

CLANG = os.environ.get("HEPTA_CLANG") or shutil.which("clang-20")


@unittest.skipUnless(CLANG, "Clang capture required; set HEPTA_CLANG")
class FixedSliceShiftTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-fixed-slice-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def migrate(self, source, *, length=4, schema="hepta.c-contracts.v1", pointer=True):
        (self.root / "sample.c").write_text(source)
        (self.root / "compile_commands.json").write_text(json.dumps([{
            "directory": str(self.root), "file": "sample.c",
            "arguments": [CLANG, "-std=c11", "-c", "sample.c", "-o", "sample.o"]}]))
        contract = {"schema": schema, "functions": {"sample": {"slices": {"p": {"length": length, "access": "read"}}}}} if pointer else None
        if schema == "hepta.c-record-views.v1":
            contract["records"] = {}
            contract["functions"]["sample"]["records"] = {}
        return migrate_c_project(self.root / "compile_commands.json", self.root / "bundle",
                                 contracts=contract, clang=CLANG)

    def test_fixed_four_is_preserved_in_safe_core_and_foreign_bridge(self):
        result = self.migrate("unsigned int sample(const unsigned char *p){return p[3];}")
        self.assertTrue(result["ok"], result["diagnostics"])
        source = (self.root / "bundle/source.hepta").read_text()
        bridge = (self.root / "bundle/bridge.rs").read_text()
        self.assertIn("assert((4 as usize) <= len(read p_p))", source)
        self.assertIn("let n_b_p = 4 as usize;", bridge)

    def test_fixed_extent_is_preserved_by_record_view_bridge(self):
        result = self.migrate("unsigned int sample(const unsigned char *p){return p[3];}", schema="hepta.c-record-views.v1")
        self.assertTrue(result["ok"], result["diagnostics"])
        bridge = (self.root / "bundle/bridge.rs").read_text()
        self.assertIn("let n_b_p = 4;", bridge)
        self.assertIn("from_raw_parts", bridge)
        self.assertNotIn("let n_b_p = 1", bridge)

    def test_fixed_extent_bound_is_an_explicit_profile(self):
        result = self.migrate("unsigned int sample(const unsigned char *p){return p[0];}", length=MAX_FIXED_SLICE_ELEMENTS)
        self.assertTrue(result["ok"], result["diagnostics"])
        self.assertIn(str(MAX_FIXED_SLICE_ELEMENTS), (self.root / "bundle/bridge.rs").read_text())

    def test_defined_promoted_byte_shift_has_interval_receipt(self):
        result = self.migrate("int sample(const unsigned char *p){return p[0]<<23;}")
        self.assertTrue(result["ok"], result["diagnostics"])
        proof = result["functions"][0]["proven_nonnegative_shifts"][0]
        self.assertEqual(proof["operand_interval"], [0, 255])
        self.assertEqual(proof["result_interval"], [0, 255 << 23])

    def test_next_signed_left_shift_overflows_and_rejects(self):
        result = self.migrate("int sample(const unsigned char *p){return p[0]<<24;}")
        self.assertFalse(result["ok"])
        self.assertIn("E_C_SHIFT", [row["code"] for row in result["diagnostics"]])
        self.assertFalse((self.root / "bundle").exists())

    def test_signed_right_shift_of_potential_negative_stays_rejected(self):
        result = self.migrate("int sample(int value){return value>>1;}", pointer=False)
        self.assertFalse(result["ok"])
        self.assertIn("E_C_SHIFT", [row["code"] for row in result["diagnostics"]])

    def test_dynamic_shift_count_stays_rejected(self):
        result = self.migrate("int sample(unsigned char value, unsigned int count){return value<<count;}", pointer=False)
        self.assertFalse(result["ok"])
        self.assertIn("E_C_SHIFT", [row["code"] for row in result["diagnostics"]])

    def test_narrowing_cannot_acquire_unsound_interval_proof(self):
        result = self.migrate("int sample(unsigned int value){return ((int)value)>>1;}", pointer=False)
        self.assertFalse(result["ok"])
        self.assertIn("E_C_SIGNED_CONVERSION", [row["code"] for row in result["diagnostics"]])


if __name__ == "__main__":
    unittest.main()
