"""Both historical implementation lines actually execute through the new core."""
from __future__ import annotations

import copy
import ctypes
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.core import (build_core, execute_core, from_executable_core,
                        from_scalar_core, verify_core)
from hepta.executable_core import lower_executable_core
from hepta.hia_program import HIAProgramRejected
from hepta.hia_program_source import lower_source
from hepta.parser import parse
from tests.test_hia_core import fixture, _PROJECT


SCALAR = '''module unified;
export "C" fn sum_rows(n:i32)->i32 effects {panic} {
    let mut sum:i32=0;
    let mut i:i32=0;
    while i<n {
        let mut j:i32=0;
        while j<i {sum=sum+j;j=j+1;}
        if i<3 {sum=sum+2;} else {sum=sum+1;}
        i=i+1;
    }
    return sum;
}
'''
OWNED = '''module unified_owned;
fn fill(data:mut Buffer<u8>,n:usize)->Unit effects {panic,write} {
    for i in 0..n {data[i]=(i as u8);}
}
export "C" fn checksum(n:usize)->u64 effects {alloc,block,panic,write} {
    let mut data=buffer(n);
    fill(mut data,n);
    let mut total:u64=0;
    for i in 0..n {total=total+(data[i] as u64);}
    drop(move data);
    return total;
}
'''


class CoreUnificationTests(unittest.TestCase):
    def test_real_old_ssa_phi_edges_and_structured_core_agree_in_new_interpreter(self):
        program, checked, scalar = fixture(SCALAR)
        structured = lower_executable_core(program, checked)
        imported = [
            ("legacy_scalar_ssa", from_scalar_core(
                scalar, program=program, checked=checked, project_sha256=_PROJECT),
             {"schema", "module", "functions"}, None),
            ("legacy_executable", from_executable_core(structured, source=SCALAR),
             {"schema", "module", "functions", "exports"}, ["sum_rows"]),
            ("source", lower_source(SCALAR),
             {"schema", "module", "functions", "exports"}, ["sum_rows"]),
        ]
        # The legacy scalar-only import retains its closed v1 envelope. Source
        # and structured imports also carry the source signature's checked
        # scalar entry list; those exports are executable Core, not source or
        # a producer receipt. Each route still has an exact field contract.
        for route, core, fields, exports in imported:
            with self.subTest(route=route):
                snapshot = core.as_dict()
                self.assertEqual(set(snapshot), fields)
                self.assertEqual(snapshot["schema"], "hepta.hia.program.v1")
                self.assertEqual(snapshot.get("exports"), exports)
                self.assertIsNone(core.structured_bytes)
                self.assertEqual(core.scalar_entrypoints, frozenset({"sum_rows"}))
                self.assertEqual(verify_core(core.canonical_bytes).scalar_entrypoints,
                                 frozenset({"sum_rows"}))
                for n in (-2, 0, 1, 2, 3, 5, 9):
                    expected = sum(sum(range(i)) + (2 if i < 3 else 1)
                                   for i in range(max(n, 0)))
                    with patch("hepta.parser.parse", side_effect=AssertionError("source replay")):
                        self.assertEqual(execute_core(core, "sum_rows", [n])["result"], expected)

    def test_imported_owned_operations_share_the_same_resource_authority(self):
        old = lower_executable_core(parse(OWNED, "owned.hepta"))
        core = from_executable_core(old, source=OWNED)
        self.assertEqual(set(core.as_dict()), {"schema", "module", "functions", "exports"})
        self.assertEqual(core.as_dict()["exports"], ["checksum"])
        self.assertEqual(core.scalar_entrypoints, frozenset({"checksum"}))
        self.assertNotIn("fill", core.scalar_entrypoints)
        for n in (0, 1, 11, 260):
            report = execute_core(core, "checksum", [n])
            self.assertEqual(report["result"], sum(i % 256 for i in range(n)))
            self.assertEqual(report["resources"]["live_owners"], 0)
            self.assertEqual(report["resources"]["live_local_loans"], 0)
        mutated = core.as_dict()
        # A changed resource program cannot inherit safety from its old receipt.
        for fn in mutated["functions"]:
            for block in fn["blocks"]:
                block["ops"] = [op for op in block["ops"] if op["op"] != "owner.drop"]
        with self.assertRaises(HIAProgramRejected):
            verify_core(mutated)

    def test_legacy_import_still_refuses_rebound_source_and_changed_old_phi(self):
        program, checked, scalar = fixture(SCALAR)
        other, other_checked, _ = fixture(SCALAR.replace("sum+2", "sum+3"))
        with self.assertRaises(ValueError):
            from_scalar_core(scalar, program=other, checked=other_checked,
                             project_sha256=_PROJECT)
        old = lower_executable_core(program, checked)
        changed = copy.deepcopy(old)
        changed["functions"][0]["name"] = "substituted"
        with self.assertRaises(ValueError):
            from_executable_core(changed, source=SCALAR)

    @unittest.skipUnless(shutil.which(os.environ.get("CLANG", "clang")), "clang required")
    def test_both_legacy_inputs_and_owned_resources_reach_same_direct_native_backend(self):
        program, checked, scalar = fixture(SCALAR)
        old = lower_executable_core(program, checked)
        programs = [from_scalar_core(scalar, program=program, checked=checked,
                                    project_sha256=_PROJECT),
                    from_executable_core(old, source=SCALAR),
                    from_executable_core(lower_executable_core(parse(OWNED, "owned.hepta")),
                                         source=OWNED)]
        with tempfile.TemporaryDirectory() as temp:
            for i, core in enumerate(programs):
                out = Path(temp) / f"core{i}.so"
                with patch("hepta.parser.parse", side_effect=AssertionError("source replay")):
                    receipt = build_core(core, out, clang=os.environ.get("CLANG", "clang"))
                self.assertTrue(receipt["ok"], receipt)
                lib = ctypes.CDLL(str(out))
                name, ctype = ("checksum", ctypes.c_uint64) if i == 2 else ("sum_rows", ctypes.c_int32)
                fn = getattr(lib, name)
                fn.argtypes, fn.restype = [ctype], ctype
                for n in (0, 1, 5, 9):
                    self.assertEqual(fn(n), execute_core(core, name, [n])["result"])


if __name__ == "__main__":
    unittest.main()
