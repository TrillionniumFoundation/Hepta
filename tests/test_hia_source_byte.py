"""Strict source-to-byte-oracle boundary; fake downstream is NOT native validation."""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from hepta.hia_source_byte import HIASourceByteRejected, replay_source_byte_path

PROJECT = "d" * 64
SOURCE = "a" * 64
RESOURCE = "b" * 64
BYTE = "c" * 64


def analysis(native=True, *, parameter_names=("enabled", "second")):
    f = SimpleNamespace(name="case", extern_c=False,
        params=[SimpleNamespace(name=name, mode="value", type="bool")
                for name in parameter_names])
    project = SimpleNamespace(identity=PROJECT, unchanged=lambda: True)
    return SimpleNamespace(
        program=SimpleNamespace(functions=[f]), checked=SimpleNamespace(ok=True),
        project=project,
        report={"ok": True, "status": "checked" if native else "frontend_only",
                "checks": {"rust_borrows_types": "rustc_checked" if native else "not_run"},
                "backend": {"ok": native}})


def graph():
    return {"source_sha256": SOURCE, "project_sha256": PROJECT,
            "obligations": {}, "functions": [{"name": "case", "params": [
                {"id": "p0", "type": "bool", "mode": "value"},
                {"id": "p1", "type": "bool", "mode": "value"}]}]}


def semantic():
    return {"schema": "hepta.hsir.v0", "profile": "checked_typed_ast_not_verified_mir",
            "source_sha256": SOURCE, "all_expressions_typed": True,
            "untyped_expressions": [], "external_obligations": [],
            "foreign_assumptions": [], "volatile_accesses": []}


def byte_witness():
    value = {"resource_ir_sha256": RESOURCE,
             "schema": "hepta.hia-byte-memory-trace.v0",
             "status": "finite_external_byte_actions_over_verified_resource_path",
             "function": "case",
             "claims": {
                 "memory_bytes_match_original_source_proved": False,
                 "full_memory_ssa_proved": False,
                 "interprocedural_aliasing_proved": False,
                 "pointer_provenance_proved": False,
                 "allocator_failure_semantics_proved": False,
                 "native_llvm_backend_refinement_proved": False,
                 "whole_language_soundness_proved": False,
             },
             "external_allocation_extents_and_memory_actions": True,
             "allocation_count": 1, "free_count": 1}
    wire = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    value["trace_sha256"] = sha256(wire).hexdigest()
    return value


class SourceByteBindingTests(unittest.TestCase):
    def setUp(self):
        self.native = True
        self.record = analysis()
        self.g = graph()
        self.s = semantic()
        self.ver = {"ok": True, "status": "resource_cfg_verified", "ir_sha256": RESOURCE}
        self.w = byte_witness()
        self.inputs = {"enabled": True, "second": False}
        self.actions = ({"kind": "alloc", "bytes": 6}, {"kind": "read", "index": 3})

    def run_case(self, *, native=True, changes=None):
        if changes is not None:
            changes()
        with (patch("hepta.hia_source_byte.analyze_project", return_value=self.record) as load,
              patch("hepta.hia_source_byte.lower_checked_program", return_value=self.s),
              patch("hepta.hia_source_byte.lower_resource_ir", return_value=self.g),
              patch("hepta.hia_source_byte.verify_resource_ir", return_value=self.ver),
              patch("hepta.hia_source_byte.replay_byte_memory_path", return_value=self.w) as execute):
            report = replay_source_byte_path("input.hepta", "case",
                boolean_arguments=self.inputs, actions=self.actions, native=native)
        return report, load, execute

    def test_source_parameter_order_wins_over_caller_key_order(self):
        self.inputs = {"second": False, "enabled": True}
        report, load, execute = self.run_case()
        self.assertEqual(report["project_sha256"], PROJECT)
        self.assertEqual(report["source_sha256"], SOURCE)
        self.assertEqual(report["reference"], "pinned_rustc_checked")
        self.assertFalse(report["claims"]["external_byte_actions_are_source_values"])
        self.assertFalse(report["claims"]["native_backend_refinement_proved"])
        self.assertEqual(report["byte_trace_sha256"], self.w["trace_sha256"])
        execute.assert_called_once()
        self.assertEqual(execute.call_args.kwargs["inputs"], {"p0": True, "p1": False})
        self.assertEqual(execute.call_args.kwargs["actions"], self.actions)
        self.assertTrue(load.call_args.kwargs["native"])
        self.assertEqual(self.run_case()[0]["receipt_sha256"], report["receipt_sha256"])

    def test_explicit_frontend_only_never_promotes_native_qualification(self):
        self.record = analysis(False)
        result = self.run_case(native=False)[0]
        self.assertEqual(result["reference"], "frontend_only")
        self.assertFalse(result["claims"]["native_backend_refinement_proved"])

    def test_native_requires_real_rust_receipt_and_backend_success(self):
        for mutation in (lambda: self.record.report["checks"].update(rust_borrows_types="not_run"),
                         lambda: self.record.report["backend"].update(ok=1),
                         lambda: self.record.report.update(status="frontend_only"),
                         lambda: self.record.report.update(ok=1)):
            with self.subTest(mutation=mutation):
                self.setUp(); mutation()
                with self.assertRaisesRegex(HIASourceByteRejected, "E_HIA_SOURCE_BYTE"):
                    self.run_case()

    def test_bool_parameter_types_and_exact_inventory_reject(self):
        for changed in ({"enabled": 1, "second": False}, {"enabled": True},
                        {"enabled": True, "second": False, "surplus": False},
                        {"p0": True, "p1": False}, {"enabled": None, "second": False}):
            with self.subTest(changed=changed):
                self.inputs = changed
                with self.assertRaisesRegex(HIASourceByteRejected, "E_HIA_SOURCE_BYTE"):
                    self.run_case()
        self.inputs = {"enabled": True, "second": False}
        self.record.program.functions[0].params[1].mode = "mut"
        with self.assertRaises(HIASourceByteRejected):
            self.run_case()

    def test_resource_slot_order_identity_and_foreign_source_reject(self):
        for field, value in (("id", "p9"), ("type", "u8"), ("mode", "take")):
            self.g = graph()
            self.g["functions"][0]["params"][1][field] = value
            with self.subTest(field=field):
                with self.assertRaises(HIASourceByteRejected):
                    self.run_case()
        self.g = graph()
        self.s["external_obligations"] = [{"ffi": "unproved"}]
        with self.assertRaises(HIASourceByteRejected):
            self.run_case()

    def test_wrong_source_projection_and_stale_result_reject(self):
        self.g["source_sha256"] = "0" * 64
        with self.assertRaises(HIASourceByteRejected):
            self.run_case()
        self.g = graph()
        calls = [True, False]
        self.record.project.unchanged = lambda: calls.pop(0)
        with self.assertRaises(HIASourceByteRejected):
            self.run_case()

    def test_forged_trace_proof_receipt_reject(self):
        for mutation in (
                lambda: self.w.update(resource_ir_sha256="0" * 64),
                lambda: self.w["claims"].update(memory_bytes_match_original_source_proved=0),
                lambda: self.w["claims"].update(native_llvm_backend_refinement_proved=True),
                lambda: self.w.update(trace_sha256="e" * 64),
                lambda: self.w.update(external_allocation_extents_and_memory_actions=1)):
            self.w = byte_witness()
            mutation()
            with self.assertRaises(HIASourceByteRejected):
                self.run_case()

    def test_real_checked_source_frontend_only_byte_owner_lifetime(self):
        # Runs canonical parse/check/resource lowering (no mock, no rustc).
        # This is NOT a proof that externally supplied allocation bytes are
        # the value of buffer(4), merely a source-bound finite path witness.
        import tempfile
        source = '''module source_byte;
pub fn case(enabled: bool, second: bool) -> Unit effects {alloc, block, panic} {
    let mut data: Buffer<u8> = buffer(4);
    data[1] = 72;
    let value: u8 = data[1];
    if enabled { drop(move data); }
    else { drop(move data); }
}
'''
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "case.hepta"
            path.write_text(source, encoding="utf-8")
            report = replay_source_byte_path(
                path, "case", boolean_arguments={"enabled": True, "second": False},
                actions=({"kind": "alloc", "bytes": 4},
                         {"kind": "write", "index": 1, "value": 72},
                         {"kind": "read", "index": 1}), native=False)
            self.assertEqual(report["reference"], "frontend_only")
            self.assertEqual(report["byte_trace"]["allocation_count"], 1)
            self.assertEqual(report["byte_trace"]["free_count"], 1)
            self.assertEqual(report["byte_trace"]["memory_token_final"], 3)
            self.assertEqual([ev["value"] for ev in
                              report["byte_trace"]["memory_observations"]
                              if ev["kind"] == "read"], [72])
            self.assertFalse(report["claims"]["memory_byte_semantics_match_source_proved"])

    def test_unsupported_actions_and_mode_reject_before_source_checker(self):
        self.actions = ({"kind": "alloc", "bytes": 5},) * 20000
        with self.assertRaises(HIASourceByteRejected):
            self.run_case()
        self.actions = ({"kind": "alloc", "bytes": 5},)
        with self.assertRaises(HIASourceByteRejected):
            replay_source_byte_path("x.hepta", "case", boolean_arguments=self.inputs,
                actions=self.actions, native=1)


if __name__ == "__main__":
    unittest.main()
