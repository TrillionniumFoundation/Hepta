"""Replay real checked source; never authenticate a graph by its own digest."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.modules import load_project
from hepta.checker import check
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_source import verify_resource_source


ROOT = Path(__file__).resolve().parents[1]
SIMPLE = "fn main()->Unit effects {alloc,block,panic} {let bytes=buffer(8);drop(move bytes);}"


def exported(path):
    project = load_project(path)
    checked = check(project.program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return lower_resource_ir(project.program, checked, project_sha256=project.identity)


def function(document, name):
    return next(fn for fn in document["functions"] if fn["name"] == name)


class ResourceSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-resource-source-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source = self.directory / "main.hepta"
        self.source.write_text(SIMPLE, encoding="utf-8")

    def assert_rejected(self, graph, code, *, native=False):
        report = verify_resource_source(self.source, graph, native=native)
        self.assertFalse(report["ok"], report)
        self.assertFalse(report["source_binding_verified"], report)
        self.assertEqual(report["diagnostics"][0]["code"], code, report)
        self.assertTrue(all(v is False for v in report["claims"].values()))
        return report

    def test_native_replay_covers_owned_adt_generic_match_and_returned_loans(self):
        for entry in (self.source, ROOT / "examples/owned/main.hepta",
                      ROOT / "examples/owned_generics/main.hepta",
                      ROOT / "examples/resource_ir/returned_views.hepta"):
            with self.subTest(entry=entry):
                report = verify_resource_source(entry, exported(entry))
                self.assertTrue(report["ok"], report)
                self.assertTrue(report["source_binding_verified"])
                self.assertEqual(report["status"], "source_replayed")
                self.assertEqual(report["source_binding"]["native_reference"], "rustc_checked")
                self.assertEqual(report["source_validation"]["checks"]["rust_borrows_types"], "rustc_checked")
                self.assertEqual(report["source_binding"]["resource_ir_sha256"],
                                 report["resource_verification"]["ir_sha256"])
                self.assertTrue(all(v is False for v in report["claims"].values()))
                payload = {k: v for k, v in report.items() if k != "sha256"}
                self.assertEqual(report["sha256"], hashlib.sha256(json.dumps(
                    payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                    allow_nan=False).encode()).hexdigest())

    def test_explicit_frontend_profile_never_claims_native_validation(self):
        report = verify_resource_source(self.source, exported(self.source), native=False)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["status"], "frontend_only_source_replayed")
        self.assertEqual(report["source_binding"]["native_reference"], "not_run")
        self.assertEqual(report["source_validation"]["checks"]["rust_borrows_types"], "not_run")

    def test_missing_native_compiler_does_not_fall_back(self):
        graph = exported(self.source)
        report = verify_resource_source(self.source, graph, rustc=str(self.directory / "absent-rustc"))
        self.assertFalse(report["ok"])
        self.assertFalse(report["source_binding_verified"])
        self.assertEqual(report["diagnostics"][0]["code"], "E_RIR_SOURCE_REJECTED")

    def test_graph_self_asserted_source_identity_is_not_accepted(self):
        graph = exported(self.source)
        graph["source_sha256"] = "0" * 64
        self.assertTrue(verify_resource_ir(graph)["ok"])
        self.assert_rejected(graph, "E_RIR_SOURCE_IDENTITY")

    def test_balanced_but_omitted_acquisition_and_drop_are_not_source_evidence(self):
        graph = exported(self.source)
        # This is a valid resource graph for an empty function, but not the
        # graph obtained from the unchanged source that allocates/releases.
        function(graph, "main")["blocks"][0]["ops"] = []
        self.assertTrue(verify_resource_ir(graph)["ok"])
        self.assert_rejected(graph, "E_RIR_SOURCE_GRAPH")

    def test_internally_valid_return_origin_substitution_is_rejected(self):
        self.source.write_text("fn first(a:read [u8],b:read [u8])->read [u8] from a effects {} {return read a;}", encoding="utf-8")
        graph = exported(self.source)
        fn = function(graph, "first")
        fn["returns"]["origin"] = "p1"
        borrow = next(op for block in fn["blocks"] for op in block["ops"] if op["op"] == "borrow")
        borrow["place"]["root"] = "p1"
        self.assertTrue(verify_resource_ir(graph)["ok"])
        self.assert_rejected(graph, "E_RIR_SOURCE_GRAPH")

    def test_external_obligations_are_retained_after_actual_native_check(self):
        self.source.write_text('extern "C" fn native(x:u64)->u64 effects {ffi,unsafe}; fn call(x:u64)->u64 effects {ffi,unsafe} {unsafe {return native(x);}}', encoding="utf-8")
        graph = exported(self.source)
        report = verify_resource_source(self.source, graph)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["status"], "source_replayed_with_external_assumptions")
        self.assertEqual(report["source_binding"]["external_obligations"]["foreign:native"]["status"], "assumed_not_verified")
        self.assertTrue(report["source_binding"]["canonical_foreign_assumptions"])
        self.assertFalse(report["claims"]["external_contracts_proved"])
        # Erasing both the call and declaration produces a self-consistent
        # data-only graph; exact source replay must detect the omission.
        graph["functions"] = [fn for fn in graph["functions"] if not fn["external"]]
        graph["obligations"] = {}
        for fn in graph["functions"]:
            for block in fn["blocks"]:
                block["ops"] = [op for op in block["ops"] if op["op"] != "foreign"]
        self.assertTrue(verify_resource_ir(graph)["ok"])
        self.assert_rejected(graph, "E_RIR_SOURCE_GRAPH")

    def test_import_change_invalidates_project_even_when_entry_bytes_match(self):
        module = self.directory / "helper.hepta"
        module.write_text("pub fn value()->u64 effects {} {return 1;}", encoding="utf-8")
        self.source.write_text("import helper; fn main()->Unit effects {panic} {assert(helper::value()==1);}", encoding="utf-8")
        graph = exported(self.source)
        module.write_text("pub fn value()->u64 effects {} {return 2;}", encoding="utf-8")
        self.assert_rejected(graph, "E_RIR_SOURCE_IDENTITY")

    def test_source_change_is_detected_after_replay(self):
        graph = exported(self.source)
        actual_lower = lower_resource_ir

        def mutate_after_lowering(*args, **kwargs):
            result = actual_lower(*args, **kwargs)
            self.source.write_text(SIMPLE + "\n// changed during replay\n", encoding="utf-8")
            return result

        with patch("hepta.resource_source.lower_resource_ir", side_effect=mutate_after_lowering):
            self.assert_rejected(graph, "E_RIR_SOURCE_STALE")

    def test_import_symlink_rebinding_is_detected_after_replay(self):
        for name in ("helper_a.hepta", "helper_b.hepta"):
            (self.directory / name).write_text("pub fn value()->u64 effects {} {return 1;}", encoding="utf-8")
        alias = self.directory / "helper.hepta"
        alias.symlink_to("helper_a.hepta")
        self.source.write_text("import helper; fn main()->Unit effects {panic} {assert(helper::value()==1);}", encoding="utf-8")
        graph = exported(self.source)
        actual_lower = lower_resource_ir

        def rebind_after_lowering(*args, **kwargs):
            result = actual_lower(*args, **kwargs)
            alias.unlink()
            alias.symlink_to("helper_b.hepta")
            return result

        with patch("hepta.resource_source.lower_resource_ir", side_effect=rebind_after_lowering):
            self.assert_rejected(graph, "E_RIR_SOURCE_STALE")

    def test_actual_rust_borrow_rejection_cannot_be_overridden_by_valid_graph(self):
        graph = exported(self.source)
        self.source.write_text("""
        struct Packet{data:Buffer<u8>}
        fn view(p:read Packet)->read Buffer<u8> effects {} {return read p.data;}
        fn observe(a:read Buffer<u8>,p:take Packet)->Unit effects {alloc,block} {drop(move p);}
        fn main()->Unit effects {alloc,block,panic} {
          let p=Packet{data:buffer(4)};observe(read view(read p),move p);
        }
        """, encoding="utf-8")
        report = self.assert_rejected(graph, "E_RIR_SOURCE_REJECTED", native=True)
        self.assertIn("E0505", {d["code"] for d in report["source_validation"]["diagnostics"]})

    def test_resource_leak_is_rejected_before_native_source_work(self):
        graph = exported(self.source)
        for block in function(graph, "main")["blocks"]:
            block["ops"] = [op for op in block["ops"] if op["op"] != "drop"]
        report = self.assert_rejected(graph, "E_RIR_LEAK")
        self.assertIsNone(report["source_validation"])

    def test_elevated_claims_are_rejected_not_copied_into_replay(self):
        graph = exported(self.source)
        graph["claims"]["source_to_ir_refinement_proved"] = True
        self.assert_rejected(graph, "E_RIR_CLAIM")

    def test_cli_reads_bounded_unambiguous_graph_and_runs_native_replay(self):
        graph_path = self.directory / "graph.json"
        graph_path.write_text(json.dumps(exported(self.source)), encoding="utf-8")
        process = subprocess.run([sys.executable, "-m", "hepta.resource_source", str(self.source), str(graph_path)],
                                 cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        report = json.loads(process.stdout)
        self.assertTrue(report["source_binding_verified"])
        self.assertEqual(report["status"], "source_replayed")
        graph_path.write_text('{"schema":"bad","schema":"hepta.resource-ir.v3"}', encoding="utf-8")
        process = subprocess.run([sys.executable, "-m", "hepta.resource_source", str(self.source), str(graph_path)],
                                 cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 1)
        report = json.loads(process.stdout)
        self.assertEqual(report["diagnostics"][0]["code"], "E_RIR_JSON")
        self.assertIsNone(report["source_validation"])


if __name__ == "__main__":
    unittest.main()
