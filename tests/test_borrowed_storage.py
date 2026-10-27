"""Stored references use real Rust regions; unsupported native/IR paths close."""
import copy
from pathlib import Path
import os
import tempfile
import unittest

from hepta.backend import compile_rust, find_rustc
from hepta.flow_ir import lower_checked_cfg
from hepta.hmir import HMIRUnsupported, lower_checked_cfg as lower_hmir
from hepta.lexer import tokenize
from hepta.parser import parse
from hepta.pipeline import analyze, analyze_project, concurrent_ir_analysis, hsir_analysis, interface_hash, resource_ir_analysis
from tools.borrowed_storage_cases import FRONTEND_REJECTIONS, MUTABLE, NATIVE_REJECTIONS, SHARED
from tools.qualify_borrowed_storage import qualify, validate_borrowed_storage_report

ROOT = Path(__file__).resolve().parents[1]
RUSTC = find_rustc(os.environ.get("RUSTC"))


class BorrowedStorageFrontendTests(unittest.TestCase):
    def test_explicit_lifetime_syntax_preserves_spans_and_type_identity(self):
        tokens = tokenize("\n  'region '_", "life.hepta")
        self.assertEqual([(t.kind, t.value, t.span.line, t.span.column) for t in tokens[:-1]],
                         [("LIFETIME", "region", 2, 3), ("LIFETIME", "_", 2, 11)])
        program = parse("struct V<'a>{data:read 'a [u8]} fn f<'a>(x:read 'a [u8])->V<'a> effects {} {return V{data:read x};}")
        self.assertEqual(program.structs[0].lifetime_params, ("a",))
        self.assertEqual(str(program.structs[0].fields[0].type), "read 'a [u8]")
        self.assertEqual(program.functions[0].params[0].lifetime, "a")
        self.assertEqual(str(program.functions[0].return_type), "V<'a>")

    def test_scope_affine_and_unsupported_shapes_are_rejected_before_codegen(self):
        for name, (source, code) in FRONTEND_REJECTIONS.items():
            with self.subTest(name=name):
                analysis = analyze(source, name + ".hepta", native=False)
                self.assertFalse(analysis.report["ok"], analysis.report)
                self.assertIsNone(analysis.rust)
                self.assertIn(code, {d["code"] for d in analysis.report["diagnostics"]})

    def test_frontend_only_cannot_claim_lifetime_verification(self):
        source = NATIVE_REJECTIONS["copied_shared_view_keeps_owner_live"][0]
        analysis = analyze(source, native=False, crate_type="bin")
        self.assertTrue(analysis.report["ok"], analysis.report)
        self.assertEqual(analysis.report["status"], "frontend_only")
        self.assertEqual(analysis.report["checks"]["rust_borrows_types"], "not_run")
        self.assertTrue(analysis.report["borrowed_storage"]["native_lifetimes_required"])
        self.assertFalse(analysis.report["borrowed_storage"]["native_lifetimes_checked"])
        self.assertFalse(hsir_analysis(analysis)["hsir"]["claims"]["native_borrow_validation"])

    def test_unsupported_c_and_independent_ir_reject_even_unused_lifetime_records(self):
        source = "struct View<'a>{value:read 'a u64} fn main()->Unit effects {} {}"
        analysis = analyze(source, native=False, crate_type="bin")
        self.assertTrue(analysis.report["ok"], analysis.report)
        c = analyze(source, native=False, backend="c", crate_type="bin")
        self.assertFalse(c.report["ok"])
        self.assertIsNone(c.c)
        self.assertEqual(c.report["diagnostics"][0]["code"], "E_C_BORROW_STORAGE")
        for lower, key in ((resource_ir_analysis, "resource_ir"), (concurrent_ir_analysis, "concurrent_ir")):
            result = lower(analysis)
            self.assertFalse(result["ok"], result)
            self.assertIsNone(result[key])
            self.assertIsNone(result["verifier"])
        with self.assertRaises(HMIRUnsupported):
            lower_hmir(analysis.program, analysis.checked)

    def test_interface_hsir_and_descriptive_cfg_preserve_lifetime_and_origin_identity(self):
        source = "fn choose<'a,'b>(a:read 'a u64,b:read 'b u64)->read 'a u64 from a effects {} {return read a;}"
        analysis = analyze(source, native=False)
        self.assertTrue(analysis.report["ok"], analysis.report)
        changed = source.replace("b:read 'b", "b:read 'a")
        self.assertNotEqual(interface_hash(parse(source)), interface_hash(parse(changed)))
        hsir = hsir_analysis(analysis)["hsir"]["functions"][0]
        cfg = lower_checked_cfg(analysis.program, analysis.checked)["functions"][0]["signature"]
        for signature in (hsir, cfg):
            self.assertEqual(signature["lifetime_params"], ["a", "b"])
            self.assertEqual(signature["return_lifetime"], "a")
            self.assertEqual(signature["return_origin"], "a")
            self.assertEqual([p["lifetime"] for p in signature["params"]], ["a", "b"])

    def test_reserved_reference_type_spellings_fail_without_internal_crash(self):
        for spelling in ("ref_read", "ref_mut", "ref_read<u8>"):
            analysis = analyze(f"fn bad(x:{spelling})->Unit effects {{}} {{}}", native=False)
            self.assertFalse(analysis.report["ok"], analysis.report)


class NativeBorrowedStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="hepta-borrowed-storage-tests-")
        cls.report = qualify(Path(cls.directory.name) / "qualification.json", rustc=RUSTC)
        if cls.report["status"] != "passed":
            raise AssertionError(cls.report.get("error", "native storage qualification failed"))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_real_native_programs_and_all_static_denominators(self):
        validate_borrowed_storage_report(self.report)
        self.assertEqual(len(self.report["positives"]), 5)
        self.assertEqual(len(self.report["native_rejections"]), 10)
        self.assertEqual(len(self.report["frontend_rejections"]), 22)
        self.assertEqual(self.report["positives"][0]["execution"]["stdout"], "275\n")
        self.assertTrue(all(not row["native_execution_attempted"] for row in self.report["native_rejections"]))

    def test_public_pipeline_native_check_rejects_every_lifetime_candidate_with_source_mapping(self):
        for name, (source, codes) in NATIVE_REJECTIONS.items():
            with self.subTest(name=name):
                analysis = analyze(source, name + ".hepta", native=True, crate_type="bin", rustc=RUSTC)
                self.assertFalse(analysis.report["ok"], analysis.report)
                self.assertEqual(analysis.report["checks"]["types_effects_resources"], "passed_in_supported_subset")
                self.assertEqual(analysis.report["checks"]["rust_borrows_types"], "rejected")
                self.assertFalse(analysis.report["borrowed_storage"]["native_lifetimes_checked"])
                self.assertTrue(codes.intersection(d["code"] for d in analysis.report["diagnostics"]))
                self.assertTrue(any(mapping["span"]["path"] == name + ".hepta" and mapping["is_primary"]
                                    for diagnostic in analysis.report["diagnostics"] for mapping in diagnostic.get("source_mappings", [])))

    def test_reference_only_library_has_a_real_no_std_object(self):
        source = """struct View<'a>{data:read 'a [u8]}
pub fn sum<'a>(data:read 'a [u8])->u64 effects {panic} {
    let view=View{data:read data};let mut total:u64=0;
    for i in 0..len(view.data){total=wrapping_add(total,view.data[i] as u64);}return total;
}"""
        analysis = analyze(source, native=True, no_std=True, crate_type="obj", rustc=RUSTC)
        self.assertTrue(analysis.report["ok"], analysis.report)
        artifact = Path(self.directory.name) / "view-no-std.o"
        built = compile_rust(analysis.rust, rustc=RUSTC, crate_type="obj", output=artifact)
        self.assertTrue(built["ok"], built)
        self.assertGreater(built["artifact_bytes"], 0)
        self.assertNotIn("std::vec", analysis.rust)

    def test_report_rejects_omitted_native_checks_malformed_denominators_and_inflated_claims(self):
        mutations = [
            lambda r: r.update(compiler_sha256="0" * 64),
            lambda r: r["sources"].pop("examples/borrowed_storage/library.hepta"),
            lambda r: r["claims"].update(frontend_independently_proves_lifetimes=True),
            lambda r: r["claims"].update(actual_valid_native_programs_executed=1),
            lambda r: r.update(whole_language_soundness_proved=True),
            lambda r: r["positives"][0]["frontend"].pop("claims"),
            lambda r: r["positives"][0]["frontend"]["claims"].update(whole_language_soundness_proved=True),
            lambda r: r["positives"][0]["frontend"].update(all_lifetimes_independently_proved=True),
            lambda r: r["scope"].update(verification="all lifetimes proved"),
            lambda r: r.update(rust_toolchain={}),
            lambda r: r["positives"].pop(),
            lambda r: r["positives"].__setitem__(1, r["positives"][0]),
            lambda r: r["positives"][0]["frontend"].update(checks={}),
            lambda r: r["positives"][0]["frontend"]["borrowed_storage"].update(native_lifetimes_checked=False),
            lambda r: r["positives"][0]["frontend"].update(status="frontend_only"),
            lambda r: r["positives"][0].update(generated_source="fn main() {}"),
            lambda r: r["positives"][0]["build"].update(artifact_bytes=True),
            lambda r: r["positives"][0]["build"].update(artifact_sha256=None, validation_artifact_sha256=None),
            lambda r: r["positives"][0]["build"].update(check_only=True),
            lambda r: r["positives"][0]["build"].update(flags=[]),
            lambda r: r["positives"][0]["execution"].update(returncode=False),
            lambda r: r["positives"][0]["execution"].update(stdout="276\n"),
            lambda r: r["positives"][0]["execution"].update(elapsed_ns=0),
            lambda r: r["native_rejections"].pop(),
            lambda r: r["native_rejections"].__setitem__(1, r["native_rejections"][0]),
            lambda r: r["native_rejections"][0].update(source_sha256="0" * 64),
            lambda r: r["native_rejections"][0].update(native_execution_attempted=True),
            lambda r: r["native_rejections"][0]["native_check"].update(returncode=0),
            lambda r: r["native_rejections"][0]["native_check"].update(returncode=True),
            lambda r: r["native_rejections"][0]["native_check"].update(argv=["false"]),
            lambda r: r["native_rejections"][0]["native_check"].update(metadata_emitted=True),
            lambda r: r["native_rejections"][0]["native_check"].update(stderr="borrow checking failed"),
            lambda r: r["native_rejections"][0].update(diagnostics=[]),
            lambda r: r["native_rejections"][0]["diagnostics"][0].pop("source_mappings"),
            lambda r: r["frontend_rejections"].pop(),
            lambda r: r["frontend_rejections"][0]["frontend"].update(ok=True),
            lambda r: r["unsupported_profiles"]["c"].update(ok=True),
            lambda r: r["unsupported_profiles"]["resource_ir"].update(resource_ir={}),
            lambda r: r["unsupported_profiles"].pop("concurrent_ir"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                changed = copy.deepcopy(self.report)
                mutate(changed)
                with self.assertRaises(ValueError):
                    validate_borrowed_storage_report(changed)
        for malformed in (None, [], "passed", {"status": "passed"}):
            with self.subTest(malformed=repr(malformed)), self.assertRaises(ValueError):
                validate_borrowed_storage_report(malformed)

    def test_qualification_does_not_overwrite_an_existing_attempt(self):
        with self.assertRaises(ValueError):
            qualify(Path(self.directory.name) / "qualification.json", rustc=RUSTC)


if __name__ == "__main__":
    unittest.main()
