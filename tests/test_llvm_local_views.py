"""Local native views: real differential cleanup, rejection and evidence tests."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_backend import emit_c
from hepta.llvm_owned_backend import LLVMOwnedRejected, compile_owned_llvm, emit_owned_llvm
from hepta.owned_drop_plan import DropPlan, derive_resource_drop_plan
from hepta.pipeline import analyze, analyze_project
from hepta.resource_ir import ResourceIRError, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_source import verify_resource_source
from tools.qualify_llvm_local_views import ENTRY, UNSUPPORTED, observations, qualify, sha, validate_report
from tools.resource_view_cases import FRONTEND_REJECTIONS, NATIVE_REJECTIONS, SCOPED_NEIGHBOURS


class LocalViewLoweringTests(unittest.TestCase):
    def test_existing_generic_disjoint_and_local_view_programs_lower_independently(self):
        fixture = analyze_project(ENTRY, native=False)
        neighbours = analyze(SCOPED_NEIGHBOURS, "scoped.hepta", native=False)
        with patch("hepta.backend.compile_rust") as rust, patch("hepta.c_backend.compile_c") as c:
            for analysis in (fixture, neighbours):
                self.assertTrue(analysis.report["ok"], analysis.report)
                self.assertIn("define", emit_owned_llvm(analysis.program, analysis.checked).text)
                self.assertIn("__hepta_cb", emit_c(analysis.program, analysis.checked))
            rust.assert_not_called()
            c.assert_not_called()

    def test_all_illegal_aliases_and_owner_moves_are_independently_rejected(self):
        for name, (source, _) in NATIVE_REJECTIONS.items():
            with self.subTest(name=name):
                analysis = analyze(source, name + ".hepta", native=False)
                self.assertTrue(analysis.report["ok"], analysis.report)
                with self.assertRaises(ResourceIRError) as error:
                    emit_owned_llvm(analysis.program, analysis.checked)
                self.assertEqual(error.exception.code, "E_RIR_LOAN_CONFLICT")
                c = analyze(source, name + ".hepta", native=False, backend="c")
                self.assertFalse(c.report["ok"], c.report)
                self.assertEqual(c.report["diagnostics"][0]["code"], "E_C_RESOURCE_IR")

    def test_exclusive_affinity_and_read_only_writes_still_reject(self):
        for name, (source, code) in FRONTEND_REJECTIONS.items():
            for backend in ("rust", "c"):
                with self.subTest(name=name, backend=backend):
                    analysis = analyze(source, name + ".hepta", native=False, backend=backend)
                    self.assertFalse(analysis.report["ok"], analysis.report)
                    self.assertIn(code, {d["code"] for d in analysis.report["diagnostics"]})

    def test_unsupported_regions_and_unused_shapes_remain_rejected(self):
        for name, source in UNSUPPORTED.items():
            with self.subTest(name=name):
                analysis = analyze(source, name + ".hepta", native=False)
                self.assertTrue(analysis.report["ok"], analysis.report)
                with self.assertRaises((ResourceIRError, LLVMOwnedRejected)):
                    emit_owned_llvm(analysis.program, analysis.checked)
                c = analyze(source, name + ".hepta", native=False, backend="c")
                self.assertFalse(c.report["ok"], c.report)
                # An unused v5 declaration currently fails at the earlier
                # resource schema gate; the used-v5 case below reaches the
                # explicit native profile guard.
                expected = "E_C_RESOURCE_IR" if name == "labelled_view" else "E_C_BORROW_STORAGE"
                self.assertEqual(c.report["diagnostics"][0]["code"], expected)

    def test_v5_labelled_views_pass_resource_verifier_but_do_not_enter_v4_native_scope(self):
        source = """struct L<'a>{tag:u64,data:read 'a [u8]}
fn f(data:read [u8])->u64 effects {} {let v=L{tag:9,data:read data};return v.tag;}"""
        analysis = analyze(source, "labelled.hepta", native=False)
        self.assertTrue(analysis.report["ok"], analysis.report)
        graph = lower_resource_ir(analysis.program, analysis.checked)
        self.assertEqual(graph["schema"], "hepta.resource-ir.v5")
        self.assertTrue(verify_resource_ir(graph)["ok"])
        with self.assertRaisesRegex(LLVMOwnedRejected, "E_LLVM_OWNED_VIEW_PROFILE"):
            emit_owned_llvm(analysis.program, analysis.checked)
        self.assertFalse(analyze(source, "labelled.hepta", native=False, backend="c").report["ok"])

    def test_owner_drop_plan_guard_remains_active_in_a_program_with_local_views(self):
        analysis = analyze_project(ENTRY, native=False)

        def forged(types, name):
            if name == "Pair":
                return DropPlan("struct", fields=(("left", "Buffer<u8>", False), ("right", "Buffer<u8>", True)))
            return derive_resource_drop_plan(types, name)

        with patch("hepta.llvm_owned_backend.derive_resource_drop_plan", side_effect=forged):
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_LLVM_OWNED_DROP_PLAN"):
                emit_owned_llvm(analysis.program, analysis.checked)

    def test_layout_equal_source_rename_cannot_rebind_old_llvm_before_native(self):
        source = ENTRY.read_text()
        before = analyze(source, "identity.hepta", native=False)
        after = analyze(source.replace("Bytes", "Reading"), "identity.hepta", native=False)
        original = emit_owned_llvm(before.program, before.checked)
        changed = emit_owned_llvm(after.program, after.checked)
        self.assertEqual(original.text, changed.text)
        self.assertNotEqual(original.resource_ir_sha256, changed.resource_ir_sha256)
        with tempfile.TemporaryDirectory() as td, patch("hepta.llvm_owned_backend._clang_run") as clang:
            with self.assertRaisesRegex(LLVMOwnedRejected, "E_LLVM_OWNED_ORIGIN"):
                compile_owned_llvm(original, program=after.program, checked=after.checked, output=Path(td) / "wrong.o", kind="object")
            clang.assert_not_called()
            self.assertFalse((Path(td) / "wrong.o").exists())

    def test_consistently_resealed_view_graph_cannot_replace_source(self):
        analysis = analyze_project(ENTRY, native=False)
        graph = lower_resource_ir(analysis.program, analysis.checked, project_sha256=analysis.project.identity)
        graph["types"]["Bytes<'_>"]["field"] = "different"
        self.assertTrue(verify_resource_ir(graph)["ok"])
        rejected = verify_resource_source(ENTRY, graph, native=False)
        self.assertFalse(rejected["ok"], rejected)
        self.assertEqual(rejected["diagnostics"][0]["code"], "E_RIR_SOURCE_GRAPH")


class NativeLocalViewQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="hepta-local-views-test-")
        cls.report = qualify(Path(cls.directory.name) / "receipt.json", rustc=os.environ.get("RUSTC"),
                             clang=os.environ.get("CLANG", "clang"), cc=os.environ.get("CC", "gcc"))
        if not cls.report["ok"]:
            raise AssertionError(cls.report.get("validation_error", cls.report))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_real_native_complete_cases_faults_cleanup_and_bounds(self):
        validate_report(self.report)
        expected = observations()
        self.assertEqual(len(expected), 140)
        for name, native in self.report["native"].items():
            with self.subTest(backend=name):
                self.assertEqual(native["observations"], expected)
                self.assertEqual(sum(row["allocations"] for row in expected), 110)
                self.assertEqual(sum(row["releases"] for row in expected), 110)
                self.assertEqual(sum(row["refusals"] for row in expected), 30)
                self.assertTrue(all(row["live"] == 0 for row in native["observations"]))
                self.assertEqual(native["bounds"]["returncode"], -6)

    def test_real_wrong_native_cleanup_is_executed_and_observed(self):
        negative = self.report["negative_control"]
        self.assertEqual(negative["execution"]["returncode"], 86)
        self.assertEqual(negative["observations"][-1]["allocations"], 2)
        self.assertEqual(negative["observations"][-1]["releases"], 0)
        self.assertEqual(negative["observations"][-1]["live"], 2)

    def test_strict_validator_rejects_report_tampering_without_rerunning_natives(self):
        mutations = {
            "compiler": lambda r: r.update(compiler_sha256="0" * 64),
            "lifetime_claim": lambda r: r["claims"].update(stored_view_parameters_or_returns_supported=True),
            "v5_claim": lambda r: r["claims"].update(labelled_views_supported=True),
            "performance_claim": lambda r: r["claims"].update(performance_qualified=True),
            "resource_graph": lambda r: r["resource_graph"]["types"]["Bytes<'_>"].update(field="other"),
            "llvm": lambda r: r["generated_sources"].update(llvm=r["generated_sources"]["llvm"] + "\n"),
            "oracle": lambda r: r["generated_sources"].update(cases_sha256="0" * 64),
            "missing_backend": lambda r: r["native"].pop("c"),
            "missing_case": lambda r: r["native"]["llvm"]["observations"].pop(),
            "live_owner": lambda r: r["native"]["llvm"]["observations"][20].update(live=1),
            "raw_stdout": lambda r: r["native"]["llvm"]["execution"].update(stdout="", stdout_sha256=sha(b"")),
            "bounds": lambda r: r["native"]["llvm"]["bounds"].update(returncode=0),
            "binary": lambda r: r["native"]["llvm"]["executable"].update(sha256="0" * 64),
            "library": lambda r: r["native"]["c"]["library"].update(sha256="0" * 64),
            "fallback": lambda r: r["builds"]["llvm"]["claims"].update(fallback_used=True),
            "reference": lambda r: r["builds"]["llvm"]["reference_validation"]["checks"].update(rust_borrows_types="not_run"),
            "layout_scope": lambda r: r["builds"]["llvm"]["native_backend"]["target_layout_probe"].update(compiler_checked=1),
            "layout_origin": lambda r: r["builds"]["llvm"]["native_backend"]["target_layout_probe"].update(bound_llvm_sha256="0" * 64),
            "ub_checks": lambda r: r["builds"]["c"]["flags"].remove("-fsanitize=undefined"),
            "command": lambda r: r["native"]["llvm"]["execution"]["command"].append("unexpected"),
            "leak_execution": lambda r: r["negative_control"]["execution"].update(returncode=0),
            "leak_live": lambda r: r["negative_control"]["observations"][-1].update(live=0),
            "leak_source": lambda r: r["negative_control"].update(source_sha256="0" * 64),
            "negative_denominator": lambda r: r["source_rejections"].pop(next(iter(r["source_rejections"]))),
            "fake_origin_rejection": lambda r: r["tamper_rejections"]["rehashed_native_branch"].update(native_invoked=True),
            "rejected_claim_proof": lambda r: r["source_rejections"]["escaping_view"]["build"]["claims"].update(whole_language_memory_safety_proved=True),
            "rejected_claim_execution": lambda r: r["source_rejections"]["escaping_view"]["build"]["claims"].update(native_execution_qualified=True),
            "rejected_claim_cross_target": lambda r: r["source_rejections"]["escaping_view"]["build"]["claims"].update(cross_target_execution_qualified=True),
            "unsupported_reference_target": lambda r: r["source_rejections"]["escaping_view"]["build"]["reference_validation"]["backend"].update(target="aarch64-unknown-linux-gnu"),
            "unsupported_reference_compiler": lambda r: r["source_rejections"]["escaping_view"]["build"]["reference_validation"]["backend"]["toolchain"].update(executable_sha256="0" * 64),
            "unsupported_reference_scope": lambda r: r["source_rejections"]["escaping_view"]["build"]["reference_validation"]["borrowed_storage"].update(native_lifetimes_checked=False),
            "unsupported_reference_graph": lambda r: r["source_rejections"]["escaping_view"]["build"]["reference_validation"]["project"].update(sha256="0" * 64),
            "c_target": lambda r: r["builds"]["c"].update(target="aarch64-unknown-linux-gnu"),
            "llvm_version": lambda r: r["builds"]["llvm"]["native_backend"]["toolchain"].update(version="rustc 1.0"),
            "rust_rejection_borrow_status": lambda r: r["source_rejections"]["shared_view_blocks_owner_write"]["build"]["reference_validation"]["checks"].update(rust_borrows_types="not_run"),
            "rust_rejection_profile": lambda r: r["source_rejections"]["shared_view_blocks_owner_write"]["build"]["reference_validation"]["profile"].update(crate_type="bin"),
            "rust_rejection_flags": lambda r: r["source_rejections"]["shared_view_blocks_owner_write"]["build"]["reference_validation"]["backend"]["flags"].remove("overflow-checks=yes"),
            "frontend_rejection_claim": lambda r: r["source_rejections"]["exclusive_copy"]["build"]["reference_validation"]["borrowed_storage"].update(general_lifetime_system_complete=True),
        }
        with patch("tools.qualify_llvm_local_views.execute") as native:
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    report = json_copy(self.report)
                    mutate(report)
                    with self.assertRaises(ValueError):
                        validate_report(report)
            native.assert_not_called()


def json_copy(value):
    # Round-tripping removes incidental shared Python dict identities between
    # observations; mutation tests operate on the actual JSON wire format.
    import json
    return json.loads(json.dumps(value))
