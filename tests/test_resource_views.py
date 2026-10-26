"""Independent stored-loan rules, current-source replay, and real native checks."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.backend import compile_rust
from hepta.checker import check
from hepta.modules import load_project
from hepta.parser import parse
from hepta.pipeline import analyze, analyze_project
from hepta.resource_ir import ResourceIRError, verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_source import verify_resource_source
from tools.resource_view_cases import FRONTEND_REJECTIONS, NATIVE_REJECTIONS, SCOPED_NEIGHBOURS, VIEWS
from tools.qualify_resource_views import qualify, validate_report

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "examples/resource_views/owned_buffer.hepta"
SHARED = VIEWS + """fn f(data:read [u8])->Unit effects {panic} {
 let first=Bytes{data:read data};let copied=first;assert(copied.data[0]==0);assert(first.data[0]==0);
}"""
EXCLUSIVE = VIEWS + """fn f(data:mut [u8])->Unit effects {panic,write} {
 let mut edit=Edit{data:mut data};edit.data[0]=7;drop(move edit);
}"""


def lower(source):
    program = parse(source)
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return lower_resource_ir(program, checked)


def exported(path):
    project = load_project(path)
    checked = check(project.program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return lower_resource_ir(project.program, checked, project_sha256=project.identity)


def function(document, name="f"):
    return next(fn for fn in document["functions"] if fn["name"] == name)


def operation(document, name, *, function_name="f", index=0):
    return [(block, i, op) for block in function(document, function_name)["blocks"]
            for i, op in enumerate(block["ops"]) if op["op"] == name][index]


class StoredViewResourceTests(unittest.TestCase):
    def reject(self, graph, code):
        report = verify_resource_ir(graph)
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["diagnostics"][0]["code"], code, report)

    def test_real_generic_owner_fallible_constructor_and_views_share_one_graph(self):
        graph = exported(ENTRY)
        report = verify_resource_ir(graph)
        self.assertEqual(graph["schema"], "hepta.resource-ir.v4")
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["generic_calls_checked"], 1)
        self.assertEqual(report["stored_views"]["types"], ["Bytes<'_>", "Edit<'_>"])
        self.assertFalse(report["stored_views"]["generic_lifetime_composition_checked"])
        self.assertTrue(all(value is False for value in report["claims"].values()))
        self.assertEqual(lower("fn main()->Unit effects {} {}" )["schema"], "hepta.resource-ir.v3")

    def test_shared_copy_remains_live_after_original_ends(self):
        graph = lower(SHARED)
        block, index, op = operation(graph, "copy_view", index=1)
        # End the first view immediately after its copy, then read that copy.
        block["ops"].insert(index + 1, {"op": "end_view", "src": op["src"]})
        block["ops"] = [item for i, item in enumerate(block["ops"])
                        if not (i > index + 1 and item.get("src") == op["src"])]
        self.assertTrue(verify_resource_ir(graph)["ok"])

    def test_borrow_end_cannot_release_a_stored_loan(self):
        graph = lower(SHARED)
        block, index, op = operation(graph, "bind_view")
        block["ops"].insert(index + 1, {"op": "end_borrow", "id": op["loan"]})
        self.reject(graph, "E_RIR_LOAN")

    def test_binding_requires_an_actual_live_loan(self):
        graph = lower(SHARED)
        operation(graph, "bind_view")[2]["loan"] = "fabricated"
        self.reject(graph, "E_RIR_VIEW_ORIGIN")

    def test_binding_cannot_upgrade_shared_to_exclusive(self):
        graph = lower(EXCLUSIVE)
        operation(graph, "borrow")[2]["mode"] = "read"
        self.reject(graph, "E_RIR_VIEW_ORIGIN")

    def test_exclusive_view_cannot_be_duplicated_or_reused_after_move(self):
        graph = lower(EXCLUSIVE)
        operation(graph, "move_view")[2]["op"] = "copy_view"
        self.reject(graph, "E_RIR_VIEW_COPY")
        graph = lower(EXCLUSIVE)
        block, index, op = operation(graph, "move_view")
        block["ops"].insert(index + 1, {"op": "use_view", "src": op["src"], "mode": "read"})
        self.reject(graph, "E_RIR_VIEW_LIVE")

    def test_ended_and_uninitialized_views_cannot_be_read(self):
        for started in (True, False):
            with self.subTest(started=started):
                graph = lower(SHARED)
                block, index, op = operation(graph, "end_view")
                if started:
                    block["ops"].insert(index + 1, {"op": "use_view", "src": op["src"], "mode": "read"})
                else:
                    block["ops"].insert(0, {"op": "use_view", "src": op["src"], "mode": "read"})
                self.reject(graph, "E_RIR_VIEW_LIVE")

    def test_missing_view_end_is_not_an_implicitly_forgiven_exit(self):
        for source, expected in ((SHARED, "E_RIR_LOAN_ESCAPE"), (EXCLUSIVE, "E_RIR_LEAK")):
            with self.subTest(source=source):
                graph = lower(source)
                block, index, _ = operation(graph, "end_view", index=-1)
                del block["ops"][index]
                self.reject(graph, expected)

    def test_shared_or_immutable_local_view_cannot_write(self):
        for source in (SHARED, EXCLUSIVE):
            with self.subTest(source=source):
                graph = lower(source)
                op = operation(graph, "use_view")[2]
                op["mode"] = "write"
                for local in function(graph)["locals"]:
                    local["mutable"] = False
                self.reject(graph, "E_RIR_VIEW_MUTABILITY")

    def test_owner_access_conflicts_with_stored_permission(self):
        for source, mode in ((SHARED, "write"), (EXCLUSIVE, "read"), (EXCLUSIVE, "write")):
            with self.subTest(source=source, mode=mode):
                graph = lower(source)
                function(graph)["params"][0]["mode"] = "mut"
                block, index, _ = operation(graph, "bind_view")
                block["ops"].insert(index + 1, {"op": "use", "place": {"root": "p0", "path": ["*"]}, "mode": mode})
                self.reject(graph, "E_RIR_LOAN_CONFLICT")

    def test_ordinary_operations_cannot_bypass_stored_view_rules(self):
        for op in ({"op": "use", "place": {"root": "v1", "path": []}, "mode": "read"},
                   {"op": "move", "src": "v1", "dest": "v4"}, {"op": "drop", "src": "v1"}):
            with self.subTest(op=op):
                graph = lower(EXCLUSIVE)
                block, index, _ = operation(graph, "use_view")
                block["ops"].insert(index, op)
                self.reject(graph, "E_RIR_VIEW_ACCESS")

    def test_stored_views_cannot_hide_in_aggregates_or_cross_signatures(self):
        graph = lower(SHARED)
        graph["types"]["Hidden"] = {"kind": "struct", "name": "Hidden", "args": [], "fields": [{"name": "view", "type": "Bytes<'_>"}]}
        self.reject(graph, "E_RIR_VIEW_TYPE")
        for boundary in ("params", "returns"):
            with self.subTest(boundary=boundary):
                graph = lower(SHARED)
                fn = function(graph)
                target = fn["params"][0] if boundary == "params" else fn["returns"]
                target["type"] = "Bytes<'_>"
                self.reject(graph, "E_RIR_VIEW_ESCAPE")

    def test_generic_instantiation_cannot_smuggle_a_stored_view(self):
        graph = exported(ENTRY)
        operation(graph, "call", function_name="create")[2]["type_args"] = ["Edit<'_>"]
        self.reject(graph, "E_RIR_GENERIC")

    def test_view_states_are_checked_at_branch_joins_and_loop_backedges(self):
        for body in ("if flag {} else {}", "while flag {}"):
            with self.subTest(body=body):
                graph = lower(VIEWS + "fn f(data:read [u8],flag:bool)->Unit effects {panic} {let view=Bytes{data:read data};" + body + "assert(view.data[0]==0);}")
                fn = function(graph)
                view = operation(graph, "copy_view")[2]["dest"]
                branch = next(b for b in fn["blocks"] if b["term"]["op"] == "branch")
                arm = next(b for b in fn["blocks"] if b["id"] == branch["term"]["then"])
                arm["ops"].append({"op": "end_view", "src": view})
                self.reject(graph, "E_RIR_JOIN")

    def test_scalar_labelled_shared_view_with_source_order_and_copy(self):
        graph = lower("""struct Tagged<'a>{data:read 'a [u8],tag:u64,valid:bool}
        fn f(data:read [u8])->Unit effects {panic} {
          let first=Tagged{valid:true,tag:9,data:read data};
          let copied=first;
          assert(copied.tag==9);
          assert(copied.valid);
          assert(len(first.data)==4);
        }""")
        self.assertEqual(graph["schema"], "hepta.resource-ir.v5")
        self.assertEqual(graph["types"]["Tagged<'_>"]["scalars"],
                         [{"name": "tag", "type": "u64"}, {"name": "valid", "type": "bool"}])
        self.assertEqual(verify_resource_ir(graph)["stored_views"]["profile"],
                         "local_single_u8_slice_records_v2_copy_scalars")
        binding = operation(graph, "bind_view")[2]
        self.assertEqual([label["name"] for label in binding["scalars"]], ["tag", "valid"])
        self.assertTrue(verify_resource_ir(graph)["ok"])

    def test_scalar_labelled_exclusive_view_can_mutate_borrowed_slice(self):
        graph = lower("""struct TaggedEdit<'a>{data:mut 'a [u8],tag:u32}
        fn f(data:mut [u8])->Unit effects {panic,write} {
          let mut edit=TaggedEdit{tag:5,data:mut data};
          edit.data[0]=7;
          assert(edit.tag==5);
          drop(move edit);
        }""")
        self.assertEqual(graph["schema"], "hepta.resource-ir.v5")
        self.assertTrue(verify_resource_ir(graph)["ok"])
        self.assertTrue(any(op["op"] == "use_view" and op["mode"] == "write"
                            for block in function(graph)["blocks"] for op in block["ops"]))

    def test_labelled_view_rejects_self_resealed_copy_metadata_tamper(self):
        base = lower("""struct Tagged<'a>{data:read 'a [u8],tag:u64,valid:bool}
        fn f(data:read [u8])->Unit effects {panic} {
          let view=Tagged{data:read data,tag:7,valid:true};
          assert(view.tag==7);
          assert(view.valid);
        }""")
        self.assertTrue(verify_resource_ir(base)["ok"])
        def altered(change):
            graph = copy.deepcopy(base)
            change(graph)
            return graph
        cases = [
            ("E_RIR_VIEW_SCALAR", lambda g: operation(g, "bind_view")[2]["scalars"].pop()),
            ("E_RIR_VIEW_SCALAR", lambda g: operation(g, "bind_view")[2]["scalars"][0].update(name="hidden")),
            ("E_RIR_VIEW_SCALAR", lambda g: operation(g, "bind_view")[2]["scalars"].reverse()),
            ("E_RIR_VIEW_SCALAR", lambda g: operation(g, "bind_view")[2]["scalars"][0].update(
                src=operation(g, "bind_view")[2]["scalars"][1]["src"])),
            ("E_RIR_VIEW_TYPE", lambda g: g["types"]["Tagged<'_>"]["scalars"][0].update(type="Buffer<u8>")),
            ("E_RIR_VIEW_TYPE", lambda g: g["types"]["Tagged<'_>"]["scalars"][1].update(name="tag")),
            ("E_RIR_SCHEMA", lambda g: g.update(schema="hepta.resource-ir.v4")),
        ]
        for code, mutate in cases:
            with self.subTest(code=code):
                self.reject(altered(mutate), code)

    def test_v5_cannot_be_resealed_without_any_labelled_view_type(self):
        graph = lower("""struct Tagged<'a>{data:read 'a [u8],tag:u64}
        fn f(data:read [u8])->Unit effects {panic} {
            let tagged=Tagged{data:read data,tag:7};
            assert(tagged.tag==7);
        }""")
        self.assertTrue(verify_resource_ir(graph)["ok"])
        graph["types"]["Tagged<'_>"]["scalars"] = []
        self.reject(graph, "E_RIR_VIEW_TYPE")

    def test_preexisting_v4_view_profiles_stay_strict_and_unchanged(self):
        graph = lower(SHARED)
        self.assertEqual(graph["schema"], "hepta.resource-ir.v4")
        self.assertNotIn("scalars", graph["types"]["Bytes<'_>"])
        self.assertTrue(verify_resource_ir(graph)["ok"])
        graph["types"]["Bytes<'_>"]["scalars"] = []
        self.reject(graph, "E_RIR_SCHEMA")

    def test_general_lifetime_shapes_remain_explicitly_unsupported(self):
        sources = [
            "struct V<'a>{data:read 'a u64} fn main()->Unit effects {} {}",
            "struct V<'a>{data:read 'a [u8],extra:mut 'a [u8]} fn main()->Unit effects {} {}",
            "struct V<'a>{data:read 'a [u8]} struct N<'a>{view:V<'a>} fn main()->Unit effects {} {}",
            "struct V<'a>{data:read 'a [u8]} fn f<'a>(x:read 'a [u8])->V<'a> effects {} {return V{data:read x};}",
        ]
        for source in sources:
            with self.subTest(source=source), self.assertRaises(ResourceIRError) as caught:
                lower(source)
            self.assertEqual(caught.exception.code, "E_RIR_LOWER_UNSUPPORTED")

    def test_frontend_affine_and_read_only_rejections_are_preserved(self):
        for name, (source, code) in FRONTEND_REJECTIONS.items():
            with self.subTest(name=name):
                analysis = analyze(source, name + ".hepta", native=False)
                self.assertFalse(analysis.report["ok"])
                self.assertIn(code, {d["code"] for d in analysis.report["diagnostics"]})

    def test_native_unsafe_candidates_are_also_independently_rejected(self):
        for name, (source, _) in NATIVE_REJECTIONS.items():
            with self.subTest(name=name), self.assertRaises(ResourceIRError) as caught:
                lower(source)
            self.assertEqual(caught.exception.code, "E_RIR_LOAN_CONFLICT")

    def test_source_replay_rejects_valid_but_different_view_description(self):
        graph = exported(ENTRY)
        graph["types"]["Bytes<'_>"]["field"] = "unrelated"
        self.assertTrue(verify_resource_ir(graph)["ok"])
        report = verify_resource_source(ENTRY, graph, native=False)
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["diagnostics"][0]["code"], "E_RIR_SOURCE_GRAPH")


class NativeStoredViewResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="hepta-resource-views-tests-")
        cls.rustc = os.environ.get("RUSTC")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_fresh_native_replay_has_precise_independent_stored_view_scope(self):
        report = verify_resource_source(ENTRY, exported(ENTRY), rustc=self.rustc)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["status"], "source_replayed")
        self.assertEqual(report["source_binding"]["independent_stored_views"], report["resource_verification"]["stored_views"])
        self.assertFalse(report["source_validation"]["borrowed_storage"]["independent_resource_ir_supported"])

    def test_actual_rust_rejects_every_invalid_candidate_without_execution(self):
        for name, (source, codes) in NATIVE_REJECTIONS.items():
            with self.subTest(name=name):
                analysis = analyze(source, name + ".hepta", rustc=self.rustc)
                self.assertFalse(analysis.report["ok"], analysis.report)
                self.assertEqual(analysis.report["checks"]["types_effects_resources"], "passed_in_supported_subset")
                self.assertTrue(codes.intersection(d["code"] for d in analysis.report["diagnostics"]))

    def test_disjoint_fields_loop_moves_and_early_returns_run_natively(self):
        graph = lower(SCOPED_NEIGHBOURS)
        self.assertTrue(verify_resource_ir(graph)["ok"])
        analysis = analyze(SCOPED_NEIGHBOURS, rustc=self.rustc, crate_type="bin")
        self.assertTrue(analysis.report["ok"], analysis.report)
        executable = Path(self.directory.name) / "scoped-neighbours"
        built = compile_rust(analysis.rust, rustc=self.rustc, crate_type="bin", output=executable)
        self.assertTrue(built["ok"], built)
        run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
        self.assertEqual((run.returncode, run.stdout, run.stderr), (0, "", ""))

    def test_standalone_data_verifier_never_imports_frontend(self):
        path = Path(self.directory.name) / "graph.json"
        path.write_text(json.dumps(exported(ENTRY)))
        command = [sys.executable, "-c", "import sys;from hepta.resource_ir import read_resource_ir,verify_resource_ir;assert verify_resource_ir(read_resource_ir(sys.argv[1]))['ok'];assert 'hepta.parser' not in sys.modules;assert 'hepta.checker' not in sys.modules", str(path)]
        process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_real_allocator_faults_cleanup_and_recovery_have_source_bound_evidence(self):
        output = Path(self.directory.name) / "execution.json"
        report = qualify(output, rustc=self.rustc)
        self.assertTrue(report["ok"], report)
        validate_report(report)
        self.assertEqual(len(report["observations"]), 10)
        self.assertEqual(report["observations"][-1], {"allocator_refusals": 2})
        self.assertTrue(all(row["live"] == 0 for row in report["observations"][:-1]))
        mutations = [
            lambda r: r.update(compiler_sha256="0" * 64),
            lambda r: r["inputs"].pop("tools/qualify_resource_views.py"),
            lambda r: r.update(source_refinement_proved=True),
            lambda r: r.update(whole_language_soundness_proved=0),
            lambda r: r["graph"].update(sha256="0" * 64),
            lambda r: r["resource_verification"]["stored_views"].update(generic_lifetime_composition_checked=True),
            lambda r: r["source_replay"]["source_binding"].update(compiler_sha256="0" * 64),
            lambda r: r["source_replay"]["claims"].update(user_program_executed=True),
            lambda r: r["source_validation"]["borrowed_storage"].update(independent_resource_ir_supported=True),
            lambda r: r["native_build"].update(check_only=True),
            lambda r: r["native_build"].update(artifact_bytes=True),
            lambda r: r["driver_build"]["argv"].__setitem__(7, "unrelated-library.a"),
            lambda r: r["driver_compiler"].update(executable_sha256="0" * 64),
            lambda r: r["execution"].update(returncode=False),
            lambda r: r["execution"].update(stdout=""),
            lambda r: r["execution"].update(executable_sha256="0" * 64),
            lambda r: r["observations"].pop(),
            lambda r: r["observations"][0].update(live=False),
            lambda r: r["observations"][-1].update(allocator_refusals=1),
            lambda r: r["execution"].update(stdout=r["execution"]["stdout"].replace('"live":0', '"live":7,"live":0', 1)),
        ]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                changed = copy.deepcopy(report)
                mutation(changed)
                with self.assertRaises(ValueError):
                    validate_report(changed)
        with self.assertRaises(ValueError):
            qualify(output, rustc=self.rustc)

    def test_failed_caller_build_keeps_prior_source_graph_and_native_results(self):
        output = Path(self.directory.name) / "failed-execution.json"
        report = qualify(output, rustc=self.rustc, cc=str(Path(self.directory.name) / "absent-cc"))
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "failed")
        self.assertIn("validation_error", report)
        self.assertTrue(report["source_replay"]["ok"])
        self.assertTrue(report["native_build"]["ok"])
        self.assertNotIn("execution", report)
        self.assertEqual(json.loads(output.read_text()), report)
        self.assertTrue(Path(report["graph"]["path"]).is_file())

    def test_timeout_retains_partial_process_bytes_in_the_failure_report(self):
        output = Path(self.directory.name) / "timeout-execution.json"
        actual_run = subprocess.run

        def timed_out(argv, *args, **kwargs):
            if argv[:2] == [sys.executable, "-c"]:
                raise subprocess.TimeoutExpired(argv, 20, output=b"partial\xff", stderr=b"error\xfe")
            return actual_run(argv, *args, **kwargs)

        with patch("tools.qualify_resource_views.subprocess.run", side_effect=timed_out):
            report = qualify(output, rustc=self.rustc)
        self.assertFalse(report["ok"])
        self.assertTrue(report["independent_process"]["timed_out"])
        self.assertEqual(report["independent_process"]["stdout_bytes_base64"], "cGFydGlhbP8=")
        self.assertEqual(report["independent_process"]["stderr_bytes_base64"], "ZXJyb3L+")
        self.assertNotIn("execution", report)
        self.assertEqual(json.loads(output.read_text()), report)


if __name__ == "__main__":
    unittest.main()
