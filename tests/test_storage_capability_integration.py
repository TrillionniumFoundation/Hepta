"""Storage regions must not hide runtime owners or turn snapshots into owners.

Invalid region candidates receive metadata-only Rust checks. Only the three
known-valid snapshot programs below are linked and executed.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from hepta.backend import compile_rust, find_rustc
from hepta.hmir import HMIRUnsupported, lower_checked_cfg as lower_hmir
from hepta.pipeline import analyze, analyze_project, concurrent_ir_analysis, resource_ir_analysis


RUSTC = find_rustc(os.environ.get("RUSTC"))
EFFECTS = "alloc,block,panic,io,write,spawn"
EMPTY_MAIN = "fn main()->Unit effects {} {}"
IO_START = "let mut io=io_reactor(2,1,8);let pair=io_local_pair(mut io);assert(pair.status==0);"
IO_TAKE = "let mut count:usize=0;let mut status:u8=0;let recovered=io_take(mut io,move request,mut count,mut status);release(move recovered);io_shutdown(move io);"


def main(body):
    return "fn main()->Unit effects {" + EFFECTS + "}{" + body + "}"


def hidden_owner_cases():
    cases = {}
    capabilities = {
        "IoReactor": "E_BORROW_STORAGE_PROFILE", "IoRequest": "E_BORROW_STORAGE_PROFILE",
        "TaskGroup": "E_NESTED_LINEAR", "Task<u64>": "E_NESTED_LINEAR",
        "Sender<u64>": "E_SENDER_TYPE", "Cancellation": "E_CANCELLATION_TYPE",
    }
    for owner, code in capabilities.items():
        for mode in ("read", "mut"):
            cases[mode + "_" + owner] = ("struct Hidden<'a>{value:" + mode + " 'a " + owner + "}" + EMPTY_MAIN, code)
    for owner in ("IoReactor", "IoRequest"):
        routes = {
            "nominal_record": ("struct Box{value:" + owner + "}", "Box"),
            "nominal_enum": ("enum Box{Some(" + owner + "),Empty}", "Box"),
            "generic_record": ("struct Box<T>{value:T}", "Box<" + owner + ">"),
            "generic_enum": ("enum Box<T>{Some(T),Empty}", "Box<" + owner + ">"),
            "result": ("", "Result<" + owner + ",u8>"),
            "array": ("", "[" + owner + ";2]"),
            "slice": ("", "[" + owner + "]"),
            "buffer": ("", "Buffer<" + owner + ">"),
            "raw_pointee": ("", "raw const " + owner),
        }
        for mode in ("read", "mut"):
            for route, (prefix, target) in routes.items():
                source = prefix + "struct Hidden<'a>{value:" + mode + " 'a " + target + "}" + EMPTY_MAIN
                cases[owner + "_" + mode + "_" + route] = (source, "E_BORROW_STORAGE_PROFILE")
            nested = "struct Inner<'a>{value:" + mode + " 'a " + owner + "}struct Outer<'a>{inner:Inner<'a>}"
            cases[owner + "_" + mode + "_nested_view"] = (nested + EMPTY_MAIN, "E_BORROW_STORAGE_PROFILE")
        identity = "fn identity<T:Owned>(value:take T)->T effects {}{return move value;}"
        cases[owner + "_owned_generic"] = (identity + "fn f(value:take " + owner + ")->" + owner
                                           + " effects {}{return identity::<" + owner + ">(move value);}", "E_GENERIC_COPY")
        mixed = "struct Mixed<'a>{value:read 'a u64,owner:" + owner + "}" + EMPTY_MAIN
        cases[owner + "_owning_payload_beside_reference"] = (mixed, "E_BORROW_STORAGE_PROFILE")
    for typ in ("IoPair", "IoReport", "GroupTreeReport"):
        cases[typ + "_source_construction"] = (main("let fake=" + typ + "{};"), "E_REPORT_CONSTRUCTION")
    cases["stored_snapshot_mutation_needs_write_effect"] = (
        "struct Edit<'a>{data:mut 'a IoReport}"
        "fn edit<'a>(data:mut 'a IoReport)->Unit effects {}{let mut view=Edit{data:mut data};view.data.open_ports=0;drop(move view);}",
        "E_EFFECT")
    cases["snapshot_from_lifetime_mismatch"] = (
        "fn choose<'a,'b>(left:read 'a IoReport,right:read 'b IoReport)->read 'a IoReport from right effects {}{return read right;}",
        "E_LIFETIME_ORIGIN")
    return cases


FRONTEND_REJECTIONS = hidden_owner_cases()
UNSUPPORTED_DECLARATIONS = {
    "unused_pair_record": "struct Unused{pair:IoPair}",
    "unused_report_record": "struct Unused{report:IoReport}",
    "unused_generic_pair": "struct Box<T>{value:T}struct Unused{pair:Box<IoPair>}",
    "unused_enum_report": "enum Unused{Some(IoReport),Empty}",
    "unused_result_report": "struct Unused{result:Result<IoReport,u8>}",
    "unused_array_pair": "struct Unused{pairs:[IoPair;2]}",
    "unused_reactor_parameter": "fn inspect(value:read IoReactor)->Unit effects {}{}",
    "unused_request_parameter": "fn inspect(value:read IoRequest)->Unit effects {}{}",
}

COPY_PROGRAMS = {
    "copy_snapshots_survive_owner_cleanup": """
struct Bundle{pair:IoPair,io:IoReport,tree:GroupTreeReport}
enum Reports{Present(IoReport,GroupTreeReport),Empty}
fn identity<T:Copy>(value:T)->T effects {}{return value;}
""" + main(IO_START + """
let report=io_report(read io);
let mut root=task_group(0,0,1);let child=task_group(0,0,1);
assert(group_adopt(mut root,move child));let tree=group_tree_snapshot(read root);
let original=Bundle{pair:pair,io:report,tree:tree};let copied=identity::<Bundle>(original);
let rows=[report,report];let packed=Reports::Present(report,tree);
let closed=io_shutdown(move io);let joined=group_tree_join(move root);
assert(closed.open_ports==0);assert(joined.joined_groups==2);
assert(copied.io.open_ports==2);assert(copied.pair.left!=copied.pair.right);
assert(copied.tree.groups==2);assert(original.tree.depth==2);assert(rows[1].open_ports==2);
match packed{Reports::Present(i,t)=>{assert(i.open_ports==2);assert(t.groups==2);},Reports::Empty=>{assert(false);}}
"""),
    "shared_snapshot_views_survive_owner_cleanup": """
struct View<'a,'b>{pair:read 'a IoPair,io:read 'a IoReport,tree:read 'b GroupTreeReport}
struct Outer<'a,'b>{view:View<'a,'b>,tag:u64}
fn forward<'a,'b>(value:Outer<'a,'b>)->Outer<'a,'b> effects {}{return value;}
""" + main(IO_START + """
let report=io_report(read io);let mut root=task_group(0,0,1);let child=task_group(0,0,1);
assert(group_adopt(mut root,move child));let tree=group_tree_snapshot(read root);
let first=forward(Outer{view:View{pair:read pair,io:read report,tree:read tree},tag:19});let copied=first;
let closed=io_shutdown(move io);let joined=group_tree_join(move root);
assert(closed.shutdown);assert(joined.joined_groups==2);
assert(copied.view.pair.status==0);assert(copied.view.io.open_ports==2);
assert(copied.view.tree.groups==2);assert(first.tag==19);
"""),
    "mutable_snapshot_view_moves_through_nested_field": """
struct View<'a>{io:mut 'a IoReport,tree:read 'a GroupTreeReport}
struct Outer<'a>{view:View<'a>,tag:u64}
fn forward<'a>(value:take View<'a>)->View<'a> effects {}{return move value;}
""" + main("""
let io=io_reactor(2,1,8);let mut report=io_shutdown(move io);
let root=task_group(0,0,1);let tree=group_tree_join(move root);
let outer=Outer{view:View{io:mut report,tree:read tree},tag:31};
let mut view=forward(move outer.view);view.io.open_ports=7;
assert(view.tree.joined_groups==1);assert(outer.tag==31);drop(move view);
assert(report.open_ports==7);assert(report.shutdown);
"""),
}

NATIVE_REJECTIONS = {
    "copied_shared_buffer_view_blocks_io_admission": (
        "struct View<'a>{data:read 'a [u8]}" + main(IO_START + """
let bytes=buffer(8);let view=View{data:read bytes};let copied=view;
let request=io_read(mut io,pair.left,move bytes,8,0);assert(len(copied.data)==8);
""" + IO_TAKE), {"E0505"}),
    "moved_nested_mutable_buffer_view_blocks_io_admission": (
        "struct View<'a>{data:mut 'a [u8]}struct Outer<'a>{view:View<'a>}"
        "fn forward<'a>(value:take View<'a>)->View<'a> effects {}{return move value;}"
        + main(IO_START + """
let mut bytes=buffer(8);let outer=Outer{view:View{data:mut bytes}};
let mut view=forward(move outer.view);let request=io_write(mut io,pair.left,move bytes,8,0);
view.data[0]=1;drop(move view);
""" + IO_TAKE), {"E0505"}),
    "snapshot_copy_local_cannot_escape_in_view": (
        "struct View<'a>{data:read 'a IoReport}"
        "fn snapshot<'a>(io:read 'a IoReactor)->View<'a> effects {}{let local=io_report(read io);return View{data:read local};}"
        + EMPTY_MAIN, {"E0515"}),
    "two_mutable_snapshot_fields_cannot_alias": (
        "struct View<'a>{left:mut 'a IoReport,right:mut 'a IoReport}" + main("""
let io=io_reactor(2,1,8);let mut report=io_shutdown(move io);
let view=View{left:mut report,right:mut report};drop(move view);
"""), {"E0499"}),
    "copied_snapshot_view_keeps_snapshot_borrowed": (
        "struct View<'a>{data:read 'a IoReport}" + main("""
let io=io_reactor(2,1,8);let mut report=io_shutdown(move io);
let view=View{data:read report};let copied=view;report.open_ports=1;
assert(copied.data.shutdown);
"""), {"E0502", "E0506"}),
}


class StorageCapabilityFrontendTests(unittest.TestCase):
    def test_scoped_capabilities_cannot_hide_in_stored_references_or_containers(self):
        self.assertEqual(len(FRONTEND_REJECTIONS), 61)
        for name, (source, code) in FRONTEND_REJECTIONS.items():
            with self.subTest(case=name):
                analysis = analyze(source, name + ".hepta", native=False)
                self.assertFalse(analysis.report["ok"], analysis.report)
                self.assertIsNone(analysis.rust)
                self.assertIn(code, {d["code"] for d in analysis.report["diagnostics"]})
                self.assertTrue(any(d["phase"] == "check" and d["span"]["path"] == name + ".hepta"
                                    for d in analysis.report["diagnostics"] if d["code"] == code))

    def test_module_type_rewriting_preserves_recursive_capability_rejection(self):
        with tempfile.TemporaryDirectory(prefix="hepta-storage-modules-") as directory:
            root = Path(directory)
            (root / "library.hepta").write_text("module library;pub struct Box<T>{value:T}")
            for owner in ("IoReactor", "IoRequest"):
                with self.subTest(owner=owner):
                    entry = root / "main.hepta"
                    entry.write_text("module entry;import library as caps;struct View<'a>{data:read 'a caps::Box<"
                                     + owner + ">}" + EMPTY_MAIN)
                    report = analyze_project(entry, native=False, crate_type="bin").report
                    self.assertFalse(report["ok"], report)
                    self.assertIn("E_BORROW_STORAGE_PROFILE", {d["code"] for d in report["diagnostics"]})

    def test_unused_io_declarations_cannot_disappear_from_unsupported_backends(self):
        for name, declaration in UNSUPPORTED_DECLARATIONS.items():
            with self.subTest(case=name):
                source = declaration + EMPTY_MAIN
                analysis = analyze(source, name + ".hepta", native=False, crate_type="bin")
                self.assertTrue(analysis.report["ok"], analysis.report)
                c = analyze(source, native=False, backend="c", crate_type="bin")
                self.assertFalse(c.report["ok"], c.report)
                self.assertIsNone(c.c)
                for lower, key in ((resource_ir_analysis, "resource_ir"), (concurrent_ir_analysis, "concurrent_ir")):
                    result = lower(analysis)
                    self.assertFalse(result["ok"], result)
                    self.assertIsNone(result[key])
                    self.assertIsNone(result["verifier"])
                with self.assertRaises(HMIRUnsupported):
                    lower_hmir(analysis.program, analysis.checked)

    def test_stored_runtime_snapshots_do_not_silently_become_no_std(self):
        for typ in ("IoPair", "IoReport", "GroupTreeReport"):
            with self.subTest(snapshot=typ):
                source = "struct View<'a>{data:read 'a " + typ + "}fn f()->Unit effects {}{}"
                result = analyze(source, native=False, no_std=True).report
                self.assertFalse(result["ok"], result)
                self.assertIn("E_NO_STD", {d["code"] for d in result["diagnostics"]})


class StorageCapabilityNativeTests(unittest.TestCase):
    def test_valid_copy_and_affine_snapshot_programs_execute(self):
        with tempfile.TemporaryDirectory(prefix="hepta-storage-capability-native-") as directory:
            for name, source in COPY_PROGRAMS.items():
                with self.subTest(case=name):
                    analysis = analyze(source, name + ".hepta", rustc=RUSTC, crate_type="bin")
                    self.assertTrue(analysis.report["ok"], analysis.report)
                    if "borrowed_storage" in analysis.report:
                        self.assertTrue(analysis.report["borrowed_storage"]["native_lifetimes_checked"])
                    output = Path(directory) / name
                    built = compile_rust(analysis.rust, rustc=RUSTC, crate_type="bin", output=output)
                    self.assertTrue(built["ok"], built)
                    self.assertGreater(built["artifact_bytes"], 0)
                    executed = subprocess.run([str(output)], capture_output=True, text=True, timeout=10)
                    self.assertEqual((executed.returncode, executed.stdout, executed.stderr), (0, "", ""))

    def test_invalid_regions_receive_only_native_metadata_checks(self):
        for name, (source, codes) in NATIVE_REJECTIONS.items():
            with self.subTest(case=name):
                path = name + ".hepta"
                frontend = analyze(source, path, native=False, crate_type="bin")
                self.assertTrue(frontend.report["ok"], frontend.report)
                self.assertFalse(frontend.report["borrowed_storage"]["native_lifetimes_checked"])
                rejected = analyze(source, path, rustc=RUSTC, crate_type="bin")
                self.assertFalse(rejected.report["ok"], rejected.report)
                self.assertIs(rejected.report["backend"]["check_only"], True)
                self.assertEqual(rejected.report["checks"]["types_effects_resources"], "passed_in_supported_subset")
                self.assertEqual(rejected.report["checks"]["rust_borrows_types"], "rejected")
                self.assertTrue(codes.intersection(d["code"] for d in rejected.report["diagnostics"]))
                self.assertTrue(any(m["is_primary"] and m["span"]["path"] == path
                                    for d in rejected.report["diagnostics"] for m in d.get("source_mappings", [])))


if __name__ == "__main__":
    unittest.main()
