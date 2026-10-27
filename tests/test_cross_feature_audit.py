"""Adversarial integration regressions across modules, ADTs, patches, and C.

These tests exercise public analysis/build entrypoints, observable native
behavior, and controlled filesystem races. They do not establish language
soundness, global resource bounds, or equivalence of the two backends.
"""
from __future__ import annotations

import ctypes
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.backend import compile_rust, sha256
from hepta.c_backend import compile_c
from hepta.c_import import import_header
from hepta.modules import load_project
from hepta.parser import parse
from hepta.pipeline import analyze_project, interface_hash
from hepta.protocol import apply_patch as apply_file_patch, apply_project_patch


ROOT = Path(__file__).resolve().parents[1]
RUSTC = os.environ.get("RUSTC", str(ROOT.parent / "toolchains/rust-1.90.0/bin/rustc"))
HAS_RUST = Path(RUSTC).is_file()
HAS_C = shutil.which("gcc") is not None


class ProjectFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-cross-audit-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def put(self, relative: str, source: str) -> Path:
        target = self.directory / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
        return target

    def rejects(self, entry: Path, code: str | None = None, **options):
        try:
            result = analyze_project(entry, native=False, **options).report
        except HeptaError as error:
            result = {"ok": False, "diagnostics": [error.diagnostic.to_dict()]}
        self.assertFalse(result["ok"], result)
        if code:
            self.assertIn(code, {d["code"] for d in result["diagnostics"]}, result)
        return result

    def execute(self, entry: Path, backend="rust", *, link_args=None):
        result = analyze_project(entry, backend=backend, crate_type="bin", rustc=RUSTC)
        self.assertTrue(result.report["ok"], result.report)
        output = self.directory / (backend + "-program")
        if backend == "rust":
            built = compile_rust(result.rust, rustc=RUSTC, crate_type="bin", output=output, link_args=link_args)
        else:
            built = compile_c(result.c, crate_type="bin", output=output, sanitize=True, link_args=link_args)
            self.assertFalse(built["rustc_used"])
        self.assertTrue(built["ok"], built)
        process = subprocess.run([str(output)], cwd=self.directory, capture_output=True, timeout=8)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        return result, process


class ModulePrivacyAudit(ProjectFixture):
    def private_fixture(self):
        secret = self.put("secret.hepta", """
            fn hidden()->u64 effects {} {return 17;}
            struct Hidden {value:u64}
            enum HiddenChoice {Some(u64),None}
            pub fn value()->HiddenChoice effects {} {return HiddenChoice::Some(17);}
            fn worker(data:take Buffer<u8>,cancel:read Cancellation)->u64
            effects {alloc,block} {release(move data);return 17;}
        """)
        entry = self.put("main.hepta", "import secret; fn main()->Unit effects {} {}")
        loaded = load_project(entry)
        names = next(module["symbols"] for module in loaded.modules if module["path"] == str(secret))
        return entry, names

    def test_private_function_cannot_be_called_by_inspected_internal_name(self):
        entry, names = self.private_fixture()
        entry.write_text("import secret; fn main()->Unit effects {panic} {assert(" + names["hidden"] + "()==17);}")
        self.rejects(entry)

    def test_private_type_cannot_be_constructed_by_internal_name(self):
        entry, names = self.private_fixture()
        hidden = names["Hidden"]
        entry.write_text("import secret; fn main()->Unit effects {panic} {let x:" + hidden + "=" + hidden + "{value:17};assert(x.value==17);}")
        self.rejects(entry)

    def test_private_enum_cannot_be_destructured_by_internal_name(self):
        entry, names = self.private_fixture()
        hidden = names["HiddenChoice"]
        entry.write_text("import secret; fn main()->Unit effects {panic} {let x=secret::value();match x {" + hidden + "::Some(v)=>{assert(v==17);}," + hidden + "::None=>{assert(false);}}}")
        self.rejects(entry)

    def test_private_worker_name_cannot_bypass_import_visibility(self):
        entry, names = self.private_fixture()
        entry.write_text("import secret; fn main()->Unit effects {alloc,block,spawn,panic} {let task=spawn(" + names["worker"] + ",move buffer(1));assert(join(move task)==17);}")
        self.rejects(entry)

    def test_private_generic_type_remains_private_when_instantiated(self):
        self.put("secret.hepta", "struct Box<T>{value:T} pub fn answer()->u64 effects {} {return 1;}")
        entry = self.put("main.hepta", "import secret; fn main()->Unit effects {} {let x:secret::Box<u64>=secret::Box{value:1};}")
        self.rejects(entry, "E_MODULE_PRIVATE")

    def test_imported_generic_helper_keeps_transitive_effect_obligations(self):
        self.put("helper.hepta", "pub fn guarded<T>(value:T)->T effects {panic} {assert(false);return value;}")
        entry = self.put("main.hepta", "import helper; fn main()->Unit effects {} {helper::guarded::<u64>(1);}")
        self.rejects(entry, "E_EFFECT")

    def test_cross_file_match_and_generic_calls_cannot_hide_unsafe_worker(self):
        self.put("danger.hepta", "pub fn hidden<T>(value:T)->Unit effects {unsafe} {unsafe {}}")
        self.put("worker.hepta", """
            import danger;
            enum Choice {A,B}
            pub fn run(data:take Buffer<u8>,cancel:read Cancellation)->u64 effects {alloc,block,unsafe} {
                match Choice::A {Choice::A=>{unsafe {danger::hidden::<u64>(1);}},Choice::B=>{}}
                release(move data);return 0;
            }
        """)
        entry = self.put("main.hepta", "import worker; fn main()->Unit effects {alloc,block,spawn,panic,unsafe} {let task=spawn(worker::run,move buffer(1));join(move task);}")
        self.rejects(entry, "E_TASK_WORKER_EFFECT")

    def test_imported_take_parameter_still_consumes_the_caller_owner(self):
        self.put("sink.hepta", "pub fn consume(data:take Buffer<u8>)->Unit effects {alloc,block} {release(move data);}")
        entry = self.put("main.hepta", "import sink; fn main()->Unit effects {alloc,block,panic} {let data=buffer(8);sink::consume(move data);release(move data);}")
        self.rejects(entry, "E_USE_AFTER_MOVE")


@unittest.skipUnless(HAS_RUST, "pinned native compiler is unavailable")
class NativeModuleAudit(ProjectFixture):
    def test_nested_generic_enums_and_patterns_resolve_across_three_files(self):
        self.put("model.hepta", "pub struct Pair<T,E>{left:T,right:E} pub enum Choice<T>{Some(T),None}")
        self.put("logic.hepta", """
            import model;
            fn identity<T>(value:T)->T effects {} {return value;}
            pub fn wrap<T>(value:T)->model::Choice<model::Pair<T,u8>> effects {} {
                return model::Choice::Some(model::Pair{left:identity::<T>(value),right:7});
            }
            pub fn choose<T>(value:read model::Choice<T>,fallback:T)->T effects {} {
                match value {model::Choice::Some(found)=>{return found;},model::Choice::None=>{return fallback;}}
            }
        """)
        entry = self.put("main.hepta", """
            import model as m; import logic as ops;
            fn main()->Unit effects {panic} {
                let present=ops::wrap::<u64>(35);
                let fallback:m::Pair<u64,u8>=m::Pair{left:9,right:2};
                let found=ops::choose::<m::Pair<u64,u8>>(read present,fallback);
                assert(found.left==35);assert(found.right==7);
                let missing:m::Choice<m::Pair<u64,u8>>=m::Choice::None;
                let alternate=ops::choose::<m::Pair<u64,u8>>(read missing,fallback);
                assert(alternate.left==9);assert(alternate.right==2);
            }
        """)
        self.execute(entry)

    def test_cross_file_resource_transfer_executes_both_enum_arms(self):
        self.put("consume.hepta", """
            pub enum Mode{Early,Late}
            pub fn apply(mode:Mode,data:take Buffer<u8>)->u64 effects {alloc,block} {
                match mode {Mode::Early=>{release(move data);return 11;},Mode::Late=>{}}
                let length=len(read data);release(move data);return length as u64;
            }
        """)
        entry = self.put("main.hepta", "import consume; fn main()->Unit effects {alloc,block,panic} {assert(consume::apply(consume::Mode::Early,move buffer(3))==11);assert(consume::apply(consume::Mode::Late,move buffer(3))==3);}")
        self.execute(entry)


@unittest.skipUnless(HAS_RUST, "native validation is required for patch acceptance")
class GraphTransactionAudit(ProjectFixture):
    def graph(self, *, symlink=False):
        self.dep = self.put("dep.hepta", "pub fn answer()->u64 effects {} {return 1;}")
        self.other = self.put("other.hepta", "pub fn helper()->u64 effects {} {return 2;}")
        if symlink:
            self.link = self.directory / "chosen.hepta"
            self.link.symlink_to(self.dep.name)
        imported = "chosen" if symlink else "dep"
        self.entry = self.put("main.hepta", f"import {imported}; import other; fn main()->i32 effects {{}} {{return {imported}::answer() as i32;}}")
        self.original = load_project(self.entry)
        return {"schema": "hepta.patch.v2", "expected_project_sha256": self.original.identity,
                "target": "dep.hepta", "expected_source_sha256": sha256(self.dep.read_bytes()),
                "expected_interface_sha256": interface_hash(self.original.program), "symbol": "answer",
                "replacement_body": "{return 3;}"}

    def symlink_graph_or_rejected(self):
        # Rejecting source symlinks altogether is also a valid closed policy.
        try:
            return self.graph(symlink=True)
        except HeptaError as error:
            self.assertEqual(error.diagnostic.phase, "module")
            return None

    def test_import_symlink_binding_is_part_of_unchanged_snapshot(self):
        if self.symlink_graph_or_rejected() is None:
            return
        alternate = self.put("alternate.hepta", "pub fn answer()->u64 effects {} {return 2;}")
        self.link.unlink()
        self.link.symlink_to(alternate.name)
        self.assertFalse(self.original.unchanged(), "unchanged() ignored a changed import edge")

    def test_retarget_to_an_already_imported_source_invalidates_graph_identity(self):
        first = self.put("a.hepta", "pub fn answer()->u64 effects {} {return 1;}")
        second = self.put("b.hepta", "pub fn answer()->u64 effects {} {return 2;}")
        link = self.directory / "chosen.hepta"
        link.symlink_to(first.name)
        entry = self.put("main.hepta", "import a;import b;import chosen;fn main()->i32 effects {} {return chosen::answer() as i32;}")
        before = load_project(entry)
        request = {"schema": "hepta.patch.v2", "expected_project_sha256": before.identity,
                   "target": "a.hepta", "expected_source_sha256": sha256(first.read_bytes()),
                   "expected_interface_sha256": interface_hash(before.program), "symbol": "answer",
                   "replacement_body": "{return 3;}"}
        link.unlink()
        link.symlink_to(second.name)
        after = load_project(entry)
        # Content hashes alone coincide because a and b were already loaded.
        self.assertEqual(before.sources, after.sources)
        self.assertNotEqual(before.identity, after.identity)
        report = apply_project_patch(entry, request, apply=True, rustc=RUSTC)
        self.assertFalse(report["ok"], report)
        self.assertIn("E_STALE_PROJECT", {d["code"] for d in report["diagnostics"]})
        self.assertIn("return 1", first.read_text())

    def test_symlink_retarget_during_staging_prevents_commit(self):
        request = self.symlink_graph_or_rejected()
        if request is None:
            return
        alternate = self.put("alternate.hepta", "pub fn answer()->u64 effects {} {return 2;}")
        before = self.dep.read_bytes()
        real_chmod = os.chmod
        def race(*args, **kwargs):
            real_chmod(*args, **kwargs)
            self.link.unlink()
            self.link.symlink_to(alternate.name)
        with patch("hepta.protocol.os.chmod", side_effect=race):
            report = apply_project_patch(self.entry, request, apply=True, rustc=RUSTC)
        self.assertFalse(report["ok"], report)
        self.assertFalse(report["applied"], report)
        self.assertEqual(self.dep.read_bytes(), before)

    def test_dry_run_cannot_validate_new_unrequested_dependency_snapshot(self):
        request = self.graph()
        before = self.dep.read_bytes()
        def race(*args, **kwargs):
            self.other.write_text(self.other.read_text().replace("return 2", "return 9"))
            return analyze_project(*args, **kwargs)
        with patch("hepta.pipeline.analyze_project", side_effect=race):
            report = apply_project_patch(self.entry, request, apply=False, rustc=RUSTC)
        self.assertFalse(report["ok"], report)
        self.assertFalse(report["applied"], report)
        self.assertEqual(self.dep.read_bytes(), before)

    def test_regular_dependency_change_during_staging_prevents_commit(self):
        request = self.graph()
        before = self.dep.read_bytes()
        real_chmod = os.chmod
        def race(*args, **kwargs):
            real_chmod(*args, **kwargs)
            self.other.write_text(self.other.read_text().replace("return 2", "return 9"))
        with patch("hepta.protocol.os.chmod", side_effect=race):
            report = apply_project_patch(self.entry, request, apply=True, rustc=RUSTC)
        self.assertFalse(report["ok"], report)
        self.assertFalse(report["applied"], report)
        self.assertEqual(self.dep.read_bytes(), before)

    def test_generic_parameter_contract_is_frozen_even_when_signature_types_do_not_change(self):
        dep = self.put("dep.hepta", "pub fn constant<T>()->u64 effects {} {return 7;}")
        entry = self.put("main.hepta", "import dep; fn main()->i32 effects {} {return dep::constant::<u64>() as i32;}")
        before = load_project(entry)
        dep.write_text(dep.read_text().replace("<T>", "<U>"))
        after = load_project(entry)
        request = {"schema": "hepta.patch.v2", "expected_project_sha256": after.identity,
                   "target": "dep.hepta", "expected_source_sha256": sha256(dep.read_bytes()),
                   "expected_interface_sha256": interface_hash(before.program), "symbol": "constant",
                   "replacement_body": "{return 0;}"}
        report = apply_project_patch(entry, request, rustc=RUSTC)
        self.assertFalse(report["ok"], report)
        self.assertIn("E_STALE_INTERFACE", {d["code"] for d in report["diagnostics"]})

    def test_overlapping_graph_and_file_transactions_coordinate_shared_source_locks(self):
        for second_mode in ("v2", "v1"):
            with self.subTest(second_mode=second_mode):
                shared = self.put(second_mode + "/shared.hepta", "pub fn answer()->u64 effects {} {return 1;}")
                first_entry = self.put(second_mode + "/first.hepta", "import shared;fn main()->i32 effects {} {return shared::answer() as i32;}")
                second_entry = self.put(second_mode + "/second.hepta", first_entry.read_text())
                def graph_request(entry, value):
                    project = load_project(entry)
                    return {"schema": "hepta.patch.v2", "expected_project_sha256": project.identity,
                            "target": "shared.hepta", "expected_source_sha256": sha256(shared.read_bytes()),
                            "expected_interface_sha256": interface_hash(project.program), "symbol": "answer",
                            "replacement_body": "{return " + str(value) + ";}"}
                first_request = graph_request(first_entry, 2)
                second_request = graph_request(second_entry, 3)
                if second_mode == "v1":
                    second_request = {"schema": "hepta.patch.v1", "expected_source_sha256": sha256(shared.read_bytes()),
                                      "expected_interface_sha256": interface_hash(parse(shared.read_text(), str(shared))),
                                      "symbol": "answer", "replacement_body": "{return 3;}"}
                ready, proceed = threading.Event(), threading.Event()
                local = threading.local()
                real_replace = os.replace
                def pause_first_writer(source, destination):
                    if Path(destination) == shared and getattr(local, "first", False):
                        ready.set()
                        if not proceed.wait(5):
                            raise TimeoutError("first transaction was not released")
                    return real_replace(source, destination)
                def first_writer():
                    local.first = True
                    return apply_project_patch(first_entry, first_request, apply=True, rustc=RUSTC)
                with patch("hepta.protocol.os.replace", side_effect=pause_first_writer), ThreadPoolExecutor(max_workers=1) as executor:
                    first = executor.submit(first_writer)
                    try:
                        self.assertTrue(ready.wait(5), "first transaction did not reach atomic writeback")
                        second = (apply_project_patch(second_entry, second_request, apply=True, rustc=RUSTC)
                                  if second_mode == "v2" else apply_file_patch(shared, second_request, apply=True, rustc=RUSTC))
                    finally:
                        proceed.set()
                    first_result = first.result(timeout=5)
                self.assertTrue(first_result["applied"], first_result)
                self.assertFalse(second["ok"], second)
                self.assertFalse(second["applied"], second)
                self.assertIn("return 2", shared.read_text())


@unittest.skipUnless(HAS_C, "native GCC is unavailable")
class CIntegrationAudit(ProjectFixture):
    def imported_api(self, declaration, *, contracts=None):
        header = self.put("api.h", declaration)
        imported = import_header(header, contracts=contracts)
        binding = self.put("api.hepta", imported.source)
        self.put("api.hepta.imports.json", json.dumps(imported.manifest))
        return header, binding

    def test_unsupported_language_features_fail_before_artifact_replacement(self):
        sources = [
            "fn main()->Unit effects {alloc,block,panic,write} {let group=task_group(0,0,1);group_cancel_and_join(move group);}",
            "fn main()->Unit effects {} {let value:i32=3.5 as i32;}",
        ]
        destination = self.put("existing-artifact", "previous-artifact-must-survive")
        for source in sources:
            with self.subTest(source=source):
                entry = self.put("main.hepta", source)
                result = analyze_project(entry, backend="c", crate_type="bin")
                self.assertFalse(result.report["ok"], result.report)
                self.assertEqual(result.report["checks"]["types_effects_resources"], "passed_in_supported_subset")
                self.assertTrue({"E_C_RESOURCE_IR", "E_C_BACKEND_CAST"} & {d["code"] for d in result.report["diagnostics"]})
                self.assertIsNone(result.c)
                process = subprocess.run([sys.executable, "-m", "hepta", "build", str(entry), "--backend", "c", "-o", str(destination)], cwd=ROOT, capture_output=True, timeout=15)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(destination.read_text(), "previous-artifact-must-survive")

    @unittest.skipUnless(HAS_RUST, "native differential validation requires Rust")
    def test_cross_module_struct_and_read_borrow_execute_with_both_backends(self):
        self.put("math.hepta", "pub struct Pair{left:i64,right:i64} pub fn total(pair:read Pair)->i64 effects {panic} {return pair.left+pair.right;}")
        entry = self.put("main.hepta", "import math; fn main()->Unit effects {panic} {let pair:math::Pair=math::Pair{left:13,right:29};assert(math::total(read pair)==42);}")
        rust, rust_process = self.execute(entry, "rust")
        native, c_process = self.execute(entry, "c")
        self.assertEqual(rust_process.stdout, c_process.stdout)
        self.assertEqual(native.report["checks"]["rust_borrows_types"], "not_run")
        self.assertEqual(native.report["checks"]["c_types_codegen"], "gcc_checked")
        self.assertTrue(rust.report["ok"])

    @unittest.skipUnless(HAS_RUST, "native differential validation requires Rust")
    def test_isize_minimum_has_the_same_behavior_in_native_backends(self):
        minimum = -(1 << (ctypes.sizeof(ctypes.c_void_p) * 8 - 1))
        entry = self.put("main.hepta", f"fn main()->Unit effects {{panic}} {{let value:isize={minimum};assert(value<0);}}")
        self.execute(entry, "rust")
        self.execute(entry, "c")

    @unittest.skipUnless(HAS_RUST, "native differential validation requires Rust")
    def test_imported_public_struct_crosses_module_and_real_c_abi_in_both_backends(self):
        self.imported_api("typedef struct Point { int x; double y; } Point; Point shift(Point value);", contracts={"shift": {"ffi", "unsafe"}})
        implementation = self.put("api.c", '#include "api.h"\nPoint shift(Point value) {value.x+=9;value.y+=2.5;return value;}')
        obj = self.directory / "api.o"
        compiled = subprocess.run(["gcc", "-std=c11", "-Werror", "-c", str(implementation), "-o", str(obj)], capture_output=True, timeout=15)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        entry = self.put("main.hepta", """
            import api;
            fn main()->Unit effects {ffi,unsafe,panic} {
                let input:api::Point=api::Point{x:3,y:4.0};
                unsafe {let shifted=api::shift(input);assert(shifted.x==12);assert(shifted.y==6.5);}
            }
        """)
        for backend in ("rust", "c"):
            with self.subTest(backend=backend):
                result, _ = self.execute(entry, backend, link_args=[str(obj)])
                self.assertEqual(len(result.report["project"]["c_imports"]), 1)
                self.assertTrue(result.report["assumptions"])

    def test_host_c_probe_facts_cannot_be_reused_for_foreign_target(self):
        self.imported_api("typedef struct Counter { long value; } Counter;")
        entry = self.put("main.hepta", 'import api; pub export "C" fn take_counter(value:api::Counter)->api::Counter effects {} {return value;}')
        result = analyze_project(entry, target="thumbv7em-none-eabi", no_std=True,
                                 native=False, rustc=RUSTC)
        self.assertFalse(result.report["ok"], result.report)
        self.assertIn("E_C_IMPORT_TARGET", {d["code"] for d in result.report["diagnostics"]})


if __name__ == "__main__":
    unittest.main()
