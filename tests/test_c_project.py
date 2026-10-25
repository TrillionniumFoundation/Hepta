"""Captured project migration: native positives and semantic rejection gates."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import MigrationRejected, migrate_c_project
from hepta.c_project import capture_project, verify_capture


FIXTURE = Path(__file__).parent / "fixtures/c_migration/native"


class CProjectMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-c-project-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clang = shutil.which("clang")
        self.assertIsNotNone(self.clang, "Clang is required for project migration")
        self.database = self.root / "compile_commands.json"
        self.output = self.root / "converted"

    def project(self, sources, flags=None):
        entries = []
        for name, source in sources.items():
            (self.root / name).write_text(source)
            entries.append({"directory": str(self.root), "file": name,
                            "arguments": ["clang", "-std=c11", *(flags or []), "-c", name, "-o", name + ".o"]})
        self.database.write_text(json.dumps(entries))

    def migrate(self, contracts=None, native=False):
        return migrate_c_project(self.database, self.output, contracts=contracts, clang=self.clang,
                                 verify_native=native, rustc=os.environ.get("RUSTC"))

    def rejected(self, source, code, contracts=None):
        self.project({"input.c": source})
        report = self.migrate(contracts)
        self.assertFalse(report["ok"], report)
        self.assertFalse(self.output.exists())
        self.assertIn(code, [item["code"] for item in report["diagnostics"]], report)
        return report

    def test_capture_includes_flags_headers_and_rejects_changed_inputs(self):
        (self.root / "inc.h").write_text("#define LOCAL_FACTOR 3\n")
        self.project({"input.c": '#include "inc.h"\nunsigned int scale(unsigned int x){return x*LOCAL_FACTOR*FACTOR;}'}, ["-DFACTOR=2"])
        capture = capture_project(self.database, clang=self.clang)
        self.assertEqual(len(capture["configurations"]), 1)
        self.assertIn("-DFACTOR=2", capture["configurations"][0]["frontend_arguments"])
        self.assertEqual(sum(item["project_input"] for item in capture["dependencies"]), 2)
        verify_capture(capture)
        (self.root / "inc.h").write_text("#define LOCAL_FACTOR 4\n")
        with self.assertRaisesRegex(MigrationRejected, "changed"):
            verify_capture(capture)

    def test_unmodeled_build_flags_are_not_silently_discarded(self):
        self.project({"input.c": "int f(int x){return x;}"}, ["-fwrapv"])
        result = self.migrate()
        self.assertFalse(result["ok"])
        self.assertIn("E_C_BUILD_FLAG", [d["code"] for d in result["diagnostics"]])

    def test_retargeted_header_symlink_invalidates_build_capture(self):
        (self.root / "first.h").write_text("#define VALUE 1\n")
        (self.root / "second.h").write_text("#define VALUE 2\n")
        header = self.root / "current.h"
        header.symlink_to(self.root / "first.h")
        self.project({"input.c": '#include "current.h"\nint f(int x){return x+VALUE;}'})
        capture = capture_project(self.database, clang=self.clang)
        header.unlink()
        header.symlink_to(self.root / "second.h")
        with self.assertRaisesRegex(MigrationRejected, "changed"):
            verify_capture(capture)

    def test_command_string_is_never_run_as_shell(self):
        self.project({"input.c": "int f(int x){return x;}"})
        self.database.write_text(json.dumps([{"directory": str(self.root), "file": "input.c",
                                               "command": "clang -std=c11 -c input.c ; touch marker"}]))
        self.assertFalse(self.migrate()["ok"])
        self.assertFalse((self.root / "marker").exists())

    def test_duplicate_macro_configurations_require_separate_artifacts(self):
        self.project({"input.c": "int f(int x){return x;}"})
        entries = json.loads(self.database.read_text())
        self.database.write_text(json.dumps(entries + entries))
        result = self.migrate()
        self.assertFalse(result["ok"])
        self.assertIn("E_C_BUILD_SOURCE", [d["code"] for d in result["diagnostics"]])

    def test_all_active_declarations_remain_in_rejection_inventory(self):
        report = self.rejected("int first; int f(int x){return x;} int last;", "E_C_TOPLEVEL")
        project = [d for d in report["declarations"] if d["status"] != "system_or_compiler_declaration"]
        self.assertEqual([d["name"] for d in project], ["first", "f", "last"])
        self.assertEqual(report["coverage"]["active_project_declarations"], 3)

    def test_unresolved_project_prototype_refuses_bundle(self):
        self.rejected("int missing(int x); int f(int x){return x;}", "E_C_EXTERNAL")

    def test_locals_loops_calls_and_multiple_translation_units(self):
        self.project({
            "helper.c": "unsigned int helper(unsigned int x){return x*3u;}",
            "caller.c": "unsigned int helper(unsigned int x); unsigned int run(unsigned int n){unsigned int value=0u; for(unsigned int i=0u;i<n;++i){value+=helper(i);} while(value>100u){value-=100u;} return value;}"
        })
        result = self.migrate()
        self.assertTrue(result["ok"], result.get("diagnostics"))
        self.assertEqual(len(result["functions"]), 2)
        text = (self.output / "source.hepta").read_text()
        self.assertIn("while", text)
        self.assertIn("c_helper", text)
        self.assertFalse(result["claims"]["source_equivalence_proved"])
        self.assertEqual(result["native_validation"], "not_run")

    def test_uninitialized_local_and_unsupported_continue_are_rejected(self):
        self.rejected("int f(int x){int y; y=x;return y;}", "E_C_LOCAL")
        self.rejected("int f(int x){while(x>0){--x;continue;}return x;}", "E_C_STATEMENT")

    def test_pointer_requires_explicit_contract(self):
        self.rejected("unsigned int f(const unsigned char *p,unsigned long n){return p[0];}", "E_C_POINTER_CONTRACT")

    def fixed_integer_contract(self, count=1):
        return {"schema": "hepta.c-contracts.v1", "functions": {"f": {"slices": {
            str(index): {"length": 1, "access": "read", "element": "int"} for index in range(count)}}}}

    def test_typed_void_aliases_require_initialization_before_control_flow(self):
        contract = self.fixed_integer_contract()
        self.rejected("int f(void *value){int *p; return *p;}", "E_C_POINTER_ALIAS", contract)
        self.rejected("int f(void *value){int *p; if(value){p=(int*)value;}return *p;}", "E_C_POINTER_ALIAS", contract)

    def test_typed_void_alias_reinterpretation_and_write_are_rejected(self):
        contract = self.fixed_integer_contract()
        self.rejected("unsigned int f(void *value){unsigned int *p;p=(unsigned int*)value;return *p;}", "E_C_POINTER_CAST", contract)
        self.rejected("int f(void *value){int *p;p=(int*)value;*p=3;return *p;}", "E_C_READ_ONLY", contract)
        self.rejected("int f(void *value,void *other){int *p;p=(int*)value;p=(int*)other;return *p;}", "E_C_LVALUE", self.fixed_integer_contract(2))

    def test_fixed_length_and_contract_selector_schema_fail_closed(self):
        for length in (0, 2, True, -1):
            contract = self.fixed_integer_contract()
            contract["functions"]["f"]["slices"]["0"]["length"] = length
            self.rejected("int f(void *value){return *((int*)value);}", "E_C_POINTER_CONTRACT", contract)
        contract = self.fixed_integer_contract()
        contract["functions"]["f"]["slices"]["value"] = dict(contract["functions"]["f"]["slices"]["0"])
        self.rejected("int f(void *value){return *((int*)value);}", "E_C_POINTER_CONTRACT", contract)

    def test_documentation_does_not_enable_semantic_attributes(self):
        self.rejected("/** an integer */ __attribute__((noinline)) int f(int x){return x;}", "E_C_ATTRIBUTE")

    def test_complete_upstream_modules_keep_void_abi_and_read_aliasing(self):
        fixture = FIXTURE.parent / "c_algorithms"
        from tools.qualify_c_algorithms import verify_upstream
        self.assertEqual(len(verify_upstream()["files"]), 6)
        for path in fixture.glob("*.h"):
            shutil.copyfile(path, self.root / path.name)
        self.project({name: (fixture / name).read_text() for name in ("compare-int.c", "hash-int.c")})
        result = self.migrate(json.loads((fixture / "contracts.json").read_text()), native=True)
        self.assertTrue(result["ok"], result.get("diagnostics"))
        self.assertEqual(result["coverage"]["active_project_declarations"], 6)
        self.assertEqual(result["coverage"]["status_counts"], {"function_converted": 3, "prototype_resolved": 3})
        self.assertIn("*mut core::ffi::c_void", (self.output / "bridge.rs").read_text())
        self.assertEqual(sum(len(fn["read_pointer_aliases"]) for fn in result["functions"]), 5)
        library = ctypes.CDLL(str(self.output / "libtranslated.so"))
        library.int_compare.argtypes = library.int_equal.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        library.int_compare.restype = library.int_equal.restype = ctypes.c_int32
        library.int_hash.argtypes, library.int_hash.restype = [ctypes.c_void_p], ctypes.c_uint32
        lo, hi = ctypes.c_int32(-(1 << 31)), ctypes.c_int32((1 << 31) - 1)
        self.assertEqual(library.int_compare(ctypes.byref(lo), ctypes.byref(hi)), -1)
        self.assertEqual(library.int_compare(ctypes.byref(lo), ctypes.byref(lo)), 0)
        self.assertEqual(library.int_equal(ctypes.byref(lo), ctypes.byref(lo)), 1)
        self.assertEqual(library.int_hash(ctypes.byref(lo)), 1 << 31)

    def test_read_contract_cannot_hide_mutation(self):
        contract = {"schema": "hepta.c-contracts.v1", "functions": {"f": {"slices": {"p": {"length": "n", "access": "read"}}}}}
        self.rejected("unsigned int f(unsigned char *p,unsigned long n){p[0]=1;return p[0];}", "E_C_READ_ONLY", contract)

    def test_mutable_alias_patterns_require_separate_model(self):
        contract = {"schema": "hepta.c-contracts.v1", "functions": {"f": {"slices": {
            "p": {"length": "n", "access": "mut"}, "q": {"length": "n", "access": "read"}}}}}
        self.rejected("int f(unsigned char *p,const unsigned char *q,unsigned long n){p[0]=q[0];return 0;}", "E_C_ALIAS_CONTRACT", contract)

    def test_signed_narrowing_is_not_silently_redefined(self):
        self.rejected("int f(unsigned long x){return (int)x;}", "E_C_SIGNED_CONVERSION")

    def test_malloc_free_are_not_turned_into_assumed_owners(self):
        report = self.rejected("#include <stdlib.h>\nint f(int x){free(0);return x;}", "E_C_ALLOCATOR")
        self.assertFalse(report["claims"]["pointer_contracts_inferred"])

    def test_malloc_requires_full_initialization_not_default_zero_values(self):
        self.rejected("#include <stdlib.h>\n#include <stdint.h>\nint64_t f(size_t n){if(n==0)return 0; unsigned char *p=malloc(n); if(!p)return -1; int64_t r=p[0];free(p);return r;}", "E_C_ALLOCATOR_INITIALIZATION")

    def test_malloc_zero_length_behavior_is_not_silently_changed(self):
        self.rejected("#include <stdlib.h>\n#include <stdint.h>\nint64_t f(size_t n){unsigned char *p=calloc(n,1); if(!p)return -1; int64_t r=0;free(p);return r;}", "E_C_ALLOCATOR")

    def test_allocation_length_narrowing_is_not_stripped_by_pattern_matching(self):
        source = (FIXTURE.parent / "owned_bytes.c").read_text()
        self.rejected(source.replace("malloc(count)", "malloc((unsigned char)count)"), "E_C_ALLOCATOR")

    def test_transitive_allocator_calls_require_explicit_sequencing(self):
        source = (FIXTURE.parent / "owned_bytes.c").read_text()
        source += "\nint64_t relay(size_t n){return owned_malloc_sum(n);}\nint64_t both(size_t n){return relay(n)+relay(n);}\n"
        self.rejected(source, "E_C_EVALUATION_ORDER")

    def test_allocator_rejects_escape_and_post_free_read(self):
        source = (FIXTURE.parent / "owned_bytes.c").read_text()
        self.rejected(source.replace("free(data);\n    return result;", "free(data);\n    return data[0];", 1), "E_C_ALLOCATOR_AFTER_FREE")

    def test_owned_malloc_calloc_success_and_capacity_failure(self):
        self.project({"owned.c": (FIXTURE.parent / "owned_bytes.c").read_text()})
        result = self.migrate(native=True)
        self.assertTrue(result["ok"], result.get("diagnostics"))
        self.assertEqual({fn["allocation_profile"]["kind"] for fn in result["functions"]}, {"malloc", "calloc"})
        text = (self.output / "source.hepta").read_text()
        self.assertIn("try_buffer", text)
        self.assertIn("match move allocation_result", text)
        self.assertIn("release(move owned_data)", text)
        lib = ctypes.CDLL(str(self.output / "libtranslated.so"))
        for name in ("owned_malloc_sum", "owned_calloc_sum"):
            function = getattr(lib, name)
            function.argtypes = [ctypes.c_size_t]
            function.restype = ctypes.c_int64
            self.assertEqual(function(0), 0)
            self.assertEqual(function(32), sum(range(32)) if name == "owned_malloc_sum" else 0)
            self.assertEqual(function(ctypes.c_size_t(-1).value), -1)

    def test_atomic_commit_then_parent_fsync_failure_requires_recovery(self):
        # Full migrator + real Clang frontend; native code generation is not
        # required to test publication status after the atomic rename.
        self.project({"input.c": "int f(int x){return x;}"})
        import hepta.c_project_publish as publisher
        fsync = os.fsync
        expected_parent_inode = self.root.stat().st_ino

        def fail_parent_fsync(fd):
            if os.fstat(fd).st_ino == expected_parent_inode:
                raise OSError(5, "injected final parent fsync failure")
            return fsync(fd)

        with patch.object(publisher.os, "fsync", side_effect=fail_parent_fsync):
            report = self.migrate(native=False)
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "recovery_required")
        self.assertTrue(report["publication_may_have_committed"])
        self.assertEqual(report["publication_recovery_path"], str(self.output))
        self.assertIn("E_C_PROJECT_RECOVERY_REQUIRED",
                      [item["code"] for item in report["diagnostics"]])
        self.assertTrue(self.output.is_dir())
        self.assertTrue(all((self.output / name).is_file() for name in
                            ("source.hepta", "generated.rs", "bridge.rs", "migration.json")))

    def test_existing_output_bundle_is_preserved(self):
        self.project({"input.c": "int f(int x){return x;}"})
        self.output.mkdir()
        (self.output / "keep").write_text("unchanged")
        result = self.migrate()
        self.assertFalse(result["ok"])
        self.assertEqual((self.output / "keep").read_text(), "unchanged")

    def test_frozen_native_module_real_abi_and_buffer_differential(self):
        for name in ("native.c", "native.h"):
            shutil.copyfile(FIXTURE / name, self.root / name)
        self.project({"native.c": (FIXTURE / "native.c").read_text()})
        contracts = json.loads((FIXTURE / "contracts.json").read_text())
        result = self.migrate(contracts, native=True)
        self.assertTrue(result["ok"], result.get("diagnostics"))
        self.assertTrue(result["contract_scope"]["may_narrow_original_c_input_domain"])
        self.assertFalse(result["claims"]["source_equivalence_proved"])
        self.assertEqual(result["native_validation"], "passed")
        original = self.root / "original.so"
        compiled = subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC", str(self.root / "native.c"), "-o", str(original)], capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        class Point(ctypes.Structure):
            _fields_ = [("x", ctypes.c_int32), ("y", ctypes.c_double)]
        versions = [ctypes.CDLL(str(original)), ctypes.CDLL(str(self.output / "libtranslated.so"))]
        for lib in versions:
            lib.native_add.argtypes = [ctypes.c_int32, ctypes.c_int32]
            lib.native_add.restype = ctypes.c_int32
            lib.native_transform.argtypes = [Point, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
            lib.native_transform.restype = Point
        rng = random.Random(301731)
        for n in [0, 1, 2, 3, 31, 32, 63, 256]:
            for _ in range(8):
                data = (ctypes.c_uint8 * n)(*[rng.randrange(256) for _ in range(n)])
                point = Point(rng.randrange(-1000, 1000), rng.random() * 1000)
                a, b = [lib.native_transform(point, data, n) for lib in versions]
                self.assertEqual((a.x, a.y), (b.x, b.y))
                x, y = rng.randrange(-1000000, 1000000), rng.randrange(-1000000, 1000000)
                self.assertEqual(versions[0].native_add(x, y), versions[1].native_add(x, y))


if __name__ == "__main__":
    unittest.main()
