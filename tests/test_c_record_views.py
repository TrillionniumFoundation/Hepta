"""Soundness regressions for complete C record-view module migration."""
from __future__ import annotations

import copy
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import migrate_c_project
from tools.qualify_c_ring_buffer import FIXTURE, FLAGS, capture_fixture, run_sequences, boundary_controls, owned_client, layout_probe


SOURCE = r'''
#include <stddef.h>
/** A borrowed caller-owned byte store. */
struct State {
    /** Live initialized bytes. */ unsigned char *data;
    size_t n;
    unsigned int head;
};
void start(struct State *ctx, unsigned char *data, size_t n) {
    ctx->data = data;
    ctx->n = n;
    ctx->head = 0;
}
void tick(struct State *ctx, unsigned char value) {
    ctx->data[ctx->head] = value;
    ctx->head = (ctx->head + 1u) % ctx->n;
}
unsigned int read_at(struct State *ctx, size_t i) {
    return ctx->data[i];
}
'''
CONTRACT = {
    "schema": "hepta.c-record-views.v1",
    "records": {"State": {"buffers": {"data": {"length_field": "n", "add": 0}}}},
    "functions": {
        "start": {"records": {"ctx": {"access": "mut", "initialize": {"data": "data"}}}, "slices": {"data": {"length": "n", "access": "mut"}}},
        "tick": {"records": {"ctx": {"access": "mut"}}, "slices": {}},
        "read_at": {"records": {"ctx": {"access": "read"}}, "slices": {}},
    },
}


class CRecordViewsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-c-record-view-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clang = shutil.which("clang")
        self.assertIsNotNone(self.clang, "Clang is required for C record-view qualification")
        self.rustc = os.environ.get("RUSTC")
        self.counter = 0

    def migrate(self, source=SOURCE, contracts=None, *, native=False, flags=None):
        self.counter += 1
        work = self.root / str(self.counter)
        work.mkdir()
        (work / "input.c").write_text(source)
        database = work / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(work), "file": "input.c", "arguments": ["clang", "-std=c11", *(flags or []), "-c", "input.c"]}]))
        result = migrate_c_project(database, work / "translated", contracts=copy.deepcopy(CONTRACT if contracts is None else contracts), clang=self.clang, rustc=self.rustc, verify_native=native)
        return result, work

    def reject(self, source, code, contracts=None):
        report, work = self.migrate(source, contracts)
        self.assertFalse(report["ok"], report)
        self.assertFalse((work / "translated").exists())
        self.assertIn(code, [d["code"] for d in report["diagnostics"]], report["diagnostics"])
        return report

    def test_generic_view_translates_changed_names_and_algorithms(self):
        report, work = self.migrate(native=True)
        self.assertTrue(report["ok"], report["diagnostics"])
        self.assertFalse(report["record_views"]["ownership_inference"])
        self.assertFalse(report["record_views"]["stored_references_added_to_language"])
        generated = (work / "translated/source.hepta").read_text()
        self.assertNotIn("raw ", generated)
        class State(ctypes.Structure):
            _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("n", ctypes.c_size_t), ("head", ctypes.c_uint32)]
        lib = ctypes.CDLL(str(work / "translated/libtranslated.so"))
        lib.start.argtypes = [ctypes.POINTER(State), ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
        lib.tick.argtypes = [ctypes.POINTER(State), ctypes.c_uint8]
        lib.read_at.argtypes, lib.read_at.restype = [ctypes.POINTER(State), ctypes.c_size_t], ctypes.c_uint32
        data, state = (ctypes.c_uint8 * 4)(), State()
        lib.start(ctypes.byref(state), data, 4)
        for value in range(9):
            lib.tick(ctypes.byref(state), value)
        self.assertEqual(list(data), [8, 5, 6, 7])
        self.assertEqual(state.head, 1)
        self.assertEqual([lib.read_at(ctypes.byref(state), i) for i in range(4)], list(data))

    def test_complete_unmodified_upstream_native_sequence_and_layout(self):
        database = capture_fixture(self.root)
        contracts = json.loads((FIXTURE / "contracts.json").read_text())
        report = migrate_c_project(database, self.root / "translated", contracts=contracts, clang=self.clang, rustc=self.rustc, verify_native=True)
        self.assertTrue(report["ok"], report["diagnostics"])
        self.assertEqual(report["coverage"]["active_project_declarations"], 22)
        self.assertEqual(report["coverage"]["status_counts"], {"function_converted": 9, "prototype_resolved": 9, "record_converted": 1, "record_forward_resolved": 1, "type_alias_resolved": 2})
        original = self.root / "original.so"
        compiled = subprocess.run(["gcc", *FLAGS, "-O2", "-shared", "-fPIC", str(self.root / "ringbuffer.c"), "-o", str(original)], capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        translated = self.root / "translated/libtranslated.so"
        result = run_sequences(original, translated, steps=128)
        self.assertEqual(result["state_transitions"], 1024)
        self.assertEqual(result["native_differential_calls"], 4104)
        self.assertGreater(result["zero_length_null_slice_calls"], 0)
        layout = layout_probe(original, (self.root / "translated/generated.rs").read_text(), self.root, shutil.which("gcc"), self.rustc)
        self.assertEqual(layout["size"], {"gcc": 32, "rust": 32})
        self.assertEqual(layout["head_index"], {"gcc": 24, "rust": 24})

    def test_real_overlap_null_extent_and_bounds_controls(self):
        database = capture_fixture(self.root)
        report = migrate_c_project(database, self.root / "translated", contracts=json.loads((FIXTURE / "contracts.json").read_text()), clang=self.clang, rustc=self.rustc, verify_native=True)
        self.assertTrue(report["ok"], report["diagnostics"])
        results = boundary_controls(self.root / "translated/libtranslated.so")
        self.assertEqual(len(results), 9)
        self.assertTrue(all(item["actual_exit"] == -6 for item in results))

    def test_real_owned_client_allocation_refusal_early_drop_recovery(self):
        database = capture_fixture(self.root)
        report = migrate_c_project(database, self.root / "translated", contracts=json.loads((FIXTURE / "contracts.json").read_text()), clang=self.clang, rustc=self.rustc, verify_native=True)
        self.assertTrue(report["ok"], report["diagnostics"])
        result = owned_client((self.root / "translated/source.hepta").read_text(), self.root, self.rustc)
        self.assertEqual([call["result"] for call in result["calls"]], [0, 7, -1, 0, -1, 0])
        self.assertTrue(all(call["live_allocations_after"] == 0 for call in result["calls"]))
        self.assertFalse(result["upstream_allocator_migration_claimed"])

    def test_unused_unsupported_declaration_still_rejects_complete_module(self):
        report = self.reject(SOURCE + "\nint unused_global;\n", "E_C_TOPLEVEL")
        self.assertTrue(report["declaration_inventory_complete"])
        project = [item for item in report["declarations"] if item["status"] != "system_or_compiler_declaration"]
        self.assertEqual([item["name"] for item in project], ["State", "start", "tick", "read_at", "unused_global"])
        self.assertEqual(report["coverage"]["active_project_declarations"], 5)

    def test_by_value_pointer_record_abi_cannot_silently_drop_pointer_field(self):
        contracts = copy.deepcopy(CONTRACT)
        contracts["functions"]["copy_state"] = {"slices": {}, "records": {}}
        self.reject(SOURCE + "\nstruct State copy_state(struct State state){return state;}\n", "E_C_VIEW_VALUE_ABI", contracts)

    def test_initializer_pointer_assignment_must_match_contract(self):
        self.reject(SOURCE.replace("ctx->data = data;", "ctx->data = data + 1;"), "E_C_VIEW_INIT")

    def test_initializer_must_not_read_old_uninitialized_record(self):
        self.reject(SOURCE.replace("ctx->head = 0;", "ctx->head = ctx->head;"), "E_C_VIEW_INIT")

    def test_initializer_all_fields_exactly_once_without_conditional_writes(self):
        for source in (SOURCE.replace("ctx->head = 0;", ""), SOURCE.replace("ctx->head = 0;", "ctx->head = 0; ctx->head = 1;"), SOURCE.replace("ctx->head = 0;", "if(n) ctx->head = 0;")):
            with self.subTest(source=source):
                self.reject(source, "E_C_VIEW_INIT")

    def test_pointer_fields_cannot_change_after_initialization(self):
        self.reject(SOURCE.replace("ctx->data[ctx->head] = value;", "ctx->data = ctx->data;"), "E_C_VIEW_POINTER_WRITE")

    def test_buffer_extent_cannot_change_while_borrowed(self):
        self.reject(SOURCE.replace("ctx->data[ctx->head] = value;", "ctx->n += 1;"), "E_C_VIEW_EXTENT_WRITE")

    def test_read_record_cannot_write_scalar_or_storage_or_call_mutator(self):
        for body in ("ctx->head=1; return 0;", "ctx->data[i]=1; return 0;", "tick(ctx,1);return 0;"):
            with self.subTest(body=body):
                self.reject(SOURCE.replace("return ctx->data[i];", body), "E_C_READ_ONLY")

    def test_call_result_with_unsequenced_other_operand_is_rejected(self):
        contracts = copy.deepcopy(CONTRACT)
        contracts["functions"]["tick"]["records"]["ctx"]["access"] = "mut"
        source = SOURCE.replace("void tick(", "unsigned int tick(").replace("ctx->head = (ctx->head + 1u) % ctx->n;", "ctx->head = (ctx->head + 1u) % ctx->n; return ctx->head;")
        source = source.replace("return ctx->data[i];", "return tick(ctx, 1) + ctx->head;")
        contracts["functions"]["read_at"]["records"]["ctx"]["access"] = "mut"
        self.reject(source, "E_C_EVALUATION_ORDER", contracts)

    def test_conditional_initialization_does_not_invent_zero_value(self):
        source = SOURCE.replace("return ctx->data[i];", "unsigned int value; if(i) value=1; return value;")
        self.reject(source, "E_C_LOCAL")

    def test_read_before_first_assignment_is_rejected(self):
        self.reject(SOURCE.replace("return ctx->data[i];", "unsigned int value; return value;"), "E_C_REFERENCE")

    def test_signed_relative_cursor_indices_preserve_defined_c_access(self):
        bodies = [
            ("unsigned char *p=ctx->data; ++p; return p[-1];", 13),
            ("unsigned char *p=ctx->data; ++p; int back=-1; return p[back];", 13),
            ("unsigned char *p=ctx->data; ++p; ++p; ++p; ++p; return p[-1];", 41),
            ("unsigned char *p=ctx->data; ++p; ++p; ++p; ++p; return p[-4];", 13),
            ("unsigned char *p=ctx->data; ++p; return p[0];", 23),
        ]
        class State(ctypes.Structure):
            _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("n", ctypes.c_size_t), ("head", ctypes.c_uint32)]
        for body, expected in bodies:
            with self.subTest(body=body):
                report, work = self.migrate(SOURCE.replace("return ctx->data[i];", body), native=True)
                self.assertTrue(report["ok"], report["diagnostics"])
                original = work / "original.so"
                build = subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC", str(work / "input.c"), "-o", str(original)], capture_output=True, text=True)
                self.assertEqual(build.returncode, 0, build.stderr)
                observed = []
                for path in (original, work / "translated/libtranslated.so"):
                    lib = ctypes.CDLL(str(path))
                    lib.read_at.argtypes, lib.read_at.restype = [ctypes.POINTER(State), ctypes.c_size_t], ctypes.c_uint32
                    data = (ctypes.c_uint8 * 4)(13, 23, 37, 41)
                    state = State(data, 4, 0)
                    observed.append(lib.read_at(ctypes.byref(state), 0))
                    self.assertEqual(list(data), [13, 23, 37, 41])
                self.assertEqual(observed, [expected, expected])

    def test_relative_cursor_checks_before_narrowing_and_dereference(self):
        script = r'''import ctypes,resource,sys
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
class R(ctypes.Structure):
 _fields_=[('data',ctypes.POINTER(ctypes.c_uint8)),('n',ctypes.c_size_t),('head',ctypes.c_uint32)]
lib=ctypes.CDLL(sys.argv[1]);lib.read_at.argtypes=[ctypes.POINTER(R),ctypes.c_size_t];lib.read_at.restype=ctypes.c_uint32
data=(ctypes.c_uint8*4)(13,23,37,41);state=R(data,4,0)
lib.read_at(ctypes.byref(state),0)
'''
        for body in ("unsigned char *p=ctx->data; ++p; return p[-2];",
                     "unsigned char *p=ctx->data; ++p; ++p; ++p; ++p; return p[0];",
                     "unsigned char *p=ctx->data; ++p; size_t huge=(size_t)-1; return p[huge];",
                     "unsigned char *p=ctx->data; ++p; long long back=(-9223372036854775807LL - 1LL); return p[back];"):
            with self.subTest(body=body):
                report, work = self.migrate(SOURCE.replace("return ctx->data[i];", body), native=True)
                self.assertTrue(report["ok"], report["diagnostics"])
                result = subprocess.run([os.sys.executable, "-c", script, str(work / "translated/libtranslated.so")], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, -6, result.stderr)

    def test_unmodeled_relative_pointer_mutations_still_fail_closed(self):
        for body in ("unsigned char *p=ctx->data; p+=1; return p[0];",
                     "unsigned char *p=ctx->data; ++p; --p; return p[0];"):
            with self.subTest(body=body):
                self.reject(SOURCE.replace("return ctx->data[i];", body), "E_C_LVALUE")

    def test_record_attributes_and_volatile_are_not_ignored_as_comments(self):
        self.reject(SOURCE.replace("struct State {", "struct __attribute__((packed)) State {"), "E_C_RECORD")
        self.reject(SOURCE.replace("unsigned int head;", "volatile unsigned int head;"), "E_C_TYPE")

    def test_contract_schema_rejects_unknown_fields_and_missing_record(self):
        invalid = []
        extra = copy.deepcopy(CONTRACT); extra["trusted"] = True; invalid.append(extra)
        absent = copy.deepcopy(CONTRACT); absent["records"] = {}; invalid.append(absent)
        mode = copy.deepcopy(CONTRACT); mode["functions"]["tick"]["records"]["ctx"]["access"] = "owned"; invalid.append(mode)
        for contract in invalid:
            with self.subTest(contract=contract):
                self.reject(SOURCE, "E_C_VIEW_CONTRACT", contract)

    def test_nonexistent_extent_and_unknown_extra_record_are_rejected(self):
        contract = copy.deepcopy(CONTRACT)
        contract["records"]["State"]["buffers"]["data"]["length_field"] = "missing"
        self.reject(SOURCE, "E_C_VIEW_FIELD", contract)
        self.reject(SOURCE + "\nstruct Extra {int ignored;};\n", "E_C_VIEW_CONTRACT")

    def test_plain_char_flag_is_retained_in_semantic_build_capture(self):
        source = SOURCE.replace("unsigned char", "char")
        result, _ = self.migrate(source, flags=["-funsigned-char"])
        self.assertTrue(result["ok"], result["diagnostics"])
        config = result["build"]["configurations"][0]
        self.assertTrue(config["model"]["char_unsigned"])
        self.assertIn("-funsigned-char", config["frontend_arguments"])
        self.assertEqual(result["record_views"]["records"]["State"]["data"]["element"], "u8")

    def test_mixed_translation_unit_char_models_fail_with_complete_inventory(self):
        entries, contracts = [], {"schema": "hepta.c-record-views.v1", "records": {}, "functions": {}}
        for name, flag in (("A", "-funsigned-char"), ("B", "-fsigned-char")):
            path = self.root / (name + ".c")
            path.write_text("#include <stddef.h>\nstruct " + name + "{char *data;size_t n;};int read_" + name + "(struct " + name + " *value){return value->data[0];}\n")
            entries.append({"directory": str(self.root), "file": path.name, "arguments": ["clang", "-std=c11", flag, "-c", path.name]})
            contracts["records"][name] = {"buffers": {"data": {"length_field": "n", "add": 0}}}
            contracts["functions"]["read_" + name] = {"records": {"value": {"access": "read"}}, "slices": {}}
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps(entries))
        report = migrate_c_project(database, self.root / "translated", contracts=contracts, clang=self.clang, rustc=self.rustc, verify_native=True)
        self.assertFalse(report["ok"])
        self.assertIn("E_C_PROJECT_MODEL", [d["code"] for d in report["diagnostics"]])
        self.assertTrue(report["declaration_inventory_complete"])
        self.assertEqual(report["coverage"]["active_project_declarations"], 4)
        self.assertEqual({item["name"] for item in report["declarations"] if item["status"] != "system_or_compiler_declaration"}, {"A", "B", "read_A", "read_B"})
        self.assertFalse((self.root / "translated").exists())

    def test_user_macro_and_include_path_cannot_spoof_native_char_model(self):
        for flags in (["-D__CHAR_UNSIGNED__=1"], ["-D", "__CHAR_UNSIGNED__=1"], ["-I", "-funsigned-char"]):
            with self.subTest(flags=flags):
                source = "int f(char value){return value;}"
                report, work = self.migrate(source, {"schema": "hepta.c-contracts.v1", "functions": {}}, native=True, flags=flags)
                self.assertTrue(report["ok"], report["diagnostics"])
                model = report["build"]["configurations"][0]
                self.assertFalse(model["model"]["char_unsigned"])
                self.assertEqual(model["abi_model_arguments"], ["-std=c11"])
                self.assertEqual(report["functions"][0]["params"][0]["type"], "i8")
                lib = ctypes.CDLL(str(work / "translated/libtranslated.so"))
                lib.f.argtypes, lib.f.restype = [ctypes.c_int8], ctypes.c_int32
                self.assertEqual(lib.f(-1), -1)

    def test_project_typedef_named_size_t_does_not_override_native_abi(self):
        # typedef names are not C keywords; a project can choose a different
        # underlying type. It must outrank the convenience std typedef map.
        source = "typedef unsigned short size_t; size_t f(size_t x){return x;}"
        result, work = self.migrate(source, {"schema": "hepta.c-contracts.v1", "functions": {}}, native=True)
        self.assertTrue(result["ok"], result["diagnostics"])
        self.assertEqual(result["functions"][0]["params"][0]["type"], "u16")
        self.assertEqual(result["functions"][0]["return"], "u16")
        lib = ctypes.CDLL(str(work / "translated/libtranslated.so"))
        lib.f.argtypes, lib.f.restype = [ctypes.c_uint16], ctypes.c_uint16
        self.assertEqual(lib.f(65535), 65535)


if __name__ == "__main__":
    unittest.main()
