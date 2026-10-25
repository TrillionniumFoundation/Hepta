"""Complete selected-class implementation migration, native execution and refusal."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.cpp_class_migrate import migrate_cpp_class
from tools.validate_cpp_class import qualify_cpp_class, validate_cpp_class_qualification

CLANGXX = os.environ.get("CLANGXX", "clang++")
CLANG = shutil.which(CLANGXX)
NATIVE = CLANG and shutil.which("gcc") and shutil.which(os.environ.get("RUSTC", "rustc"))
BASIC = """
struct Counter {
    unsigned int value;
    Counter(unsigned int initial) noexcept: value(initial) {}
    unsigned int add(unsigned int arg0) noexcept { value = value + arg0; return value; }
    unsigned int get() const noexcept { return value; }
};
"""


@unittest.skipUnless(CLANG, "selected class migration requires Clang 20 or newer")
class CppClassMigrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-cpp-class-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def migrate(self, text=BASIC, name="sample"):
        source, output = self.root / (name + ".cpp"), self.root / (name + ".hepta")
        source.write_text(text)
        return migrate_cpp_class(source, output, clangxx=CLANGXX), output

    def test_complete_value_class_becomes_real_struct_and_free_functions(self):
        report, output = self.migrate()
        self.assertTrue(report["ok"], report)
        generated = output.read_text()
        self.assertIn("pub struct Counter", generated)
        self.assertIn("receiver: mut Counter, arg0: u32", generated)
        self.assertIn("receiver.value = wrapping_add(receiver.value, arg0);", generated)
        self.assertIn("receiver: read Counter", generated)
        self.assertNotIn('extern "C"', generated)
        self.assertNotIn("unsafe", generated)
        self.assertEqual(report["translated_class"]["unconverted_members"], [])
        self.assertEqual(report["translated_class"]["destructor"], "implicit_trivial")
        self.assertEqual(report["foreign_calls_introduced"], 0)
        self.assertFalse(report["foreign_cpp_implementation_retained"])
        self.assertFalse(report["resource_owning_raii_translated"])
        self.assertFalse(report["source_equivalence_proved"])
        self.assertFalse(report["cpp_abi_preserved"])
        self.assertEqual(report["native_validation"], "not_run")
        self.assertEqual(report["differential_validation"], "not_run")
        self.assertEqual(report["hepta_frontend"]["assumptions"], [])
        self.assertEqual(report["output_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())

    def test_declaration_identity_handles_names_and_real_constructor_field_order(self):
        source = """
            class S {
            public:
                unsigned int arg0;
                unsigned int receiver;
                S(unsigned int receiver, unsigned int arg0) noexcept: receiver(arg0), arg0(receiver) {}
                unsigned int get(unsigned int receiver) noexcept { return arg0 ^ this->receiver ^ receiver; }
                ~S() noexcept = default;
            };
        """
        report, output = self.migrate(source)
        self.assertTrue(report["ok"], report)
        text = output.read_text()
        self.assertIn("return S {arg0: arg0, receiver: arg1};", text)
        self.assertIn("receiver.arg0", text)
        self.assertIn("receiver.receiver", text)
        self.assertEqual(report["translated_class"]["destructor"], "explicit_defaulted_trivial")

    def test_every_unsupported_declaration_or_lifecycle_refuses_whole_unit(self):
        cases = {
            "resource_owner": "struct S { int* p; S(int value) noexcept: p(new int(value)) {} ~S() noexcept { delete p; } int get() const noexcept { return *p; } };",
            "nontrivial_destructor": BASIC.replace("unsigned int get()", "~Counter() noexcept { value = 0; } unsigned int get()"),
            "mutable_nonconst_getter": "struct S { mutable int x; S(int p) noexcept: x(p) {} int get() noexcept { return x; } };",
            "volatile_field": BASIC.replace("unsigned int value;", "volatile unsigned int value;"),
            "const_field": BASIC.replace("unsigned int value;", "const unsigned int value;").replace("value = value + arg0;", ""),
            "bitfield": BASIC.replace("unsigned int value;", "unsigned int value: 12;"),
            "default_field_initializer": BASIC.replace("unsigned int value;", "unsigned int value = 1;"),
            "private_field": BASIC.replace("struct Counter {", "class Counter {"),
            "protected_method": BASIC.replace("unsigned int get()", "protected: unsigned int get()"),
            "static_state": BASIC.replace("unsigned int value;", "unsigned int value; inline static int count = 0;"),
            "friend": BASIC.replace("unsigned int value;", "unsigned int value; friend int hidden(Counter&);"),
            "nested_alias": BASIC.replace("unsigned int value;", "unsigned int value; using hidden = int;"),
            "nested_type": BASIC.replace("unsigned int value;", "unsigned int value; struct Hidden {};"),
            "virtual": BASIC.replace("unsigned int get()", "virtual unsigned int get()"),
            "inheritance": "struct Base {}; " + BASIC.replace("struct Counter {", "struct Counter: Base {"),
            "template": "template<class T> " + BASIC,
            "hidden_extern": BASIC + 'extern "C" int hidden();',
            "global_state": "int global = 0;\n" + BASIC,
            "extra_class": BASIC + "struct Other { int x; };",
            "incomplete_method": BASIC.replace("unsigned int get() const noexcept { return value; }", "unsigned int get() const noexcept;"),
            "overload": BASIC.replace("unsigned int get()", "unsigned int get(int x) noexcept { return value; } unsigned int get()"),
            "default_parameter": BASIC.replace("unsigned int arg0)", "unsigned int arg0 = 0)"),
            "reference_parameter": BASIC.replace("unsigned int arg0)", "const unsigned int& arg0)"),
            "escaping_receiver": BASIC.replace("unsigned int get() const noexcept { return value; }", "Counter* get() noexcept { return this; }"),
            "constructor_body": BASIC.replace("value(initial) {}", "value(initial) { value = 3; }"),
            "missing_field_initializer": BASIC.replace("unsigned int value;", "unsigned int value; int uninitialized;"),
            "method_call": BASIC.replace("return value; }\n    unsigned int get", "return get(); }\n    unsigned int get"),
            "function_attribute": BASIC.replace("unsigned int get()", "[[nodiscard]] unsigned int get()"),
            "throwing_method": BASIC.replace("get() const noexcept", "get() const"),
            "preprocessor": "#define X 1\n" + BASIC,
        }
        for name, source in cases.items():
            with self.subTest(refusal=name):
                report, output = self.migrate(source, name)
                self.assertFalse(report["ok"], report)
                self.assertTrue(report["rejected"], report)
                self.assertFalse(output.exists())

    def test_existing_and_symlink_outputs_are_never_replaced(self):
        source = self.root / "source.cpp"
        source.write_text(BASIC)
        output = self.root / "keep.hepta"
        output.write_text("preserved")
        existing = migrate_cpp_class(source, output, clangxx=CLANGXX)
        self.assertFalse(existing["ok"])
        self.assertEqual(output.read_text(), "preserved")
        link = self.root / "link.hepta"
        link.symlink_to(self.root / "absent")
        rejected = migrate_cpp_class(source, link, clangxx=CLANGXX)
        self.assertFalse(rejected["ok"])
        self.assertTrue(link.is_symlink())

    def test_source_change_after_ast_capture_refuses_publication(self):
        import hepta.cpp_class_migrate as migrator
        source, output = self.root / "race.cpp", self.root / "race.hepta"
        source.write_text(BASIC)
        run = migrator._run

        def changed(args, **kwargs):
            captured = run(args, **kwargs)
            if "-ast-dump=json" in args:
                source.write_text(BASIC + "\nint unconverted;\n")
            return captured

        with patch.object(migrator, "_run", side_effect=changed):
            report = migrate_cpp_class(source, output, clangxx=CLANGXX)
        self.assertFalse(report["ok"])
        self.assertEqual(report["rejected"][0]["code"], "E_CPP_CLASS_RACE")
        self.assertFalse(output.exists())

    def test_absent_compiler_is_explicit_rejection(self):
        source = self.root / "source.cpp"
        source.write_text(BASIC)
        output = self.root / "absent.hepta"
        report = migrate_cpp_class(source, output, clangxx="/no/such/clang++")
        self.assertFalse(report["ok"])
        self.assertEqual(report["rejected"][0]["code"], "E_CPP_CLASS_TOOLCHAIN")
        self.assertFalse(output.exists())


@unittest.skipUnless(NATIVE, "class differential needs Clang 20, GCC and pinned Rust 1.90")
class CppClassNativeTests(unittest.TestCase):
    def test_real_dual_backend_differential_and_executed_mutation_control(self):
        with tempfile.TemporaryDirectory(prefix="hepta-cpp-class-native-") as temporary:
            report = qualify_cpp_class(temporary, clangxx=CLANGXX, rustc=os.environ.get("RUSTC"), cc="gcc")
            self.assertTrue(report["ok"], report)
            self.assertTrue(validate_cpp_class_qualification(report))
            self.assertEqual(report["execution"]["cases_per_backend"], 1777)
            self.assertEqual(report["migration"]["translated_class"]["destructor"], "explicit_defaulted_trivial")
            self.assertEqual(len(report["migration"]["translated_class"]["fields"]), 4)
            self.assertEqual(len(report["migration"]["translated_class"]["methods"]), 9)
            mismatch = json.loads(report["negative_control"]["execution_process"]["stdout"])
            self.assertEqual(mismatch["status"], "differential_mismatch")
            self.assertNotEqual(mismatch["observed"], mismatch["reference"])

            def replace_execution(record, action):
                action(record["execution"])
                stdout = json.dumps(record["execution"], sort_keys=True) + "\n"
                record["execution_process"].update(stdout=stdout, stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest())

            mutations = {
                "boolean_exit": lambda r: r["execution_process"].update(returncode=False),
                "failed_reference": lambda r: r["reference_build"].update(returncode=7),
                "missing_inputs": lambda r: r.update(inputs={}),
                "stale_compiler": lambda r: r.update(hepta_compiler_sha256="0" * 64),
                "fake_safety_proof": lambda r: r.update(whole_language_memory_safety_proved=True),
                "fake_abi": lambda r: r["migration"].update(cpp_abi_preserved=True),
                "unconverted_member": lambda r: r["migration"]["translated_class"].update(unconverted_members=["hidden"]),
                "migrated_text_changed": lambda r: r.update(migrated_source_text="module empty;"),
                "backend_not_run": lambda r: r["backends"]["c"]["native"].update(status="not_run"),
                "backend_checks_only": lambda r: r["backends"]["rust"]["native"].update(check_only=True),
                "metadata_not_run": lambda r: r["backends"]["rust"]["frontend"]["backend"].update(status="not_run"),
                "c_foreign_link": lambda r: r["backends"]["c"]["native"].update(link_args=["original-cpp.o"]),
                "native_wrong_bytes": lambda r: r["backends"]["c"]["native"].update(artifact_bytes=1),
                "missing_toolchain": lambda r: r["backends"]["rust"]["native"].update(toolchain={}),
                "missing_flags": lambda r: r["backends"]["c"]["native"].update(flags=[]),
                "wrong_execution_command": lambda r: r["execution_process"]["command"].__setitem__(-1, "wrong.so"),
                "fake_observation_digests": lambda r: replace_execution(r, lambda e: e.update(observations_sha256={name: "0" * 64 for name in ("cpp", "rust", "c")})),
                "float_case_count": lambda r: replace_execution(r, lambda e: e["cases_by_family"].update(word_trace=305.0)),
                "negative_not_run": lambda r: r["negative_control"]["execution_process"].update(returncode=0),
                "negative_source_changed": lambda r: r["negative_control"].update(source_sha256="0" * 64),
                "negative_wrong_artifact": lambda r: r["negative_control"]["execution_process"]["command"].__setitem__(-1, "wrong.so"),
                "negative_build_not_run": lambda r: r["negative_control"]["build"]["native"].update(status="not_run"),
            }
            for name, mutate in mutations.items():
                with self.subTest(evidence_mutation=name):
                    altered = copy.deepcopy(report)
                    mutate(altered)
                    with self.assertRaises(ValueError):
                        validate_cpp_class_qualification(altered)


if __name__ == "__main__":
    unittest.main()
