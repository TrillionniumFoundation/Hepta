"""Bounded class control flow and typed non-type template arguments."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.c_migrate import MigrationRejected
from hepta.cpp_class_migrate import migrate_cpp_class
from hepta.cpp_contracts import _concrete, _validate, bridge_cpp_contracts
from tools.validate_cpp_extensions import LOOPS, SIZES, qualify_cpp_extensions

CLANGXX = os.environ.get("CLANGXX", "clang++")
RUSTC = os.environ.get("RUSTC", "rustc")
CLANG = shutil.which(CLANGXX)
NATIVE = CLANG and shutil.which(RUSTC) and shutil.which("g++") and shutil.which("gcc")


def _contract() -> dict:
    return json.loads((SIZES / "contract.json").read_text())


@unittest.skipUnless(CLANG, "Clang 20 or newer required")
class CppClassLoopTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-class-loops-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def migrate(self, source: str, name: str = "class") -> tuple[dict, Path]:
        entry, output = self.root / (name + ".cpp"), self.root / (name + ".hepta")
        entry.write_text(source)
        return migrate_cpp_class(entry, output, clangxx=CLANGXX), output

    def test_complete_stateful_class_and_shadowed_for_indices_are_implemented(self):
        report, output = self.migrate((LOOPS / "mixer.cpp").read_text())
        self.assertTrue(report["ok"], report)
        generated = output.read_text()
        self.assertIn("receiver.state = localbinding0;", generated)
        self.assertIn("wrapping_mul(localbinding0, 1664525)", generated)
        self.assertIn("receiver: read Mixer", generated)
        self.assertNotIn("extern", generated)
        self.assertNotIn("unsafe", generated)
        methods = report["translated_class"]["methods"]
        self.assertEqual([m["automatic_scalar_locals"] for m in methods], [2, 2, 1, 3])
        self.assertEqual({m["scalar_statement_authority"] for m in methods}, {"hepta.c_migrate._stmt"})
        self.assertEqual(report["translated_class"]["unconverted_members"], [])
        self.assertEqual(report["hepta_frontend"]["assumptions"], [])
        self.assertFalse(report["foreign_cpp_implementation_retained"])
        self.assertFalse(report["resource_owning_raii_translated"])

    def test_unmodeled_local_lifetime_alias_or_control_flow_rejects_whole_class(self):
        template = """struct State {
            unsigned int state;
            State(unsigned int seed) noexcept: state(seed) {}
            unsigned int operation(unsigned int count) noexcept { BODY }
        };"""
        bodies = {
            "uninitialized": "unsigned int n; n = count; return n;",
            "static_local": "static unsigned int n = 0; return n;",
            "thread_local": "thread_local unsigned int n = 0; return n;",
            "volatile_local": "volatile unsigned int n = count; return n;",
            "const_local": "const unsigned int n = count; return n;",
            "reference_alias": "unsigned int& n = state; n = count; return n;",
            "pointer_alias": "unsigned int* n = &state; return *n;",
            "late_declaration": "state = count; unsigned int n = count; return n;",
            "nested_declaration": "if (count > 0u) { unsigned int n = count; state = n; } return state;",
            "two_declarations": "unsigned int a = count, b = state; return a ^ b;",
            "loop_body_declaration": "for (unsigned int i = 0; i < count; ++i) { unsigned int n = i; state = n; } return state;",
            "break": "while (state < count) { ++state; break; } return state;",
            "continue": "for (unsigned int i = 0; i < count; ++i) { continue; } return state;",
            "do_return": "do { return state; } while (count > 0u); return state;",
            "missing_loop_condition": "for (unsigned int i = 0;; ++i) { state = i; } return state;",
            "condition_variable": "while (unsigned int n = count) { state = n; } return state;",
            "jump": "again: state = count; if (count > 0u) goto again; return state;",
        }
        for name, body in bodies.items():
            with self.subTest(case=name):
                report, output = self.migrate(template.replace("BODY", body), name)
                self.assertFalse(report["ok"], report)
                self.assertFalse(output.exists())


class CppTemplateSizeContractTests(unittest.TestCase):
    def test_v4_renders_exact_typed_sizes_for_objects_and_function_templates(self):
        candidate = _validate(_contract())
        obj = candidate["handles"][0]
        self.assertEqual(_concrete(obj["cpp_type"], obj["template_args"]),
                         "std::array<std::uint32_t, static_cast<std::size_t>(4)>")
        for size in (0, 1, 65536):
            candidate = _contract()
            candidate["handles"][0]["template_args"][1]["value"] = size
            self.assertIs(_validate(candidate), candidate)

    def test_old_wire_schemas_keep_type_only_template_arguments(self):
        for schema in ("v1", "v2", "v3"):
            with self.subTest(schema=schema):
                candidate = _contract()
                candidate["schema"] = "hepta.cpp-contract." + schema
                if schema != "v3":
                    candidate.pop("scopes")
                if schema == "v1":
                    for handle in candidate["handles"]:
                        handle.pop("constructors")
                with self.assertRaisesRegex(MigrationRejected, "explicit v4"):
                    _validate(candidate)

    def test_non_type_arguments_are_not_coerced_or_pasted_into_cpp(self):
        bad = [True, False, -1, 65537, 4.0, "4", "4); throw 0;", None, [], {}]
        for value in bad:
            with self.subTest(value=value):
                candidate = _contract()
                candidate["handles"][0]["template_args"][1]["value"] = value
                with self.assertRaises(MigrationRejected):
                    _validate(candidate)
        for value in ({"kind": "integer", "value": 4}, {"kind": "size", "value": 4, "cpp": "4"},
                      4, [4], "std::uint32_t", {"value": 4}):
            with self.subTest(argument=value):
                candidate = _contract()
                candidate["functions"][0]["template_args"] = [value]
                with self.assertRaises(MigrationRejected):
                    _validate(candidate)


@unittest.skipUnless(NATIVE, "Clang 20+, Rust, GCC and G++ required")
class CppExtensionsNativeTests(unittest.TestCase):
    def test_actual_migration_backends_and_two_template_specializations(self):
        with tempfile.TemporaryDirectory(prefix="hepta-cpp-extensions-") as directory:
            report = qualify_cpp_extensions(Path(directory) / "qualification", clangxx=CLANGXX, rustc=RUSTC)
            self.assertTrue(report["ok"])
            classes = report["class_implementation_migration"]
            self.assertEqual(classes["execution"]["cases_per_backend"], 592)
            self.assertEqual(len(set(classes["execution"]["observations_sha256"].values())), 1)
            self.assertTrue(classes["execution"]["independent_python_integer_oracle"])
            self.assertTrue(classes["negative_control"]["detected"])
            self.assertFalse(classes["original_cpp_implementation_linked_into_migrated_libraries"])
            for backend in classes["builds"].values():
                self.assertEqual(backend["foreign_cpp_link_inputs"], [])
                self.assertFalse(backend["library"]["retained"])
                self.assertNotIn("path", backend["library"])
                self.assertFalse(Path(backend["library"]["path_during_execution"]).exists())
                self.assertTrue(Path(backend["linker_map"]["path"]).is_file())
            self.assertTrue(classes["reference_only_marker_present_only_in_reference_library"])
            self.assertTrue(Path(classes["execution"]["raw_results"]["path"]).is_file())
            templates = report["sized_template_bridging"]
            self.assertTrue(templates["native_link_qualified"])
            self.assertTrue(templates["foreign_cpp_implementation_retained"])
            self.assertFalse(templates["foreign_nonretention_proved"])
            self.assertEqual([v["extent"] for v in templates["variants"]], [4, 8])
            for variant in templates["variants"]:
                self.assertEqual(variant["execution"]["std_array_differential_cases"], 24)
                self.assertEqual(variant["execution"]["counted_lifecycle_cases"], 24)
                self.assertEqual(variant["execution"]["constructor_failure_paths"], 1)
                self.assertEqual(variant["execution"]["handle_transitions"], 7)
                self.assertEqual(variant["execution"]["live_members"], 0)
                self.assertEqual(variant["execution_process"]["returncode"], 0)
                specs = variant["generation"]["template_specializations"]
                self.assertEqual(len(specs), 3)
                self.assertTrue(all(s["selected_instantiation_native_checked"] for s in specs))
                self.assertTrue(all(not s["all_template_instantiations_qualified"] for s in specs))
            self.assertTrue(templates["upgrade_experiment"]["generated_c_header_identical"])
            self.assertEqual(templates["upgrade_experiment"]["consumer_source_edits"], 0)
            self.assertGreater(templates["upgrade_experiment"]["generated_cpp_lines_added"], 0)
            self.assertEqual(len(templates["upgrade_experiment"]["generation_and_native_check_ns"]), 2)
            self.assertIsNone(templates["upgrade_experiment"]["human_maintenance_minutes"])

    def test_native_rejects_wrong_template_category_signature_or_destructor(self):
        with tempfile.TemporaryDirectory(prefix="hepta-sized-refuse-") as directory:
            root = Path(directory)
            for kind in ("size_category", "function_return", "throwing_destructor"):
                with self.subTest(case=kind):
                    candidate = copy.deepcopy(_contract())
                    header = root / (kind + ".hpp")
                    text = (SIZES / "foreign.hpp").read_text()
                    if kind == "size_category":
                        candidate["handles"][0]["template_args"][1] = "u32"
                    elif kind == "function_return":
                        candidate["functions"][0]["returns"] = "u64"
                    else:
                        text = text.replace("~CountedArray() noexcept", "~CountedArray() noexcept(false)")
                    header.write_text(text)
                    output = root / kind
                    report = bridge_cpp_contracts(header, candidate, output, cxx="g++", rustc=RUSTC)
                    self.assertFalse(report["ok"], report)
                    self.assertEqual(report["diagnostics"][0]["code"], "E_CPP_NATIVE")
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
