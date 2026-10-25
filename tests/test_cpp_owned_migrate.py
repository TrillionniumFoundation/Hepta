"""Real resource-class migration: full-body binding, cleanup and allocator refusal."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.cpp_owned_migrate import migrate_cpp_owned
from tools.release_check import require_collected_qualification
from tools.validate_cpp_owned import EXAMPLE, cases, qualify_cpp_owned, validate_report
from tests.test_cpp_owned_source_replay import forge_unrelated_safe_projection

CLANGXX = os.environ.get("CLANGXX", "clang++")
CLANG = shutil.which(CLANGXX)
NATIVE = CLANG and shutil.which("gcc") and shutil.which("g++") and shutil.which(os.environ.get("RUSTC", "rustc"))


@unittest.skipUnless(CLANG, "owned migration requires native Clang 20+")
class CppOwnedMigrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-cpp-owned-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = (EXAMPLE / "owned_bytes.cpp").read_text()

    def migrate(self, source=None, label="candidate"):
        original, output = self.root / (label + ".cpp"), self.root / (label + ".hepta")
        original.write_text(self.source if source is None else source)
        return migrate_cpp_owned(original, output, clangxx=CLANGXX), output

    def test_complete_nontrivial_owner_and_lifecycle_really_become_hepta(self):
        report, output = self.migrate()
        self.assertTrue(report["ok"], report)
        self.assertEqual(output.read_text(), (EXAMPLE / "expected.hepta").read_text())
        self.assertTrue(report["selected_resource_raii_translated"])
        self.assertTrue(report["lifecycle_early_exits_translated"])
        self.assertFalse(report["native_traits"]["trivially_destructible"])
        self.assertFalse(report["native_traits"]["copy_constructible"])
        self.assertTrue(report["native_traits"]["nothrow_move_constructible"])
        self.assertEqual(report["source_declarations"], 2)
        self.assertEqual(report["converted_source_declarations"], 2)
        self.assertEqual(len(report["declaration_inventory"]), 15)
        self.assertEqual(report["unconverted_members"], [])
        self.assertEqual(report["complete_ast_sha256"], report["protocol_ast_sha256"])
        self.assertTrue(report["resource_verification"]["ok"])
        self.assertEqual(report["resource_ir"]["obligations"], {})
        self.assertNotIn('extern "C"', output.read_text())
        self.assertNotIn("unsafe", output.read_text())
        self.assertFalse(report["whole_cpp_raii_supported"])
        self.assertFalse(report["source_equivalence_proved"])
        self.assertFalse(report["foreign_cpp_implementation_retained"])
        self.assertEqual(report["native_execution"], "not_run")

    def test_names_are_bound_by_declaration_identity_not_required_spelling(self):
        renames = {"OwnedBytes": "Arena", "run_owned": "exercise", "data_": "storage", "size_": "extent",
                   "size": "count", "first": "original", "second": "moved", "borrowed": "viewed",
                   "index": "offset", "value": "byte", "code": "problem", "data": "view",
                   "fill": "paint", "get": "at", "set": "write", "reject_constructor": "fail_ctor", "early": "stop"}
        source = re.sub(r"\b[A-Za-z_][A-Za-z0-9_]*\b", lambda word: renames.get(word[0], word[0]), self.source)
        report, output = self.migrate(source)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["class_name"], "Arena")
        self.assertEqual(report["lifecycle_function"], "exercise")
        self.assertIn("pub struct Arena", output.read_text())
        self.assertIn("pub fn exercise", output.read_text())
        self.assertEqual(report["declaration_inventory"][1]["name"], "storage")
        self.assertEqual(report["declaration_inventory"][10]["name"], "count")

    def test_any_unmatched_body_side_effect_or_ownership_protocol_is_rejected(self):
        source = self.source
        cases = {
            "destructor_leak": source.replace("~OwnedBytes() noexcept { delete[] data_; }", "~OwnedBytes() noexcept {}"),
            "wrong_scalar_delete": source.replace("delete[] data_;", "delete data_;"),
            "constructor_failure_leak": source.replace("            delete[] data_;", "            (void)data_;", 1),
            "different_constructor_error": source.replace("throw 2;", "throw 3;"),
            "uninitialized_allocation": source.replace("new unsigned char[size]{}", "new unsigned char[size]"),
            "wrong_allocation_extent": source.replace("new unsigned char[size]{}", "new unsigned char[size + 1]{}"),
            "zero_allocates": source.replace("size == 0 ? nullptr : new unsigned char[size]{}", "new unsigned char[size]{}"),
            "move_leaves_pointer_alias": source.replace("other.data_ = nullptr;", "(void)other.data_;"),
            "move_leaves_extent": source.replace("other.size_ = 0;", "(void)other.size_;"),
            "move_allocates": source.replace("data_(other.data_), size_(other.size_)", "data_(new unsigned char[other.size_]{}), size_(other.size_)"),
            "move_can_throw": source.replace("OwnedBytes(OwnedBytes&& other) noexcept", "OwnedBytes(OwnedBytes&& other)"),
            "copy_enabled": source.replace("OwnedBytes(const OwnedBytes&) = delete;", "OwnedBytes(const OwnedBytes&) = default;"),
            "copy_assignment_enabled": source.replace("operator=(const OwnedBytes&) = delete", "operator=(const OwnedBytes&) = default"),
            "wrong_extent_read": source.replace("return size_;", "return size_ + 1;"),
            "wrong_borrow_origin": source.replace("return data_;", "return data_ + 1;"),
            "wrong_read_index": source.replace("return data_[index];", "return data_[index + 1];"),
            "wrong_write_value": source.replace("data_[index] = value;", "data_[index] = value + 1;"),
            "out_of_bounds_loop": source.replace("i < size_;", "i <= size_;"),
            "changed_fill_body": source.replace("data_[i] = value;", "data_[i] = 0;"),
            "extra_builtin_side_effect": source.replace("return size_;", "__builtin_trap(); return size_;"),
            "unknown_member": source.replace("unsigned long size_;", "unsigned long size_; int hidden;"),
            "unknown_method": source.replace("public:", "public: bool unknown() const noexcept { return false; }"),
            "hidden_extern": source + '\nextern "C" void hidden();\n',
            "hidden_global": source + "\nint global = 0;\n",
            "preprocessing": "#define MODE 1\n" + source,
            "custom_allocation": source + "\nvoid* operator new[](unsigned long);\n",
            "changed_lifecycle_constant": source.replace("value ^ 90", "value ^ 91"),
            "changed_error_result": source.replace("return 2002;", "return 2004;"),
            "changed_catch": source.replace("return 1001;", "return 0;"),
            "moved_from_observed": source.replace("if (early)", "if (first.size() != 0) { return 9000; } if (early)"),
            "missing_range_guard": source.replace("if (index >= second.size()) { return 2003; }", ""),
            "early_pointer_alias": source.replace("const unsigned char* borrowed = second.data();", "const unsigned char* borrowed = first.data();"),
        }
        for label, mutated in cases.items():
            with self.subTest(rejection=label):
                self.assertNotEqual(mutated, source)
                report, output = self.migrate(mutated, label)
                self.assertFalse(report["ok"], report)
                self.assertTrue(report["diagnostics"])
                self.assertFalse(output.exists())

    def test_existing_output_symlink_and_absent_compiler_cannot_publish(self):
        original = self.root / "source.cpp"
        original.write_text(self.source)
        output = self.root / "keep.hepta"
        output.write_text("keep")
        self.assertFalse(migrate_cpp_owned(original, output, clangxx=CLANGXX)["ok"])
        self.assertEqual(output.read_text(), "keep")
        alias = self.root / "alias.hepta"
        alias.symlink_to(self.root / "absent")
        self.assertFalse(migrate_cpp_owned(original, alias, clangxx=CLANGXX)["ok"])
        self.assertTrue(alias.is_symlink())
        missing = self.root / "missing.hepta"
        rejected = migrate_cpp_owned(original, missing, clangxx="/no/such/clang++")
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["diagnostics"][0]["code"], "E_CPP_OWNED_TOOLCHAIN")
        self.assertFalse(missing.exists())

    def test_source_mutation_after_ast_capture_preserves_rejection(self):
        import hepta.cpp_owned_migrate as migrator
        original, output = self.root / "race.cpp", self.root / "race.hepta"
        original.write_text(self.source)
        run = migrator._run

        def racing(command, **kwargs):
            result = run(command, **kwargs)
            if "-ast-dump=json" in command and command[-1] == str(original):
                original.write_text(self.source + "\nint unconverted;\n")
            return result

        with patch.object(migrator, "_run", side_effect=racing):
            report = migrate_cpp_owned(original, output, clangxx=CLANGXX)
        self.assertFalse(report["ok"], report)
        self.assertEqual(report["diagnostics"][0]["code"], "E_CPP_OWNED_RACE")
        self.assertFalse(output.exists())


@unittest.skipUnless(NATIVE, "owned differential requires Clang20, GCC/G++ and pinned Rust1.90")
class CppOwnedNativeTests(unittest.TestCase):
    def test_original_and_two_backends_run_real_allocation_failure_move_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="hepta-cpp-owned-native-") as temporary:
            report = qualify_cpp_owned(temporary, clangxx=CLANGXX, rustc=os.environ.get("RUSTC"), cc="gcc")
            self.assertTrue(report["ok"], report)
            self.assertTrue(validate_report(report))
            # Exercise the collector's actual payload boundary with the real
            # producer report. Its precise successful status is not "passed".
            self.assertEqual(report["status"], "native_owned_implementation_and_cleanup_qualified")
            with patch("tools.validate_cpp_owned.validate_report", wraps=validate_report) as strict_validator:
                require_collected_qualification("cpp_owned_migration", report)
            strict_validator.assert_called_once_with(report)
            for status in ("passed", "failed", "not_run"):
                candidate = copy.deepcopy(report)
                candidate["status"] = status
                with self.subTest(collector_status=status), self.assertRaisesRegex(ValueError, "Expected evidence status"):
                    require_collected_qualification("cpp_owned_migration", candidate)
            rejected = copy.deepcopy(report)
            rejected["ok"] = False
            with self.assertRaises(ValueError):
                require_collected_qualification("cpp_owned_migration", rejected)
            self.assertEqual(len(cases()), 475)
            expected = {"ok": True, "cases": 475, "observations_fnv64": "76b9c7dcdcefd304",
                        "allocations": 359, "frees": 359, "refusals": 98, "live": 0}
            for row in (report["reference"], *report["backends"].values()):
                self.assertEqual(json.loads(row["execution"]["stdout"]), expected)
            failed = json.loads(report["negative_control"]["execution"]["stdout"])
            self.assertEqual(failed["failure"], "lifecycle")
            self.assertEqual((failed["allocated"], failed["freed"], failed["live"]), (1, 0, 1))

            # A legal abstract graph is insufficient: changing every related
            # hash and self-seal must still fail fresh current-source replay.
            # This is a receipt mutation control, not another native execution.
            unrelated = copy.deepcopy(report)
            forge_unrelated_safe_projection(unrelated["backends"]["c"])
            self.assertTrue(validate_report(unrelated, current_inputs=False))
            with self.assertRaisesRegex(ValueError, "E_CPP_OWNED_SOURCE_GRAPH"):
                validate_report(unrelated)
            with self.assertRaisesRegex(ValueError, "E_CPP_OWNED_SOURCE_GRAPH"):
                require_collected_qualification("cpp_owned_migration", unrelated)

            def false_observation(record):
                row = record["backends"]["c"]["execution"]
                changed = json.loads(row["stdout"])
                changed["allocations"] = 0
                row["stdout"] = json.dumps(changed) + "\n"
                raw = row["stdout"].encode()
                row["stdout_sha256"] = hashlib.sha256(raw).hexdigest()
                # Keep the forged byte/text envelope internally coherent, so
                # this control must reach the actual observation oracle.
                row["stdout_bytes_base64"] = base64.b64encode(raw).decode("ascii")
                row["stdout_bytes_sha256"] = hashlib.sha256(raw).hexdigest()
                row["stdout_bytes"] = len(raw)

            mutations = {
                "bool_native_exit": lambda r: r["backends"]["c"]["execution"].update(returncode=False),
                "missing_input_identity": lambda r: r.update(inputs={}),
                "stale_compiler": lambda r: r.update(hepta_compiler_sha256="0" * 64),
                "general_raii_claim": lambda r: r.update(whole_cpp_raii_supported=True),
                "fake_ast_match": lambda r: r["migration"].update(complete_ast_sha256="0" * 64),
                "missing_member": lambda r: r["migration"].update(unconverted_members=["destructor"]),
                "trivial_owner": lambda r: r["migration"]["native_traits"].update(trivially_destructible=True),
                "missing_frontends": lambda r: r["migration"].update(hepta_checks={}),
                "missing_reference_command": lambda r: r["reference"]["commands"].pop(),
                "changed_reference_link_inputs": lambda r: r["reference"]["commands"][-1]["command"].__setitem__(-3, "different.o"),
                "missing_reference_object": lambda r: r["reference"]["objects"][0].update(bytes=0),
                "wrong_cases": lambda r: r.update(cases_sha256="0" * 64),
                "false_observation": false_observation,
                "native_not_run": lambda r: r["backends"]["c"]["native"].update(status="not_run"),
                "only_checked": lambda r: r["backends"]["rust"]["native"].update(check_only=True),
                "missing_toolchain": lambda r: r["backends"]["c"]["native"].update(toolchain={}),
                "missing_native_flags": lambda r: r["backends"]["rust"]["native"].update(flags=[]),
                "changed_emitted_source": lambda r: r["backends"]["c"].update(emitted_source="int fake;"),
                "changed_harness": lambda r: r["backends"]["c"].update(harness_source="int main(void){return 0;}"),
                "changed_case_header": lambda r: r["backends"]["c"]["case_header"].update(sha256="0" * 64),
                "changed_compiled_source": lambda r: r["backends"]["c"]["compiled_source"].update(sha256="0" * 64),
                "external_cpp_link": lambda r: r["backends"]["c"].update(foreign_cpp_link_inputs=["original.o"]),
                "source_binding_missing": lambda r: r["backends"]["c"]["source_binding"].update(source_binding_verified=False),
                "source_binding_other_graph": lambda r: r["backends"]["c"]["source_binding"]["source_binding"].update(resource_ir_sha256="0" * 64),
                "resource_verdict_not_run": lambda r: r["backends"]["c"]["resource_verification"].update(ok=False),
                "different_executable": lambda r: r["backends"]["c"]["execution"]["command"].__setitem__(0, "another-program"),
                "negative_not_executed": lambda r: r["negative_control"]["execution"].update(returncode=0),
                "negative_unchanged_codegen": lambda r: r["negative_control"].update(compiled_emitted_sha256=r["negative_control"]["emitted_sha256"]),
                "negative_other_harness": lambda r: r["negative_control"].update(harness_source="int main(void){return 3;}"),
            }
            for label, mutate in mutations.items():
                with self.subTest(evidence_mutation=label):
                    candidate = copy.deepcopy(report)
                    mutate(candidate)
                    with self.assertRaises(ValueError):
                        validate_report(candidate)


if __name__ == "__main__":
    unittest.main()
