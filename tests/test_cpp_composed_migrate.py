"""Actual AST algorithms, complete rejection boundaries and native RAII order."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import hepta.cpp_composed_migrate as migrator
from hepta.pipeline import analyze_project
from hepta.resource_ir import verify_resource_ir
from hepta.resource_lowering import lower_resource_ir
from hepta.resource_source import verify_resource_source
import tools.validate_cpp_composed as qualifier
from tools.validate_cpp_owned import _captured_streams

CLANGXX = os.environ.get("CLANGXX", "/usr/lib/llvm-20/bin/clang++")
CLANG = shutil.which(CLANGXX)
NATIVE = CLANG and shutil.which("gcc") and shutil.which("g++") and shutil.which(os.environ.get("RUSTC", "rustc"))


def forge_legal_unrelated_graph(row):
    graph = row["resource_ir"]
    function = next(fn for fn in graph["functions"] if fn["name"].endswith("translated_run"))
    value = next(local["id"] for local in function["locals"] if local["type"] == "u64")
    function["blocks"] = [{"id": function["entry"], "ops": [], "term": {"op": "return", "value": value, "loan": None}}]
    verdict = verify_resource_ir(graph)
    if verdict["ok"] is not True:
        raise AssertionError(verdict)
    row["resource_verification"] = verdict
    binding = row["source_binding"]
    binding["resource_verification"] = copy.deepcopy(verdict)
    binding["source_binding"]["resource_ir_sha256"] = verdict["ir_sha256"]
    seal = {key: value for key, value in binding.items() if key != "sha256"}
    binding["sha256"] = hashlib.sha256(json.dumps(seal, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


@unittest.skipUnless(CLANG, "requires the admitted Clang20+ frontend")
class ComposedMigrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hepta-composed-source-")
        self.addCleanup(temp.cleanup); self.root = Path(temp.name)
        self.source = (qualifier.EXAMPLE / "pair.cpp").read_text()

    def migrate(self, source, label="candidate"):
        original, output = self.root / (label + ".cpp"), self.root / (label + ".hepta")
        original.write_text(source)
        return migrator.migrate_cpp_composed(original, output, clangxx=CLANGXX), output

    def test_three_distinct_implementations_have_complete_declaration_ledgers(self):
        expected = {"pair": (2, 61, 463), "triple": (3, 63, 500), "quad": (4, 64, 537)}
        outputs = set()
        for name, (count, declarations, nodes) in expected.items():
            with self.subTest(name=name):
                source = (qualifier.EXAMPLE / (name + ".cpp")).read_text()
                report, output = self.migrate(source, name)
                self.assertTrue(report["ok"], report.get("diagnostics"))
                rendered = output.read_text(); outputs.add(rendered)
                self.assertEqual(rendered, (qualifier.EXAMPLE / (name + ".hepta")).read_text())
                self.assertEqual((report["resource_count"], report["active_declarations"], report["complete_ast_nodes"]), (count, declarations, nodes))
                self.assertEqual(len(report["declaration_inventory"]), declarations)
                self.assertEqual(report["unconverted_declarations"], [])
                self.assertEqual(report["source_declarations"], report["converted_source_declarations"])
                self.assertEqual(report["composite_lowering"], "declaration_bound_expression_and_control_flow_translation")
                self.assertTrue(report["resource_verification"]["ok"])
                self.assertFalse(report["native_traits"]["trivially_destructible"])
                self.assertFalse(report["foreign_cpp_implementation_retained"])
                self.assertEqual(report["foreign_cpp_calls"], 0)
                self.assertNotIn('extern "C"', rendered)
                self.assertNotIn("unsafe", rendered)
                self.assertEqual(report["native_execution"], "not_run")
        self.assertEqual(len(outputs), 3)

    def test_real_algorithm_changes_translate_instead_of_matching_fixed_composite_ast(self):
        baseline, original = self.migrate(self.source, "original")
        variants = {
            "coefficient": self.source.replace(" * 3ULL", " * 9ULL"),
            "initializer_expression": self.source.replace("left_(left, reject == 1)", "left_(left + 2UL, reject == 1)"),
            "condition": self.source.replace("if (early == 1)", "if (early == 7)"),
            "new_local": self.source.replace("return weighted + right_.get(index)", "const unsigned long long extra = 17ULL;\n        return extra + weighted + right_.get(index)"),
            "handler": self.source.replace("return 1000 +", "return 7000 +").replace("catch (...) { return 1001; }", "catch (...) { return 7001; }"),
            "constructor_error": self.source.replace("throw 3;", "throw 9;"),
        }
        self.assertTrue(baseline["ok"])
        for name, source in variants.items():
            with self.subTest(name=name):
                report, output = self.migrate(source, name)
                self.assertTrue(report["ok"], report.get("diagnostics"))
                self.assertNotEqual(output.read_text(), original.read_text())
                self.assertNotEqual(report["complete_ast_sha256"], baseline["complete_ast_sha256"])

    def test_constructor_source_spelling_order_obeys_actual_field_initialization_order(self):
        original = ": left_(left, reject == 1), right_(right, reject == 2)"
        changed = ": right_(right, reject == 2), left_(left, reject == 1)"
        report, output = self.migrate(self.source.replace(original, changed))
        self.assertTrue(report["ok"], report.get("diagnostics"))
        self.assertEqual(output.read_text(), (qualifier.EXAMPLE / "pair.hepta").read_text())

    def test_declaration_identity_and_hygienic_generated_names(self):
        names = {"OwnedBytes": "Arena", "PairedBytes": "Composite", "run_pair": "apply",
                 "left_": "receiver", "right_": "arg0", "left": "created0", "right": "result1",
                 "value": "caughtcode", "first": "resource0", "second": "resource1", "size": "extent",
                 "data": "view", "fill": "paint", "get": "at", "set": "put"}
        changed = re.sub(r"\b[A-Za-z_][A-Za-z_0-9]*\b", lambda match: names.get(match[0], match[0]), self.source)
        report, output = self.migrate(changed)
        self.assertTrue(report["ok"], report.get("diagnostics"))
        self.assertEqual(output.read_text(), (qualifier.EXAMPLE / "pair.hepta").read_text())
        self.assertEqual(report["source_class"], "Composite")

    def test_unexplained_effects_members_lifetimes_and_cpp_constructs_reject_without_output(self):
        s = self.source
        cases = {
            "unconverted_global": s + "\nint hidden = 7;\n",
            "unconverted_function": s + "\nint hidden() noexcept { return 7; }\n",
            "unconverted_alias": s + "\nusing Extra = int;\n",
            "preprocessor": "#define EXTRA 1\n" + s,
            "extra_member": s.replace("    OwnedBytes left_;", "    int hidden;\n    OwnedBytes left_;"),
            "static_member": s.replace("    OwnedBytes left_;", "    static int hidden;\n    OwnedBytes left_;"),
            "mutable_owner": s.replace("    OwnedBytes left_;", "    mutable OwnedBytes left_;"),
            "owner_reference_field": s.replace("    OwnedBytes left_;", "    OwnedBytes& left_;"),
            "in_class_initializer": s.replace("    OwnedBytes left_;", "    OwnedBytes left_{1, false};"),
            "inheritance": s.replace("class PairedBytes {", "class PairedBytes : public OwnedBytes {"),
            "custom_destructor": s.replace("~PairedBytes() noexcept = default;", "~PairedBytes() noexcept {}"),
            "throwing_destructor": s.replace("~PairedBytes() noexcept = default;", "~PairedBytes() noexcept(false) = default;"),
            "virtual_method": s.replace("    void prepare", "    virtual void prepare"),
            "unmodeled_member_template": s.replace("    void prepare", "    template<class T> void unused(T v) noexcept {}\n    void prepare"),
            "ctor_side_effect": s.replace("if (reject == 3) {", "++reject; if (reject == 3) {"),
            "constructor_error_collision": s.replace("throw 3;", "throw 1;"),
            "constructor_hidden_field_dependency": s.replace("right_(right, reject == 2)", "right_(left_.size(), reject == 2)"),
            "constructor_noexcept": s.replace("unsigned int reject)\n        :", "unsigned int reject) noexcept\n        :"),
            "copyable_owner": s.replace("PairedBytes(const PairedBytes&) = delete;", "PairedBytes(const PairedBytes&) = default;"),
            "assignment_body": s.replace("PairedBytes& operator=(PairedBytes&&) = delete;", "PairedBytes& operator=(PairedBytes&&) { return *this; }"),
            "move_swaps_fields": s.replace("other.left_)), right_(static_cast<OwnedBytes&&>(other.right_)", "other.right_)), right_(static_cast<OwnedBytes&&>(other.left_)"),
            "move_side_effect": s.replace("right_(static_cast<OwnedBytes&&>(other.right_)) {}", "right_(static_cast<OwnedBytes&&>(other.right_)) { left_.fill(9); }"),
            "moved_from_read": s.replace("return second.score(index);", "return first.limit();"),
            "double_move": s.replace("if (early == 2)", "PairedBytes third(static_cast<PairedBytes&&>(first)); if (early == 2)"),
            "owner_alias": s.replace("return second.score(index);", "const PairedBytes& alias = second; return alias.score(index);"),
            "borrow_local": s.replace("const unsigned long long weighted =", "const unsigned char* escaped = left_.data();\n        const unsigned long long weighted ="),
            "borrow_return": s.replace("    void prepare", "    const unsigned char* escape() const noexcept { return left_.data(); }\n    void prepare"),
            "unknown_loop": s.replace("left_.fill(value);", "for (unsigned int j=0; j<1; ++j) { left_.fill(value); }"),
            "argument_side_effect": s.replace("left_.fill(value);", "left_.fill(value++);"),
            "local_assignment": s.replace("left_.fill(value);", "value = 0; left_.fill(value);"),
            "nonconst_scalar_method": s.replace("score(unsigned long index) const noexcept", "score(unsigned long index) noexcept"),
            "parameter_default": s.replace("score(unsigned long index) const", "score(unsigned long index = 0) const"),
            "volatile_scalar": s.replace("const unsigned long long weighted", "volatile unsigned long long weighted"),
            "leaf_leak": s.replace("~OwnedBytes() noexcept { delete[] data_; }", "~OwnedBytes() noexcept {}"),
            "leaf_wrong_extent": s.replace("new unsigned char[size]{}", "new unsigned char[size + 1]{}"),
            "leaf_nonzeroed": s.replace("new unsigned char[size]{}", "new unsigned char[size]"),
            "handler_side_effect": s.replace("catch (int code) {", "catch (int code) { ++code;"),
            "unreachable_statement": s.replace("return second.score(index);", "return second.score(index); second.prepare(value);"),
        }
        self.assertEqual(len(cases), 38)
        for name, source in cases.items():
            with self.subTest(name=name):
                report, output = self.migrate(source, name)
                self.assertFalse(report["ok"], name)
                self.assertTrue(report["diagnostics"], name)
                self.assertFalse(output.exists(), name)

    def test_existing_output_and_symlink_are_preserved(self):
        source = self.root / "source.cpp"; source.write_text(self.source)
        output = self.root / "existing.hepta"; output.write_text("keep me")
        link = self.root / "link.hepta"; link.symlink_to(output)
        for path in (output, link):
            result = migrator.migrate_cpp_composed(source, path, clangxx=CLANGXX)
            self.assertFalse(result["ok"])
            self.assertEqual(output.read_text(), "keep me")
        self.assertTrue(link.is_symlink())

    def test_source_race_rejects_publication(self):
        source, output = self.root / "race.cpp", self.root / "race.hepta"; source.write_text(self.source)
        run = migrator._run
        def racing(command, **kwargs):
            result = run(command, **kwargs)
            if "-ast-dump=json" in command and command[-1] == str(source):
                source.write_text(self.source + "\nint inserted;\n")
            return result
        with patch.object(migrator, "_run", side_effect=racing):
            result = migrator.migrate_cpp_composed(source, output, clangxx=CLANGXX)
        self.assertFalse(result["ok"])
        self.assertEqual(result["diagnostics"][0]["code"], "E_CPP_COMPOSED_RACE")
        self.assertFalse(output.exists())

    def test_source_edit_during_actual_link_withdraws_only_own_publication(self):
        source, output = self.root / "late-source.cpp", self.root / "late-source.hepta"
        source.write_text(self.source)
        link = migrator.os.link
        def edit_and_link(stage, destination):
            source.write_text(self.source + "\nint changed_after_validation;\n")
            return link(stage, destination)
        with patch.object(migrator.os, "link", side_effect=edit_and_link):
            report = migrator.migrate_cpp_composed(source, output, clangxx=CLANGXX)
        self.assertFalse(report["ok"])
        self.assertEqual(report["diagnostics"][0]["code"], "E_CPP_COMPOSED_RACE")
        self.assertFalse(output.exists())

    def test_changed_staging_bytes_cannot_be_reported_as_checked_source(self):
        source, output = self.root / "stage.cpp", self.root / "stage.hepta"
        source.write_text(self.source)
        link = migrator.os.link
        def edit_and_link(stage, destination):
            Path(stage).write_text("unchecked replacement\n")
            return link(stage, destination)
        with patch.object(migrator.os, "link", side_effect=edit_and_link):
            report = migrator.migrate_cpp_composed(source, output, clangxx=CLANGXX)
        self.assertFalse(report["ok"])
        self.assertFalse(output.exists())

    def test_competing_output_replacement_is_preserved_on_publication_failure(self):
        source, output = self.root / "competing.cpp", self.root / "competing.hepta"
        source.write_text(self.source)
        link = migrator.os.link
        def replace_after_link(stage, destination):
            link(stage, destination)
            Path(destination).unlink()
            Path(destination).write_text("independent writer content\n")
        with patch.object(migrator.os, "link", side_effect=replace_after_link):
            report = migrator.migrate_cpp_composed(source, output, clangxx=CLANGXX)
        self.assertFalse(report["ok"])
        self.assertEqual(output.read_text(), "independent writer content\n")


class ComposedReplayAndFailureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hepta-composed-replay-")
        self.addCleanup(temp.cleanup); self.root = Path(temp.name)
        (self.root / "migrated.hepta").write_bytes((qualifier.EXAMPLE / "pair.hepta").read_bytes())
        self.entry = self.root / "consumer.hepta"; self.entry.write_bytes((qualifier.EXAMPLE / "consumer.hepta").read_bytes())

    def row(self, backend):
        checked = analyze_project(self.entry, backend=backend, native=False, crate_type="obj")
        self.assertTrue(checked.report["ok"], checked.report.get("diagnostics"))
        graph = lower_resource_ir(checked.program, checked.checked, project_sha256=checked.project.identity)
        return {"frontend": checked.report, "resource_ir": graph, "resource_verification": verify_resource_ir(graph),
                "source_binding": verify_resource_source(self.entry, graph, native=False),
                "emitted_source": checked.c if backend == "c" else checked.rust}

    def test_legal_self_resealed_graph_still_must_match_real_source(self):
        for backend in ("rust", "c"):
            row = self.row(backend)
            variant = {"entry_source": qualifier._identity(self.entry)}
            report = {"hepta_compiler_sha256": row["frontend"]["compiler_sha256"]}
            qualifier._replay_backend(row, variant, backend, report)
            forge_legal_unrelated_graph(row)
            self.assertTrue(verify_resource_ir(row["resource_ir"])["ok"])
            with self.subTest(backend=backend), self.assertRaisesRegex(ValueError, "E_CPP_COMPOSED_SOURCE_GRAPH"):
                qualifier._replay_backend(row, variant, backend, report)

    def test_changed_codegen_rejects_without_native_execution(self):
        for backend in ("rust", "c"):
            row = self.row(backend); row["emitted_source"] += "\n// changed\n"
            with self.subTest(backend=backend), self.assertRaisesRegex(ValueError, "E_CPP_COMPOSED_SOURCE_CODEGEN"):
                qualifier._replay_backend(row, {"entry_source": qualifier._identity(self.entry)}, backend,
                                          {"hepta_compiler_sha256": row["frontend"]["compiler_sha256"]})

    def test_compile_timeout_preserves_completed_source_graph_and_partial_bytes(self):
        row = {}; timeout = subprocess.TimeoutExpired(["mock-compiler"], 7, output=b"prefix\xff", stderr=b"error\xfe")
        def frontend(entry, **kwargs):
            return analyze_project(entry, native=False, **kwargs)
        with patch.object(qualifier, "analyze_project", side_effect=frontend), patch.object(qualifier, "compile_c", side_effect=timeout):
            with self.assertRaises(subprocess.TimeoutExpired):
                qualifier._build(self.entry, self.root / "failed", "c", qualifier.cases("pair"), row)
        self.assertEqual((row["status"], row["stage"]), ("failed", "native_compile"))
        self.assertTrue(row["frontend"]["ok"])
        self.assertTrue(row["source_binding"]["ok"])
        self.assertTrue(Path(row["compiled_source"]["path"]).is_file())
        self.assertEqual(base64.b64decode(row["failure"]["stdout_bytes_base64"]), b"prefix\xff")
        self.assertEqual(base64.b64decode(row["failure"]["stderr_bytes_base64"]), b"error\xfe")

    @unittest.skipUnless(CLANG, "requires Clang for real migration before mock reference timeout")
    def test_reference_timeout_keeps_migration_and_first_command(self):
        record = {"command": ["mock-reference-compiler"], "returncode": None, "status": "timeout", "timeout_seconds": 1,
                  **_captured_streams(b"reference-prefix\xff", b"diagnostic\xfe")}
        with patch.object(qualifier, "_run", return_value=record):
            report = qualifier.qualify_cpp_composed(self.root / "reference-timeout", clangxx=CLANGXX)
        self.assertFalse(report["ok"])
        variant = report["variants"]["pair"]
        self.assertTrue(variant["migration"]["ok"])
        self.assertEqual(variant["stage"], "reference_build")
        self.assertEqual(variant["reference"]["commands"], [record])
        self.assertNotIn("execution", variant["reference"])


@unittest.skipUnless(NATIVE, "requires Clang20, GCC/G++ and pinned Rust1.90")
class ComposedNativeTests(unittest.TestCase):
    def test_three_actual_cpp_rust_c_programs_fail_allocation_and_preserve_cleanup_order(self):
        with tempfile.TemporaryDirectory(prefix="hepta-composed-native-") as temporary:
            report = qualifier.qualify_cpp_composed(temporary, clangxx=CLANGXX, rustc=os.environ.get("RUSTC"))
            self.assertTrue(report["ok"], report["diagnostics"])
            self.assertTrue(qualifier.validate_report(report, clangxx=CLANGXX))
            expected = {"pair": (437, 401, 196, "79fca1db8d2f0865"),
                        "triple": (613, 796, 307, "857e18f53bf7b178"),
                        "quad": (833, 1409, 423, "6d4d805955152153")}
            for name, (count, allocated, refusals, digest) in expected.items():
                variant = report["variants"][name]
                for row in (variant["reference"], *variant["backends"].values()):
                    observed = json.loads(row["execution"]["stdout"])
                    self.assertEqual(observed, {"ok": True, "cases": count, "observations_fnv64": digest,
                        "allocations": allocated, "frees": allocated, "refusals": refusals, "live": 0})
                for ordinal in range(1, qualifier.VARIANTS[name] + 1):
                    self.assertGreater(variant["case_families"]["allocation_refusal_" + str(ordinal)], 0)
                for mutation, row in variant["negative_controls"].items():
                    self.assertEqual(row["execution"]["returncode"], 3)
                    failure = json.loads(row["execution"]["stdout"])
                    self.assertEqual(failure["live"], qualifier.VARIANTS[name] if mutation == "leak" else 0)
            mutations = {
                "status": lambda r: r.update(status="passed"),
                "broadened_scope": lambda r: r.update(whole_cpp_raii_supported=True),
                "stale_compiler": lambda r: r.update(hepta_compiler_sha256="0" * 64),
                "missing_variant": lambda r: r["variants"].pop("quad"),
                "missing_cases": lambda r: r["variants"]["pair"]["case_families"].pop("allocation_refusal_2"),
                "false_declaration_count": lambda r: r["variants"]["pair"]["migration"].update(active_declarations=True),
                "unexplained_ast_change": lambda r: r["variants"]["pair"]["migration"].update(complete_ast_sha256="0" * 64),
                "unselected_compiler": lambda r: r["variants"]["pair"]["migration"]["target_model"].update(compiler="/bin/true"),
                "reference_exit_bool": lambda r: r["variants"]["pair"]["reference"]["execution"].update(returncode=False),
                "wrong_reference_command": lambda r: r["variants"]["pair"]["reference"]["commands"][0]["command"].append("-fno-exceptions"),
                "reference_tool_identity": lambda r: r["variants"]["pair"]["reference"].update(compiler_driver="/bin/true"),
                "native_not_run": lambda r: r["variants"]["pair"]["backends"]["rust"]["native"].update(status="not_run"),
                "external_cpp_link": lambda r: r["variants"]["pair"]["backends"]["rust"].update(foreign_cpp_link_inputs=["original.o"]),
                "bad_graph_self_resealed": lambda r: forge_legal_unrelated_graph(r["variants"]["pair"]["backends"]["c"]),
                "missing_order_control": lambda r: r["variants"]["pair"]["negative_controls"].pop("destruction_order"),
                "negative_not_executed": lambda r: r["variants"]["pair"]["negative_controls"]["leak"]["execution"].update(returncode=0),
            }
            for name, mutate in mutations.items():
                changed = copy.deepcopy(report); mutate(changed)
                with self.subTest(mutation=name), self.assertRaises(ValueError):
                    qualifier.validate_report(changed, clangxx=CLANGXX)


if __name__ == "__main__":
    unittest.main()
