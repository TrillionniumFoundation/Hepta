"""Captured constexpr selection preserves template and runtime boundaries."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_migrate import MigrationRejected
from hepta.c_project import capture_project
from hepta.cpp_project_migrate import _lower_cpp_capture, lower_cpp_project
from hepta.hia_program import execute_program
from tools.qualify_cpp_constexpr import qualify_cpp_constexpr, validate_cpp_constexpr_receipt


CLANG = os.environ.get("CLANG") or shutil.which("clang")
CLANGXX = os.environ.get("CLANGXX") or (str(Path(CLANG).with_name("clang++")) if CLANG else None)


class CPPConstexprMigrationTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(CLANG and CLANGXX, "Actual Clang is required")
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-cpp-constexpr-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def database(self, sources, flags=None):
        entries = []
        for name, source in sources.items():
            (self.root / name).write_text(source)
            if name.endswith(".cpp"):
                entries.append({"directory": str(self.root), "file": name,
                                "arguments": ["clang++", "-std=c++20", *(flags or []),
                                              "-c", name, "-o", name + ".o"]})
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps(entries))
        return database

    def test_concrete_type_and_value_parameters_choose_nested_branches(self):
        database = self.database({"input.cpp": '''
template<class T, unsigned Mode> T choose(T value) noexcept {
    if constexpr (sizeof(T) == 4) {
        if constexpr (Mode == 0) { return value + 3; }
        else { return value + 7; }
    } else {
        if constexpr (Mode == 0) { return value + 11; }
        else { return value + 13; }
    }
}
extern "C" unsigned n0(unsigned x) noexcept { return choose<unsigned,0>(x); }
extern "C" unsigned n1(unsigned x) noexcept { return choose<unsigned,1>(x); }
extern "C" unsigned long w0(unsigned long x) noexcept { return choose<unsigned long,0>(x); }
extern "C" unsigned long w1(unsigned long x) noexcept { return choose<unsigned long,1>(x); }
'''})
        migration = lower_cpp_project(database, clangxx=CLANGXX)
        self.assertEqual(len(migration["constexpr_selections"]), 8)
        self.assertTrue(all(row["template_pattern_odr_sha256"] for row in migration["constexpr_selections"]))
        for function, bits, increment in (("n0", 32, 3), ("n1", 32, 7), ("w0", 64, 11), ("w1", 64, 13)):
            for value in (0, 7, (1 << bits) - 1):
                self.assertEqual(execute_program(migration["program"], function, [value])["result"],
                                 (value + increment) % (1 << bits))
        selected_functions = {row["hia_function"] for row in migration["constexpr_selections"]}
        template_functions = [function for function in migration["program"].as_dict()["functions"]
                              if function["name"] in selected_functions]
        self.assertEqual({function["name"] for function in template_functions}, selected_functions)
        # The general c_bool_to_int helper legitimately retains its runtime
        # branch. Only concrete template decisions must disappear here.
        self.assertTrue(all(block["term"]["op"] != "branch"
                            for function in template_functions for block in function["blocks"]))

    def test_false_without_else_and_shadowed_scalar_lifetimes(self):
        database = self.database({"input.cpp": '''
template<unsigned Mode> unsigned choose(unsigned value) noexcept {
    unsigned result = value;
    if constexpr (Mode == 0) { unsigned value = 7; result += value; }
    else { unsigned value = 11; result += value; }
    if constexpr (Mode == 9) { throw 17; }
    return result + value;
}
extern "C" unsigned zero(unsigned value) noexcept { return choose<0>(value); }
extern "C" unsigned one(unsigned value) noexcept { return choose<1>(value); }
'''})
        migration = lower_cpp_project(database, clangxx=CLANGXX)
        self.assertEqual(execute_program(migration["program"], "zero", [10])["result"], 27)
        self.assertEqual(execute_program(migration["program"], "one", [10])["result"], 31)
        none = [row for row in migration["constexpr_selections"] if row["selected_branch"] == "none"]
        self.assertEqual(len(none), 2)
        self.assertTrue(all(row["condition_value"] is False and len(row["discarded_branches"]) == 1 for row in none))

    def test_discarded_object_is_accounted_for_but_selected_object_rejects(self):
        source = '''
template<class T> T choose(T value) noexcept {
    if constexpr (sizeof(T)==4) { return value+3; }
    else {
        struct Resource {
            T& value;
            explicit Resource(T& x) noexcept : value(x) { value += 7; }
            ~Resource() noexcept { value += 9; }
        };
        Resource local(value);
        return value;
    }
}
extern "C" unsigned narrow(unsigned value) noexcept { return choose(value); }
'''
        database = self.database({"input.cpp": source})
        migration = lower_cpp_project(database, clangxx=CLANGXX)
        self.assertEqual(execute_program(migration["program"], "narrow", [5])["result"], 8)
        selection, = migration["constexpr_selections"]
        self.assertEqual(selection["discarded_branches"][0]["branch"], "else")
        self.assertNotIn("Resource", migration["source"])
        self.database({"input.cpp": source + '\nextern "C" unsigned long wide(unsigned long value) noexcept { return choose(value); }\n'})
        with self.assertRaises(MigrationRejected) as caught:
            lower_cpp_project(database, clangxx=CLANGXX)
        self.assertEqual(caught.exception.code, "E_C_LOCAL")

    def test_non_template_constexpr_keeps_return_control_flow(self):
        database = self.database({"input.cpp": '''
extern "C" unsigned direct(unsigned value) noexcept {
    if constexpr (true) { return value + 5; }
    else { return value / (value - value); }
}
extern "C" unsigned fallthrough(unsigned value) noexcept {
    if constexpr (false) { return value / (value - value); }
    return value + 7;
}
'''})
        migration = lower_cpp_project(database, clangxx=CLANGXX)
        self.assertEqual(execute_program(migration["program"], "direct", [0])["result"], 5)
        self.assertEqual(execute_program(migration["program"], "fallthrough", [0])["result"], 7)
        self.assertTrue(all(row["template_pattern_odr_sha256"] is None for row in migration["constexpr_selections"]))
        self.assertTrue(all(operation["op"] != "int.div.checked"
                            for function in migration["program"].as_dict()["functions"]
                            for block in function["blocks"] for operation in block["ops"]))

    def test_full_template_pattern_conflict_in_discarded_branch_rejects(self):
        database = self.database({
            "branch.hpp": '''template<class T> T choose(T value) noexcept {
if constexpr (sizeof(T)==4) { return value+3; } else { return value+UNSELECTED; }
}\n''',
            "one.cpp": '#include "branch.hpp"\nextern "C" unsigned one(unsigned x) noexcept {return choose(x);}\n',
            "two.cpp": '#include "branch.hpp"\nextern "C" unsigned two(unsigned x) noexcept {return choose(x);}\n',
        }, ["-DUNSELECTED=7"])
        migration = lower_cpp_project(database, clangxx=CLANGXX)
        self.assertEqual(execute_program(migration["program"], "two", [5])["result"], 8)
        self.assertTrue(any(row["status"] == "identical_inline_or_template_definition_resolved"
                            for row in migration["declarations"]))
        entries = json.loads(database.read_text())
        entries[1]["arguments"][2] = "-DUNSELECTED=11"
        database.write_text(json.dumps(entries))
        with self.assertRaises(MigrationRejected) as caught:
            lower_cpp_project(database, clangxx=CLANGXX)
        self.assertEqual(caught.exception.code, "E_CPP_PROJECT_ODR")

    def test_constexpr_init_statement_remains_rejected(self):
        database = self.database({"input.cpp": '''
extern "C" unsigned entry(unsigned value) noexcept {
    if constexpr (constexpr unsigned local = 7; local == 7) { return value + local; }
    else { return value; }
}
'''})
        with self.assertRaises(MigrationRejected) as caught:
            lower_cpp_project(database, clangxx=CLANGXX)
        self.assertEqual(caught.exception.code, "E_CPP_PROJECT_CONSTEXPR")

    def test_complete_template_identity_checked_across_distinct_source_files(self):
        pattern = ('template<class T> T choose(T value) noexcept { '
                   'if constexpr (sizeof(T)==4) { return value+3; } '
                   'else { return value+7; } }\n')
        one = pattern + 'extern "C" unsigned one(unsigned value) noexcept {return choose(value);}\n'
        two = pattern + 'extern "C" unsigned two(unsigned value) noexcept {return choose(value);}\n'
        database = self.database({"one.cpp": one, "two.cpp": two})
        migration = lower_cpp_project(database, clangxx=CLANGXX)
        self.assertEqual(execute_program(migration["program"], "one", [5])["result"], 8)
        self.assertEqual(execute_program(migration["program"], "two", [5])["result"], 8)
        self.assertTrue(any(row["status"] == "identical_inline_or_template_definition_resolved"
                            for row in migration["declarations"]))
        # Different file/offset template keys still resolve to the same concrete
        # symbol. Its selected u32 body is identical; the full patterns are not.
        # This source violates the ODR and is not executed as a C++ oracle.
        self.database({"one.cpp": one, "two.cpp": two.replace("return value+7;", "return value+11;")})
        with self.assertRaises(MigrationRejected) as caught:
            lower_cpp_project(database, clangxx=CLANGXX)
        self.assertEqual(caught.exception.code, "E_CPP_PROJECT_ODR")

    def test_missing_or_ambiguous_constant_value_does_not_default_false(self):
        from hepta import cpp_project_migrate
        database = self.database({"input.cpp": 'extern "C" unsigned entry(unsigned x) noexcept { if constexpr (true) {return x+3;} else {return x+7;} }\n'})
        capture = capture_project(database, clang=CLANGXX, language="c++")
        original = cpp_project_migrate.invoke
        changes = [lambda condition: condition.pop("value"),
                   lambda condition: condition.update(value=True),
                   lambda condition: condition.update(value="0"),
                   lambda condition: condition.update(value="unknown"),
                   lambda condition: condition.update(type={"qualType": "int"}),
                   lambda condition: condition.update(kind="ParenExpr"),
                   lambda condition: condition.update(inner=[])]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                def changed_ast(args, directory):
                    raw = original(args, directory)
                    tree = json.loads(raw)
                    stack = [tree]
                    while stack:
                        node = stack.pop()
                        if node.get("kind") == "IfStmt" and node.get("isConstexpr"):
                            change(node["inner"][0])
                        stack.extend(node.get("inner", []))
                    return json.dumps(tree)
                with patch("hepta.cpp_project_migrate.invoke", side_effect=changed_ast):
                    with self.assertRaises(MigrationRejected) as caught:
                        _lower_cpp_capture(capture)
                self.assertEqual(caught.exception.code, "E_CPP_PROJECT_CONSTEXPR")

    def test_discarded_local_class_member_bindings_have_stable_exact_identities(self):
        from hepta import cpp_project_migrate
        database = self.database({
            "branch.hpp": '''template<class T> T choose(T value) noexcept {
if constexpr (sizeof(T)==4) { return value+3; }
else {
    struct Resource {
        T first; T second;
        explicit Resource(T value) noexcept : first(value), second(value) {}
        T read() const noexcept { return first; }
    };
    Resource resource(value);
    return resource.read();
}
}\n''',
            "one.cpp": '#include "branch.hpp"\nextern "C" unsigned one(unsigned x) noexcept {return choose(x);}\n',
            "two.cpp": '#include "branch.hpp"\nextern "C" unsigned two(unsigned x) noexcept {return choose(x);}\n',
        })
        migration = lower_cpp_project(database, clangxx=CLANGXX)
        self.assertEqual(execute_program(migration["program"], "one", [5])["result"], 8)
        self.assertEqual(execute_program(migration["program"], "two", [5])["result"], 8)
        self.assertTrue(any(row["status"] == "identical_inline_or_template_definition_resolved"
                            for row in migration["declarations"]))
        original = cpp_project_migrate.invoke
        altered = []

        def changed_binding(args, directory):
            raw = original(args, directory)
            if args[-1] != "two.cpp":
                return raw
            tree = json.loads(raw)
            nodes = list(cpp_project_migrate._nodes(tree))
            fields = {node["name"]: node["id"] for node in nodes
                      if node.get("kind") == "FieldDecl" and node.get("name") in {"first", "second"}}
            self.assertEqual(set(fields), {"first", "second"})
            for node in nodes:
                if node.get("referencedMemberDecl") == fields["first"]:
                    # Identity-only negative control: changing the declaration
                    # relation must remain visible even when names/types agree.
                    # This is a mutated AST check, not a defined C++ execution.
                    node["referencedMemberDecl"] = fields["second"]
                    altered.append(node["kind"])
            return json.dumps(tree)

        with patch("hepta.cpp_project_migrate.invoke", side_effect=changed_binding):
            with self.assertRaises(MigrationRejected) as caught:
                lower_cpp_project(database, clangxx=CLANGXX)
        self.assertTrue(altered)
        self.assertEqual(caught.exception.code, "E_CPP_PROJECT_ODR")

    def test_captured_configuration_is_rechecked_before_branch_selection(self):
        database = self.database({"input.cpp": 'extern "C" unsigned entry(unsigned x) noexcept {if constexpr (SELECTED) {return x+3;} else {return x+7;}}\n'}, ["-DSELECTED=1"])
        capture = capture_project(database, clang=CLANGXX, language="c++")
        entries = json.loads(database.read_text()); entries[0]["arguments"][2] = "-DSELECTED=0"
        database.write_text(json.dumps(entries))
        with self.assertRaises(MigrationRejected) as caught:
            _lower_cpp_capture(capture)
        self.assertEqual(caught.exception.code, "E_C_BUILD_CHANGED")

    def test_actual_two_unit_native_differential_and_target_link_control(self):
        report = qualify_cpp_constexpr(self.root / "qualification", clang=CLANG, clangxx=CLANGXX)
        self.assertTrue(report["ok"], report.get("diagnostic"))
        self.assertEqual(report["case_count"], 80)
        self.assertEqual(report["native_result_executions"], 160)
        self.assertEqual(len(report["constexpr_selections"]), 13)
        self.assertEqual(sum(len(row["instances"]) for row in report["template_instances"]), 7)
        self.assertFalse(report["claims"]["discarded_object_lifecycle_executed"])
        forged = deepcopy(report)
        forged["processes"][forged["target_link_process"]]["argv"].append(str(self.root / "qualification/original-0.o"))
        with self.assertRaisesRegex(ValueError, "only the directly generated HIA object"):
            validate_cpp_constexpr_receipt(forged)


if __name__ == "__main__":
    unittest.main()
