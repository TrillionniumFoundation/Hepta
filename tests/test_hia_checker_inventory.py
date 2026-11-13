"""Source custody and real CPython import-template controls.

No HIA program, compiler, business entry, installed wheel or cold gate is run.
The original checker and front test modules remain independently required.
"""
from __future__ import annotations

from contextlib import ExitStack
from hashlib import sha256
import os
from pathlib import Path
from types import FunctionType
import unittest
from unittest.mock import patch

from hepta import hia_checker_identity as identity
from tools import generate_hia_checker_inventory as inventory

ROOT = Path(__file__).resolve().parents[1]

LEGACY_SEMANTIC_CORE = (
    "hia_front_continuation.py",
    "hia_front_runtime.py",
    "hia_front_selection.py",
    "hia_core_verification_native.py",
    "hia_core_verification_ports.py",
    "hia_core_verification_selection.py",
    "hia_exception_delivery.py",
    "hia_checker_identity.py",
    "hia_native_helpers.py",
    "hia_program.py",
    "hia_program_composite.py",
    "hia_capability_flow.py",
    "hia_opcodes.py",
    "hia_schema.py",
    "hia_json_preflight.py",
    "hia_json_decode.py",
    "hia_json_preflight_native.py",
    "hia_json_decode_native.py",
    "hia_json_canonical_native.py",
    "hia_sha256_native.py",
    "hia_sha256_stream_native.py",
    "hia_function_shape_native.py",
    "hia_program_shape_native.py",
    "hia_instruction_policy_native.py",
    "hia_core_admission_native.py",
    "hia_capability_renaming_native.py",
    "hia_composite_types_native.py",
    "hia_task_helpers_native.py",
    "hia_composite_functions_native.py",
    "hia_composite_functions_errors.py",
    "hia_composite_function_tokens.py",
    "hia_composite_constructor_native.py",
    "hia_composite_constructor_errors.py",
    "hia_composite_outer_native.py",
    "hia_native_value_graph.py",
    "hia_nominal_admission_native.py",
    "hia_nominal_function_native.py",
    "hia_nominal_module_native.py",
    "hia_nominal_terminators_native.py",
    "hia_call_primitive_native.py",
    "hia_record_transitions_native.py",
    "hia_record_operations_native.py",
    "hia_enum_operations_native.py",
    "hia_enum_match_native.py",
    "hia_task_operations_native.py",
    "hia_task_helper_cache_native.py",
    "hia_program_execution_native.py",
    "hia_static_budget.py",
    "hia_static_budget_native.py",
    "hia_heap_bound.py",
    "hia_heap_bound_native.py",
    "hia_heap_live_native.py",
    "hia_heap_payload_native.py",
    "hia_machine_transport.py",
)
LEGACY_MECHANISM_ROLES = (
    "hia_agent_assembly.py",
    "hia_assembly_front_native.py",
    "hia_assembly_front_ports.py",
    "hia_assembly_front_selection.py",
    "hia_service_requests_native.py",
    "hia_service_requests_foreign.py",
    "hia_core_emitter_native.py",
    "hia_core_emitter_selection.py",
    "hia_core_lowering_native.py",
    "hia_core_lowering_selection.py",
    "hia_machine_plan.py",
    "hia_machine_plan_control_native.py",
    "hia_machine_plan_native.py",
    "hia_native_build_foreign.py",
    "hia_native_build_native.py",
    "hia_native_build_selection.py",
    "hia_native_byte_abi.py",
    "hia_native_byte_abi_native.py",
    "hia_native_byte_abi_foreign.py",
    "hia_native_byte_abi_selection.py",
    "hia_proof_contract_foreign.py",
    "hia_proof_contract_native.py",
    "hia_proof_contract_selection.py",
    "hia_service_verification_foreign.py",
    "hia_service_verification_native.py",
    "hia_service_artifacts_native.py",
    "hia_service_artifacts_foreign.py",
    "hia_service_evaluation_native.py",
    "hia_service_evaluation_foreign.py",
)


class CheckerInventorySourceTests(unittest.TestCase):
    def test_complete_fixed_point_preserves_semantic_roles_and_real_registry_targets(self):
        actual = inventory.check(ROOT)
        self.assertEqual(identity.SEMANTIC_CORE_SOURCE_FILES, LEGACY_SEMANTIC_CORE)
        self.assertEqual(identity.MECHANISM_SOURCE_FILES[:len(LEGACY_MECHANISM_ROLES)],
                         LEGACY_MECHANISM_ROLES)
        self.assertEqual(identity.CORE_SOURCE_FILES, actual["names"])
        self.assertEqual(identity.CHECKER_IMPORT_EDGES, actual["edges"])
        self.assertEqual(identity.CHECKER_SOURCE_ROLES, actual["roles"])
        self.assertEqual(identity.CHECKER_SELECTOR_ROLES, actual["selector_roles"])
        self.assertEqual(identity.CHECKER_SELECTOR_OCCURRENCES, actual["selector_occurrences"])
        self.assertEqual(identity.CHECKER_EXTERNAL_IMPORTS, actual["external_imports"])
        self.assertEqual(identity.CHECKER_DYNAMIC_IMPORTS, actual["dynamic_imports"])
        templates = [edge for edge in actual["edges"] if edge[-1] == "reviewed-opcode-template"]
        self.assertEqual(len(templates), 3)
        self.assertEqual({edge[1] for edge in templates}, set(inventory.REVIEWED_IMPORTS["templates"]))
        for source, field, target, aliases in actual["registry_targets"]:
            self.assertIn((source, field, 0, target[:-3], aliases, target,
                           "registry-bound-target"), actual["edges"])
            self.assertIn(target, actual["names"])
        self.assertEqual({target for _source, target, _aliases in actual["actual_template_targets"]},
                         {"hia_machine_plan.py", "hia_native_byte_abi.py",
                          "hia_program.py", "hia_program_native.py"})

    def test_actual_proof_solver_import_is_recorded_as_hosted_not_a_registry(self):
        import ast
        consumers = (
            ("hia_proof_contract.py", "_safe_core_method_reference"),
            ("hia_safe_core.py", "validate_safe_core_artifact"),
            ("hia_translation_validation.py", "_z3_module"),
        )
        shape = ast.dump(ast.parse('importlib.import_module("z3")', mode="eval").body,
                         include_attributes=False)
        actual = inventory.checked_inventory(ROOT)
        for filename, scope in consumers:
            path = ROOT / "hepta" / filename
            with self.subTest(source=filename, scope=scope):
                records = inventory._dynamic_imports(ast.parse(path.read_bytes()), filename)
                record = (filename, scope, shape, "hosted-literal-provider:z3")
                self.assertEqual(records.count(record), 1)
                self.assertNotIn((filename, scope, shape, "finite-reviewed-registry"), records)
                self.assertIn(record, actual["dynamic_imports"])
                self.assertIn((filename, scope, "dynamic", "z3", ()),
                              actual["external_imports"])
        self.assertNotIn("z3.py", actual["names"])

    def test_solver_import_review_rejects_changed_scope_target_and_call_shape(self):
        import ast
        consumers = (
            ("hia_proof_contract.py", "_safe_core_method_reference"),
            ("hia_safe_core.py", "validate_safe_core_artifact"),
            ("hia_translation_validation.py", "_z3_module"),
        )
        call = b'importlib.import_module("z3")'
        for filename, scope in consumers:
            target = ROOT / "hepta" / filename
            raw = target.read_bytes()
            self.assertEqual(raw.count(call), 1)
            mutations = (
                (call, b'importlib.import_module("unreviewed_solver")'),
                (call, b'importlib.import_module(solver_name)'),
                (call, b'importlib.import_module(name="z3")'),
                (call, b'importlib.import_module("z3", __package__)'),
                (call, b'other_importer.import_module("z3")'),
                (("def " + scope + "(").encode(), b'def unreviewed_solver_scope('),
            )
            for before, after in mutations:
                with self.subTest(source=filename, replacement=after):
                    self.assertEqual(raw.count(before), 1)
                    with self.assertRaisesRegex(ValueError, "unreviewed dynamic import mechanism"):
                        inventory._dynamic_imports(ast.parse(raw.replace(before, after, 1)), filename)
            with self.subTest(source=filename, other_source=True):
                with self.assertRaisesRegex(ValueError, "unreviewed dynamic import mechanism"):
                    inventory._dynamic_imports(ast.parse(raw), "unreviewed_proof_consumer.py")

    def test_fresh_identity_keeps_sorted_read_order_and_reads_each_path_again(self):
        expected = sorted(set(identity.CORE_SOURCE_FILES) | set(identity.MECHANISM_SOURCE_FILES))
        original = Path.read_bytes
        calls = []
        generation = 0
        def read(path):
            nonlocal generation
            raw = original(path)
            calls.append(path.name)
            return raw + b"\n# source drift observed in this call\n" if (
                generation and path.name == "hia_schema.py") else raw
        with patch.object(Path, "read_bytes", read):
            first = identity.checker_source_identity()
            generation = 1
            second = identity.checker_source_identity()
        self.assertEqual(calls, expected + expected)
        self.assertEqual(list(first), expected)
        self.assertEqual(list(second), expected)
        self.assertNotEqual(first["hia_schema.py"], second["hia_schema.py"])
        self.assertEqual({key: value for key, value in first.items() if key != "hia_schema.py"},
                         {key: value for key, value in second.items() if key != "hia_schema.py"})

    def test_unlisted_relative_import_is_not_ignored(self):
        original = Path.read_bytes
        def changed(path):
            raw = original(path)
            return raw + b"\nfrom .hia_inventory_missing_input import observe\n" if path.name == "hia_schema.py" else raw
        with patch.object(Path, "read_bytes", changed):
            with self.assertRaisesRegex(ValueError, "physical dependency is missing"):
                inventory.checked_inventory(ROOT)

    def test_placeholder_name_is_only_allowed_in_three_original_templates(self):
        original = Path.read_bytes
        def changed(path):
            raw = original(path)
            return raw + b"\nfrom ._module import _member\n" if path.name == "hia_schema.py" else raw
        with patch.object(Path, "read_bytes", changed):
            with self.assertRaisesRegex(ValueError, "unreviewed synthetic import"):
                inventory.checked_inventory(ROOT)

    def test_changed_template_adapter_or_bound_policy_requires_new_review(self):
        original = Path.read_bytes
        for relative in ("hepta/hia_host_import.py", *inventory.REVIEWED_IMPORTS["authoring_files"]):
            target = ROOT / relative
            def changed(path):
                raw = original(path)
                return raw + b"\n# changed reviewed import input\n" if path == target else raw
            with self.subTest(path=relative), patch.object(Path, "read_bytes", changed):
                with self.assertRaisesRegex(ValueError, "reviewed"):
                    inventory.validate_host_import_templates(ROOT)

    def test_unknown_selector_literal_cannot_become_a_claimed_native_owner(self):
        original = Path.read_bytes
        def changed(path):
            raw = original(path)
            return raw + b"\nUNREVIEWED = 'HEPTA_HIA_UNREVIEWED_INVENTORY_MANIFEST'\n" if path.name == "hia_schema.py" else raw
        with patch.object(Path, "read_bytes", changed):
            with self.assertRaisesRegex(ValueError, "unreviewed checker dependency selector"):
                inventory.checked_inventory(ROOT)

    def test_missing_literal_factory_target_is_a_missing_dependency(self):
        original = Path.read_bytes
        target = b'"hia_worker_request_native"'
        self.assertIn(target, original(ROOT / "hepta/hia_native_helpers.py"))
        def changed(path):
            raw = original(path)
            return raw.replace(target, b'"hia_inventory_missing_factory"', 1) if path.name == "hia_native_helpers.py" else raw
        with patch.object(Path, "read_bytes", changed):
            with self.assertRaisesRegex(ValueError, "literal registry target is missing"):
                inventory.checked_inventory(ROOT)

    def test_removing_recorded_edges_cannot_pass_the_exact_inventory_check(self):
        original = Path.read_text
        path = ROOT / "hepta/hia_checker_identity.py"
        text = original(path)
        first = text.index("CHECKER_IMPORT_EDGES =")
        last = text.index("CHECKER_SOURCE_ROLES =", first)
        changed = text[:first] + "CHECKER_IMPORT_EDGES = ()\n" + text[last:]
        self.assertNotEqual(changed, text)
        def read(value, *args, **kwargs):
            return changed if value == path else original(value, *args, **kwargs)
        with patch.object(Path, "read_text", read):
            with self.assertRaisesRegex(ValueError, "custody inventory is stale"):
                inventory.check(ROOT)

    def test_serialized_identities_and_provider_declarations_are_not_capabilities(self):
        fake = {"manifest_sha256": "a" * 64, "images": {}, "sources": {}}
        for selector in (*identity.NATIVE_OWNERS, *identity.HELD_NATIVE_OWNERS):
            with self.subTest(selector=selector):
                with self.assertRaises(ValueError):
                    identity.require_bound_checker_owner(selector, fake)
        for selector, role in identity.CHECKER_SELECTOR_ROLES.items():
            if role not in ("semantic-checker-owner", "held-semantic-checker-owner"):
                with self.subTest(provider=selector):
                    with self.assertRaisesRegex(ValueError, "outside the checker's semantic"):
                        identity.require_bound_checker_owner(selector, fake)

    def test_published_empty_selector_refusal_precedes_image_admission(self):
        clean = {key: value for key, value in os.environ.items()
                 if not (key.startswith("HEPTA_HIA_") and key.endswith("_MANIFEST"))}
        for selector in identity.STRICT_EMPTY_NATIVE_SELECTORS:
            with self.subTest(selector=selector), patch.dict(os.environ, clean, clear=True), \
                    patch.dict(os.environ, {selector: ""}), \
                    patch.object(identity, "_manifest_bytes", side_effect=AssertionError("read selected manifest")), \
                    patch.object(identity, "_admit_bundle", side_effect=AssertionError("admitted selected bundle")):
                with self.assertRaisesRegex(ValueError, "selector must not be empty"):
                    identity.checker_native_selection()

    def test_explicit_absent_family_masks_ambient_both_and_never_admits(self):
        from hepta.hia_backend_family_selection import (
            lowering_family, emitter_family, plan_family, elf_family)
        clean = {key: value for key, value in os.environ.items()
                 if not (key.startswith("HEPTA_HIA_") and key.endswith("_MANIFEST"))}
        for family in (lowering_family, emitter_family, plan_family, elf_family):
            main, control = family._modules()
            with self.subTest(family=family.name), patch.dict(os.environ, clean, clear=True), ExitStack() as stack:
                old_main, old_control = main._OWNER.get(), control._OWNER.get()
                stack.callback(main._OWNER.set, old_main)
                stack.callback(control._OWNER.set, old_control)
                main._OWNER.set(None)
                control._OWNER.set(None)
                stack.enter_context(patch.dict(os.environ, {
                    family.bundle_selector: "/unread-main",
                    family.control_selector: "/unread-control"}))
                stack.enter_context(patch.object(identity, "_manifest_bytes",
                    side_effect=AssertionError("captured None read manifest")))
                stack.enter_context(patch.object(identity, "_admit_bundle",
                    side_effect=AssertionError("captured None admitted bundle")))
                with family.scope({}):
                    observed = identity.checker_native_selection()
                    self.assertIsNone(observed[family.bundle_selector])
                    self.assertIsNone(observed[family.control_selector])
                    self.assertEqual(family.observe(), (True, None, None))


def _one_reference():
    from .review_target import alpha
    return alpha


def _three_reference():
    from .review_target import alpha, beta, gamma
    return alpha, beta, gamma


def _five_reference():
    from .review_target import alpha, beta, gamma, delta, epsilon
    return alpha, beta, gamma, delta, epsilon


class CheckerImportTemplateSourceTests(unittest.TestCase):
    def test_actual_single_import_keeps_namespace_hook_fromlist_and_identity(self):
        from hepta.hia_host_import import member_importer
        token = object()
        observations = []
        namespace = {"__name__": "reviewed.consumer", "__package__": "reviewed"}
        class Module:
            alpha = token
        def hook(name, globals, locals, fromlist, level):
            observations.append((name, globals is namespace, tuple(sorted(locals or {})), fromlist, level))
            return Module
        namespace["__builtins__"] = {"__import__": hook}
        reference = FunctionType(_one_reference.__code__, namespace)
        actual = member_importer(namespace, "review_target", "alpha")
        self.assertIs(reference(), token)
        expected = list(observations)
        observations.clear()
        self.assertIs(actual(), token)
        self.assertEqual(observations, expected)
        self.assertEqual(actual.__code__.co_names, ("review_target", "alpha"))
        self.assertEqual(actual.__code__.co_varnames, ("alpha",))

    def test_actual_three_and_five_imports_keep_one_import_and_field_order(self):
        from hepta.hia_host_import import members_importer
        for count, oracle in ((3, _three_reference), (5, _five_reference)):
            names = ("alpha", "beta", "gamma", "delta", "epsilon")[:count]
            values = {name: object() for name in names}
            observations = []
            namespace = {"__name__": "reviewed.consumer", "__package__": "reviewed"}
            class Module:
                def __getattr__(self, name):
                    if name in values:
                        observations.append(("field", name))
                        return values[name]
                    raise AttributeError(name)
            module = Module()
            def hook(name, globals, locals, fromlist, level):
                observations.append(("import", name, globals is namespace, fromlist, level))
                return module
            namespace["__builtins__"] = {"__import__": hook}
            with self.subTest(arity=count):
                expected = FunctionType(oracle.__code__, namespace)()
                reference_trace = list(observations)
                observations.clear()
                actual = members_importer(namespace, "review_target", names)()
                self.assertEqual(observations, reference_trace)
                self.assertEqual(sum(row[0] == "import" for row in observations), 1)
                self.assertEqual(tuple(row[1] for row in observations if row[0] == "field"), names)
                self.assertTrue(all(left is right for left, right in zip(expected, actual)))

    def test_actual_import_error_retains_original_object_and_outer_context(self):
        from hepta.hia_host_import import member_importer
        for in_handler in (False, True):
            outer = LookupError("outer")
            for kind in ("reference", "template"):
                error = ImportError("actual import hook refusal")
                namespace = {"__name__": "reviewed.consumer", "__package__": "reviewed"}
                def hook(*args):
                    raise error
                namespace["__builtins__"] = {"__import__": hook}
                function = (FunctionType(_one_reference.__code__, namespace) if kind == "reference"
                            else member_importer(namespace, "review_target", "alpha"))
                def exercise():
                    try:
                        function()
                    except ImportError as observed:
                        self.assertIs(observed, error)
                        self.assertIs(observed.__context__, outer if in_handler else None)
                    else:
                        self.fail("real import hook error was suppressed")
                with self.subTest(outer=in_handler, kind=kind):
                    if in_handler:
                        try:
                            raise outer
                        except LookupError:
                            exercise()
                    else:
                        exercise()


if __name__ == "__main__":
    unittest.main()
