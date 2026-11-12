"""Permanent source controls for the explicit joint owner dependency boundary.

These tests execute no selected HIA business image. The unchanged original
checker closure assertion remains an independent control in its own module.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import importlib
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta import hia_checker_identity as identity

ORIGINAL_CORE = (
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
)
CURRENT_CORE = ORIGINAL_CORE + ('hia_machine_transport.py',)
EXPLICIT_MECHANISMS = (
    "hia_core_emitter_native.py",
    "hia_core_emitter_selection.py",
    "hia_core_lowering_native.py",
    "hia_core_lowering_selection.py",
    "hia_exception_delivery.py",
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
)
NEW_RESOURCES = (
    'examples/hia_bootstrap/core_emitter.hiaasm',
    'examples/hia_bootstrap/native_byte_abi.hiaasm',
    'examples/hia_bootstrap/native_build.hiaasm',
    'examples/hia_bootstrap/service_verification.hiaasm',
    'examples/hia_bootstrap/proof_contract.hiaasm',
)
NEW_HELPERS = {
    'HEPTA_HIA_PROOF_CONTRACT_MANIFEST': ('hia_proof_contract_native', 'NativeProofContractImage'),
    'HEPTA_HIA_CORE_EMITTER_MANIFEST': ('hia_core_emitter_native', 'NativeCoreEmitter'),
    'HEPTA_HIA_NATIVE_BYTE_ABI_MANIFEST': ('hia_native_byte_abi_native', 'NativeByteABI'),
    'HEPTA_HIA_NATIVE_BUILD_MANIFEST': ('hia_native_build_native', 'NativeBuild'),
    'HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST': ('hia_service_verification_native', 'NativeVerificationImage'),
}
ROOT = Path(__file__).resolve().parents[1]


class JointOwnerIntegrationSourceTests(unittest.TestCase):
    def test_exact_original_core_and_all_mechanisms_remain_fresh_sorted_inputs(self):
        self.assertEqual(identity.CORE_SOURCE_FILES, CURRENT_CORE)
        self.assertEqual(identity.MECHANISM_SOURCE_FILES, EXPLICIT_MECHANISMS)
        self.assertFalse(set(CURRENT_CORE) & set(EXPLICIT_MECHANISMS))
        expected = sorted(set(CURRENT_CORE) | set(EXPLICIT_MECHANISMS))
        self.assertEqual(len(expected), 67)
        root = Path(identity.__file__).parent
        original = Path.read_bytes
        observed = []
        def read(path):
            observed.append(path)
            return original(path)
        with patch.object(Path, 'read_bytes', read):
            before = identity.checker_source_identity()
            after = identity.checker_source_identity()
        self.assertEqual(observed, [root / name for name in expected] * 2)
        self.assertEqual(before, after)
        self.assertEqual(list(before), expected)
        self.assertEqual(before, {name: sha256(original(root / name)).hexdigest()
                                  for name in expected})

    def test_each_mechanism_drift_and_first_missing_file_are_not_cached_or_skipped(self):
        original = Path.read_bytes
        baseline = identity.checker_source_identity()
        root = Path(identity.__file__).parent
        for name in EXPLICIT_MECHANISMS:
            with self.subTest(source=name):
                def changed(path):
                    raw = original(path)
                    return raw + b'\n# controlled mechanism drift\n' if path == root / name else raw
                with patch.object(Path, 'read_bytes', changed):
                    actual = identity.checker_source_identity()
                self.assertEqual(set(actual), set(baseline))
                self.assertEqual([key for key in actual if actual[key] != baseline[key]], [name])
        target = EXPLICIT_MECHANISMS[len(EXPLICIT_MECHANISMS) // 2]
        calls = []
        fault = FileNotFoundError('controlled mechanism source missing')
        def missing(path):
            calls.append(path.name)
            if path == root / target:
                raise fault
            return original(path)
        with patch.object(Path, 'read_bytes', missing):
            with self.assertRaises(FileNotFoundError) as caught:
                identity.checker_source_identity()
        self.assertIs(caught.exception, fault)
        ordered = sorted(baseline)
        self.assertEqual(calls, ordered[:ordered.index(target) + 1])

    def test_held_services_and_captured_backend_capabilities_keep_distinct_entries(self):
        from hepta.hia_native_helpers import HELPERS
        for key, expected in NEW_HELPERS.items():
            self.assertEqual(HELPERS[key], expected)
        for key in ('HEPTA_HIA_SERVICE_CONTEXT_MANIFEST',
                    'HEPTA_HIA_SERVICE_EMISSION_MANIFEST',
                    'HEPTA_HIA_SERVICE_VERIFICATION_MANIFEST',
                    'HEPTA_HIA_PROOF_CONTRACT_MANIFEST'):
            self.assertIn(key, identity.HELD_NATIVE_OWNERS)
            self.assertNotIn(key, identity.NATIVE_OWNERS)
            self.assertNotIn(key, identity.CAPTURED_NATIVE_OWNERS)
        for key in ('HEPTA_HIA_CORE_LOWERING_MANIFEST', 'HEPTA_HIA_MACHINE_PLAN_MANIFEST',
                    'HEPTA_HIA_CORE_EMITTER_MANIFEST', 'HEPTA_HIA_NATIVE_BYTE_ABI_MANIFEST',
                    'HEPTA_HIA_NATIVE_BUILD_MANIFEST'):
            self.assertIn(key, identity.NATIVE_OWNERS)
            self.assertIn(key, identity.CAPTURED_NATIVE_OWNERS)
            self.assertNotIn(key, identity.HELD_NATIVE_OWNERS)

    def test_resource_and_complete_source_inventories_cover_each_new_owner(self):
        from hepta.hia_agent_contract import (DISCOVERY_FILES, NATIVE_SOURCE_FILES,
            PUBLICATION_BUILD_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES)
        from tools.hia_selfhost_contract import file_digests
        resources = (*NATIVE_SOURCE_FILES, *PUBLICATION_BUILD_FILES,
                     *SOURCE_BUILD_FILES, *COMPILER_BUILD_FILES)
        self.assertEqual(len(resources), len(set(resources)))
        self.assertTrue(DISCOVERY_FILES)
        declared = file_digests()
        manifest = (ROOT / 'MANIFEST.in').read_text().splitlines()
        for name in NEW_RESOURCES:
            with self.subTest(resource=name):
                self.assertIn(name, NATIVE_SOURCE_FILES)
                self.assertIn(name, declared)
                self.assertIn('include ' + name, manifest)
                self.assertEqual(declared[name], sha256((ROOT / name).read_bytes()).hexdigest())
        from tools.build_hia_service_verification import REQUIRED_SOURCE_NAMES
        replay = 'tests/test_hia_service_verification_default_replay.py'
        self.assertIn(replay, REQUIRED_SOURCE_NAMES)
        self.assertIn(replay, declared)
        self.assertIn('tests/test_hia_joint_owner_integration.py', declared)

    def test_physical_arena_dependency_is_an_exclusive_core_member(self):
        self.assertIn('hia_machine_transport.py', identity.CORE_SOURCE_FILES)
        self.assertNotIn('hia_machine_transport.py', identity.MECHANISM_SOURCE_FILES)
        self.assertEqual(identity.CORE_SOURCE_FILES, CURRENT_CORE)
        root = ROOT / 'hepta'
        arena = ast.parse((root / 'hia_machine_transport.py').read_bytes())
        self.assertFalse(any(isinstance(node, ast.ImportFrom) and node.level
                             for node in ast.walk(arena)))
        call = ast.parse((root / 'hia_call_primitive_native.py').read_bytes())
        self.assertTrue(any(isinstance(node, ast.ImportFrom) and node.level == 1
                            and node.module == 'hia_machine_transport'
                            and any(alias.name == '_private_zeroed_buffer' for alias in node.names)
                            for node in ast.walk(call)))
        self.assertIs(identity.CHECKER_MECHANISM_SOURCE_FILES, identity.MECHANISM_SOURCE_FILES)

    def test_every_required_cold_builder_input_is_in_the_actual_fresh_closure(self):
        from tools.hia_selfhost_contract import file_digests
        declared = file_digests()
        inventories = {}
        for path in sorted((ROOT / 'tools').glob('build_hia_*.py')):
            tree = ast.parse(path.read_bytes())
            names = {target.id for node in tree.body if isinstance(node, ast.Assign)
                     for target in node.targets if isinstance(target, ast.Name)}
            for name in sorted(names & {'REQUIRED_SOURCE_NAMES', 'OWNED_SOURCE_FILES'}):
                inventories[path.stem, name] = path
        expected = {
            ('build_hia_machine_elf', 'OWNED_SOURCE_FILES'),
            ('build_hia_native_build', 'REQUIRED_SOURCE_NAMES'),
            ('build_hia_native_byte_abi', 'REQUIRED_SOURCE_NAMES'),
            ('build_hia_program_normalization', 'REQUIRED_SOURCE_NAMES'),
            ('build_hia_proof_contract', 'REQUIRED_SOURCE_NAMES'),
            ('build_hia_service_context', 'REQUIRED_SOURCE_NAMES'),
            ('build_hia_service_emission', 'REQUIRED_SOURCE_NAMES'),
            ('build_hia_service_verification', 'REQUIRED_SOURCE_NAMES'),
            ('build_hia_source_admission', 'REQUIRED_SOURCE_NAMES'),
        }
        self.assertEqual(set(inventories), expected)
        for module_name, inventory in sorted(inventories):
            builder = importlib.import_module('tools.' + module_name)
            names = getattr(builder, inventory)
            self.assertIs(type(names), tuple)
            self.assertTrue(names)
            self.assertEqual(len(names), len(set(names)))
            for name in names:
                with self.subTest(builder=module_name, inventory=inventory, source=name):
                    self.assertIs(type(name), str)
                    self.assertIn(name, declared)
                    self.assertEqual(declared[name], sha256((ROOT / name).read_bytes()).hexdigest())
