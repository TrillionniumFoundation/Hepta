"""New patch owner Source controls, separate from its actual Native/VM gates."""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
from types import FunctionType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
ENTRIES = ('_check_patch_interface', 'apply_program_patch')


def retained():
    return json.loads((ROOT / 'tests/fixtures/hia_patch_result_originals.json').read_bytes())


def definitions(text):
    return {node.name: node for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)}


class PatchResultSourceTests(unittest.TestCase):
    def test_two_full_bodies_and_passive_templates_equal_the_retained_originals(self):
        original = retained()
        public = (ROOT / 'hepta/hia_program_tools.py').read_text()
        policy = (ROOT / 'tools/hia_patch_result_policy.py').read_text()
        passive = (ROOT / 'hepta/hia_patch_result_definitions.py').read_text()
        self.assertEqual(tuple(definitions(policy)), ENTRIES)
        for name in ENTRIES:
            for text in (public, policy, passive):
                node = definitions(text)[name]
                self.assertEqual(ast.get_source_segment(text, node) + '\n',
                                 original['original_functions'][name])
        owner = ast.parse((ROOT / 'hepta/hia_patch_result_native.py').read_bytes())
        calls = [node.func for node in ast.walk(owner) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(node, ast.Name) and node.id in ENTRIES for node in calls))

    def test_all_retained_files_source10_source8_cli43_and_engines_are_unchanged(self):
        original = retained()
        for path, row in original['retained_files'].items():
            raw = (ROOT / path).read_bytes()
            self.assertEqual(len(raw), row['bytes'], path)
            self.assertEqual(sha256(raw).hexdigest(), row['sha256'], path)
            if row['test_ids']:
                ids = []
                for cls in ast.parse(raw).body:
                    if isinstance(cls, ast.ClassDef):
                        ids.extend(path[:-3].replace('/', '.') + '.' + cls.name + '.' + node.name
                                   for node in cls.body if isinstance(node, ast.FunctionDef)
                                   and node.name.startswith('test_'))
                self.assertEqual(ids, row['test_ids'], path)
        cli = json.loads((ROOT / 'tests/fixtures/hia_cli_routing_retained.json').read_bytes())
        self.assertEqual(cli['original_ids'], original['original_cli43_ids'])
        self.assertEqual(len(cli['original_ids']), 43)

    def test_code_admission_has_independent_authority_and_rejects_changed_definitions(self):
        from hepta import hia_program_tools as public
        from hepta.hia_patch_result_definitions import capture_definitions
        namespace = vars(public)
        before = dict(namespace)
        records = capture_definitions(namespace)
        self.assertEqual(namespace, before)
        for name in ENTRIES:
            function = before[name]
            self.assertTrue(records[name].current(function))
            alias = FunctionType(function.__code__, namespace)
            self.assertFalse(records[name].current(alias))
            code, defaults, kwdefaults = function.__code__, function.__defaults__, function.__kwdefaults__
            try:
                function.__defaults__ = ()
                self.assertFalse(records[name].current(function))
                with self.assertRaises(ValueError):
                    capture_definitions(namespace)
                function.__defaults__ = defaults
                function.__kwdefaults__ = {}
                self.assertFalse(records[name].current(function))
                with self.assertRaises(ValueError):
                    capture_definitions(namespace)
            finally:
                function.__code__, function.__defaults__, function.__kwdefaults__ = code, defaults, kwdefaults
        with self.assertRaises(AttributeError):
            records['apply_program_patch'].current = lambda value: True

    def test_foreign_namespace_keys_are_rejected_without_running_key_protocols(self):
        from hepta import hia_program_tools as public
        from hepta.hia_patch_result_definitions import capture_definitions
        events = []
        class Key(str):
            def __hash__(self):
                events.append('hash')
                return str.__hash__(self)
            def __eq__(self, other):
                events.append('eq')
                return str.__eq__(self, other)
        copied = dict(vars(public))
        copied[Key('foreign-key')] = object()
        events.clear()
        with self.assertRaises(ValueError):
            capture_definitions(copied)
        self.assertEqual(events, [])

    def test_four_result_unpack_is_the_only_new_finite_shape(self):
        from tools.hia_patch_result_control import Compiler, OPS
        from tools.hia_machine_plan_control import Ref
        owner = object.__new__(Compiler)
        value, outputs = Ref(0), [Ref(index) for index in range(1, 5)]
        row = {'kind': 'effect', 'opcode': OPS['UNPACK'], 'raw': [4],
               'arguments': [value], 'destinations': outputs, 'consume': [value], 'vector': []}
        owner.functions = [SimpleNamespace(instructions=[row], cell_slots=set())]
        owner.literals = []
        owner._validate_calls()
        for change in ({'raw': [5]}, {'destinations': outputs[:3]},
                       {'destinations': [outputs[0]] * 4}, {'arguments': []},
                       {'vector': [value]}, {'consume': []}):
            owner.functions[0].instructions = [{**row, **change}]
            with self.subTest(change=tuple(change)), self.assertRaises(ValueError):
                owner._validate_calls()

    def test_unknown_captured_provider_is_called_once_without_attribute_probes(self):
        from hepta.hia_patch_result_native import NativePatchResult
        owner = object.__new__(NativePatchResult)
        owner._definitions = {}
        owner._import_builtins_match = True
        events, document, request, marker = [], object(), object(), object()
        class Foreign:
            def __getattribute__(self, name):
                raise AssertionError('unexpected foreign attribute: ' + name)
            def __call__(self, *values):
                events.append(values)
                return marker
        provider = Foreign()
        self.assertIs(owner.invoke_bound_apply(provider, document, request), marker)
        self.assertIs(owner.invoke_bound_interface(provider, document, request, marker), marker)
        self.assertEqual(events, [(document, request), (document, request, marker)])
        self.assertFalse(hasattr(owner, '_entry'))

    def test_r3_drive_and_busy_lease_are_mechanically_retained_without_constructor(self):
        current = ast.parse((ROOT / 'hepta/hia_patch_result_native.py').read_bytes())
        prior = ast.parse((ROOT / 'hepta/hia_inspect_program_native.py').read_bytes())
        def methods(tree, name):
            cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name)
            return {node.name: node for node in cls.body if isinstance(node, ast.FunctionDef)}
        new, old = methods(current, 'PatchResultFrame'), methods(prior, 'InspectProgramFrame')
        self.assertNotIn('__init__', new)
        for name in ('_invoke', 'step', 'service', 'drive', 'take', 'close', '_retire'):
            self.assertEqual(ast.dump(new[name], include_attributes=False),
                             ast.dump(old[name], include_attributes=False), name)

    def test_generator_emits_complete_reproducible_core_and_actual_host_pins(self):
        from tools.generate_hia_patch_result import generated, SOURCE_PATH, PORTS_PATH, DATA_PATH
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_patch_result_native import HOST_SOURCE_FILES
        first, second = generated(), generated()
        self.assertEqual(first[:3], second[:3])
        for path, raw in zip((SOURCE_PATH, PORTS_PATH, DATA_PATH), first[:3]):
            self.assertEqual((ROOT / path).read_bytes(), raw)
        checked = assemble_program(first[0]).as_dict()
        self.assertEqual(checked['schema'], 'hepta.hia.program.v8')
        self.assertEqual(checked['module'], 'patch_result')
        self.assertLessEqual(len(checked['functions']), 128)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in checked['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in checked['functions'] for block in fn['blocks']), 8192)
        self.assertLessEqual(len(first[0]), 1048576)
        assignment = {node.targets[0].id: ast.literal_eval(node.value)
                      for node in ast.parse(first[2]).body if isinstance(node, ast.Assign)}
        self.assertEqual(set(assignment['HOST_SOURCE_SHA256']), set(HOST_SOURCE_FILES))
        for name in HOST_SOURCE_FILES:
            self.assertEqual(assignment['HOST_SOURCE_SHA256'][name],
                             sha256((ROOT / 'hepta' / name).read_bytes()).hexdigest())
        self.assertEqual(assignment['SOURCE_SHA256'], sha256(first[0]).hexdigest())

    def test_explicit_manifest_rejects_relative_or_parent_paths_before_native_mapping(self):
        from hepta.hia_patch_result_native import admit_patch_result
        from hepta.hia_front_runtime import NativeFrontImage
        with patch.object(NativeFrontImage, '__init__', side_effect=AssertionError('unexpected mapping')):
            for value in ('manifest.json', '../manifest.json', '/tmp/../manifest.json'):
                with self.subTest(path=value), self.assertRaises(ValueError):
                    admit_patch_result(value)

    def test_signature_dependency_is_never_created_inside_a_policy_or_global_lookup(self):
        tree = ast.parse((ROOT / 'hepta/hia_patch_result_native.py').read_bytes())
        methods = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        for name in ('_global_in', 'definition_current', 'invoke_bound_apply', 'invoke_bound_interface'):
            self.assertFalse(any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(methods[name])))
            self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                                 and node.func.id in ('_admit_signature', 'admit_inspect_program')
                                 for node in ast.walk(methods[name])))
        calls = [node for node in ast.walk(methods['_admit_signature']) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'admit_inspect_program']
        self.assertEqual(len(calls), 1)

    def test_exact_slice_constants_preserve_full_codes_and_reject_unknown_fields(self):
        from hepta import hia_program_tools as public
        from hepta import hia_patch_result_definitions as admitted
        namespace = vars(public)
        records = admitted.capture_definitions(namespace)
        for name in ENTRIES:
            self.assertTrue(records[name].current(namespace[name]))
            self.assertTrue(admitted._code_equal(namespace[name].__code__, admitted.POLICY_CODES[name]))
        code = public._check_patch_interface.__code__
        positions = [index for index, item in enumerate(code.co_consts) if type(item) is slice]
        self.assertTrue(positions, 'actual 3.14 original changed[:8] must contain an exact slice')
        index = positions[0]
        value = code.co_consts[index]
        self.assertIsNone(value.start)
        self.assertEqual(value.stop, 8)
        self.assertIsNone(value.step)
        self.assertTrue(admitted._constant_equal(value, slice(None, 8, None)))
        self.assertTrue(admitted._constant_equal(
            slice((None, 1), slice(2, 3, None), b'x'),
            slice((None, 1), slice(2, 3, None), b'x')))
        for changed in (slice(0, 8, None), slice(None, 9, None), slice(None, 8, 1)):
            with self.subTest(changed_field=(changed.start, changed.stop, changed.step)):
                constants = list(code.co_consts)
                constants[index] = changed
                mutated = code.replace(co_consts=tuple(constants))
                self.assertFalse(admitted._code_equal(mutated, admitted.POLICY_CODES['_check_patch_interface']))
        events = []
        class Unknown:
            def __getattribute__(self, name):
                events.append('attribute')
                raise AssertionError('unknown field attribute protocol ran')
            def __eq__(self, other):
                events.append('equality')
                raise AssertionError('unknown field equality protocol ran')
            def __iter__(self):
                events.append('iteration')
                raise AssertionError('unknown field iteration protocol ran')
            def __repr__(self):
                events.append('representation')
                raise AssertionError('unknown field representation protocol ran')
        foreign = Unknown()
        for position in range(3):
            with self.subTest(unknown_field=position):
                fields = [None, 8, None]
                fields[position] = foreign
                left, right = slice(*fields), slice(*fields)
                self.assertFalse(admitted._constant_equal(left, right))
                self.assertFalse(admitted._constant_equal(left, value))
                self.assertFalse(admitted._constant_equal(value, right))
                constants = list(code.co_consts)
                constants[index] = left
                self.assertFalse(admitted._code_equal(
                    code.replace(co_consts=tuple(constants)), admitted.POLICY_CODES['_check_patch_interface']))
        self.assertFalse(admitted._constant_equal(slice(None, 8.0, None), slice(None, 8.0, None)))
        self.assertEqual(events, [])



if __name__ == '__main__':
    unittest.main()
