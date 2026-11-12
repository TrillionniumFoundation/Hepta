"""Source custody and default-import controls for the two distinct front owners.

These tests do not confer native, installed, current-cold, whole JSON or active
interpreter-stack qualification. The original caller suites remain unchanged.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
OWNED = (
    'examples/hia_bootstrap/assembly_front.hiaasm',
    'examples/hia_bootstrap/core_verification.hiaasm',
    'hepta/hia_agent_assembly.py',
    'hepta/hia_assembly_front_native.py',
    'hepta/hia_assembly_front_ports.py',
    'hepta/hia_assembly_front_selection.py',
    'hepta/hia_checker_identity.py',
    'hepta/hia_core_verification_native.py',
    'hepta/hia_core_verification_ports.py',
    'hepta/hia_core_verification_selection.py',
    'hepta/hia_front_continuation.py',
    'hepta/hia_front_runtime.py',
    'hepta/hia_front_selection.py',
    'hepta/hia_native_helpers.py',
    'hepta/hia_program.py',
    'tests/fixtures/hia_front_continuation_r5.py.txt',
    'tools/generate_hia_assembly_front.py',
    'tools/generate_hia_core_verification.py',
    'tools/hia_assembly_front_policy.py',
    'tools/hia_core_verification_policy.py',
    'tools/hia_front_control.py',
    'tools/hia_front_generator.py',
)


class FrontRegistrationSourceTests(unittest.TestCase):
    def test_all_owner_inputs_are_explicit_cold_source_members(self):
        from tools.hia_selfhost_contract import SOURCE_FILES
        self.assertTrue(set(OWNED) <= set(SOURCE_FILES))
        self.assertIn('tests/test_hia_front_registration.py', SOURCE_FILES)
        for name in OWNED:
            self.assertTrue((ROOT / name).is_file(), name)

    def test_two_resources_and_helper_roles_are_distinct(self):
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from hepta.hia_native_helpers import HELPERS
        from hepta.hia_checker_identity import NATIVE_OWNERS, CAPTURED_NATIVE_OWNERS, HELD_NATIVE_OWNERS
        from hepta import hia_core_verification_native as core, hia_assembly_front_native as assembly
        for stem, module, factory in (
            ('core_verification', core, 'NativeCoreVerification'),
            ('assembly_front', assembly, 'NativeAssemblyFront'),
        ):
            with self.subTest(owner=stem):
                name = 'examples/hia_bootstrap/' + stem + '.hiaasm'
                self.assertEqual(NATIVE_SOURCE_FILES.count(name), 1)
                self.assertEqual(module.SOURCE, ROOT / name)
                self.assertEqual(HELPERS[module.SELECTOR], ('hia_' + stem + '_native', factory))
                self.assertIn(module.SELECTOR, NATIVE_OWNERS)
                self.assertIn(module.SELECTOR, CAPTURED_NATIVE_OWNERS)
                self.assertNotIn(module.SELECTOR, HELD_NATIVE_OWNERS)

    def test_core_owner_keeps_assembly_in_the_application_layer(self):
        from hepta import hia_checker_identity as identity
        core = set(identity.CORE_SOURCE_FILES)
        mechanisms = set(identity.MECHANISM_SOURCE_FILES)
        self.assertEqual((len(core), len(mechanisms), len(core | mechanisms)), (54, 25, 79))
        self.assertFalse(core & mechanisms)
        self.assertIn('hia_exception_delivery.py', core)
        self.assertNotIn('hia_agent_assembly.py', core)
        self.assertNotIn('hia_program_tools.py', core)
        self.assertIn('hia_agent_assembly.py', mechanisms)
        self.assertEqual(identity.CHECKER_MECHANISM_EXTERNAL_PROVIDERS['hia_agent_assembly.py'],
                         ('hia_program_tools.py',))
        imports = set()
        for name in core:
            for node in ast.walk(ast.parse((ROOT / 'hepta' / name).read_bytes())):
                if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
                    imports.add(node.module + '.py')
        self.assertEqual(imports - core, {'hia_program_runtime.py'})

    def test_core_and_assembly_generated_bytes_remain_the_qualified_inputs(self):
        from tools import generate_hia_core_verification as core, generate_hia_assembly_front as assembly
        expected = (
            (core, 'core_verification', '2931664bb7af879f48c82bb36e897654ca25d3708d198b9edb06da34de647546', 2),
            (assembly, 'assembly_front', '440e65fc0e41b8b586b44d3ab3bdad65bf4705eed50ab11d9a123d0d9a40d9d2', 16),
        )
        for generator, stem, digest, count in expected:
            with self.subTest(owner=stem):
                source, ports, policy, _ = generator.generated()
                self.assertEqual(len(policy.functions), count)
                self.assertEqual(sha256(source).hexdigest(), digest)
                self.assertEqual(source, (ROOT / ('examples/hia_bootstrap/' + stem + '.hiaasm')).read_bytes())
                self.assertEqual(ports, (ROOT / ('hepta/hia_' + stem + '_ports.py')).read_bytes())

    def test_runtime_does_not_import_the_plan_or_authoring_policy(self):
        files = ('hia_front_continuation.py', 'hia_front_runtime.py', 'hia_front_selection.py',
                 'hia_core_verification_native.py', 'hia_core_verification_ports.py',
                 'hia_core_verification_selection.py', 'hia_assembly_front_native.py',
                 'hia_assembly_front_ports.py', 'hia_assembly_front_selection.py')
        for filename in files:
            for node in ast.walk(ast.parse((ROOT / 'hepta' / filename).read_bytes())):
                with self.subTest(file=filename, line=getattr(node, 'lineno', None)):
                    if isinstance(node, ast.ImportFrom):
                        self.assertFalse((node.module or '').startswith(('tools', 'tests')))
                        self.assertNotIn(node.module, ('hia_core_lowering_native', 'hia_machine_plan_control_native'))
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                        self.assertNotIn(node.func.id, ('eval', 'exec', 'compile', '__import__'))

    def test_default_installation_identity_does_not_generate_abi_ports(self):
        script = '''
import json, sys
calls = []
def observe(frame, event, arg):
    if event == 'call' and (frame.f_code.co_name == '_mapping_merge_primitive' or
            (frame.f_code.co_name == '_profile' and frame.f_globals.get('__name__', '').startswith('hepta.'))):
        calls.append([frame.f_globals.get('__name__'), frame.f_code.co_name])
sys.setprofile(observe)
try:
    from hepta.hia_agent_contract import installation_manifest
    result = installation_manifest()
finally:
    sys.setprofile(None)
ports = ('hia_native_build_foreign', 'hia_native_byte_abi_foreign',
         'hia_service_verification_foreign', 'hia_proof_contract_foreign',
         'hia_core_verification_ports', 'hia_assembly_front_ports')
assert calls == [], calls
assert not any('hepta.' + name in sys.modules for name in ports)
assert len(result['worker_sha256']) == 64
print(json.dumps({'fixed_port_generators': calls, 'default_identity': True}))
'''
        environment = {key: value for key, value in os.environ.items()
                       if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        result = subprocess.run([sys.executable, '-B', '-c', script], cwd=ROOT,
            env=environment, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(json.loads(result.stdout), {'fixed_port_generators': [], 'default_identity': True})

    def test_emitter_factory_initializes_once_without_resurrecting_a_global(self):
        from hepta import hia_core_emitter_native as emitter
        namespace = vars(emitter)
        had_value = '_merge_mapping' in namespace
        original = namespace.get('_merge_mapping')
        marker = object()
        try:
            namespace['_merge_mapping'] = emitter._MAPPING_NOT_LOADED
            with patch.object(emitter, '_mapping_merge_primitive', return_value=marker) as factory:
                emitter._load_mapping_primitive()
                emitter._load_mapping_primitive()
                self.assertIs(namespace['_merge_mapping'], marker)
                self.assertEqual(factory.call_count, 1)
            for state in ('replacement', 'none', 'deleted'):
                with self.subTest(state=state), patch.object(emitter, '_mapping_merge_primitive',
                        side_effect=AssertionError('unexpected ABI regeneration')):
                    if state == 'deleted':
                        namespace.pop('_merge_mapping', None)
                    else:
                        namespace['_merge_mapping'] = marker if state == 'replacement' else None
                    emitter._load_mapping_primitive()
                    if state == 'deleted':
                        self.assertNotIn('_merge_mapping', namespace)
                    else:
                        self.assertIs(namespace['_merge_mapping'], marker if state == 'replacement' else None)
        finally:
            if had_value:
                namespace['_merge_mapping'] = original
            else:
                namespace.pop('_merge_mapping', None)

    def test_emitter_claimed_call_observes_each_current_global_binding(self):
        from hepta import hia_core_emitter_native as emitter
        namespace = vars(emitter)
        had_value = '_merge_mapping' in namespace
        original = namespace.get('_merge_mapping')
        frame = object()
        calls = []
        def replacement(actual, left, right):
            calls.append((actual, left, right))
            return 'replacement-result'
        try:
            for outer in (False, True):
                ambient = LookupError('outer')
                def exercise():
                    namespace['_merge_mapping'] = replacement
                    self.assertEqual(emitter.EmitterFrame._call(frame, (3, 4), (0, 254)), 'replacement-result')
                    self.assertEqual(calls[-1], (frame, 3, 4))
                    for state in ('none', 'deleted'):
                        if state == 'none':
                            namespace['_merge_mapping'] = None
                        else:
                            namespace.pop('_merge_mapping', None)
                        caught = None
                        try:
                            emitter.EmitterFrame._call(frame, (3, 4), (0, 254))
                        except BaseException as error:
                            caught = error
                        self.assertIs(type(caught), TypeError if state == 'none' else NameError)
                        self.assertIs(caught.__context__, ambient if outer else None)
                        if state == 'deleted':
                            self.assertEqual(caught.name, '_merge_mapping')
                        caught = None
                if outer:
                    try:
                        raise ambient
                    except LookupError:
                        exercise()
                else:
                    exercise()
        finally:
            if had_value:
                namespace['_merge_mapping'] = original
            else:
                namespace.pop('_merge_mapping', None)


if __name__ == '__main__':
    unittest.main()
