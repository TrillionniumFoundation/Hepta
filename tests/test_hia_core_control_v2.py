"""Complete Core v2 profile controls; native execution requires explicit artifacts."""
from __future__ import annotations

import ast
from contextlib import ExitStack
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from hepta import hia_program_native as backend
from hepta import hia_core_lowering_selection as selection
from hepta.hia_program import verify_program
from tests.test_hia_core_lowering_native import comparable
from tests.test_hia_program_native import minimal_document

ROOT = Path(__file__).resolve().parents[1]
BASE = 'a706c6e1b6aa5e5ba0e0fcec2c1c5a9db36ea21f'
DEVELOPMENT = 'HEPTA_HIA_CORE_CONTROL_V2_DEVELOPMENT_MANIFEST'


class CoreControlV2SourceTests(unittest.TestCase):
    def test_complete_v1_source_domain_remains_exact(self):
        import gzip
        raw = (ROOT / 'tests/fixtures/hia_core_control_v1_originals_v1.json.gz').read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), '9176a3e4b236787d8b4f613075191c2111fd994567fb0c42c78eaf7b09a87b2d')
        original = json.loads(gzip.decompress(raw))
        self.assertEqual(original['origin_commit'], BASE)
        paths = ['tools/hia_core_lowering_ir.py', 'tools/hia_core_lowering_policy.py',
                 'tools/generate_hia_core_lowering.py', selection.ABI_SOURCE]
        old = selection.checked_abi((ROOT / selection.ABI_SOURCE).read_bytes())
        self.assertEqual((len(old['units']), len(selection.source_names(old))), (32, 33))
        paths.extend(selection.source_names(old))
        for name in paths:
            with self.subTest(name=name):
                value = (ROOT / name).read_bytes()
                row = original['files'][name]
                self.assertEqual(value, row['content'].encode())
                self.assertEqual((len(value), sha256(value).hexdigest()), (row['bytes'], row['sha256']))

    def test_original_v1_inprocess_body_is_retained_exactly(self):
        raw = (ROOT / 'tests/fixtures/hia_continuation_inprocess_v1_before_core39.py.txt').read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), '34081d23cab3733dcdc26fa233cde63056b3d149f89de72c3f20059191718eaa')
        original = ast.parse(raw)
        current = ast.parse((ROOT / 'hepta/hia_native_continuation_inprocess.py').read_bytes())
        def method(tree, name):
            cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'InProcessContinuation')
            return next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
        old = method(original, 'run')
        new = method(current, '_run_v1')
        new.name = 'run'
        self.assertEqual(ast.dump(old), ast.dump(new))

    def test_v2_contains_all_Function_and_Emitter_bodies(self):
        current = ast.parse((ROOT / 'tools/hia_core_lowering_v2_policy.py').read_bytes())
        old = ast.parse((ROOT / 'tools/hia_core_lowering_policy.py').read_bytes())
        emitter = ast.parse((ROOT / 'tools/hia_core_emitter_policy.py').read_bytes())
        expected = old.body + [next(node for node in emitter.body
                                   if isinstance(node, ast.ClassDef) and node.name == '_Emitter')]
        self.assertEqual(ast.dump(ast.Module(body=current.body, type_ignores=[])),
                         ast.dump(ast.Module(body=expected, type_ignores=[])))

    def test_v2_uses_exact_distinct_profiles_and_types(self):
        raw = (ROOT / selection.ABI_SOURCE_V2).read_bytes()
        abi = selection.checked_abi_v2(raw)
        self.assertEqual((len(abi['units']), len(abi['modes'])), (39, 36))
        self.assertEqual(abi['modes']['_Emitter.__init__']['arity'], 6)
        self.assertEqual(len(abi['generator_modes']), 2)
        self.assertTrue(all('core_lowering_v2_' in name for name in selection.source_names(abi)))
        with self.assertRaises(ValueError):
            selection.checked_abi(raw)
        with self.assertRaises(ValueError):
            selection.checked_abi_v2((ROOT / selection.ABI_SOURCE).read_bytes())
        for field in ('protocol_magic', 'pool_magic', 'packet_bytes', 'workspace_bytes',
                      'output_bytes', 'pool_bytes', 'literal_count'):
            value = json.loads(raw)
            value[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                selection.checked_abi_v2(json.dumps(value).encode())
        for field in ('number', 'arity'):
            value = json.loads(raw)
            value['modes']['_Emitter.__init__'][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                selection.checked_abi_v2(json.dumps(value).encode())

    def test_original_native_capacity_limits_are_unchanged(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        abi = selection.checked_abi_v2((ROOT / selection.ABI_SOURCE_V2).read_bytes())
        names = [*selection.source_names(abi),
                 'examples/hia_bootstrap/continuation_policy_v2.hepta',
                 'examples/hia_bootstrap/continuation_inprocess_packer_v2.hepta']
        self.assertEqual(len(names), 42)
        for name in names:
            with self.subTest(name=name):
                raw = (ROOT / name).read_bytes()
                program = assemble_program(raw).as_dict()
                functions = program['functions']
                blocks = [block for function in functions for block in function['blocks']]
                self.assertEqual(render_assembly(program).encode(), raw)
                self.assertLessEqual(len(raw), 1 << 20)
                self.assertLessEqual(len(raw.splitlines()), 16384)
                self.assertLessEqual(len(functions), 128)
                self.assertLessEqual(len(blocks), 1536)
                self.assertLessEqual(sum(len(block['ops']) + 1 for block in blocks), 8192)
                self.assertTrue(all(len(f['blocks']) <= 256 and len(f['params']) <= 16 for f in functions))

    def test_v1_resource_inventory_never_acquires_v2_implicitly(self):
        from hepta.hia_agent_contract import CONTINUATION_BUILD_FILES
        from hepta.hia_native_continuation_selection import resource_names
        for kind in ('core-lowering', 'core-emitter', 'execution-observation', 'byte-wrapper', 'machine-object'):
            self.assertEqual(resource_names(kind), CONTINUATION_BUILD_FILES)
            if kind != 'core-lowering':
                with self.assertRaises(ValueError):
                    resource_names(kind, core_v2=True)
        self.assertEqual(resource_names('core-lowering', core_v2=True),
                         CONTINUATION_BUILD_FILES + (
                             'docs/HIA_CORE_CONTINUATION_ABI_V2.json',
                             'examples/hia_bootstrap/continuation_policy_v2.hepta',
                             'examples/hia_bootstrap/continuation_inprocess_packer_v2.hepta'))
        for invalid in (1, None, 'true'):
            with self.assertRaises(ValueError):
                resource_names('core-lowering', core_v2=invalid)


class CoreControlV2NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get(DEVELOPMENT)
        if not path:
            raise unittest.SkipTest('requires explicit current Core v2 native in-process artifact')
        cls.manifest = Path(path).resolve(strict=True)
        cls.owner = selection.installed_core_lowering(cls.manifest, vars(backend))
        if cls.owner._admitted_bundle.abi['schema'] != 'hepta.hia.core-lowering-abi.v2':
            raise AssertionError('Core v2 gate cannot accept a v1 owner')
        from hepta.hia_native_continuation_inprocess import InProcessContinuation
        if type(cls.owner._continuation) is not InProcessContinuation:
            raise AssertionError('Core v2 requires actual in-process native scheduling')

    def test_ordinary_complete_lowering_matches_with_old_bodies_poisoned(self):
        from tools.qualify_hia_program import qualification_program
        from tests.test_hia_program_native_review import _empty_memory_program
        documents = (minimal_document(), _empty_memory_program(), qualification_program())
        clear = {name: '' for name in os.environ if name.startswith('HEPTA_HIA_') and name.endswith('_MANIFEST')}
        with patch.dict(os.environ, clear):
            expected = [backend.emit_program_machine(verify_program(d)) for d in documents]
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {selection.SELECTOR: str(self.manifest)}))
            for cls in (backend._Function, backend._Emitter):
                for name, value in vars(cls).items():
                    if inspect.isfunction(value) and name != '__new__':
                        stack.enter_context(patch.object(cls, name,
                            side_effect=AssertionError('retained complete policy body entered: ' + name)))
            for doc, wanted in zip(documents, expected):
                actual = backend.emit_program_machine(verify_program(doc))
                self.assertEqual(comparable(actual), comparable(wanted))
                self.assertNotEqual(actual.implementation_sha256, wanted.implementation_sha256)

    def test_ordinary_foreign_StopIteration_is_not_generator_termination(self):
        events = []
        class Code:
            def push(self, register):
                events.append(register)
                raise StopIteration('ordinary selected foreign operation')
        def observed(call):
            events.clear()
            try:
                call()
            except BaseException as error:
                return type(error), error.args, type(error.__cause__), list(events)
            self.fail('foreign StopIteration was silently consumed')
        wanted = observed(lambda: backend._prologue(Code(), 0))
        actual = observed(lambda: self.owner.invoke('_prologue', (Code(), 0)))
        self.assertEqual(actual, wanted)
        self.assertIs(actual[0], StopIteration)

    def test_native_generator_partial_extend_and_original_exceptions(self):
        for name in self.owner.generator_modes:
            for fault in (None, LookupError, StopIteration, KeyboardInterrupt):
                def observe(native):
                    events, output = [], []
                    class Row:
                        def __init__(self, number):
                            self.number = number
                        def __getitem__(self, key):
                            events.append((self.number, key))
                            if self.number == 1 and fault is not None:
                                raise fault('selected body')
                            return 'u64'
                    rows = [Row(0), Row(1), Row(2)]
                    generator = self.owner.generator(name, iter(rows)) if native else (p['type'] for p in rows)
                    try:
                        output.extend(generator)
                        result = ('value', None)
                    except BaseException as error:
                        result = ('error', type(error), error.args,
                                  None if error.__cause__ is None else (type(error.__cause__), error.__cause__.args))
                    return output, events, result
                with self.subTest(name=name, fault=fault):
                    self.assertEqual(observe(True), observe(False))

    def test_native_generator_suspend_send_throw_and_close(self):
        for name in self.owner.generator_modes:
            def observe(native, action):
                events = []
                class Row:
                    def __getitem__(self, key):
                        events.append(key)
                        return 'u64'
                rows = [Row(), Row()]
                generator = self.owner.generator(name, iter(rows)) if native else (p['type'] for p in rows)
                first = next(generator)
                try:
                    if action == 'send':
                        value = generator.send(None)
                        terminal = next(generator)
                    elif action == 'throw':
                        value = generator.throw(LookupError('external suspension'))
                    else:
                        value = generator.close()
                    result = ('value', value)
                except BaseException as error:
                    result = ('error', type(error), error.args)
                finally:
                    generator.close()
                return first, events, result
            for action in ('send', 'throw', 'close'):
                with self.subTest(name=name, action=action):
                    self.assertEqual(observe(True, action), observe(False, action))
