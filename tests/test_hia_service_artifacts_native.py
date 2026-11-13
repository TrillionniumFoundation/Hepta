"""Actual artifact policy image, independent originals and physical effects."""
from __future__ import annotations

import ast
from contextlib import ExitStack
import ctypes
from dataclasses import replace
import gc
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import weakref

from hepta import hia_agent_service as api
from hepta import hia_service_artifacts_native as native
from tests import hia_service_artifacts_fixtures as fixtures

ROOT = Path(__file__).resolve().parents[1]


def _ast_fields(value):
    """Compare every current AST field, including empty fields and scalar types.

    The fixture retains its original Python 3.12 ast.dump text as evidence.
    Policy equality uses the same interpreter to parse the hash-checked source.
    Location attributes remain excluded, exactly as in the original comparison.
    """
    if isinstance(value, ast.AST):
        return ('AST', type(value).__name__, tuple(
            (name, _ast_fields(field)) for name, field in ast.iter_fields(value)))
    if isinstance(value, list):
        return ('list', tuple(_ast_fields(item) for item in value))
    return (type(value).__name__, value)


class ServiceArtifactsSourceTests(unittest.TestCase):
    def test_six_exact_original_bodies_and_hia_regeneration(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_service_artifacts import document, program, table
        from tools.generate_hia_service_artifacts_foreign import source
        from hepta import hia_service_artifacts_foreign as foreign
        original = json.loads(fixtures.ORIGINAL.read_bytes())
        policy = next(node for node in ast.parse((ROOT/'tools/hia_service_artifacts_policy.py').read_bytes()).body
                      if isinstance(node, ast.ClassDef))
        self.assertEqual(tuple(n.name for n in policy.body), fixtures.METHODS)
        self.assertEqual(tuple(native.ARITIES), fixtures.METHODS)
        for actual in policy.body:
            row = original['methods'][actual.name]
            self.assertEqual(sha256(row['source'].encode()).hexdigest(), row['sha256'])
            expected = ast.parse(row['source']).body[0]
            self.assertEqual(_ast_fields(actual), _ast_fields(expected))
        compiled = program()
        self.assertEqual([f.kind for f in compiled.functions], ['function']*6+['generator'])
        self.assertEqual(render_assembly(document()).encode(), native.SOURCE.read_bytes())
        self.assertEqual(source().encode(), (ROOT/'hepta/hia_service_artifacts_foreign.py').read_bytes())
        self.assertEqual(sha256(table(compiled)).hexdigest(), foreign.TABLE_SHA256)

    def test_no_business_callback_runtime_compilation_or_unsupported_delete(self):
        from tools.hia_service_artifacts_control import compile_policy
        for name in ('hia_service_artifacts_native.py', 'hia_service_artifacts_foreign.py'):
            tree = ast.parse((ROOT/'hepta'/name).read_bytes())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or '').startswith(('tests', 'tools')))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ('exec', 'eval', 'compile'))
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, {n+'_reference' for n in fixtures.METHODS})
        policy = (ROOT/'tools/hia_service_artifacts_policy.py').read_text()
        for replacement in ('del self.store', 'del arguments["program"]'):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                compile_policy(policy.replace('del self, owner, program, foreign_buffer_exports', replacement))

    def test_missing_global_uses_original_nameerror_metadata_and_context(self):
        from tests.hia_native_name_resolution import assert_missing_global_port
        assert_missing_global_port(self, native.ArtifactsFrame)

    def test_all_six_public_routes_and_complete_held_custody_are_registered(self):
        from hepta.hia_checker_identity import HELD_NATIVE_OWNERS, NATIVE_OWNERS, MECHANISM_SOURCE_FILES
        from hepta.hia_native_helpers import HELPERS
        expected = ('hia_service_artifacts_native', 'NativeArtifactsImage')
        self.assertEqual(HELD_NATIVE_OWNERS[native.SELECTOR], expected)
        self.assertEqual(HELPERS[native.SELECTOR], expected)
        self.assertNotIn(native.SELECTOR, NATIVE_OWNERS)
        self.assertTrue({'hia_service_artifacts_native.py', 'hia_service_artifacts_foreign.py'} <= set(MECHANISM_SOURCE_FILES))
        tree = ast.parse((ROOT/'hepta/hia_agent_service.py').read_bytes())
        service = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'HIAAgentService')
        methods = {n.name: n for n in service.body if isinstance(n, ast.FunctionDef)}
        retained = json.loads(fixtures.ORIGINAL.read_bytes())
        for name in fixtures.METHODS:
            old = methods[name+'_reference']
            old.name = name
            row = retained['methods'][name]
            self.assertEqual(sha256(row['source'].encode()).hexdigest(), row['sha256'])
            expected = ast.parse(row['source']).body[0]
            self.assertEqual(_ast_fields(old), _ast_fields(expected))
            public = methods[name]
            self.assertTrue(any(isinstance(n, ast.Constant) and n.value == '_native_artifacts'
                                for n in ast.walk(public)))
            self.assertEqual([n.args[0].value for n in ast.walk(public)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == 'prepare'], [name])


class ServiceArtifactsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools import build_hia_service_artifacts as builder
        cold = os.environ.get('HEPTA_HIA_SERVICE_ARTIFACTS_COLD_REPORT')
        compiler_choice = os.environ.get('HEPTA_HIA_SERVICE_ARTIFACTS_DEVELOPMENT_COMPILER')
        manifest_choice = os.environ.get('HEPTA_HIA_SERVICE_ARTIFACTS_DEVELOPMENT_MANIFEST')
        if sum(bool(value) for value in (cold, compiler_choice, manifest_choice)) != 1:
            raise ValueError('service artifacts requires one explicit cold, development compiler, or development manifest selection')
        cls.inputs = {}
        if cold:
            cold = Path(cold).resolve(); cold_bytes = cold.read_bytes()
            report = json.loads(cold_bytes, object_pairs_hook=builder._pairs)
            try:
                nested = Path(report['nested_report']); nested_bytes = nested.read_bytes()
                compiler = Path(json.loads(nested_bytes)['generations'][-1]['produced_image']).resolve()
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('service-artifacts cold report lacks a compiler') from error
            compiler_bytes = compiler.read_bytes()
            sources = builder.admit_cold_build(compiler_bytes, cold_bytes)
            if (type(report.get('qualification_wall_limit_seconds')) is not int or report['qualification_wall_limit_seconds'] != 180
                    or type(report.get('cleanup_wall_limit_seconds')) is not int or report['cleanup_wall_limit_seconds'] != 3
                    or any(sources.get(name) != sha256((ROOT / name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES)):
                raise ValueError('service-artifacts fixture requires complete original-limit current cold source')
            cls.inputs.update({str(cold): sha256(cold_bytes).hexdigest(), str(nested): sha256(nested_bytes).hexdigest(),
                               str(compiler): sha256(compiler_bytes).hexdigest()})
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_SERVICE_ARTIFACTS_EVIDENCE')
        if evidence:
            base = Path(evidence); base.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls.folder = base / cls.__name__; cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-artifacts-native-')
            cls.folder = Path(cls.temporary.name)
        if cold:
            cls.manifest_path = builder.build(cls.folder / 'current-cold-build', compiler, cold)
            mode = 'MATCHING_CURRENT_SOURCE_COLD'
        elif compiler_choice:
            compiler = Path(compiler_choice).resolve()
            cls.manifest_path = builder.build_development(cls.folder / 'development-build', compiler)
            cls.inputs[str(compiler)] = sha256(compiler.read_bytes()).hexdigest()
            mode = 'EXPLICIT_COMPILER_DEVELOPMENT'
        else:
            cls.manifest_path = Path(manifest_choice).resolve(); mode = 'EXPLICIT_MANIFEST_DEVELOPMENT'
        cls.manifest = cls.manifest_path
        raw = cls.manifest_path.read_bytes()
        record = json.loads(raw, object_pairs_hook=builder._pairs)
        cls.image = native.installed_artifacts(cls.manifest_path)
        cls.inputs.update({str(cls.manifest_path): sha256(raw).hexdigest(),
                           str(cls.manifest_path.parent / record['image_path']): record['image_sha256']})
        cls.inputs.update({str(ROOT / name): sha256((ROOT / name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES})
        cls.entries = {}; cls.original_entry = cls.image._entry
        def counted(source, size, output, capacity, work, extent):
            result = cls.original_entry(source, size, output, capacity, work, extent)
            if size == len(cls.image.table) and extent == cls.image.workspace_bytes:
                mode = str(struct.unpack_from('<Q', ctypes.string_at(work, extent), 152)[0])
                cls.entries[mode] = cls.entries.get(mode, 0) + 1
            return result
        cls.image._entry = counted
        (cls.folder / 'fixture.json').write_text(json.dumps({'mode': mode, 'inputs': cls.inputs,
            'manifest_path': str(cls.manifest_path), 'current_source_cold': bool(cold),
            'whole_stack_native': False, 'python': sys.version}, indent=2) + '\n')

    @classmethod
    def tearDownClass(cls):
        cls.image._entry = cls.original_entry
        after = {name: sha256(Path(name).read_bytes()).hexdigest() for name in cls.inputs}
        cls.record('actual-entries', cls.entries)
        cls.record('input-after', after)
        if after != cls.inputs:
            raise AssertionError('held artifact inputs changed')
        if cls.temporary:
            cls.temporary.cleanup()

    @classmethod
    def record(cls, name, value):
        (cls.folder/(name+'.json')).write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')

    def compare(self, name, factory=fixtures.service, mutate=None):
        left, right = factory(), factory()
        if mutate:
            mutate(left)
            mutate(right)
        expected = fixtures.observed(lambda: fixtures.invoke_original(name, left))
        before = self.image.entries
        actual = fixtures.observed(lambda: fixtures.invoke_native(self.image, name, right))
        self.assertEqual(actual, expected)
        self.assertEqual(right.store.events, left.store.events)
        self.assertGreater(self.image.entries, before)
        return expected

    def test_all_six_methods_original_connections_and_object_and_linked_bytes(self):
        rows = []
        for connection in (False, True):
            for kind in ('object', 'linked'):
                for name in fixtures.METHODS:
                    with self.subTest(connection=connection, kind=kind, name=name):
                        value = self.compare(name, lambda: fixtures.service(connection=connection, output_kind=kind))
                        self.assertIn('returned', value)
                        rows.append([name, connection, kind])
        self.record('six-method-original-comparisons', rows)

    def test_public_default_and_selected_routes_preserve_all_six_independent_originals(self):
        rows = []
        aliases = tuple('_NATIVE_ARTIFACTS_'+name.strip('_').upper()+'_REFERENCE' for name in fixtures.METHODS)
        for selected in (False, True):
            for connection in (False, True):
                for name in fixtures.METHODS:
                    left = fixtures.service(connection=connection)
                    right = fixtures.service(connection=connection)
                    right._native_artifacts = native.NativeArtifactsService(self.image) if selected else None
                    expected = fixtures.observed(lambda: fixtures.invoke_original(name, left))
                    values = fixtures.arguments(name, right)
                    keyword = {} if name == '_signature_values' else {'_connection': right.store.connection}
                    before = self.image.entries
                    with ExitStack() as stack:
                        if selected:
                            for original in fixtures.METHODS:
                                stack.enter_context(patch.object(api.HIAAgentService, original+'_reference',
                                    side_effect=AssertionError('selected public route called original body')))
                            for alias in aliases:
                                stack.enter_context(patch.object(api, alias,
                                    side_effect=AssertionError('selected public route called original alias')))
                        actual = fixtures.observed(lambda: getattr(api.HIAAgentService, name)(right, *values, **keyword))
                    self.assertEqual(actual, expected, (name, selected, connection))
                    self.assertEqual(right.store.events, left.store.events)
                    if selected:
                        self.assertGreater(self.image.entries, before)
                    else:
                        self.assertEqual(self.image.entries, before)
                    rows.append([name, selected, connection, self.image.entries-before])
        self.record('public-default-and-selected-originals', rows)

    def test_held_owner_survives_ambient_change_and_closed_owner_refuses(self):
        custody = native.installed_artifacts(self.manifest, capture_identity=True)
        owner = native.NativeArtifactsService(custody.image, checker_custody=custody)
        service = fixtures.service()
        arguments = (service, service.refs['program'], 'target', None)
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)+'.missing'}):
            self.assertEqual(owner.finish(owner.prepare('_profile', arguments)),
                             {'profile_checked': service.refs['program']})
            with self.assertRaises((FileNotFoundError, ValueError)):
                native.admitted_artifacts()
        self.assertIs(owner.checker_owner(), custody)
        owner.closed = True
        with self.assertRaises(native.ArtifactsUnknown):
            owner.prepare('_profile', arguments)

    def test_profile_program_errors_and_dynamic_global_provider(self):
        self.compare('_profile', mutate=lambda s: s.profiles.pop('target'))
        for data in (b'invalid json', b'{}', b'{"schema":"wrong"}'):
            self.compare('_program', mutate=lambda s: s.store.objects.__setitem__('program', (data, {})))
        for name in ('decode_json', 'verify_program', '_signatures'):
            target = '_signature_values' if name == '_signatures' else '_program'
            events = []
            def replacement(*arguments):
                events.append(name)
                raise LookupError('original dynamic provider '+name)
            left, right = fixtures.service(), fixtures.service()
            with patch.object(api, name, replacement):
                expected = fixtures.observed(lambda: fixtures.invoke_original(target, left))
                actual = fixtures.observed(lambda: fixtures.invoke_native(self.image, target, right))
            self.assertEqual(actual, expected)
            self.assertEqual(events, [name, name])

    def test_native_context_core_signature_and_export_bindings(self):
        for field, bad in (('installation', {'changed': True}), ('context', {'id': 'other'}),
                           ('core_sha256', 'other'), ('signatures', {'wrong': True}),
                           ('foreign_buffer_exports', [['x', 3]])):
            with self.subTest(field=field):
                result = self.compare('_native', mutate=lambda s: s.metadata.__setitem__(field, bad))
                self.assertIn('error', result)
        self.compare('_native', mutate=lambda s: s.context.__setitem__('foreign_buffer_exports', None))

    def test_build_record_rejects_each_exact_subject_and_byte_binding(self):
        cases = [
            ('record', 'context', {'id': 'other'}),
            ('record', 'native_artifact', {'id': 'other'}),
            ('record', 'installation', {}),
            ('record', 'target_profile', {}),
            ('record', 'backend_profile', {}),
            ('record', 'signatures', {}),
            ('record', 'native_build', []),
            ('record', 'object_artifact', []),
            ('built', 'object_artifact', {}),
            ('built', 'object_sha256', 'other'),
            ('built', 'core_sha256', 'other'),
            ('built', 'input_sha256', 'other'),
            ('built', 'implementation_sha256', 'other'),
            ('built', 'kind', 'other'),
            ('built', 'foreign_buffer_exports', None),
            ('built', 'artifact_sha256', 'other'),
            ('object_metadata', 'schema', 'other'),
            ('object_metadata', 'core_sha256', 'other'),
            ('object_metadata', 'machine_plan_sha256', 'other'),
            ('object_metadata', 'installation', {}),
        ]
        for owner, field, bad in cases:
            with self.subTest(owner=owner, field=field):
                value = self.compare('_build_inputs', mutate=lambda s: getattr(s, owner).__setitem__(field, bad))
                self.assertIn('error', value)
        result = self.compare('_build_inputs', mutate=lambda s: s.store.objects.__setitem__(
            'object', (b'changed bytes', s.object_metadata)))
        self.assertIn('error', result)
        self.record('build-binding-mismatch-cases', cases)

    def test_lazy_metadata_generator_preserves_first_failure_and_held_context(self):
        class BrokenItems(dict):
            def items(self):
                yield 'context', self['context']
                yield 'candidate', {'id': 'bad-first'}
                raise AssertionError('generator advanced after first true mismatch')
        def changed(service):
            service.metadata = BrokenItems(service.metadata)
            data, _ = service.store.objects['native']
            service._native = lambda *a, **k: (data, service.metadata, service.program)
        try:
            raise KeyError('outer exact handled context')
        except KeyError:
            result = self.compare('_build_inputs', mutate=changed)
        self.assertEqual(result['error'][3], 'E_HIA_RECEIPT_BINDING')
        self.assertEqual(result['error'][-1], ('KeyError', "'outer exact handled context'"))

    def test_actual_keyword_mapping_primitive_preserves_rejection_before_store_effect(self):
        class BrokenMapping:
            def keys(self):
                raise LookupError('exact mapping keys failure')
        rows = []
        for mapping in ({'kind': 'duplicate'}, {1: None}, object(), BrokenMapping()):
            left, right = fixtures.service(), fixtures.service()
            with patch.object(api, '_connection_arguments', lambda value: mapping):
                expected = fixtures.observed(lambda: fixtures.invoke_original('_native', left))
                actual = fixtures.observed(lambda: fixtures.invoke_native(self.image, '_native', right))
            self.assertEqual(actual, expected)
            self.assertIn('error', actual)
            self.assertEqual(left.store.events, [])
            self.assertEqual(right.store.events, [])
            rows.append({'mapping_type': type(mapping).__name__, 'observation': actual})
        self.record('actual-keyword-mapping-refusals', rows)

    def test_signature_error_traceback_retains_only_original_live_arguments(self):
        rows = []
        for route in ('direct', 'public-default', 'public-selected'):
            for outer in (False, True):
                def execute(path):
                    events, refs = [], {}
                    image = self.image
                    def exception():
                        error = sys.exception()
                        return None if error is None else str(error)
                    class Value:
                        def __init__(self, name):
                            self.name = name
                            refs[name] = weakref.ref(self)
                        def __del__(self):
                            events.append((self.name, exception()))
                    class Service(Value):
                        _native_emission = None
                        def __init__(self):
                            super().__init__('service')
                            self._native_artifacts = native.NativeArtifactsService(image) if path == 'public-selected' else None
                    def fail(program, exports):
                        events.append(('callee', refs['service']() is None, exception()))
                        raise ValueError('signature provider failure')
                    def invoke():
                        if path == 'original':
                            return fixtures.original_class()._signature_values(Service(), Value('program'), Value('exports'))
                        if path == 'direct':
                            return image.run('_signature_values', Service(), Value('program'), Value('exports'))
                        return api.HIAAgentService._signature_values(Service(), Value('program'), Value('exports'))
                    def caught():
                        try:
                            invoke()
                        except ValueError as error:
                            return error
                        raise AssertionError('original signature failure was lost')
                    with patch.object(api, '_signatures', fail):
                        if outer:
                            try:
                                raise KeyError('outer signature failure')
                            except KeyError:
                                error = caught()
                        else:
                            error = caught()
                    held = {name: ref() is not None for name, ref in refs.items()}
                    context = None if error.__context__ is None else str(error.__context__)
                    first = list(events)
                    error = None
                    gc.collect()
                    return {'held': held, 'context': context, 'before_release': first,
                            'after_release': events, 'released': {name: ref() is None for name, ref in refs.items()}}
                expected, actual = execute('original'), execute(route)
                self.assertEqual(actual, expected, (route, outer))
                self.assertEqual(actual['held'], {'service': False, 'program': True, 'exports': True})
                self.assertTrue(all(actual['released'].values()))
                rows.append({'route': route, 'outer': outer, 'expected': expected, 'actual': actual})
        self.record('held-signature-error-lifetimes', rows)

    def test_signature_delete_releases_service_before_exact_callee_and_retains_arguments(self):
        rows = []
        for selected in (False, True):
            for outer in (False, True):
                def execute(route):
                    events, references = [], {}
                    def exception():
                        value = sys.exception()
                        return None if value is None else str(value)
                    class Value:
                        def __init__(self, name):
                            self.name = name
                            references[name] = weakref.ref(self)
                        def __del__(self):
                            events.append(('drop', self.name, exception()))
                    def callee(program, exports):
                        events.append(('call', references['service']() is None,
                            references['program']() is program, references['exports']() is exports, exception()))
                        return 'signature result'
                    class Owner:
                        signatures = staticmethod(callee)
                    class Service(Value):
                        def __init__(self):
                            super().__init__('service')
                            self._native_emission = Owner() if selected else None
                            self._native_artifacts = None
                    method = fixtures.original_class()._signature_values
                    artifacts_image = self.image
                    def call():
                        if route == 'direct':
                            return self.image.run('_signature_values', Service(), Value('program'), Value('exports'))
                        if route.startswith('public'):
                            service = Service()
                            if route == 'public-selected':
                                service._native_artifacts = native.NativeArtifactsService(artifacts_image)
                            arguments = {'service': service}
                            del service
                            return api.HIAAgentService._signature_values(arguments.pop('service'), Value('program'), Value('exports'))
                        return method(Service(), Value('program'), Value('exports'))
                    with patch.object(api, '_signatures', callee):
                        # The independent original captures the same late-bound global.
                        method = fixtures.original_class()._signature_values
                        if outer:
                            try:
                                raise LookupError('held outer')
                            except LookupError:
                                result = call()
                        else:
                            result = call()
                    gc.collect()
                    return result, events, {name: ref() is None for name, ref in references.items()}
                expected = execute('original')
                for route in ('direct', 'public-default', 'public-selected'):
                    actual = execute(route)
                    self.assertEqual(actual, expected, (route, selected, outer))
                    self.assertTrue(all(actual[2].values()))
                    self.assertTrue(next(event for event in actual[1] if event[0] == 'call')[1])
                    rows.append({'route': route, 'selected': selected, 'outer': outer, 'expected': expected, 'actual': actual})
        self.record('physical-named-delete-lifetimes', rows)

    def test_actual_issued_identity_and_lost_ack_do_not_repeat_delete(self):
        events = []
        class Service:
            _native_emission = None
            def __del__(self):
                events.append('service')
        frame = self.image.prepare('_signature_values', (Service(), object(), ()))
        self.assertEqual(frame.step(), 1)
        issued = frame.pending
        with self.assertRaises(RuntimeError):
            frame.service(replace(issued))
        while True:
            op, destinations, args, raw, vector = frame._parts()
            if op == 15 and raw and raw[0] == 2:
                break
            frame.service(frame.pending)
            self.assertEqual(frame.step(), 1)
        self.assertEqual(events, [])
        issued = frame.pending
        frame.service(issued)
        self.assertEqual(events, ['service'])
        invoke = frame._invoke
        def lost(command, *args, **kwargs):
            returned = invoke(command, *args, **kwargs)
            if command == 1:
                raise KeyboardInterrupt('lost delete ACK after actual native return')
            return returned
        frame._invoke = lost
        with self.assertRaises(KeyboardInterrupt):
            frame.step()
        before = self.image.entries
        for action in (frame.step, frame.drive, frame.take, lambda: frame.service(issued)):
            with self.assertRaises(RuntimeError):
                action()
        self.assertEqual(self.image.entries, before)
        self.assertEqual(events, ['service'])
        self.assertTrue(frame._uncertain)
        self.record('actual-delete-lost-ack', {'delete_effects': events, 'refused_replays': 4,
            'actual_entries_after_loss': before, 'uncertain': True})


    def test_independent_vm_complete_error_retirement_frames_all_modes(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(native.SOURCE.read_bytes())
        function = checked.as_dict()['functions'][0]
        rows = []
        for mode in range(1, self.image.function_count+1):
            state = bytearray(self.image.workspace_bytes)
            output = bytearray(b'\xb7'*2048)
            nonce, count = 7000+mode, 0
            def call(command, flag=0, error=0, op=0):
                nonlocal count
                sequence = int.from_bytes(state[144:152], 'little')
                struct.pack_into('<6Q', state, 0, command, nonce, sequence,
                    mode if command == 0 else op if command == 2 else flag, error, self.image.runtime_profile)
                raw = self.image.table
                src = ctypes.create_string_buffer(raw+b'\xa5'*16, len(raw)+16)
                out = ctypes.create_string_buffer(bytes(output)+b'\xb7'*16, len(output)+16)
                work = ctypes.create_string_buffer(bytes(state)+b'\xc9'*16, len(state)+16)
                actual = self.image._entry(src,len(raw),out,len(output),work,len(state))
                owners = [_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(output)),_Owner(-3,bytearray(state))]
                expected = _Machine(checked,10000000,16<<20,None,128).invoke(function,
                    [_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
                self.assertEqual(actual,expected)
                self.assertEqual(out.raw[:len(output)],bytes(owners[1].data))
                self.assertEqual(work.raw[:len(state)],bytes(owners[2].data))
                self.assertEqual(src.raw,raw+b'\xa5'*16)
                self.assertEqual(out.raw[len(output):],b'\xb7'*16)
                self.assertEqual(work.raw[len(state):],b'\xc9'*16)
                output[:],state[:]=owners[1].data,owners[2].data
                count+=1
                return actual
            self.assertEqual(call(0),1)
            self.assertEqual(call(2,op=int.from_bytes(output[32:40],'little')),4)
            status=call(1,error=1)
            while status==1:
                self.assertIn(int.from_bytes(output[32:40],'little'),(2,16,21,28))
                self.assertEqual(call(2,op=int.from_bytes(output[32:40],'little')),4)
                status=call(1)
                self.assertLess(count,4096)
            self.assertEqual(status,3)
            status=call(4)
            while status==1:
                self.assertIn(int.from_bytes(output[32:40],'little'),(16,28))
                self.assertEqual(call(2,op=int.from_bytes(output[32:40],'little')),4)
                status=call(1)
                self.assertLess(count,4096)
            self.assertEqual(status,5)
            rows.append({'mode':mode,'frames':count,'output_sha256':sha256(output).hexdigest(),
                         'workspace_sha256':sha256(state).hexdigest(),'full_buffers_equal':True})
        self.record('vm-native-all-modes-error-retirement',rows)
