"""Exact original requests, real native paths, provider order and custody."""
from __future__ import annotations
import ast
import ctypes
import struct
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_service_requests_native as native
from tests import hia_service_requests_fixtures as fixtures

ROOT = Path(__file__).resolve().parents[1]


class ServiceRequestsSourceTests(unittest.TestCase):
    def test_missing_global_preserves_original_nameerror_metadata_and_context(self):
        from tests.hia_native_name_resolution import assert_missing_global_port
        assert_missing_global_port(self, native.RequestsFrame)

    def test_all_eight_original_bodies_and_staticmethod_are_exact(self):
        retained = json.loads(fixtures.ORIGINAL.read_bytes())
        service = next(n for n in ast.parse((ROOT/'hepta/hia_agent_service.py').read_bytes()).body
                       if isinstance(n, ast.ClassDef) and n.name == 'HIAAgentService')
        policy = next(n for n in ast.parse((ROOT/'tools/hia_service_requests_policy.py').read_bytes()).body
                      if isinstance(n, ast.ClassDef))
        self.assertEqual(tuple(n.name for n in policy.body), fixtures.METHODS)
        self.assertEqual(tuple(native.ARITIES), fixtures.METHODS)
        for name in fixtures.METHODS:
            row = retained['methods'][name]
            self.assertEqual(sha256(row['source'].encode()).hexdigest(), row['sha256'])
            expected = ast.parse(row['source']).body[0]
            old = next(n for n in service.body if isinstance(n, ast.FunctionDef) and n.name == name+'_reference')
            old.name = name
            actual = next(n for n in policy.body if n.name == name)
            self.assertEqual(ast.dump(old), ast.dump(expected))
            self.assertEqual(ast.dump(actual), ast.dump(expected))

    def test_all_hia_and_fixed_ports_regenerate_without_runtime_business_source(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_service_requests import document, program, table
        from tools.generate_hia_service_requests_foreign import source
        from hepta import hia_service_requests_foreign as foreign
        policy = program()
        self.assertEqual(render_assembly(document()).encode(), native.SOURCE.read_bytes())
        self.assertEqual(source().encode(), (ROOT/'hepta/hia_service_requests_foreign.py').read_bytes())
        self.assertEqual(sha256(table(policy)).hexdigest(), foreign.TABLE_SHA256)
        self.assertEqual([f.kind for f in policy.functions], ['function']*8+['with_region','generator'])
        for filename in ('hia_service_requests_native.py','hia_service_requests_foreign.py'):
            for node in ast.walk(ast.parse((ROOT/'hepta'/filename).read_bytes())):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or '').startswith(('tests','tools')))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ('exec','eval','compile'))
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, {name+'_reference' for name in fixtures.METHODS})

    def test_unreviewed_handler_exits_and_finally_regions_refuse(self):
        from tools.hia_service_requests_control import compile_policy
        source = (ROOT/'tools/hia_service_requests_policy.py').read_text()
        marker = '                    break\n                except UnicodeDecodeError:'
        self.assertIn(marker, source)
        alternatives = (
            ('                except UnicodeDecodeError:\n                    chunk = chunk[:-1]',
             '                except UnicodeDecodeError:\n                    break'),
            ('                except UnicodeDecodeError:\n                    chunk = chunk[:-1]',
             '                except UnicodeDecodeError:\n                    continue'),
            ('                except UnicodeDecodeError:\n                    chunk = chunk[:-1]',
             '                finally:\n                    chunk = chunk[:-1]'))
        for before, after in alternatives:
            with self.subTest(after=after):
                with self.assertRaises(ValueError):
                    compile_policy(source.replace(before, after, 1))

    def test_fixed_ports_are_lazy_and_owner_is_declared_outside_core(self):
        from hepta.hia_checker_identity import HELD_NATIVE_OWNERS, NATIVE_OWNERS, MECHANISM_SOURCE_FILES, CORE_SOURCE_FILES
        from hepta.hia_native_helpers import HELPERS
        expected = ('hia_service_requests_native','NativeRequestsImage')
        self.assertEqual(HELPERS[native.SELECTOR], expected)
        self.assertEqual(HELD_NATIVE_OWNERS[native.SELECTOR], expected)
        self.assertNotIn(native.SELECTOR, NATIVE_OWNERS)
        self.assertTrue({'hia_service_requests_native.py','hia_service_requests_foreign.py'} <= set(MECHANISM_SOURCE_FILES))
        self.assertNotIn('hia_service_requests_native.py', CORE_SOURCE_FILES)
        tree = ast.parse((ROOT/'hepta/hia_service_requests_native.py').read_bytes())
        self.assertFalse(any(isinstance(n, ast.ImportFrom) and any(
            a.name == 'hia_service_requests_foreign' for a in n.names) for n in tree.body))


class ServiceRequestsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools import build_hia_service_requests as builder
        cold = os.environ.get('HEPTA_HIA_SERVICE_REQUESTS_COLD_REPORT')
        compiler_choice = os.environ.get('HEPTA_HIA_SERVICE_REQUESTS_DEVELOPMENT_COMPILER')
        manifest_choice = os.environ.get('HEPTA_HIA_SERVICE_REQUESTS_DEVELOPMENT_MANIFEST')
        if sum(bool(value) for value in (cold, compiler_choice, manifest_choice)) != 1:
            raise ValueError('service requests requires one explicit cold, development compiler, or development manifest selection')
        cls.inputs = {}
        if cold:
            cold = Path(cold).resolve(); cold_bytes = cold.read_bytes()
            report = json.loads(cold_bytes, object_pairs_hook=builder._pairs)
            try:
                nested = Path(report['nested_report']); nested_bytes = nested.read_bytes()
                compiler = Path(json.loads(nested_bytes)['generations'][-1]['produced_image']).resolve()
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('service-requests cold report lacks a compiler') from error
            compiler_bytes = compiler.read_bytes()
            sources = builder.admit_cold_build(compiler_bytes, cold_bytes)
            if (type(report.get('qualification_wall_limit_seconds')) is not int or report['qualification_wall_limit_seconds'] != 180
                    or type(report.get('cleanup_wall_limit_seconds')) is not int or report['cleanup_wall_limit_seconds'] != 3
                    or any(sources.get(name) != sha256((ROOT / name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES)):
                raise ValueError('service-requests fixture requires complete original-limit current cold source')
            cls.inputs.update({str(cold): sha256(cold_bytes).hexdigest(), str(nested): sha256(nested_bytes).hexdigest(),
                               str(compiler): sha256(compiler_bytes).hexdigest()})
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_SERVICE_REQUESTS_EVIDENCE')
        if evidence:
            base = Path(evidence); base.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls.folder = base / cls.__name__; cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-requests-native-')
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
        cls.image = native.installed_requests(cls.manifest_path)
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
        (cls.folder / 'actual-entries.json').write_text(json.dumps(cls.entries, indent=2) + '\n')
        (cls.folder / 'input-after.json').write_text(json.dumps(after, indent=2) + '\n')
        if after != cls.inputs:
            raise AssertionError('held requests inputs changed')
        if cls.temporary is not None:
            cls.temporary.cleanup()


    def compare(self, name, factory, arguments, *, providers=None):
        with ExitStack() as stack:
            for target, replacement in (providers or ()):
                stack.enter_context(patch(target, replacement))
            oracle = fixtures.original_class()
            left, right = factory(), factory()
            expected = fixtures.observed(lambda: getattr(oracle, name)(left, *arguments))
            before = self.image.entries
            observed = fixtures.observed(lambda: self.image.run(name, right, *arguments))
        self.assertEqual(observed, expected)
        self.assertEqual(fixtures.snapshot(right), fixtures.snapshot(left))
        self.assertGreater(self.image.entries, before)
        return expected

    def test_discovery_profiles_describe_artifacts_and_diagnostics(self):
        self.compare('_profiles', fixtures.service, ())
        for section in ('manifest','language','backend','examples','diagnostics','plans'):
            with self.subTest(section=section):
                self.compare('_hia_describe', fixtures.service, ({'section': section},))
        for arguments in ({'section':'manifest','cursor':'bad'},
                          {'section':'backend','backend_profile':'bad'}):
            self.compare('_hia_describe', fixtures.service, (arguments,))
        self.compare('_hia_artifact', fixtures.service,
                     ({'artifact_profile': 'artifact','source': {'kind':'utf8','text':'中文\x00é'}},))
        for error in (ValueError('rejected'), api.AgentRejected('E_HIA_CASE','retained detail')):
            self.compare('_error', fixtures.service, ('request', error))
        error = ValueError('pending diagnostic')
        error.code = object()
        error.pending_slot_snapshot = {'generation': '3'}
        self.compare('_error', fixtures.service, ('request', error))

    def test_static_examples_are_exact_and_execute_actual_hia(self):
        expected = fixtures.original_class()._examples()
        before = self.image.entries
        actual = self.image.run('_examples')
        self.assertEqual(actual, expected)
        self.assertGreater(self.image.entries, before)
        owner = native.NativeRequestsService(self.image)
        with patch.object(api.HIAAgentService, '_examples_reference', side_effect=AssertionError('old example body')):
            token = native._ACTIVE.set(owner)
            try:
                self.assertEqual(api.HIAAgentService._examples(), expected)
            finally:
                native._ACTIVE.reset(token)

    def test_static_default_retains_original_class_binding_independence(self):
        expected = fixtures.original_class()._examples()
        call = api.HIAAgentService._examples
        original = fixtures.original_class()._examples
        # The test process may poison all old bodies. This explicit default
        # oracle comparison binds its one independent frozen original instead.
        with (patch.dict(os.environ, {native.SELECTOR: ''}),
              patch.object(api, 'HIAAgentService', None),
              patch.object(api, '_NATIVE_REQUESTS_EXAMPLES_REFERENCE', original)):
            self.assertEqual(call(), expected)

    def test_original_utf8_binary_escape_and_cursor_routes(self):
        ref = {'id':'artifact','sha256':'identity'}
        data_cases = (b'', b'plain', 'a中文éz'.encode(), b'\xff\x00\x81', b'\x00'*50000)
        for data in data_cases:
            for limit in (1, 2, 4, 65536):
                with self.subTest(data=data[:8], limit=limit):
                    self.compare('_hia_read', lambda: fixtures.service(data),
                                 ({'artifact': ref,'max_bytes':limit},))
        for row in (None, {'artifact_id':'other','sha256':'identity','offset':1},
                    {'artifact_id':'artifact','sha256':'other','offset':1},
                    {'artifact_id':'artifact','sha256':'identity','offset':1}):
            self.compare('_hia_read', lambda: fixtures.service(b'abcdef',cursor=row),
                         ({'artifact':ref,'cursor':'retained','max_bytes':2},))

    def test_page_loop_restores_outer_physical_exception_on_each_retry(self):
        observations = []
        class Bytes(bytes):
            def decode(self, *args, **kwargs):
                observed = sys.exception()
                observations.append(None if observed is None else (type(observed).__name__, str(observed)))
                return super().decode(*args, **kwargs)
            def __getitem__(self, key):
                return Bytes(super().__getitem__(key))
        ref = {'id':'artifact','sha256':'identity'}
        args = {'artifact':ref,'max_bytes':3}
        records = []
        for native_run in (False, True):
            observations.clear()
            try:
                raise RuntimeError('surrounding retained handler')
            except RuntimeError as outer:
                service = fixtures.service(Bytes('a中文'.encode()))
                result = (self.image.run('_hia_read', service, args) if native_run else
                          fixtures.original_class()._hia_read(service, args))
                self.assertIs(sys.exception(), outer)
                records.append((result, list(observations), fixtures.snapshot(service)))
        self.assertEqual(records[1], records[0])

    def test_candidate_import_and_native_payload_keep_lazy_unbound_branch(self):
        from tools.hia_agent_native_qualification import add_program
        raw = api.wire(add_program())
        arguments = {'context': {'id':'context'}, 'change': {'kind':'import','format':'core-json',
                     'source': {'id':'input'}}}
        self.compare('_hia_candidate', lambda: fixtures.service(raw), (arguments,))
        arguments = {'context': {'id':'context'}, 'change': {'kind':'patch','base_program':{'id':'base'},
                     'patch':{'id':'patch'},'patch_schema':'schema-exact'}}
        with patch.dict(os.environ, {'HEPTA_HIA_CORE_PATCH_MANIFEST':'selected-fixed'}):
            self.compare('_hia_candidate', lambda: fixtures.service(b'raw-input'), (arguments,), providers=(
                ('hepta.hia_agent_candidate_native.apply_candidate_patch',
                 lambda manifest, before, patch_bytes, schema: (b'native-core',b'native-diagnostic')),))

    def test_inspection_selection_and_lazy_generator_use_actual_providers(self):
        from tools.hia_agent_native_qualification import add_program
        program = api.verify_program(add_program())
        name = program.as_dict()['functions'][0]['name']
        block = program.as_dict()['functions'][0]['blocks'][0]['id']
        for view, selector in (('summary',{}),('function',{'function':name}),
                ('block',{'function':name,'block':block}),('function',{}),
                ('function',{'function':'missing'}),('block',{'function':name,'block':'missing'}),
                ('dependencies',{})):
            self.compare('_hia_inspect', lambda: fixtures.service(program=program),
                         ({'program':{'id':'program'},'view':view,'selector':selector},))
        class Contains(dict):
            def __contains__(self, key):
                raise StopIteration('membership provider stopped')
        self.compare('_hia_inspect', lambda: fixtures.service(program=program),
                     ({'program':{'id':'program'},'view':'dependencies','selector':Contains()},))

    def test_with_scope_enter_failure_suppression_and_exact_exit_order(self):
        events = []
        class Scope:
            def __init__(self, fail_enter=False, suppress=False):
                self.fail_enter, self.suppress = fail_enter, suppress
            def __enter__(self):
                events.append('enter')
                if self.fail_enter:
                    raise LookupError('entry failed')
                return None
            def __exit__(self, typ, error, traceback):
                events.append(('exit', None if typ is None else typ.__name__, None if error is None else str(error)))
                return self.suppress
        for fail_enter, fail_body, suppress in ((False,False,False),(True,False,False),
                                               (False,True,False),(False,True,True)):
            records = []
            for native_run in (False, True):
                events.clear()
                service = fixtures.service()
                if fail_body:
                    def fail(*args):
                        raise KeyError('profile store failed')
                    service.store.profile = fail
                with patch('hepta.hia_proof_contract_selection.proof_contract_scope',
                           lambda owner: Scope(fail_enter,suppress)):
                    result = fixtures.observed(lambda: self.image.run('_profiles', service) if native_run
                                               else fixtures.original_class()._profiles(service))
                records.append((result, list(events), fixtures.snapshot(service)))
            self.assertEqual(records[1], records[0])

        # The real proof scope must preserve a captured absence even when a
        # new ambient selector would fail admission, and restore its caller.
        # This uses the original body and the actual HIA image with the real
        # ContextVar/context manager, independently of the controlled Scope.
        from hepta import hia_proof_contract_selection as proof_selection
        original_description = api.proof_contract_description
        records = []
        scope_rows = []
        for native_run in (False, True):
            service = fixtures.service()
            observed = []
            outer = object()
            token = proof_selection._ACTIVE.set(outer)

            def description():
                observed.append(proof_selection._ACTIVE.get() is None)
                return original_description()

            try:
                with patch.dict(os.environ, {proof_selection.SELECTOR: str(self.manifest)+'.missing'}), \
                     patch.object(api, 'proof_contract_description', description):
                    result = fixtures.observed(lambda: self.image.run('_profiles', service) if native_run
                                               else fixtures.original_class()._profiles(service))
                self.assertIs(proof_selection._ACTIVE.get(), outer)
                self.assertEqual(observed, [True])
                self.assertIn('returned', result)
                records.append((result, fixtures.snapshot(service)))
                scope_rows.append({'native': native_run, 'captured_absence_observed': observed,
                                   'outer_scope_restored': True, 'bad_ambient_selector_not_readmitted': True})
            finally:
                proof_selection._ACTIVE.reset(token)
        self.assertEqual(records[1], records[0])
        (self.folder / 'real-proof-scope-integration.json').write_text(
            json.dumps(scope_rows, sort_keys=True, indent=2)+'\n')

    def test_held_owner_survives_ambient_change_and_closed_owner_refuses(self):
        custody = native.installed_requests(self.manifest, capture_identity=True)
        owner = native.NativeRequestsService(custody.image, checker_custody=custody)
        expected = fixtures.original_class()._examples()
        with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)+'.missing'}):
            self.assertEqual(owner.finish(owner.prepare('_examples', ())), expected)
            with self.assertRaises((FileNotFoundError, ValueError)):
                native.admitted_requests()
        self.assertIs(owner.checker_owner(), custody)
        owner.closed = True
        with self.assertRaises(native.RequestsUnknown):
            owner.prepare('_examples', ())

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


    def record(self, name, value):
        (self.folder/(name+'.json')).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

    def test_actual_issued_identity_and_lost_ack_cannot_repeat_request_effect(self):
        class Arguments(dict):
            calls = 0
            def __getitem__(self, name):
                self.calls += 1
                return super().__getitem__(name)
        arguments = Arguments(artifact={'id':'artifact','sha256':'identity'})
        frame = self.image.prepare('_hia_read', (fixtures.service(b'bytes'),arguments))
        self.assertEqual(frame.step(),1)
        issued = frame.pending
        with self.assertRaises(RuntimeError):
            frame.service(replace(issued))
        self.assertEqual(arguments.calls,0)
        while struct.unpack_from('<Q',frame.pending.raw,32)[0] != 4:
            frame.service(frame.pending)
            self.assertEqual(frame.step(),1)
        issued = frame.pending
        frame.service(issued)
        self.assertEqual(arguments.calls,1)
        real = frame._invoke
        def lost(command,*args,**kwargs):
            returned = real(command,*args,**kwargs)
            if command == 1:
                raise KeyboardInterrupt('lost ACK after actual HIA return')
            return returned
        frame._invoke = lost
        with self.assertRaises(KeyboardInterrupt):
            frame.step()
        before = self.image.entries
        for call in (frame.step,frame.drive,frame.take,lambda:frame.service(issued)):
            with self.assertRaises(RuntimeError):
                call()
        self.assertEqual(self.image.entries,before)
        self.assertEqual(arguments.calls,1)
        self.assertTrue(frame._uncertain)
        self.record('actual-lost-ack',{'actual_entries':before,'getitem_calls':arguments.calls,
                                     'uncertain':frame._uncertain,'refused_replays':4})
