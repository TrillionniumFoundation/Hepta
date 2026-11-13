"""Original verification policy, real HIA permissions, and retained identities.

Provider doubles are used only by the labelled differential corpus. The public
SQLite/proof and installed-wheel cases use the actual providers. A retained
compiler or manifest is an explicit development input, never current cold.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
import ctypes
from dataclasses import replace
import dis
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import weakref

from hepta import hia_agent_service as api
from hepta import hia_service_verification_native as native
from hepta import hia_machine_plan_control_native as transport
from tests import hia_service_verification_fixtures as fixtures
from tests import hia_service_verification_foreign_fixtures as foreign_fixtures
from tests import hia_service_verification_lifetimes as lifetimes

ROOT = Path(__file__).resolve().parents[1]
ABI = 0xfffffffd


class ServiceVerificationSourceTests(unittest.TestCase):
    def test_global_nameerror_preserves_name_and_active_context(self):
        from tests.hia_native_name_resolution import assert_missing_global_port
        assert_missing_global_port(self, native.VerificationFrame)

    def test_original_seven_methods_and_independent_oracle_are_exact(self):
        raw = fixtures.ORIGINAL.read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), fixtures.ORIGINAL_SHA)
        original = json.loads(raw)
        self.assertTrue(all(fn.__globals__ is vars(api) for fn in fixtures.REFERENCE.values()))
        source = ast.parse((ROOT / 'hepta/hia_agent_service.py').read_bytes())
        service = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == 'HIAAgentService')
        author = ast.parse((ROOT / 'tools/hia_service_verification_policy.py').read_bytes()).body[-1]
        for name in native.ARITIES:
            with self.subTest(name=name):
                retained = next(n for n in service.body if isinstance(n, ast.FunctionDef) and n.name == name + '_reference')
                expected = ast.parse(''.join('@' + item + '\n' for item in original['methods'][name]['decorators'])
                                     + original['methods'][name]['source']).body[0]
                retained.name = name
                self.assertEqual(ast.dump(retained, include_attributes=False), ast.dump(expected, include_attributes=False))
                actual = next(n for n in author.body if isinstance(n, ast.FunctionDef) and n.name == name)
                self.assertEqual(ast.dump(actual, include_attributes=False), ast.dump(expected, include_attributes=False))

    def test_actual_hia_and_fixed_foreign_sources_regenerate(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from tools.generate_hia_service_verification import document, program
        from tools.generate_hia_service_verification_foreign import source
        raw = render_assembly(document()).encode()
        self.assertEqual(raw, native.SOURCE.read_bytes())
        self.assertEqual(source().encode(), (ROOT / 'hepta/hia_service_verification_foreign.py').read_bytes())
        self.assertLessEqual(len(assemble_program(raw).as_dict()['functions']), 128)
        policy = program()
        self.assertEqual(len(policy.functions), 8)
        self.assertEqual([function.kind for function in policy.functions].count('generator'), 1)

    def test_runtime_never_imports_authoring_or_retained_business(self):
        for name in ('hepta/hia_service_verification_native.py', 'hepta/hia_service_verification_foreign.py'):
            tree = ast.parse((ROOT / name).read_bytes())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or '').startswith(('tools', 'tests')))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ('eval', 'exec', 'compile'))
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, {method + '_reference' for method in native.ARITIES})
        from hepta.hia_checker_identity import HELD_NATIVE_OWNERS, NATIVE_OWNERS
        from hepta.hia_native_helpers import HELPERS
        expected = ('hia_service_verification_native', 'NativeVerificationImage')
        self.assertEqual(HELD_NATIVE_OWNERS[native.SELECTOR], expected)
        self.assertEqual(HELPERS[native.SELECTOR], expected)
        self.assertNotIn(native.SELECTOR, NATIVE_OWNERS)

    def test_all_public_routes_and_static_binding_use_selected_owner(self):
        tree = ast.parse((ROOT / 'hepta/hia_agent_service.py').read_bytes())
        service = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'HIAAgentService')
        methods = {n.name: n for n in service.body if isinstance(n, ast.FunctionDef)}
        for name in native.ARITIES:
            node = methods[name]
            attrs = {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
            self.assertIn('prepare', attrs)
            self.assertIn('finish', attrs)
            self.assertIn(name + '_reference', attrs)
        self.assertTrue(any(isinstance(n, ast.Constant) and n.value == '_native_verification'
                            for n in ast.walk(methods['_held_checker_owners'])))
        self.assertTrue({'_call_reference', '_call_native_journal'} <=
                        {n.attr for n in ast.walk(methods['call']) if isinstance(n, ast.Attribute)})
        for name in ('_call_reference', '_call_native_journal'):
            self.assertIn('_replay_verification', {n.attr for n in ast.walk(methods[name]) if isinstance(n, ast.Attribute)})

    def test_invalid_selected_manifest_is_refusal_before_service_creation(self):
        with tempfile.TemporaryDirectory(prefix='hia-verification-selection-source-') as directory:
            state = Path(directory) / 'never-created'
            env = {key: '' for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')}
            env[native.SELECTOR] = str(Path(directory) / 'missing-manifest.json')
            with patch.dict(os.environ, env), patch.object(api, 'catalog', side_effect=AssertionError('catalog entered')):
                with self.assertRaises(OSError):
                    api.HIAAgentService(state)
            self.assertFalse(state.exists())


class ServiceVerificationNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools import build_hia_service_verification as builder
        cold = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_COLD_REPORT')
        compiler_choice = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_DEVELOPMENT_COMPILER')
        manifest_choice = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_DEVELOPMENT_MANIFEST')
        if sum(bool(value) for value in (cold, compiler_choice, manifest_choice)) != 1:
            raise ValueError('service verification requires one explicit cold, development compiler, or development manifest selection')
        cls.inputs = {}
        if cold:
            cold = Path(cold).resolve(); cold_bytes = cold.read_bytes()
            report = json.loads(cold_bytes, object_pairs_hook=builder._pairs)
            try:
                nested = Path(report['nested_report']); nested_bytes = nested.read_bytes()
                compiler = Path(json.loads(nested_bytes)['generations'][-1]['produced_image']).resolve()
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('service-verification cold report lacks a compiler') from error
            compiler_bytes = compiler.read_bytes()
            sources = builder.admit_cold_build(compiler_bytes, cold_bytes)
            if (type(report.get('qualification_wall_limit_seconds')) is not int or report['qualification_wall_limit_seconds'] != 180
                    or type(report.get('cleanup_wall_limit_seconds')) is not int or report['cleanup_wall_limit_seconds'] != 3
                    or any(sources.get(name) != sha256((ROOT / name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES)):
                raise ValueError('service-verification fixture requires complete original-limit current cold source')
            cls.inputs.update({str(cold): sha256(cold_bytes).hexdigest(), str(nested): sha256(nested_bytes).hexdigest(),
                               str(compiler): sha256(compiler_bytes).hexdigest()})
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_SERVICE_VERIFICATION_EVIDENCE')
        if evidence:
            base = Path(evidence); base.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls.folder = base / cls.__name__; cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-verification-native-')
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
        raw = cls.manifest_path.read_bytes()
        record = json.loads(raw, object_pairs_hook=builder._pairs)
        cls.image = native.installed_verification(cls.manifest_path)
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
            raise AssertionError('held verification inputs changed')
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def record(self, name, value):
        (self.folder / (name + '.json')).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

    @staticmethod
    def forbidden(*args, **kwargs):
        raise AssertionError('selected verification called retained business policy')

    def poison_references(self, stack):
        for name in native.ARITIES:
            stack.enter_context(patch.object(api.HIAAgentService, name + '_reference', self.forbidden))

    def independent_environment(self, manifest=None):
        env = {key: '' for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')}
        env[native.SELECTOR] = '' if manifest is None else str(manifest)
        return patch.dict(os.environ, env)

    def identity_files(self, label, *, suffix=b''):
        case = self.folder / (self._testMethodName + '-' + label); case.mkdir(mode=0o700)
        value = json.loads(self.manifest_path.read_bytes()); image = case / 'verification.image.bin'
        image.write_bytes((self.manifest_path.parent / value['image_path']).read_bytes() + suffix)
        value.update(image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest())
        manifest = case / 'manifest.json'; manifest.write_text(json.dumps(value, sort_keys=True) + '\n')
        source = case / 'source.hiaasm'; source.write_bytes(native.SOURCE.read_bytes())
        return SimpleNamespace(case=case, manifest=manifest, image=image, source=source)

    def public_session(self, service, prefix):
        from tools.hia_agent_native_qualification import Session, ToolClient, add_program
        session = Session(ToolClient(service.call), prefix=prefix)
        session.freeze({'schema': 'hepta.hia.agent.workload.v1', 'cases': [{'function': 'transform', 'arguments': [0]}],
                        'warmup_iterations': 0, 'repetitions': 1})
        return session, session.import_program(add_program())

    def test_original_seven_methods_complete_controlled_provider_corpus(self):
        rows = []
        for case in fixtures.CASES:
            with self.subTest(case=case):
                expected = fixtures.fixture_call(case, False)
                before = self.image.entries
                actual = fixtures.fixture_call(case, True, self.image)
                rows.append({'case': case, 'reference': expected, 'native': actual,
                             'actual_entries': self.image.entries - before})
                self.assertGreater(rows[-1]['actual_entries'], 0)
                self.assertEqual(actual, expected)
        self.assertEqual(len(rows), 38)
        self.record('controlled-provider-38', rows)

    def test_normal_call_lifetimes_direct_and_both_public_routes(self):
        rows = []
        for case in ('success', 'profile-error', 'profile-stop', 'subject-error', 'publish-error'):
            for outer in (False, True):
                expected = lifetimes.observation(case, False, outer)
                for selected, route in ((True, 'direct'), (False, 'public'), (True, 'public')):
                    with self.subTest(case=case, outer=outer, selected=selected, route=route):
                        before = self.image.entries
                        actual = lifetimes.observation(case, selected, outer, self.image, route=route)
                        rows.append({'case': case, 'outer': outer, 'selected': selected, 'route': route,
                                     'reference': expected, 'actual': actual, 'actual_entries': self.image.entries - before})
                        self.assertEqual(actual, expected)
                        if selected:
                            self.assertGreater(rows[-1]['actual_entries'], 0)
                        else:
                            self.assertEqual(rows[-1]['actual_entries'], 0)
        self.record('ordinary-call-public-lifetimes-30', rows)

    def test_mapping_and_lazy_double_truth_lifetimes_use_original_operations(self):
        rows = []
        for kind in (False, True):
            for case in foreign_fixtures.MAPPING_CASES:
                for outer in (False, True):
                    with self.subTest(family='mapping', case=case, kind=kind, outer=outer):
                        expected = foreign_fixtures.mapping_observation(case, False, outer=outer, kind=kind)
                        before = self.image.entries
                        actual = foreign_fixtures.mapping_observation(case, True, self.image, outer=outer, kind=kind)
                        rows.append({'family': 'mapping', 'case': case, 'kind': kind, 'outer': outer,
                                     'reference': expected, 'native': actual, 'actual_entries': self.image.entries - before})
                        self.assertEqual(actual, expected)
        for case in foreign_fixtures.GENERATOR_CASES:
            for outer in (False, True):
                with self.subTest(family='generator', case=case, outer=outer):
                    expected = foreign_fixtures.generator_observation(case, False, outer=outer)
                    before = self.image.entries
                    actual = foreign_fixtures.generator_observation(case, True, self.image, outer=outer)
                    rows.append({'family': 'generator', 'case': case, 'outer': outer, 'reference': expected,
                                 'native': actual, 'actual_entries': self.image.entries - before})
                    self.assertEqual(actual, expected)
        self.assertEqual(len(rows), 60)
        self.assertTrue(all(row['actual_entries'] > 0 for row in rows))
        self.record('mapping-and-generator-60', rows)

    def test_public_sqlite_proof_cached_request_and_same_held_consumer(self):
        from hepta import hia_checker_identity as checker
        from hepta.hia_agent_store import digest
        case = self.folder / 'actual-public'; case.mkdir(mode=0o700)
        with self.independent_environment(self.manifest_path), ExitStack() as stack:
            self.poison_references(stack)
            service = api.HIAAgentService(case / 'state')
            try:
                before = service._native_verification.image.entries
                session, candidate = self.public_session(service, 'verification-public')
                proved = session.verify(candidate)
                selection = checker.checker_native_selection(held_owners=service._held_checker_owners())
                evidence = session.read_json(proved['checks'][0]['evidence_artifact'])
                self.assertEqual(evidence['native_checker_selection'], selection)
                self.assertEqual(proved['checks'][0]['checker']['native_selection_sha256'], digest(selection))
                request = next(record for record in session.client.records if record['tool'] == 'hia_verify')
                replay = session.client.call('hia_verify', request['arguments'])
                self.assertEqual(replay['result'], proved)
                retained = service._verification(proved['verification_receipt'], session.context, candidate)
                self.assertEqual(retained['checks'], proved['checks'])
                self.record('real-public-proof-replay', {'proof': proved, 'evidence': evidence, 'selection': selection,
                    'records': session.client.records, 'actual_entries': service._native_verification.image.entries - before})
            finally:
                service.close()

    def test_actual_held_proof_survives_drift_and_rejects_restarted_other_image(self):
        from hepta import hia_checker_identity as checker
        from hepta.hia_agent_store import AgentRejected, digest
        a = self.identity_files('A'); b = self.identity_files('B-explicit-trailing-byte-mutant', suffix=b'\x90')
        rows = []
        with self.independent_environment(a.manifest), patch.object(native, 'SOURCE', a.source), ExitStack() as stack:
            self.poison_references(stack)
            service = api.HIAAgentService(a.case / 'state')
            try:
                session, candidate = self.public_session(service, 'verification-proof-scope')
                held = service._native_verification.checker_owner()
                expected = checker.checker_native_selection(held_owners=service._held_checker_owners())
                for label, selected in (('original', str(a.manifest)), ('different-image', str(b.manifest)), ('cleared', '')):
                    os.environ[native.SELECTOR] = selected
                    proved = session.verify(candidate)
                    evidence = session.read_json(proved['checks'][0]['evidence_artifact'])
                    self.assertEqual(evidence['native_checker_selection'], expected)
                    self.assertEqual(proved['checks'][0]['checker']['native_selection_sha256'], digest(expected))
                    service._verification(proved['verification_receipt'], session.context, candidate)
                    rows.append({'selector_state': label, 'held': expected[native.SELECTOR], 'proof': proved})
                for path in (a.source, a.image, a.manifest):
                    raw = path.read_bytes(); path.write_bytes(raw + b'changed')
                    try:
                        with self.assertRaises((ValueError, OSError)):
                            native.installed_verification(a.manifest)
                        self.assertEqual(checker.checker_native_selection(held_owners=service._held_checker_owners()), expected)
                        service._verification(proved['verification_receipt'], session.context, candidate)
                    finally:
                        path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    checker.checker_native_selection(held_owners=(expected[native.SELECTOR],))
                with self.assertRaises(ValueError):
                    checker.checker_native_selection(held_owners=(held, held))
            finally:
                service.close()
            os.environ[native.SELECTOR] = str(b.manifest)
            other = api.HIAAgentService(a.case / 'state')
            try:
                with self.assertRaises(AgentRejected) as caught:
                    other._verification(proved['verification_receipt'], session.context, candidate)
                self.assertEqual(caught.exception.code, 'E_HIA_PROOF_SCOPE')
            finally:
                other.close()
            os.environ[native.SELECTOR] = str(a.manifest)
            restored = api.HIAAgentService(a.case / 'state')
            try:
                restored._verification(proved['verification_receipt'], session.context, candidate)
                self.assertIs(restored._native_verification.image, held.image)
            finally:
                restored.close()
        self.record('held-proof-drift-restart', rows)

    def profile_frame(self, calls, callback=None):
        class Service:
            def _profile(self, *args, **kwargs):
                calls.append((args, kwargs))
                return callback() if callback is not None else None
        service = Service()
        frame = self.image.prepare('_subject', (service, {'subject': {'kind': 'other', 'backend_profile': 'backend'}}, None, None))
        status = frame.step()
        while status == 1:
            op, destinations, args, raw, vector = frame._parts()
            if op == 9 and raw == (0, 255) and getattr(frame._get(args[0]), '__self__', None) is service:
                return frame
            frame.service(frame.pending)
            status = frame.step()
        self.fail('actual HIA did not reach its original profile call')

    def test_exact_issued_object_and_raw_payload_required_before_effect(self):
        calls = []; first = self.profile_frame(calls); second = self.profile_frame(calls)
        try:
            issued = first.pending
            for supplied in (replace(issued), second.pending, SimpleNamespace(raw=issued.raw)):
                with self.assertRaises(native.VerificationUnknown):
                    first.service(supplied)
            raw = issued.raw
            object.__setattr__(issued, 'raw', raw[:16] + bytes((raw[16] ^ 1,)) + raw[17:])
            with self.assertRaises(native.VerificationUnknown):
                first.service(issued)
            object.__setattr__(issued, 'raw', raw)
            self.assertEqual(calls, [])
            first.service(issued)
            self.assertEqual(len(calls), 1)
            with self.assertRaises(native.VerificationUnknown):
                first.service(issued)
            while first.step() == 1:
                first.service(first.pending)
            self.assertEqual(first.take(), None)
            second.service(second.pending)
            while second.step() == 1:
                second.service(second.pending)
            self.assertEqual(second.take(), None)
        finally:
            first.close(); second.close()

    def test_actual_native_claim_ack_and_result_store_loss_never_repeat_call(self):
        rows = []
        for boundary in ('claim', 'ack', 'observed-store'):
            calls = []; frame = self.profile_frame(calls); issued = frame.pending
            fault = KeyboardInterrupt('actual verification ' + boundary)
            actual_entry = self.image._entry; injected = []
            def entry(source, size, output, capacity, work, extent):
                command = struct.unpack_from('<Q', ctypes.string_at(work, extent))[0]
                answer = actual_entry(source, size, output, capacity, work, extent)
                if work is frame.state and command == (2 if boundary == 'claim' else 1):
                    injected.append(command); raise fault
                return answer
            offset = next(item.offset for item in dis.get_instructions(native.VerificationFrame.service)
                          if item.opname == 'STORE_FAST' and item.argval == 'observed')
            def trace(pyframe, event, arg):
                if pyframe.f_code is native.VerificationFrame.service.__code__:
                    pyframe.f_trace_opcodes = True
                    if event == 'opcode' and pyframe.f_lasti == offset:
                        injected.append(offset); raise fault
                return trace
            try:
                if boundary == 'observed-store':
                    prior = sys.gettrace(); arming = sys._getframe()
                    old_trace, old_opcodes = arming.f_trace, arming.f_trace_opcodes
                    arming.f_trace = trace; arming.f_trace_opcodes = True
                    sys.settrace(trace)
                    try:
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            frame.service(issued)
                    finally:
                        sys.settrace(prior)
                        arming.f_trace, arming.f_trace_opcodes = old_trace, old_opcodes
                else:
                    with patch.object(self.image, '_entry', entry), self.assertRaises(KeyboardInterrupt) as caught:
                        frame.service(issued)
                        if boundary == 'ack':
                            frame.step()
                self.assertIs(caught.exception, fault)
                self.assertEqual(len(injected), 1)
                self.assertEqual(len(calls), 0 if boundary == 'claim' else 1)
                self.assertTrue(frame._uncertain)
                before = bytes(frame.state)
                with self.assertRaises((native.VerificationUnknown, RuntimeError)):
                    frame.service(issued)
                self.assertEqual(bytes(frame.state), before)
                self.assertEqual(len(calls), 0 if boundary == 'claim' else 1)
                rows.append({'boundary': boundary, 'positive_injections': injected, 'calls': len(calls),
                             'state_sha256': sha256(before).hexdigest(), 'state_prefix': list(struct.unpack_from('<42Q', before))})
            finally:
                frame.close(release=False)
        self.record('actual-handoff-loss', rows)

    def test_reentrant_attempt_cannot_spend_outer_permission_and_scope_restores(self):
        calls = []; attempts = []; nested = []
        def callback():
            with self.assertRaises(native.VerificationUnknown):
                frame.service(issued)
            attempts.append('same-issued-refused')
            nested.append(self.image.run('_subject', SimpleNamespace(), {'subject': {'kind': 'core'}}, None, None))
        frame = self.profile_frame(calls, callback); issued = frame.pending
        frame.service(issued)
        while frame.step() == 1:
            frame.service(frame.pending)
        self.assertIsNone(frame.take()); frame.close()
        self.assertEqual(calls, [(('backend', 'backend'), {})])
        self.assertEqual(attempts, ['same-issued-refused']); self.assertEqual(nested, [None])
        self.assertIsNone(native.active_verification())

    def test_exception_matching_mechanism_failure_is_not_a_known_policy_error(self):
        record = {'context': 'ctx', 'installation': {}, 'candidate': 'candidate', 'validation_profile': 'validation',
                  'candidate_core_sha256': 'core', 'base_program': None, 'base_core_sha256': None,
                  'subject': {'kind': 'core'}, 'checks': []}
        class Service:
            identities = {}
            store = SimpleNamespace(get_json=lambda *a, **kw: (record, None))
            tools = {'hia_verify': {'outputSchema': {'properties': {'result': {'properties': {'checks': {}}}}}}}
            def _profile(self, *a, **kw): pass
            def _program(self, *a, **kw): return SimpleNamespace(sha256='core')
            def _subject(self, *a, **kw): pass
            def _context(self, *a, **kw): return {'target_profile': 'target'}
        error = api.AgentRejected('original-schema', 'original checks', 'checks')
        frame = self.image.prepare('_verification', (Service(), 'receipt', 'ctx', None, None))
        with patch.object(api, 'validate', side_effect=error), patch.object(api, 'proof_subject', return_value={}):
            status = frame.step()
            while status == 1 and frame._parts()[0] != 21:
                frame.service(frame.pending); status = frame.step()
            self.assertEqual(frame._parts()[0], 21)
            self.assertIs(frame.error, error)
            real_delivery = self.image._delivery
            replacement = RuntimeError('actual fixed delivery unavailable')
            with patch.object(self.image, '_delivery', SimpleNamespace(deliver=lambda value: (_ for _ in ()).throw(replacement))):
                with self.assertRaises(RuntimeError) as caught:
                    frame.service(frame.pending)
            self.assertIs(caught.exception, replacement)
            self.assertTrue(frame._uncertain); self.assertFalse(frame.completed)
            self.assertIs(self.image._delivery, real_delivery)
            with self.assertRaises(RuntimeError): frame.step()
        frame.close(release=False)

    def test_partial_actual_mapping_constructor_releases_only_own_resource(self):
        import hepta.hia_exception_delivery as delivery
        value = json.loads(self.manifest_path.read_bytes())
        raw = (self.manifest_path.parent / value['image_path']).read_bytes()
        rows = []
        for kind in (MemoryError, KeyboardInterrupt):
            error = kind('verification partial image'); references = []
            def refused(image):
                references.append(weakref.ref(image._mapping)); raise error
            with patch.object(delivery.ExceptionDelivery, 'from_hia', side_effect=refused):
                caught = None
                try:
                    native.NativeVerificationImage(raw, sha256(raw).hexdigest())
                except BaseException as observed:
                    caught = observed
                else:
                    self.fail('constructor fault did not propagate')
            self.assertIs(caught, error); self.assertIsNotNone(error.__traceback__)
            self.assertIsNotNone(references[0]()); self.assertTrue(references[0]().closed)
            rows.append({'error': kind.__name__, 'same_exception': True, 'mapping_closed_with_traceback_held': True})
        self.record('partial-image-cleanup', rows)

    def test_actual_same_length_emission_requests_do_not_select_business(self):
        from hepta.hia_exception_delivery import EMIT_REQUEST, CODE_BYTES, CODE_SHA256
        from tools.generate_hia_service_verification import program
        from tools.generate_hia_machine_plan_control import table
        request = struct.pack('<8Q', transport.EMIT_MAGIC, *([0] * 7))
        self.assertEqual(len(request), len(EMIT_REQUEST))
        self.assertNotEqual(request, EMIT_REQUEST)
        for label, raw in (('policy', request), ('delivery', EMIT_REQUEST), ('unknown', b'\0' * 64)):
            source = ctypes.create_string_buffer(raw + b'\xa5' * 16, 80)
            output = ctypes.create_string_buffer(b'\xb7' * ((1 << 20) + 16), (1 << 20) + 16)
            work = ctypes.create_string_buffer(b'\0' * 128 + b'\xc9' * 16, 144)
            result = self.image._entry(source, 64, output, 1 << 20, work, 128)
            self.assertEqual(source.raw, raw + b'\xa5' * 16)
            self.assertEqual(output.raw[1 << 20:], b'\xb7' * 16)
            self.assertEqual(work.raw[128:], b'\xc9' * 16)
            if label == 'policy':
                self.assertEqual(output.raw[:result], table(program()))
                self.assertEqual(output.raw[:result], self.image.table)
            elif label == 'delivery':
                self.assertEqual(result, CODE_BYTES)
                self.assertEqual(sha256(output.raw[:result]).hexdigest(), CODE_SHA256)
            else:
                self.assertEqual(result, ABI)

    def test_independent_vm_complete_protocol_frames_all_eight_modes(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(native.SOURCE.read_bytes())
        function = checked.as_dict()['functions'][0]
        rows = []
        for mode in range(1, 9):
            state = bytearray(self.image.workspace_bytes)
            output = bytearray(b'\xb7' * 2048)
            nonce = 7000 + mode; count = 0
            def call(command, flag=0, error=0, op=0):
                nonlocal count
                sequence = int.from_bytes(state[144:152], 'little')
                struct.pack_into('<6Q', state, 0, command, nonce, sequence,
                                 mode if command == 0 else op if command == 2 else flag, error, self.image.runtime_profile)
                raw = self.image.table
                src = ctypes.create_string_buffer(raw + b'\xa5' * 16, len(raw) + 16)
                out = ctypes.create_string_buffer(bytes(output) + b'\xb7' * 16, len(output) + 16)
                work = ctypes.create_string_buffer(bytes(state) + b'\xc9' * 16, len(state) + 16)
                actual = self.image._entry(src, len(raw), out, len(output), work, len(state))
                owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(output)), _Owner(-3, bytearray(state))]
                expected = _Machine(checked, 10000000, 16 << 20, None, 128).invoke(function,
                    [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
                self.assertEqual(actual, expected)
                self.assertEqual(out.raw[:len(output)], bytes(owners[1].data))
                self.assertEqual(work.raw[:len(state)], bytes(owners[2].data))
                self.assertEqual(src.raw, raw + b'\xa5' * 16)
                self.assertEqual(out.raw[len(output):], b'\xb7' * 16)
                self.assertEqual(work.raw[len(state):], b'\xc9' * 16)
                output[:] = owners[1].data; state[:] = owners[2].data; count += 1
                return actual
            self.assertEqual(call(0), 1)
            self.assertEqual(call(2, op=int.from_bytes(output[32:40], 'little')), 4)
            # Protocol-only failed first observation. A generated try/except
            # may first request its match-type GLOBAL and EXCEPTION_MATCH;
            # this transport supplies a declared non-match flag. It does not
            # claim an actual provider or exception-matching observation.
            status = call(1, error=1)
            while status == 1:
                self.assertIn(int.from_bytes(output[32:40], 'little'), (2, 16, 21, 28))
                self.assertEqual(call(2, op=int.from_bytes(output[32:40], 'little')), 4)
                status = call(1)
                self.assertLess(count, 512)
            self.assertEqual(status, 3)
            status = call(4)
            while status == 1:
                self.assertIn(int.from_bytes(output[32:40], 'little'), (16, 28))
                self.assertEqual(call(2, op=int.from_bytes(output[32:40], 'little')), 4)
                status = call(1); self.assertLess(count, 512)
            self.assertEqual(status, 5)
            rows.append({'mode': mode, 'frames': count, 'whole_output_and_workspace_equal': True,
                         'state_sha256': sha256(state).hexdigest(), 'output_sha256': sha256(output).hexdigest()})
        self.record('vm-native-eight-mode-error-retirement', rows)

    def test_installed_wheel_public_sqlite_proof_without_authoring_or_reference(self):
        from hepta.hia_agent_contract import (DISCOVERY_FILES, NATIVE_SOURCE_FILES,
            SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES)
        from tests.test_hia_program_native import minimal_document
        self.assertIn('examples/hia_bootstrap/service_verification.hepta', NATIVE_SOURCE_FILES)
        case = self.folder / 'installed-wheel'; case.mkdir(mode=0o700)
        source = case / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = (tuple('docs/' + item for item in DISCOVERY_FILES) + NATIVE_SOURCE_FILES
                     + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES)
        self.assertEqual(len(resources), len(set(resources)))
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        wheels, installed = case / 'wheels', case / 'installed'
        built = subprocess.run([packaging, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-index', '--no-build-isolation',
                                '--wheel-dir', str(wheels), str(source)], cwd=case, capture_output=True, timeout=120)
        (case / 'wheel-build.stdout').write_bytes(built.stdout); (case / 'wheel-build.stderr').write_bytes(built.stderr)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        wheel, = wheels.glob('*.whl')
        copied = subprocess.run([packaging, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index', '--target', str(installed), str(wheel)],
                                cwd=case, capture_output=True, timeout=120)
        (case / 'wheel-install.stdout').write_bytes(copied.stdout); (case / 'wheel-install.stderr').write_bytes(copied.stderr)
        self.assertEqual(copied.returncode, 0, copied.stdout + copied.stderr)
        selection = case / 'selection'; selection.mkdir(mode=0o700)
        manifest = json.loads(self.manifest_path.read_bytes())
        shutil.copyfile(self.manifest_path.parent / manifest['image_path'], selection / manifest['image_path'])
        (selection / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')
        (case / 'program.json').write_text(json.dumps(minimal_document(), sort_keys=True) + '\n')
        child_source = r'''import ctypes,hashlib,importlib.abc,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed verification imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_agent_service as api
from hepta import hia_service_verification_native as owner
from hepta.hia_checker_identity import checker_native_selection
from hepta.hia_agent_store import digest
from hepta.hia_program import verify_program
assert Path(sys.argv[1]) in owner.SOURCE.parents
def forbidden(*args,**kwargs):raise AssertionError('installed verification used retained policy')
for name in owner.ARITIES:setattr(api.HIAAgentService,name+'_reference',forbidden)
manifest=Path(sys.argv[2]);os.environ[owner.SELECTOR]=str(manifest)
service=api.HIAAgentService(sys.argv[3]);selected=service._native_verification
held=checker_native_selection(held_owners=service._held_checker_owners());calls={};entry=selected.image._entry
def counted(source,size,output,capacity,work,extent):
    answer=entry(source,size,output,capacity,work,extent)
    if size==len(selected.image.table) and extent==selected.image.workspace_bytes:
        mode=str(int.from_bytes(ctypes.string_at(work,extent)[152:160],'little'));calls[mode]=calls.get(mode,0)+1
    return answer
selected.image._entry=counted
examples=service._examples()
workload=service.store.json(examples['workload'],'workload')
objective=service.store.json(examples['objective'],'objective')
cost=service.store.json(examples['cost_policy'],'cost-policy')
frozen=service._hia_context({'compiler_profile':service.profiles['compiler'],'target_profile':service.profiles['target'],
    'baseline_program':None,'workload':workload,'objective':objective,
    'budget':{'max_candidates':3,'max_model_tokens':10,'max_total_wall_ms':300000,
              'max_native_wall_ms':1000,'max_memory_bytes':str(64*1024**2),'cost_policy':cost}})
verified=verify_program(Path(sys.argv[4]).read_bytes())
candidate=service.store.put(verified.canonical_bytes,'core',{'context':frozen['context']})
args={'candidate':candidate,'context':frozen['context'],'base_program':None,'subject':{'kind':'core'},
      'validation_profile':service.profiles['validation'],'claims':['core_admission']}
before=service.store.db.execute('SELECT COALESCE(MAX(rowid),0) FROM artifacts').fetchone()[0]
proved=service._hia_verify(args)
kinds=[row[0] for row in service.store.db.execute('SELECT kind FROM artifacts WHERE rowid>? ORDER BY rowid',(before,))]
assert kinds==['verification-assumptions','verification-evidence','verification-receipt'],kinds
evidence=service.store.get_json(proved['checks'][0]['evidence_artifact'])[0]
assert evidence['native_checker_selection']==held
assert proved['checks'][0]['checker']['native_selection_sha256']==digest(held)
service._verification(proved['verification_receipt'],frozen['context'],candidate)
os.environ[owner.SELECTOR]=''
service._verification(proved['verification_receipt'],frozen['context'],candidate)
assert checker_native_selection(held_owners=service._held_checker_owners())==held
os.environ[owner.SELECTOR]=str(manifest);assert owner.admitted_verification() is selected.image
selection=json.loads(manifest.read_bytes());image=manifest.parent/selection['image_path'];refusals=[]
for label,path in [('image',image),('source',owner.SOURCE)]:
    raw=path.read_bytes();path.write_bytes(raw+b'changed');state=Path(sys.argv[3]+'-refused-'+label)
    try:
        try:api.HIAAgentService(state)
        except ValueError:refusals.append(label)
        else:raise AssertionError('changed selected '+label+' admitted')
        assert not state.exists()
        service._verification(proved['verification_receipt'],frozen['context'],candidate)
        assert checker_native_selection(held_owners=service._held_checker_owners())==held
    finally:path.write_bytes(raw)
assert refusals==['image','source']
assert {'1','2','3'}<=set(calls) and all(number>0 for number in calls.values()),calls
assert not any(name=='tools' or name.startswith('tools.') for name in sys.modules)
selected.image._entry=entry;service.close()
print(json.dumps({'actual_entries':calls,'proof':proved,'evidence':evidence,'kinds':kinds,'warm_refusals':refusals,
    'held_owner':held[owner.SELECTOR],'installed_source':str(owner.SOURCE),'reference_called':False,
    'authoring_imported':False,'whole_stack_native':False},sort_keys=True))
'''
        (case / 'installed-control.py').write_text(child_source)
        env = {key: value for key, value in os.environ.items() if not key.startswith('HEPTA_HIA_')}
        child = subprocess.run([sys.executable, '-I', '-S', '-B', str(case / 'installed-control.py'), str(installed),
            str(selection / 'manifest.json'), str(case / 'state'), str(case / 'program.json')], cwd=case, env=env,
            capture_output=True, text=True, timeout=30)
        (case / 'actual.stdout').write_text(child.stdout); (case / 'actual.stderr').write_text(child.stderr)
        self.assertEqual(child.returncode, 0, child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(result['kinds'], ['verification-assumptions', 'verification-evidence', 'verification-receipt'])
        self.record('installed-wheel', {'wheel': {'path': str(wheel), 'bytes': wheel.stat().st_size,
                    'sha256': sha256(wheel.read_bytes()).hexdigest()}, 'result': result})
