"""New recovery controls for exact proof policy and fixed hosted mechanisms.

Every original failed/lost run remains separate. This file supplies a new
permanent suite; its results never stand in for the unchanged 22+18 caller gate.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
from copy import deepcopy
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

from hepta import hia_proof_contract as api
from hepta import hia_proof_contract_native as native
from hepta import hia_proof_contract_selection as selection
from hepta import hia_machine_plan_control_native as transport
from tests import hia_proof_contract_fixtures as fixtures

ROOT = Path(__file__).resolve().parents[1]
ABI = 0xfffffffd


class ProofContractSourceTests(unittest.TestCase):
    def test_eight_original_bodies_policy_and_signatures_are_exact(self):
        original = fixtures.ORIGINAL.read_bytes()
        self.assertEqual(sha256(original).hexdigest(), fixtures.ORIGINAL_SHA)
        oracle = {n.name: n for n in ast.parse(original).body if isinstance(n, ast.FunctionDef)}
        authored = {n.name: n for n in ast.parse((ROOT / 'tools/hia_proof_contract_policy.py').read_bytes()).body
                    if isinstance(n, ast.FunctionDef)}
        public = {n.name: n for n in ast.parse((ROOT / 'hepta/hia_proof_contract.py').read_bytes()).body
                  if isinstance(n, ast.FunctionDef)}
        self.assertEqual(tuple(oracle), tuple(native.ARITIES))
        self.assertEqual(tuple(authored), tuple(native.ARITIES))
        for name, expected in oracle.items():
            retained = public[name + '_reference']; retained.name = name
            with self.subTest(name=name):
                self.assertEqual(ast.dump(expected), ast.dump(retained))
                self.assertEqual(ast.dump(expected), ast.dump(authored[name]))
                self.assertEqual(ast.dump(expected.args), ast.dump(public[name].args))

    def test_actual_hia_regenerates_all_sixteen_frames(self):
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        from tools.generate_hia_proof_contract import document, program
        from tools.generate_hia_machine_plan_control import table
        value = program()
        self.assertEqual(len(value.functions), 16)
        self.assertEqual(sum(fn.kind == 'generator' for fn in value.functions), 8)
        rendered = render_assembly(document()).encode()
        self.assertEqual(rendered, native.SOURCE.read_bytes())
        self.assertLessEqual(len(assemble_program(rendered).as_dict()['functions']), 128)
        self.assertGreater(len(table(value)), 64)

    def test_runtime_has_no_authoring_or_old_body_evaluation(self):
        for name in ('hepta/hia_proof_contract_native.py', 'hepta/hia_proof_contract_foreign.py',
                     'hepta/hia_proof_contract_selection.py'):
            for node in ast.walk(ast.parse((ROOT / name).read_bytes())):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse((node.module or '').startswith(('tools', 'tests')))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, ('eval', 'exec', 'compile'))
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, {key + '_reference' for key in native.ARITIES})
        from hepta.hia_checker_identity import HELD_NATIVE_OWNERS, NATIVE_OWNERS
        from hepta.hia_native_helpers import HELPERS
        row = ('hia_proof_contract_native', 'NativeProofContractImage')
        self.assertEqual(HELD_NATIVE_OWNERS[native.SELECTOR], row)
        self.assertEqual(HELPERS[native.SELECTOR], row)
        self.assertNotIn(native.SELECTOR, NATIVE_OWNERS)

    def test_public_capture_and_consumer_scope_are_explicit(self):
        tree = ast.parse((ROOT / 'hepta/hia_agent_service.py').read_bytes())
        service = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'HIAAgentService')
        methods = {n.name: n for n in service.body if isinstance(n, ast.FunctionDef)}
        self.assertIn('_native_proof_contract', {n.attr for n in ast.walk(methods['__init__']) if isinstance(n, ast.Attribute)})
        for name in ('_profiles', '_subject', '_hia_verify', '_verification', '_replay_verification',
                     '_required_claims', '_check_native_refinement_evidence'):
            with self.subTest(name=name):
                consumer = methods[name]
                if name == '_profiles':
                    # Requests now owns this complete original policy. Check
                    # both routes and the exact policy body, including the
                    # proof scope, instead of requiring it in the thin route.
                    retained = deepcopy(methods['_profiles_reference'])
                    retained.name = name
                    policy = next(n for n in ast.parse(
                        (ROOT / 'tools/hia_service_requests_policy.py').read_bytes()).body
                        if isinstance(n, ast.ClassDef))
                    lowered = next(n for n in policy.body if isinstance(n, ast.FunctionDef) and n.name == name)
                    self.assertEqual(ast.dump(retained), ast.dump(lowered))
                    self.assertIn('_profiles_reference', {n.attr for n in ast.walk(consumer)
                        if isinstance(n, ast.Attribute)})
                    self.assertTrue(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                        and isinstance(n.func.value, ast.Name) and n.func.value.id == 'owner'
                        and n.func.attr == 'prepare' and n.args
                        and isinstance(n.args[0], ast.Constant) and n.args[0].value == name
                        for n in ast.walk(consumer)))
                    self.assertTrue(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                        and isinstance(n.func.value, ast.Name) and n.func.value.id == 'owner'
                        and n.func.attr == 'finish' for n in ast.walk(consumer)))
                    consumer = lowered
                self.assertTrue(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                                    and n.func.id == 'proof_contract_scope' for n in ast.walk(consumer)))
        self.assertTrue(any(isinstance(n, ast.Constant) and n.value == '_native_proof_contract'
                            for n in ast.walk(methods['_held_checker_owners'])))
        self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                             and n.func.id == 'proof_contract_scope'
                             for n in ast.walk(methods['_native_refinement_binding'])))

    def test_core_and_mechanism_roles_have_exact_provider_edges(self):
        from hepta import hia_checker_identity as identity
        core = set(identity.CORE_SOURCE_FILES); mechanisms = set(identity.CHECKER_MECHANISM_SOURCE_FILES)
        self.assertEqual((len(core), len(mechanisms), len(core | mechanisms)), (54, 25, 79))
        self.assertFalse(core & mechanisms)
        providers = identity.CHECKER_MECHANISM_EXTERNAL_PROVIDERS
        for filename in mechanisms:
            dependencies = set()
            for node in ast.walk(ast.parse((ROOT / 'hepta' / filename).read_bytes())):
                if isinstance(node, ast.ImportFrom) and node.level == 1:
                    if node.module:
                        dependencies.add(node.module + '.py')
                    else:
                        dependencies.update(alias.name + '.py' for alias in node.names)
            with self.subTest(filename=filename):
                self.assertEqual(dependencies - core - mechanisms, set(providers.get(filename, ())))
        self.assertEqual(set(identity.checker_source_identity()), core | mechanisms)

    def test_every_mechanism_remains_in_all_nine_checker_digests(self):
        from hepta import (hia_checker_identity as identity, hia_optimization, hia_program_llvm,
            hia_program_native, hia_bounded_unroll, hia_scalar_lowering_check, hia_x86_search,
            hia_finite_context, hia_safe_core, hia_scalar_proof_contract)
        checkers = (hia_optimization.checker_identity, hia_program_llvm._implementation_hash,
            hia_program_native._implementation_hash, hia_bounded_unroll.checker_identity,
            hia_scalar_lowering_check.checker_identity, hia_x86_search._implementation_hash,
            hia_finite_context._implementation, hia_safe_core._checker_source_identity,
            lambda: hia_scalar_proof_contract._source_identity('validate_translation'))
        original_read = Path.read_bytes
        for filename in identity.CHECKER_MECHANISM_SOURCE_FILES:
            def changed(path):
                raw = original_read(path)
                return raw + b'\n# controlled source observation\n' if path.name == filename else raw
            for checker in checkers:
                before = checker()
                with self.subTest(filename=filename, checker=checker.__module__), patch.object(Path, 'read_bytes', changed):
                    self.assertNotEqual(before, checker())

    def test_invalid_selected_manifest_cannot_create_service_state(self):
        from hepta import hia_agent_service
        with tempfile.TemporaryDirectory(prefix='proof-selection-source-') as directory:
            state = Path(directory) / 'not-created'
            env = {key: '' for key in os.environ if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST')}
            env[native.SELECTOR] = str(Path(directory) / 'missing')
            with patch.dict(os.environ, env), patch.object(hia_agent_service, 'catalog',
                    side_effect=AssertionError('catalog entered')):
                with self.assertRaises(OSError):
                    hia_agent_service.HIAAgentService(state)
            self.assertFalse(state.exists())


class ProofContractNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools import build_hia_proof_contract as builder
        cold = os.environ.get('HEPTA_HIA_PROOF_CONTRACT_COLD_REPORT')
        compiler_choice = os.environ.get('HEPTA_HIA_PROOF_CONTRACT_DEVELOPMENT_COMPILER')
        manifest_choice = os.environ.get('HEPTA_HIA_PROOF_CONTRACT_DEVELOPMENT_MANIFEST')
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
                raise ValueError('proof-contract cold report lacks a compiler') from error
            compiler_bytes = compiler.read_bytes()
            sources = builder.admit_cold_build(compiler_bytes, cold_bytes)
            if (type(report.get('qualification_wall_limit_seconds')) is not int or report['qualification_wall_limit_seconds'] != 180
                    or type(report.get('cleanup_wall_limit_seconds')) is not int or report['cleanup_wall_limit_seconds'] != 3
                    or any(sources.get(name) != sha256((ROOT / name).read_bytes()).hexdigest() for name in builder.REQUIRED_SOURCE_NAMES)):
                raise ValueError('proof-contract fixture requires complete original-limit current cold source')
            cls.inputs.update({str(cold): sha256(cold_bytes).hexdigest(), str(nested): sha256(nested_bytes).hexdigest(),
                               str(compiler): sha256(compiler_bytes).hexdigest()})
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_PROOF_CONTRACT_EVIDENCE')
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
        cls.image = native.installed_proof_contract(cls.manifest_path)
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
            stack.enter_context(patch.object(api, name + '_reference', self.forbidden))

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


    def effect_frame(self, calls, callback=None):
        class Condition:
            def __bool__(condition):
                calls.append('truth')
                if callback is not None:
                    callback()
                return True
        frame = self.image.prepare('_require', (Condition(), 'controlled message'))
        status = frame.step()
        while status == 1 and frame._parts()[0] != 8:
            frame.service(frame.pending); status = frame.step()
        self.assertEqual(status, 1)
        self.assertEqual(frame._parts()[0], 8)
        return frame

    def test_new_controlled_corpus_matches_all_eight_original_policy_roots(self):
        module = fixtures.reference_module()
        module.checker_native_selection = lambda **ignored: {}
        rows = []
        with self.independent_environment(), ExitStack() as stack:
            stack.enter_context(patch.object(api, 'checker_native_selection', lambda **ignored: {}))
            self.poison_references(stack)
            for label, name, args in fixtures.cases():
                expected = fixtures.observe(lambda: fixtures.call_reference(module, name, deepcopy(args)))
                actual = fixtures.observe(lambda: self.image.run(name, *deepcopy(args)))
                rows.append({'label': label, 'entry': name, 'expected': expected, 'actual': actual,
                             'match': actual == expected})
                with self.subTest(label=label):
                    self.assertEqual(actual, expected)
        self.assertEqual({row['entry'] for row in rows}, set(native.ARITIES))
        self.record('new-controlled-policy-corpus', rows)

    def test_public_global_replacement_and_deletion_are_observed(self):
        module = fixtures.reference_module()
        args = ('core_admission', 'proved', 'domain', fixtures.subject(), {}, {},
                {'checker': api._CHECKERS['core_admission'], 'core_sha256': 'c' * 64,
                 'native_checker_selection': {}}, ())
        rows = []
        for kind in ('replace', 'delete'):
            for outer in (False, True):
                traces = []
                def run(native_route):
                    target = api if native_route else module
                    trace = []; traces.append(trace)
                    def changed(identity, statement):
                        trace.append(identity)
                        return {'id': identity, 'statement': statement}
                    with ExitStack() as stack:
                        stack.enter_context(patch.object(target, 'checker_native_selection', lambda **ignored: {}))
                        if kind == 'replace':
                            stack.enter_context(patch.object(target, '_item', changed))
                        else:
                            previous = target._item
                            del target._item
                            stack.callback(setattr, target, '_item', previous)
                        def call():
                            return (self.image.run('proof_result', *deepcopy(args)) if native_route else
                                    fixtures.call_reference(module, 'proof_result', deepcopy(args)))
                        if outer:
                            try:
                                raise LookupError('outer handler')
                            except LookupError:
                                return fixtures.observe(call)
                        return fixtures.observe(call)
                expected, actual = run(False), run(True)
                self.assertEqual(actual, expected)
                self.assertEqual(traces[0], traces[1])
                rows.append({'kind': kind, 'outer': outer, 'expected': expected, 'actual': actual,
                             'expected_trace': traces[0], 'actual_trace': traces[1]})
        self.record('public-global-observations', rows)

    def test_generator_stopiteration_and_error_cause_use_real_python_generator(self):
        module = fixtures.reference_module()
        rows = []
        for kind in (StopIteration, LookupError):
            for outer in (False, True):
                def run(native_route):
                    class Row:
                        def get(row, name):
                            raise kind('controlled generator callback')
                    evidence = {'schema': 'hepta.hia.optimization-verification.v1', 'status': 'verified',
                        'base_sha256': 'c' * 64, 'candidate_sha256': 'c' * 64, 'checker_sha256': 'k',
                        'solver': {}, 'claims': {'core_scalar_effect_equivalence_checked': True},
                        'resource_delta': {'resource_trace_equivalence_checked': True}, 'obligations': [Row()]}
                    arguments = ('behavior_equivalence', 'proved', fixtures.subject(), evidence)
                    def call():
                        return self.image.run('_method', *arguments) if native_route else module._method(*arguments)
                    if outer:
                        try: raise OSError('outer')
                        except OSError: return fixtures.observe(call)
                    return fixtures.observe(call)
                expected, actual = run(False), run(True)
                self.assertEqual(actual, expected)
                rows.append({'error': kind.__name__, 'outer': outer, 'expected': expected, 'actual': actual})
        self.record('real-generator-errors', rows)

    def test_success_retirement_ignores_outer_handler_and_error_keeps_original_locals(self):
        module = fixtures.reference_module()
        rows = []
        for outer in (False, True):
            def normal():
                frame = self.image.prepare('_item', ('id', 'statement'))
                value = self.image.finish(frame)
                self.assertTrue(frame._retired)
                self.assertEqual(value, {'id': 'id', 'statement': 'statement'})
            if outer:
                try: raise LookupError('outer')
                except LookupError: normal()
            else: normal()
            def run(native_route):
                trace = []
                class Condition:
                    def __bool__(condition):
                        raise LookupError('condition failed')
                    def __del__(condition):
                        trace.append(None if sys.exception() is None else type(sys.exception()).__name__)
                def call():
                    return (self.image.run('_require', Condition(), 'unused') if native_route else
                            module._require(Condition(), 'unused'))
                def captured():
                    try: call()
                    except LookupError as error: return error
                    raise AssertionError('missing original error')
                error = captured()
                before = list(trace)
                error.__traceback__ = None
                error = None
                return {'held': before, 'released': list(trace)}
            if outer:
                try: raise OSError('outer')
                except OSError: expected, actual = run(False), run(True)
            else:
                expected, actual = run(False), run(True)
            self.assertEqual(actual, expected)
            rows.append({'outer': outer, 'expected': expected, 'actual': actual})
        self.record('physical-handler-and-traceback-lifetime', rows)

    def test_exact_held_capability_is_required_and_conflicts_are_rejected(self):
        from hepta.hia_checker_identity import checker_native_selection
        with self.independent_environment(self.manifest_path):
            first = selection.capture_proof_contract()
            second = selection.capture_proof_contract()
        self.assertIs(first.image, second.image)
        self.assertIsNot(first.custody, second.custody)
        self.assertEqual(first.bind_checker_owners((first.custody,)), (first.custody,))
        invalid = []; self.assertIs(first.bind_checker_owners(invalid), invalid)
        duplicate = (first.custody, first.custody)
        self.assertIs(first.bind_checker_owners(duplicate), duplicate)
        with self.independent_environment():
            with self.assertRaises(ValueError):
                checker_native_selection(held_owners=duplicate)
            with self.assertRaises(ValueError):
                checker_native_selection(held_owners=first.bind_checker_owners((second.custody,)))
            held = checker_native_selection(held_owners=(first.custody,))
            evidence = {'checker': api._CHECKERS['core_admission'], 'core_sha256': 'c' * 64,
                        'native_checker_selection': checker_native_selection()}
            arguments = dict(claim='core_admission', status='proved', domain='domain',
                             subject=fixtures.subject(), profile={}, installation={}, evidence=evidence)
            with selection.proof_contract_scope(first):
                from hepta.hia_agent_store import AgentRejected
                with self.assertRaises(AgentRejected):
                    api.proof_result(**arguments)
                evidence['native_checker_selection'] = held
                value = api.proof_result(**arguments)
            self.assertEqual(value['checker']['native_selection_sha256'], api.digest(held))
        self.record('held-capability', {'manifest_sha256': sha256(first.custody.manifest).hexdigest(), 'selected': held})

    def test_service_captured_absence_and_held_image_survive_environment_drift(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_checker_identity import checker_native_selection
        case = self.identity_files('held')
        with self.independent_environment():
            absent = HIAAgentService(self.folder / 'captured-none')
            try:
                self.assertIsNone(absent._native_proof_contract)
                with patch.dict(os.environ, {native.SELECTOR: '/unread-new-selection'}):
                    absent._profiles()
            finally:
                absent.close()
        with self.independent_environment(case.manifest):
            service = HIAAgentService(self.folder / 'captured-proof')
        try:
            owner = service._native_proof_contract
            self.assertIsNotNone(owner)
            held = checker_native_selection(held_owners=service._held_checker_owners())
            raw = case.image.read_bytes(); case.image.write_bytes(raw + b'changed')
            with self.independent_environment('/unread-new-selection'):
                with selection.proof_contract_scope(owner):
                    self.assertEqual(api.proof_subject(fixtures.record(), {}), api.proof_subject_reference(fixtures.record(), {}))
                self.assertEqual(checker_native_selection(held_owners=service._held_checker_owners()), held)
            with self.independent_environment(case.manifest), self.assertRaises(ValueError):
                HIAAgentService(self.folder / 'changed-image-refused')
            case.image.write_bytes(raw)
        finally:
            service.close()
        self.assertTrue(owner.closed)
        with selection.proof_contract_scope(owner), self.assertRaises(native.ProofContractUnknown):
            api.proof_contract_description()

    def test_exact_issued_object_and_raw_payload_precede_foreign_effect(self):
        calls = []; first = self.effect_frame(calls); second = self.effect_frame(calls)
        try:
            issued = first.pending
            for supplied in (replace(issued), second.pending, SimpleNamespace(raw=issued.raw)):
                with self.assertRaises(native.ProofContractUnknown): first.service(supplied)
            raw = issued.raw
            object.__setattr__(issued, 'raw', raw[:16] + bytes((raw[16] ^ 1,)) + raw[17:])
            with self.assertRaises(native.ProofContractUnknown): first.service(issued)
            object.__setattr__(issued, 'raw', raw)
            self.assertEqual(calls, [])
            first.service(issued)
            self.assertEqual(calls, ['truth'])
            with self.assertRaises(native.ProofContractUnknown): first.service(issued)
            while first.step() == 1: first.service(first.pending)
            self.assertIsNone(first.take())
            second.service(second.pending)
            while second.step() == 1: second.service(second.pending)
            self.assertIsNone(second.take())
            self.assertEqual(calls, ['truth', 'truth'])
        finally:
            first.close(); second.close()

    def test_reentry_does_not_reuse_permission_and_scope_resets_after_error(self):
        calls = []; attempts = []
        def callback():
            with self.assertRaises(native.ProofContractUnknown): frame.service(issued)
            attempts.append(self.image.run('_item', 'nested', 'allowed separate frame'))
        frame = self.effect_frame(calls, callback); issued = frame.pending
        frame.service(issued)
        while frame.step() == 1: frame.service(frame.pending)
        self.assertIsNone(frame.take()); frame.close()
        self.assertEqual(calls, ['truth'])
        self.assertEqual(attempts, [{'id': 'nested', 'statement': 'allowed separate frame'}])
        with self.independent_environment():
            self.assertIsNone(selection.selected_proof_contract())
            with self.assertRaises(LookupError):
                with selection.proof_contract_scope(None):
                    raise LookupError('scope exit')
            self.assertIsNone(selection.selected_proof_contract())
    def test_actual_native_claim_ack_and_result_store_loss_never_repeat_call(self):
        rows = []
        for boundary in ('claim', 'ack', 'observed-store'):
            calls = []; frame = self.effect_frame(calls); issued = frame.pending
            fault = KeyboardInterrupt('actual verification ' + boundary)
            actual_entry = self.image._entry; injected = []
            def entry(source, size, output, capacity, work, extent):
                command = struct.unpack_from('<Q', ctypes.string_at(work, extent))[0]
                answer = actual_entry(source, size, output, capacity, work, extent)
                if work is frame.state and command == (2 if boundary == 'claim' else 1):
                    injected.append(command); raise fault
                return answer
            offset = next(item.offset for item in dis.get_instructions(native.ProofContractFrame.service)
                          if item.opname == 'STORE_FAST' and item.argval == 'observed')
            def trace(pyframe, event, arg):
                if pyframe.f_code is native.ProofContractFrame.service.__code__:
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
                with self.assertRaises((native.ProofContractUnknown, RuntimeError)):
                    frame.service(issued)
                self.assertEqual(bytes(frame.state), before)
                self.assertEqual(len(calls), 0 if boundary == 'claim' else 1)
                rows.append({'boundary': boundary, 'positive_injections': injected, 'calls': len(calls),
                             'state_sha256': sha256(before).hexdigest(), 'state_prefix': list(struct.unpack_from('<42Q', before))})
            finally:
                frame.close(release=False)
        self.record('actual-handoff-loss', rows)

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
                    native.NativeProofContractImage(raw, sha256(raw).hexdigest())
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
        from tools.generate_hia_proof_contract import program
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

    def test_independent_vm_complete_protocol_frames_all_sixteen_modes(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(native.SOURCE.read_bytes())
        function = checked.as_dict()['functions'][0]
        rows = []
        for mode in range(1, 17):
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
        self.record('vm-native-sixteen-mode-error-retirement', rows)

    def test_replacement_exception_delivery_cannot_acknowledge_known_policy_error(self):
        import importlib
        subject, evidence = fixtures.safe_core_case('proved')
        frame = self.image.prepare('_safe_core_method', ('proved', subject, evidence))
        original = LookupError('controlled importlib provider exception')
        real_import = importlib.import_module
        def import_failure(name, *args, **kwargs):
            if name == 'z3': raise original
            return real_import(name, *args, **kwargs)
        try:
            with patch.object(importlib, 'import_module', import_failure):
                status = frame.step()
                while status == 1 and frame._parts()[0] != 21:
                    frame.service(frame.pending); status = frame.step()
                self.assertEqual(status, 1)
                self.assertEqual(frame._parts()[0], 21)
                self.assertIs(frame.error, original)
                replacement = RuntimeError('fixed delivery unavailable')
                class Broken:
                    def deliver(self, value): raise replacement
                with patch.object(self.image, '_delivery', Broken()):
                    with self.assertRaises(RuntimeError) as caught:
                        frame.service(frame.pending)
                self.assertIs(caught.exception, replacement)
                self.assertTrue(frame._uncertain)
                self.assertFalse(frame.completed)
                with self.assertRaises(RuntimeError): frame.step()
        finally:
            frame.close(release=False)

    def test_installed_wheel_public_sqlite_proof_without_authoring_or_reference(self):
        from hepta.hia_agent_contract import (DISCOVERY_FILES, NATIVE_SOURCE_FILES,
            SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES)
        from tests.test_hia_program_native import minimal_document
        self.assertIn('examples/hia_bootstrap/proof_contract.hiaasm', NATIVE_SOURCE_FILES)
        case = self.folder / 'installed-wheel'; case.mkdir(mode=0o700)
        source = case / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = (tuple('docs/' + item for item in DISCOVERY_FILES) + NATIVE_SOURCE_FILES
                     + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES)
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
from hepta import hia_proof_contract as proof_api
from hepta import hia_proof_contract_native as owner
from hepta.hia_checker_identity import checker_native_selection
from hepta.hia_agent_store import digest
from hepta.hia_program import verify_program
assert Path(sys.argv[1]) in owner.SOURCE.parents
def forbidden(*args,**kwargs):raise AssertionError('installed verification used retained policy')
for name in owner.ARITIES:setattr(proof_api,name+'_reference',forbidden)
manifest=Path(sys.argv[2]);os.environ[owner.SELECTOR]=str(manifest)
service=api.HIAAgentService(sys.argv[3]);selected=service._native_proof_contract
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
os.environ[owner.SELECTOR]=str(manifest);assert owner.admitted_proof_contract() is selected.image
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
assert {'1','2','4','5','6','7'}<=set(calls) and all(number>0 for number in calls.values()),calls
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


if __name__ == '__main__':
    unittest.main()
