"""Independent retained references, real SQLite and actual HIA continuations.

The bounded store below is a controlled artifact/profile provider, not a claim
to execute the native byte publisher. SQLite and the selected HIA image are real.
Original whole Agent tests remain a separate integration gate.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
from copy import deepcopy
import ctypes
import dis
from dataclasses import replace
from hashlib import sha256
import importlib.util
import json
import inspect
import os
from pathlib import Path
import random
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import weakref
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta.hia_agent_store import AgentRejected, wire
from hepta.hia_execution_budget import _ReferenceExecutionBudgetStore
from hepta.hia_service_context_native import (SOURCE, SCHEMA, SELECTOR, REQUEST_MAGIC,
    RESULT_MAGIC, NativeContextImage, NativeContextService, ContextState, ContextUnknown,
    ContextReceipt, admitted_context)

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / 'tests/fixtures/hia_service_context_original_v74.json'


def original_class():
    raw = ORIGINAL.read_bytes()
    assert sha256(raw).hexdigest() == 'b93b703657d1354aa0d65e5625da35581c548645c7f237ae94d160740baabace'
    fixture = json.loads(raw)
    assert fixture['source_sha256'] == 'd5a4a19fe4fe4882dd4e7b5a4e4fd3ed63948d982c092b587a1078c29e874b17'
    methods = {}
    for name, source in fixture['methods'].items():
        namespace = dict(vars(api))
        exec(compile(source, str(ORIGINAL), 'exec'), namespace)
        methods[name] = namespace[name]
    return type('RetainedV74Reference', (), methods)


REFERENCE = original_class()


def fixtures():
    workload = {'schema': 'hepta.hia.agent.workload.v1',
        'cases': [{'function': 'identity', 'arguments': [23],
                   'expected': {'status': 'returned', 'values': [23]}}],
        'warmup_iterations': 0, 'repetitions': 1}
    objective = {'schema': 'hepta.hia.agent.objective.v1', 'metric': 'artifact_bytes',
        'required_claims': ['core_admission', 'encoding_check'],
        'allow_unchanged': True, 'min_improvement_ratio': 0.0}
    cost = {'schema': 'hepta.hia.agent.cost-policy.v1',
        'external_costs': {'model_tokens': None, 'model_wall_ns': None, 'discovery_wall_ns': None},
        'external_costs_complete': False, 'expected_invocations': '0'}
    args = {'compiler_profile': {'id': 'compiler', 'sha256': '1' * 64},
        'target_profile': {'id': 'target', 'sha256': '2' * 64}, 'baseline_program': None,
        'workload': 'workload', 'objective': 'objective',
        'budget': {'max_candidates': 3.0, 'max_model_tokens': 9.0,
                   'max_total_wall_ms': 3000.0, 'max_native_wall_ms': 1000.0,
                   'max_memory_bytes': str(64 * 1024**2), 'cost_policy': 'cost'}}
    return args, {'workload': workload, 'objective': objective, 'cost': cost}


class DB:
    def __init__(self, trace):
        self.connection = sqlite3.connect(':memory:', isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.trace, self.fault = trace, None
        self.connection.executescript('''CREATE TABLE contexts(id TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL, artifact TEXT NOT NULL, created_ns TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE execution_budgets(context_id TEXT PRIMARY KEY, used_native_ns TEXT NOT NULL, owner TEXT);''')

    def execute(self, statement, parameters=()):
        self.trace.append(('sql', statement, parameters))
        if self.fault:
            self.fault('before', statement, parameters)
        cursor = self.connection.execute(statement, parameters)
        if self.fault:
            self.fault('after', statement, parameters)
        return cursor


class ControlledStore:
    def __init__(self, trace, values):
        self.trace, self.values = trace, values
        self.db = DB(trace)
        self.execution_budgets = _ReferenceExecutionBudgetStore(self)
        self.published = []
        self.before_publish = self.after_publish = None

    def get_json(self, ref, *, kind=None, _connection=None):
        self.trace.append(('get_json', ref, kind, _connection is not None))
        if type(ref) is dict:
            return deepcopy(self.published[int(ref['id'][2:])]), {'kind': kind}
        return self.values[ref], {'kind': kind}

    def json(self, value, kind):
        self.trace.append(('publish', kind))
        if self.before_publish:
            self.before_publish(value)
        self.published.append(deepcopy(value))
        ref = {'id': 'a-' + str(len(self.published) - 1), 'sha256': sha256(wire(value)).hexdigest(),
               'uri': 'hia://artifacts/controlled'}
        if self.after_publish:
            self.after_publish(value, ref)
        return ref


def service_fixture():
    args, values = fixtures()
    trace = []
    service = SimpleNamespace(catalog_sha256='a' * 64, identities={'worker': 'b' * 64})
    service.store = ControlledStore(trace, values)
    service._profile = lambda ref, kind, **kw: trace.append(('profile', kind, ref, bool(kw)))
    service._program = lambda ref: SimpleNamespace(sha256='c' * 64)
    return service, args, trace


def stable_environment(trace, *, now=1_000_000_000):
    stack = ExitStack()
    stack.enter_context(patch.object(api, '_now', side_effect=lambda: trace.append(('sampled',)) or 'fixed-sample'))
    # The original module has the same global imported module objects; its
    # local _now is patched separately by reference_run below.
    stack.enter_context(patch.object(api.time, 'time_ns', side_effect=lambda: trace.append(('clock', now)) or now))
    stack.enter_context(patch.object(api.uuid, 'uuid4', side_effect=lambda: trace.append(('uuid',)) or SimpleNamespace(hex='1' * 32)))
    stack.enter_context(patch.object(api.platform, 'system', side_effect=lambda: trace.append(('system',)) or 'Linux'))
    stack.enter_context(patch.object(api.platform, 'machine', side_effect=lambda: trace.append(('machine',)) or 'x86_64'))
    stack.enter_context(patch.object(api.os, 'cpu_count', side_effect=lambda: trace.append(('cpu_count',)) or 8))
    return stack


def reference_run(method, service, *args, **kwargs):
    function = getattr(REFERENCE, method)
    with patch.dict(function.__globals__, {'_now': api._now}):
        return function(service, *args, **kwargs)


def observed(call):
    try:
        return {'value': call(), 'error': None}
    except Exception as error:
        return {'value': None, 'error': (type(error).__name__, str(error), getattr(error, 'code', None))}


def snapshot(service, args, trace, outcome):
    return {'outcome': outcome, 'args': args, 'trace': trace,
        'published': service.store.published,
        'contexts': [tuple(row) for row in service.store.db.connection.execute('SELECT * FROM contexts')],
        'budgets': [tuple(row) for row in service.store.db.connection.execute('SELECT * FROM execution_budgets')]}


def foreign_numeric_lifetimes(image):
    held, rows = [], []
    def observe(method, phase, outer_on, native):
            service, _, sql_trace = service_fixture()
            service.store.db.connection.execute('INSERT INTO contexts VALUES (?,?,?,?,0)',
                                                ('x', 'hash', '{}', '100'))
            events, refs = [], []
            outer = LookupError('original outer') if outer_on else None
            def event(*parts):
                events.append(parts)
            class Value:
                def __init__(self, label):
                    self.label, self.sink, self.outer = label, events, outer
                    refs.append((label, weakref.ref(self)))
                def __del__(self):
                    self.sink.append(('del', self.label, sys.exception() is self.outer))
            class Truth(Value):
                def __init__(self): super().__init__('truth')
                def __bool__(self):
                    event('truth')
                    return False
            class Quotient(Value):
                def __init__(self): super().__init__('quotient')
                def __gt__(self, other):
                    event('max-compare', other)
                    return Truth()
            class Remaining(Value):
                def __init__(self): super().__init__('remaining')
                def __floordiv__(self, other):
                    event('floor', other)
                    return Quotient()
            class Deadline(Value):
                def __init__(self): super().__init__('deadline')
                def __sub__(self, other):
                    event('deadline-sub', type(other).__name__)
                    return Remaining()
            class Wall(Value):
                def __init__(self): super().__init__('wall')
                def __radd__(self, other):
                    event('deadline-add', other)
                    return Deadline()
            class Elapsed(Value):
                def __init__(self): super().__init__('elapsed')
                def __gt__(self, other):
                    event('budget-compare', type(other).__name__)
                    return Truth()
            class Factor(Value):
                def __init__(self): super().__init__('factor')
                def __mul__(self, other):
                    event('multiply', other)
                    return Wall()
            class Clock(Value):
                def __init__(self): super().__init__('clock')
                def __sub__(self, other):
                    event('clock-sub', other)
                    return Elapsed()
            class Budget(dict):
                def __getitem__(self, key):
                    event('budget-get', key)
                    if key == 'max_total_wall_ms':
                        return Factor()
                    return super().__getitem__(key)
            if phase == 'multiply': Factor.__mul__ = int.__mul__
            if phase == 'clock-sub': Clock.__sub__ = int.__sub__
            if phase == 'budget-compare': Elapsed.__gt__ = int.__gt__
            if phase == 'deadline-add': Wall.__radd__ = int.__radd__
            if phase == 'deadline-sub': Deadline.__sub__ = int.__sub__
            if phase == 'floor': Remaining.__floordiv__ = int.__floordiv__
            if phase == 'max-compare': Quotient.__gt__ = int.__gt__
            if phase == 'truth': Truth.__bool__ = list.clear
            def clock():
                event('clock')
                return Clock()
            context = {'ref': {'id': 'x'}, 'budget': Budget(max_candidates=3)}
            owner = NativeContextService(service, image) if native else None
            def invoke():
                with patch.object(api.time, 'time_ns', clock):
                    if native:
                        return owner.budget(context) if method == '_budget' else owner.remaining_ms(context)
                    return reference_run(method, service, context)
            def capture():
                try:
                    value = invoke()
                    return {'value': value, 'error': None}
                except BaseException as error:
                    held.append((error, owner, service, context, outer))
                    return {'value': None, 'error': {
                        'type': type(error).__name__, 'message': str(error),
                        'context_is_outer': error.__context__ is outer,
                        'cause': None if error.__cause__ is None else type(error.__cause__).__name__,
                        'notes': getattr(error, '__notes__', None)}}
            if outer is None:
                outcome = capture()
            else:
                try:
                    raise outer
                except LookupError:
                    outcome = capture()
            result = {'events': list(events), 'objects_alive': [(name, ref() is not None) for name, ref in refs],
                      'outcome': outcome, 'sql': sql_trace}
            if owner is not None:
                assert owner.unknown == {}, 'ordinary numeric failure must have confirmed delivery'
                assert owner.last.stage == (7 if outcome['error'] else 5)
            service.store.db.connection.close()
            return result
    domains = {'_budget': ('success', 'clock-sub', 'multiply', 'budget-compare', 'truth'),
               '_remaining_ms': ('success', 'multiply', 'deadline-add', 'deadline-sub', 'floor', 'max-compare', 'truth')}
    for method, phases in domains.items():
        for phase in phases:
            for outer in (False, True):
                reference = observe(method, phase, outer, False)
                actual = observe(method, phase, outer, True)
                rows.append({'method': method, 'phase': phase, 'outer': outer,
                             'reference': reference, 'native': actual, 'equal': reference == actual})
    return rows, held


class ServiceContextSourceTests(unittest.TestCase):
    def test_generated_source_is_exact(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_service_context import document, GRAPHS
        self.assertEqual(render_assembly(document()), SOURCE.read_text())
        for kind, graph in GRAPHS.items():
            self.assertIn((kind - 1) * 100 + 1, graph)
            for targets in graph.values():
                for target in targets if type(targets) is tuple else (targets,):
                    self.assertTrue(target == 0 or target in graph)

    def test_selection_failure_is_not_reference_fallback(self):
        with patch.dict(os.environ, {SELECTOR: '/never-selected-context-manifest'}):
            with self.assertRaises(FileNotFoundError):
                admitted_context()
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(admitted_context())

    def test_original_four_methods_are_frozen(self):
        import textwrap
        fixture = json.loads(ORIGINAL.read_bytes())
        self.assertEqual(sha256(ORIGINAL.read_bytes()).hexdigest(),
                         'b93b703657d1354aa0d65e5625da35581c548645c7f237ae94d160740baabace')
        options = {'include_attributes': False}
        if 'show_empty' in inspect.signature(ast.dump).parameters:
            options['show_empty'] = False
        for name, text in fixture['methods'].items():
            current = ast.parse(textwrap.dedent(inspect.getsource(getattr(api.HIAAgentService, name + '_reference')))).body[0]
            original = ast.parse(text).body[0]
            current.name = original.name
            self.assertEqual(ast.dump(current, **options), ast.dump(original, **options))

    def test_arithmetic_reuses_exact_shared_hia_bigint_function_bodies(self):
        from tools.hia_native_bigints import BODY
        from tools.hia_service_context_arithmetic import body, OPERATIONS
        original = {node.name: node for node in ast.parse(BODY).body}
        emitted = {node.name: node for node in ast.parse(body()).body if node.name in original}
        class RestoreNames(ast.NodeTransformer):
            def visit_Call(self, node):
                self.generic_visit(node)
                if isinstance(node.func, ast.Name) and node.func.id in ('ctx_big_get', 'ctx_big_put'):
                    node.func.id = node.func.id.removeprefix('ctx_big_')
                return node
        options = {'include_attributes': False}
        if 'show_empty' in inspect.signature(ast.dump).parameters:
            options['show_empty'] = False
        self.assertEqual(set(emitted), set(original))
        for name in original:
            self.assertEqual(ast.dump(RestoreNames().visit(emitted[name]), **options),
                             ast.dump(original[name], **options))
        self.assertEqual(set(OPERATIONS), {14, 17, 26, 27, 28, 35, 206, 207, 208, 212,
                                          304, 404, 305, 405, 307, 502, 308, 503, 309, 504})


class ServiceContextNativeTests(unittest.TestCase):
    def identity_files(self, label, *, suffix=b'', raw_suffix=b''):
        case = self.folder / (self._testMethodName + '-' + label)
        case.mkdir(mode=0o700)
        value = json.loads(self.manifest_path.read_bytes())
        image = case / 'context.image.bin'
        image.write_bytes((self.manifest_path.parent / value['image_path']).read_bytes() + suffix)
        value.update(image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest())
        manifest = case / 'manifest.json'
        manifest.write_bytes(json.dumps(value, sort_keys=True).encode() + raw_suffix)
        source = case / 'source.hiaasm'; source.write_bytes(SOURCE.read_bytes())
        return SimpleNamespace(case=case, manifest=manifest, source=source, image=image, value=value)

    def identity_session(self, service, prefix):
        from tools.hia_agent_native_qualification import Session, ToolClient, add_program
        session = Session(ToolClient(service.call), prefix=prefix)
        session.freeze({'schema': 'hepta.hia.agent.workload.v1',
            'cases': [{'function': 'transform', 'arguments': [0]}],
            'warmup_iterations': 0, 'repetitions': 1})
        candidate = session.import_program(add_program())
        return session, candidate

    @classmethod
    def setUpClass(cls):
        from tools import build_hia_service_context as builder
        from hepta.hia_service_context_native import installed_context
        cold = os.environ.get('HEPTA_HIA_SERVICE_CONTEXT_COLD_REPORT')
        compiler_choice = os.environ.get('HEPTA_HIA_SERVICE_CONTEXT_DEVELOPMENT_COMPILER')
        manifest_choice = os.environ.get('HEPTA_HIA_SERVICE_CONTEXT_DEVELOPMENT_MANIFEST')
        if sum(bool(value) for value in (cold, compiler_choice, manifest_choice)) != 1:
            raise ValueError('service context requires one explicit cold, development compiler, or development manifest selection')
        cls.inputs = {}
        if cold:
            cold = Path(cold).resolve(); cold_bytes = cold.read_bytes()
            report = json.loads(cold_bytes, object_pairs_hook=builder._pairs)
            try:
                nested_path = Path(report['nested_report'])
                nested_bytes = nested_path.read_bytes()
                nested = json.loads(nested_bytes)
                compiler = Path(nested['generations'][-1]['produced_image']).resolve()
            except (KeyError, IndexError, TypeError) as error:
                raise ValueError('service-context cold report lacks a compiler') from error
            compiler_bytes = compiler.read_bytes()
            sources = builder.admit_cold_build(compiler_bytes, cold_bytes)
            if (type(report.get('qualification_wall_limit_seconds')) is not int
                    or report['qualification_wall_limit_seconds'] != 180
                    or type(report.get('cleanup_wall_limit_seconds')) is not int
                    or report['cleanup_wall_limit_seconds'] != 3
                    or any(sources.get(name) != sha256((ROOT / name).read_bytes()).hexdigest()
                           for name in builder.REQUIRED_SOURCE_NAMES)):
                raise ValueError('service-context fixture requires the complete original-limit current cold source')
            cls.inputs.update({str(cold): sha256(cold_bytes).hexdigest(),
                               str(nested_path): sha256(nested_bytes).hexdigest(),
                               str(compiler): sha256(compiler_bytes).hexdigest()})
        cls.temporary = None
        evidence = os.environ.get('HEPTA_HIA_SERVICE_CONTEXT_EVIDENCE')
        if evidence:
            base = Path(evidence); base.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls.folder = base / cls.__name__; cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-context-native-')
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
            cls.manifest_path = Path(manifest_choice).resolve()
            mode = 'EXPLICIT_MANIFEST_DEVELOPMENT'
        manifest_raw = cls.manifest_path.read_bytes()
        manifest = json.loads(manifest_raw, object_pairs_hook=builder._pairs)
        cls.image = installed_context(cls.manifest_path)
        image_path = cls.manifest_path.parent / manifest['image_path']
        cls.inputs.update({str(SOURCE): sha256(SOURCE.read_bytes()).hexdigest(),
                           str(cls.manifest_path): sha256(manifest_raw).hexdigest(),
                           str(image_path): sha256(image_path.read_bytes()).hexdigest()})
        cls.inputs.update({str(ROOT / name): sha256((ROOT / name).read_bytes()).hexdigest()
                           for name in builder.REQUIRED_SOURCE_NAMES})
        (cls.folder / 'fixture.json').write_text(json.dumps({'mode': mode, 'inputs': cls.inputs,
            'manifest_path': str(cls.manifest_path), 'current_source_cold': bool(cold),
            'whole_stack_native': False}, indent=2, sort_keys=True) + '\n')

    @classmethod
    def tearDownClass(cls):
        for name, expected in cls.inputs.items():
            if sha256(Path(name).read_bytes()).hexdigest() != expected:
                raise AssertionError('held context input changed: ' + name)
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def compare_freeze(self, mutate=lambda service, args, trace: None):
        observations = []
        for native in (False, True):
            service, args, trace = service_fixture()
            mutate(service, args, trace)
            owner = NativeContextService(service, self.image)
            with stable_environment(trace):
                outcome = observed(lambda: owner.freeze(args) if native else reference_run('_hia_context', service, args))
            observations.append(snapshot(service, args, trace, outcome))
            service.store.db.connection.close()
        self.assertEqual(observations[0], observations[1])
        return observations[0]

    def test_actual_proof_records_held_image_after_selector_replacement_and_clear(self):
        from hepta import hia_checker_identity as checker, hia_service_context_native as native
        from hepta.hia_agent_store import digest
        a = self.identity_files('A')
        b = self.identity_files('B-explicit-trailing-byte-custody-mutant', suffix=b'\x90')
        env = {key: '' for key in checker.NATIVE_OWNERS}
        env[SELECTOR] = str(a.manifest)
        observations = []
        with patch.dict(os.environ, env), patch.object(native, 'SOURCE', a.source):
            service = api.HIAAgentService(a.case / 'state')
            try:
                owner = service._native_context
                held = owner.checker_owner()
                entry, calls = owner.image._entry, []
                def actual(*args):
                    calls.append(1)
                    return entry(*args)
                with patch.object(owner.image, '_entry', actual):
                    session, candidate = self.identity_session(service, 'held-context-proof')
                    for label, selection in (('original', str(a.manifest)),
                            ('different-image', str(b.manifest)), ('cleared', '')):
                        os.environ[SELECTOR] = selection
                        before = len(calls)
                        result = session.verify(candidate)
                        self.assertGreater(len(calls), before)
                        check = result['checks'][0]
                        evidence = session.read_json(check['evidence_artifact'])
                        expected = checker.checker_native_selection(held_owners=(held,))
                        self.assertEqual(evidence['native_checker_selection'], expected)
                        self.assertEqual(check['checker']['native_selection_sha256'], digest(expected))
                        selected = expected[SELECTOR]
                        self.assertEqual(selected['images']['image']['image_sha256'], a.value['image_sha256'])
                        self.assertNotEqual(selected['images']['image']['image_sha256'], b.value['image_sha256'])
                        self.assertEqual(selected['manifest_sha256'], sha256(a.manifest.read_bytes()).hexdigest())
                        service._verification(result['verification_receipt'], session.context, candidate)
                        self.assertIs(service._native_context.image, owner.image)
                        observations.append({'selector_state': label, 'actual_entries': len(calls)-before,
                            'held_identity': selected, 'ordinary_consumer_accepted': True})
                    # Capture uses original admitted bytes, not newly occupying
                    # files. The service still executes its unchanged mapping.
                    a.source.write_bytes(a.source.read_bytes() + b'\nchanged source path')
                    a.image.write_bytes(b'changed image path')
                    a.manifest.write_bytes(b'changed manifest path')
                    result = session.verify(candidate)
                    selected = session.read_json(result['checks'][0]['evidence_artifact'])['native_checker_selection'][SELECTOR]
                    self.assertEqual(selected, expected[SELECTOR])
                    os.environ[SELECTOR] = str(a.manifest)
                    with self.assertRaises((ValueError, OSError)):
                        api.HIAAgentService(a.case / 'refused-new-state')
                    self.assertFalse((a.case / 'refused-new-state').exists())
                self.assertFalse(owner.unknown)
                self.assertFalse(owner.active)
            finally:
                service.close()
        (a.case / 'actual-proof-observations.json').write_text(json.dumps(observations, sort_keys=True, indent=2))

    def test_actual_cached_mapping_retains_separate_admission_manifest_bytes(self):
        from hepta import hia_checker_identity as checker, hia_service_context_native as native
        a = self.identity_files('A')
        b = self.identity_files('B-same-image-different-manifest-bytes', raw_suffix=b'\n')
        env = {key: '' for key in checker.NATIVE_OWNERS}
        with patch.dict(os.environ, env), patch.object(native, 'SOURCE', a.source):
            first = native.installed_context(a.manifest, capture_identity=True)
            second = native.installed_context(b.manifest, capture_identity=True)
            self.assertIs(first.image, second.image)
            self.assertIs(native.installed_context(a.manifest), first.image)
            one = checker.checker_native_selection(held_owners=(first,))[SELECTOR]
            two = checker.checker_native_selection(held_owners=(second,))[SELECTOR]
            self.assertNotEqual(one['manifest_sha256'], two['manifest_sha256'])
            self.assertEqual(one['images'], two['images'])
            self.assertEqual(one['sources'], two['sources'])
            for path in (a.source, a.image, a.manifest, b.image, b.manifest):
                path.unlink()
            with patch.object(first.image, '_entry', side_effect=AssertionError('identity executed native entry')):
                self.assertEqual(checker.checker_native_selection(held_owners=(first,))[SELECTOR], one)
                self.assertEqual(checker.checker_native_selection(held_owners=(second,))[SELECTOR], two)
            owner = NativeContextService(SimpleNamespace(), first.image, checker_custody=first)
            with patch.object(api.time, 'time_ns', return_value=0):
                self.assertEqual(owner.remaining_captured(3_000_000_000), 3000)
        (a.case / 'actual-cache-admission-observations.json').write_text(json.dumps({'first': one, 'second': two,
            'same_mapping': True, 'deleted_paths_did_not_replace_held_bytes': True}, sort_keys=True, indent=2))

    def test_actual_ordinary_proof_consumer_rejects_other_held_image_after_restart(self):
        from hepta import hia_checker_identity as checker, hia_service_context_native as native
        a = self.identity_files('A')
        b = self.identity_files('B-explicit-trailing-byte-custody-mutant', suffix=b'\x90')
        env = {key: '' for key in checker.NATIVE_OWNERS}; env[SELECTOR] = str(a.manifest)
        with patch.dict(os.environ, env), patch.object(native, 'SOURCE', a.source):
            first = api.HIAAgentService(a.case / 'state')
            try:
                session, candidate = self.identity_session(first, 'held-context-restart')
                result = session.verify(candidate)
                original_identity = first._native_context.checker_owner()
                retained = session.read_json(result['checks'][0]['evidence_artifact'])
                with self.assertRaises(ValueError):
                    checker.checker_native_selection(held_owners=(retained['native_checker_selection'][SELECTOR],))
            finally:
                first.close()
            os.environ[SELECTOR] = str(b.manifest)
            second = api.HIAAgentService(a.case / 'state')
            try:
                self.assertNotEqual(second._native_context.image.image_sha256, original_identity.image.image_sha256)
                with self.assertRaises(AgentRejected) as rejected:
                    second._verification(result['verification_receipt'], session.context, candidate)
                self.assertEqual(rejected.exception.code, 'E_HIA_PROOF_SCOPE')
            finally:
                second.close()
            os.environ[SELECTOR] = str(a.manifest)
            third = api.HIAAgentService(a.case / 'state')
            try:
                third._verification(result['verification_receipt'], session.context, candidate)
                self.assertIs(third._native_context.image, original_identity.image)
            finally:
                third.close()
        (a.case / 'actual-restart-observations.json').write_text(json.dumps({'original_image': a.value['image_sha256'],
            'other_mapping': b.value['image_sha256'], 'different_owner_rejected': 'E_HIA_PROOF_SCOPE',
            'original_owner_still_consumes_original_receipt': True}, sort_keys=True, indent=2))

    def test_actual_held_checker_capability_rejects_mismatched_bytes_and_duplicate_owner(self):
        from hepta import hia_checker_identity as checker, hia_service_context_native as native
        a = self.identity_files('A')
        b = self.identity_files('B-explicit-trailing-byte-custody-mutant', suffix=b'\x90')
        env = {key: '' for key in checker.NATIVE_OWNERS}
        with patch.dict(os.environ, env), patch.object(native, 'SOURCE', a.source):
            held = native.installed_context(a.manifest, capture_identity=True)
            other = native.installed_context(b.manifest, capture_identity=True)
            wrong_manifest = json.loads(held.manifest); wrong_manifest['compiler_sha256'] = True
            invalid = (replace(held, source=b'changed source'),
                replace(held, manifest=json.dumps(wrong_manifest).encode()),
                replace(held, manifest=held.manifest[:-1] + b',"schema":"duplicate"}'),
                replace(held, selector='UNREGISTERED_CONTEXT'),
                replace(held, image=other.image), replace(held, source=bytearray(held.source)))
            with patch.object(held.image, '_entry', side_effect=AssertionError('identity executed native entry')):
                for changed in invalid:
                    with self.subTest(change=repr(changed)[:80]):
                        with self.assertRaises(ValueError):
                            checker.checker_native_selection(held_owners=(changed,))
                with self.assertRaises(ValueError):
                    checker.checker_native_selection(held_owners=(held, held))
                with self.assertRaises(ValueError):
                    NativeContextService(SimpleNamespace(), held.image, checker_custody=other)
                checker.checker_native_selection(held_owners=(held,))

    def test_actual_freeze_original_write_order_and_float_integer_conversions(self):
        result = self.compare_freeze()
        self.assertIsNone(result['outcome']['error'])
        self.assertEqual(len(result['published']), 1)
        self.assertEqual(result['contexts'][0][3:], ('1000000000', 0))
        self.assertEqual(result['budgets'][0][1:], ('0', None))
        effects = [row[0] if row[0] != 'sql' else row[1].split()[0] + ':' + row[1].split()[2]
                   for row in result['trace'] if row[0] in ('publish', 'sql')]
        self.assertEqual(effects, ['publish', 'INSERT:contexts', 'INSERT:execution_budgets'])
        for name in ('max_candidates', 'max_model_tokens', 'max_total_wall_ms', 'max_native_wall_ms'):
            self.assertIs(type(result['args']['budget'][name]), int)

    def test_actual_validation_and_error_order_before_publication(self):
        cases = {
            'workload_first': lambda s, a, t: s.store.values['workload'].update(schema='bad'),
            'objective': lambda s, a, t: s.store.values['objective'].update(metric='bad'),
            'cost': lambda s, a, t: s.store.values['cost'].update(expected_invocations='-1'),
            'memory': lambda s, a, t: a['budget'].update(max_memory_bytes='0'),
            'native': lambda s, a, t: a['budget'].update(max_native_wall_ms=4000.0),
            'tokens': lambda s, a, t: s.store.values['cost']['external_costs'].update(model_tokens=10),
            'complete': lambda s, a, t: s.store.values['cost'].update(external_costs_complete=True),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                result = self.compare_freeze(mutate)
                self.assertIsNotNone(result['outcome']['error'])
                self.assertEqual(result['published'], [])
                self.assertEqual(result['contexts'], [])
                self.assertEqual(result['budgets'], [])

    def test_actual_partial_effects_never_reordered_or_rolled_back(self):
        for boundary in ('publish-before', 'publish-after', 'context-before', 'context-after', 'budget-before', 'budget-after'):
            def mutate(service, args, trace, boundary=boundary):
                error = ValueError('original-' + boundary)
                def fail(*unused):
                    raise error
                if boundary == 'publish-before': service.store.before_publish = fail
                if boundary == 'publish-after': service.store.after_publish = fail
                if boundary.startswith(('context-', 'budget-')):
                    table, point = boundary.split('-')
                    needle = 'INSERT INTO contexts ' if table == 'context' else 'INSERT INTO execution_budgets '
                    def fault(stage, statement, params):
                        if stage == point and statement.startswith(needle):
                            raise error
                    service.store.db.fault = fault
            with self.subTest(boundary=boundary):
                result = self.compare_freeze(mutate)
                self.assertEqual(result['outcome']['error'][0], 'ValueError')
                self.assertEqual(len(result['published']), int(boundary != 'publish-before'))
                self.assertEqual(len(result['contexts']), int(boundary in ('context-after', 'budget-before', 'budget-after')))
                self.assertEqual(len(result['budgets']), int(boundary == 'budget-after'))

    def test_actual_baseline_and_live_args_are_read_at_original_times(self):
        def mutate(service, args, trace):
            args['baseline_program'] = {'id': 'baseline'}
            def profile(ref, kind, **kw):
                trace.append(('profile', kind, deepcopy(ref)))
                if kind == 'compiler':
                    args['target_profile']['id'] = 'changed-by-compiler'
            service._profile = profile
            service._program = lambda ref: trace.append(('program', ref)) or SimpleNamespace(sha256='d' * 64)
            def published(value, ref):
                args['compiler_profile'] = {'id': 'after-publication', 'sha256': '9' * 64}
            service.store.after_publish = published
        result = self.compare_freeze(mutate)
        self.assertEqual(result['published'][0]['target_profile']['id'], 'changed-by-compiler')
        self.assertEqual(result['published'][0]['baseline_core_sha256'], 'd' * 64)
        self.assertEqual(result['outcome']['value']['compiler_profile']['id'], 'after-publication')

    def prepare_context(self, native=False):
        service, args, trace = service_fixture()
        owner = NativeContextService(service, self.image)
        with stable_environment(trace):
            frozen = owner.freeze(args) if native else reference_run('_hia_context', service, args)
        trace.clear()
        return service, owner, frozen['context'], trace

    def test_actual_lookup_identity_stale_profile_and_explicit_connection(self):
        for change in ('good', 'bad-id', 'bad-hash', 'stale', 'connection'):
            outcomes = []
            for native in (False, True):
                service, owner, ref, trace = self.prepare_context(native)
                if change == 'bad-id': ref['id'] = 'missing'
                if change == 'bad-hash': ref['sha256'] = '0' * 64
                if change == 'stale': service.identities = {'changed': True}
                connection = service.store.db if change == 'connection' else None
                result = observed(lambda: owner.context(ref, connection=connection) if native else
                    reference_run('_context', service, ref, _connection=connection))
                if result['error'] is None: self.assertIs(result['value']['ref'], ref)
                outcomes.append((result, trace))
                service.store.db.connection.close()
            with self.subTest(change=change): self.assertEqual(*outcomes)

    def test_actual_budget_exact_deadline_and_conditional_attempts(self):
        for elapsed in (2_999_999_999, 3_000_000_000, 3_000_000_001):
            for candidate in (False, True):
                rows = []
                for native in (False, True):
                    service, owner, ref, trace = self.prepare_context(native)
                    context = {'ref': ref, 'budget': {'max_total_wall_ms': 3000, 'max_candidates': 1}}
                    with stable_environment(trace, now=1_000_000_000 + elapsed):
                        first = observed(lambda: owner.budget(context, candidate=candidate) if native else
                            reference_run('_budget', service, context, candidate=candidate))
                        second = observed(lambda: owner.budget(context, candidate=candidate) if native else
                            reference_run('_budget', service, context, candidate=candidate))
                    rows.append((first, second, trace, tuple(service.store.db.connection.execute('SELECT attempts FROM contexts').fetchone())))
                    service.store.db.connection.close()
                with self.subTest(elapsed=elapsed, candidate=candidate): self.assertEqual(*rows)

    def test_actual_arbitrary_precision_negative_clock_and_sqlite_identity_domain(self):
        for created in ('1' + '0' * 1000, '-' + '9' * 1000, 'not-a-number'):
            for key in (b'opaque-bytes', 7, 7.5, None):
                rows = []
                for native in (False, True):
                    service, args, trace = service_fixture()
                    service.store.db.connection.execute('INSERT INTO contexts VALUES (?,?,?,?,0)', (key, 'hash', '{}', created))
                    owner = NativeContextService(service, self.image)
                    context = {'ref': {'id': key}, 'budget': {'max_total_wall_ms': 10**1100, 'max_candidates': 1}}
                    with stable_environment(trace, now=-123):
                        result = observed(lambda: owner.remaining_ms(context) if native else reference_run('_remaining_ms', service, context))
                    rows.append((result, trace))
                    service.store.db.connection.close()
                with self.subTest(created=created[:8], key=key): self.assertEqual(*rows)

    def test_actual_capture_is_one_sql_read_remaining_requeries_each_call(self):
        service, owner, ref, trace = self.prepare_context(True)
        context = {'ref': ref, 'budget': {'max_total_wall_ms': 3000}}
        row, deadline = owner.capture_deadline({'context': ref}, context)
        self.assertEqual(deadline, 4_000_000_000)
        service.store.db.connection.execute('UPDATE contexts SET created_ns=?', ('999999999999999',))
        before = sum(item[0] == 'sql' for item in trace)
        with stable_environment(trace, now=2_000_000_001):
            self.assertEqual(owner.remaining_captured(deadline), 1999)
            self.assertEqual(owner.remaining_captured(deadline), 1999)
            fresh = owner.remaining_ms(context)
        self.assertGreater(fresh, 1999)
        self.assertEqual(sum(item[0] == 'sql' for item in trace) - before, 1)
        self.assertEqual(row['created_ns'], '1000000000')
        service.store.db.connection.close()

    def test_actual_fake_or_mutated_result_cannot_authorize_callback(self):
        service, args, trace = service_fixture()
        owner = NativeContextService(service, self.image)
        state = ContextState(owner, 1, {'args': args})
        owner.active[state.identity] = state
        original = state.call(0)
        for fake in (replace(original), replace(original, words=(True,) + original.words[1:])):
            with self.assertRaises(ContextUnknown): state.invoke(fake)
        self.assertEqual(trace, [])
        self.assertEqual(state.buffer.raw, original.raw)
        state.invoke(original)
        self.assertEqual(trace[0][0], 'profile')
        with self.assertRaises(ContextUnknown): state.invoke(original)
        self.assertEqual(len(trace), 1)

    def test_actual_lost_preclaim_and_post_effect_ack_never_repeat(self):
        for event in (1, 2):
            service, args, trace = service_fixture()
            base = self.image
            error = KeyboardInterrupt('lost-native-ack')
            class Lost:
                fired = False
                def _entry(self, source, size, output, capacity, state, extent):
                    request = struct.unpack('<8Q', ctypes.string_at(source, size))
                    value = base._entry(source, size, output, capacity, state, extent)
                    if request[1] == event and not self.fired:
                        self.fired = True
                        raise error
                    return value
            owner = NativeContextService(service, Lost())
            with self.assertRaises(KeyboardInterrupt) as caught: owner.freeze(args)
            self.assertIs(caught.exception, error)
            self.assertEqual(len(owner.unknown), 1)
            state = next(iter(owner.unknown.values()))
            before = list(trace)
            state.fenced = False  # Diagnostic loss cannot restore native grant.
            with self.assertRaises(ContextUnknown): state.invoke(state.receipt)
            self.assertEqual(trace, before)
            self.assertEqual(len(trace), 0 if event == 1 else 1)

    def test_actual_known_exception_identity_and_terminal_error_no_replay(self):
        service, args, trace = service_fixture()
        error = ValueError('original foreign exception')
        def fail(*a, **kw):
            trace.append(('entered',))
            raise error
        service._profile = fail
        owner = NativeContextService(service, self.image)
        with self.assertRaises(ValueError) as caught: owner.freeze(args)
        self.assertIs(caught.exception, error)
        self.assertEqual(owner.last.stage, 7)  # v2 separately consumes physical error-delivery permission.
        self.assertEqual(owner.active, {})
        self.assertEqual(owner.unknown, {})
        self.assertEqual(trace, [('entered',)])

    def test_actual_public_routes_pin_selected_owner_and_disable_reference(self):
        service, args, trace = service_fixture()
        selected = NativeContextService(service, self.image)
        service._native_context = selected
        with patch.object(api.HIAAgentService, '_hia_context_reference', side_effect=AssertionError('hosted reference entered')), stable_environment(trace):
            result = api.HIAAgentService._hia_context(service, args)
        context = selected.context(result['context'])
        with patch.dict(os.environ, {SELECTOR: ''}), patch.object(api.HIAAgentService, '_context_reference', side_effect=AssertionError('hosted context entered')), patch.object(api.HIAAgentService, '_budget_reference', side_effect=AssertionError('hosted budget entered')), patch.object(api.HIAAgentService, '_remaining_ms_reference', side_effect=AssertionError('hosted remaining entered')), stable_environment(trace):
            self.assertEqual(api.HIAAgentService._context(service, result['context'])['ref'], result['context'])
            self.assertIsNone(api.HIAAgentService._budget(service, context))
            self.assertEqual(api.HIAAgentService._remaining_ms(service, context), 3000)

    def test_actual_int_conversion_partial_mutation_and_exception_identity(self):
        class OriginalFailure(ValueError):
            pass
        results = []
        for native in (False, True):
            service, args, trace = service_fixture()
            error = OriginalFailure('third conversion')
            class Number:
                def __int__(self):
                    trace.append(('third-int', type(args['budget']['max_candidates']).__name__,
                                  type(args['budget']['max_model_tokens']).__name__))
                    raise error
            args['budget']['max_total_wall_ms'] = Number()
            owner = NativeContextService(service, self.image)
            with stable_environment(trace):
                with self.assertRaises(OriginalFailure) as caught:
                    owner.freeze(args) if native else reference_run('_hia_context', service, args)
            self.assertIs(caught.exception, error)
            results.append((trace, type(args['budget']['max_candidates']),
                            type(args['budget']['max_model_tokens']), len(service.store.published)))
            service.store.db.connection.close()
        self.assertEqual(*results)

    def test_actual_rich_compare_truth_destructor_runs_before_next_field(self):
        traces = []
        for native in (False, True):
            service, owner, ref, trace = self.prepare_context(native)
            context = deepcopy(service.store.published[0])
            class Truth:
                def __bool__(self):
                    trace.append(('truth',))
                    return False
                def __del__(self):
                    trace.append(('truth-del',))
                    context['catalog_sha256'] = 'changed-by-destructor'
            class Identity:
                def __ne__(self, other):
                    trace.append(('compare',))
                    return Truth()
            context['installation'] = Identity()
            service.store.get_json = lambda *a, **kw: (context, None)
            with self.assertRaises(AgentRejected) as caught:
                owner.context(ref) if native else reference_run('_context', service, ref)
            self.assertEqual(caught.exception.code, 'E_HIA_CONTEXT_STALE')
            traces.append(trace)
            service.store.db.connection.close()
        self.assertEqual(*traces)
        self.assertEqual(traces[0][-3:], [('compare',), ('truth',), ('truth-del',)])

    def test_actual_sql_parameter_protocol_and_clock_exception_order(self):
        traces = []
        for native in (False, True):
            service, args, trace = service_fixture()
            service.store.db.connection.execute('INSERT INTO contexts VALUES (?,?,?,?,0)', ('x', 'hash', '{}', 'broken'))
            class Key:
                def __conform__(self, protocol):
                    trace.append(('conform', protocol is sqlite3.PrepareProtocol))
                    return 'x'
            context = {'ref': {'id': Key()}, 'budget': {'max_total_wall_ms': 1000, 'max_candidates': 1}}
            owner = NativeContextService(service, self.image)
            with stable_environment(trace):
                result = observed(lambda: owner.budget(context, candidate=True) if native else reference_run('_budget', service, context, candidate=True))
            # Do not retain or compare the opaque Key itself in the trace.
            traces.append((result, [row if row[0] != 'sql' else row[:2] for row in trace]))
            service.store.db.connection.close()
        self.assertEqual(*traces)
        self.assertEqual(traces[0][1][-2:], [('conform', True), ('clock', 1_000_000_000)])

    def test_actual_error_clock_temporary_retires_outside_original_handler(self):
        for stop in (False, True):
            for outer_on in (False, True):
                observations, retained = [], []
                for native in (False, True):
                    service, args, trace = service_fixture()
                    service.store.db.connection.execute('INSERT INTO contexts VALUES (?,?,?,?,0)',
                                                        ('x', 'hash', '{}', 'broken'))
                    events, refs = [], []
                    outer = LookupError('outer') if outer_on else None
                    supplied = StopIteration('original stop payload') if stop else None
                    if supplied is not None:
                        supplied.add_note('original note')
                        supplied.__cause__ = KeyError('original cause')
                        class Number:
                            def __int__(self):
                                events.append(('int',))
                                raise supplied
                        service.store.db.connection.row_factory = lambda cursor, row: {'created_ns': Number()}
                    class Clock:
                        def __init__(self, sink, active):
                            self.sink, self.active = sink, active
                        def __del__(self):
                            self.sink.append(('clock-del', sys.exception() is self.active))
                    def now():
                        events.append(('clock',))
                        value = Clock(events, outer)
                        refs.append(weakref.ref(value))
                        return value
                    context = {'ref': {'id': 'x'}, 'budget': {'max_total_wall_ms': 1000}}
                    owner = NativeContextService(service, self.image) if native else None
                    def invoke():
                        with patch.object(api.time, 'time_ns', now):
                            return owner.budget(context) if native else reference_run('_budget', service, context)
                    def capture():
                        try:
                            invoke()
                        except BaseException as error:
                            retained.append((error, service, owner, outer, supplied))
                            return (type(error).__name__, str(error), error is supplied if stop else None,
                                    error.__context__ is outer, type(error.__cause__).__name__ if error.__cause__ else None,
                                    getattr(error, '__notes__', None), repr(error.value) if stop else None)
                        self.fail('original clock error was swallowed')
                    if outer is not None:
                        try:
                            raise outer
                        except LookupError:
                            error_info = capture()
                    else:
                        error_info = capture()
                    observations.append((list(events), [ref() is not None for ref in refs], error_info))
                    if owner is not None:
                        self.assertEqual(owner.last.stage, 7)
                        self.assertEqual(owner.unknown, {})
                    service.store.db.connection.close()
                self.assertEqual(*observations)
                self.assertEqual(observations[0][0][-1], ('clock-del', True))
                self.assertEqual(observations[0][1], [False])
                if stop:
                    self.assertEqual(observations[0][2][0], 'StopIteration')
                    self.assertIs(observations[0][2][2], True)

    def test_actual_partial_record_operand_release_order_and_handler_context(self):
        for outer_on in (False, True):
            observations, retained = [], []
            for native in (False, True):
                original, args, trace = service_fixture()
                events, refs = [], []
                outer = LookupError('outer record handler') if outer_on else None
                supplied = ValueError('cpu observation failed')
                class Leaf:
                    def __init__(self, label):
                        self.label, self.sink, self.active = label, events, outer
                        refs.append(weakref.ref(self))
                    def __del__(self):
                        self.sink.append(('del', self.label, sys.exception() is self.active))
                class Service:
                    store = original.store
                    _profile = staticmethod(original._profile)
                    _program = staticmethod(original._program)
                    @property
                    def catalog_sha256(self):
                        events.append(('get', 'catalog'))
                        return Leaf('catalog')
                    @property
                    def identities(self):
                        events.append(('get', 'identities'))
                        return Leaf('identities')
                service = Service()
                owner = NativeContextService(service, self.image) if native else None
                def fail_cpu():
                    events.append(('cpu-error',))
                    raise supplied
                def invoke():
                    with stable_environment(trace), patch.object(api.platform, 'system', lambda: Leaf('system')), \
                         patch.object(api.platform, 'machine', lambda: Leaf('machine')), \
                         patch.object(api.os, 'cpu_count', fail_cpu):
                        return owner.freeze(args) if native else reference_run('_hia_context', service, args)
                def capture():
                    try:
                        invoke()
                    except BaseException as error:
                        retained.append((error, supplied, outer, service, owner))
                        self.assertIs(error, supplied)
                        self.assertIs(error.__context__, outer)
                        return
                    self.fail('partial record provider error was swallowed')
                if outer is not None:
                    try:
                        raise outer
                    except LookupError:
                        capture()
                else:
                    capture()
                observations.append((list(events), [ref() is not None for ref in refs]))
                self.assertEqual(original.store.published, [])
                service.store.db.connection.close()
            self.assertEqual(*observations)
            self.assertEqual([event[1] for event in observations[0][0] if event[0] == 'del'],
                             ['machine', 'system', 'identities', 'catalog'])
            self.assertTrue(all(event[2] for event in observations[0][0] if event[0] == 'del'))
            self.assertEqual(observations[0][1], [False] * 4)

    def test_actual_cleanup_claim_ack_and_delivery_ack_loss_keep_unknown_custody(self):
        from hepta.hia_service_context_native import TEMPORARIES
        clock_action = 600 + TEMPORARIES.index('now')
        retained = []
        for boundary in ('error-ack', 'cleanup-claim', 'cleanup-ack', 'delivery-ack'):
            service, args, trace = service_fixture()
            service.store.db.connection.execute('INSERT INTO contexts VALUES (?,?,?,?,0)',
                                                ('x', 'hash', '{}', 'broken'))
            events, refs, calls = [], [], []
            interruption = KeyboardInterrupt(boundary)
            base = self.image
            class Lost:
                delivery = base.delivery
                fired = False
                def _entry(self, source, size, output, capacity, state, extent):
                    request = struct.unpack('<8Q', ctypes.string_at(source, size))
                    before = struct.unpack('<16Q', ctypes.string_at(state, extent))
                    value = base._entry(source, size, output, capacity, state, extent)
                    calls.append((request[1], before[3], before[5]))
                    selected = (boundary == 'error-ack' and request[1] == 3
                        or boundary == 'cleanup-claim' and request[1] == 1 and before[3] == clock_action
                        or boundary == 'cleanup-ack' and request[1] == 2 and before[3] == clock_action
                        or boundary == 'delivery-ack' and request[1] == 4 and before[10] == 1)
                    if selected and not self.fired:
                        self.fired = True
                        raise interruption
                    return value
            class Clock:
                def __init__(self, sink):
                    self.sink = sink
                def __del__(self):
                    self.sink.append(('clock-del', sys.exception() is None))
            def now():
                value = Clock(events)
                refs.append(weakref.ref(value))
                return value
            selected = Lost()
            owner = NativeContextService(service, selected)
            context = {'ref': {'id': 'x'}, 'budget': {'max_total_wall_ms': 1000}}
            with patch.object(api.time, 'time_ns', now), self.assertRaises(KeyboardInterrupt) as caught:
                owner.budget(context)
            self.assertIs(caught.exception, interruption)
            self.assertTrue(selected.fired)
            self.assertIsNone(owner.last)
            self.assertEqual(len(owner.unknown), 1)
            state = next(iter(owner.unknown.values()))
            retained.append((state, owner, interruption))
            self.assertIsInstance(state.error, ValueError)
            self.assertEqual([ref() is not None for ref in refs],
                             [boundary in ('error-ack', 'cleanup-claim')])
            self.assertEqual(events, [] if boundary in ('error-ack', 'cleanup-claim') else [('clock-del', True)])
            before = (list(trace), list(events), list(calls), state.buffer.raw)
            state.fenced = False  # Losing only Python diagnostics restores no native claim.
            with self.assertRaises(ContextUnknown):
                state.invoke(state.receipt)
            self.assertEqual((trace, events, calls, state.buffer.raw), before)
            self.assertEqual(service.store.db.connection.execute('SELECT attempts FROM contexts').fetchone()[0], 0)
            service.store.db.connection.close()

    def test_actual_delivery_result_store_interruption_does_not_terminalize_original_error(self):
        service, args, trace = service_fixture()
        service.store.db.connection.execute('INSERT INTO contexts VALUES (?,?,?,?,0)',
                                            ('x', 'hash', '{}', 'broken'))
        owner = NativeContextService(service, self.image)
        interruption = KeyboardInterrupt('delivery receipt STORE_FAST handoff')
        instructions = list(dis.get_instructions(ContextState._finish_error))
        offset = next(ins.offset for ins in instructions if ins.opname == 'STORE_FAST' and ins.argval == 'delivered')
        injections = []
        def tracer(frame, event, arg):
            if frame.f_code is ContextState._finish_error.__code__:
                frame.f_trace_opcodes = True
                if event == 'opcode' and frame.f_lasti == offset:
                    self.assertNotIn('delivered', frame.f_locals)
                    injections.append(offset)
                    raise interruption
            return tracer
        context = {'ref': {'id': 'x'}, 'budget': {'max_total_wall_ms': 1000}}
        caller = sys._getframe()
        previous_trace, previous_opcodes = sys.gettrace(), caller.f_trace_opcodes
        try:
            # CPython 3.12 also needs the already-active caller to request
            # opcode monitoring before installing the global trace function.
            # The two original unarmed controls remain retained failures.
            caller.f_trace_opcodes = True
            sys.settrace(tracer)
            with stable_environment(trace), self.assertRaises(KeyboardInterrupt) as caught:
                owner.budget(context)
        finally:
            caller.f_trace_opcodes = previous_opcodes
            sys.settrace(previous_trace)
        self.assertIs(caught.exception, interruption)
        self.assertEqual(injections, [offset])
        self.assertIsNone(owner.last)
        state = next(iter(owner.unknown.values()))
        self.assertEqual(state.receipt.stage, 7)
        self.assertIsInstance(state.error, ValueError)
        self.assertIs(owner.active[state.identity], state)
        state.fenced = False
        before = (state.buffer.raw, list(trace))
        with self.assertRaises(ContextUnknown):
            state.invoke(state.receipt)
        self.assertEqual((state.buffer.raw, trace), before)
        service.store.db.connection.close()

    def test_actual_foreign_context_unknown_remains_explicit_nonterminal_boundary(self):
        service, args, trace = service_fixture()
        supplied = ContextUnknown('foreign provider reports an unknown result')
        def provider(*args, **kwargs):
            trace.append(('provider',))
            raise supplied
        service._profile = provider
        owner = NativeContextService(service, self.image)
        with self.assertRaises(ContextUnknown) as caught:
            owner.freeze(args)
        self.assertIs(caught.exception, supplied)
        self.assertIsNone(owner.last)
        self.assertEqual(trace, [('provider',)])
        self.assertEqual(len(owner.unknown), 1)
        state = next(iter(owner.unknown.values()))
        self.assertEqual(state.receipt.stage, 2)
        self.assertEqual(state.receipt.words[10], 0)
        self.assertIs(state.error, supplied)
        state.fenced = False
        with self.assertRaises(ContextUnknown):
            state.invoke(state.receipt)
        self.assertEqual(trace, [('provider',)])
        service.store.db.connection.close()

    def test_actual_same_size_business_and_delivery_requests_have_distinct_magic(self):
        from hepta.hia_exception_delivery import EMIT_REQUEST, EMIT_MAGIC, CODE_BYTES, CODE_SHA256
        business = struct.pack('<8Q', REQUEST_MAGIC, 0, 0, 11, 22, 0, 1, 0)
        self.assertEqual(len(business), len(EMIT_REQUEST))
        self.assertNotEqual(REQUEST_MAGIC, EMIT_MAGIC)
        requests = [('business', business, 160, 0, 144),
                    ('delivery', EMIT_REQUEST, 160, 0xb7, CODE_BYTES),
                    ('delivery-with-business-fields', struct.pack('<8Q', EMIT_MAGIC, 0, 0, 11, 22, 0, 1, 0), 160, 0xb7, 0xfffffffd),
                    ('delivery-short-output', EMIT_REQUEST, CODE_BYTES - 1, 0xb7, 0xfffffffe),
                    ('business-delivery-output-size', business, CODE_BYTES, 0, 0xfffffffd)]
        for name, raw, capacity, fill, expected in requests:
            with self.subTest(name=name):
                source = ctypes.create_string_buffer(raw + b'\xc9' * 16, len(raw) + 16)
                output = ctypes.create_string_buffer(b'\xa5' * (capacity + 16), capacity + 16)
                state = ctypes.create_string_buffer(bytes([fill]) * 128 + b'\xb7' * 16, 144)
                result = self.image._entry(source, len(raw), output, capacity, state, 128)
                self.assertEqual(result, expected)
                self.assertEqual(source.raw, raw + b'\xc9' * 16)
                self.assertEqual(output.raw[capacity:], b'\xa5' * 16)
                self.assertEqual(state.raw[128:], b'\xb7' * 16)
                if name == 'business':
                    self.assertEqual(struct.unpack('<2Q', output.raw[:16]), (RESULT_MAGIC, 0))
                    self.assertEqual(struct.unpack('<16Q', state.raw[:128])[2:8], (1, 1, 1, 1, 11, 22))
                else:
                    self.assertEqual(state.raw[:128], bytes([fill]) * 128)
                    if name == 'delivery':
                        self.assertEqual(sha256(output.raw[:CODE_BYTES]).hexdigest(), CODE_SHA256)
                        self.assertEqual(output.raw[CODE_BYTES:], b'\xa5' * (capacity + 16 - CODE_BYTES))
                    else:
                        self.assertEqual(output.raw, b'\xa5' * (capacity + 16))

    def test_actual_integer_arithmetic_all_actions_original_python_oracle(self):
        service, args, trace = service_fixture()
        owner = NativeContextService(service, self.image)
        oracle = {14: lambda a, b: a + b, 17: lambda a, b: a > b,
                  26: lambda a, b: a <= b, 27: lambda a, b: a <= b,
                  28: lambda a, b: a > b, 35: lambda a, b: a > b,
                  206: lambda a, b: a - b, 207: lambda a, b: a * b,
                  208: lambda a, b: a > b, 212: lambda a, b: a != b,
                  304: lambda a, b: a * b, 404: lambda a, b: a * b,
                  305: lambda a, b: a + b, 405: lambda a, b: a + b,
                  307: lambda a, b: a - b, 502: lambda a, b: a - b,
                  308: lambda a, b: a // b, 503: lambda a, b: a // b,
                  309: lambda a, b: max(b, a), 504: lambda a, b: max(b, a)}
        values = [0, 1, -1, 127, -128, 128, -129, 255, -256,
                  999999, -999999, 1000000, -1000000, 1000001, -1000001]
        for bits in (31, 32, 63, 64, 127, 128, 1023, 4096, 32768):
            values.extend(((1 << bits) - 1, 1 << bits, (1 << bits) + 1,
                           -((1 << bits) - 1), -(1 << bits), -((1 << bits) + 1)))
        rng = random.Random(0xC075)
        cases = 0
        for action, calculate in oracle.items():
            for index, left in enumerate(values):
                right = (1000000 if action in (207, 304, 404, 308, 503)
                         else 0 if action in (309, 504)
                         else rng.choice(values[:39]))
                expected = calculate(left, right)
                actual = owner.numeric(action, left, right)
                self.assertIs(type(actual), type(expected), (action, index))
                self.assertTrue(actual == expected, (action, index, left.bit_length(), right.bit_length()))
                cases += 1
        self.assertEqual(cases, 1380)
        self.assertEqual(trace, [])
        service.store.db.connection.close()

    def test_actual_integer_interop_never_observes_foreign_numeric_methods(self):
        from hepta.hia_service_context_native import _INTEGER_INTEROP
        service, args, trace = service_fixture()
        owner = NativeContextService(service, self.image)
        observed = []
        class Number(int):
            def bit_length(self):
                observed.append('bit_length')
                raise AssertionError('foreign int subclass was boxed as an exact integer')
            def __add__(self, other):
                observed.append('add')
                raise AssertionError('foreign numeric policy executed in representation port')
        class Opaque:
            def __getattribute__(self, name):
                observed.append(name)
                raise AssertionError('opaque numeric object was inspected')
        for left, right in ((Number(7), 3), (3, Number(7)), (True, 4), (4, False),
                            (3.5, 2), (2, 3.5), (Opaque(), 3), (3, Opaque())):
            self.assertIs(owner.numeric(14, left, right), _INTEGER_INTEROP)
        self.assertEqual(observed, [])
        service.store.db.connection.close()

    def test_actual_integer_storage_extends_beyond_the_prior_corpus_width(self):
        # This concrete larger input does not establish all-input equivalence.
        owner = NativeContextService(SimpleNamespace(), self.image)
        large = (1 << 1_048_577) + 123
        rows = []
        for value in (large, -large):
            with patch.object(api.time, 'time_ns', return_value=-19):
                result = owner.remaining_captured(value)
            expected = max(0, (value - (-19)) // 1_000_000)
            self.assertIs(type(result), int)
            self.assertTrue(result == expected)
            encoded = int.to_bytes(result, (int.bit_length(result) + 8) // 8, 'little', signed=True)
            rows.append({'action': 'remaining_captured', 'negative': value < 0,
                         'operand_bits': int.bit_length(value), 'result_bytes': len(encoded),
                         'result_sha256': sha256(encoded).hexdigest(), 'equal': True})
        for action, right, expected in ((14, -large + 1, 1),
                                         (207, 1_000_000, large * 1_000_000),
                                         (212, large, False)):
            result = owner.numeric(action, large, right)
            self.assertIs(type(result), type(expected))
            self.assertTrue(result == expected)
            rows.append({'action': action, 'operand_bits': int.bit_length(large), 'equal': True})
        self.assertEqual(owner.unknown, {})
        self.assertEqual(owner.active, {})
        (self.folder / 'actual-large-integer-storage.json').write_text(
            json.dumps({'cases': rows, 'fixed_integer_width_limit': False,
                        'physical_allocation_limits_removed': False}, indent=2, sort_keys=True) + '\n')

    def test_actual_integer_full_workspace_matches_independent_vm_and_refusals(self):
        from hepta.hia_service_context_native import MATH_MAGIC
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        program = assemble_program(SOURCE.read_bytes())
        entry = next(fn for fn in program.as_dict()['functions'] if fn['name'] == 'f0')
        cases = []
        for action, left, right in ((14, -129, 255), (206, -(1 << 128), 7),
                (207, -32769, 1000000), (26, -(1 << 64), -(1 << 64)),
                (17, (1 << 64), -1), (212, 0, 0), (308, -1000001, 1000000),
                (503, -999999, 1000000), (309, -99, 0), (504, 99, 0)):
            a = left.to_bytes((left.bit_length() + 8) // 8, 'little', signed=True)
            b = right.to_bytes((right.bit_length() + 8) // 8, 'little', signed=True)
            raw = struct.pack('<8Q', MATH_MAGIC, action, 1, 1, len(a), len(b), 0, 0) + a + b
            limbs = (len(a) + len(b)) // 4 + 4
            cases.append((str(action), raw, 33 + limbs * 4, 4 * (24 + limbs * 8), 32))
        good = cases[0]
        for field in (1, 2, 3, 4, 5, 6, 7):
            words = list(struct.unpack('<8Q', good[1][:64])); words[field] = 0xffffffffffffffff
            cases.append(('bad-field-' + str(field), struct.pack('<8Q', *words) + good[1][64:], good[2], good[3], 0xfffffffd))
        cases.extend([('short-output', good[1], 32, good[3], 0xfffffffe),
                      ('short-workspace', good[1], good[2], good[3] - 1, 0xfffffffe)])
        for label, raw, capacity, extent, expected_count in cases:
            with self.subTest(case=label):
                owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(b'\xa5' * capacity)),
                          _Owner(-3, bytearray(b'\xb7' * extent))]
                expected = _Machine(program, 10000000, 16 << 20, None, 128).invoke(entry,
                    [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
                source = ctypes.create_string_buffer(raw + b'\xc9' * 16, len(raw) + 16)
                output = ctypes.create_string_buffer(b'\xa5' * (capacity + 16), capacity + 16)
                work = ctypes.create_string_buffer(b'\xb7' * extent + b'\xda' * 16, extent + 16)
                actual = self.image._entry(source, len(raw), output, capacity, work, extent)
                self.assertEqual(actual, expected_count)
                self.assertEqual(actual, expected)
                self.assertEqual(source.raw, raw + b'\xc9' * 16)
                self.assertEqual(output.raw, bytes(owners[1].data) + b'\xa5' * 16)
                self.assertEqual(work.raw, bytes(owners[2].data) + b'\xda' * 16)

    def test_actual_foreign_numeric_operator_and_temporary_lifetimes(self):
        rows, held = foreign_numeric_lifetimes(self.image)
        (self.folder / 'foreign-numeric-lifetimes.json').write_text(json.dumps({
            'cases': rows, 'matched': sum(row['equal'] for row in rows),
            'total': len(rows), 'held_error_count': len(held)}, indent=2, sort_keys=True) + '\n')
        self.assertEqual(len(rows), 24)
        for row in rows:
            with self.subTest(method=row['method'], phase=row['phase'], outer=row['outer']):
                self.assertEqual(row['reference'], row['native'])

    def test_actual_error_cleanup_full_vm_native_frames_and_terminal_refusal(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        program = assemble_program(SOURCE.read_bytes())
        entry = next(fn for fn in program.as_dict()['functions'] if fn['name'] == 'f0')
        base, frames, vm_state = self.image, [], bytearray(128)
        test = self
        class Mirrored:
            delivery = base.delivery
            def _entry(self, source, size, output, capacity, state, extent):
                raw = ctypes.string_at(source, size)
                test.assertEqual(ctypes.string_at(state, extent), bytes(vm_state))
                src = ctypes.create_string_buffer(raw + b'\xa5' * 16, len(raw) + 16)
                out = ctypes.create_string_buffer(b'\0' * capacity + b'\xb7' * 16, capacity + 16)
                work = ctypes.create_string_buffer(bytes(vm_state) + b'\xc9' * 16, extent + 16)
                actual = base._entry(src, size, out, capacity, work, extent)
                owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(capacity)), _Owner(-3, vm_state)]
                vm = _Machine(program, 10000000, 16 << 20, None, 128)
                expected = vm.invoke(entry, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
                test.assertEqual(actual, expected)
                test.assertEqual(src.raw, raw + b'\xa5' * 16)
                test.assertEqual(out.raw, bytes(owners[1].data) + b'\xb7' * 16)
                test.assertEqual(work.raw, bytes(vm_state) + b'\xc9' * 16)
                frames.append((struct.unpack('<8Q', raw)[1], struct.unpack('<16Q', vm_state), expected))
                ctypes.memmove(output, out, capacity)
                ctypes.memmove(state, work, extent)
                return actual
        service, args, trace = service_fixture()
        service.store.db.connection.execute('INSERT INTO contexts VALUES (?,?,?,?,0)',
                                            ('x', 'hash', '{}', 'broken'))
        transport = Mirrored()
        owner = NativeContextService(service, transport)
        context = {'ref': {'id': 'x'}, 'budget': {'max_total_wall_ms': 1000}}
        with stable_environment(trace), self.assertRaises(ValueError):
            owner.budget(context)
        self.assertEqual(owner.last.stage, 7)
        self.assertTrue(any(event == 3 for event, _, _ in frames))
        self.assertTrue(any(words[3] >= 600 for _, words, _ in frames))
        self.assertEqual(vm_state, owner.last.raw)
        words = owner.last.words
        retained = ctypes.create_string_buffer(bytes(vm_state), 128)
        for event in (1, 2, 3, 4):
            raw = struct.pack('<8Q', REQUEST_MAGIC, event, words[4], *words[6:8], 0, 3, 0)
            source, output = ctypes.create_string_buffer(raw, 64), ctypes.create_string_buffer(144)
            before = retained.raw
            self.assertEqual(transport._entry(source, 64, output, 144, retained, 128), 16)
            self.assertEqual(retained.raw, before)
        self.assertGreater(len(frames), 15)
        service.store.db.connection.close()

    def test_installed_wheel_real_service_without_authoring_or_reference(self):
        from hepta.hia_agent_contract import (DISCOVERY_FILES, NATIVE_SOURCE_FILES,
            SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES)
        name = 'examples/hia_bootstrap/service_context.hiaasm'
        self.assertIn(name, NATIVE_SOURCE_FILES, 'parent integration must register the actual context asset')
        case = self.folder / 'installed-wheel'; case.mkdir(mode=0o700)
        source = case / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = (tuple('docs/' + item for item in DISCOVERY_FILES) + NATIVE_SOURCE_FILES
                     + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES)
        self.assertEqual(len(resources), len(set(resources)))
        for item in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / item; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / item, target)
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        wheels, installed = case / 'wheels', case / 'installed'
        built = subprocess.run([packaging, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-index',
            '--no-build-isolation', '--wheel-dir', str(wheels), str(source)], cwd=case,
            capture_output=True, timeout=120)
        (case / 'wheel-build.log').write_bytes(built.stdout + built.stderr)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        wheel, = wheels.glob('*.whl')
        copied = subprocess.run([packaging, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=case, capture_output=True, timeout=120)
        (case / 'wheel-install.log').write_bytes(copied.stdout + copied.stderr)
        self.assertEqual(copied.returncode, 0, copied.stdout + copied.stderr)
        selection = case / 'selection'; selection.mkdir(mode=0o700)
        manifest = json.loads(self.manifest_path.read_bytes())
        shutil.copyfile(self.manifest_path.parent / manifest['image_path'], selection / manifest['image_path'])
        (selection / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')
        program = r'''import importlib.abc,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed context imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_service_context_native import SOURCE,SELECTOR,admitted_context
from hepta.hia_checker_identity import checker_native_selection
assert Path(sys.argv[1]) in SOURCE.parents,SOURCE
def forbidden(*args,**kwargs):raise AssertionError('installed context used hosted reference policy')
for name in ('_hia_context_reference','_context_reference','_budget_reference','_remaining_ms_reference'):
    setattr(HIAAgentService,name,forbidden)
manifest=Path(sys.argv[2]);os.environ[SELECTOR]=str(manifest)
service=HIAAgentService(sys.argv[3]);selected=service._native_context
assert selected is not None
held_checker=checker_native_selection(held_owners=service._held_checker_owners())[SELECTOR]
assert held_checker['images']['image']['image_sha256']==selected.image.image_sha256
assert held_checker['sources']['image']==__import__('hashlib').sha256(SOURCE.read_bytes()).hexdigest()
examples=service._examples()
workload=service.store.json(examples['workload'],'workload')
objective=service.store.json(examples['objective'],'objective')
cost=service.store.json(examples['cost_policy'],'cost-policy')
args={'compiler_profile':service.profiles['compiler'],'target_profile':service.profiles['target'],
      'baseline_program':None,'workload':workload,'objective':objective,
      'budget':{'max_candidates':3,'max_model_tokens':10,'max_total_wall_ms':300000,
                'max_native_wall_ms':1000,'max_memory_bytes':str(64*1024**2),'cost_policy':cost}}
frozen=service._hia_context(args)
os.environ[SELECTOR]=''
assert checker_native_selection(held_owners=service._held_checker_owners())[SELECTOR]==held_checker
context=service._context(frozen['context'])
service._budget(context,candidate=True)
remaining=service._remaining_ms(context)
row,deadline=selected.capture_deadline({'context':frozen['context']},context)
assert type(remaining) is int and 0<=remaining<=300000
assert type(deadline) is int and 0<=selected.remaining_captured(deadline)<=300000
assert service.store.db.execute('SELECT attempts FROM contexts WHERE id=?',(frozen['context']['id'],)).fetchone()[0]==1
budget=service.store.db.execute('SELECT used_native_ns,owner FROM execution_budgets WHERE context_id=?',(frozen['context']['id'],)).fetchone()
assert tuple(budget)==('0',None),tuple(budget)
assert selected.unknown=={} and selected.active=={}
# Every new selection still reads actual bytes after the immutable map is warm.
os.environ[SELECTOR]=str(manifest);assert admitted_context() is selected.image
value=json.loads(manifest.read_bytes());image=manifest.parent/value['image_path']
image_raw=image.read_bytes();source_raw=SOURCE.read_bytes();refusals=[]
for kind,path,raw in (('image',image,image_raw),('source',SOURCE,source_raw)):
    path.write_bytes(raw+b'changed')
    new_state=Path(sys.argv[3]+'-refused-'+kind)
    try:
        try:HIAAgentService(new_state)
        except ValueError:refusals.append(kind)
        else:raise AssertionError('changed selected '+kind+' was admitted')
        assert not new_state.exists()
        # The old owner keeps its actual immutable machine code.
        assert type(service._remaining_ms(context)) is int
        assert checker_native_selection(held_owners=service._held_checker_owners())[SELECTOR]==held_checker
    finally:path.write_bytes(raw)
assert refusals==['image','source']
assert not any(name=='tools' or name.startswith('tools.') for name in sys.modules)
service.close()
print(json.dumps({'context_id':frozen['context']['id'],'installed_source':str(SOURCE),
    'remaining_ms':remaining,'existing_budget_row':list(budget),'warm_refusals':refusals,
    'authoring_imported':False,'reference_called':False,'whole_stack_native':False},sort_keys=True))
'''
        env = dict(os.environ)
        for key in tuple(env):
            if key.startswith('HEPTA_HIA_'):
                env.pop(key)
        child = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', program, str(installed),
            str(selection / 'manifest.json'), str(case / 'state')], cwd=case,
            env=env, capture_output=True, text=True, timeout=30)
        (case / 'actual.stdout.log').write_text(child.stdout)
        (case / 'actual.stderr.log').write_text(child.stderr)
        self.assertEqual(child.returncode, 0, child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(result['warm_refusals'], ['image', 'source'])
        self.assertEqual(result['existing_budget_row'], ['0', None])

    def test_actual_native_all_state_bytes_match_independent_vm(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        program = assemble_program(SOURCE.read_bytes())
        entry = next(fn for fn in program.as_dict()['functions'] if fn['name'] == 'f0')
        base, observations = self.image, []
        states = {}
        class Mirrored:
            delivery = base.delivery  # Already emitted/admitted by this exact image; all context frames remain mirrored.
            def _entry(self, source, size, output, capacity, state, extent):
                raw = ctypes.string_at(source, size)
                from hepta.hia_service_context_native import MATH_MAGIC
                if struct.unpack('<Q', raw[:8])[0] == MATH_MAGIC:
                    owners = [_Owner(-1, bytearray(raw)),
                              _Owner(-2, bytearray(ctypes.string_at(output, capacity))),
                              _Owner(-3, bytearray(ctypes.string_at(state, extent)))]
                    actual = base._entry(source, size, output, capacity, state, extent)
                    expected = _Machine(program, 10000000, 16 << 20, None, 128).invoke(entry,
                        [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
                    if (actual != expected or ctypes.string_at(source, size) != raw
                            or ctypes.string_at(output, capacity) != bytes(owners[1].data)
                            or ctypes.string_at(state, extent) != bytes(owners[2].data)):
                        raise AssertionError('complete exact-integer VM/native output or scratch differs')
                    return actual
                identity = struct.unpack('<8Q', raw)[3:5]
                vm_state = states.setdefault(identity, bytearray(extent))
                self_before = ctypes.string_at(state, extent)
                if self_before != bytes(vm_state): raise AssertionError('independent pre-state differs')
                original = ctypes.create_string_buffer(raw + b'\xa5' * 16, len(raw) + 16)
                result = ctypes.create_string_buffer(capacity + 16)
                work = ctypes.create_string_buffer(extent + 16)
                ctypes.memmove(work, self_before, extent)
                ctypes.memset(ctypes.addressof(result) + capacity, 0xb7, 16)
                ctypes.memset(ctypes.addressof(work) + extent, 0xc9, 16)
                actual = base._entry(original, size, result, capacity, work, extent)
                owners = [_Owner(-1, bytearray(raw)), _Owner(-2, bytearray(capacity)), _Owner(-3, vm_state)]
                vm = _Machine(program, 10000000, 16 << 20, None, 128)
                expected = vm.invoke(entry, [_View(owners[0], False), _View(owners[1], True), _View(owners[2], True)])[0]
                if actual != expected or result.raw[:capacity] != bytes(owners[1].data) or work.raw[:extent] != bytes(vm_state):
                    raise AssertionError('complete VM/native output or retained state differs')
                if original.raw != raw + b'\xa5' * 16 or result.raw[capacity:] != b'\xb7' * 16 or work.raw[extent:] != b'\xc9' * 16:
                    raise AssertionError('machine continuation changed a guarded extent')
                ctypes.memmove(output, result, capacity); ctypes.memmove(state, work, extent)
                observations.append((identity, struct.unpack('<8Q', raw)[1], expected))
                return actual
        service, args, trace = service_fixture()
        owner = NativeContextService(service, Mirrored())
        with stable_environment(trace):
            result = owner.freeze(args)
            context = owner.context(result['context'])
            owner.budget(context, candidate=True)
            self.assertEqual(owner.remaining_ms(context), 3000)
            row, deadline = owner.capture_deadline({'context': result['context']}, context)
            self.assertEqual(owner.remaining_captured(deadline), 3000)
        self.assertEqual(len(states), 6)
        self.assertGreater(len(observations), 150)
        service.store.db.connection.close()
