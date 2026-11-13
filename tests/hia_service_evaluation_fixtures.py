"""Exact original nine-body oracle and explicitly controlled foreign providers."""
from __future__ import annotations
from contextlib import ExitStack
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from types import FunctionType, SimpleNamespace
from unittest.mock import patch
import sys
import weakref

from hepta import hia_agent_service as api
from hepta import hia_agent_runner as runner
from hepta import hia_agent_buffers as buffers
from hepta.hia_agent_store import AgentRejected
from hepta.hia_service_evaluation_native import ARITIES

ORIGINAL = Path(__file__).with_name('fixtures') / 'hia_service_evaluation_original_v79.json'
ORIGINAL_SHA = '2129b8f6bfe7a966f2c592c5de006d52dacb97676a48d0acd9691efe4c9d0708'
METHODS = tuple(ARITIES)[:7]


def original_functions():
    raw = ORIGINAL.read_bytes()
    if sha256(raw).hexdigest() != ORIGINAL_SHA:
        raise AssertionError('original evaluation oracle changed')
    retained = json.loads(raw)
    result = {}
    for name, item in {**retained['methods'], **retained['helpers']}.items():
        local = {}
        exec(compile(item['source'], str(ORIGINAL), 'exec'), vars(api), local)
        result[name] = local[name]
    return result


REFERENCE = original_functions()


def key(ref):
    return ref['id'] if type(ref) is dict else ref


class Clock:
    def __init__(self, events):
        self.events, self.monotonic, self.wall = events, 100, 1_000_000
    def monotonic_ns(self):
        value = self.monotonic
        self.monotonic += 10
        self.events.append(['monotonic_ns', value])
        return value
    def time_ns(self):
        value = self.wall
        self.wall += 100
        self.events.append(['time_ns', value])
        return value


class Program:
    def __init__(self, label):
        self.label, self.sha256, self.input_sha256 = label, label + '-core', label + '-input'


class Rows:
    """Controlled provider verifies length-before-slice without claiming real SQL."""
    def __init__(self, owner):
        self.owner = owner
    def __len__(self):
        self.owner.events.append(['rows_length', 10001])
        return 10001
    def __getitem__(self, at):
        self.owner.events.append(['rows_slice', at.start, at.stop, at.step])
        return self.owner.rows


class Query:
    def __init__(self, owner, sql, arguments):
        self.owner, self.sql, self.arguments = owner, sql, arguments
    def fetchone(self):
        self.owner.events.append(['fetchone'])
        return {'created_ns': '0'}
    def fetchall(self):
        self.owner.events.append(['fetchall'])
        return Rows(self.owner) if self.owner.case == 'cost-truncated' else self.owner.rows


class DB:
    def __init__(self, owner):
        self.owner = owner
    def execute(self, sql, arguments):
        self.owner.events.append(['sql', sql, arguments])
        return Query(self.owner, sql, arguments)


class Claim:
    def __init__(self, owner):
        self.owner, self.native_ns, self.completed = owner, 25, False
    def run(self, function, data, signatures, cases, *, now, total_ms, warmup, repetitions, memory_bytes):
        self.owner.events.append(['claim.run', data.hex(), now, total_ms, warmup, repetitions, memory_bytes])
        if self.owner.case == 'claim-error':
            raise self.owner.failure
        return function(data, signatures, cases, timeout_ms=total_ms,
                        warmup=warmup, repetitions=repetitions, memory_bytes=memory_bytes)
    def complete(self):
        self.owner.events.append(['claim.complete'])
        if self.completed:
            raise AssertionError('claim completed twice')
        self.completed = True


class Budgets:
    def __init__(self, owner):
        self.owner = owner
    def claim(self, context, owner, budget, started):
        self.owner.events.append(['claim', context, owner, budget, started])
        self.owner.claim = Claim(self.owner)
        return self.owner.claim


class Retained:
    def __init__(self, owner):
        self.owner = owner
    def snapshot(self):
        self.owner.events.append(['slot.snapshot'])
        return {'target_slot': 'slot', 'current': 'old'}
    def current(self):
        self.owner.events.append(['slot.current'])
        return 'new'
    def reference(self, offset):
        self.owner.events.append(['slot.reference', offset])
        return {'id': 'cand' if offset == 896 else 'base'}


class Slots:
    def __init__(self, owner):
        self.owner = owner
    def operate(self, operation, service, **kwargs):
        if service is not self.owner:
            raise AssertionError('slot ledger did not receive the original service')
        self.owner.events.append(['slot.operate', operation, deepcopy(kwargs)])
        return Retained(self.owner)


class Store:
    def __init__(self, owner):
        self.owner, self.documents, self.artifacts, self.published = owner, {}, {}, []
        self.db, self.execution_budgets, self.slot_ledger = DB(owner), Budgets(owner), Slots(owner)
    def get_json(self, ref, *, kind=None, _connection=None):
        self.owner.events.append(['get_json', deepcopy(ref), kind, _connection])
        return self.documents[key(ref)], {}
    def get(self, ref, *, kind=None, _connection=None):
        self.owner.events.append(['get', deepcopy(ref), kind, _connection])
        return self.artifacts[key(ref)]
    def json(self, value, kind, *, _connection=None):
        self.owner.events.append(['publish', kind, _connection])
        if self.owner.case == 'publish-error' and kind == 'measurements':
            raise self.owner.failure
        ref = {'id': 'p' + str(len(self.published))}
        self.published.append([kind, deepcopy(value)])
        self.documents[ref['id']] = deepcopy(value)
        return ref
    def put(self, data, kind, metadata):
        self.owner.events.append(['put', data.hex(), kind, deepcopy(metadata)])
        return {'id': 'captured'}


class Ports:
    def __init__(self, case, image=None, witness=None):
        self.case, self.image, self.witness = case, image, witness
        self.events, self.failure = [], LookupError('controlled foreign failure')
        self.identities, self.profiles = {'backend_sha256': 'backend'}, {'target': 'target', 'backend': 'direct'}
        self.store = Store(self)
        self.programs = {name: Program(name) for name in ('base', 'cand')}
        self.context = {'ref': {'id': 'ctx'}, 'target_profile': 'target',
            'foreign_buffer_exports': [], 'baseline_core_sha256': None,
            'workload': {'id': 'workload'}, 'objective': {'id': 'objective'},
            'budget': {'max_total_wall_ms': 10000, 'max_native_wall_ms': 1000,
                       'max_memory_bytes': '67108864', 'cost_policy': {'id': 'policy'}}}
        self.objective = {'metric': 'artifact_bytes', 'allow_unchanged': True,
                          'min_improvement_ratio': 0.0, 'require_net_benefit': False}
        self.signature = {'f': {'params': ['i64'], 'returns': ['i64']}}
        self.rows = [{'sequence': 1, 'tool': 'tool', 'request_id': 'r', 'context_id': 'ctx',
                      'wall_ns': '17', 'status': 'returned', 'details': b'{}'},
                     {'sequence': 2, 'tool': 'other', 'request_id': None, 'context_id': None,
                      'wall_ns': '9', 'status': 'returned', 'details': b'{}'}]
        self.clock = Clock(self.events)
        self._native_context = None
        self.claim = None
        for name, data in (('base', b'baseline-bytes'), ('cand', b'c')):
            metadata = {'installation': self.identities, 'context': {'id': 'ctx'},
                        'candidate': {'id': name}, 'core_sha256': self.programs[name].sha256,
                        'signatures': self.signature, 'foreign_buffer_exports': [],
                        'output_kind': 'shared'}
            self.store.artifacts[name] = (data, metadata)
        data, metadata = self.store.artifacts['cand']
        object_bytes = b'object'
        object_ref = {'id': 'object', 'sha256': sha256(object_bytes).hexdigest()}
        built = {'object_artifact': object_ref, 'object_sha256': sha256(object_bytes).hexdigest(),
                 'core_sha256': self.programs['cand'].sha256,
                 'input_sha256': self.programs['cand'].input_sha256, 'implementation_sha256': 'backend',
                 'kind': 'shared', 'foreign_buffer_exports': [], 'artifact_sha256': sha256(data).hexdigest()}
        self.store.artifacts['object'] = (object_bytes,
            {'schema': 'hepta.hia.agent.build-object.v1', 'core_sha256': self.programs['cand'].sha256,
             'machine_plan_sha256': None, 'installation': self.identities})
        record = {**metadata, 'native_artifact': {'id': 'cand'}, 'target_profile': 'target',
                  'backend_profile': 'direct', 'native_build': built,
                  'object_artifact': object_ref, 'object_sha256': built['object_sha256']}
        self.store.documents.update({'build': record,
            'policy': {'external_costs': {'model': '0'}, 'external_costs_complete': True, 'expected_invocations': '10'},
            'workload': {'schema': 'hepta.hia.agent.workload.v1',
                         'cases': [{'function': 'f', 'arguments': [3]}, {'function': 'f', 'arguments': [-1]}],
                         'warmup_iterations': 0, 'repetitions': 1}})
        self.args = {'context': {'id': 'ctx'}, 'baseline_artifact': {'id': 'base'},
                     'candidate_artifact': {'id': 'cand'}, 'build_receipt': {'id': 'build'},
                     'verification_receipts': [], 'request_key': 'request', 'target_slot': 'slot',
                     'expected_current': 'old', 'evaluation_receipt': {'id': 'evaluation'}}
        self.evaluation = {'context': self.args['context'], 'candidate_artifact': self.args['candidate_artifact'],
            'installation': self.identities, 'build_receipt': self.args['build_receipt'],
            'baseline_core_sha256': 'base-core', 'baseline_artifact': self.args['baseline_artifact'],
            'report_complete': True, 'planned_workload_complete': True, 'termination_confirmed': True,
            'outcome': 'improved', 'measurements': {'id': 'measurements'}, 'full_cost_ledger': {'id': 'cost'}}
        self.store.documents['evaluation'] = self.evaluation
        self.store.artifacts.update({'measurements': (b'measurements', {}), 'cost': (b'cost', {})})
        if case == 'native-installation':
            metadata['installation'] = {'changed': True}
        elif case == 'native-signature':
            metadata['signatures'] = {}
        elif case == 'build-object':
            self.store.artifacts['object'] = (b'changed', self.store.artifacts['object'][1])
        elif case == 'build-receipt':
            record['target_profile'] = 'different'
        elif case == 'cost-unknown':
            self.store.documents['policy']['external_costs_complete'] = False
        elif case == 'adopt-incomplete':
            self.evaluation['planned_workload_complete'] = False
        elif case == 'adopt-net':
            self.objective['require_net_benefit'] = True
        elif case == 'adopt-abi':
            self.store.artifacts['base'][1]['signatures'] = {'different': {}}
        elif case == 'eval-latency-trap':
            self.objective['metric'] = 'latency_ns'
        elif case == 'eval-context-owner':
            owner = self
            class Context:
                def capture_deadline(self, args, context):
                    owner.events.append(['capture_deadline', deepcopy(args['context'])])
                    return None, 10_000_000_000
                def remaining_captured(self, deadline):
                    owner.events.append(['remaining_captured', deadline])
                    return max(0, (deadline-owner.clock.time_ns())//1_000_000)
            self._native_context = Context()

    def _route(self, name, arguments):
        if self.image is None:
            # Exact original signatures include keyword-only connection.
            if name in ('_native', '_build_inputs', '_build_receipt', '_hia_adopt_native'):
                return REFERENCE[name](self, *arguments[:-1], _connection=arguments[-1])
            return REFERENCE[name](self, *arguments)
        frame = self.image.prepare(name, (self, *arguments), witness=self.witness)
        arguments = None
        return self.image.finish(frame)
    def _native(self, ref, context=None, *, _connection=None):
        return self._route('_native', (ref, context, _connection))
    def _build_inputs(self, ref, context, artifact, *, _connection=None):
        return self._route('_build_inputs', (ref, context, artifact, _connection))
    def _build_receipt(self, ref, context, artifact, *, _connection=None):
        return self._route('_build_receipt', (ref, context, artifact, _connection))
    def _cost_ledger(self, context, evaluation_wall_ns, native_wall_ns):
        return self._route('_cost_ledger', (context, evaluation_wall_ns, native_wall_ns))
    def _context(self, ref, *, _connection=None):
        self.events.append(['context', deepcopy(ref), _connection])
        return self.context
    def _program(self, ref, *, _connection=None):
        self.events.append(['program', deepcopy(ref), _connection])
        return self.programs[key(ref)]
    def _signature_values(self, program, exports=()):
        self.events.append(['signatures', program.label, exports])
        return self.signature
    def _required_claims(self, context, artifact, receipts, baseline, *, _connection=None):
        self.events.append(['required_claims', deepcopy(artifact), baseline, _connection])
        return self.objective
    def _lease(self, lease):
        self.events.append(['lease', lease])
        return {'id': 'lease', 'generation': '1', 'artifact': {'id': 'cand'}}
    def reference_batch(self, program, cases, **kwargs):
        self.events.append(['reference', program.label, deepcopy(cases), deepcopy(kwargs)])
        observations = [self.observation(case) for case in cases]
        if self.case == 'reference-difference' and program.label == 'cand':
            observations[0]['values'] = ['different']
        if self.case == 'reference-budget' and program.label == 'cand':
            return {'status': 'budget_exceeded', 'report': None}
        return {'status': 'returned', 'report': {'complete': True, 'observations': observations}}
    def observation(self, case):
        if case['arguments'][0] < 0:
            return {'status': 'trapped', 'trap_code': 'E_TEST', 'ledger': {'resources': {}}}
        return {'status': 'returned', 'values': [case['arguments'][0]], 'ledger': {'resources': {}}}
    def native_batch(self, data, signatures, cases, **kwargs):
        self.events.append(['native', data.hex(), deepcopy(cases), deepcopy(kwargs)])
        if self.case == 'invoke-budget':
            return {'status': 'budget_exceeded', 'termination_confirmed': True, 'captured_buffers': []}
        if kwargs.get('capture_buffers'):
            return {'status': 'returned', 'termination_confirmed': True, 'captured_buffers': [
                {'argument': 0, 'data': b'bytes', 'extent': '5'}] if self.case == 'invoke-buffers' else [],
                'report': {'observations': [{'status': 'returned', 'values': [cases[0]['arguments'][0]]}]}}
        if cases and cases[0]['arguments'][0] < 0:
            return {'status': 'trapped', 'returncode': -6, 'termination_confirmed': True}
        observations = [{'status': 'returned', 'values': [case['arguments'][0]], 'mismatch': False} for case in cases]
        return {'status': 'returned', 'termination_confirmed': True, 'returncode': 0,
                'report': {'completed_cases': len(cases), 'observations': observations, 'total_native_ns': '11'}}

    def invoke_case(self):
        if self.case.startswith('native-'):
            return self._native({'id': 'cand'}, {'id': 'ctx'})
        if self.case.startswith('build-'):
            return self._build_inputs({'id': 'build'}, {'id': 'ctx'}, {'id': 'cand'})
        if self.case.startswith('receipt-'):
            return self._build_receipt({'id': 'build'}, {'id': 'ctx'}, {'id': 'cand'})
        if self.case.startswith('cost-'):
            return self._cost_ledger(self.context, 99, 25)
        if self.case.startswith('adopt-'):
            return self._route('_hia_adopt_native', (self.args, None))
        if self.case.startswith('invoke-'):
            return self._route('invoke_lease', ('lease', 'f', [3]))
        return self._route('_hia_evaluate', (self.args,))


CASES = ('native-ok', 'native-installation', 'native-signature',
         'build-ok', 'build-object', 'build-receipt', 'receipt-ok',
         'cost-complete', 'cost-unknown', 'cost-truncated',
         'eval-ok', 'eval-context-owner', 'eval-latency-trap', 'reference-difference',
         'reference-budget', 'claim-error', 'publish-error',
         'adopt-ok', 'adopt-incomplete', 'adopt-net', 'adopt-abi',
         'invoke-ok', 'invoke-buffers', 'invoke-budget')


def normalize(value):
    if isinstance(value, Program):
        return ['program', value.label]
    if type(value) is bytes:
        return ['bytes', value.hex()]
    if type(value) in (list, tuple):
        return [normalize(item) for item in value]
    if type(value) is dict:
        return {name: normalize(item) for name, item in value.items()}
    return value


def fixture_call(case, image=None, witness=None):
    ports = Ports(case, image, witness)
    with ExitStack() as stack:
        stack.enter_context(patch.object(api, 'time', ports.clock))
        stack.enter_context(patch.object(api, 'validate', lambda *args, **kwargs: ports.events.append(['validate'])))
        stack.enter_context(patch.object(runner, 'run_reference_batch', ports.reference_batch))
        stack.enter_context(patch.object(runner, 'run_native_batch', ports.native_batch))
        stack.enter_context(patch.object(buffers, 'validate_cases', lambda *args: ports.events.append(['validate_cases'])))
        stack.enter_context(patch.object(buffers, 'validate_arguments', lambda *args: ports.events.append(['validate_arguments'])))
        try:
            result = ports.invoke_case()
            error = None
        except BaseException as caught:
            result = None
            error = {'type': type(caught).__name__, 'args': normalize(caught.args),
                     'code': getattr(caught, 'code', None), 'original_failure': caught is ports.failure}
        return {'value': normalize(result), 'error': error, 'events': normalize(ports.events),
                'publications': normalize(ports.store.published),
                'claim_complete': None if ports.claim is None else ports.claim.completed}


def loop_lifetime_observation(case, outer, image=None):
    """Run the exact original evaluation body with an observable for iterator.

    The replacement enumerate is a foreign provider shared by both routes.
    It records original break, continue, exhaustion and held-error release;
    no test policy replaces the nine emitted bodies.
    """
    def exercise():
        ports = Ports('reference-budget' if case == 'incomplete' else 'eval-ok', image)
        drops, references = [], []
        enumerate_original = enumerate
        def handled():
            error = sys.exception()
            return None if error is None else [type(error).__name__, list(error.args)]
        class ObservedIterator:
            def __init__(self, values):
                self.inner = enumerate_original(values)
                self.index = 0
                references.append(weakref.ref(self))
                ports.events.append(['iterator-created'])
            def __iter__(self):
                ports.events.append(['iterator-iter'])
                return self
            def __next__(self):
                ports.events.append(['iterator-next',self.index])
                if case == 'next-error' and self.index == 1:
                    raise ports.failure
                self.index += 1
                return next(self.inner)
            def __del__(self):
                event = ['iterator-del',handled()]
                drops.append(event)
                ports.events.append(event)
        original_native = ports.native_batch
        def native_batch(*args, **kwargs):
            if case == 'native-budget':
                ports.events.append(['controlled-native-budget'])
                return {'status':'budget_exceeded','returncode':-9,
                        'termination_confirmed':True,'report':None}
            return original_native(*args, **kwargs)
        def call():
            try:
                return {'value':ports.invoke_case(),'error':None}
            except BaseException as error:
                return {'value':None,'error':error}
        with ExitStack() as stack:
            stack.enter_context(patch.object(api,'time',ports.clock))
            stack.enter_context(patch.object(api,'enumerate',ObservedIterator,create=True))
            stack.enter_context(patch.object(api,'validate',lambda *a,**k:ports.events.append(['validate'])))
            stack.enter_context(patch.object(runner,'run_reference_batch',ports.reference_batch))
            stack.enter_context(patch.object(runner,'run_native_batch',native_batch))
            stack.enter_context(patch.object(buffers,'validate_cases',lambda *a:ports.events.append(['validate_cases'])))
            stack.enter_context(patch.object(buffers,'validate_arguments',lambda *a:ports.events.append(['validate_arguments'])))
            outcome = call()
        error_record = None if outcome['error'] is None else {
            'type':type(outcome['error']).__name__,'args':normalize(outcome['error'].args),
            'original_failure':outcome['error'] is ports.failure}
        result = normalize(outcome['value'])
        ports.failure = None
        before = {'alive':[ref() is not None for ref in references],
                  'drops':list(drops),'events':normalize(ports.events)}
        outcome.clear()
        after = {'alive':[ref() is not None for ref in references],
                 'drops':list(drops),'events':normalize(ports.events)}
        return {'value':result,'error':error_record,'before_release':before,
                'after_release':after,'publications':normalize(ports.store.published),
                'claim_complete':None if ports.claim is None else ports.claim.completed}
    if outer:
        try:
            raise LookupError('evaluation loop outer')
        except LookupError:
            return exercise()
    return exercise()
