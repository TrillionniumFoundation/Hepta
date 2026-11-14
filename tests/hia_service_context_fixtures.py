"""Independent published context bodies and observable foreign providers.

The differential fixture uses the actual schema/buffer implementations and
SQLite. Its deterministic artifact provider represents only the named object
port; separate integration tests exercise the actual AgentStore and worker.
"""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
from unittest.mock import patch

from hepta import hia_agent_service as api
from hepta import hia_agent_buffers as buffers

FIXTURE = Path(__file__).parent / 'fixtures/service_context_b569c21.py.txt'
FIXTURE_SHA256 = '1beb6fe21d69cf72d9198ee3b28db0f846732d13fe32e2d28a44f1400f2d4058'
METHODS = ('_hia_context', '_context', '_budget', '_remaining_ms')


def frozen(namespace=None):
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('published context reference changed')
    scope = dict(vars(api) if namespace is None else namespace)
    exec(compile(raw, str(FIXTURE), 'exec'), scope)
    return scope['FrozenContextService']


def documents():
    workload = {'schema': 'hepta.hia.agent.workload.v2', 'cases': [
        {'function': 'f', 'arguments': [3, {'bytes_hex': 'aabb'},
            {'byte_length': 5, 'fill_byte': 1}],
         'expected': {'status': 'returned', 'values': [0]}}],
        'foreign_buffer_exports': [{'function': 'f', 'max_buffer_bytes': 32}],
        'warmup_iterations': 0, 'repetitions': 1}
    objective = {'schema': 'hepta.hia.agent.objective.v1', 'metric': 'artifact_bytes',
        'required_claims': ['core_admission', 'encoding_check'],
        'allow_unchanged': True, 'min_improvement_ratio': 0.0}
    cost = {'schema': 'hepta.hia.agent.cost-policy.v1', 'external_costs': {
        'model_tokens': None, 'model_wall_ns': None, 'discovery_wall_ns': None},
        'external_costs_complete': False, 'expected_invocations': '0'}
    return workload, objective, cost


class ProviderFailure(RuntimeError):
    pass


class Fixture:
    def __init__(self, *, fail_at=None, changed=None, now=10**18, created=None):
        self.trace, self.fail_at, self.now = [], fail_at, now
        self.primary = ProviderFailure('actual foreign provider failure')
        self.primary.add_note('retain this note')
        self.connection = sqlite3.connect(':memory:')
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('CREATE TABLE contexts (id TEXT, sha256 TEXT, artifact TEXT, created_ns TEXT, attempts INTEGER)')
        self.records, self.budget_creations, self.consumed = {}, [], []
        self.workload, self.objective, self.cost = documents()
        self.args = {'compiler_profile': {'id': 'compiler', 'sha256': '1'*64},
            'target_profile': {'id': 'target', 'sha256': '2'*64}, 'baseline_program': None,
            'workload': 'workload', 'objective': 'objective', 'budget': {
                'cost_policy': 'cost', 'max_candidates': 4, 'max_model_tokens': 100,
                'max_total_wall_ms': 3000, 'max_native_wall_ms': 1000,
                'max_memory_bytes': '536870912'}}
        if changed:
            changed(self)
        self.records.update(workload=self.workload, objective=self.objective, cost=self.cost)
        self.service = SimpleNamespace(catalog_sha256='c'*64, identities={'source': 'd'*64})
        self.service._profile = self.wrap('profile', lambda ref, name: None)
        self.service._program = self.wrap('program', lambda ref: SimpleNamespace(sha256='b'*64))
        self.service._consume_attempt = self.wrap('consume_attempt', self.consumed.append)
        fixture = self
        class Cursor:
            def __init__(self, actual): self.actual = actual
            def fetchone(self): return fixture.invoke('fetchone', self.actual.fetchone)
        class Database:
            def execute(self, sql, values):
                return fixture.invoke('execute', lambda: Cursor(fixture.connection.execute(sql, values)), sql, values,
                                      supplied=False)
        self.service.store = SimpleNamespace(
            get_json=self.wrap('get_json', self.get_json),
            json=self.wrap('json', self.put_json), db=Database(),
            execution_budgets=SimpleNamespace(create=self.wrap('budget_create', self.budget_creations.append)))
        self.namespace = dict(vars(api))
        for name in ('validate', 'uint64', 'keys', 'decode_data', 'wire', 'reject'):
            self.namespace[name] = self.wrap(name, getattr(api, name))
        self.namespace.update(
            time=SimpleNamespace(time_ns=self.wrap('time_ns', lambda: self.now)),
            _now=self.wrap('_now', lambda: '2026-11-14T00:00:00Z'),
            uuid=SimpleNamespace(uuid4=self.wrap('uuid4', lambda: SimpleNamespace(hex='e'*32))),
            platform=SimpleNamespace(system=self.wrap('system', lambda: 'Linux'),
                                     machine=self.wrap('machine', lambda: 'x86_64')),
            os=SimpleNamespace(cpu_count=self.wrap('cpu_count', lambda: 2)))
        self.context = {'schema': 'hepta.hia.agent.context.v1', 'installation': self.service.identities,
            'catalog_sha256': self.service.catalog_sha256, 'compiler_profile': self.args['compiler_profile'],
            'target_profile': self.args['target_profile'], 'budget': self.args['budget']}
        manifest = self.put_json(self.context, 'context')
        self.ref = {'id': 'ctx-retained', 'sha256': manifest['sha256']}
        self.connection.execute('INSERT INTO contexts VALUES (?,?,?,?,0)',
            (self.ref['id'], self.ref['sha256'], api.wire(manifest).decode(), str(now if created is None else created)))
        self.context['ref'] = self.ref

    def invoke(self, event, function, *args, supplied=True, **kwargs):
        active = sys.exception()
        self.trace.append((event, deepcopy(args), deepcopy(kwargs),
                           None if active is None else (type(active).__name__, str(active))))
        if len(self.trace) == self.fail_at:
            raise self.primary
        return function(*args, **kwargs) if supplied else function()

    def wrap(self, label, function):
        return lambda *args, **kwargs: self.invoke(label, function, *args, **kwargs)

    def get_json(self, ref, *, kind=None):
        value = self.records[ref if type(ref) is str else ref['id']]
        return deepcopy(value), {}

    def put_json(self, value, kind):
        digest = sha256(api.wire(value)).hexdigest()
        reference = {'id': 'a-' + digest, 'sha256': digest, 'uri': 'hia://artifacts/' + digest}
        self.records[reference['id']] = deepcopy(value)
        return reference

    def observe(self, image, mode, *, candidate=False):
        argument = (self.args, self.ref, self.context, self.context)[mode-1]
        result = error = None
        with ExitStack() as stack:
            for name in ('export_manifest', 'buffer_size'):
                stack.enter_context(patch.object(buffers, name, self.wrap(name, getattr(buffers, name))))
            try:
                if image is None:
                    method = getattr(frozen(self.namespace), METHODS[mode-1])
                    result = method(self.service, argument, **({'candidate': candidate} if mode == 3 else {}))
                else:
                    from hepta.hia_service_context_native import ContextFrame
                    result = ContextFrame(image, mode, self.service, argument,
                                          candidate=candidate, namespace=self.namespace).finish()
            except BaseException as caught:
                error = caught
        observed = {'result': result, 'trace': self.trace,
            'error': None if error is None else (type(error).__name__, str(error), getattr(error, '__notes__', None)),
            'rows': [tuple(row) for row in self.connection.execute('SELECT * FROM contexts ORDER BY id')],
            'records': self.records, 'budget_creations': self.budget_creations, 'consumed': self.consumed,
            'args': self.args}
        return observed, error

    def close(self):
        self.connection.close()
