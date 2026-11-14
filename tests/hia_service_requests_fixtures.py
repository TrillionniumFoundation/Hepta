"""Independent frozen request oracle and observable storage/provider doubles."""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

from hepta import hia_agent_service as api

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT/'tests/fixtures/hia_service_requests_original_v81.json'
METHODS = ('_profiles', '_examples', '_error', '_hia_describe', '_hia_artifact',
           '_hia_read', '_hia_inspect', '_hia_candidate')


def original_class():
    import textwrap
    retained = json.loads(ORIGINAL.read_bytes())
    source = 'class HIAAgentService:\n' + '\n'.join(
        textwrap.indent(retained['methods'][name]['source'], '    ') for name in METHODS)
    namespace = dict(vars(api))
    exec(compile(source, str(ORIGINAL), 'exec'), namespace)
    return namespace['HIAAgentService']


def observed(callback):
    try:
        return {'returned': callback()}
    except BaseException as error:
        return {'error': [type(error).__module__, type(error).__qualname__, str(error),
                          getattr(error, 'code', None), getattr(error, 'phase', None),
                          getattr(error, 'name', None),
                          None if error.__context__ is None else (
                              type(error.__context__).__name__, str(error.__context__))]}


class Cursor:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class Database:
    def __init__(self, events, cursor=None):
        self.events, self.cursor = events, cursor

    def execute(self, sql, arguments):
        self.events.append(('sql', sql, arguments))
        return Cursor(self.cursor)


class Store:
    def __init__(self, data=b'', *, cursor=None):
        self.data, self.events = data, []
        self.db = Database(self.events, cursor)
        self.objects = {}

    def get(self, ref):
        self.events.append(('get', deepcopy(ref)))
        return self.data, {}

    def get_json(self, ref):
        self.events.append(('get_json', deepcopy(ref)))
        return deepcopy(self.objects[ref['id']]), {}

    def put(self, data, kind, metadata=None):
        row = {'id': kind+'-'+sha256(data).hexdigest(), 'sha256': sha256(data).hexdigest()}
        self.events.append(('put', data, kind, deepcopy(metadata)))
        return row

    def json(self, value, kind):
        self.events.append(('json', deepcopy(value), kind))
        return {'id': kind+'-'+sha256(api.wire(value)).hexdigest(),
                'sha256': sha256(api.wire(value)).hexdigest()}

    def profile(self, name, body):
        self.events.append(('profile', name, deepcopy(body)))
        return {'id': name}, {'id': 'profile-'+name}


def service(data=b'', *, cursor=None, program=None):
    store = Store(data, cursor=cursor)
    value = SimpleNamespace(store=store, identities={'version': 'test-exact'},
        catalog_sha256='catalog-exact', artifact_roots=(Path('/request-root'),),
        _native_proof_contract=None)
    value.profiles = {name: {'id': name} for name in ('backend','artifact','lowering','target','validation','plan')}
    value.profile_artifacts = {name: {'id': 'profile-'+name} for name in value.profiles}
    value.resources = {name: {'id': name} for name in (
        'schema_registry','assembly_grammar','core_language','byte_bootstrap_guide',
        'self_hosting_core_guide','self_hosting_core_support','machine_validation_guide',
        'proof_contract_guide','buffer_lifecycle_guide','examples','diagnostics','plan_schema',
        'machine_plan_guide','macro_policy','macro_policy_guide')}
    value.manifest = {'id': 'manifest'}
    def profile(ref, kind):
        store.events.append(('profile-check', ref, kind))
    def get_program(ref):
        store.events.append(('program', deepcopy(ref)))
        return program
    value._profile = profile
    value._program = get_program
    value._context = lambda ref: {'foreign_buffer_exports': []}
    value._examples = lambda: {'schema': 'fake-provider-example'}
    return value


def snapshot(value):
    return {'events': value.store.events, 'profiles': value.profiles,
        'profile_artifacts': value.profile_artifacts, 'resources': value.resources,
        'manifest': value.manifest}
