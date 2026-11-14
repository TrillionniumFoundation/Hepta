"""Independent original artifact policies and observable storage boundaries."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import textwrap
from types import SimpleNamespace

from hepta import hia_agent_service as api
from tools.hia_agent_native_qualification import add_program

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / 'tests/fixtures/hia_service_artifacts_original_v82.json'
METHODS = ('_profile', '_program', '_signature_values', '_native',
           '_build_receipt', '_build_inputs')


def original_class():
    retained = json.loads(ORIGINAL.read_bytes())
    source = 'class HIAAgentService:\n' + '\n'.join(
        textwrap.indent(retained['methods'][name]['source'], '    ')
        for name in METHODS)
    namespace = dict(vars(api))
    exec(compile(source, str(ORIGINAL), 'exec'), namespace)
    return namespace['HIAAgentService']


def normalized(value):
    if hasattr(value, 'as_dict') and hasattr(value, 'sha256'):
        return {'verified_program': value.as_dict(), 'sha256': value.sha256,
                'input_sha256': value.input_sha256}
    if type(value) is tuple:
        return tuple(normalized(item) for item in value)
    if type(value) is list:
        return [normalized(item) for item in value]
    if type(value) is dict:
        return {key: normalized(item) for key, item in value.items()}
    return value


def observed(callback):
    try:
        return {'returned': normalized(callback())}
    except BaseException as error:
        return {'error': [type(error).__module__, type(error).__qualname__, str(error),
                          getattr(error, 'code', None), getattr(error, 'phase', None),
                          getattr(error, 'name', None),
                          None if error.__context__ is None else (
                              type(error.__context__).__name__, str(error.__context__))]}


class Store:
    def __init__(self):
        self.events = []
        self.connection = None
        self.objects = {}
        self.records = {}

    def connection_event(self, name, arguments, keywords):
        if self.connection is None:
            if keywords:
                raise AssertionError('an absent private connection was forwarded')
        elif set(keywords) != {'_connection'} or keywords['_connection'] is not self.connection:
            raise AssertionError('the exact private connection was not forwarded')
        self.events.append((name, deepcopy(arguments), bool(keywords)))

    def check_profile(self, ref, profile, **keywords):
        self.connection_event('profile', (ref, profile), keywords)
        return {'profile_checked': ref}

    def get(self, ref, *, kind=None, **keywords):
        self.connection_event('get', (ref, kind), keywords)
        return self.objects[ref['id']]

    def get_json(self, ref, *, kind=None, **keywords):
        self.connection_event('get_json', (ref, kind), keywords)
        return self.records[ref['id']], {}


def service(*, connection=False, output_kind='object'):
    store = Store()
    if connection:
        store.connection = object()
    document = add_program(optimized=True)
    program = api.verify_program(document)
    value = SimpleNamespace(store=store, identities={'backend_sha256': 'backend-sha'},
        profiles={'target': {'id': 'target'}, 'backend': {'id': 'backend'}},
        _native_emission=None, program=program)
    value.refs = {name: {'id': name} for name in ('program', 'native', 'context', 'build', 'object')}
    object_bytes = b'object\x00bytes\xff'
    data = object_bytes if output_kind == 'object' else b'linked\x00native'
    object_sha = sha256(object_bytes).hexdigest()
    value.refs['object']['sha256'] = object_sha
    value.context = {'foreign_buffer_exports': []}
    value.metadata = {'installation': value.identities, 'context': value.refs['context'],
        'candidate': value.refs['program'], 'core_sha256': program.sha256,
        'signatures': api._signatures(program, ()), 'foreign_buffer_exports': []}
    value.built = {'object_artifact': value.refs['object'], 'object_sha256': object_sha,
        'core_sha256': program.sha256, 'input_sha256': program.input_sha256,
        'implementation_sha256': value.identities['backend_sha256'], 'kind': output_kind,
        'foreign_buffer_exports': [], 'artifact_sha256': sha256(data).hexdigest(),
        'machine_plan_sha256': 'machine-plan-sha'}
    value.record = {**value.metadata, 'native_artifact': value.refs['native'],
        'target_profile': value.profiles['target'], 'backend_profile': value.profiles['backend'],
        'native_build': value.built, 'object_artifact': value.refs['object'],
        'object_sha256': object_sha, 'output_kind': output_kind}
    value.object_metadata = {'schema': 'hepta.hia.agent.build-object.v1',
        'core_sha256': program.sha256, 'machine_plan_sha256': 'machine-plan-sha',
        'installation': value.identities}
    store.objects['program'] = (api.wire(document), {})
    store.objects['native'] = (data, value.metadata)
    store.objects['object'] = (object_bytes, value.object_metadata)
    store.records['build'] = value.record

    def get_program(ref, **keywords):
        store.connection_event('program', (ref,), keywords)
        return program

    def get_context(ref, **keywords):
        store.connection_event('context', (ref,), keywords)
        return value.context

    def signatures(selected, exports=()):
        store.events.append(('signatures', selected.sha256, exports))
        return api._signatures(selected, exports)

    def get_native(ref, context=None, **keywords):
        store.connection_event('native', (ref, context), keywords)
        return data, value.metadata, program

    def build_inputs(ref, context, artifact, **keywords):
        store.connection_event('build_inputs', (ref, context, artifact), keywords)
        return value.record, data, object_bytes, program

    value._program = get_program
    value._context = get_context
    value._signature_values = signatures
    value._native = get_native
    value._build_inputs = build_inputs
    return value


def arguments(name, service):
    refs = service.refs
    if name == '_profile':
        return (refs['program'], 'target')
    if name == '_program':
        return (refs['program'],)
    if name == '_signature_values':
        return (service.program, ())
    if name == '_native':
        return (refs['native'], refs['context'])
    return (refs['build'], refs['context'], refs['native'])


def invoke_original(name, service):
    method = getattr(original_class(), name)
    values = arguments(name, service)
    if name == '_signature_values':
        return method(service, *values)
    return method(service, *values, _connection=service.store.connection)


def invoke_native(image, name, service):
    values = arguments(name, service)
    if name != '_signature_values':
        values += (service.store.connection,)
    return image.run(name, service, *values)
