"""Independent complete proof-method originals and finite fake providers.

No selected owner is imported here. Original bytes are pinned separately from
all candidate source. Observations preserve exceptions, effects, weak lifetime
facts and declared GC phases; they do not normalise name/obj or traceback data.
"""
from __future__ import annotations
import builtins
import gc
from hashlib import sha256
import json
from pathlib import Path
import sys
import textwrap
import traceback
import types
import weakref

ORIGINALS = Path(__file__).resolve().parent / 'fixtures/hia_service_verification_original_r12'
PINNED = {"_behavior_equivalence.py.txt":"939d69a36845690b7a8ecc4401f38634ce7d04d7d79e615bace6894f71939e40","_subject.py.txt":"c347c2ccadbced0ba592f44c7e8b8c484d2c018f639a5e77dea1a2ab14c1feee","_hia_verify.py.txt":"7d65782088b03d478ef3709a2d62b8b06813e6a01ce544f4d8355ff6da37cdb1","_verification.py.txt":"20e20d0da9d39646648329c8df57c7e6860d4ea091094559a8b305523fca459d","_replay_verification.py.txt":"01b6641021545b58812ca8c8ace1fd42b3f2b780a04ab930a67aa87883b429ae","_native_refinement_binding.py.txt":"082518153f673b72295612689ada71ac20ebca063e761ea14a8c4af99d79f5f1","_independent_native_refinement.py.txt":"389de8ff5c9c32a2641a4212d9b73f4e0b5da15f0f74c3c767d2fa22652b5a76","_check_native_refinement_evidence.py.txt":"8135ff4027a997ddc737d54b038792126f9e91519138ee939f9cd2a6e419f8d6","_required_claims.py.txt":"32b9166c1154070cb13be86a1f1b9194a7a1ecee62a1e92f377fd5e92cba7e40","AgentRejected.py.txt":"30dc9ad1340152ba28445b2138a354eeaf1f0f6edafb94573c45914665acf21b","reject.py.txt":"5bc1a0a02aa8057d238a45db3b612d8efd573ecb02be4a017927a19bacca02a6"}
METHODS = ["_behavior_equivalence","_subject","_hia_verify","_verification","_replay_verification","_native_refinement_binding","_independent_native_refinement","_check_native_refinement_evidence","_required_claims"]
MODES = ["behavior","subject","verify","verification","replay","binding","refinement","check","claims"]
ERRORS = {value.__name__: value for value in (ValueError, TypeError, AttributeError,
    RuntimeError, OSError, MemoryError, StopIteration, KeyboardInterrupt)}
_DEFINITIONS = None

def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()

def original_namespace():
    global _DEFINITIONS
    pieces = {}
    for name, expected in PINNED.items():
        raw = (ORIGINALS / name).read_bytes()
        if sha256(raw).hexdigest() != expected:
            raise ValueError('verification original source identity differs: ' + name)
        pieces[name] = raw.decode()
    if _DEFINITIONS is None:
        source = pieces['AgentRejected.py.txt'] + '\n' + pieces['reject.py.txt']
        for name in METHODS:
            text = textwrap.dedent(pieces[name + '.py.txt'])
            if name == '_native_refinement_binding':
                if not text.startswith('@staticmethod\n'):
                    raise ValueError('original staticmethod decorator changed')
                text = text[len('@staticmethod\n'):]
            source += '\n' + text
        namespace = {'__name__': 'hepta.hia_agent_service', '__package__': 'hepta',
                     '__builtins__': dict(vars(builtins))}
        exec(compile(source, str(ORIGINALS / 'complete-originals.py'), 'exec'), namespace)
        _DEFINITIONS = namespace
    return {'__name__': 'hepta.hia_agent_service', '__package__': 'hepta',
            '__builtins__': dict(vars(builtins)),
            'AgentRejected': _DEFINITIONS['AgentRejected']}

def original_function(namespace, mode):
    name = METHODS[MODES.index(mode)]
    definition = _DEFINITIONS[name]
    return types.FunctionType(definition.__code__, namespace, name, definition.__defaults__)

def original_factory(world, mode, arguments):
    function = original_function(world.namespace, mode)
    call = {'function': function, 'arguments': arguments}
    del function, arguments
    return call.pop('function')(*call.pop('arguments'))

def role(value):
    if value is None or type(value) in (bool, int, float, str):
        return value
    if type(value) is bytes:
        return {'bytes': value.hex()}
    if isinstance(value, Tracked):
        return object.__getattribute__(value, 'tag')
    if type(value) in (list, tuple):
        return [role(item) for item in value]
    if type(value) is dict:
        return {str(key): role(item) for key, item in value.items()}
    return {'type': type(value).__module__ + '.' + type(value).__qualname__}

def error_fields(error, world, seen=None):
    if error is None:
        return None
    if seen is None:
        seen = set()
    if id(error) in seen:
        return {'cycle': True}
    seen.add(id(error))
    fields = {'type': type(error).__module__ + '.' + type(error).__qualname__,
              'args': role(error.args), 'text': str(error),
              'same_injected': error is world.fault, 'same_outer': error is world.outer,
              'name': role(getattr(error, 'name', None)), 'obj': role(getattr(error, 'obj', None)),
              'code': role(getattr(error, 'code', None)), 'phase': role(getattr(error, 'phase', None)),
              'suppress_context': error.__suppress_context__}
    fields['cause'] = error_fields(error.__cause__, world, seen)
    fields['context'] = error_fields(error.__context__, world, seen)
    return fields

class FixtureError(RuntimeError):
    pass

class SafeCoreRejected(ValueError):
    def __init__(self, message, validation=None, counterexample=None):
        super().__init__(message)
        self.validation, self.counterexample = validation, counterexample

class Tracked:
    __slots__ = ('world', 'tag', '__weakref__')
    def __init__(self, world, tag):
        object.__setattr__(self, 'world', world)
        object.__setattr__(self, 'tag', tag)
        world.refs.append((tag, weakref.ref(self)))
    def __getattribute__(self, name):
        if name in ('canonical_bytes', 'sha256', 'input_sha256', 'function_frames',
                    'name', 'root', 'tools', 'identities'):
            world = object.__getattribute__(self, 'world')
            world.event(object.__getattribute__(self, 'tag') + '.get.' + name)
        return object.__getattribute__(self, name)
    def __del__(self):
        world = object.__getattribute__(self, 'world')
        world.events.append({'event': object.__getattribute__(self, 'tag') + '.delete',
                             'active': world.active()})

class Program(Tracked):
    __slots__ = ('document', 'canonical_bytes', 'sha256', 'input_sha256')
    def __init__(self, world, tag, document, raw):
        super().__init__(world, tag)
        self.document = document
        self.canonical_bytes = raw
        self.sha256 = sha256(raw).hexdigest()
        self.input_sha256 = sha256(b'input:' + raw).hexdigest()
    def as_dict(self):
        self.world.event(self.tag + '.as_dict')
        return self.document

class Image(Tracked):
    __slots__ = ('sha256', 'function_frames')
    def __init__(self, world, tag):
        super().__init__(world, tag)
        self.sha256 = sha256(tag.encode()).hexdigest()
        self.function_frames = [('entry', 16)]

class Query(Tracked):
    __slots__ = ('name',)
    def __init__(self, world, name):
        super().__init__(world, 'query.' + name)
        self.name = name
    def __lt__(self, other):
        self.world.event(self.tag + '.less', other)
        return self.name < other.name
    def read_bytes(self):
        self.world.event(self.tag + '.read_bytes')
        return ('(check-sat);' + self.name).encode()

class QueryDirectory(Tracked):
    __slots__ = ()
    def __truediv__(self, part):
        self.world.event('path.divide', part)
        return self
    def glob(self, pattern):
        self.world.event('path.glob', pattern)
        return [Query(self.world, name) for name in self.world.query_names]

class Manager(Tracked):
    __slots__ = ()
    def __enter__(self):
        self.world.event('temporary.enter')
        return '/fake/verification'
    def __exit__(self, typ, value, tb):
        self.world.event('temporary.exit', {'type': None if typ is None else typ.__name__,
                                          'exception': error_fields(value, self.world)})
        if self.world.case['scenario'] == 'exit-error':
            raise OSError('declared temporary exit failure')
        return self.world.case['scenario'] == 'suppress'

class TemporaryProvider:
    def __init__(self, world):
        self.world = world
    def TemporaryDirectory(self, **kwargs):
        self.world.event('temporary.create', kwargs)
        return Manager(self.world, 'temporary')

class Store(Tracked):
    __slots__ = ('root',)
    def __init__(self, world):
        super().__init__(world, 'store')
        self.root = '/fake/root'
    def get_json(self, ref, kind=None):
        self.world.event('store.get_json', {'ref': ref, 'kind': kind})
        return self.world.json_value(ref, kind), {'ref': ref}
    def get(self, ref, kind=None):
        self.world.event('store.get', {'ref': ref, 'kind': kind})
        if kind == 'machine-validation-query':
            data = b'wrong' if self.world.case['scenario'] == 'bytes' else b'(check-sat);query0.smt2'
        else:
            data = b'actual'
        return data, {'ref': ref}
    def json(self, value, kind):
        self.world.event('store.json', {'value': role(value), 'kind': kind})
        self.world.writes.append({'kind': kind, 'value': role(value)})
        return kind + ':' + str(len(self.world.writes))
    def put(self, data, kind):
        self.world.event('store.put', {'data': role(data), 'kind': kind})
        self.world.writes.append({'kind': kind, 'data': role(data)})
        return kind + ':' + str(len(self.world.writes))

class Service(Tracked):
    __slots__ = ('_store', 'identities', 'tools')
    def __init__(self, world):
        super().__init__(world, 'service')
        self._store = None if world.case.get('temporary_store') else Store(world)
        self.identities = {'source': 'fixed-fixture'}
        self.tools = {'hia_verify': {'outputSchema': {'properties': {
            'result': {'properties': {'checks': {'type': 'array'}}}}}}}
    @property
    def store(self):
        self.world.event('service.store.get')
        return Store(self.world) if self._store is None else self._store
    def _profile(self, value, kind):
        self.world.event('service._profile', {'value': value, 'kind': kind})
        return None
    def _program(self, reference):
        self.world.event('service._program', reference)
        return self.world.program('base' if reference == 'base' else 'candidate')
    def _context(self, reference):
        self.world.event('service._context', reference)
        return self.world.context()
    def _remaining_ms(self, context):
        self.world.event('service._remaining_ms')
        case = self.world.case
        if case['scenario'] == 'minimum':
            return 20
        if case['scenario'] in ('deadline', 'publication-deadline'):
            return 0 if self.world.counts['service._remaining_ms'] > 1 else 200
        return 200
    def _build_receipt(self, receipt, context, artifact):
        self.world.event('service._build_receipt', {'receipt': receipt, 'context': context, 'artifact': artifact})
        result = self.world.built()
        if self.world.case['mode'] == 'subject' and self.world.case['scenario'] == 'native-mismatch':
            result['candidate'] = 'other'
        return result
    def _build_inputs(self, receipt, context, artifact):
        self.world.event('service._build_inputs', {'receipt': receipt, 'context': context, 'artifact': artifact})
        return self.world.built(), b'final', b'object', self.world.program(
            'other' if self.world.case['scenario'] == 'core' and self.world.case['mode'] == 'check' else 'candidate')
    def _compile(self, program, output, plan, remaining, **kwargs):
        self.world.event('service._compile', {'output': output, 'plan': plan, 'remaining': remaining, 'kwargs': kwargs})
        return (b'changed' if self.world.case['scenario'] == 'encoding-bytes' else b'actual',
                {'object_sha256': 'changed' if self.world.case['scenario'] == 'encoding-object' else 'object-sha'})
    def _native(self, artifact, context):
        self.world.event('service._native', {'artifact': artifact, 'context': context})
        return b'native', self.world.native(), self.world.program('candidate')
    def __getattr__(self, name):
        if name in METHODS:
            mode = MODES[METHODS.index(name)]
            self.world.event('service.lookup.' + name)
            return BoundWorkflow(self, mode)
        raise AttributeError(name)

class BoundWorkflow:
    __slots__ = ('service', 'mode')
    def __init__(self, service, mode):
        self.service, self.mode = service, mode
    def __call__(self, *arguments):
        service, mode = self.service, self.mode
        world = service.world
        supplied = arguments if mode == 'binding' else (service, *arguments)
        return world.factory(world, mode, supplied)

def proof_result_value(**values):
    return {'claim': values['claim'], 'status': values['status'], 'domain': values['domain'],
            'subject': values['subject'], 'profile': values['profile'],
            'installation': values['installation']}

class World:
    def __init__(self, case, factory):
        self.case, self.factory = case, factory
        self.events, self.writes, self.refs = [], [], []
        self.counts, self.fault_hits, self.clock_calls = {}, 0, 0
        self.fault = self.outer = None
        self.namespace = original_namespace()
        self.query_names = ['query0.smt2', 'query1.smt2'] if case['scenario'] == 'queries' else []
        self._install()
    def active(self):
        error = sys.exception()
        if error is None:
            return None
        if error is self.fault:
            return 'injected'
        if error is self.outer:
            return 'outer'
        return type(error).__module__ + '.' + type(error).__qualname__
    def event(self, label, values=None):
        occurrence = self.counts.get(label, 0) + 1
        self.counts[label] = occurrence
        self.events.append({'event': label, 'occurrence': occurrence, 'values': role(values),
                            'active': self.active()})
        fault = self.case.get('base_fault')
        if fault and fault['label'] == label and fault['occurrence'] == occurrence:
            self.fault_hits += 1
            error = ERRORS[fault['family']]('declared:' + label)
            self.fault = error
            raise error
    def _install(self):
        ns = self.namespace
        ns.update({'SAFE_CORE_METHOD': 'independent-safe-core', 'SAFE_CORE_DOMAIN': 'bounded-safe-core',
            'SAFE_CORE_SERVICE_PROFILE': 'fixture-service-profile', 'PLAN_SCHEMA': {'schema': 'plan'},
            'time': types.SimpleNamespace(monotonic_ns=self.clock),
            'tempfile': TemporaryProvider(self), 'Path': self.path,
            'itertools': __import__('itertools'), 'sha256': sha256,
            '_signatures': self.signatures, '_vm_observation': self.vm_observation,
            'wire': canonical, 'digest': lambda value: sha256(canonical(value)).hexdigest(),
            'validate': self.validate, 'reject': self.reject,
            'proof_subject': self.proof_subject, 'proof_result': self.proof_result,
            'assumptions_document': self.assumptions,
            'installation_manifest': self.installation_manifest})
        ns['__builtins__']['__import__'] = self.importer
    def importer(self, name, globals=None, locals=None, fromlist=(), level=0):
        self.event('import.' + name, {'fromlist': list(fromlist), 'level': level,
            'globals_same': globals is self.namespace,
            'locals': None if locals is None else sorted(locals)})
        table = {
            'hia_optimization': {'PURE': {'const', 'identity'}, 'DEFAULT_POLICY': {},
                                 'verify_optimization': self.optimize},
            'hia_program': {'WIDTHS': {'u8': 8, 'u64': 64}, 'integer_range': self.integer_range},
            'hia_machine_plan': {'validate_block_layout_plan': self.validate_plan,
                                 'preservation_checks': self.preservation},
            'hia_program_native': {'emit_program_machine': self.emit},
            'hia_safe_core': {'ARTIFACT_PROFILE': 'fixture-safe', 'ARTIFACT_OBLIGATIONS': [('valid', 'unsat')],
                'SafeCoreRejected': SafeCoreRejected, '_profile': self.safe_profile,
                '_checker_source_identity': self.checker_identity, 'validate_safe_core_artifact': self.safe_validate},
            'hia_safe_core_elf': {'bind_final_artifact': self.elf_binding}}
        short = name.rsplit('.', 1)[-1]
        if short not in table:
            raise FixtureError('original attempted undeclared provider import: ' + name)
        module = types.ModuleType('hepta.' + short)
        for key, value in table[short].items():
            setattr(module, key, value)
        return module
    def clock(self):
        self.event('clock')
        self.clock_calls += 1
        if self.case['scenario'] == 'iteration-deadline' and self.clock_calls > 1:
            return 10 ** 12
        if self.case['scenario'] == 'final-deadline' and self.clock_calls > 3:
            return 10 ** 12
        return 0
    def path(self, value):
        self.event('Path', value)
        return QueryDirectory(self, 'path')
    def context(self):
        return {'ref': 'context', 'target_profile': 'target', 'objective': 'objective',
                'foreign_buffer_exports': [['entry', 'buffer']] if self.case['scenario'] in ('exports', 'plan-exports') else []}
    def document(self, tag):
        scenario = self.case['scenario']
        typ = 'u64' if scenario in ('wide', 'domains') or scenario.startswith('solver-') else 'bool'
        term = {'op': 'jump', 'target': 'entry'} if scenario == 'cycle' else {'op': 'ret'}
        fn = {'name': 'entry', 'params': [{'name': 'x', 'type': typ}], 'returns': [typ],
              'effects': ['io'] if scenario == 'effect' else [], 'entry': 'entry',
              'blocks': [{'id': 'entry', 'params': [], 'ops': [
                  {'op': 'unknown' if scenario == 'unknown-op' else 'const'}], 'term': term}]}
        if scenario == 'too-many-blocks':
            fn['blocks'] += [{'id': 'extra' + str(i), 'params': [], 'ops': [], 'term': {'op': 'ret'}}
                             for i in range(129)]
        if scenario == 'interface' and tag == 'candidate':
            fn['effects'] = ['trap']
        return {'schema': 'fixture-core', 'functions': [] if scenario == 'empty' and self.case['mode'] == 'binding' else [fn]}
    def program(self, tag):
        if self.case['scenario'] == 'identity':
            raw = b'same-core'
        else:
            raw = tag.encode() + b'-core'
        return Program(self, 'program.' + tag, self.document(tag), raw)
    def signatures(self, program):
        self.event('signatures', program)
        return {fn['name']: {'params': [p['type'] for p in fn['params']], 'returns': fn['returns']}
                for fn in program.document['functions']}
    def integer_range(self, typ):
        self.event('integer_range', typ)
        return (0, 255)
    def vm_observation(self, program, case, *, steps):
        self.event('vm_observation', {'program': program, 'case': case, 'steps': steps})
        scenario = self.case['scenario']
        return {'status': 'budget_exceeded' if scenario == 'vm-budget' else 'returned',
                'values': [1 if scenario == 'vm-refuted' and program.tag == 'program.candidate' else 0],
                'trap_code': None, 'ledger': {'resources': {'bytes': 0}}}
    def optimize(self, original, revised, policy):
        self.event('verify_optimization', policy)
        suffix = self.case['scenario'].removeprefix('solver-')
        return {'status': suffix if suffix in ('verified', 'rejected', 'unknown', 'timeout') else 'unknown'}
    def validate(self, value, schema, label):
        self.event('validate', label)
        if self.case['scenario'] in ('schema', 'schema-returns', 'plan-invalid'):
            raise self.namespace['AgentRejected']('E_FIXTURE_SCHEMA', 'declared invalid schema')
    def reject(self, code, message, phase='admission', **kwargs):
        self.event('reject', {'code': code, 'message': message, 'phase': phase})
        if self.case['scenario'] == 'schema-returns':
            return None
        raise self.namespace['AgentRejected'](code, message, phase, **kwargs)
    def validate_plan(self, program, plan):
        self.event('validate_block_layout_plan', plan)
        return plan
    def preservation(self, plan, program):
        self.event('preservation_checks', plan)
        return {'accepted': True}
    def emit(self, program, **kwargs):
        self.event('emit_program_machine', kwargs)
        return Image(self, 'planned' if 'machine_plan' in kwargs else 'canonical')
    def safe_profile(self, program, **kwargs):
        self.event('safe_profile', kwargs)
        if self.case['scenario'] == 'profile':
            raise SafeCoreRejected('outside admitted safe profile')
    def checker_identity(self):
        self.event('checker_source_identity')
        return {'checker': 'fixture'}
    def safe_validate(self, program, object_bytes, final_bytes, **kwargs):
        self.event('validate_safe_core_artifact', {'object': object_bytes, 'final': final_bytes, **kwargs})
        scenario = self.case['scenario']
        validation = {'status': 'refuted' if scenario == 'refuted' else 'unknown',
                      'solver': {'fixture': True}, 'obligations': []}
        if scenario in ('refuted', 'unknown'):
            raise SafeCoreRejected('declared safe-core rejection', validation,
                                   {'obligation': 'valid'} if scenario == 'refuted' else None)
        if scenario in ('value-error', 'suppress'):
            if scenario == 'suppress':
                raise RuntimeError('declared uncaught provider error')
            raise ValueError('declared provider unsupported')
        return {'status': 'proved', 'solver': {'fixture': True}, 'obligations': []}
    def elf_binding(self, object_bytes, final_bytes, entry):
        self.event('bind_final_artifact', entry)
        return {'binding': {'fixture': 'elf'}}
    def proof_subject(self, record, profile):
        self.event('proof_subject', profile)
        return {'subject': record['subject'], 'target': profile}
    def proof_result(self, **kwargs):
        self.event('proof_result', kwargs)
        return proof_result_value(**kwargs)
    def assumptions(self, value):
        self.event('assumptions_document', value)
        return {'proof': value}
    def installation_manifest(self):
        self.event('installation_manifest')
        return {'source': 'changed' if self.case['scenario'] == 'installation' else 'fixed-fixture'}
    def built(self):
        scenario = self.case['scenario']
        return {'candidate': 'candidate', 'output_kind': 'object' if scenario == 'output' else 'shared',
                'object_artifact': 'object', 'machine_plan': None,
                'native_build': {'object_sha256': 'object-sha',
                                 'foreign_buffer_exports': [['entry']] if scenario == 'exports' else []}}
    def native(self):
        return {'candidate': 'candidate', 'machine_plan': {'layout': 'fixed'} if self.case['scenario'] == 'plan' else None,
                'codegen': {'plan': 'plan'}}
    def subject(self):
        mode, scenario = self.case['mode'], self.case['scenario']
        if mode == 'subject':
            kind = {'core': 'core', 'canonical': 'canonical_lowering', 'plan': 'agent_machine_plan',
                    'plan-invalid': 'agent_machine_plan'}.get(scenario, 'native_artifact')
        elif mode == 'verify':
            kind = 'agent_machine_plan' if scenario.startswith('plan') else 'native_artifact' if scenario.startswith('encoding') or scenario in ('native', 'publication-deadline') else 'core'
        else:
            kind = 'core' if scenario == 'subject' else 'agent_machine_plan' if scenario == 'plan' else 'native_artifact'
        return {'kind': kind, 'backend_profile': 'backend', 'lowering_profile': 'lowering',
                'plan_profile': 'plan-profile', 'plan': 'plan', 'native_artifact': 'artifact',
                'build_receipt': 'build'}
    def args(self):
        return {'context': 'context', 'candidate': 'candidate',
                'base_program': None if self.case['scenario'] == 'behavior-no-base' else 'base',
                'subject': self.subject(), 'validation_profile': 'validation', 'claims': self.claim_names()}
    def claim_names(self):
        mode, scenario = self.case['mode'], self.case['scenario']
        if scenario == 'empty':
            return []
        if scenario in ('mixed', 'all'):
            return ['core_admission', 'encoding_check', 'behavior_equivalence']
        if scenario.startswith('encoding') or mode == 'claims' and scenario in ('artifact',):
            return ['encoding_check']
        if scenario.startswith('behavior') or scenario == 'baseline':
            return ['behavior_equivalence']
        if scenario in ('native', 'unsupported', 'plan', 'plan-exports', 'publication-deadline'):
            return ['lowering_refinement']
        if scenario == 'unknown-claim':
            return ['unsupported_claim']
        return ['core_admission']
    def raw_binding(self, subject, built, tag='candidate'):
        raw = tag.encode() + b'-core'
        return {'candidate_core_sha256': sha256(raw).hexdigest(), 'input_sha256': sha256(b'input:' + raw).hexdigest(),
                'native_artifact': subject['native_artifact'], 'build_receipt': subject['build_receipt'],
                'object_artifact': built['object_artifact'], 'object_sha256': sha256(b'object').hexdigest(),
                'final_image_sha256': sha256(b'final').hexdigest(), 'output_kind': built['output_kind'],
                'entry_symbols': ['entry'], 'foreign_buffer_exports': built['native_build']['foreign_buffer_exports']}
    def receipt(self):
        subject = self.subject()
        scenario = self.case['scenario']
        claim = self.claim_names()[0] if self.claim_names() else 'core_admission'
        record = {'context': 'other' if scenario == 'context' else 'context',
            'candidate': 'other' if scenario == 'candidate' else 'candidate', 'base_program': 'base',
            'candidate_core_sha256': 'changed' if scenario == 'core' else sha256(b'candidate-core').hexdigest(),
            'base_core_sha256': 'changed' if scenario in ('base', 'baseline') else sha256(b'base-core').hexdigest(),
            'installation': {'source': 'changed' if scenario == 'installation' else 'fixed-fixture'},
            'validation_profile': 'validation', 'subject': subject}
        scoped = proof_result_value(claim=claim, status='refuted' if scenario == 'missing' else 'proved',
            domain='fixture-domain', subject={'subject': subject, 'target': 'target'},
            profile='validation', installation=record['installation'], evidence={})
        record['checks'] = [{**scoped, 'assumptions_artifact': 'assumptions', 'evidence_artifact': 'evidence'}]
        if scenario == 'duplicate':
            record['checks'].append(dict(record['checks'][0]))
        return record
    def evidence(self):
        record = self.receipt()
        scoped = {key: value for key, value in record['checks'][0].items()
                  if key not in ('assumptions_artifact', 'evidence_artifact')}
        result = {'method': 'independent-safe-core' if self.case['scenario'] == 'safe' else 'fixture',
                  'proof_binding': scoped, 'artifact_binding': self.raw_binding(self.subject(), self.built()),
                  'validation': None, 'queries': []}
        if self.case['scenario'] == 'binding':
            result['artifact_binding'] = {'changed': True}
            result['proof_binding'] = {'changed': True}
        if self.case['mode'] == 'check':
            result['validation'] = {'image_binding': {'fixture': 'elf'}, 'obligations': [
                {'query_sha256': sha256(b'(check-sat);query0.smt2').hexdigest(), 'query_file': 'query0.smt2'}]}
            result['queries'] = [{'name': 'query0.smt2',
                                  'sha256': sha256(b'(check-sat);query0.smt2').hexdigest(), 'artifact': 'query'}]
            scenario = self.case['scenario']
            if scenario == 'validation':
                result['validation']['image_binding'] = {'changed': True}
            elif scenario == 'queries':
                result['queries'] = None
            elif scenario == 'count':
                result['queries'] = []
            elif scenario == 'shape':
                result['queries'] = [{'invalid': True}]
            elif scenario == 'report':
                result['validation']['obligations'][0]['query_file'] = 'different'
        return result
    def json_value(self, ref, kind):
        if kind == 'verification-receipt':
            return self.receipt()
        if kind == 'verification-evidence':
            return self.evidence()
        if kind == 'verification-assumptions':
            scoped = {key: value for key, value in self.receipt()['checks'][0].items()
                      if key not in ('assumptions_artifact', 'evidence_artifact')}
            return {'changed': True} if self.case['scenario'] == 'assumptions' else {'proof': scoped}
        if ref == 'objective':
            return {'required_claims': self.claim_names()}
        return {'layout': 'fixed'}
    def arguments(self):
        service, mode = Service(self), self.case['mode']
        scenario = self.case['scenario']
        if mode == 'behavior':
            return (service, self.program('base'), self.program('candidate'), 0 if scenario == 'budget' else 200)
        if mode == 'subject':
            return service, self.args(), self.program('candidate')
        if mode == 'verify':
            return service, self.args()
        if mode == 'verification':
            return service, 'receipt', 'context', 'candidate'
        if mode == 'replay':
            record = self.receipt()
            result = {'candidate': record['candidate'], 'subject': record['subject'],
                      'checks': record['checks'], 'verification_receipt': 'receipt'}
            arguments = self.args()
            arguments['claims'] = ['changed'] if scenario == 'claims' else [c['claim'] for c in record['checks']]
            return service, {'result': result}, arguments
        if mode == 'binding':
            del service
            return self.subject(), self.built(), self.program('candidate'), b'object', b'final'
        if mode == 'refinement':
            return service, self.args(), self.program('candidate'), self.context()
        if mode == 'check':
            return service, self.evidence(), self.subject(), 'context', self.program('candidate')
        if mode == 'claims':
            return service, self.context(), 'artifact', [] if scenario == 'empty' else ['receipt'], sha256(b'base-core').hexdigest()
        raise FixtureError('unknown complete method mode')
    def alive(self):
        return [tag for tag, reference in self.refs if reference() is not None]

def _invoke(world):
    call = {'factory': world.factory, 'world': world, 'mode': world.case['mode'],
            'arguments': world.arguments()}
    return call.pop('factory')(call.pop('world'), call.pop('mode'), call.pop('arguments'))

def observe_case(case, factory=original_factory):
    world = World(case, factory)
    unraisables = []
    previous_hook = sys.unraisablehook
    sys.unraisablehook = lambda event: unraisables.append({
        'type': type(event.exc_value).__name__, 'text': str(event.exc_value)})
    retained = []
    def run():
        try:
            result = _invoke(world)
        except BaseException as error:
            outcome = {'status': 'raised', 'exception': error_fields(error, world)}
            retained.append(error)
        else:
            outcome = {'status': 'returned', 'value': role(result)}
            del result
        return outcome
    try:
        if case['outer']:
            try:
                raise KeyError('declared outer')
            except KeyError as error:
                world.outer = error
                outcome = run()
        else:
            outcome = run()
        alive_at_return = world.alive()
        raw_exceptions = []
        for error in retained:
            raw_exceptions.append({'metadata': error_fields(error, world),
                'traceback': traceback.format_exception(type(error), error, error.__traceback__)})
        # A declared consumer release point, identical in both lanes. It is
        # recorded, not silently inserted to normalise a candidate's lifetime.
        world.events.append({'event': 'consumer.traceback.clear_frames', 'count': len(retained),
                             'active': world.active()})
        if case['retain_traceback']:
            for error in retained:
                traceback.clear_frames(error.__traceback__)
        retained.clear()
        error = None
        world.fault = world.outer = None
        alive_after_consumer = world.alive()
        collected = gc.collect() if case['explicit_gc'] else None
        expected_faults = 1 if case.get('base_fault') else 0
        if world.fault_hits != expected_faults:
            raise FixtureError('declared fault count differs: %r' % (world.fault_hits,))
        if unraisables:
            raise FixtureError('observer captured unraisable exception')
        row = {'id': case['id'], 'mode': case['mode'], 'outcome': outcome,
            'events': world.events, 'writes': world.writes,
            'fault_hits': world.fault_hits, 'alive_at_return': alive_at_return,
            'alive_after_consumer': alive_after_consumer, 'alive_at_seal': world.alive(),
            'explicit_gc_collected': collected, 'unraisables': unraisables}
        sealed = json.loads(canonical(row))
        # No returned mutable event list can later be changed by a finalizer.
        return sealed, raw_exceptions
    finally:
        sys.unraisablehook = previous_hook

def derive_faults(base_cases, observations):
    by_id = {row['id']: row for row in observations}
    manifest = json.loads((ORIGINALS / 'cases.json').read_bytes())
    cases = {case['id']: case for case in base_cases}
    result = []
    for identifier in manifest['fault_basis']:
        basis, observed = cases[identifier], by_id[identifier]
        for event in observed['events']:
            if 'occurrence' not in event:
                continue
            for family in manifest['fault_families']:
                fault = {'label': event['event'], 'occurrence': event['occurrence'], 'family': family}
                case = {**basis, 'base_fault': fault}
                suffix = sha256(canonical(fault)).hexdigest()[:16]
                case['id'] = 'derived.' + identifier + '.' + suffix
                result.append(case)
    return result
