"""Independent original service rollback/adopt object-protocol observations.

Only the two exact frozen original method bodies are executed by original().
No HIA control graph, adapter port or candidate outcome defines an expectation.
The optional factory is used only after an independently saved original bundle.
"""
from __future__ import annotations
import ast
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

FIXTURE = Path(__file__).resolve().parent / 'fixtures/hia_service_slot_original_bc011'
PINS = {
    'rollback.bc011.py.txt': 'a519b619fab259455444da24aba65883e2bf7d9101a4ba73ea6a147a297a7e5a',
    'adopt.bc011.py.txt': '8bc5c40abacc8364e811accc520d6a5bb737eabd50651759b71d56b03ccb6ad8',
}
ERRORS = {
    'ValueError': ValueError, 'TypeError': TypeError, 'AttributeError': AttributeError,
    'RuntimeError': RuntimeError, 'StopIteration': StopIteration,
    'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit, 'MemoryError': MemoryError,
}
_CODE = {}


def canonical(value):
    # ensure_ascii=True deliberately preserves lone surrogate code points.
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def original_sources():
    rows = []
    for name, digest in PINS.items():
        raw = (FIXTURE / name).read_bytes()
        if sha256(raw).hexdigest() != digest:
            raise ValueError('original body changed: ' + name)
        rows.append({'path': name, 'bytes': len(raw), 'sha256': digest})
    return rows


def original(mode, make_service, make_arguments, namespace):
    name = 'rollback' if mode == 'rollback' else 'adopt'
    if mode not in ('rollback', 'adopt'):
        raise ValueError('unknown original mode')
    if name not in _CODE:
        original_sources()
        filename = name + '.bc011.py.txt'
        source = textwrap.dedent((FIXTURE / filename).read_text())
        tree = ast.parse(source, filename=str(FIXTURE / filename))
        if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
            raise ValueError('original is not exactly one method')
        module = compile(tree, str(FIXTURE / filename), 'exec')
        codes = [value for value in module.co_consts if isinstance(value, types.CodeType)]
        if len(codes) != 1:
            raise ValueError('original code object count differs')
        _CODE[name] = codes[0]
    method = types.FunctionType(_CODE[name], namespace)
    # No local strong reference to either temporary receiver or arguments.
    return method(make_service(), make_arguments())


class Refusal(ValueError):
    def __init__(self, code, message, stage=None):
        super().__init__(message)
        self.code, self.stage = code, stage


class Observed:
    __slots__ = ('fx', 'token', '__weakref__')

    def __init__(self, fx, token):
        self.fx, self.token = fx, token
        fx.register(self, token)

    def __del__(self):
        try:
            target = self.fx.late_events if self.fx.closed else self.fx.events
            target.append({'event': 'delete', 'object': self.token,
                           'active_exception': self.fx.active()})
        except BaseException as error:
            # __del__ never asserts. The observer checks this external record.
            try:
                self.fx.callback_errors.append(type(error).__name__)
            except BaseException:
                pass


class Value(Observed):
    __slots__ = ('value',)

    def __init__(self, fx, token, value=None):
        super().__init__(fx, token)
        self.value = token if value is None else value

    def __ne__(self, other):
        self.fx.point(self.token + '.ne.before', {'other': self.fx.snapshot(other)})
        right = other.value if isinstance(other, Value) else other
        result = self.value != right
        self.fx.point(self.token + '.ne.after', {'result': result})
        if self.fx.recipe.get('comparison') == 'not-implemented':
            return NotImplemented
        if self.fx.recipe.get('comparison', 'truth') == 'bool':
            return result
        return Truth(self.fx, self.token + '.comparison', result)

    def __eq__(self, other):
        self.fx.point(self.token + '.eq.before', {'other': self.fx.snapshot(other)})
        right = other.value if isinstance(other, Value) else other
        result = self.value == right
        self.fx.point(self.token + '.eq.after', {'result': result})
        return result

    def __bool__(self):
        self.fx.point(self.token + '.bool.before')
        result = bool(self.value)
        self.fx.point(self.token + '.bool.after', {'result': result})
        return result

    def __str__(self):
        self.fx.point(self.token + '.str.before')
        result = str(self.value)
        self.fx.point(self.token + '.str.after')
        return result


class Truth(Observed):
    __slots__ = ('value',)

    def __init__(self, fx, token, value):
        super().__init__(fx, token)
        self.value = value

    def __bool__(self):
        self.fx.point(self.token + '.bool.before')
        value = self.value
        self.fx.point(self.token + '.bool.after', {'result': value})
        return value


class Mapping(Observed):
    __slots__ = ('values', 'reads')

    def __init__(self, fx, token, values):
        super().__init__(fx, token)
        self.values, self.reads = values, {}

    def __getitem__(self, key):
        label = self.token + '.get.' + key
        self.fx.point(label + '.before')
        self.reads[key] = self.reads.get(key, 0) + 1
        if self.fx.recipe.get('missing') == self.token + '.' + key:
            raise KeyError(key)
        value = self.values[key]
        change = self.fx.recipe.get('replace_read')
        if change and change['map'] == self.token and change['key'] == key and self.reads[key] >= change['at']:
            value = self.fx.value(change['value'], self.token + '.' + key + '.replacement')
        self.fx.point(label + '.after', {'value': self.fx.snapshot(value)})
        return value

    def get(self, key, default=None):
        self.fx.point(self.token + '.getmethod.before', {'key': key})
        result = self.values.get(key, default)
        self.fx.point(self.token + '.getmethod.after', {'value': self.fx.snapshot(result)})
        return result


class Sequence(Observed):
    __slots__ = ('values', 'site', 'kind')

    def __init__(self, fx, site, values, kind):
        super().__init__(fx, site + '.sequence')
        self.values, self.site, self.kind = values, site, kind

    def __iter__(self):
        self.fx.point(self.site + '.iter.before')
        iterator = Iterator(self.fx, self.site, self.values, self.kind)
        self.fx.point(self.site + '.iter.after')
        return iterator


class Iterator(Observed):
    __slots__ = ('values', 'index', 'site', 'kind')

    def __init__(self, fx, site, values, kind):
        super().__init__(fx, site + '.iterator')
        self.values, self.index, self.site, self.kind = values, 0, site, kind

    def __iter__(self):
        self.fx.point(self.site + '.iterator.iter.before')
        result = self
        self.fx.point(self.site + '.iterator.iter.after')
        return result

    def __next__(self):
        self.fx.point(self.site + '.next.before', {'index': self.index})
        if self.kind == 'next-ValueError' and self.index == 1:
            raise ValueError('explicit iterator refusal')
        if self.kind == 'next-StopIteration' and self.index == 1:
            raise StopIteration('explicit iterator stop')
        if self.index == len(self.values):
            self.fx.point(self.site + '.eof')
            raise StopIteration
        value = self.values[self.index]
        self.index += 1
        self.fx.point(self.site + '.next.after', {'value': self.fx.snapshot(value)})
        return value


class DetachedCall(Observed):
    __slots__ = ('owner_kind', 'name')

    def __init__(self, fx, owner_kind, name):
        super().__init__(fx, owner_kind + '.' + name + '.detached')
        self.owner_kind, self.name = owner_kind, name

    def __call__(self, *args, **kwargs):
        return self.fx.provider(self.owner_kind + '.' + self.name, args, kwargs)


class BoundOverride(Observed):
    __slots__ = ('owner', 'owner_kind', 'name')

    def __init__(self, fx, owner, owner_kind, name):
        super().__init__(fx, owner_kind + '.' + name + '.bound-override')
        self.owner, self.owner_kind, self.name = owner, owner_kind, name

    def __call__(self, *args, **kwargs):
        return self.fx.provider(self.owner_kind + '.' + self.name, args, kwargs)


class Provider(Observed):
    __slots__ = ('kind', '__dict__')
    METHODS = frozenset()

    def __init__(self, fx, kind):
        super().__init__(fx, kind)
        self.kind = kind
        if fx.recipe.get('calls') == 'instance-override':
            for name in sorted(self.METHODS):
                object.__setattr__(self, name, DetachedCall(fx, kind, name))

    def __getattribute__(self, name):
        if name in object.__getattribute__(self, 'METHODS'):
            fx = object.__getattribute__(self, 'fx')
            kind = object.__getattribute__(self, 'kind')
            fx.point(kind + '.lookup.' + name + '.before')
            style = fx.recipe.get('calls', 'method')
            if style == 'detached':
                result = DetachedCall(fx, kind, name)
            elif style == 'bound-override':
                result = BoundOverride(fx, self, kind, name)
            else:
                result = object.__getattribute__(self, name)
            fx.point(kind + '.lookup.' + name + '.after')
            return result
        return object.__getattribute__(self, name)


class Ledger(Provider):
    __slots__ = ()
    METHODS = frozenset(('validate_u64', 'rollback', 'admit_evaluation',
                         'admit_net_benefit', 'adopt'))

    def __init__(self, fx):
        super().__init__(fx, 'ledger')

    def validate_u64(self, *args, **kwargs):
        return self.fx.provider('ledger.validate_u64', args, kwargs)

    def rollback(self, *args, **kwargs):
        return self.fx.provider('ledger.rollback', args, kwargs)

    def admit_evaluation(self, *args, **kwargs):
        return self.fx.provider('ledger.admit_evaluation', args, kwargs)

    def admit_net_benefit(self, *args, **kwargs):
        return self.fx.provider('ledger.admit_net_benefit', args, kwargs)

    def adopt(self, *args, **kwargs):
        return self.fx.provider('ledger.adopt', args, kwargs)


class Store(Provider):
    __slots__ = ()
    METHODS = frozenset(('get_json', 'get', 'json'))

    def __init__(self, fx):
        super().__init__(fx, 'store')

    def get_json(self, *args, **kwargs):
        return self.fx.provider('store.get_json', args, kwargs)

    def get(self, *args, **kwargs):
        return self.fx.provider('store.get', args, kwargs)

    def json(self, *args, **kwargs):
        return self.fx.provider('store.json', args, kwargs)


class Service(Provider):
    __slots__ = ('ledger_reads', 'store_reads', 'retained_ledger', 'retained_store')
    METHODS = frozenset(('_context', '_build_receipt', '_required_claims',
                         '_reference_adoption_evaluation', '_reference_adoption_net_benefit',
                         '_native', '_conditional_slot', '_reference_slot_adopt',
                         '_reference_slot_rollback'))

    def __init__(self, fx):
        super().__init__(fx, 'service')
        self.ledger_reads = self.store_reads = 0
        self.retained_ledger = None
        self.retained_store = None

    def __getattribute__(self, name):
        if name in ('_slot_ledger', 'store', 'identities'):
            fx = object.__getattribute__(self, 'fx')
            fx.point('service.lookup.' + name + '.before')
            if name == '_slot_ledger':
                index = object.__getattribute__(self, 'ledger_reads')
                object.__setattr__(self, 'ledger_reads', index + 1)
                values = fx.ledger_reads
                present = values[index] if index < len(values) else values[-1]
                if not present:
                    result = None
                elif fx.recipe.get('temporary_ledger'):
                    result = fx.make_ledger()
                else:
                    result = object.__getattribute__(self, 'retained_ledger')
                    if result is None:
                        result = fx.make_ledger()
                        object.__setattr__(self, 'retained_ledger', result)
            elif name == 'store':
                object.__setattr__(self, 'store_reads', object.__getattribute__(self, 'store_reads') + 1)
                if fx.recipe.get('temporary_store'):
                    result = fx.make_store()
                else:
                    result = object.__getattribute__(self, 'retained_store')
                    if result is None:
                        result = fx.make_store()
                        object.__setattr__(self, 'retained_store', result)
            else:
                result = Value(fx, 'installation.actual', 'installation')
            fx.point('service.lookup.' + name + '.after')
            return result
        return super().__getattribute__(name)

    def _context(self, *args, **kwargs):
        return self.fx.provider('service._context', args, kwargs)

    def _build_receipt(self, *args, **kwargs):
        return self.fx.provider('service._build_receipt', args, kwargs)

    def _required_claims(self, *args, **kwargs):
        return self.fx.provider('service._required_claims', args, kwargs)

    def _reference_adoption_evaluation(self, *args, **kwargs):
        return self.fx.provider('service._reference_adoption_evaluation', args, kwargs)

    def _reference_adoption_net_benefit(self, *args, **kwargs):
        return self.fx.provider('service._reference_adoption_net_benefit', args, kwargs)

    def _native(self, *args, **kwargs):
        return self.fx.provider('service._native', args, kwargs)

    def _conditional_slot(self, *args, **kwargs):
        return self.fx.provider('service._conditional_slot', args, kwargs)

    def _reference_slot_adopt(self, *args, **kwargs):
        return self.fx.provider('service._reference_slot_adopt', args, kwargs)

    def _reference_slot_rollback(self, *args, **kwargs):
        return self.fx.provider('service._reference_slot_rollback', args, kwargs)


class ServiceSubclass(Service):
    __slots__ = ()

    def _conditional_slot(self, *args, **kwargs):
        self.fx.events.append({'event': 'subclass-override', 'name': '_conditional_slot'})
        return self.fx.provider('service._conditional_slot', args, kwargs)


class ProviderDescriptor:
    __slots__ = ('kind', 'name')

    def __init__(self, kind, name):
        self.kind, self.name = kind, name

    def __get__(self, instance, owner):
        if instance is None:
            return self
        fx = object.__getattribute__(instance, 'fx')
        fx.point(self.kind + '.descriptor.' + self.name + '.before')
        result = (DetachedCall(fx, self.kind, self.name)
                  if fx.recipe.get('descriptor_detached') else
                  BoundOverride(fx, instance, self.kind, self.name))
        fx.point(self.kind + '.descriptor.' + self.name + '.after')
        return result


class DescriptorService(Service):
    __slots__ = ()
    _context = ProviderDescriptor('service', '_context')
    _build_receipt = ProviderDescriptor('service', '_build_receipt')
    _required_claims = ProviderDescriptor('service', '_required_claims')
    _reference_adoption_evaluation = ProviderDescriptor('service', '_reference_adoption_evaluation')
    _reference_adoption_net_benefit = ProviderDescriptor('service', '_reference_adoption_net_benefit')
    _native = ProviderDescriptor('service', '_native')
    _conditional_slot = ProviderDescriptor('service', '_conditional_slot')
    _reference_slot_adopt = ProviderDescriptor('service', '_reference_slot_adopt')
    _reference_slot_rollback = ProviderDescriptor('service', '_reference_slot_rollback')


class DescriptorLedger(Ledger):
    __slots__ = ()
    validate_u64 = ProviderDescriptor('ledger', 'validate_u64')
    rollback = ProviderDescriptor('ledger', 'rollback')
    admit_evaluation = ProviderDescriptor('ledger', 'admit_evaluation')
    admit_net_benefit = ProviderDescriptor('ledger', 'admit_net_benefit')
    adopt = ProviderDescriptor('ledger', 'adopt')


class DescriptorStore(Store):
    __slots__ = ()
    get_json = ProviderDescriptor('store', 'get_json')
    get = ProviderDescriptor('store', 'get')
    json = ProviderDescriptor('store', 'json')


class Fixture:
    def __init__(self, case):
        self.case = case
        self.recipe = case.get('recipe', {})
        self.events, self.raw_tracebacks, self.callback_errors = [], [], []
        self.late_events, self.closed = [], False
        self.refs, self.aliases, self.occurrences = [], {}, {}
        self.outer = None
        self.injected_fault = None
        self.fault_injected = False
        self.native_calls = 0
        self.cuts = []
        self.namespace = {'__builtins__': dict(vars(builtins)),
                          'uint64': self.uint64, 'digest': self.digest, 'reject': self.reject}
        for name in self.recipe.get('global_missing', []):
            self.namespace.pop(name, None)
            self.namespace['__builtins__'].pop(name, None)
        for name in self.recipe.get('global_builtin', []):
            self.namespace['__builtins__'][name] = self.namespace.pop(name)
        fault = case.get('fault')
        if fault is not None:
            self.injected_fault = ERRORS[fault['family']]('injected:' + fault['event'])
        mask = self.recipe.get('ledger', [True, True] if case['mode'] == 'rollback' else [True, True, True])
        self.ledger_reads = []
        for flag in mask:
            self.ledger_reads.append(bool(flag))  # condition lookup
            if flag:
                self.ledger_reads.append(True)   # original repeated method lookup
        for index in self.recipe.get('ledger_relookup_none', []):
            self.ledger_reads[index] = False

    def register(self, value, token):
        self.refs.append((token, weakref.ref(value)))

    def active(self):
        value = sys.exception()
        if value is None:
            return None
        if value is self.outer:
            return 'outer'
        if value is self.injected_fault:
            return 'injected'
        return type(value).__name__

    def point(self, event, details=None):
        number = self.occurrences.get(event, 0) + 1
        self.occurrences[event] = number
        row = {'event': event, 'occurrence': number, 'active_exception': self.active()}
        if details is not None:
            row['details'] = details
        self.events.append(row)
        self.cuts.append({'event': event, 'occurrence': number})
        fault = self.case.get('fault')
        if fault and event == fault['event'] and number == fault['occurrence']:
            if self.fault_injected:
                raise AssertionError('one injected fault reached twice')
            self.fault_injected = True
            raise self.injected_fault

    def snapshot(self, value, seen=None):
        if seen is None:
            seen = set()
        if value is None or type(value) in (bool, int, str):
            return {'type': type(value).__name__, 'value': value}
        if type(value) is float:
            return {'type': 'float', 'hex': value.hex()}
        if type(value) is bytes:
            return {'type': 'bytes', 'hex': value.hex()}
        if isinstance(value, Observed):
            result = {'type': type(value).__name__, 'token': value.token}
            if type(value) is Value:
                result['value'] = self.snapshot(value.value, seen)
            return result
        if id(value) in seen:
            return {'cycle': type(value).__name__}
        seen.add(id(value))
        try:
            if type(value) in (tuple, list):
                return {'type': type(value).__name__, 'items': [self.snapshot(item, seen) for item in value]}
            if type(value) is dict:
                return {'type': 'dict', 'items': [[self.snapshot(k, seen), self.snapshot(v, seen)]
                                                for k, v in value.items()]}
            if type(value) is types.MethodType:
                return {'type': 'bound-method', 'name': value.__name__,
                        'receiver': self.snapshot(value.__self__, seen)}
            if type(value) is types.FunctionType:
                return {'type': 'function', 'name': value.__name__}
            return {'type': type(value).__name__}
        finally:
            seen.remove(id(value))

    def exception(self, error, seen=None):
        if seen is None:
            seen = set()
        if id(error) in seen:
            return {'cycle': type(error).__name__}
        seen.add(id(error))
        result = {'type': type(error).__name__, 'module': type(error).__module__,
                  'args': self.snapshot(error.args), 'injected_identity': error is self.injected_fault,
                  'outer_identity': error is self.outer,
                  'suppress_context': error.__suppress_context__}
        for name in ('name', 'obj', 'value', 'code', 'stage'):
            if hasattr(error, name):
                result[name] = self.snapshot(getattr(error, name))
        result['cause'] = None if error.__cause__ is None else self.exception(error.__cause__, seen)
        result['context'] = None if error.__context__ is None else self.exception(error.__context__, seen)
        seen.remove(id(error))
        return result

    def value(self, specification, token):
        if type(specification) is not dict:
            return specification
        kind = specification.get('kind')
        if kind == 'opaque':
            return Value(self, token, specification.get('value', token))
        if kind == 'int':
            return int(specification['decimal'])
        if kind == 'bytes':
            return bytes.fromhex(specification['hex'])
        if kind == 'string_codepoints':
            return ''.join(chr(value) for value in specification['codepoints'])
        if kind == 'float':
            return float.fromhex(specification['hex'])
        if kind == 'list':
            return [self.value(item, token + '.' + str(i)) for i, item in enumerate(specification['items'])]
        if kind == 'dict':
            return {key: self.value(item, token + '.' + key) for key, item in specification['items'].items()}
        raise ValueError('unsupported frozen value recipe')

    def make_service(self):
        cls = (DescriptorService if self.recipe.get('calls') == 'descriptor' else
               ServiceSubclass if self.recipe.get('service_subclass') else Service)
        return cls(self)

    def make_ledger(self):
        return (DescriptorLedger if self.recipe.get('calls') == 'descriptor' else Ledger)(self)

    def make_store(self):
        return (DescriptorStore if self.recipe.get('calls') == 'descriptor' else Store)(self)

    def make_arguments(self):
        values = {
            'context': Value(self, 'arguments.context', 'context'),
            'target_slot': Value(self, 'arguments.target_slot', 'target-slot'),
            'candidate_artifact': Value(self, 'arguments.candidate_artifact', 'candidate'),
            'evaluation_receipt': Value(self, 'arguments.evaluation_receipt', 'evaluation'),
            'verification_receipts': Value(self, 'arguments.verification_receipts', 'verification'),
            'retained_generation': self.value(self.recipe.get('retained_generation', '1'), 'arguments.retained_generation'),
            'reason': Value(self, 'arguments.reason', 'reason'),
            'expected_current': Value(self, 'arguments.expected_current', 'expected-current'),
        }
        return Mapping(self, 'arguments', values)

    def sequence(self, site, values):
        kind = self.recipe.get('unpack', {}).get(site, 'tuple')
        if kind.startswith('short-'):
            values = values[:int(kind.split('-')[1])]
            kind = 'iter'
        elif kind == 'long':
            values = [*values, Value(self, site + '.extra')]
            kind = 'iter'
        if kind == 'tuple':
            return tuple(values)
        if kind == 'list':
            return list(values)
        return Sequence(self, site, tuple(values), kind)

    def provider(self, site, arguments, keywords):
        self.point(site + '.call.before', {
            'arguments': self.snapshot(arguments), 'keywords': self.snapshot(keywords)})
        if site in ('ledger.validate_u64', 'global.uint64',
                    'service._build_receipt', 'ledger.admit_evaluation',
                    'service._reference_adoption_evaluation', 'store.get',
                    'ledger.admit_net_benefit', 'service._reference_adoption_net_benefit'):
            result = Value(self, site + '.ignored-result')
        elif site == 'service._context':
            result = Value(self, 'context-local', 'context-local')
        elif site == 'store.get_json':
            mismatch = self.recipe.get('mismatch')
            values = {
                'context': Value(self, 'evaluation.context', 'wrong' if mismatch == 'context' else 'context'),
                'candidate_artifact': Value(self, 'evaluation.candidate_artifact', 'wrong' if mismatch == 'candidate' else 'candidate'),
                'installation': Value(self, 'evaluation.installation', 'wrong' if mismatch == 'installation' else 'installation'),
                'build_receipt': Value(self, 'evaluation.build_receipt', 'build'),
                'baseline_core_sha256': Value(self, 'evaluation.baseline_core_sha256', 'core'),
                'measurements': Value(self, 'evaluation.measurements', 'measurements'),
                'full_cost_ledger': Value(self, 'evaluation.full_cost_ledger', 'cost-ledger'),
                'baseline_artifact': Value(self, 'evaluation.baseline_artifact', 'baseline'),
            }
            result = self.sequence('evaluation-unpack', [Mapping(self, 'evaluation', values),
                                                       Value(self, 'evaluation-ignored-metadata')])
        elif site == 'service._required_claims':
            result = Value(self, 'objective', 'objective')
            replacement = self.recipe.get('replace_global_after_claims')
            if replacement is not None:
                self.namespace[replacement] = self.replaced_global
        elif site == 'service._native':
            self.native_calls += 1
            side = 'candidate' if self.native_calls == 1 else 'baseline'
            signature = 'different' if self.recipe.get('mismatch') == 'abi' and side == 'candidate' else 'same-signatures'
            metadata = Mapping(self, side + '-metadata',
                               {'signatures': Value(self, side + '-signatures', signature)})
            result = self.sequence(side + '-native-unpack',
                [Value(self, side + '-data'), metadata, Value(self, side + '-program')])
        elif site == 'service._conditional_slot':
            result = Mapping(self, 'snapshot', {'current': Value(self, 'snapshot-current', 'old-current')})
        elif site in ('ledger.rollback', 'service._reference_slot_rollback'):
            result = self.sequence('rollback-unpack',
                [Value(self, 'current', 'new-current'), Value(self, 'artifact', 'active-artifact')])
        elif site in ('ledger.adopt', 'service._reference_slot_adopt'):
            result = Value(self, 'current', 'new-current')
        elif site == 'store.json':
            self.events.append({'event': 'receipt-content', 'value': self.snapshot(arguments[0])})
            result = Value(self, 'receipt', 'receipt')
        else:
            raise AssertionError('unknown original provider: ' + site)
        self.point(site + '.call.after', {'result': self.snapshot(result)})
        return result

    def uint64(self, *args, **kwargs):
        return self.provider('global.uint64', args, kwargs)

    def digest(self, value):
        self.point('global.digest.call.before', {'value': self.snapshot(value)})
        result = Value(self, 'abi', 'abi-digest')
        self.point('global.digest.call.after')
        return result

    def reject(self, code, message, stage=None):
        self.point('global.reject.call.before', {'code': code, 'message': message, 'stage': stage})
        if self.recipe.get('reject_returns'):
            result = Value(self, 'reject.ignored-result')
            self.point('global.reject.call.after')
            return result
        raise Refusal(code, message, stage)

    def replaced_global(self, *args, **kwargs):
        self.point('global.replacement.call.before', {'arguments': self.snapshot(args)})
        result = Value(self, 'replacement-result')
        self.point('global.replacement.call.after')
        return result


def observe(case, *, factory=None):
    """One full observation, including explicitly declared consumer phases.

The semantic output is copied at its endpoint. Full raw traceback frames are
returned separately, never normalized into candidate expectations.
"""
    history = []
    for index in range(case.get('recipe', {}).get('prime_count', 0)):
        warm = {'id': case['id'] + '.declared-prime-' + str(index),
                'mode': case['mode'], 'outer': False, 'recipe': {}}
        history.append(observe(warm, factory=factory))
    fx = Fixture(case)
    run = original if factory is None else factory
    held = []
    result = None
    outcome = None

    def invoke():
        return run(case['mode'], fx.make_service, fx.make_arguments, fx.namespace)

    def consume():
        nonlocal result, outcome
        try:
            result = invoke()
            outcome = {'kind': 'returned', 'value': fx.snapshot(result)}
            fx.events.append({'event': 'returned-to-consumer', 'active_exception': fx.active()})
        except BaseException as error:
            outcome = {'kind': 'raised', 'error': fx.exception(error)}
            fx.raw_tracebacks.append({
                'type': type(error).__name__,
                'frames': [{'filename': entry.filename, 'lineno': entry.lineno,
                            'name': entry.name, 'line': entry.line}
                           for entry in traceback.extract_tb(error.__traceback__)],
            })
            fx.events.append({'event': 'caught-by-consumer', 'active_exception': fx.active()})
            if case.get('recipe', {}).get('traceback') in ('release-inside', 'release-outside'):
                held.append(error)
            if case.get('recipe', {}).get('traceback') == 'release-inside':
                held.clear()
                fx.events.append({'event': 'explicit-held-error-release-inside', 'active_exception': fx.active()})
        fx.events.append({'event': 'consumer-release-result', 'active_exception': fx.active()})
        result = None
        # This drops the observer's preowned injected reference. The original
        # error/traceback remains live only through explicit held or callers.
        fx.injected_fault = None
        if case.get('recipe', {}).get('traceback') == 'release-outside':
            fx.events.append({'event': 'before-explicit-held-error-release-outside', 'active_exception': fx.active()})
            held.clear()
            fx.events.append({'event': 'after-explicit-held-error-release-outside', 'active_exception': fx.active()})

    if case.get('outer', False):
        try:
            raise LookupError('outer-original-observation')
        except LookupError as outer:
            fx.outer = outer
            consume()
            fx.events.append({'event': 'outer-restored', 'is_original': sys.exception() is outer})
        fx.outer = None
    else:
        consume()
    if held:
        raise AssertionError('observer held unexpected error after declared release')
    if case.get('recipe', {}).get('explicit_gc'):
        fx.events.append({'event': 'explicit-final-gc', 'collected': gc.collect(),
                          'active_exception': fx.active()})
    live = [{'token': token, 'alive': reference() is not None} for token, reference in fx.refs]
    value = {'case': case['id'], 'mode': case['mode'], 'outcome': outcome,
             'events': fx.events, 'live_at_endpoint': live,
             'callback_errors': fx.callback_errors, 'fault_injected': fx.fault_injected,
             'declared_history': [row['observation'] for row in history]}
    # Deep copy through the sole canonical representation prevents later GC
    # from mutating a record that was already returned by this observation.
    frozen = json.loads(canonical(value))
    raw = json.loads(canonical(fx.raw_tracebacks))
    cuts = json.loads(canonical(fx.cuts))
    fx.closed = True
    # Only observer scaffolding is released after the semantic endpoint. It
    # owns no user receiver/value; late finalizers remain externally visible.
    fx.namespace.clear()
    return {'observation': frozen, 'raw_tracebacks': raw, 'cutpoints': cuts,
            'late_events': fx.late_events}
