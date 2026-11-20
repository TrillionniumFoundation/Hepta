"""Independent original-only observations of the Store's dynamic byte limit.

This finite addition preserves the earlier 463/160 fixtures. It executes the
unchanged 73f1634 put code with fake providers and stops at the first subsequent
admission effect. No candidate graph, native image, VM, SQL or filesystem effect
is used to determine an expected result.
"""
from __future__ import annotations

from types import FunctionType

from tests.hia_store_artifact_profile_oracle import Fixture, canonical


def cases():
    fixed = [
        ('default', 'default', 'ordinary'),
        ('zero', 0, 'ordinary'), ('zero-empty', 0, 'empty'),
        ('one', 1, 'ordinary'), ('equal', 12, 'ordinary'),
        ('below', 11, 'ordinary'),
        ('negative', -1, 'ordinary'), ('negative-empty', -1, 'empty'),
        ('huge-positive', 'huge-positive', 'ordinary'),
        ('huge-negative', 'huge-negative', 'ordinary'),
        ('bool-false', False, 'ordinary'), ('bool-true', True, 'ordinary'),
        ('nan', 'nan', 'ordinary'), ('positive-infinity', 'positive-infinity', 'ordinary'),
        ('negative-infinity', 'negative-infinity', 'ordinary'),
        ('none', None, 'ordinary'), ('string', 'invalid-string', 'ordinary'),
        ('list', 'invalid-list', 'ordinary'), ('missing', 'missing', 'ordinary'),
        ('wrong-data-no-read', 'missing', 'bytearray'),
        ('opaque-false', {'comparison': False}, 'ordinary'),
        ('opaque-true', {'comparison': True}, 'ordinary'),
        ('opaque-not-implemented', {'comparison': 'not-implemented'}, 'ordinary'),
        ('truth-false', {'comparison': 'truth', 'truth': False}, 'ordinary'),
        ('truth-true', {'comparison': 'truth', 'truth': True}, 'ordinary'),
        ('truth-invalid', {'comparison': 'truth', 'truth': 1}, 'ordinary'),
        ('comparison-rebind', {'comparison': False, 'rebind': -1}, 'ordinary'),
        ('int-subclass-false', {'comparison': False, 'int_subclass': True}, 'ordinary'),
        ('int-subclass-true', {'comparison': True, 'int_subclass': True}, 'ordinary'),
    ]
    result = [{'name': 'limit.' + name, 'method': 'put', 'limit': limit, 'data': data}
              for name, limit, data in fixed]
    for event in ('limit.lt', 'limit.truth'):
        for error in ('ValueError', 'OSError', 'StopIteration', 'KeyboardInterrupt'):
            result.append({'name': 'limit.' + event + '.' + error,
                'method': 'put', 'limit': {'comparison': 'truth', 'truth': False},
                'faults': [{'event': event, 'error': error, 'message': 'original-limit-' + error}]})
    for original in ('opaque-false', 'missing', 'limit.lt.StopIteration', 'limit.truth.OSError'):
        item = next(value for value in result if value['name'] == 'limit.' + original)
        result.append({**item, 'name': item['name'] + '.outer', 'outer_except': True})
    return result


class LimitNamespace(dict):
    """Observe the actual LOAD_GLOBAL ordering without a candidate adapter."""
    def __init__(self, values, fixture):
        super().__init__(values)
        self.fixture = fixture

    def __getitem__(self, name):
        if name in ('type', 'bytes', 'len', 'MAX_ARTIFACT_BYTES'):
            self.fixture.emit('limit.lookup' if name == 'MAX_ARTIFACT_BYTES'
                              else 'guard.lookup.' + name)
        return dict.__getitem__(self, name)


class LimitTruth:
    def __init__(self, fixture, value):
        self.fixture, self.value = fixture, value

    def __bool__(self):
        self.fixture.emit('limit.truth')
        return self.value


class OpaqueLimit:
    def __init__(self, fixture, specification):
        self.fixture, self.specification = fixture, specification

    def __lt__(self, other):
        self.fixture.emit('limit.lt', other)
        if 'rebind' in self.specification:
            value = self.specification['rebind']
            self.fixture.namespace['MAX_ARTIFACT_BYTES'] = value
            self.fixture.state['limit_rebound_to'] = value
        result = self.specification['comparison']
        if result == 'not-implemented':
            return NotImplemented
        if result == 'truth':
            return LimitTruth(self.fixture, self.specification['truth'])
        return result


class IntegerLimit(int):
    def __new__(cls, fixture, specification):
        value = super().__new__(cls, 67108864)
        value.fixture, value.specification = fixture, specification
        return value

    __lt__ = OpaqueLimit.__lt__


def prepare(case):
    # The accepted branch reaches this exact next original effect. The sentinel
    # keeps these controls about limit binding/first-error order, not unrelated
    # publication policy already covered by the separate complete 463 cases.
    specification = {**case, 'faults': [*case.get('faults', ()),
        {'event': 'native.admission', 'error': 'OSError', 'message': 'limit-boundary-complete'}]}
    fixture = Fixture(specification)
    namespace = LimitNamespace(fixture.namespace, fixture)
    fixture.namespace = namespace
    choice = case['limit']
    if type(choice) is dict:
        value = IntegerLimit(fixture, choice) if choice.get('int_subclass') else OpaqueLimit(fixture, choice)
    elif type(choice) is str:
        if choice == 'missing':
            del namespace['MAX_ARTIFACT_BYTES']
            return fixture
        value = {'default': 67108864, 'huge-positive': 1 << 4096,
            'huge-negative': -(1 << 4096), 'nan': float('nan'),
            'positive-infinity': float('inf'), 'negative-infinity': float('-inf'),
            'invalid-string': 'not-a-number', 'invalid-list': []}[choice]
    else:
        value = choice
    namespace['MAX_ARTIFACT_BYTES'] = value
    return fixture


def observe_original(case):
    fixture = prepare(case)
    original = fixture.namespace['OriginalStore'].put
    # Same frozen complete code object, with a transparent instrumented globals
    # dictionary. The method body and its evaluation/call order are unmodified.
    original = FunctionType(original.__code__, fixture.namespace,
                            original.__name__, original.__defaults__)
    return fixture.observe(lambda name, store, arguments, keywords, namespace:
                           original(store, *arguments, **keywords))


def observe_candidate(case, image, frame_type):
    fixture = prepare(case)
    return fixture.observe(lambda name, store, arguments, keywords, namespace:
                           frame_type(image, 1, store, arguments, namespace=namespace).finish())
