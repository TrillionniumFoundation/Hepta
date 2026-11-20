"""Pure original-method observations before writing any suspended-call prototype.

Only frozen json/profile/check_profile bodies run.  Providers, the store, SQL,
and callable descriptors are fake; this module imports no Hepta package.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
ERRORS = {
    'ValueError': ValueError, 'StopIteration': StopIteration,
    'OSError': OSError, 'AttributeError': AttributeError,
    'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit,
    'GeneratorExit': GeneratorExit, 'RuntimeError': RuntimeError,
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def original_namespace(fixture):
    names = ('json', 'profile', 'check_profile')
    text = 'class Original:\n' + ''.join(
        (ROOT / 'fixtures' / ('AgentStore.' + name + '.py.txt')).read_text() + '\n'
        for name in names)
    ns = {'wire': fixture.wire, 'decode_data': fixture.decode,
          'reject': fixture.reject, '__builtins__': __builtins__}
    exec(compile(text, '<frozen-73-Store-three-call-order-bodies>', 'exec'), ns)
    return ns


class Call:
    def __init__(self, fixture, name, generation):
        self.fixture, self.name, self.generation = fixture, name, generation

    def __call__(self, *args, **kwargs):
        f = self.fixture
        f.emit(self.name + '.call', self.generation, args, kwargs)
        f.maybe('callee')
        if self.name == 'put':
            return f.result
        if self.name == 'get_json':
            return Result(f)
        return Cursor(f)

    def __del__(self):
        f = self.fixture
        f.emit(self.name + '.delete', self.generation)


class Descriptor:
    def __init__(self, name):
        self.name = name

    def __get__(self, obj, cls=None):
        f = object.__getattribute__(obj, 'fixture')
        f.emit(self.name + '.descriptor')
        f.maybe('lookup')
        return Call(f, self.name, f.generation)


class Subject:
    def __init__(self, fixture):
        self.fixture = fixture
        self.db = DB(fixture)

    def __getattribute__(self, name):
        if name in ('put', 'get_json'):
            f = object.__getattribute__(self, 'fixture')
            if f.case.get('lookup') == 'descriptor':
                return object.__getattribute__(self, name)
            f.emit(name + '.lookup')
            f.maybe('lookup')
            return Call(f, name, f.generation)
        return object.__getattribute__(self, name)

    def json(self, value, kind):
        self.fixture.emit('subject.json', value, kind)
        return self.fixture.ref


class DescriptorSubject(Subject):
    put = Descriptor('put')
    get_json = Descriptor('get_json')


class DB:
    def __init__(self, fixture):
        self.fixture = fixture

    def __getattribute__(self, name):
        if name == 'execute':
            f = object.__getattribute__(self, 'fixture')
            f.emit('execute.lookup')
            # check_profile has an earlier SELECT which is deliberately not
            # the deferred-argument call under test.
            if f.case['method'] == 'profile':
                f.maybe('lookup')
            return Call(f, 'execute', f.generation)
        return object.__getattribute__(self, name)


class Cursor:
    def __init__(self, fixture):
        self.fixture = fixture

    def fetchone(self):
        self.fixture.emit('cursor.fetchone')
        return {'artifact': 'encoded-ref'}


class Result:
    def __init__(self, fixture):
        self.fixture = fixture

    def __getitem__(self, index):
        self.fixture.emit('result.getitem', index)
        self.fixture.maybe('getitem')
        return self.fixture.result


class Fixture:
    def __init__(self, case):
        self.case = case
        self.events = []
        self.generation = 1
        self.result = {'result': 'original-call'}
        self.ref = {'id': 'profile-id', 'sha256': 'profile-sha'}
        self.error = ERRORS[case.get('error', 'ValueError')]('provider-error')
        self.outer = RuntimeError('outer-active-error')
        self.subject = (DescriptorSubject if case.get('lookup') == 'descriptor'
                        else Subject)(self)
        self.namespace = original_namespace(self)

    def snapshot(self, value):
        if isinstance(value, (tuple, list)):
            return [self.snapshot(item) for item in value]
        if type(value) is dict:
            return {key: self.snapshot(item) for key, item in value.items()}
        if isinstance(value, bytes):
            return {'bytes': value.hex()}
        if value is self.subject:
            return {'identity': 'subject'}
        if value is self.subject.db:
            return {'identity': 'db'}
        return value

    def active(self):
        error = sys.exception()
        if error is None:
            return None
        if error is self.error:
            return 'provider-error'
        if error is self.outer:
            return 'outer-active-error'
        return type(error).__name__ + ':' + str(error)

    def emit(self, name, *values):
        self.events.append({'event': name, 'values': self.snapshot(values),
                            'active_exception': self.active()})

    def maybe(self, phase):
        if self.case.get('phase') == phase:
            # The initial SELECT in check_profile is not the call under test.
            if phase == 'callee' and self.case['method'] == 'check_profile':
                calls = [x for x in self.events if x['event'] == 'get_json.call']
                if not calls:
                    return
            raise self.error

    def wire(self, value):
        self.emit('wire', value)
        self.maybe('provider')
        if self.case.get('replace'):
            self.generation = 2
            self.emit('replace-call-target', 2)
        return b'encoded'

    def decode(self, value):
        self.emit('decode', value)
        self.maybe('provider')
        if self.case.get('replace'):
            self.generation = 2
            self.emit('replace-call-target', 2)
        return self.ref

    def reject(self, *args, **kwargs):
        raise AssertionError(('unexpected reject', args, kwargs))

    def exception(self, error):
        def related(value):
            if value is None:
                return None
            if value is self.error:
                return 'provider-error'
            if value is self.outer:
                return 'outer-active-error'
            return {'type': type(value).__name__, 'args': self.snapshot(value.args)}
        return {'type': type(error).__name__, 'args': self.snapshot(error.args),
                'is_original_error': error is self.error,
                'name': getattr(error, 'name', None),
                'obj': self.snapshot(getattr(error, 'obj', None)),
                'cause': related(error.__cause__),
                'context': related(error.__context__),
                'suppress_context': error.__suppress_context__}

    def invoke(self, owner=None):
        method = self.case['method']
        args = (({'value': 1}, 'kind', {'metadata': 1}) if method == 'json'
                else ('profile-id', {'value': 1}) if method == 'profile'
                else (self.ref, self.ref))
        callback = (getattr(self.namespace['Original'], method) if owner is None
                    else owner)
        return callback(self.subject, *args)

    def observe(self, owner=None):
        def run():
            try:
                result = self.invoke(owner)
                outcome = {'returned': self.snapshot(result),
                           'result_alias': result is self.result}
            except BaseException as error:
                outcome = {'exception': self.exception(error)}
            return outcome
        if self.case.get('outer_except'):
            try:
                raise self.outer
            except BaseException:
                outcome = run()
                self.emit('after-owner')
        else:
            outcome = run()
            self.emit('after-owner')
        return {'name': self.case['name'], 'outcome': outcome,
                'trace': json.loads(canonical(self.events))}


def cases():
    rows = []
    for method in ('json', 'check_profile', 'profile'):
        for outer in (False, True):
            for replace in (False, True):
                rows.append({'name': f'{method}.normal.outer{int(outer)}.replace{int(replace)}',
                             'method': method, 'outer_except': outer, 'replace': replace})
            for phase in ('lookup', 'provider', 'callee'):
                for error in ERRORS:
                    rows.append({'name': f'{method}.{phase}.{error}.outer{int(outer)}',
                                 'method': method, 'phase': phase, 'error': error,
                                 'outer_except': outer})
    for method in ('json', 'check_profile'):
        for outer in (False, True):
            rows.append({'name': f'{method}.descriptor.AttributeError.outer{int(outer)}',
                         'method': method, 'phase': 'lookup', 'error': 'AttributeError',
                         'lookup': 'descriptor', 'outer_except': outer})
    return rows


def main():
    inputs = cases()
    first = [Fixture(case).observe() for case in inputs]
    second = [Fixture(case).observe() for case in inputs]
    if canonical(first) != canonical(second):
        raise AssertionError('original observations are not repeatable')
    report = {'schema': 'hepta.hia.store-call-order-original-observations.v1',
              'runtime': sys.version, 'original_method_files': {
                  name: hashlib.sha256((ROOT / 'fixtures' / ('AgentStore.' + name + '.py.txt')).read_bytes()).hexdigest()
                  for name in ('json', 'profile', 'check_profile')},
              'candidate_executed': False, 'native_VM_SQL_filesystem_effects': False,
              'twice_identical': True, 'case_count': len(inputs), 'cases': inputs,
              'observations': first}
    dest = ROOT / ('call-order-original-py' + str(sys.version_info.major) + str(sys.version_info.minor) + '.json')
    data = canonical(report) + b'\n'
    dest.write_bytes(data)
    print(json.dumps({'path': str(dest), 'cases': len(inputs), 'sha256': hashlib.sha256(data).hexdigest()}))


if __name__ == '__main__':
    main()
