"""Independent original-only SQL expression observer. No run authorized yet."""
from __future__ import annotations
import argparse
import base64
import builtins
import gc
import hashlib
import importlib.abc
import json
from pathlib import Path
import sys
import types
import weakref
ROOT = Path(__file__).resolve().parent
ORIGINAL_SHA256 = 'b8c81da6c1bd879756e29ba9cc2f943af00deef35d5729928253d2ec395dcd80'


def canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode()


class NoProduct(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('hepta', 'tools', 'sqlite3', 'ctypes', 'subprocess'):
            raise AssertionError('forbidden original-observer import: ' + fullname)


def forbid_effect(event, arguments):
    if event in ('subprocess.Popen', 'os.system', 'sqlite3.connect', 'ctypes.dlopen', 'ctypes.dlsym', 'os.fork', 'os.forkpty', 'socket.__new__') or event.startswith('os.exec'):
        raise AssertionError('forbidden original-observer effect: ' + event)


class Rejected(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Harness:
    def __init__(self, case):
        self.case, self.events, self.late = case, [], []
        self.phase, self.closed = 'setup', False
        self.refs, self.identities, self.serials, self.hits = {}, {}, {}, {}
        self.outer = self.fault = None
        if case.get('fault'):
            self.fault = getattr(builtins, case['fault']['type'])('fault:' + case['fault']['point'])
        self.fault_count = 0
        self.sql_counts = {'select': 0, 'insert': 0}
        self.service = self.current_store = None

    def tag(self, obj, stem):
        serial = self.serials.get(stem, 0) + 1
        self.serials[stem] = serial
        label = stem + str(serial)
        ref = weakref.ref(obj)
        self.refs[label] = ref
        self.identities[id(obj)] = ref, label
        return label

    def view(self, value):
        if type(value) in (str, int, bool, float, type(None)):
            return value
        if type(value) is bytes:
            return {'bytes_hex': value.hex()}
        tagged = self.identities.get(id(value))
        if tagged and tagged[0]() is value:
            return {'object': tagged[1], 'type': type(value).__name__}
        if type(value) in (tuple, list):
            return {'type': type(value).__name__, 'items': [self.view(v) for v in value]}
        if type(value) is dict:
            return {'type': 'dict', 'items': [[str(k), self.view(v)] for k, v in value.items()]}
        return {'type': type(value).__name__}

    def error_identity(self, error):
        return 'injected' if error is self.fault else 'outer' if error is self.outer else None

    def active(self):
        error = sys.exception()
        return None if error is None else {'type': type(error).__name__, 'identity': self.error_identity(error)}

    def note(self, point, **values):
        event = {'point': point, 'phase': self.phase, 'active_exception': self.active(), **{k: self.view(v) for k, v in values.items()}}
        (self.late if self.closed else self.events).append(event)

    def hit(self, point, **values):
        ordinal = self.hits.get(point, 0) + 1
        self.hits[point] = ordinal
        self.note(point, occurrence=ordinal, **values)
        fault = self.case.get('fault')
        if fault and fault['point'] == point and fault.get('occurrence', 1) == ordinal:
            self.fault_count += 1
            raise self.fault
        action = self.case.get('action')
        if action and action['point'] == point and action.get('occurrence', 1) == ordinal:
            self.action(action['kind'])

    def action(self, kind):
        self.note('argument.action.begin', kind=kind)
        if kind == 'gc':
            self.note('argument.gc.returned', collected=gc.collect())
        elif kind == 'rebind-service':
            service = self.service()
            service._replacement = Store(self, 'replacement')
            self.note('argument.service.rebound', replacement=service._replacement)
        elif kind == 'rebind-db':
            store = None if self.current_store is None else self.current_store()
            self.note('argument.borrowed-store.alive', alive=store is not None)
            if store is not None:
                store._db = Database(self, 'replacement')
                self.note('argument.db.rebound', database=store._db)
        else:
            raise AssertionError(kind)
        self.note('argument.action.end', kind=kind)

    def error(self, error, seen=None):
        seen = set() if seen is None else seen
        if id(error) in seen:
            return {'cycle': type(error).__name__}
        seen.add(id(error))
        get = BaseException.__getattribute__
        value = {'type': type(error).__name__, 'identity': self.error_identity(error), 'args': self.view(get(error, 'args')), 'suppress_context': get(error, '__suppress_context__')}
        for name in ('name', 'obj', 'code'):
            try:
                value[name] = self.view(get(error, name))
            except AttributeError:
                pass
        for name in ('__cause__', '__context__'):
            item = get(error, name)
            value[name] = None if item is None else self.error(item, seen)
        return value

    def wire(self, value):
        self.hit('wire', value=value)
        return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()

    def digest(self, value):
        self.hit('digest', value=value)
        return 'sql-observer-cursor'

    def reject(self, code, message):
        self.hit('reject', code=code, message=message)
        raise Rejected(code, message)

    def alive(self):
        return {key: ref() is not None for key, ref in sorted(self.refs.items())}


class TraceMap:
    def __init__(self, h, name, values):
        self.h, self.name, self.values = h, name, values
        self.label = h.tag(self, name + '-')

    def __getitem__(self, key):
        self.h.hit(self.name + '.get.' + key)
        return self.values[key]

    def __contains__(self, key):
        self.h.hit(self.name + '.contains.' + key)
        return key in self.values

    def get(self, key, default=None):
        self.h.hit(self.name + '.method_get.' + key, default=default)
        return self.values.get(key, default)

    def __del__(self):
        self.h.note('mapping.delete', label=self.label)


class Offset(int):
    def __new__(cls, h, value):
        result = super().__new__(cls, value)
        result.h = h
        return result

    def __add__(self, other):
        self.h.hit('offset.add', left=int(self), right=other)
        return int(self) + other


class Metadata:
    def __init__(self, h):
        self.h, self.label = h, h.tag(self, 'metadata-')
        h.note('metadata.created', label=self.label)

    def __del__(self):
        self.h.note('metadata.delete', label=self.label)


def execute(h, stage, label, owner, sql, parameters):
    kind = 'select' if sql.startswith('SELECT ') else 'insert'
    h.hit('db.' + stage + '.execute.before', receiver=label, sql=sql, parameters=parameters)
    h.sql_counts[kind] += 1
    h.note('sql.fake-effect', kind=kind, ordinal=h.sql_counts[kind], receiver=label)
    h.hit('db.' + stage + '.execute.after', receiver=label)
    row = None if kind == 'insert' else TraceMap(h, 'row', {
        'artifact_id': 'artifact-A', 'sha256': 'digest-A', 'offset': Offset(h, 0)})
    retained_db = owner if h.case.get('cursor_retains_db', True) else None
    return Cursor(h, kind, row, retained_db)


class Callable:
    def __init__(self, h, stage, operation, owner, retain, payload=None):
        self.h, self.stage, self.operation = h, stage, operation
        self.owner = owner if retain else None
        self.receiver_label = object.__getattribute__(owner, 'label')
        self.payload = payload
        self.label = h.tag(self, operation + '-callable-')
        h.note('callable.created', label=self.label, receiver=self.receiver_label, retains_owner=retain)

    def __call__(self, *arguments):
        if self.operation == 'execute':
            return execute(self.h, self.stage, self.receiver_label, self.owner, *arguments)
        self.h.hit('cursor.' + self.stage + '.fetchone.before', receiver=self.receiver_label)
        self.h.hit('cursor.' + self.stage + '.fetchone.after', receiver=self.receiver_label)
        return self.payload

    def __del__(self):
        self.h.note('callable.delete', label=self.label)


class Database:
    def __init__(self, h, stage):
        self.h, self.stage = h, stage
        self.label = h.tag(self, 'db-' + stage + '-')
        h.note('db.created', label=self.label)

    def __getattribute__(self, name):
        if name == 'execute':
            h = object.__getattribute__(self, 'h')
            stage = object.__getattribute__(self, 'stage')
            h.hit('db.' + stage + '.execute.lookup', receiver=object.__getattribute__(self, 'label'))
            mode = h.case.get('execute_callable', 'method')
            if mode != 'method':
                return Callable(h, stage, 'execute', self, mode == 'bound')
        return object.__getattribute__(self, name)

    def execute(self, sql, parameters):
        return execute(self.h, self.stage, self.label, self, sql, parameters)

    def __del__(self):
        self.h.note('db.delete', label=self.label)


class Cursor:
    def __init__(self, h, kind, row, db):
        self.h, self.kind, self.row, self.db = h, kind, row, db
        self.label = h.tag(self, 'cursor-' + kind + '-')
        h.note('cursor.created', label=self.label, retains_db=db is not None)

    def __getattribute__(self, name):
        if name == 'fetchone':
            h = object.__getattribute__(self, 'h')
            kind = object.__getattribute__(self, 'kind')
            h.hit('cursor.' + kind + '.fetchone.lookup', receiver=object.__getattribute__(self, 'label'))
            mode = h.case.get('fetchone_callable', 'method')
            if mode != 'method':
                return Callable(h, kind, 'fetchone', self, mode == 'bound', object.__getattribute__(self, 'row'))
        return object.__getattribute__(self, name)

    def fetchone(self):
        self.h.hit('cursor.' + self.kind + '.fetchone.before', receiver=self.label)
        self.h.hit('cursor.' + self.kind + '.fetchone.after', receiver=self.label)
        return self.row

    def __del__(self):
        self.h.note('cursor.delete', label=self.label)


class Store:
    def __init__(self, h, stage, db=None):
        self.h, self.stage = h, stage
        self.label = h.tag(self, 'store-' + stage + '-')
        self._db = Database(h, stage) if db is None else db
        self._cycle = self if h.case.get('store_cycle') and stage in ('select', 'insert') else None
        h.note('store.created', label=self.label, intentional_self_cycle=self._cycle is self)

    def __getattribute__(self, name):
        if name == 'db':
            h = object.__getattribute__(self, 'h')
            stage = object.__getattribute__(self, 'stage')
            h.hit('store.' + stage + '.db.lookup', receiver=object.__getattribute__(self, 'label'))
            return object.__getattribute__(self, '_db')
        return object.__getattribute__(self, name)

    def get(self, ref):
        self.h.hit('store.get.before', ref=ref)
        self.h.hit('store.get.after')
        return b'abcdef', Metadata(self.h)

    def __del__(self):
        self.h.note('store.delete', label=self.label)


class Service:
    def __init__(self, h):
        self._h, self._lookups, self._replacement = h, 0, None
        self._get_store = Store(h, 'get')
        self._persistent = {}
        self._databases = {k: Database(h, k) for k in ('select', 'insert')} if h.case.get('persistent_db') else {}
        if h.case.get('store_lifetime', 'temporary') == 'persistent':
            self._persistent = {k: Store(h, k, self._databases.get(k)) for k in ('select', 'insert')}
        h.service = weakref.ref(self)
        h.tag(self, 'service-')

    def __getattribute__(self, name):
        if name == 'store':
            h = object.__getattribute__(self, '_h')
            index = object.__getattribute__(self, '_lookups') + 1
            object.__setattr__(self, '_lookups', index)
            if index == 1:
                h.hit('service.data-store.lookup')
                return object.__getattribute__(self, '_get_store')
            stage = 'select' if h.case.get('cursor', True) and index == 2 else 'insert'
            h.hit('sql.' + stage + '.store.lookup')
            replacement = object.__getattribute__(self, '_replacement')
            if replacement is not None:
                value = replacement
            elif h.case.get('store_lifetime', 'temporary') == 'persistent':
                value = object.__getattribute__(self, '_persistent')[stage]
            else:
                value = Store(h, stage, object.__getattribute__(self, '_databases').get(stage))
            h.current_store = weakref.ref(value)
            return value
        return object.__getattribute__(self, name)


def original_function(namespace):
    raw = (ROOT / 'original_hia_read.py.txt').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ORIGINAL_SHA256
    module = compile('class Original:\n' + raw.decode(), str(ROOT / 'original_hia_read.py.txt'), 'exec', dont_inherit=True)
    cls = next(c for c in module.co_consts if isinstance(c, types.CodeType) and c.co_name == 'Original')
    code = next(c for c in cls.co_consts if isinstance(c, types.CodeType) and c.co_name == '_hia_read')
    assert not code.co_freevars
    return types.FunctionType(code, namespace)


def traceback_record(error):
    result, tb = [], error.__traceback__
    while tb is not None:
        result.append({'file': tb.tb_frame.f_code.co_filename, 'function': tb.tb_frame.f_code.co_name, 'line': tb.tb_lineno})
        tb = tb.tb_next
    return result


def consume(h, function, service, args):
    value = error = None
    raw_traceback = []
    try:
        value = function(service, args)
    except BaseException as caught:
        error = caught
        h.phase = 'caller-error-held'
        outcome = {'status': 'raised', 'error': h.error(caught)}
        raw_traceback = traceback_record(caught)
    else:
        h.phase = 'caller-result-held'
        outcome = {'status': 'returned', 'value': h.view(value), 'ordered_keys': list(value) if type(value) is dict else None}
    h.note('caller.terminal', alive=h.alive())
    # A declared consumer boundary, not traceback/metadata normalization.
    h.phase = 'consumer-release'
    value = error = None
    h.fault = None
    h.note('caller.consumer-released', alive=h.alive())
    return outcome, raw_traceback


def observe(case):
    h = Harness(case)
    service = Service(h)
    ref = TraceMap(h, 'ref', {'id': 'artifact-A', 'sha256': 'digest-A'})
    values = {'artifact': ref, 'max_bytes': case.get('limit', 2)}
    if case.get('cursor', True):
        values['cursor'] = 'prior-cursor'
    args = TraceMap(h, 'args', values)
    namespace = {'__builtins__': dict(vars(builtins)), 'base64': base64, 'wire': h.wire, 'digest': h.digest, 'reject': h.reject}
    function = original_function(namespace)
    h.phase = 'original-call'
    if case.get('outer'):
        try:
            raise KeyError('declared-outer')
        except KeyError as outer:
            h.outer = outer
            outcome, raw_traceback = consume(h, function, service, args)
            h.note('caller.outer-after')
            h.outer = None
    else:
        outcome, raw_traceback = consume(h, function, service, args)
    h.phase = 'caller-input-release'
    del service, args, ref, values, function, namespace
    h.note('caller.inputs-released', alive=h.alive())
    h.phase = 'declared-final-gc'
    collected = gc.collect()
    h.note('caller.final-gc-returned', collected=collected, alive=h.alive())
    result = {'case': case['id'], 'outcome': outcome, 'events': h.events, 'fault_count': h.fault_count,
              'sql_fake_effects': h.sql_counts, 'weakly_observed_alive': h.alive(),
              'explicit_final_gc_collected': collected}
    snapshot = json.loads(canonical(result))
    h.closed = True
    return snapshot, h.late, raw_traceback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sys.meta_path.insert(0, NoProduct())
    sys.addaudithook(forbid_effect)
    freeze = json.loads((ROOT / 'freeze.json').read_bytes())
    def pins():
        return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in freeze['files']}
    before = pins()
    assert before == {name: row['sha256'] for name, row in freeze['files'].items()}
    cases = json.loads((ROOT / 'inputs.json').read_bytes())['cases']
    case, = [case for case in cases if case['id'] == args.case_id]
    observed, late, raw_traceback = observe(case)
    post_boundary_gc = gc.collect()
    assert observed['fault_count'] == (1 if case.get('fault') else 0)
    after = pins()
    assert before == after
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'observation.json').write_bytes(canonical(observed))
    (args.output / 'late-events.json').write_bytes(canonical(late))
    (args.output / 'raw-traceback.json').write_bytes(canonical(raw_traceback))
    (args.output / 'identity.json').write_bytes(canonical({'runtime': sys.version, 'executable': sys.executable,
        'source_before': before, 'source_after': after, 'fresh_original_code': True, 'case_id': case['id'],
        'post_boundary_gc_collected': post_boundary_gc, 'actual_sql': 0, 'native_entries': 0, 'vm_entries': 0, 'all_input_or_history_equivalence_claimed': False,
        'resource_generation_or_ack_guarantee_claimed': False}))


if __name__ == '__main__':
    main()
