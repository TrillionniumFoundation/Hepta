"""Original-provider observations for the complete Store lifecycle bodies."""
from contextlib import ExitStack
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch
import stat
import sys


class InjectedFailure(RuntimeError):
    pass


class Fixture:
    def __init__(self, scenario, *, ambient=None):
        self.scenario = scenario
        self.ambient = ambient
        self.trace = []
        self.failures = {}
        self.enabled = scenario != 'no_native_admissions'
        self.db = Database(self)
        self.lock = SimpleNamespace(label='original-lock')
        self.row_type = type('Row', (), {})

    def clean(self, value):
        if isinstance(value, PathValue):
            return {'path': value.name}
        if isinstance(value, Owner):
            return {'owner': value.name}
        if isinstance(value, Database):
            return {'database': True}
        if value is self.row_type:
            return {'row_type': True}
        if value is self.lock:
            return {'lock': True}
        if isinstance(value, dict):
            return {key: self.clean(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.clean(item) for item in value]
        if value is None or type(value) in (str, int, bool):
            return value
        return {'type': type(value).__name__}

    def active_error(self):
        error = sys.exception()
        return None if error is None else [type(error).__name__, str(error)]

    def event(self, label, *args, **kwargs):
        self.trace.append([label, self.clean(args), self.clean(kwargs), self.active_error()])
        if self.scenario == 'fail:' + label or self.scenario.startswith('fail:' + label + '+'):
            failure = self.failures.setdefault(label, InjectedFailure(label))
            raise failure

    def path(self, name):
        self.event('Path', name)
        return PathValue(self, str(name))

    def admission(self, name):
        def call(**kwargs):
            self.event('admit:' + name, **kwargs)
            if self.scenario == 'namespace_only':
                return 'admission:' + name if name == 'namespace' else None
            return 'admission:' + name if self.enabled else None
        return call

    def factory(self, name):
        def call(store, admission, **kwargs):
            self.event('create:' + name, admission, **kwargs)
            return Owner(self, name) if name == 'budget' or admission is not None else None
        return call

    def connect(self, database, **kwargs):
        self.event('connect', database, **kwargs)
        return self.db

    def geteuid(self):
        self.event('geteuid')
        return 1000

    def chmod(self, path, mode):
        self.event('chmod', path, mode)

    def rlock(self):
        self.event('RLock')
        return self.lock

    def install(self, api):
        stack = ExitStack()
        stack.enter_context(patch.object(api, 'Path', self.path))
        stack.enter_context(patch.object(api, 'os', SimpleNamespace(geteuid=self.geteuid, chmod=self.chmod)))
        stack.enter_context(patch.object(api, 'sqlite3', SimpleNamespace(connect=self.connect, Row=self.row_type)))
        stack.enter_context(patch.object(api, 'threading', SimpleNamespace(RLock=self.rlock)))
        for module, name, admission, factory in (
            ('hia_execution_budget', 'budget', 'admitted_execution_budget', 'execution_budget_store'),
            ('hia_request_journal_native', 'request', 'admitted_request_journal', 'request_journal_store'),
            ('hia_artifact_namespace_native', 'namespace', 'admitted_artifact_namespace', 'artifact_namespace_store'),
            ('hia_slot_ledger_continuation_native', 'ledger', 'admitted_slot_ledger', 'slot_ledger_store'),
        ):
            provider = import_module('hepta.' + module)
            stack.enter_context(patch.object(provider, admission, self.admission(name)))
            stack.enter_context(patch.object(provider, factory, self.factory(name)))
        return stack


class PathValue:
    def __init__(self, fixture, name):
        self.fixture, self.name = fixture, name

    def __str__(self):
        self.fixture.event('str:' + self.name)
        return self.name

    def __truediv__(self, name):
        self.fixture.event('join:' + self.name, name)
        return PathValue(self.fixture, self.name + '/' + name)

    def absolute(self):
        self.fixture.event('absolute:' + self.name)
        return self

    def resolve(self):
        self.fixture.event('resolve:' + self.name)
        return self

    def mkdir(self, **kwargs):
        self.fixture.event('mkdir:' + self.name, **kwargs)

    def exists(self):
        self.fixture.event('exists:' + self.name)
        return self.fixture.scenario in ('existing_database', 'database_not_regular',
                                         'database_foreign_uid', 'database_writable')

    def is_symlink(self):
        self.fixture.event('symlink:' + self.name)
        return self.fixture.scenario == 'symlink:' + self.name

    def info(self, kind):
        self.fixture.event(kind + ':' + self.name)
        regular = self.name not in ('root', 'root/artifacts')
        mode = (stat.S_IFREG | 0o600) if regular else (stat.S_IFDIR | 0o700)
        uid = 1000
        scenario = self.fixture.scenario
        if scenario == 'foreign_uid:' + self.name:
            uid = 1001
        if scenario == 'writable:' + self.name:
            mode |= 0o022
        if scenario == 'nonordinary:' + self.name:
            mode = stat.S_IFIFO | 0o600
        if self.name == 'root/state.sqlite3':
            if scenario == 'database_not_regular':
                mode = stat.S_IFIFO | 0o600
            if scenario == 'database_foreign_uid':
                uid = 1001
            if scenario == 'database_writable':
                mode |= 0o022
            if scenario == 'database_postopen_nonordinary' and self.fixture.db.connected:
                mode = stat.S_IFIFO | 0o600
        return SimpleNamespace(st_uid=uid, st_mode=mode, st_dev=7, st_ino=11)

    def stat(self):
        return self.info('stat')

    def lstat(self):
        return self.info('lstat')


class Database:
    def __init__(self, fixture):
        object.__setattr__(self, 'fixture', fixture)
        object.__setattr__(self, 'connected', False)

    def __setattr__(self, name, value):
        self.fixture.event('db-set:' + name, value)
        object.__setattr__(self, name, value)

    def execute(self, sql):
        self.fixture.event('execute:' + sql)
        return self

    def executescript(self, sql):
        self.fixture.event('schema', sql)

    def fetchone(self):
        self.fixture.event('fetchone')
        return ('artifacts',)

    def close(self):
        self.fixture.event('close:database')
        if '+cleanup_failure' in self.fixture.scenario:
            raise self.fixture.failures.setdefault('cleanup:database', InjectedFailure('cleanup:database'))


class Owner:
    def __init__(self, fixture, name):
        self.fixture, self.name = fixture, name

    def close(self):
        self.fixture.event('close:' + self.name)
        if '+cleanup_failure' in self.fixture.scenario:
            raise self.fixture.failures.setdefault('cleanup:' + self.name, InjectedFailure('cleanup:' + self.name))


class StoreObject:
    def __init__(self, fixture):
        object.__setattr__(self, '_fixture', fixture)

    def __setattr__(self, name, value):
        self._fixture.event('set:' + name, value)
        object.__setattr__(self, name, value)


def outcome(fixture, call, store):
    try:
        result = call()
        error = None
    except BaseException as failure:
        result = None
        error = {
            'type': type(failure).__name__, 'args': fixture.clean(failure.args),
            'code': getattr(failure, 'code', None), 'phase': getattr(failure, 'phase', None),
            'notes': getattr(failure, '__notes__', None),
            'injected_identity': next((name for name, value in fixture.failures.items() if value is failure), None),
            'context': None if failure.__context__ is None else [type(failure.__context__).__name__, str(failure.__context__)],
            'cause': None if failure.__cause__ is None else [type(failure.__cause__).__name__, str(failure.__cause__)],
            'suppress_context': failure.__suppress_context__,
        }
    return {'trace': fixture.trace, 'error': error, 'result': fixture.clean(result),
            'attributes': {name: fixture.clean(value) for name, value in vars(store).items() if name != '_fixture'}}


SCENARIOS = (
    'all_native_admissions', 'no_native_admissions', 'namespace_only', 'existing_database',
    'symlink:root', 'foreign_uid:root', 'writable:root', 'symlink:root/artifacts',
    'foreign_uid:root/artifacts', 'writable:root/artifacts', 'nonordinary:root/artifacts',
    'database_not_regular', 'database_foreign_uid', 'database_writable',
    'nonordinary:root/state.sqlite3-wal', 'foreign_uid:root/state.sqlite3-wal',
    'writable:root/state.sqlite3-wal', 'nonordinary:root/state.sqlite3-shm',
    'fail:admit:budget', 'fail:admit:request', 'fail:admit:namespace', 'fail:admit:ledger',
    'fail:Path', 'fail:mkdir:root', 'fail:mkdir:root/artifacts', 'fail:connect',
    'fail:chmod', 'fail:db-set:row_factory', 'fail:execute:PRAGMA journal_mode=WAL',
    'fail:execute:PRAGMA synchronous=FULL', 'fail:RLock', 'fail:schema', 'fail:fetchone',
    'fail:create:budget', 'fail:create:request', 'fail:create:namespace', 'fail:create:ledger',
    'fail:create:ledger+cleanup_failure',
)
