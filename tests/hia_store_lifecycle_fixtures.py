"""Observable foreign effects for the unchanged current Store lifecycle bodies.

These are test providers, not a replacement production Store or an alternative
policy. The frozen original and actual native image see the same providers.
"""
from __future__ import annotations

from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
from unittest.mock import patch

from hepta import hia_agent_store as store_api
from hepta import hia_execution_budget as budget_api

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/store_lifecycle_ad352ee.py.txt'
FIXTURE_SHA = '098ef2094a48b93782f740762ed932e7eaf0b734f71db49dac57c29260c877e3'


def frozen(namespace=None):
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA:
        raise AssertionError('frozen original Store lifecycle changed')
    scope = dict(vars(store_api)) if namespace is None else dict(namespace)
    exec(compile(raw, str(FIXTURE), 'exec'), scope)
    return scope['FrozenStoreLifecycle']


class PrimaryFailure(BaseException):
    def __init__(self, fixture, label='primary'):
        super().__init__(label)
        self.fixture, self.label = fixture, label

    def add_note(self, note):
        self.fixture.event('note', self.label, note)
        if self.fixture.note_fails:
            raise self.fixture.note_error
        super().add_note(note)


class CleanupFailure(BaseException):
    pass


class NoteFailure(BaseException):
    pass


class ObservedInfo:
    def __init__(self, fixture, name, mode, uid=7):
        self.fixture, self.name = fixture, name
        self.fields = dict(st_mode=mode, st_uid=uid, st_dev=11, st_ino=19)

    def __getattribute__(self, key):
        if key in ('st_mode', 'st_uid', 'st_dev', 'st_ino'):
            fixture = object.__getattribute__(self, 'fixture')
            name = object.__getattribute__(self, 'name')
            fixture.event('stat-field', name, key)
            return object.__getattribute__(self, 'fields')[key]
        return object.__getattribute__(self, key)


class ObservedPath:
    def __init__(self, fixture, name):
        self.fixture, self.name = fixture, name

    def absolute(self):
        self.fixture.event('absolute', self.name)
        return self

    def mkdir(self, **keywords):
        self.fixture.event('mkdir', self.name, keywords)

    def is_symlink(self):
        self.fixture.event('is_symlink', self.name)
        return self.fixture.symlink == self.name

    def resolve(self):
        self.fixture.event('resolve', self.name)
        return self

    def stat(self):
        self.fixture.event('stat', self.name)
        return self.fixture.infos[self.name]

    def lstat(self):
        self.fixture.event('lstat', self.name)
        if self.name == 'root/state.sqlite3' and self.fixture.connected and self.fixture.after_connect_not_regular:
            return self.fixture.nonregular
        return self.fixture.infos[self.name]

    def exists(self):
        self.fixture.event('exists', self.name)
        return self.fixture.database_exists

    def __truediv__(self, suffix):
        self.fixture.event('divide', self.name, suffix)
        return ObservedPath(self.fixture, self.name + '/' + suffix)

    def __str__(self):
        self.fixture.event('str-path', self.name)
        return self.name


class ObservedDatabase:
    def __init__(self, fixture):
        object.__setattr__(self, 'fixture', fixture)
        object.__setattr__(self, 'close_count', 0)

    def __setattr__(self, key, value):
        if key == 'row_factory':
            self.fixture.event('row_factory', value)
        object.__setattr__(self, key, value)

    def execute(self, statement):
        self.fixture.event('execute', statement)
        return self

    def fetchone(self):
        self.fixture.event('fetchone')
        return None

    def executescript(self, script):
        self.fixture.event('executescript', script)

    def close(self):
        self.close_count += 1
        self.fixture.event('db.close')
        if self.fixture.cleanup_fails:
            raise self.fixture.cleanup_error


class ObservedBudget:
    def __init__(self, fixture):
        self.fixture = fixture

    def close(self):
        self.fixture.event('budget.close')


class Fixture:
    def __init__(self, *, budget=False, database_exists=False, symlink=None,
                 wrong_uid=None, writable=None, non_directory=False,
                 database_not_regular=False, sidecar_not_regular=False,
                 after_connect_not_regular=False, fail_at=None,
                 cleanup_fails=False, note_fails=False, reject_returns=False):
        self.trace = []
        self.fail_at, self.cleanup_fails, self.note_fails = fail_at, cleanup_fails, note_fails
        self.budget, self.database_exists, self.symlink = budget, database_exists, symlink
        self.after_connect_not_regular, self.reject_returns = after_connect_not_regular, reject_returns
        self.connected = False
        self.primary = PrimaryFailure(self)
        self.cleanup_error, self.note_error = CleanupFailure('cleanup'), NoteFailure('note')
        self.admission = object() if budget else None
        self.row_factory = object()
        self.lock = object()
        self.infos = {}
        for name in ('root', 'root/artifacts', 'root/state.sqlite3',
                     'root/state.sqlite3-wal', 'root/state.sqlite3-shm'):
            mode = (stat.S_IFDIR | 0o700) if name in ('root', 'root/artifacts') else (stat.S_IFREG | 0o600)
            if (name == 'root/artifacts' and non_directory
                    or name == 'root/state.sqlite3' and database_not_regular
                    or name == 'root/state.sqlite3-wal' and sidecar_not_regular):
                mode = stat.S_IFIFO | 0o600
            if name == writable:
                mode |= 0o022
            self.infos[name] = ObservedInfo(self, name, mode, 8 if name == wrong_uid else 7)
        self.nonregular = ObservedInfo(self, 'after-connect', stat.S_IFIFO | 0o600)
        self.db = ObservedDatabase(self)
        self.budget_owner = ObservedBudget(self)
        fixture = self

        class Store:
            def __setattr__(self, key, value):
                fixture.event('set-store', key, value)
                object.__setattr__(self, key, value)

            def __getattribute__(self, key):
                if key in ('root', 'artifacts', 'db', 'database', 'database_identity',
                           'lock', 'database_sidecars', 'execution_budgets'):
                    fixture.event('get-store', key)
                return object.__getattribute__(self, key)

        self.store = Store()
        self.namespace = dict(vars(store_api))
        self.namespace.update(Path=self.path,
            os=SimpleNamespace(geteuid=self.geteuid, chmod=self.chmod),
            stat=SimpleNamespace(S_ISDIR=self.isdir, S_ISREG=self.isreg),
            sqlite3=SimpleNamespace(connect=self.connect, Row=self.row_factory),
            threading=SimpleNamespace(RLock=self.rlock), reject=self.reject)

    def normalized(self, value):
        if isinstance(value, ObservedPath):
            return ('path', value.name)
        if value is self.db:
            return 'database'
        if value is self.budget_owner:
            return 'budget'
        if value is self.admission and value is not None:
            return 'admission'
        if value is self.row_factory:
            return 'row-factory'
        if value is self.lock:
            return 'lock'
        if value is self.store:
            return 'store'
        if type(value) is dict:
            return {key: self.normalized(item) for key, item in value.items()}
        if type(value) in (tuple, list):
            return tuple(self.normalized(item) for item in value)
        return value

    def event(self, *event):
        active = sys.exception()
        label = None if active is None else str(active)
        self.trace.append((self.normalized(event), label))
        if self.fail_at is not None and len(self.trace) == self.fail_at:
            raise self.primary

    def path(self, name):
        self.event('Path', name)
        return ObservedPath(self, name)

    def geteuid(self):
        self.event('geteuid')
        return 7

    def chmod(self, path, mode):
        self.event('chmod', path, mode)

    def isdir(self, mode):
        self.event('isdir', mode)
        return stat.S_ISDIR(mode)

    def isreg(self, mode):
        self.event('isreg', mode)
        return stat.S_ISREG(mode)

    def connect(self, database, **keywords):
        self.event('connect', database, keywords)
        self.connected = True
        return self.db

    def rlock(self):
        self.event('RLock')
        return self.lock

    def admit_budget(self):
        self.event('admit_budget')
        return self.admission

    def create_budget(self, store, admission):
        self.event('create_budget', store, admission)
        return self.budget_owner

    def reject(self, *arguments):
        self.event('reject', *arguments)
        if not self.reject_returns:
            raise store_api.AgentRejected(*arguments)

    def observe(self, function):
        with ExitStack() as stack:
            stack.enter_context(patch.object(budget_api, 'admitted_execution_budget', self.admit_budget))
            stack.enter_context(patch.object(budget_api, 'execution_budget_store', self.create_budget))
            error = None
            try:
                result = function()
            except BaseException as caught:
                error = caught
                result = ('raised', type(caught).__name__, str(caught),
                          tuple(getattr(caught, '__notes__', ())))
            else:
                result = ('returned', result)
        fields = self.normalized(vars(self.store))
        return {'result': result, 'trace': self.trace, 'fields': fields, 'closed': self.db.close_count}, error
