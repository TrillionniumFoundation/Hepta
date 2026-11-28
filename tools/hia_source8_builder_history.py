"""A complete Source8 builder relation with physical dependency custody.

This is data-only source history. It neither executes the predecessor nor
qualifies the current Bootstrap implementation or its performance gate.
"""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import stat

SELF = 'tools/hia_source8_builder_history.py'
FIXTURE = 'tests/fixtures/hia_source8_builder_successor_v1.json'
FIXTURE_SHA256 = '9cd63e6395238b5e0c8874649ac3969a2203cfc83d5a6c553cced4ae4f6825b1'
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_SHA256 = '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'
BUILDER = 'tools/build_hia_service_bootstrap.py'
CURRENT = {'bytes': 31169, 'sha256': 'f2ebc4b904ad8b34ff4dac8cb9268edfcb7cf71279ce217d536fbd894648dbc6'}
PRIOR = {'bytes': 30952, 'sha256': 'd0e5f770166ed9bfb7834ccc1834404d50b1f2b7ff4e1b6172ca113813ce03f8'}
INTRODUCED_INPUTS = {'hepta/hia_program_runtime_dispatch.py': {'bytes': 23556, 'sha256': '73c06c1a92e2028df69fe111b01b52263741ecb0bb2b4e20611292ab41cc39f4'}, 'tests/test_hia_program_runtime_dispatch.py': {'bytes': 23751, 'sha256': '870af530d2188d10ed6887a8ccf428b5dd0d3961986caeeeb7bdad5aa2358db3'}, 'tests/hia_runtime_dispatch_source_history.py': {'bytes': 4743, 'sha256': '6dbb1a3eb0f6790193335164a5992a35901d3a256be979644cd57f21fad2fa13'}, 'tests/fixtures/hia_runtime_dispatch_observer_successor_v1.json': {'bytes': 957, 'sha256': '58ec792c5147a85082000a8c5f7337210a3d2fa2926d3d697acf06f74b9f7883'}}
_SCHEMA = 'hepta.hia.source8-builder-successor.v1'
_SCOPE = 'EXPLICIT_SOURCE8_BUILDER_SOURCE_HISTORY'
_EXECUTED_PATH = Path(__file__).resolve(strict=True)
_EXECUTED_SOURCE = _EXECUTED_PATH.read_bytes()


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('Source8 builder history needs complete immutable bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _pairs(rows):
    answer = {}
    for key, value in rows:
        if key in answer:
            raise ValueError('duplicate Source8 builder history field')
        answer[key] = value
    return answer


def _name(root, path):
    path = Path(path)
    if not path.is_absolute():
        path = root / path
    try:
        name = path.relative_to(root).as_posix()
    except ValueError:
        raise ValueError('Source8 builder history path escapes its root') from None
    if (name in ('', '.') or any(p in ('', '.', '..', '.git') for p in name.split('/'))
            or root / name != path):
        raise ValueError('Source8 builder history path is not canonical')
    return path, name


def _stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class BuilderHistory:
    def __init__(self, root, take):
        self.root = Path(root).resolve(strict=True)
        self.take = take
        self.captures = {}
        self._initial = {}
        self.prior_sources = {}
        self._prior = {}
        self._inventory = ()

    def capture(self, path):
        path, name = _name(self.root, path)
        cursor = path
        while cursor != self.root:
            if stat.S_ISLNK(cursor.lstat().st_mode):
                raise ValueError('Source8 builder history input uses a symlink: ' + name)
            cursor = cursor.parent
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('Source8 builder history needs an owned regular file: ' + name)
        raw = self.take(path)
        pin(raw)
        if path.read_bytes() != raw or _stamp(before) != _stamp(path.lstat()):
            raise ValueError('Source8 builder capture differs from actual bytes: ' + name)
        value = (raw, stat.S_IMODE(before.st_mode))
        if name in self._initial and self._initial[name] != value:
            raise ValueError('Source8 builder physical input changed: ' + name)
        if name in self.captures and self.captures[name] != raw:
            raise ValueError('Source8 builder physical capture was rewritten: ' + name)
        self._initial[name] = value
        self.captures[name] = raw
        return raw

    def prior_take(self, path):
        path, name = _name(self.root, path)
        verify_unchanged(self)
        actual = self.capture(path)
        return self._prior.get(name, actual)

    def review(self):
        verify_unchanged(self)
        return {
            'schema': 'hepta.hia.source8-builder-review.v1',
            'scope': _SCOPE,
            'physical_root': str(self.root),
            'actual_builder': pin(self.captures[BUILDER]),
            'explicit_prior_builder': pin(self._prior[BUILDER]),
            'introduced_inputs': {n: pin(self.captures[n]) for n in INTRODUCED_INPUTS},
            'complete_physical_sources': {
                n: {**pin(raw), 'mode': mode}
                for n, (raw, mode) in sorted(self._initial.items())},
            'full_inverse_and_forward_replay': True,
            'physical_capture_rewritten': False,
            'prior_projection_is_physical_source': False,
            'current_product_execution_qualified': False,
        }


def prepare(root, supplied, *, take=Path.read_bytes):
    if type(supplied) is not dict or set(supplied) != {BUILDER}:
        raise ValueError('Source8 builder history accepts only its complete builder')
    if pin(supplied[BUILDER]) != CURRENT:
        raise ValueError('unreviewed Source8 builder history argument')
    h = BuilderHistory(root, take)
    if (h.capture(h.root / SELF) != _EXECUTED_SOURCE
            or _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE):
        raise ValueError('Source8 builder executing reader differs')
    frozen = h.capture(h.root / FIXTURE)
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('Source8 builder immutable relation differs')
    relation = json.loads(frozen, object_pairs_hook=_pairs)
    if (type(relation) is not dict or set(relation) != {
            'schema', 'scope', 'source_commit', 'files', 'introduced_inputs',
            'original_authorities_changed', 'original_test_methods_changed',
            'current_product_execution_qualified'}
            or relation['schema'] != _SCHEMA or relation['scope'] != _SCOPE
            or relation['source_commit'] != '175ac187d63bc67f77c4e40a366e6dd5d2416e49'
            or set(relation['files']) != {BUILDER}
            or relation['introduced_inputs'] != INTRODUCED_INPUTS
            or relation['original_authorities_changed'] is not False
            or relation['original_test_methods_changed'] is not False
            or relation['current_product_execution_qualified'] is not False):
        raise ValueError('Source8 builder immutable relation domain differs')
    engine_raw = h.capture(h.root / ENGINE)
    if sha256(engine_raw).hexdigest() != ENGINE_SHA256:
        raise ValueError('Source8 builder frozen inverse engine differs')
    from tools import hia_frozen_component_sources as engine
    if Path(engine.__file__).read_bytes() != engine_raw:
        raise ValueError('Source8 builder imported another inverse engine')
    actual = h.capture(h.root / BUILDER)
    if actual != supplied[BUILDER] or pin(actual) != CURRENT:
        raise ValueError('Source8 builder argument is not its physical capture')
    for name, expected in INTRODUCED_INPUTS.items():
        if pin(h.capture(h.root / name)) != expected:
            raise ValueError('Source8 builder dependency differs: ' + name)
    h.prior_sources[BUILDER] = engine.history_inverse(
        actual, relation['files'][BUILDER], PRIOR)
    h._prior = dict(h.prior_sources)
    h._inventory = tuple(sorted(h._initial))
    verify_unchanged(h)
    return dict(h.prior_sources), h


def verify_unchanged(history):
    if (type(history) is not BuilderHistory
            or history.prior_sources != history._prior
            or set(history._prior) != {BUILDER}
            or pin(history._prior[BUILDER]) != PRIOR
            or tuple(sorted(history._initial)) != history._inventory
            or history.captures != {n: row[0] for n, row in history._initial.items()}
            or _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE):
        raise ValueError('Source8 builder actual or prior custody changed')
    for name in history._inventory:
        history.capture(history.root / name)
    if (pin(history.captures[BUILDER]) != CURRENT
            or history.captures[SELF] != _EXECUTED_SOURCE
            or sha256(history.captures[FIXTURE]).hexdigest() != FIXTURE_SHA256
            or sha256(history.captures[ENGINE]).hexdigest() != ENGINE_SHA256
            or any(pin(history.captures[n]) != expected
                   for n, expected in INTRODUCED_INPUTS.items())):
        raise ValueError('Source8 builder terminal identities differ')
    verify_physical_unchanged(history)


def verify_physical_unchanged(history):
    """End with physical reads after the last caller-supplied take callback."""
    if (type(history) is not BuilderHistory
            or history.prior_sources != history._prior
            or set(history._prior) != {BUILDER}
            or pin(history._prior[BUILDER]) != PRIOR
            or tuple(sorted(history._initial)) != history._inventory
            or history.captures != {n: row[0] for n, row in history._initial.items()}):
        raise ValueError('Source8 builder terminal custody changed')
    for name in history._inventory:
        path, _ = _name(history.root, history.root / name)
        cursor = path
        while cursor != history.root:
            if stat.S_ISLNK(cursor.lstat().st_mode):
                raise ValueError('Source8 builder terminal path uses a symlink: ' + name)
            cursor = cursor.parent
        before = path.lstat()
        expected, mode = history._initial[name]
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != mode
                or path.read_bytes() != expected
                or _stamp(before) != _stamp(path.lstat())):
            raise ValueError('Source8 builder actual input changed after take: ' + name)
    if _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE:
        raise ValueError('Source8 builder executed reader changed after take')
