"""Physical current sources and an explicit retained source-control domain.

This is source custody, never current product qualification. The historical
Store and 393-test readers retain all their original fixed authorities. New
sources are captured in full before any separately named predecessor is used.
"""
from __future__ import annotations
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import stat

SELF = 'tools/hia_current_source_generation.py'
FIXTURE = 'tests/fixtures/hia_current_source_generation_v1.json'
FIXTURE_SHA256 = '0f425262209c2408a387c00bae2d6698cbfaa614e90c9ad4401e5857cf743467'
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_SHA256 = '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'
BOOTSTRAP = 'tools/hia_bootstrap_source_history.py'
BOOTSTRAP_SHA256 = '705ef96364a4a6f2f6a93c2983719f59b1c92764c591cb571a66e755367c9775'
SERVICE = 'hepta/hia_agent_service.py'
REGISTRY = 'hepta/hia_native_helpers.py'
BUILDER = 'tools/build_hia_service_bootstrap.py'
VERIFICATION_TEST = 'tests/test_hia_service_verification_native.py'
STORE_READER = 'tools/hia_current_store_source_history.py'
CHANGED_INPUTS = (SERVICE, REGISTRY, BUILDER, VERIFICATION_TEST)
SOURCE8_BUILDER = {'bytes': 31169, 'sha256': 'f2ebc4b904ad8b34ff4dac8cb9268edfcb7cf71279ce217d536fbd894648dbc6'}
SOURCE8_BUILDER_READER = 'tools/hia_source8_builder_history.py'
SOURCE8_BUILDER_READER_SHA256 = '917d3cec041891638f71f48ac931bbf3a7476ff297a062070d1dbc5d3afc185f'
CURRENT = {
    SERVICE: {'bytes': 274230, 'sha256': '7351b80e8f8d46c6cf1988a56b5eb0d2acb5c31727e3d5e63bf5b6355d1e4525'},
    REGISTRY: {'bytes': 35618, 'sha256': '747c63098d9989971e40d737d7c1ffd96caa60b6095d8dc0d1015dcbe08cfb37'},
    BUILDER: {'bytes': 30952, 'sha256': 'd0e5f770166ed9bfb7834ccc1834404d50b1f2b7ff4e1b6172ca113813ce03f8'},
    VERIFICATION_TEST: {'bytes': 18906, 'sha256': 'ab20469d9dcf60b3e021a32303ddcae5fc1a89fd9f5574fb1a45619c4c4d3571'},
}
PRIOR = {
    SERVICE: {'bytes': 268730, 'sha256': '353bd2673cc4f269c9c2d6cbf226d8956703d434ca960214864f56689d8f82c1'},
    REGISTRY: {'bytes': 30812, 'sha256': 'a692a261bcc86943526f93f2ff5fb76c5351ad6a0ce5683ddf46cbdc132a13a9'},
    BUILDER: {'bytes': 10309, 'sha256': '0ac4ce2869a61fc7c4b9a86aa07bf92ea4b28cbc39651a0fa841adb1cf28469e'},
    VERIFICATION_TEST: {'bytes': 18622, 'sha256': '8b665a4d65ddfc11ff52a50882e6f54d08428d1be3b91e2bebee716da3a0a8e8'},
    STORE_READER: {'bytes': 42266, 'sha256': 'ec3a5c47b4b6c3ae238531ebd6a060f32f690e85b408a0c2970effa15dbfd1d9'},
}
_SCHEMA = 'hepta.hia.current-source-generation-relation.v1'
_SCOPE = 'EXPLICIT_RETAINED_393_SOURCE_CONTROL_DOMAIN'
_EXECUTED_PATH = Path(__file__).resolve(strict=True)
_EXECUTED_SOURCE = _EXECUTED_PATH.read_bytes()


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('current generation requires complete immutable bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _pairs(rows):
    out = {}
    for key, value in rows:
        if key in out:
            raise ValueError('duplicate source generation field')
        out[key] = value
    return out


def _name(root, path):
    path = Path(path)
    if not path.is_absolute():
        path = root / path
    try:
        name = path.relative_to(root).as_posix()
    except ValueError:
        raise ValueError('source generation path escapes its physical root') from None
    if (name in ('', '.') or any(p in ('', '.', '..', '.git') for p in name.split('/'))
            or (root / name) != path):
        raise ValueError('source generation path is not canonical')
    return path, name


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


class PhysicalHistory:
    def __init__(self, root, take):
        self.root = Path(root).resolve(strict=True)
        self.take = take
        self.captures = {}
        self._initial = {}
        self.prior_sources = {}
        self._prior = {}
        self.bootstrap_saved = None
        self.bootstrap = None
        self.project_reader = False
        self.source8_builder_history = None

    def capture(self, path):
        path, name = _name(self.root, path)
        current = path
        while current != self.root:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise ValueError('source generation input uses a symlink: ' + name)
            current = current.parent
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('source generation input is not an owned regular file: ' + name)
        raw = self.take(path)
        pin(raw)
        if path.read_bytes() != raw or _stamp(before) != _stamp(path.lstat()):
            raise ValueError('source generation capture differs from physical input: ' + name)
        row = (raw, stat.S_IMODE(before.st_mode))
        if name in self._initial and self._initial[name] != row:
            raise ValueError('source generation physical input changed: ' + name)
        if name in self.captures and self.captures[name] != raw:
            raise ValueError('source generation capture was rewritten: ' + name)
        self._initial[name] = row
        self.captures[name] = raw
        return raw

    def prior_take(self, path):
        path, name = _name(self.root, path)
        actual = self.capture(path)
        if self.prior_sources != self._prior:
            raise ValueError('source generation prior view was rewritten')
        return self.prior_sources.get(name, actual)

    def review(self):
        return {
            'schema': 'hepta.hia.current-source-generation-review.v1',
            'scope': _SCOPE,
            'physical_root': str(self.root),
            'actual_changed_inputs': {n: pin(self.captures[n]) for n in CHANGED_INPUTS},
            'complete_physical_sources': {n: {**pin(raw), 'mode': mode}
                for n, (raw, mode) in sorted(self._initial.items())},
            'explicit_prior_sources': {n: pin(raw) for n, raw in sorted(self._prior.items())},
            'reader_projected_for_original_source_controls': self.project_reader,
            'source8_builder_history': (self.source8_builder_history.review()
                if self.source8_builder_history is not None else None),
            'physical_capture_rewritten': False,
            'prior_projection_is_physical_source': False,
            'current_product_execution_qualified': False,
            'whole_native_stack_qualified': False,
        }


def prepare(root, supplied=None, *, take=Path.read_bytes, project_reader=False):
    if type(project_reader) is not bool:
        raise ValueError('source generation reader projection must be explicit')
    h = PhysicalHistory(root, take)
    if (h.capture(h.root / SELF) != _EXECUTED_SOURCE
            or _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE):
        raise ValueError('source generation executing reader differs')
    frozen = h.capture(h.root / FIXTURE)
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('source generation fixed whole-file relation differs')
    relation = json.loads(frozen, object_pairs_hook=_pairs)
    if (type(relation) is not dict or set(relation) != {
            'schema', 'scope', 'prior_commit', 'current_parent', 'files',
            'original_test_methods_changed', 'original_fixed_authorities_changed',
            'physical_projection_is_current_source', 'current_product_qualified'}
            or relation['schema'] != _SCHEMA or relation['scope'] != _SCOPE
            or relation['prior_commit'] != '077c0b2e82edd7da50d84c11b55756beb61ee043'
            or relation['original_test_methods_changed'] is not False
            or relation['original_fixed_authorities_changed'] is not False
            or relation['physical_projection_is_current_source'] is not False
            or relation['current_product_qualified'] is not False
            or set(relation['files']) != set(PRIOR)):
        raise ValueError('source generation relation domain differs')
    from tools import hia_frozen_component_sources as engine
    raw = h.capture(h.root / ENGINE)
    if sha256(raw).hexdigest() != ENGINE_SHA256 or Path(engine.__file__).read_bytes() != raw:
        raise ValueError('source generation immutable inverse engine differs')
    for name in CHANGED_INPUTS:
        raw = h.capture(h.root / name)
        if name == BUILDER and pin(raw) == SOURCE8_BUILDER:
            reader_raw = h.capture(h.root / SOURCE8_BUILDER_READER)
            if sha256(reader_raw).hexdigest() != SOURCE8_BUILDER_READER_SHA256:
                raise ValueError('source generation Source8 builder reader differs')
            from tools import hia_source8_builder_history as source8
            if Path(source8.__file__).read_bytes() != reader_raw:
                raise ValueError('source generation imported another Source8 builder reader')
            projected, h.source8_builder_history = source8.prepare(
                h.root, {BUILDER: raw}, take=h.capture)
            raw = projected[BUILDER]
        if pin(raw) != CURRENT[name]:
            raise ValueError('source generation is mixed or unreviewed: ' + name)
    raw = h.capture(h.root / BOOTSTRAP)
    if sha256(raw).hexdigest() != BOOTSTRAP_SHA256:
        raise ValueError('source generation complete behavior reader differs')
    from tools import hia_bootstrap_source_history as bootstrap
    if Path(bootstrap.__file__).read_bytes() != raw:
        raise ValueError('source generation imported another behavior reader')
    _, _, saved = bootstrap.capture(h.root, take=h.capture)
    h.bootstrap, h.bootstrap_saved = bootstrap, saved
    service_prior = bootstrap.current_service_predecessor(saved)
    for name, expected in PRIOR.items():
        raw = (h.source8_builder_history.prior_take(h.root / name)
               if name == BUILDER and h.source8_builder_history is not None
               else h.capture(h.root / name))
        restored = engine.history_inverse(raw, relation['files'][name], expected)
        if name != STORE_READER or project_reader:
            h.prior_sources[name] = restored
    if h.prior_sources[SERVICE] != service_prior:
        raise ValueError('source generation differs from the admitted complete behavior group')
    h._prior = dict(h.prior_sources)
    h.project_reader = project_reader
    if supplied is not None:
        if type(supplied) is not dict or not supplied:
            raise ValueError('source generation supplied inputs are empty or invalid')
        for name, raw in supplied.items():
            if type(name) is not str or h.capture(h.root / name) != raw:
                raise ValueError('source generation argument is not its actual capture')
    verify_unchanged(h)
    projected = {name: h.prior_sources.get(name, raw)
                 for name, raw in (supplied or {}).items()}
    return projected, h


def verify_unchanged(history):
    if (type(history) is not PhysicalHistory or history.prior_sources != history._prior
            or history.captures != {n: row[0] for n, row in history._initial.items()}
            or _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE):
        raise ValueError('source generation actual and prior custody changed')
    for name in tuple(history._initial):
        history.capture(history.root / name)
    if history.source8_builder_history is not None:
        from tools import hia_source8_builder_history as source8
        source8.verify_unchanged(history.source8_builder_history)
    elif pin(history.captures[BUILDER]) == SOURCE8_BUILDER:
        raise ValueError('source generation lost its explicit Source8 builder history')
    if history.bootstrap_saved is not None:
        history.bootstrap.unchanged(history.root, history.bootstrap_saved,
                                    take=history.capture)
    if history.captures != {n: row[0] for n, row in history._initial.items()}:
        raise ValueError('source generation physical inventory changed at terminal')
    if history.source8_builder_history is not None:
        _source8_terminal_physical(history)


def _source8_terminal_physical(history):
    """Keep the physical inventory current after all nested take callbacks."""
    from tools import hia_source8_builder_history as source8
    source8.verify_physical_unchanged(history.source8_builder_history)
    if (history.prior_sources != history._prior
            or history.captures != {n: row[0] for n, row in history._initial.items()}):
        raise ValueError('source generation terminal actual or prior custody changed')
    for name, (expected, mode) in history._initial.items():
        path, _ = _name(history.root, history.root / name)
        cursor = path
        while cursor != history.root:
            if stat.S_ISLNK(cursor.lstat().st_mode):
                raise ValueError('source generation terminal path uses a symlink: ' + name)
            cursor = cursor.parent
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != mode
                or path.read_bytes() != expected
                or _stamp(before) != _stamp(path.lstat())):
            raise ValueError('source generation input changed after final take: ' + name)
    if _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE:
        raise ValueError('source generation executed reader changed after final take')


def maybe_prepare(root, supplied, *, take=Path.read_bytes):
    """Older complete domains continue to use only their original authorities."""
    if type(supplied) is not dict or not supplied:
        return dict(supplied), None
    direct = any((name in CURRENT and pin(raw) == CURRENT[name])
                 or (name == BUILDER and pin(raw) == SOURCE8_BUILDER)
                 for name, raw in supplied.items())
    if SERVICE in supplied and pin(supplied[SERVICE]) not in (
            CURRENT[SERVICE], PRIOR[SERVICE],
            {'bytes': 268278, 'sha256': 'afc92b555bd0dfa23f25c4f9c2661af30853474342f4e32a036d37c1ce663a57'}):
        return dict(supplied), None
    from tools import hia_frozen_component_sources as engine
    eligible = set(engine.CURRENT) | {REGISTRY}
    if not direct and set(supplied).intersection(eligible):
        service = Path(root) / SERVICE
        if service.is_file():
            direct = pin(take(service)) == CURRENT[SERVICE]
            if not direct:
                registry = Path(root) / REGISTRY
                direct = registry.is_file() and pin(take(registry)) == CURRENT[REGISTRY]
    if not direct:
        return dict(supplied), None
    return prepare(root, supplied, take=take)


@contextmanager
def original_source_view(root, destination, names, *, take=Path.read_bytes):
    """Materialize the explicit fixed source-test view and retain actual inputs."""
    _, history = prepare(root, take=take, project_reader=True)
    destination = Path(destination).absolute()
    destination.mkdir(mode=0o700, exist_ok=False)
    expected = {}
    for name in names:
        if type(name) is not str:
            raise ValueError('original source view has a non-string source name')
        actual = history.capture(history.root / name)
        raw = history.prior_sources.get(name, actual)
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
        mode = history._initial[name][1]
        path.chmod(mode)
        expected[name] = (raw, mode)
    verify_unchanged(history)
    record = history.review()
    record['historical_view'] = str(destination)
    record['historical_sources'] = {n: {**pin(raw), 'mode': mode}
                                   for n, (raw, mode) in expected.items()}
    record['terminal_reread_identical'] = False
    try:
        yield destination, record, history
    finally:
        verify_unchanged(history)
        for name, (raw, mode) in expected.items():
            path = destination / name
            if (not stat.S_ISREG(path.lstat().st_mode) or path.is_symlink()
                    or path.stat().st_nlink != 1 or path.read_bytes() != raw
                    or stat.S_IMODE(path.stat().st_mode) != mode):
                raise ValueError('original source view changed during its fixed controls: ' + name)
        record['actual_after'] = history.review()['complete_physical_sources']
        record['terminal_reread_identical'] = True
