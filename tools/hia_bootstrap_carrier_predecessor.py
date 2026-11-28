"""Explicit physical carrier source to the complete, fixed v7 data domain.

Only a private source view is changed. The returned captures always describe
actual inputs, and the fixed v7 reader validates the full prepared group.
This preparation grants no current graph or native-stack qualification.
"""
from __future__ import annotations
from hashlib import sha1, sha256
import json
from pathlib import Path
import stat
from tempfile import TemporaryDirectory

SELF = 'tools/hia_bootstrap_carrier_predecessor.py'
FIXTURE = 'tests/fixtures/hia_bootstrap_carrier_service_predecessor_v1.json'
FIXTURE_PIN = {'bytes': 4352, 'sha256': 'cdbfebee1210c4fc38b74338fbd4f96b5de97ae6b9094a55e302daffe0b2c369', 'git_blob': 'd7573747bf969be596693275e2f4fb2e408fbb63'}
SOURCE = 'hepta/hia_service_verification_native.py'
CURRENT = {'bytes': 128296, 'sha256': 'ed4c39fc93e9a6109e31ededdb95f57dad40b7acb26219f105cb10d40fcc502c', 'git_blob': '4bc3e3543578ea66708aa853911dd296bde7b62b'}
PRIOR = {'bytes': 127707, 'sha256': 'c93e6d2a59aeb19dbd0c18c2de6af6be31adf16b4547db8b191bf36e504d3a81', 'git_blob': 'cd5bd50ab254810ee316570f7facf337895faff0'}
BASE_READER = 'tools/hia_bootstrap_source_history.py'
BEHAVIOR_READER = 'tools/hia_behavior_source_history.py'
BEHAVIOR_READER_PIN = {'bytes': 7856, 'sha256': 'b8118ce79cd80711e1d6a2e170fcdc5e99b9aa104eee38571ceed423e8c92b7a', 'git_blob': 'af8e08a6d4d14827090cab451d0814d1773a27f6'}
BEHAVIOR_FIXTURE = 'tests/fixtures/hia_behavior_input_history_v7.json'
BEHAVIOR_FIXTURE_PIN = {'bytes': 378805, 'sha256': '6215141499231dca05b9edf889d8113ea0745dbfe081d2f6db7c1224adbc215c', 'git_blob': '283cf68f9eae2e903b269dd2e0e2f56f17903e37'}
RELATED_INPUTS = ('examples/hia_bootstrap/carrier_cell_policy.hepta', 'examples/hia_bootstrap/carrier_image_policy.hepta', 'examples/hia_bootstrap/release_stage_carrier_policies.hiastd', 'hepta/hia_carrier_build_identity.py', 'hepta/hia_carrier_cell_abi.json', 'hepta/hia_carrier_image_abi.json', 'hepta/hia_carrier_policy_release.py', 'hepta/hia_cell_frame.py', 'hepta/hia_current_carrier_worker_bundle.py', 'hepta/hia_native_carrier_worker_bundle.py', 'hepta/hia_native_helpers.py', 'hepta/hia_native_image.py', 'hepta/hia_service_artifact_bridge.py', 'hepta/hia_service_artifact_native.py', 'hepta/hia_service_verification_native.py', 'hepta/native/carrier_cell_abi.c', 'hepta/native/carrier_cell_dispatch.inc', 'hepta/native/carrier_image_abi.c', 'hepta/native/carrier_image_dispatch.inc', 'hepta/native/native_carrier_build.py', 'tests/hia_carrier_policy_controls.py', 'tests/hia_current_carrier_controls.py', 'tests/hia_current_carrier_verification_controls.py', 'tools/capture_hia_current_carrier_bundle.py', 'tools/capture_hia_native_carrier_bundle.py', 'tools/generate_hia_carrier_cell_policy.py', 'tools/generate_hia_carrier_image_policy.py', 'tools/generate_hia_carrier_policy_release.py')
SCHEMA = 'hepta.hia.bootstrap-carrier-service-predecessor.v1'
SCOPE = 'EXPLICIT_PREDECESSOR_446_PORT_9_METHOD_DOMAIN'
_EXECUTED_PATH = Path(__file__).resolve()
_EXECUTED_SOURCE = _EXECUTED_PATH.read_bytes()


def identity(raw):
    if type(raw) is not bytes:
        raise ValueError('carrier source must be complete immutable bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate carrier history field')
        value[key] = item
    return value


def _name(name):
    if (type(name) is not str or not name or name.startswith('/')
            or Path(name).as_posix() != name
            or any(part in ('', '.', '..') for part in name.split('/'))):
        raise ValueError('carrier history path is not a confined canonical file')
    return name


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read(root, name, take, captures):
    path = root / _name(name)
    current = path
    while current != root:
        if stat.S_ISLNK(current.lstat().st_mode):
            raise ValueError('carrier history input uses a symlink')
        current = current.parent
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('carrier history input is not a regular file')
    raw = take(path)
    if type(raw) is not bytes or path.read_bytes() != raw:
        raise ValueError('carrier capture differs from actual physical bytes: ' + name)
    after = path.stat()
    if _stamp(before) != _stamp(after):
        raise ValueError('carrier physical input changed during capture: ' + name)
    row = (raw, stat.S_IMODE(after.st_mode))
    if captures.setdefault(name, row) != row:
        raise ValueError('carrier physical input changed between captures: ' + name)
    return raw


def _loaded_reader(captures):
    if (not stat.S_ISREG(_EXECUTED_PATH.lstat().st_mode)
            or _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE
            or captures[SELF][0] != _EXECUTED_SOURCE):
        raise ValueError('carrier predecessor reader changed after import')
    from tools import hia_behavior_source_history as behavior
    raw = captures[BEHAVIOR_READER][0]
    if (identity(raw) != BEHAVIOR_READER_PIN
            or behavior.SELF != BEHAVIOR_READER
            or behavior.FIXTURE != BEHAVIOR_FIXTURE
            or behavior._IMPORTED_SELF != raw
            or not stat.S_ISREG(Path(behavior.__file__).lstat().st_mode)
            or Path(behavior.__file__).read_bytes() != raw):
        raise ValueError('carrier predecessor did not execute the fixed v7 reader')
    return behavior


def _hex(value):
    if type(value) is not str or len(value) % 2 or value != value.lower():
        raise ValueError('Bootstrap source splice is not canonical hexadecimal')
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError('Bootstrap source splice is not hexadecimal') from error
    if raw.hex() != value:
        raise ValueError('Bootstrap source splice is not canonical hexadecimal')
    return raw

def _record(raw, record):
    if (type(record) is not dict
            or set(record) != {'old_bytes', 'new_bytes', 'old_sha256', 'new_sha256', 'hunks'}
            or type(record['old_bytes']) is not int or record['old_bytes'] <= 0
            or type(record['new_bytes']) is not int or record['new_bytes'] != len(raw)
            or sha256(raw).hexdigest() != record['new_sha256']
            or type(record['hunks']) is not list or not record['hunks']):
        raise ValueError('Bootstrap complete source layer differs')
    pieces = []
    old_at = new_at = 0
    decoded = []
    for hunk in record['hunks']:
        if (type(hunk) is not dict or set(hunk) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or type(hunk['old_offset']) is not int or type(hunk['new_offset']) is not int
                or hunk['old_offset'] < old_at or hunk['new_offset'] < new_at):
            raise ValueError('Bootstrap source layer coordinates differ')
        old, new = _hex(hunk['old_hex']), _hex(hunk['new_hex'])
        gap = hunk['new_offset'] - new_at
        if (old == new or hunk['old_offset'] != old_at + gap
                or hunk['new_offset'] + len(new) > len(raw)
                or raw[hunk['new_offset']:hunk['new_offset'] + len(new)] != new):
            raise ValueError('Bootstrap source splice differs from physical bytes')
        pieces.extend((raw[new_at:hunk['new_offset']], old))
        new_at, old_at = hunk['new_offset'] + len(new), hunk['old_offset'] + len(old)
        decoded.append((hunk['old_offset'], old, new))
    pieces.append(raw[new_at:])
    restored = b''.join(pieces)
    if (len(restored) != record['old_bytes']
            or sha256(restored).hexdigest() != record['old_sha256']):
        raise ValueError('Bootstrap complete predecessor digest differs')
    parts, at = [], 0
    for offset, old, new in decoded:
        if restored[offset:offset + len(old)] != old:
            raise ValueError('Bootstrap source forward predecessor differs')
        parts.extend((restored[at:offset], new))
        at = offset + len(old)
    if b''.join((*parts, restored[at:])) != raw:
        raise ValueError('Bootstrap complete current forward replay differs')
    return restored



def _pins(rows):
    return {name: {**identity(raw), 'mode': mode}
            for name, (raw, mode) in sorted(rows.items())}


def _verify_current(root, take, captures, initial):
    if captures != initial:
        raise ValueError('carrier predecessor actual capture inventory changed')
    _loaded_reader(captures)
    for name, row in tuple(initial.items()):
        _read(root, name, take, captures)
        if captures[name] != row:
            raise ValueError('carrier predecessor actual source changed')
    _loaded_reader(captures)


class _History(dict):
    def __init__(self, root, take, captures, view, entries, preparation):
        super().__init__(root=root, take=take, captures=captures, view=view,
                         scope=SCOPE, entries=tuple(entries), preparation=preparation)
        self._root = root
        self._take = take
        self._initial = dict(captures)
        self._view = dict(view)
        self._entries = tuple(entries)
        self._preparation = json.dumps(preparation, sort_keys=True, separators=(',', ':'))
        def prior_take(path):
            path = Path(path)
            if not path.is_absolute():
                path = root / path
            name = _name(path.relative_to(root).as_posix())
            verify_unchanged(self)
            if name not in self._view:
                raise FileNotFoundError(str(path))
            return self._view[name]
        self['prior_take'] = prior_take
        self._prior_take = prior_take


def verify_unchanged(history):
    if (type(history) is not _History
            or set(history) != {'root', 'take', 'captures', 'view', 'scope',
                                'entries', 'preparation', 'prior_take'}
            or history['root'] != history._root
            or history['take'] is not history._take
            or history['prior_take'] is not history._prior_take
            or history['view'] != history._view
            or history['scope'] != SCOPE or history['entries'] != history._entries
            or json.dumps(history['preparation'], sort_keys=True, separators=(',', ':'))
               != history._preparation):
        raise ValueError('carrier predecessor physical and historical domains changed')
    _verify_current(history._root, history._take, history['captures'], history._initial)


def prepare(root, supplied=None, *, take=Path.read_bytes):
    root = Path(root).resolve()
    captures = {}
    for name in (SELF, FIXTURE, BASE_READER, BEHAVIOR_READER, BEHAVIOR_FIXTURE):
        _read(root, name, take, captures)
    behavior = _loaded_reader(captures)
    if identity(captures[FIXTURE][0]) != FIXTURE_PIN:
        raise ValueError('carrier immutable predecessor fixture differs')
    if identity(captures[BEHAVIOR_FIXTURE][0]) != BEHAVIOR_FIXTURE_PIN:
        raise ValueError('carrier fixed v7 fixture differs')
    relation = json.loads(captures[FIXTURE][0], object_pairs_hook=_pairs)
    if (type(relation) is not dict
            or set(relation) != {'schema', 'source', 'current', 'prior', 'record',
                'behavior_reader', 'behavior_fixture', 'additional_inputs',
                'provenance', 'qualification_granted'}
            or relation['schema'] != SCHEMA or relation['source'] != SOURCE
            or relation['current'] != CURRENT or relation['prior'] != PRIOR
            or relation['behavior_reader'] != BEHAVIOR_READER_PIN
            or relation['behavior_fixture'] != BEHAVIOR_FIXTURE_PIN
            or relation['additional_inputs'] != list(RELATED_INPUTS)
            or relation['qualification_granted'] is not False):
        raise ValueError('carrier whole-source relation domain differs')
    original = json.loads(captures[BEHAVIOR_FIXTURE][0], object_pairs_hook=_pairs)
    if (type(original) is not dict
            or set(original) != {'schema', 'scope', 'entries', 'stage_files'}
            or original['schema'] != 'hepta.hia.behavior-input-history.v1'
            or original['scope'] != SCOPE
            or type(original['stage_files']) is not list
            or len(original['stage_files']) != len(set(original['stage_files']))
            or not original['stage_files']
            or type(original['entries']) is not dict or len(original['entries']) != 12
            or set(original['entries']) - set(original['stage_files'])):
        raise ValueError('carrier fixed v7 complete inventory differs')
    for name in (*original['stage_files'], *RELATED_INPUTS):
        _read(root, name, take, captures)
    actual = captures[SOURCE][0]
    if identity(actual) != CURRENT:
        raise ValueError('unreviewed carrier verification whole source')
    prior = _record(actual, relation['record'])
    if identity(prior) != PRIOR:
        raise ValueError('carrier inverse did not restore the complete v7 source')
    if supplied is not None:
        if type(supplied) is not dict or set(supplied) - set(original['entries']):
            raise ValueError('carrier supplied source inventory differs')
        for name, raw in supplied.items():
            if type(raw) is not bytes or captures[name][0] != raw:
                raise ValueError('carrier supplied source differs from actual physical bytes')
    initial = dict(captures)
    _verify_current(root, take, captures, initial)
    prepared = {name: captures[name] for name in
                (*original['stage_files'], BEHAVIOR_READER, BEHAVIOR_FIXTURE)}
    prepared[SOURCE] = (prior, captures[SOURCE][1])
    view = None
    inner = None
    with TemporaryDirectory(prefix='hia-bootstrap-carrier-v7-') as directory:
        stage = Path(directory).resolve()
        for name, (raw, mode) in prepared.items():
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(raw)
            path.chmod(mode)
        try:
            view, inner = behavior.prepare(stage)
            behavior.verify_unchanged(inner)
            if (inner['scope'] != SCOPE
                    or inner['entries'] != tuple(original['entries'])
                    or inner['captures'] != prepared):
                raise ValueError('carrier prepared v7 admission omitted a complete input')
            view = dict(view)
            preparation = {
                'schema': SCHEMA, 'source': SOURCE,
                'actual_source': dict(CURRENT), 'prepared_source': dict(PRIOR),
                'reader': {'path': SELF, **identity(captures[SELF][0])},
                'fixture': {'path': FIXTURE, **FIXTURE_PIN},
                'actual_physical': _pins(captures),
                'prepared_v7_physical': _pins(prepared),
                'complete_inverse_verified': True,
                'complete_forward_replay_verified': True,
                'complete_fixed_v7_group_admitted': True,
                'private_view_terminal_verified': True,
                'current_semantics_qualified': False,
                'whole_native_stack_qualified': False,
            }
        finally:
            if inner is not None:
                behavior.verify_unchanged(inner)
            check = {}
            for name, (raw, mode) in prepared.items():
                got = _read(stage, name, Path.read_bytes, check)
                if got != raw or check[name][1] != mode:
                    raise ValueError('carrier prepared source view changed before closure')
            _verify_current(root, take, captures, initial)
    history = _History(root, take, captures, view, original['entries'], preparation)
    verify_unchanged(history)
    return view, history
