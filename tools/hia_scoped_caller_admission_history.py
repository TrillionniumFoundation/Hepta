"""Complete source history for the reviewed scoped caller admission successors.

This data-only layer restores three exact qualifier files. Physical captures
remain current bytes; prior_take exposes only independently reversed complete
files to an older reader. No caller execution is certified here.
"""
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath

SELF = 'tools/hia_scoped_caller_admission_history.py'
_EXECUTED_PATH = Path(__file__).resolve()
_EXECUTED_SOURCE = _EXECUTED_PATH.read_bytes()
FIXTURE = 'tests/fixtures/hia_scoped_evaluation_cold_preparation_v1.json'
FIXTURE_PIN = {'bytes': 40763, 'sha256': '3b16b8a76f356df199da6ec95bb57b688351fd3482e34ef9fda5c59cc1e9b100'}
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_PIN = {'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'}
VERSIONS = {
    "tools/qualify_hia_evaluation_callers.py": {
        "current": {
            "bytes": 18675,
            "sha256": "5cfefde3b54516320dab7f9b39fdf9673e7437f99ffba7b71df43192597c9330"
        },
        "prior": {
            "bytes": 16120,
            "sha256": "3360ffaa55764e6b521b954ec9aa6471dd7a08c9f76c896eb439df789711e4ec"
        }
    },
    "tools/qualify_hia_service_discovery_callers.py": {
        "current": {
            "bytes": 18425,
            "sha256": "820d7b0d5404082a5ef07d27ce973015b7b8a87f7ce11b466f73ee000cc6e887"
        },
        "prior": {
            "bytes": 16600,
            "sha256": "7bb5fb5b5807f5b5f8df779eb4c556cc5c4f8c74dc4a0a809d1a6edacf6aaa39"
        }
    },
    "tools/qualify_hia_service_verification_callers.py": {
        "current": {
            "bytes": 18193,
            "sha256": "58a15fac7f5539c797398697605e7ba86ebd192981cfcf137dc51e4626efc4ee"
        },
        "prior": {
            "bytes": 16365,
            "sha256": "440f63103f8783b5a45ed2bc909508b0b5516de8319729ab93d96305cfcc16c1"
        }
    }
}
CURRENT = {name: dict(row['current']) for name, row in VERSIONS.items()}
PRIOR = {name: dict(row['prior']) for name, row in VERSIONS.items()}
_FIXED_FILE_NAMES = {
    *VERSIONS,
    'tests/test_hia_scoped_caller_source_history.py',
    'tests/test_hia_evaluation_caller_admission.py',
}


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('scoped caller history requires complete bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _name(name):
    if (type(name) is not str or not name or str(PurePosixPath(name)) != name
            or name.startswith('/') or any(part in ('.', '..', '.git') for part in name.split('/'))):
        raise ValueError('scoped caller history path is not canonical')
    return name


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate scoped caller history member')
        result[key] = value
    return result


class _History:
    def __init__(self, root, physical, take):
        self.root = Path(root).resolve(strict=True)
        self.take = take
        self.captures = {}
        self.view = {}
        self.projected = {}
        self.review = {
            'schema': 'hepta.hia.scoped-caller-admission-source-review.v1',
            'source_commit': '636081d07c9cef5d22edf1f14c3b80d371a2a22e',
            'actual_physical_current': {},
            'historical_current_inputs': {},
            'fixture': {'path': FIXTURE, **FIXTURE_PIN},
            'inverse_helper': {'path': ENGINE, **ENGINE_PIN},
            'complete_predecessors_restored': True,
            'complete_successors_replayed': True,
            'physical_capture_rewritten': False,
            'native_product_execution_claimed': False,
            'whole_native_delivery_qualified': False,
            'terminal_reread_identical': False,
        }
        self._self()
        if pin(self.capture(FIXTURE)) != FIXTURE_PIN:
            raise ValueError('scoped caller history fixed complete relation changed')
        engine_raw = self.capture(ENGINE)
        if pin(engine_raw) != ENGINE_PIN:
            raise ValueError('scoped caller history immutable inverse engine changed')
        from tools import hia_frozen_component_sources as engine
        if Path(engine.__file__).resolve().read_bytes() != engine_raw:
            raise ValueError('scoped caller history imported another inverse engine')
        self.engine = engine
        self.engine_raw = engine_raw
        relation = json.loads(self.captures[FIXTURE], object_pairs_hook=_pairs)
        if (type(relation) is not dict or set(relation) != {
                'base_commit', 'domains', 'files', 'native_product_execution_claimed',
                'original_test_methods_modified', 'schema'}
                or relation['schema'] != 'hepta.hia.scoped-evaluation-cold-test-preparation.v1'
                or relation['base_commit'] != '322d93c44587986248bac21ad37243fa266517fc'
                or relation['native_product_execution_claimed'] is not False
                or relation['original_test_methods_modified'] is not False
                or type(relation['files']) is not dict
                or set(relation['files']) != _FIXED_FILE_NAMES):
            raise ValueError('scoped caller history complete fixed domain changed')
        for name, expected in VERSIONS.items():
            row = relation['files'][name]
            if (type(row) is not dict
                    or {'bytes': row.get('new_bytes'), 'sha256': row.get('new_sha256')} != expected['current']
                    or {'bytes': row.get('old_bytes'), 'sha256': row.get('old_sha256')} != expected['prior']
                    or type(row.get('new_bytes')) is not int or type(row.get('old_bytes')) is not int):
                raise ValueError('scoped caller history fixed whole-file identity differs')
        for name, raw in physical.items():
            if self.capture(name) != raw:
                raise ValueError('scoped caller history supplied bytes differ from its selected root')
            self.projected[name] = engine.history_inverse(
                raw, relation['files'][name], VERSIONS[name]['prior'])
        self.review['actual_physical_current'] = {name: pin(raw) for name, raw in physical.items()}
        self.review['historical_current_inputs'] = {name: pin(raw) for name, raw in self.projected.items()}
        self.verify()

    def _self(self):
        if (_EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE
                or self.capture(SELF) != _EXECUTED_SOURCE):
            raise ValueError('scoped caller history executing reader differs')

    def capture(self, name):
        name = _name(name)
        raw = self.take(self.root / name)
        pin(raw)
        if name in self.captures and self.captures[name] != raw:
            raise ValueError('scoped caller history physical capture changed: ' + name)
        self.captures[name] = raw
        return raw

    def prior_take(self, path):
        path = Path(path)
        if not path.is_absolute():
            raise ValueError('scoped caller history read requires an absolute selected-root path')
        try:
            name = _name(path.relative_to(self.root).as_posix())
        except ValueError as error:
            raise ValueError('scoped caller history read escaped its selected root') from error
        raw = self.capture(name)
        selected = self.projected.get(name, raw)
        if name in self.view and self.view[name] != selected:
            raise ValueError('scoped caller history prior view changed: ' + name)
        self.view[name] = selected
        return selected

    def verify(self):
        self._self()
        for name, raw in tuple(self.captures.items()):
            if self.capture(name) != raw:
                raise ValueError('scoped caller history changed at terminal readback')
        if Path(self.engine.__file__).resolve().read_bytes() != self.engine_raw:
            raise ValueError('scoped caller history inverse engine changed at terminal')
        self.review['terminal_reread_identical'] = True


def prepare(root, physical, *, take=Path.read_bytes):
    if type(physical) is not dict:
        raise ValueError('scoped caller history requires an exact source dictionary')
    for name, raw in physical.items():
        _name(name)
        pin(raw)
    selected = {name: raw for name, raw in physical.items() if pin(raw) == CURRENT.get(name)}
    if not selected:
        return dict(physical), None
    history = _History(root, selected, take)
    output = dict(physical)
    output.update(history.projected)
    return output, {
        'prior_take': history.prior_take,
        'captures': history.captures,
        'view': history.view,
        'review': history.review,
        'verify': history.verify,
    }


def verify_unchanged(history):
    if history is not None:
        history['verify']()
