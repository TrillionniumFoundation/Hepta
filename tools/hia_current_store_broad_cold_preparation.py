"""Explicit data-only preparation for the current Store cold source controls."""
from pathlib import Path
import json
from tools import hia_frozen_component_sources as frozen

SELF = 'tools/hia_current_store_broad_cold_preparation.py'
FIXTURE = 'tests/fixtures/hia_current_store_broad_cold_v1.json'
FIXTURE_PIN = {'bytes': 196325, 'sha256': '3d868ef5659e92ffdcf4fddaef2c02e31e9247553759ffbbae2b60e2eb1cd43c'}
CURRENT = {'tools/hia_current_store_source_history.py': {'bytes': 42266, 'sha256': 'ec3a5c47b4b6c3ae238531ebd6a060f32f690e85b408a0c2970effa15dbfd1d9'}, 'tests/test_hia_current_store_source_history.py': {'bytes': 19852, 'sha256': '8cdc5d31431b728b14af81c817ef73d4ef9cd278fbeae93438b562687555affc'}}
PREVIOUS = {'tools/hia_current_store_source_history.py': {'bytes': 12229, 'sha256': 'bf36a35c4832ffcf91756b0098dc8c70d18e4b5949e957b9f381208df2427504'}, 'tests/test_hia_current_store_source_history.py': {'bytes': 19411, 'sha256': '7ddcb55e33ae6dcf61b9d7d2b6764d9afb0219691c61523fce3cf389c2fe6106'}}
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_PIN = {'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'}
_EXECUTED_PATH = Path(__file__).resolve(strict=True)
_EXECUTED_BYTES = _EXECUTED_PATH.read_bytes()


def _load(root, take):
    root = Path(root)
    saved = {}

    def capture(name):
        if (type(name) is not str or not name or Path(name).is_absolute()
                or Path(name).as_posix() != name or '..' in Path(name).parts):
            raise ValueError('Store cold preparation path is not canonical')
        raw = take(root / name)
        frozen.history_pin(raw)
        if name in saved and saved[name] != raw:
            raise ValueError('Store cold preparation input changed: ' + name)
        saved[name] = raw
        return raw

    if (capture(SELF) != _EXECUTED_BYTES
            or _EXECUTED_PATH.read_bytes() != _EXECUTED_BYTES
            or frozen.history_pin(capture(ENGINE)) != ENGINE_PIN
            or Path(frozen.__file__).read_bytes() != saved[ENGINE]):
        raise ValueError('Store cold preparation readers differ from executed sources')
    raw = capture(FIXTURE)
    if frozen.history_pin(raw) != FIXTURE_PIN:
        raise ValueError('Store cold preparation fixed authority differs')
    value = json.loads(raw)
    if (type(value) is not dict or set(value) != {
            'schema', 'files', 'staged_inputs', 'original_test_ids_and_assertions_modified', 'original_reader_preparation_adjusted',
            'old_fixed_fixtures_modified', 'historical_view_is_physical_source',
            'whole_native_delivery_qualified'}
            or value['schema'] != 'hepta.hia.current-store-broad-cold-preparation.v1'
            or type(value['files']) is not dict or set(value['files']) != set(CURRENT)
            or type(value['staged_inputs']) is not dict
            or value['original_test_ids_and_assertions_modified'] is not False
            or value['original_reader_preparation_adjusted'] is not True
            or value['old_fixed_fixtures_modified'] is not False
            or value['historical_view_is_physical_source'] is not False
            or value['whole_native_delivery_qualified'] is not False):
        raise ValueError('Store cold preparation authority scope differs')
    for name, expected in CURRENT.items():
        if frozen.history_pin(capture(name)) != expected:
            raise ValueError('Store cold preparation complete pair differs: ' + name)
    return value, capture, saved, root


def _reread(root, take, saved):
    if _EXECUTED_PATH.read_bytes() != _EXECUTED_BYTES:
        raise ValueError('Store cold preparation executed source changed')
    for name, raw in saved.items():
        if take(root / name) != raw:
            raise ValueError('Store cold preparation physical input changed: ' + name)


def predecessor(name, physical, *, root, take=Path.read_bytes):
    """Map only the two exact new complete files to their untouched predecessors."""
    if name not in CURRENT or frozen.history_pin(physical) != CURRENT[name]:
        return physical
    value, capture, saved, root = _load(root, take)
    try:
        if capture(name) != physical:
            raise ValueError('Store cold preparation supplied bytes differ from physical source')
        return frozen.history_inverse(physical, value['files'][name], PREVIOUS[name])
    finally:
        _reread(root, take, saved)


def staged_inputs(*, root, take=Path.read_bytes):
    """Return fixed source-control inputs; this grants no production qualification."""
    value, capture, saved, root = _load(root, take)
    try:
        result = {}
        for name, row in value['staged_inputs'].items():
            if (type(row) is not dict or set(row) != {'bytes', 'sha256', 'hex'}
                    or type(row['hex']) is not str):
                raise ValueError('Store cold preparation fixed input shape differs')
            raw = bytes.fromhex(row['hex'])
            if row['hex'] != raw.hex() or frozen.history_pin(raw) != {
                    'bytes': row['bytes'], 'sha256': row['sha256']}:
                raise ValueError('Store cold preparation fixed input bytes differ')
            result[name] = raw
        return result
    finally:
        _reread(root, take, saved)


CONSUMER = 'tools/read_hia_store_file_capture_callers.py'
CONSUMER_CURRENT = {'bytes': 54868, 'sha256': '4a668e26bc920b3f648e6fb0c546673a42f997a00afaf19e70ea0705bd8c0ffe'}
COMPOSITION = 'tools/hia_native_cold_composition_history.py'
COMPOSITION_PIN = {'bytes': 10987, 'sha256': 'c5a53a1adf23dfefb8f24f3a8cc82d7cf64324362746ac5d25be2f2a663d7b28'}


def consumer_predecessor(name, physical, *, root, take=Path.read_bytes):
    if name != CONSUMER or frozen.history_pin(physical) != CONSUMER_CURRENT:
        return physical
    value, capture, saved, root = _load(root, take)
    history = None
    try:
        if capture(name) != physical or frozen.history_pin(capture(COMPOSITION)) != COMPOSITION_PIN:
            raise ValueError('Store cold consumer preparation lost physical input')
        from tools import hia_native_cold_composition_history as composition
        if Path(composition.__file__).read_bytes() != saved[COMPOSITION]:
            raise ValueError('Store cold consumer preparation imported another reader')
        def physical_take(path):
            return capture(Path(path).relative_to(root).as_posix())
        projected, history = composition.prepare(root, {name: physical}, take=physical_take)
        return projected[name]
    finally:
        if history is not None:
            composition.verify_unchanged(history)
        _reread(root, take, saved)
