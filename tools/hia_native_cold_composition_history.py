"""Explicit historical views for the integrated native cold source consumers.

Every capture is a physical input. Prior bytes are held in a separate view,
and the unchanged older source readers receive that view explicitly.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath

SELF = 'tools/hia_native_cold_composition_history.py'
_EXECUTED_SOURCE = Path(__file__).read_bytes()
FIXTURE = 'tests/fixtures/hia_native_cold_composition_history_v1.json'
FIXTURE_PIN = {"bytes":28178,"sha256":"c2a8310b9fadbad463e02e54d14ae6e815ffda104c5629bfb312dd93dddfd8c4"}
CURRENT = {
    "tests/hia_caller_terminal_admission.py": {
        "bytes": 29791,
        "sha256": "46111a1e82ba4fbb7153162325ddbdda531d6e0d18de80a6ad58adcb6a3c0b0b"
    },
    "tools/read_hia_store_file_capture_callers.py": {
        "bytes": 54868,
        "sha256": "4a668e26bc920b3f648e6fb0c546673a42f997a00afaf19e70ea0705bd8c0ffe"
    },
    "tools/qualify_hia_service_lease_callers.py": {
        "bytes": 13895,
        "sha256": "0dcfdc29275f41959c1400f860d736a2220e6e1ef68bb0c34a31b5dddf3a389a"
    },
    "tests/test_hia_slot_ledger_native_integration.py": {
        "bytes": 87678,
        "sha256": "f270650c8b70ef1384d0941a85c15c68b788f8198ef88de7f3fa8c96805e853f"
    }
}
PREVIOUS = {
    "tests/hia_caller_terminal_admission.py": {
        "bytes": 26873,
        "sha256": "0c902e969fdd89e27430c61089ae4071340bd9096a439c1a71d182c75a6e11e3"
    },
    "tools/read_hia_store_file_capture_callers.py": {
        "bytes": 54357,
        "sha256": "9ac6fc1ef417f04752bc4c8b9971a4567ae01c9646216603c7425d0658be42e6"
    },
    "tools/qualify_hia_service_lease_callers.py": {
        "bytes": 11521,
        "sha256": "768363114e61b4aa315202de59a2f815a5abf5157c95111aebd480404e5a00ca"
    },
    "tests/test_hia_slot_ledger_native_integration.py": {
        "bytes": 85213,
        "sha256": "e6aacdb28c34890f897b09d088ede33cd1360a9e8cf09ba44e48fecd1187ffd1"
    }
}
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_PIN = {'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'}


SLOT_PATH = 'tests/test_hia_slot_ledger_native_integration.py'
SLOT_FIXTURE = 'tests/fixtures/hia_slot_integration_component_history_v1.json'
SLOT_FIXTURE_PIN = {'bytes': 21780, 'sha256': 'ce0a0e31a881beb64d08bf85941361bfe2e10191111fe7bfcbb65b670d8a4a26'}
SLOT_HELPER = 'tests/hia_slot_integration_component_history.py'
SLOT_HELPER_PIN = {'bytes': 9108, 'sha256': '64b4b1f1ef9de781e4ef8119156ed873b89689d7aa7d6103b7ea6c1247bf5aa4'}
SLOT_COMPONENTS = {
    "tests/hia_component_install_fixture.py": {
        "bytes": 31277,
        "sha256": "593e3b0b547a9d1e0d24a0a8c7338fb260e66e414c60f5c294d9a1d4c77f459c"
    },
    "tests/test_hia_component_install_fixture.py": {
        "bytes": 15938,
        "sha256": "9cb4de7fd7f42a04c2691488bf9c0ee6cf921113eb623170cd3021c0784c330a"
    }
}
SLOT_VERSIONS = {
    "current": {
        "bytes": 87678,
        "sha256": "f270650c8b70ef1384d0941a85c15c68b788f8198ef88de7f3fa8c96805e853f"
    },
    "external": {
        "bytes": 85231,
        "sha256": "50699c2dacdf503d5d820466ab590a9786dd2023d2d4fa06bedf1c9673d9ff42"
    },
    "installed": {
        "bytes": 85213,
        "sha256": "e6aacdb28c34890f897b09d088ede33cd1360a9e8cf09ba44e48fecd1187ffd1"
    },
    "original": {
        "bytes": 85106,
        "sha256": "02081467ee8eff2589f1b284f6259a349526b4a87d643072f12c9b24a725de7d"
    }
}


def slot_predecessor(root, raw, capture, inverse):
    frozen = capture(root / SLOT_FIXTURE)
    if pin(frozen) != SLOT_FIXTURE_PIN or pin(capture(root / SLOT_HELPER)) != SLOT_HELPER_PIN:
        raise ValueError('native composition Slot fixed source history differs')
    value = json.loads(frozen)
    if (value['schema'] != 'hepta.hia.slot-integration-component-source-history.v1'
            or value['versions'] != SLOT_VERSIONS or value['component_pins'] != SLOT_COMPONENTS
            or value['original_wheel_budget_seconds'] != 90
            or value['whole_native_delivery_qualified'] is not False):
        raise ValueError('native composition Slot original scope differs')
    for name, expected in SLOT_COMPONENTS.items():
        if pin(capture(root / name)) != expected:
            raise ValueError('native composition Slot component input differs: ' + name)
    capture(root / 'tools/hia_cold_compiler.py')
    legacy = capture(root / 'tests/fixtures/hia_installed_distribution_sources.json')
    if sha256(legacy).hexdigest() != '6b81c5c6f611e4b75fc3228936a32b1753ca33649706cda37bbae6007f69001d':
        raise ValueError('native composition Slot installed relation differs')
    legacy_row = json.loads(legacy)['files'][SLOT_PATH]
    if (legacy_row['current'] != SLOT_VERSIONS['installed']
            or legacy_row['original'] != SLOT_VERSIONS['original']):
        raise ValueError('native composition Slot installed complete pins differ')
    selected, installed = raw, None
    for key, old, new in (
            ('current_to_external', 'external', 'current'),
            ('external_to_installed', 'installed', 'external'),
            ('installed_to_original', 'original', 'installed')):
        record = value['relations'][key]
        if record['old'] != SLOT_VERSIONS[old] or record['new'] != SLOT_VERSIONS[new]:
            raise ValueError('native composition Slot complete inverse relation differs')
        selected = inverse.history_inverse(selected, {
            'old_bytes': record['old']['bytes'], 'old_sha256': record['old']['sha256'],
            'new_bytes': record['new']['bytes'], 'new_sha256': record['new']['sha256'],
            'hunks': record['hunks']}, SLOT_VERSIONS[old])
        if old == 'installed':
            installed = selected
    return installed


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('native composition source history requires exact bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def prepare(root, supplied, *, take=Path.read_bytes):
    if type(supplied) is not dict:
        raise ValueError('native composition source inputs are not a mapping')
    if not any(name in CURRENT and pin(raw) == CURRENT[name]
               for name, raw in supplied.items()):
        return dict(supplied), None
    root, saved, views = Path(root), {}, {}

    def capture(path):
        path = Path(path)
        name = path.relative_to(root).as_posix()
        if (not name or name == '.' or str(PurePosixPath(name)) != name
                or any(part in ('', '.', '..', '.git') for part in name.split('/'))):
            raise ValueError('native composition source path escaped its root')
        raw = take(path)
        pin(raw)
        if name in saved and saved[name] != raw:
            raise ValueError('native composition physical source changed: ' + name)
        saved[name] = raw
        return raw

    for name, raw in supplied.items():
        if capture(root / name) != raw:
            raise ValueError('native composition input is not its physical source')
    if (capture(root / SELF) != _EXECUTED_SOURCE
            or Path(__file__).read_bytes() != _EXECUTED_SOURCE):
        raise ValueError('native composition executing reader changed')
    fixed = capture(root / FIXTURE)
    if pin(fixed) != FIXTURE_PIN:
        raise ValueError('native composition complete fixed relation changed')
    value = json.loads(fixed)
    if (value.get('schema') != 'hepta.hia.native-cold-composition-source-history.v1'
            or value.get('base_commit') != '7b9d5a9356a18accc3d7daa7a33c80f4cbe68a00'
            or value.get('original_fixed_fixtures_modified') is not False
            or value.get('original_method_inventories_and_budgets_modified') is not False
            or value.get('prior_projection_is_physical_source') is not False
            or value.get('whole_native_delivery_qualified') is not False
            or set(value.get('files', {})) != set(CURRENT)):
        raise ValueError('native composition fixed source scope differs')
    engine = capture(root / ENGINE)
    from tools import hia_frozen_component_sources as inverse
    if pin(engine) != ENGINE_PIN or Path(inverse.__file__).read_bytes() != engine:
        raise ValueError('native composition immutable inverse reader changed')
    review = {
        'schema': 'hepta.hia.native-cold-composition-source-review.v1',
        'authority': {'path': FIXTURE, **pin(fixed)},
        'actual_captured_files': {}, 'historical_source_inputs': {},
        'prior_projection_is_physical_source': False,
        'physical_capture_rewritten': False,
        'terminal_reread_identical': False,
        'whole_native_delivery_qualified': False,
    }

    def prior_take(path):
        physical = capture(path)
        name = Path(path).relative_to(root).as_posix()
        if name in CURRENT and pin(physical) == CURRENT[name]:
            if name not in views:
                views[name] = inverse.history_inverse(
                    physical, value['files'][name], PREVIOUS[name])
                if name == SLOT_PATH and slot_predecessor(root, physical, capture, inverse) != views[name]:
                    raise ValueError('native composition independent Slot relations disagree')
            review['historical_source_inputs'][name] = pin(views[name])
            return views[name]
        return physical

    projected = {name: prior_take(root / name) for name in supplied}
    history = {'root': root, 'take': take, 'captures': saved, 'prior_take': prior_take,
               'views': views, 'review': review}
    verify_unchanged(history)
    return projected, history


def verify_unchanged(history):
    if history is None:
        return
    if Path(__file__).read_bytes() != _EXECUTED_SOURCE:
        raise ValueError('native composition executing reader changed at terminal')
    for name, raw in history['captures'].items():
        if history['take'](history['root'] / name) != raw:
            raise ValueError('native composition physical source changed at terminal: ' + name)
    for name, raw in history['views'].items():
        if pin(raw) != PREVIOUS[name] or pin(history['captures'][name]) != CURRENT[name]:
            raise ValueError('native composition prior view lost its complete current source')
    review = history['review']
    if (review.get('schema') != 'hepta.hia.native-cold-composition-source-review.v1'
            or review.get('prior_projection_is_physical_source') is not False
            or review.get('physical_capture_rewritten') is not False
            or review.get('whole_native_delivery_qualified') is not False):
        raise ValueError('native composition review cannot relabel its source view')
    review['actual_captured_files'] = {name: pin(raw) for name, raw in history['captures'].items()}
    review['historical_source_inputs'] = {name: pin(raw) for name, raw in history['views'].items()}
    review['terminal_reread_identical'] = True
