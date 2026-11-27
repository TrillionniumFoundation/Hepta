"""Data-only composition of the fixed six-result caller and older histories.

The physical caller remains in the caller's capture. Only an exact whole-file
successor is projected into the unchanged older source authorities.
"""
from hashlib import sha256
from pathlib import Path

RESULT_PATH = 'tests/test_hia_agent_native_tools.py'
RESULT_CURRENT = {
    'bytes': 47052,
    'sha256': '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2',
}
RESULT_ORIGINAL = {
    'bytes': 47052,
    'sha256': '64462e8735d8be3838396808dc05391e4437b2dba093fcc265468df6abb4cb70',
}
RESULT_HELPER = 'tools/hia_native_result_caller_history.py'
RESULT_HELPER_PIN = {
    'bytes': 2868,
    'sha256': 'e1e1edfcaeaf0f80f7b2b51604afff87908d45419f1aef87fbf8408589cc4248',
}
RESULT_FIXTURE = 'tests/fixtures/hia_native_result_caller_history_v1.json'
RESULT_FIXTURE_SHA256 = 'dccd8c04824fdaa3ac7cf638fd487622a8ecfd198236cf0108ef8dc2edb10130'


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('current caller source history requires exact bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def result_predecessor(root, name, raw, *, take=Path.read_bytes):
    """Return the precise six-result predecessor and a separate revision proof."""
    if name != RESULT_PATH or pin(raw) != RESULT_CURRENT:
        return raw, None
    root = Path(root)
    saved = {}
    def capture(path):
        value = take(path)
        if path in saved and saved[path] != value:
            raise ValueError('native result source history changed between captures')
        saved[path] = value
        return value
    helper = capture(root / RESULT_HELPER)
    frozen = capture(root / RESULT_FIXTURE)
    if pin(helper) != RESULT_HELPER_PIN or pin(frozen)['sha256'] != RESULT_FIXTURE_SHA256:
        raise ValueError('native result source history fixed dependency differs')
    from tools import hia_native_result_caller_history as history
    if Path(history.__file__).read_bytes() != helper:
        raise ValueError('native result source history imported another helper')
    restored = history.unwrap(root, name, raw, take=capture)
    if pin(restored) != RESULT_ORIGINAL:
        raise ValueError('native result source history lost its complete predecessor')
    for path, value in saved.items():
        if take(path) != value:
            raise ValueError('native result source history changed at terminal reread')
    return restored, {
        'schema': 'hepta.hia.current-native-result-caller-source-review.v1',
        'path': name, 'physical': pin(raw), 'predecessor': pin(restored),
        'helper': {'path': RESULT_HELPER, **pin(helper)},
        'fixture': {'path': RESULT_FIXTURE, **pin(frozen)},
        'assertion_revision': {'function_results': {'old': 3, 'new': 6},
                               'changed_bytes': 1},
        'deadline_methods_changed': False,
        'physical_source_and_fixed_dependencies_reread': True,
        'whole_native_delivery_qualified': False,
    }


def reviewed_source(root, name, raw, *, take=Path.read_bytes):
    """Retain the old complete source admission after the explicit new layer."""
    root = Path(root)
    saved = {}
    def capture(path):
        value = take(path)
        if path in saved and saved[path] != value:
            raise ValueError('current caller source changed between history layers')
        saved[path] = value
        return value
    selected, _ = result_predecessor(root, name, raw, take=capture)
    from tools.hia_frozen_component_sources import reviewed_source as original_review
    reviewed = original_review(root, name, selected, take=capture)
    for path, value in saved.items():
        if take(path) != value:
            raise ValueError('current caller source changed after complete old admission')
    return reviewed
