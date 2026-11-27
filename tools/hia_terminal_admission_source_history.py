"""Data-only exact history for the selected-root terminal admission successor."""
from hashlib import sha256
import json
from pathlib import Path

PATH = 'tests/hia_caller_terminal_admission.py'
CURRENT = {"bytes":26873,"sha256":"0c902e969fdd89e27430c61089ae4071340bd9096a439c1a71d182c75a6e11e3"}
PREDECESSOR = {"bytes":25395,"sha256":"2778515c091610bf51322d670d266e81fe328b95c5aa187e4a4b313f157984b3"}
FIXTURE = 'tests/fixtures/hia_current_terminal_admission_history_v1.json'
FIXTURE_PIN = {"bytes":4900,"sha256":"bc089aa39f3b6af3dde4695382fd1846fd717930ed2d9bf4f85cb6c6c7f995e7"}
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_PIN = {'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'}
DEPENDENCIES = ('tools/hia_terminal_admission_source_history.py', FIXTURE, ENGINE)


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('terminal source history requires exact bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def predecessor(root, name, raw, *, take=Path.read_bytes):
    if name != PATH or pin(raw) != CURRENT:
        return raw, None
    root, saved = Path(root), {}
    def capture(path):
        value = take(path)
        if path in saved and saved[path] != value:
            raise ValueError('terminal source history changed between captures')
        saved[path] = value
        return value
    if capture(root / PATH) != raw:
        raise ValueError('terminal source history input is not its selected physical source')
    frozen = capture(root / FIXTURE)
    if pin(frozen) != FIXTURE_PIN:
        raise ValueError('terminal source history fixed relation changed')
    value = json.loads(frozen)
    if (type(value) is not dict or set(value) != {'schema', 'path', 'base_commit',
            'successor_commit', 'scope', 'record', 'original_methods_and_budgets_changed',
            'physical_capture_rewritten'}
            or value['schema'] != 'hepta.hia.current-terminal-admission-source-history.v1'
            or value['path'] != PATH
            or value['base_commit'] != 'fddafe612d75e84232c6b35b7503d1c2d7efc5ce'
            or value['successor_commit'] != '94dd9a49c229d66faa62a7e788777fc6b9d89c35'
            or value['original_methods_and_budgets_changed'] is not False
            or value['physical_capture_rewritten'] is not False):
        raise ValueError('terminal source history fixed scope differs')
    engine = capture(root / ENGINE)
    if pin(engine) != ENGINE_PIN:
        raise ValueError('terminal source history inverse engine changed')
    from tools import hia_frozen_component_sources as inverse
    if Path(inverse.__file__).read_bytes() != engine:
        raise ValueError('terminal source history imported another inverse engine')
    restored = inverse.history_inverse(raw, value['record'], PREDECESSOR)
    for path, captured in saved.items():
        if take(path) != captured:
            raise ValueError('terminal source history changed at terminal reread')
    return restored, {
        'schema': 'hepta.hia.current-terminal-admission-source-review.v1',
        'path': PATH, 'physical': pin(raw), 'predecessor': pin(restored),
        'fixed_relation': {'path': FIXTURE, **pin(frozen)},
        'inverse_engine': {'path': ENGINE, **pin(engine)},
        'complete_inverse_and_forward_replay_verified': True,
        'original_methods_and_budgets_changed': False,
        'physical_capture_rewritten': False,
        'physical_source_and_dependencies_reread': True,
    }
