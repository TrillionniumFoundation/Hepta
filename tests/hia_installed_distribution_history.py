"""Exact predecessor relations for installed distribution qualification callers."""
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = 'tests/fixtures/hia_installed_distribution_sources.json'
FIXTURE_SHA256 = '6b81c5c6f611e4b75fc3228936a32b1753ca33649706cda37bbae6007f69001d'


@lru_cache(maxsize=1)
def _parse_records(data):
    if sha256(data).hexdigest() != FIXTURE_SHA256:
        raise ValueError('the fixed installed-distribution source relation differs')
    return json.loads(data)['files']


def _records(*, root=None, take=Path.read_bytes):
    root = ROOT if root is None else Path(root)
    path = root / FIXTURE
    data = take(path)
    records = _parse_records(data)
    if take(path) != data:
        raise ValueError('installed-distribution fixture changed at terminal readback')
    return records


def _restore(data, record):
    original = bytearray()
    end = 0
    for change in record['splices']:
        start = change['offset']
        before = change['before'].encode('utf-8')
        after = change['after'].encode('utf-8')
        current = end + start - len(original)
        if start < len(original) or data[current:current + len(after)] != after:
            raise ValueError('the installed test source differs at its reviewed splice')
        original.extend(data[end:current])
        original.extend(before)
        end = current + len(after)
    original.extend(data[end:])
    original = bytes(original)
    if {'bytes': len(original), 'sha256': sha256(original).hexdigest()} != record['original']:
        raise ValueError('the complete prior installed test source differs')
    return original


def predecessor(name, data, reverse=_restore, *, root=None, take=Path.read_bytes):
    """Unwrap exact reviewed bytes using only the caller's captured source root."""
    from tests.hia_component_authoring_history import predecessor as component_predecessor
    root = ROOT if root is None else Path(root)
    captured = {}

    def capture(path):
        raw = take(path)
        if path in captured and captured[path] != raw:
            raise ValueError('installed source-history fixture changed between captures')
        captured[path] = raw
        return raw

    history = None
    try:
        view = capture
        if (name == 'tests/test_hia_agent_native_tools.py'
                and sha256(data).hexdigest() ==
                '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2'):
            helper = capture(root / 'tools/hia_native_result_caller_history.py')
            if (len(helper) != 2868 or sha256(helper).hexdigest() !=
                    'e1e1edfcaeaf0f80f7b2b51604afff87908d45419f1aef87fbf8408589cc4248'):
                raise ValueError('native result caller source-history reader differs')
            from tools.hia_native_result_caller_history import unwrap
            data = unwrap(root, name, data, take=capture)
        if (name == 'tests/test_hia_evaluation_native.py'
                and sha256(data).hexdigest() ==
                '333abf8107aec87e42002c0a2f0218aeacdf9837642e443563f64272d6dc5083'):
            helper = capture(root / 'tools/hia_evaluation_window_history.py')
            if (len(helper) != 8876 or sha256(helper).hexdigest() !=
                    '08054cf59af6e93453fc370d08c64d1b14e9072012f69652cfae747083346cfa'):
                raise ValueError('evaluation composition source-history reader differs')
            from tools import hia_evaluation_window_history as current
            projected, history = current.prepare(root, {name: data}, take=capture)
            view = history['prior_take']
            from tools.hia_frozen_component_sources import restore_evaluation_test
            data = restore_evaluation_test(projected[name], root=root, take=view)
        data = component_predecessor(name, data, root=root, take=view)
        record = _records(root=root, take=view).get(name)
        if record is None or sha256(data).hexdigest() != record['current']['sha256']:
            return data
        return reverse(data, record)
    finally:
        if history is not None:
            current.verify_unchanged(history)
        for path, raw in captured.items():
            if take(path) != raw:
                raise ValueError('installed source-history fixture changed at terminal readback')


def journal_preparation_source(root, raw, original_pin, *, take=Path.read_bytes):
    """Verify the earlier journal preparation against its complete source image."""
    from tempfile import TemporaryDirectory
    from tests import hia_journal_installed_preparation as journal

    root = Path(root)
    captured = {}

    def capture(path):
        data = take(path)
        if path in captured and captured[path] != data:
            raise ValueError('journal source-history input changed between captures')
        captured[path] = data
        return data

    try:
        prior = predecessor(journal.PATH, raw, root=root, take=capture)
        if prior == raw:
            return journal.admit_source(root, journal.PATH, raw, original_pin)
        inputs = {name: capture(root / name) for name in journal.SOURCE_PATHS}
        if inputs[journal.PATH] != raw:
            raise ValueError('the current Journal caller differs from its supplied source')
        with TemporaryDirectory(prefix='hia-previous-journal-source-') as temporary:
            stage = Path(temporary)
            for name, data in inputs.items():
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(prior if name == journal.PATH else data)
            return journal.admit_source(stage, journal.PATH, prior, original_pin)
    finally:
        for path, data in captured.items():
            if take(path) != data:
                raise ValueError('the current Journal source inputs changed during admission')
