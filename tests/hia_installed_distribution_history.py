"""Exact predecessor relations for installed distribution qualification callers."""
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = 'tests/fixtures/hia_installed_distribution_sources.json'
FIXTURE_SHA256 = '6b81c5c6f611e4b75fc3228936a32b1753ca33649706cda37bbae6007f69001d'

# These four component tests and Delivery qualifier consume historical inputs.
# Other shared dependencies retain their original current-source semantics.
COLD_INSTALLED_PATHS = (
    'tests/test_hia_service_context_native.py',
    'tests/test_hia_store_lifecycle_native.py',
    'tests/test_hia_cost_ledger_native.py',
    'tests/test_hia_service_artifact_native.py',
    'tools/qualify_hia_native_delivery.py',
)


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
    from tools.hia_frozen_component_sources import cold_caller_source
    root = ROOT if root is None else Path(root)
    captured = {}

    def capture(path):
        raw = take(path)
        if path in captured and captured[path] != raw:
            raise ValueError('installed source-history fixture changed between captures')
        captured[path] = raw
        return raw

    try:
        cold_admission = None
        if name in COLD_INSTALLED_PATHS:
            data, cold_admission = cold_caller_source(root, name, data, take=capture)
        if cold_admission is not None:
            for source_name, loaded_path in (
                    ('tests/hia_installed_distribution_history.py', __file__),
                    ('tests/hia_component_authoring_history.py', component_predecessor.__code__.co_filename)):
                if capture(root / source_name) != Path(loaded_path).read_bytes():
                    raise ValueError('installed source-history loaded helper differs from captured root')
        from tests.hia_component_native_cold_history import predecessor as native_cold_predecessor
        data = native_cold_predecessor(name, data, root=root, take=capture)
        data = component_predecessor(name, data, root=root, take=capture)
        record = _records(root=root, take=capture).get(name)
        if record is None or sha256(data).hexdigest() != record['current']['sha256']:
            return data
        return reverse(data, record)
    finally:
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
