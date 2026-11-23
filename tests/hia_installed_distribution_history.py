"""Exact predecessor relations for installed distribution qualification callers."""
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path

FIXTURE = 'tests/fixtures/hia_installed_distribution_sources.json'
FIXTURE_SHA256 = '7dc624dec66d4f006f1b5852416ebe85ccdac52d2a04fa949482c704b839bae0'


@lru_cache(maxsize=1)
def _parse_records(data):
    if sha256(data).hexdigest() != FIXTURE_SHA256:
        raise ValueError('the fixed installed-distribution source relation differs')
    return json.loads(data)['files']


def _records():
    data = (Path(__file__).resolve().parents[1] / FIXTURE).read_bytes()
    return _parse_records(data)


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


def predecessor(name, data, reverse=_restore):
    """Unwrap only the exact reviewed file. Prior authorities check their own full bytes."""
    record = _records().get(name)
    if record is None or sha256(data).hexdigest() != record['current']['sha256']:
        return data
    return reverse(data, record)


def journal_preparation_source(root, raw, original_pin):
    """Verify the earlier journal preparation against its complete source image."""
    from tempfile import TemporaryDirectory
    from tests import hia_journal_installed_preparation as journal

    prior = predecessor(journal.PATH, raw)
    if prior == raw:
        return journal.admit_source(root, journal.PATH, raw, original_pin)
    inputs = {name: (root / name).read_bytes() for name in journal.SOURCE_PATHS}
    if inputs[journal.PATH] != raw:
        raise ValueError('the current Journal caller differs from its supplied source')
    with TemporaryDirectory(prefix='hia-previous-journal-source-') as temporary:
        stage = Path(temporary)
        for name, data in inputs.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(prior if name == journal.PATH else data)
        proof = journal.admit_source(stage, journal.PATH, prior, original_pin)
    if any((root / name).read_bytes() != data for name, data in inputs.items()):
        raise ValueError('the current Journal source inputs changed during admission')
    return proof
