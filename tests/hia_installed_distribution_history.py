"""Exact predecessor relations for installed distribution qualification callers."""
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path

FIXTURE = 'tests/fixtures/hia_installed_distribution_sources.json'
FIXTURE_SHA256 = '5b0d5ac6a492fa73d444b15184698d5819ce09566914d092b7e0744ec7531722'


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


REFERENCE_FIXTURE = 'tests/fixtures/hia_native_distribution_reference_sources.json'
REFERENCE_FIXTURE_SHA256 = 'a8b85794e88413a40e6fcc14d7764856a661b11258bc31a327bcd8eee92bd5f3'


def reference_predecessor(name, data):
    """Restore only exact reviewed reference-profile argument/scope changes."""
    raw = (Path(__file__).resolve().parents[1] / REFERENCE_FIXTURE).read_bytes()
    if sha256(raw).hexdigest() != REFERENCE_FIXTURE_SHA256:
        raise ValueError('the native reference-profile source relation differs')
    record = json.loads(raw)['files'].get(name)
    if record is not None and sha256(data).hexdigest() == record['current']['sha256']:
        return _restore(data, record)
    return data



# Exact final diagnostic routing in the existing complete caller qualifiers.
# Historical Source controls still exercise their former complete reviewed bytes.
CALLER_SOURCE_SUCCESSORS = {'tools/qualify_hia_cost_ledger_callers.py': {'original': {'bytes': 10516, 'sha256': '30842806afddf8e493cc968740e5aa947dc906d041a466ceab8c6f7e0d34e844'}, 'current': {'bytes': 11626, 'sha256': 'aee44a3870eee82d8a94e65013a05d1b64a06dea23cb5495f4569f32b0486bdb'}, 'splices': [{'offset': 1463, 'before': '', 'after': "    if name == 'tests/test_hia_agent_native_machine_validation.py':\n        from tests import hia_final_source_successor as final\n        helper = capture('tests/hia_final_source_successor.py')\n        if (_source_pin(helper) != {'bytes': 7012, 'sha256': '68ffd7b27fbd492915221a5894c7c1eb4f0101001b9fd400481e19cdf19744f7'}\n                or Path(final.__file__).read_bytes() != helper):\n            raise ValueError('complete machine caller source helper changed')\n        return final.admit_machine_caller(capture, name, raw, original_digest)\n"}, {'offset': 2064, 'before': '', 'after': "    if _source_pin(raw) != diagnostic.CURRENT:\n        from tests import hia_final_source_successor as final\n        final_source = capture('tests/hia_final_source_successor.py')\n        if (_source_pin(final_source) != {'bytes': 7012, 'sha256': '68ffd7b27fbd492915221a5894c7c1eb4f0101001b9fd400481e19cdf19744f7'}\n                or Path(final.__file__).read_bytes() != final_source):\n            raise ValueError('complete caller diagnostic source helper changed')\n        return final.admit_diagnostics(capture, name, raw, original_digest, authority, diagnostic)\n"}]}, 'tools/qualify_hia_service_context_callers.py': {'original': {'bytes': 11944, 'sha256': 'c7825a2724acb1d7137a8ad1c24aac0f865c227c5b2c27bf4ea52f05c2d8d863'}, 'current': {'bytes': 12560, 'sha256': '355e3d9790c8af2cacc249a9db82867e2a89aecf1a6ddc65a4c44d4ae624d8b7'}, 'splices': [{'offset': 3102, 'before': '        diagnostics[name] = diagnostic.admit(name, raw, digest, authority)\n', 'after': "        if _source_pin(raw) != diagnostic.CURRENT:\n            from tests import hia_final_source_successor as final\n            final_source = capture('tests/hia_final_source_successor.py')\n            if (_source_pin(final_source) != {'bytes': 7012, 'sha256': '68ffd7b27fbd492915221a5894c7c1eb4f0101001b9fd400481e19cdf19744f7'}\n                    or Path(final.__file__).read_bytes() != final_source):\n                raise ValueError('complete context diagnostic source helper changed')\n            diagnostics[name] = final.admit_diagnostics(capture, name, raw, digest, authority, diagnostic)\n        else:\n            diagnostics[name] = diagnostic.admit(name, raw, digest, authority)\n"}]}}


def caller_predecessor(name, data):
    record = CALLER_SOURCE_SUCCESSORS.get(name)
    if record is None or sha256(data).hexdigest() != record['current']['sha256']:
        return data
    restored = _restore(data, record)
    replay = restored
    for change in reversed(record['splices']):
        at = change['offset']
        before, after = change['before'].encode(), change['after'].encode()
        if replay[at:at + len(before)] != before:
            raise ValueError('complete caller source forward splice differs')
        replay = replay[:at] + after + replay[at + len(before):]
    if replay != data:
        raise ValueError('complete caller source forward replay differs')
    return restored


def predecessor(name, data, reverse=_restore):
    """Unwrap only the exact reviewed file. Prior authorities check their own full bytes."""
    data = caller_predecessor(name, reference_predecessor(name, data))
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
