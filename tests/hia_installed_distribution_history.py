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
    from tests import hia_reference_profile_history as reference
    helper = (Path(__file__).resolve().parents[1] / 'tests/hia_reference_profile_history.py').read_bytes()
    if ({'bytes': len(helper), 'sha256': sha256(helper).hexdigest()} != {'bytes': 2472, 'sha256': 'afd75b65a9ebaacc2c2cef918d43445b42829b66cdbce11b2c5a16e8e982d9e3'}
            or Path(reference.__file__).read_bytes() != helper):
        raise ValueError('complete explicit reference-profile source helper changed')
    data = reference.predecessor(name, data)
    if name == 'tests/test_hia_agent_installed_resources.py':
        from tests import hia_installed_resource_history as resource
        helper = (Path(__file__).resolve().parents[1] / 'tests/hia_installed_resource_history.py').read_bytes()
        if ({'bytes': len(helper), 'sha256': sha256(helper).hexdigest()} != {'bytes': 8334, 'sha256': 'c6b4275dfbf0e6a8138db14972aec0bef28699ba879062bc466656503b304a5d'}
                or Path(resource.__file__).read_bytes() != helper):
            raise ValueError('complete installed-resource source helper changed')
        data = resource.reference_source(name, data)
    raw = (Path(__file__).resolve().parents[1] / REFERENCE_FIXTURE).read_bytes()
    if sha256(raw).hexdigest() != REFERENCE_FIXTURE_SHA256:
        raise ValueError('the native reference-profile source relation differs')
    record = json.loads(raw)['files'].get(name)
    if record is not None and sha256(data).hexdigest() == record['current']['sha256']:
        return _restore(data, record)
    return data



# Exact final diagnostic routing in the existing complete caller qualifiers.
# Historical Source controls still exercise their former complete reviewed bytes.
CALLER_SOURCE_SUCCESSORS = {'tools/qualify_hia_cost_ledger_callers.py': {'original': {'bytes': 10516, 'sha256': '30842806afddf8e493cc968740e5aa947dc906d041a466ceab8c6f7e0d34e844'}, 'current': {'bytes': 11626, 'sha256': 'aa4ad100c98c4d994ca4a387428df0cbef8353f54fd8df61e71c600e6861e36d'}, 'splices': [{'offset': 1463, 'before': '', 'after': "    if name == 'tests/test_hia_agent_native_machine_validation.py':\n        from tests import hia_final_source_successor as final\n        helper = capture('tests/hia_final_source_successor.py')\n        if (_source_pin(helper) != {'bytes': 8968, 'sha256': '101873425ef8bba70456e915916836bcd4b48d29b2cf5b44cbd121603a097722'}\n                or Path(final.__file__).read_bytes() != helper):\n            raise ValueError('complete machine caller source helper changed')\n        return final.admit_machine_caller(capture, name, raw, original_digest)\n"}, {'offset': 2064, 'before': '', 'after': "    if _source_pin(raw) != diagnostic.CURRENT:\n        from tests import hia_final_source_successor as final\n        final_source = capture('tests/hia_final_source_successor.py')\n        if (_source_pin(final_source) != {'bytes': 8968, 'sha256': '101873425ef8bba70456e915916836bcd4b48d29b2cf5b44cbd121603a097722'}\n                or Path(final.__file__).read_bytes() != final_source):\n            raise ValueError('complete caller diagnostic source helper changed')\n        return final.admit_diagnostics(capture, name, raw, original_digest, authority, diagnostic)\n"}]}, 'tools/qualify_hia_service_context_callers.py': {'original': {'bytes': 11944, 'sha256': 'c7825a2724acb1d7137a8ad1c24aac0f865c227c5b2c27bf4ea52f05c2d8d863'}, 'current': {'bytes': 12560, 'sha256': 'd0cd44f8aefcf15ccf7d3567452a1a6c8e05aaa12a414a09f22f305ace24cdaf'}, 'splices': [{'offset': 3102, 'before': '        diagnostics[name] = diagnostic.admit(name, raw, digest, authority)\n', 'after': "        if _source_pin(raw) != diagnostic.CURRENT:\n            from tests import hia_final_source_successor as final\n            final_source = capture('tests/hia_final_source_successor.py')\n            if (_source_pin(final_source) != {'bytes': 8968, 'sha256': '101873425ef8bba70456e915916836bcd4b48d29b2cf5b44cbd121603a097722'}\n                    or Path(final.__file__).read_bytes() != final_source):\n                raise ValueError('complete context diagnostic source helper changed')\n            diagnostics[name] = final.admit_diagnostics(capture, name, raw, digest, authority, diagnostic)\n        else:\n            diagnostics[name] = diagnostic.admit(name, raw, digest, authority)\n"}]}}


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


def discovery_predecessor(name, data):
    """Accept only the complete reviewed six-result discovery successor."""
    if name != 'tests/test_hia_agent_native_tools.py' or sha256(data).hexdigest() != '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2':
        return data
    from tests import hia_final_source_successor as final
    helper = (Path(__file__).resolve().parents[1] / 'tests/hia_final_source_successor.py').read_bytes()
    if ({'bytes': len(helper), 'sha256': sha256(helper).hexdigest()} != {'bytes': 8968, 'sha256': '101873425ef8bba70456e915916836bcd4b48d29b2cf5b44cbd121603a097722'}
            or Path(final.__file__).read_bytes() != helper):
        raise ValueError('discovery result-version source helper changed')
    return final.discovery_results_predecessor(data)


def predecessor(name, data, reverse=_restore):
    """Unwrap only the exact reviewed file. Prior authorities check their own full bytes."""
    data = discovery_predecessor(name, data)
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
