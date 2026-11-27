"""Physical source custody for the Evaluation native-cold selector successor.

The earlier three-file window history is unchanged. Its explicit prior input
view sees the reviewed component-install test, while this layer retains the
actual current test bytes and verifies every consumed physical file again.
"""
from hashlib import sha256
import json
from pathlib import Path
import re

PATH = 'tests/test_hia_evaluation_native.py'
FIXTURE = 'tests/fixtures/hia_evaluation_native_cold_history_v1.json'
FIXTURE_SHA256 = '67b019bc769e4bb4ef5883f0ada2cd859c96272ea4dc7073cba582d63b7082f0'
ORIGINAL = {
    "hepta/hia_agent_service.py": {
        "bytes": 268278,
        "sha256": "afc92b555bd0dfa23f25c4f9c2661af30853474342f4e32a036d37c1ce663a57"
    },
    "hepta/hia_evaluation_native.py": {
        "bytes": 46096,
        "sha256": "71f6d3be9bd116f3419b552e075113110596124365074d74ccf8855d15dc18e4"
    },
    "tests/test_hia_evaluation_native.py": {
        "bytes": 50297,
        "sha256": "ee3a01914f902f92cb5f440acd224926c92322d346e76e14fde081516b51fbe5"
    }
}
PREVIOUS = {
    "hepta/hia_agent_service.py": {
        "bytes": 268730,
        "sha256": "353bd2673cc4f269c9c2d6cbf226d8956703d434ca960214864f56689d8f82c1"
    },
    "hepta/hia_evaluation_native.py": {
        "bytes": 47978,
        "sha256": "f9b25023b393f7b621b515b9b7f481a992715f15a386bf8c2457e2eb3136a73d"
    },
    "tests/test_hia_evaluation_native.py": {
        "bytes": 50437,
        "sha256": "333abf8107aec87e42002c0a2f0218aeacdf9837642e443563f64272d6dc5083"
    }
}
CURRENT = {
    "hepta/hia_agent_service.py": {
        "bytes": 268730,
        "sha256": "353bd2673cc4f269c9c2d6cbf226d8956703d434ca960214864f56689d8f82c1"
    },
    "hepta/hia_evaluation_native.py": {
        "bytes": 47978,
        "sha256": "f9b25023b393f7b621b515b9b7f481a992715f15a386bf8c2457e2eb3136a73d"
    },
    "tests/test_hia_evaluation_native.py": {
        "bytes": 50368,
        "sha256": "8e55e6c0adda8629c5c484173262b63f726c727b2eeefbaf4926622e59a6cec0"
    }
}
PATHS = tuple(CURRENT)


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('evaluation cold source history requires physical bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _inverse(raw, row, expected):
    if (type(row) is not dict or set(row) != {'original', 'current', 'hunks'}
            or row['original'] != expected or pin(raw) != row['current']
            or type(row['hunks']) is not list or not row['hunks']):
        raise ValueError('evaluation history complete source identity differs')
    previous_old = previous_new = 0
    parts, replay = [], []
    for hunk in row['hunks']:
        if (type(hunk) is not dict
                or set(hunk) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or type(hunk['old_offset']) is not int
                or type(hunk['new_offset']) is not int
                or hunk['old_offset'] < previous_old or hunk['new_offset'] < previous_new
                or any(type(hunk[name]) is not str
                    or re.fullmatch('(?:[0-9a-f]{2})*', hunk[name]) is None
                    for name in ('old_hex', 'new_hex'))):
            raise ValueError('evaluation history splice coordinates or bytes differ')
        old, new = bytes.fromhex(hunk['old_hex']), bytes.fromhex(hunk['new_hex'])
        oa, na = hunk['old_offset'], hunk['new_offset']
        if (old == new or oa - previous_old != na - previous_new
                or na + len(new) > len(raw) or raw[na:na + len(new)] != new):
            raise ValueError('evaluation history splice does not describe current bytes')
        parts.extend((raw[previous_new:na], old))
        replay.append((oa, old, new))
        previous_old, previous_new = oa + len(old), na + len(new)
    parts.append(raw[previous_new:])
    restored = b''.join(parts)
    if pin(restored) != expected:
        raise ValueError('evaluation history did not restore the complete predecessor')
    parts, previous_old = [], 0
    for offset, old, new in replay:
        if restored[offset:offset + len(old)] != old:
            raise ValueError('evaluation history forward replay source differs')
        parts.extend((restored[previous_old:offset], new))
        previous_old = offset + len(old)
    parts.append(restored[previous_old:])
    if b''.join(parts) != raw:
        raise ValueError('evaluation history complete forward replay differs')
    return restored


def prepare(root, captured, *, take=Path.read_bytes):
    """Return a verified prior subset and a separate physical custody record.

    Pass history['prior_take'] explicitly to the unchanged window history and
    call verify_unchanged after every consumer. Never use projected bytes as
    actual current-source captures. The complete old domains need no new file.
    """
    root = Path(root)
    if type(captured) is not dict or not captured:
        raise ValueError('evaluation cold history requires captured source bytes')
    saved = {}

    def capture(path):
        path = Path(path)
        try:
            name = path.relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError('evaluation cold history escaped its source root') from error
        if name in ('', '.') or any(p in ('', '.', '..', '.git') for p in name.split('/')):
            raise ValueError('evaluation cold history path is not canonical')
        raw = take(path)
        pin(raw)
        if name in saved and saved[name] != raw:
            raise ValueError('evaluation cold physical source changed: ' + name)
        saved[name] = raw
        return raw

    for name, raw in captured.items():
        if type(name) is not str or capture(root / name) != raw:
            raise ValueError('evaluation cold input is not its physical capture')
    physical = {name: capture(root / name) for name in PATHS}
    current = all(pin(physical[n]) == p for n, p in CURRENT.items())
    previous = all(pin(physical[n]) == p for n, p in PREVIOUS.items())
    original = all(pin(physical[n]) == p for n, p in ORIGINAL.items())
    if not (current or previous or original):
        raise ValueError('evaluation cold composition is mixed or unreviewed')
    prior = dict(physical)
    fixed = None
    if current:
        frozen = capture(root / FIXTURE)
        if sha256(frozen).hexdigest() != FIXTURE_SHA256:
            raise ValueError('evaluation cold fixed whole-file relation changed')
        value = json.loads(frozen)
        if (type(value) is not dict
                or value.get('schema') != 'hepta.hia.evaluation-native-cold-source-history.v1'
                or value.get('base_commit') != '1b4c30754871bf8c1fc5923b867ae0435d0f3b7b'
                or value.get('upstream_selector_commit') != '4681a60bba48409749160e49cd7d3a5a6018460d'
                or value.get('prior_projection_is_physical_source') is not False
                or value.get('old_fixed_relations_modified') is not False
                or set(value.get('files', {})) != {PATH}
                or value['files'][PATH].get('current') != CURRENT[PATH]):
            raise ValueError('evaluation cold relation scope differs')
        prior[PATH] = _inverse(physical[PATH], value['files'][PATH], PREVIOUS[PATH])
        fixed = {'path': FIXTURE, **pin(frozen)}

    def prior_take(path):
        observed = capture(path)
        name = Path(path).relative_to(root).as_posix()
        return prior[name] if name in prior else observed

    projected = {name: prior.get(name, raw) for name, raw in captured.items()}
    history = {'root': root, 'take': take, 'captures': saved,
               'prior_take': prior_take, 'prior_sources': prior,
               'review': {'schema': 'hepta.hia.evaluation-native-cold-source-review.v1',
                   'physical': {n: pin(b) for n, b in physical.items()},
                   'prior_projection': {n: pin(b) for n, b in prior.items()},
                   'fixed_relation': fixed, 'successor_applied': current,
                   'physical_capture_rewritten': False,
                   'prior_projection_is_physical_source': False,
                   'terminal_reread_identical': False}}
    verify_unchanged(history)
    return projected, history


def verify_unchanged(history):
    for name, raw in history['captures'].items():
        if history['take'](history['root'] / name) != raw:
            raise ValueError('evaluation cold physical source changed at terminal: ' + name)
    history['review']['terminal_reread_identical'] = True
