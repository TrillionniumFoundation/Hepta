"""Physical custody for the evaluation deadline and component-install successor.

The retained Store source-history engine stays byte-identical. Its older input
view is an explicit verified projection, never a physical-source claim.
"""
from hashlib import sha256
import json
from pathlib import Path
import re

FIXTURE = 'tests/fixtures/hia_evaluation_window_history_v1.json'
FIXTURE_SHA256 = '772d424511fea41fd2e21e8bec6f64a6f95519e890dd67179f71364375993731'
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_SHA256 = '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'
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
        "bytes": 50437,
        "sha256": "333abf8107aec87e42002c0a2f0218aeacdf9837642e443563f64272d6dc5083"
    }
}
UNCHANGED = {
    "hepta/hia_store_lifecycle_native.py": {
        "bytes": 22413,
        "sha256": "c800f2d9701698147b4702401908dc37625cdea1ee21d550b5154ea10c9806f1"
    },
    "hepta/hia_emission_native.py": {
        "bytes": 35066,
        "sha256": "2dffce808cccef4f5632d10c63dbb22b523aeed867142d64a142e44b2d4a86ba"
    }
}
PATHS = tuple(ORIGINAL) + tuple(UNCHANGED)
DEPENDENCIES = ('tools/hia_evaluation_window_history.py', FIXTURE, ENGINE)


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('evaluation source history requires physical bytes')
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
    """Return (projected_subset, history) after complete five-file admission.

    Use history['prior_take'] only as an explicit input view for the unchanged
    earlier reader. Always call verify_unchanged(history) after that consumer.
    history['captures'] contains actual physical bytes throughout.
    """
    root = Path(root)
    if type(captured) is not dict or not captured:
        raise ValueError('evaluation history requires a nonempty captured source map')
    saved = {}

    def capture(path):
        path = Path(path)
        try:
            name = path.relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError('evaluation history read escaped its source root') from error
        if (name in ('', '.') or any(part in ('', '.', '..', '.git') for part in name.split('/'))):
            raise ValueError('evaluation history source path is not canonical')
        raw = take(path)
        pin(raw)
        if name in saved and saved[name] != raw:
            raise ValueError('evaluation history physical source changed: ' + name)
        saved[name] = raw
        return raw

    for name, raw in captured.items():
        if type(name) is not str or capture(root / name) != raw:
            raise ValueError('evaluation history input is not its physical capture')
    physical = {name: capture(root / name) for name in PATHS}
    if any(pin(physical[name]) != expected for name, expected in UNCHANGED.items()):
        raise ValueError('evaluation history unchanged composition member differs')
    current = all(pin(physical[name]) == expected for name, expected in CURRENT.items())
    previous = all(pin(physical[name]) == expected for name, expected in ORIGINAL.items())
    if not current and not previous:
        raise ValueError('evaluation history mixed or unreviewed three-file successor')
    frozen = capture(root / FIXTURE)
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('evaluation history fixed relation changed')
    value = json.loads(frozen)
    if (type(value) is not dict or value.get('schema') != 'hepta.hia.evaluation-window-history.v1'
            or value.get('base_commit') != 'd38ca48f4bac7a4ebba4ed9f6175d6e5f57aacb9'
            or set(value.get('files', {})) != set(ORIGINAL)
            or value.get('unchanged') != UNCHANGED
            or value.get('prior_projection_is_physical_source') is not False
            or value.get('original_store_history_fixture_modified') is not False):
        raise ValueError('evaluation source-history relation scope differs')
    engine = capture(root / ENGINE)
    if sha256(engine).hexdigest() != ENGINE_SHA256:
        raise ValueError('the retained data-only source-history engine changed')
    prior = dict(physical)
    if current:
        for name in ORIGINAL:
            if value['files'][name].get('current') != CURRENT[name]:
                raise ValueError('evaluation current whole-file relation differs')
            prior[name] = _inverse(physical[name], value['files'][name], ORIGINAL[name])

    def prior_take(path):
        observed = capture(path)
        name = Path(path).relative_to(root).as_posix()
        return prior[name] if name in prior else observed

    projected = {name: prior.get(name, raw) for name, raw in captured.items()}
    history = {'root': root, 'take': take, 'captures': saved, 'prior_take': prior_take,
               'prior_sources': prior,
               'review': {'schema': 'hepta.hia.evaluation-window-source-review.v1',
                   'physical': {name: pin(raw) for name, raw in physical.items()},
                   'prior_projection': {name: pin(raw) for name, raw in prior.items()},
                   'fixed_relation': {'path': FIXTURE, **pin(frozen)},
                   'retained_engine': {'path': ENGINE, **pin(engine)},
                   'successor_applied': current,
                   'physical_capture_rewritten': False,
                   'prior_projection_is_physical_source': False,
                   'terminal_reread_identical': False}}
    verify_unchanged(history)
    return projected, history


def verify_unchanged(history):
    for name, raw in history['captures'].items():
        if history['take'](history['root'] / name) != raw:
            raise ValueError('evaluation physical source changed at terminal: ' + name)
    history['review']['terminal_reread_identical'] = True
