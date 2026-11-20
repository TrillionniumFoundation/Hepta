"""Exact source admission for the reviewed deadline failure diagnostics.

Only the complete pinned test-file successor is admitted. The original source,
ordered methods, 5-second assertion and 1-ms native budget remain authoritative;
the reconstructed bytes are data and are never executed in place of the caller.
"""
from hashlib import sha256
import json

PATH = 'tests/test_hia_agent_native_tools.py'
FIXTURE = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
FIXTURE_SHA256 = '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c'
ORIGINAL = {'bytes': 45385, 'sha256': 'c7a3b2b486e55a600ddd5e691729e8cddc6acd5935e5aad337e27c1f20be856a'}
CURRENT = {'bytes': 46518, 'sha256': 'b98c24327639363d266eb5e263c042e0a20d82a8f2e8cc08ffafb8f34f73f355'}


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def restore(raw, provenance):
    if (type(raw) is not bytes or pin(raw) != CURRENT
            or type(provenance) is not bytes
            or sha256(provenance).hexdigest() != FIXTURE_SHA256):
        raise ValueError('deadline diagnostics complete source or fixed provenance differs')
    value = json.loads(provenance)
    if (set(value) != {'schema', 'state', 'path', 'original', 'current', 'definition',
            'original_deadline_seconds', 'original_native_budget_ms',
            'original_method_ids_unchanged', 'production_source_exception', 'splices'}
            or value['schema'] != 'hepta.hia.caller-deadline-diagnostics-source.v1'
            or value['state'] != 'FROZEN_EXACT_FAILURE_DIAGNOSTICS_SUCCESSOR'
            or value['path'] != PATH or value['original'] != ORIGINAL or value['current'] != CURRENT
            or value['definition'] != 'NativeLifecycleTests.test_native_timeout_is_incomplete_terminated_and_not_adoptable'
            or type(value['original_deadline_seconds']) is not int or value['original_deadline_seconds'] != 5
            or type(value['original_native_budget_ms']) is not int or value['original_native_budget_ms'] != 1
            or value['original_method_ids_unchanged'] is not True
            or value['production_source_exception'] is not False
            or type(value['splices']) is not list or len(value['splices']) != 2):
        raise ValueError('deadline diagnostics source scope differs')
    entries = []
    old_end = new_end = displacement = 0
    for item in value['splices']:
        if (type(item) is not dict
                or set(item) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}
                or type(item['old_offset']) is not int or item['old_offset'] < old_end
                or type(item['new_offset']) is not int or item['new_offset'] < new_end):
            raise ValueError('deadline diagnostics splice positions differ')
        old_at, new_at = item['old_offset'], item['new_offset']
        segments = []
        for key in ('old_hex', 'new_hex'):
            text = item[key]
            if type(text) is not str or not text:
                raise ValueError('deadline diagnostics splice is not exact hexadecimal')
            try:
                segment = bytes.fromhex(text)
            except ValueError as error:
                raise ValueError('deadline diagnostics splice is not hexadecimal') from error
            if segment.hex() != text:
                raise ValueError('deadline diagnostics splice is not canonical hexadecimal')
            segments.append(segment)
        before, after = segments
        if (before == after or old_at + displacement != new_at
                or raw[new_at:new_at + len(after)] != after):
            raise ValueError('deadline diagnostics current splice differs')
        entries.append((old_at, new_at, before, after))
        old_end, new_end = old_at + len(before), new_at + len(after)
        displacement += len(after) - len(before)
    restored = raw
    for old_at, new_at, before, after in reversed(entries):
        restored = restored[:new_at] + before + restored[new_at + len(after):]
    if pin(restored) != ORIGINAL:
        raise ValueError('deadline diagnostics inverse does not restore the complete original')
    replay = restored
    for old_at, new_at, before, after in reversed(entries):
        if replay[old_at:old_at + len(before)] != before:
            raise ValueError('deadline diagnostics original splice differs')
        replay = replay[:old_at] + after + replay[old_at + len(before):]
    if replay != raw:
        raise ValueError('deadline diagnostics forward replay differs')
    return restored


def admit(name, raw, expected_sha256, provenance):
    if name != PATH or expected_sha256 != ORIGINAL['sha256']:
        raise ValueError('deadline diagnostics cannot change an original source authority')
    restore(raw, provenance)
    return {'path': PATH, 'original': dict(ORIGINAL), 'current': dict(CURRENT),
            'provenance_path': FIXTURE, 'provenance_sha256': FIXTURE_SHA256,
            'exact_splices': 2, 'complete_original_inverse_verified': True,
            'complete_current_forward_replay_verified': True,
            'original_deadline_seconds': 5, 'original_native_budget_ms': 1,
            'production_source_exception': False}
