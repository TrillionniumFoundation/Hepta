"""Exact source continuity for explicit reference-only installation tests."""
from hashlib import sha256
import json
from pathlib import Path

FIXTURE = 'tests/fixtures/hia_reference_profile_successors.json'
FIXTURE_SHA256 = 'f614d56db2f1ff703ec0e6517b5950dfa24b71093eea4f89c5d7fd770f4a0a61'


def records():
    raw = (Path(__file__).resolve().parents[1] / FIXTURE).read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('the explicit reference-profile source relation differs')
    value = json.loads(raw)
    if value['schema'] != 'hepta.hia.reference-profile-successors.v1':
        raise ValueError('the explicit reference-profile source schema differs')
    return value['files']


def _pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def restore(data, record):
    if _pin(data) != record['current']:
        raise ValueError('the complete current reference-profile source differs')
    prior = bytearray()
    end = 0
    for change in record['splices']:
        start = change['offset']
        before, after = (change[key].encode() for key in ('before', 'after'))
        current = end + start - len(prior)
        if start < len(prior) or current < end or data[current:current + len(after)] != after:
            raise ValueError('the reference-profile source differs at its reviewed splice')
        prior.extend(data[end:current]); prior.extend(before)
        end = current + len(after)
    prior.extend(data[end:])
    prior = bytes(prior)
    if _pin(prior) != record['original']:
        raise ValueError('the complete original reference-profile source differs')
    replay = bytearray()
    end = 0
    for change in record['splices']:
        start = change['offset']
        before, after = (change[key].encode() for key in ('before', 'after'))
        if start < end or prior[start:start + len(before)] != before:
            raise ValueError('the original reference-profile source differs at its reviewed splice')
        replay.extend(prior[end:start]); replay.extend(after)
        end = start + len(before)
    replay.extend(prior[end:])
    if bytes(replay) != data or _pin(replay) != record['current']:
        raise ValueError('the complete reference-profile forward replay differs')
    return prior


def predecessor(name, data):
    record = records().get(name)
    if record is not None and _pin(data) == record['current']:
        return restore(data, record)
    return data
