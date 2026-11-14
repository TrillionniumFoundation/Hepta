"""Exact source-version projection for one historical assertion.

This is a static, unexecuted integration helper. It never supplies bytes to
current authoring, HIA assembly, compilation, or installed image selection.
The historical author read is an explicit version projection in test_01;
all original assertions and the other Source/Native methods stay intact.
"""
from hashlib import sha256
import json

FIXTURE_BYTES = 4779
FIXTURE_SHA256 = 'd2a8110b14fd4bbb7de3633e631bf65e43ff4f209eb26f664c91ba514a7f5ff9'
SCHEMA = 'hia.json-wire.leaf-width-three-read-author-inverse.v1'

def _unique_pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError('duplicate author inverse field')
        result[key] = value
    return result

def _matches(raw, pin):
    return (type(pin.get('bytes')) is int
            and len(raw) == pin['bytes']
            and sha256(raw).hexdigest() == pin['sha256'])

def project_u32_history_author(actual_raw, fixture_raw):
    """Return exact pre-width-inlining author bytes for the historical inverse.

    The caller must retain and bind actual_raw separately and must continue to
    re-emit and check the current assembly from the actual candidate author.
    Unknown, partially applied, mixed, or extended revisions are refused.
    """
    if type(actual_raw) is not bytes or type(fixture_raw) is not bytes:
        raise TypeError('author and inverse fixture must be exact bytes')
    if (len(fixture_raw) != FIXTURE_BYTES
            or sha256(fixture_raw).hexdigest() != FIXTURE_SHA256):
        raise ValueError('fixed author inverse fixture identity differs')
    fixture = json.loads(fixture_raw, object_pairs_hook=_unique_pairs)
    if fixture['schema'] != SCHEMA:
        raise ValueError('author inverse schema differs')
    if _matches(actual_raw, fixture['base']):
        return actual_raw
    if not _matches(actual_raw, fixture['candidate']):
        raise ValueError('unknown or mixed JSON wire author revision')
    text = actual_raw.decode('utf-8')
    begin, end = fixture['function']['begin'], fixture['function']['end']
    if text.count(begin) != 1 or text.count(end) != 1:
        raise ValueError('author function boundaries are ambiguous')
    first = text.index(begin)
    last = text.index(end, first + len(begin))
    current = text[first:last]
    if not _matches(current.encode('utf-8'), fixture['function']['candidate_body']):
        raise ValueError('candidate leaf function differs')
    for hunk in reversed(fixture['hunks']):
        if (type(hunk['expected_occurrences_in_function']) is not int
                or hunk['expected_occurrences_in_function'] != 1
                or current.count(hunk['new']) != 1):
            raise ValueError('exact author inverse hunk differs')
        current = current.replace(hunk['new'], hunk['old'], 1)
    if not _matches(current.encode('utf-8'), fixture['function']['old_body']):
        raise ValueError('whole historical leaf function differs')
    projected = (text[:first] + current + text[last:]).encode('utf-8')
    if not _matches(projected, fixture['base']):
        raise ValueError('whole historical author inverse differs')
    return projected
