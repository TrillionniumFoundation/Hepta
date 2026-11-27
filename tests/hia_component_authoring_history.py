"""Exact predecessor bytes for the host component-custody migration.

This data-only reader changes no original observation or native authority.
Existing historical readers still validate the complete predecessor against
their own fixed pins after these five reviewed builder edits are reversed.
"""
from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = 'tests/fixtures/hia_component_authoring_successor_v1.json'
FIXTURE_SHA256 = '5aa32081d30e10ef29edec087c209031b21e617d9d00dcdb6338f404b01f2f5d'


def _records():
    raw = (ROOT / FIXTURE).read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('fixed component authoring history differs')
    value = json.loads(raw)
    if (value['schema'] != 'hepta.hia.component-authoring-successor.v1'
            or value['predecessor_commit'] != '060ce11be28009e3769633bf43aeee16aa9a5414'
            or len(value['files']) != 28):
        raise ValueError('component authoring history scope differs')
    return value['files']


def predecessor(name, raw):
    """Unwrap the exact new builder; leave every other input to its prior gate."""
    record = _records().get(name)
    if record is None or sha256(raw).hexdigest() != record['new_sha256']:
        return raw
    if len(raw) != record['new_bytes']:
        raise ValueError('component authoring successor length differs')
    pieces, new_at, old_at = [], 0, 0
    for hunk in record['hunks']:
        before, after = bytes.fromhex(hunk['old_hex']), bytes.fromhex(hunk['new_hex'])
        offset = hunk['new_offset']
        gap = offset - new_at
        if (type(offset) is not int or type(hunk['old_offset']) is not int
                or gap < 0 or hunk['old_offset'] != old_at + gap or before == after
                or raw[offset:offset + len(after)] != after):
            raise ValueError('component authoring exact source splice differs')
        pieces.extend((raw[new_at:offset], before))
        new_at, old_at = offset + len(after), hunk['old_offset'] + len(before)
    original = b''.join((*pieces, raw[new_at:]))
    if (len(original) != record['old_bytes']
            or sha256(original).hexdigest() != record['old_sha256']):
        raise ValueError('complete component authoring predecessor differs')
    return original
