"""Exact current six-result assertion, with the complete prior caller retained.

Data only: no product, builder, generator, test or oracle imports. Each call
binds the requested root's physical caller and fixed relation before returning
the complete prior bytes. It grants no exception for any other source.
"""
from hashlib import sha256
import json
from pathlib import Path

PATH = 'tests/test_hia_agent_native_tools.py'
FIXTURE = 'tests/fixtures/hia_native_result_caller_history_v1.json'
FIXTURE_SHA256 = 'dccd8c04824fdaa3ac7cf638fd487622a8ecfd198236cf0108ef8dc2edb10130'
ORIGINAL = {'bytes': 47052, 'sha256': '64462e8735d8be3838396808dc05391e4437b2dba093fcc265468df6abb4cb70'}
CURRENT = {'bytes': 47052, 'sha256': '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2'}
DEPENDENCIES = ('tools/hia_native_result_caller_history.py', FIXTURE)


def _pin(raw):
    if type(raw) is not bytes:
        raise ValueError('native result caller requires physical bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def unwrap(root, name, raw, *, take=Path.read_bytes):
    """Return only the fixed complete predecessor; current capture stays raw.

    Callers keep their older source-admission/reader checks after this explicit
    inverse. Both supported whole files are checked; unknown bytes are refused.
    """
    if type(name) is not str or name != PATH:
        raise ValueError('native result relation has no authority for this path')
    root = Path(root)
    physical = take(root / PATH)
    if physical != raw or _pin(raw) not in (CURRENT, ORIGINAL):
        raise ValueError('native result caller is not the exact physical whole file')
    frozen = take(root / FIXTURE)
    if _pin(frozen)['sha256'] != FIXTURE_SHA256:
        raise ValueError('native result caller fixed relation changed')
    value = json.loads(frozen)
    if (type(value) is not dict
            or value.get('schema') != 'hepta.hia.native-result-caller-history.v1'
            or value.get('path') != PATH or value.get('original_source') != ORIGINAL
            or value.get('current_source') != CURRENT
            or value.get('splices') != [{'at': 4929, 'old_hex': '33', 'new_hex': '36'}]):
        raise ValueError('native result relation scope differs')
    if _pin(raw) == CURRENT:
        at = 4929
        if raw[at:at + 1] != b'6':
            raise ValueError('native result successor splice differs')
        restored = raw[:at] + b'3' + raw[at + 1:]
        if _pin(restored) != ORIGINAL or restored[:at] + b'6' + restored[at + 1:] != raw:
            raise ValueError('native result inverse did not restore the complete caller')
    else:
        restored = raw
    if take(root / FIXTURE) != frozen or take(root / PATH) != physical:
        raise ValueError('native result caller or fixed relation changed at terminal')
    return restored
