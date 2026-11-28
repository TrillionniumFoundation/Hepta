"""Exact native-cold custody addition before the unchanged component history."""
from hashlib import sha256
import json
from pathlib import Path

SOURCE = 'tests/hia_component_native_cold_history.py'
FIXTURE = 'tests/fixtures/hia_component_native_cold_history_20261128.json'
FIXTURE_PIN = {'bytes': 3832, 'sha256': 'be680997e27d747594ef848c2a805ce45738c938df6083b91b0cfe8746cdd57b'}
PATH = 'tools/build_hia_service_context.py'
CURRENT = {'bytes': 5736, 'sha256': '16f50573777652d5412fb4a381ae9a120f7e06d0e55b4ba354f1d3ad2f7245a0'}
PREDECESSOR = {'bytes': 4722, 'sha256': 'a075b2f5df0a83b49e96d4f0966e0f223a4dabc33fae3eeca3b1742c99c8c71e'}


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def predecessor(name, raw, *, root, take=Path.read_bytes):
    """Admit a physical successor and recover its complete component predecessor."""
    if name != PATH or pin(raw) != CURRENT:
        return raw
    if type(raw) is not bytes:
        raise ValueError('native-cold component history requires immutable source bytes')
    root = Path(root)
    captured = {}

    def capture(path):
        value = take(path)
        if type(value) is not bytes or path in captured and captured[path] != value:
            raise ValueError('native-cold component source changed between captures')
        captured[path] = value
        return value

    try:
        if capture(root / name) != raw:
            raise ValueError('native-cold component source differs from physical root')
        if capture(root / SOURCE) != Path(__file__).read_bytes():
            raise ValueError('native-cold component loaded helper differs from physical root')
        authority = capture(root / FIXTURE)
        if pin(authority) != FIXTURE_PIN:
            raise ValueError('fixed native-cold component authority differs')
        value = json.loads(authority)
        if (value['schema'] != 'hepta.hia.component-native-cold-source-history.v1'
                or set(value['files']) != {PATH}):
            raise ValueError('native-cold component historical scope differs')
        record = value['files'][name]
        if record['current'] != CURRENT or record['predecessor'] != PREDECESSOR:
            raise ValueError('native-cold component whole-source identities differ')
        component = value['component_authority']
        physical_component = capture(root / component['path'])
        if sha256(physical_component).hexdigest() != component['sha256']:
            raise ValueError('original component authority differs')
        previous_record = json.loads(physical_component)['files'][name]
        if {'bytes': previous_record['new_bytes'],
                'sha256': previous_record['new_sha256']} != PREDECESSOR:
            raise ValueError('native-cold predecessor is not the original component source')

        pieces, current_end, prior_end = [], 0, 0
        for change in record['splices']:
            at, prior_at = change['current_offset'], change['predecessor_offset']
            before = bytes.fromhex(change['current_hex'])
            after = bytes.fromhex(change['predecessor_hex'])
            gap = at - current_end
            if (type(at) is not int or type(prior_at) is not int or gap < 0
                    or prior_at != prior_end + gap or before == after
                    or raw[at:at + len(before)] != before):
                raise ValueError('native-cold component exact inverse differs')
            pieces.extend((raw[current_end:at], after))
            current_end, prior_end = at + len(before), prior_at + len(after)
        prior = b''.join((*pieces, raw[current_end:]))
        if pin(prior) != PREDECESSOR:
            raise ValueError('complete native-cold component predecessor differs')
        replay = prior
        for change in reversed(record['splices']):
            at = change['predecessor_offset']
            before = bytes.fromhex(change['current_hex'])
            after = bytes.fromhex(change['predecessor_hex'])
            if replay[at:at + len(after)] != after:
                raise ValueError('native-cold component forward splice differs')
            replay = replay[:at] + before + replay[at + len(after):]
        if replay != raw:
            raise ValueError('complete native-cold component forward replay differs')
        return prior
    finally:
        for path, value in captured.items():
            if take(path) != value:
                raise ValueError('native-cold component terminal physical reread differs')
