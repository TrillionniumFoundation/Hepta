"""Exact source history for strict native-cold selection in seven caller qualifiers.

Only the two fixed selection splices are reversed. Every prior full-file
inventory, method, assertion, budget and terminal-capture check remains active.
This data-only helper grants source-history admission, never caller execution.
"""
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = 'tests/fixtures/hia_cold_caller_selection_history_v1.json'
FIXTURE_SHA256 = 'a9c3182285be62898e01b1a836a0ac7a471dbf6a286b0ca0dccdc4b70eb859fc'
EXPECTED = {
    "tools/qualify_hia_cost_ledger_callers.py": {
        "old": {
            "bytes": 10516,
            "sha256": "30842806afddf8e493cc968740e5aa947dc906d041a466ceab8c6f7e0d34e844"
        },
        "new": {
            "bytes": 10465,
            "sha256": "bd9682ab67948b2632523b55d595becfed7fe1f860b2544bd8449f1c052a20a1"
        }
    },
    "tools/qualify_hia_emission_callers.py": {
        "old": {
            "bytes": 10894,
            "sha256": "47aa06e0ecbc5227b09e0f3429087173637e9d429af6acc7014fa203178a806c"
        },
        "new": {
            "bytes": 10831,
            "sha256": "fd676590a944d191d8d06eff1b421ccb183c3d06c43d96445c6f92461453d90d"
        }
    },
    "tools/qualify_hia_evaluation_callers.py": {
        "old": {
            "bytes": 15126,
            "sha256": "7943e4d26b8ee83c65982f84e317579c1d687216e5fd7151259a67a617b11d6b"
        },
        "new": {
            "bytes": 15063,
            "sha256": "29c40723460571b2d336e6f23adec005b3f4a89aead62c826efb391d9de762d9"
        }
    },
    "tools/qualify_hia_native_build_admission_callers.py": {
        "old": {
            "bytes": 11099,
            "sha256": "e0c09818985203b1308b2ea53277b834ae429181d1bec54a684bd00cbb47a611"
        },
        "new": {
            "bytes": 11036,
            "sha256": "eece82a138051c392a409c54850997e4104371b3588e8365b0ae3b6b2227d864"
        }
    },
    "tools/qualify_hia_service_context_callers.py": {
        "old": {
            "bytes": 11944,
            "sha256": "c7825a2724acb1d7137a8ad1c24aac0f865c227c5b2c27bf4ea52f05c2d8d863"
        },
        "new": {
            "bytes": 11881,
            "sha256": "c4de90f655d57d0036313f5a454863bfd85b40adfbe73a16efb16ce13eff2d6f"
        }
    },
    "tools/qualify_hia_store_artifact_profile_callers.py": {
        "old": {
            "bytes": 14932,
            "sha256": "4e47769f3c67a43170773aa39eb4b461af8fcc32eb513708a0cbf932b6b406ec"
        },
        "new": {
            "bytes": 14867,
            "sha256": "59e7e38e653a47a4c0780c95f2d073cfa2e714f8e8001c13cf640a7d255857f9"
        }
    },
    "tools/qualify_hia_store_lifecycle_callers.py": {
        "old": {
            "bytes": 10143,
            "sha256": "24b530be08ed7b237b22b6f8b66a07724bdb4ea6fc4f7963f9881791e64c59c9"
        },
        "new": {
            "bytes": 10080,
            "sha256": "2d49a7ae102d1ac11015a394a4bdf5cb71a3642b4d6818755097a699e65c3a04"
        }
    }
}

def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('caller selection source must be exact bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}

def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate caller selection history member')
        value[key] = item
    return value

def reviewed(name, raw, *, root=None, take=Path.read_bytes):
    """Restore only a fixed complete successor and retain its explicit proof."""
    actual = pin(raw)
    expected = EXPECTED.get(name)
    if expected is None or actual != expected['new']:
        # Prior complete-file authorities retain responsibility for every other
        # historical version and reject unknown bytes. No exception is granted.
        return raw, None
    root = ROOT if root is None else Path(root)
    frozen = take(root / FIXTURE)
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('caller selection history fixture changed')
    value = json.loads(frozen, object_pairs_hook=_pairs)
    if (set(value) != {'schema', 'predecessor_commit', 'source_kind',
                      'whole_native_delivery_qualified', 'files'}
            or value['schema'] != 'hepta.hia.native-cold-caller-selection-history.v1'
            or value['predecessor_commit'] != 'b332b57fca954ef4ac908aef7431c039cecad09c'
            or value['source_kind'] != 'HOST_QUALIFIER_SELECTION_ONLY'
            or value['whole_native_delivery_qualified'] is not False
            or set(value['files']) != set(EXPECTED)):
        raise ValueError('caller selection history scope differs')
    record = value['files'][name]
    if (set(record) != {'old', 'new', 'hunks'}
            or record['old'] != expected['old'] or record['new'] != expected['new']
            or type(record['hunks']) is not list or len(record['hunks']) != 2):
        raise ValueError('caller selection complete fixed source pins differ')
    pieces, replay, old_at, new_at = [], [], 0, 0
    entries = []
    for item in record['hunks']:
        if (type(item) is not dict
                or set(item) != {'old_offset', 'new_offset', 'old_hex', 'new_hex'}):
            raise ValueError('caller selection splice shape differs')
        old_offset, new_offset = item['old_offset'], item['new_offset']
        if (type(old_offset) is not int or type(new_offset) is not int
                or old_offset < old_at or new_offset < new_at
                or old_offset - old_at != new_offset - new_at):
            raise ValueError('caller selection splice offsets differ')
        old, new = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if (not old or not new or old == new
                or old.hex() != item['old_hex'] or new.hex() != item['new_hex']
                or raw[new_offset:new_offset + len(new)] != new):
            raise ValueError('caller selection fixed splice bytes differ')
        pieces.extend((raw[new_at:new_offset], old))
        entries.append((old_offset, new_offset, old, new))
        old_at, new_at = old_offset + len(old), new_offset + len(new)
    original = b''.join((*pieces, raw[new_at:]))
    if pin(original) != expected['old']:
        raise ValueError('caller selection did not restore its complete predecessor')
    end = 0
    for old_offset, new_offset, old, new in entries:
        if original[old_offset:old_offset + len(old)] != old:
            raise ValueError('caller selection forward source differs')
        replay.extend((original[end:old_offset], new))
        end = old_offset + len(old)
    if b''.join((*replay, original[end:])) != raw or take(root / FIXTURE) != frozen:
        raise ValueError('caller selection forward replay or terminal fixture differs')
    return original, {
        'path': name, 'old': dict(expected['old']), 'new': dict(expected['new']),
        'fixture': {'path': FIXTURE, 'bytes': len(frozen), 'sha256': FIXTURE_SHA256},
        'exact_selection_splices': 2, 'complete_predecessor_restored': True,
        'complete_successor_replayed': True, 'original_methods_budgets_order_unchanged': True,
        'whole_native_delivery_qualified': False,
    }

def predecessor(name, raw, *, root=None, take=Path.read_bytes):
    return reviewed(name, raw, root=root, take=take)[0]

def bind_adjustment(entry, raw, proof):
    """Bind a previously admitted original source to the actual new whole file."""
    if proof is None:
        return entry
    name = proof['path']
    expected = EXPECTED[name]
    prior = {'bytes': entry['current_bytes'], 'sha256': entry['current_sha256']}
    if (entry.get('path') != name
            or pin(raw) != expected['new'] or proof['old'] != expected['old']
            or proof['new'] != expected['new']
            or prior not in (expected['old'], expected['new'])):
        raise ValueError('caller selection source adjustment lost its admitted predecessor')
    return {**entry, 'current_bytes': len(raw), 'current_sha256': sha256(raw).hexdigest(),
            'native_cold_selection_source': proof}
