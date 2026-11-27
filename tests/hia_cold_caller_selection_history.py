"""Exact source history for strict native-cold selection in seven caller qualifiers.

The fixed v1 selection relation and separate immutable v2/v3 source-admission
relations are reversed in order. Every prior full-file inventory, method,
assertion, budget and terminal-capture check remains active.
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

def _review_selection(name, raw, *, root=None, take=Path.read_bytes):
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


INTEGRATED_FIXTURE = 'tests/fixtures/hia_cold_caller_selection_history_v3.json'
INTEGRATED_FIXTURE_PIN = {
    "bytes": 27749,
    "sha256": "6a2d1a5881b2bc4ca54901c15fd37e0770cae55a86244657682a3f5a53dd37d5"
}
INTEGRATED_EXPECTED = {
    "tools/qualify_hia_cost_ledger_callers.py": {
        "old": {
            "bytes": 10465,
            "sha256": "bd9682ab67948b2632523b55d595becfed7fe1f860b2544bd8449f1c052a20a1"
        },
        "new": {
            "bytes": 14304,
            "sha256": "e196780a77f544d4563b60af646383616045eb5ecda4e912c236e4ba1ec46f60"
        }
    },
    "tools/qualify_hia_service_context_callers.py": {
        "old": {
            "bytes": 11881,
            "sha256": "c4de90f655d57d0036313f5a454863bfd85b40adfbe73a16efb16ce13eff2d6f"
        },
        "new": {
            "bytes": 15720,
            "sha256": "a91d034b5f556e5918a51d74d7fc71b83d2d681360eea24f895a61dad718f8df"
        }
    },
    "tools/qualify_hia_store_lifecycle_callers.py": {
        "old": {
            "bytes": 10080,
            "sha256": "2d49a7ae102d1ac11015a394a4bdf5cb71a3642b4d6818755097a699e65c3a04"
        },
        "new": {
            "bytes": 14213,
            "sha256": "39ef0387ce4a6883432f1b3d616a49f638ab800fc624739b4d24414a696761c1"
        }
    }
}
INTEGRATED_METADATA = {
    "schema": "hepta.hia.integrated-caller-source-admission-history.v3",
    "predecessor_commit": "241551d273c98561225263750ba98d11d93bf81c",
    "source_commits": {
        "integrated_admission": "dd8f96ca7f2fa97f7711dc96dba5d5f43fbad2a4",
        "native_result_assertion": "546c7fe9db30f493400929fc6d7fdc6e500d7591",
        "prior_history": "fddafe612d75e84232c6b35b7503d1c2d7efc5ce"
    },
    "source_kind": "HOST_QUALIFIER_SOURCE_ADMISSION_ONLY",
    "original_callers": {
        "tools/qualify_hia_cost_ledger_callers.py": 81,
        "tools/qualify_hia_service_context_callers.py": 50,
        "tools/qualify_hia_store_lifecycle_callers.py": 50
    },
    "whole_native_delivery_qualified": False
}
LEGACY_INTEGRATED_FIXTURE = 'tests/fixtures/hia_cold_caller_selection_history_v2.json'
LEGACY_INTEGRATED_FIXTURE_PIN = {
    'bytes': 33797,
    'sha256': '4746d645ffb37c63f7fb7cb20eaa3c884d6e1a7b364da5b97f31dc162e1f31f7',
}
LEGACY_INTEGRATED_EXPECTED = {
    "tools/qualify_hia_cost_ledger_callers.py": {
        "old": {
            "bytes": 10465,
            "sha256": "bd9682ab67948b2632523b55d595becfed7fe1f860b2544bd8449f1c052a20a1"
        },
        "new": {
            "bytes": 13175,
            "sha256": "e9acf21baa7a49bbf54fceb0ade491d08ab5ba4c61fb428883fb9e605fdd85ba"
        }
    },
    "tools/qualify_hia_service_context_callers.py": {
        "old": {
            "bytes": 11881,
            "sha256": "c4de90f655d57d0036313f5a454863bfd85b40adfbe73a16efb16ce13eff2d6f"
        },
        "new": {
            "bytes": 14591,
            "sha256": "1e3616ea50a545ee510dd21c7a4ba71a347ffa218eeb5eac7665ab944321327a"
        }
    },
    "tools/qualify_hia_store_lifecycle_callers.py": {
        "old": {
            "bytes": 10080,
            "sha256": "2d49a7ae102d1ac11015a394a4bdf5cb71a3642b4d6818755097a699e65c3a04"
        },
        "new": {
            "bytes": 13084,
            "sha256": "8564aa10ae521d3cd3ead9d0a4b3bdda97167cfd07c869d0c75c991479a71a6c"
        }
    }
}
LEGACY_INTEGRATED_METADATA = {
    "schema": "hepta.hia.integrated-caller-source-admission-history.v2",
    "predecessor_commit": "241551d273c98561225263750ba98d11d93bf81c",
    "successor_commit": "dd8f96ca7f2fa97f7711dc96dba5d5f43fbad2a4",
    "source_kind": "HOST_QUALIFIER_SOURCE_ADMISSION_ONLY",
    "original_callers": {
        "tools/qualify_hia_cost_ledger_callers.py": 81,
        "tools/qualify_hia_service_context_callers.py": 50,
        "tools/qualify_hia_store_lifecycle_callers.py": 50
    },
    "whole_native_delivery_qualified": False
}
INTEGRATED_CALLERS = {
    'tools/qualify_hia_cost_ledger_callers.py': 81,
    'tools/qualify_hia_service_context_callers.py': 50,
    'tools/qualify_hia_store_lifecycle_callers.py': 50,
}
INVERSE_HELPER = 'tools/hia_frozen_component_sources.py'
INVERSE_HELPER_PIN = {
    'bytes': 15561,
    'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774',
}


EVALUATION_CAPTURE_PATH = 'tools/qualify_hia_evaluation_callers.py'
EVALUATION_CAPTURE_FIXTURE = 'tests/fixtures/hia_evaluation_caller_capture_history_v1.json'
EVALUATION_CAPTURE_FIXTURE_PIN = {
    'bytes': 5804, 'sha256': '12ad0d799e09f93eddab590ed0d5e68a5053d44a1406a5f7bc2856a98d0fb157',
}
EVALUATION_CAPTURE_EXPECTED = {
    "tools/qualify_hia_evaluation_callers.py": {
        "old": {
            "bytes": 15063,
            "sha256": "29c40723460571b2d336e6f23adec005b3f4a89aead62c826efb391d9de762d9"
        },
        "new": {
            "bytes": 15168,
            "sha256": "8a0f66a01385fce272205551af0722c31dc92197346f86e757693565d7952757"
        }
    },
    "tests/hia_installed_distribution_history.py": {
        "old": {
            "bytes": 4355,
            "sha256": "8a69299935e247a8bab59c6c030d9356110c709c196cc187f986eef5df19613d"
        },
        "new": {
            "bytes": 5991,
            "sha256": "383bb1438318495782d0112349fe1be7284b7034093949f394cf658aba787fdb"
        }
    }
}


LEGACY_EVALUATION_CAPTURE_EXPECTED = EVALUATION_CAPTURE_EXPECTED
EVALUATION_CAPTURE_EXPECTED = {
    name: {version: dict(identity) for version, identity in pair.items()}
    for name, pair in LEGACY_EVALUATION_CAPTURE_EXPECTED.items()
}
EVALUATION_CAPTURE_EXPECTED[EVALUATION_CAPTURE_PATH]['new'] = {
    'bytes': 16120, 'sha256': '3360ffaa55764e6b521b954ec9aa6471dd7a08c9f76c896eb439df789711e4ec',
}
EVALUATION_DOMAINS_FIXTURE = 'tests/fixtures/hia_evaluation_original_source_domains_v1.json'
EVALUATION_DOMAINS_FIXTURE_PIN = {
    'bytes': 3187, 'sha256': 'ce9b082ed9d9496b5939767687df89e2c550b7d28419fa8f77f16626037bfe33',
}


def _evaluation_capture_versions(version):
    if type(version) is not int or version not in (1, 2):
        raise ValueError('unknown evaluation source-capture history version')
    return (EVALUATION_CAPTURE_EXPECTED if version == 2
            else LEGACY_EVALUATION_CAPTURE_EXPECTED)


def _evaluation_capture_proof(version=2):
    expected = _evaluation_capture_versions(version)
    proof = {
        'schema': 'hepta.hia.evaluation-caller-capture-source-review.v' + str(version),
        'path': EVALUATION_CAPTURE_PATH,
        'old': dict(expected[EVALUATION_CAPTURE_PATH]['old']),
        'new': dict(expected[EVALUATION_CAPTURE_PATH]['new']),
        'fixture': {'path': EVALUATION_CAPTURE_FIXTURE, **EVALUATION_CAPTURE_FIXTURE_PIN},
        'complete_pair': {path: {version: dict(identity) for version, identity in pair.items()}
                          for path, pair in expected.items()},
        'original_complete_callers': 81,
        'complete_predecessor_restored': True,
        'complete_successor_replayed': True,
        'physical_capture_rewritten': False,
        'terminal_reread_identical': True,
        'whole_native_delivery_qualified': False,
    }
    if version == 2:
        proof['original_source_domains'] = {
            'fixture': {'path': EVALUATION_DOMAINS_FIXTURE, **EVALUATION_DOMAINS_FIXTURE_PIN},
            'complete_predecessor': dict(LEGACY_EVALUATION_CAPTURE_EXPECTED[EVALUATION_CAPTURE_PATH]['new']),
            'complete_current': dict(EVALUATION_CAPTURE_EXPECTED[EVALUATION_CAPTURE_PATH]['new']),
            'prior_projection_is_physical_source': False,
            'original_sources_gain_new_dependencies': False,
        }
    return proof


def _evaluation_capture_predecessor(name, raw, root, take):
    version = next((number for number in (2, 1)
                    if name == EVALUATION_CAPTURE_PATH
                    and pin(raw) == _evaluation_capture_versions(number)[name]['new']), None)
    if version is None:
        return raw, None, {}
    expected_pair = _evaluation_capture_versions(version)
    saved = {}
    def capture(selected):
        value = take(root / selected)
        if selected in saved and saved[selected] != value:
            raise ValueError('evaluation caller capture history changed during read')
        saved[selected] = value
        return value
    for path, expected in expected_pair.items():
        physical = capture(path)
        if pin(physical) != expected['new'] or path == name and physical != raw:
            raise ValueError('evaluation caller capture pair is mixed or not physical')
    frozen = capture(EVALUATION_CAPTURE_FIXTURE)
    engine = capture(INVERSE_HELPER)
    if pin(frozen) != EVALUATION_CAPTURE_FIXTURE_PIN or pin(engine) != INVERSE_HELPER_PIN:
        raise ValueError('evaluation caller capture history authority differs')
    value = json.loads(frozen, object_pairs_hook=_pairs)
    if (type(value) is not dict or set(value) != {'schema', 'predecessor_commit',
            'original_fixed_fixtures_modified', 'historical_projection_is_physical_source', 'files'}
            or value['schema'] != 'hepta.hia.evaluation-caller-capture-history.v1'
            or value['predecessor_commit'] != '4dd6c9703b5d3b5fc5aeae91cc45c6a9f2baacda'
            or value['original_fixed_fixtures_modified'] is not False
            or value['historical_projection_is_physical_source'] is not False
            or type(value['files']) is not dict
            or set(value['files']) != set(LEGACY_EVALUATION_CAPTURE_EXPECTED)
            or LEGACY_EVALUATION_CAPTURE_EXPECTED[name]['old'] != EXPECTED[name]['new']):
        raise ValueError('evaluation caller capture history fixed scope differs')
    from tools import hia_frozen_component_sources as inverse
    if Path(inverse.__file__).read_bytes() != engine:
        raise ValueError('evaluation caller capture imported another inverse engine')
    paired = {path: saved[path] for path in expected_pair}
    if version == 2:
        domains = capture(EVALUATION_DOMAINS_FIXTURE)
        if pin(domains) != EVALUATION_DOMAINS_FIXTURE_PIN:
            raise ValueError('evaluation original-domain source authority differs')
        domain = json.loads(domains, object_pairs_hook=_pairs)
        if (type(domain) is not dict or set(domain) != {
                'schema', 'predecessor_commit', 'original_fixed_fixtures_modified',
                'historical_projection_is_physical_source', 'files'}
                or domain['schema'] != 'hepta.hia.evaluation-original-source-domains-history.v1'
                or domain['predecessor_commit'] != '0751a6df47c46090de2ff1e303fed8d82a89de47'
                or domain['original_fixed_fixtures_modified'] is not False
                or domain['historical_projection_is_physical_source'] is not False
                or type(domain['files']) is not dict
                or set(domain['files']) != {EVALUATION_CAPTURE_PATH}):
            raise ValueError('evaluation original-domain history scope differs')
        paired[name] = inverse.history_inverse(paired[name], domain['files'][name],
            LEGACY_EVALUATION_CAPTURE_EXPECTED[name]['new'])
    prior = {}
    for path, expected in LEGACY_EVALUATION_CAPTURE_EXPECTED.items():
        prior[path] = inverse.history_inverse(paired[path], value['files'][path], expected['old'])
    return prior[name], _evaluation_capture_proof(version), saved


def current_pin(name):
    """Return an explicitly frozen complete current qualifier identity."""
    if name == EVALUATION_CAPTURE_PATH:
        return dict(EVALUATION_CAPTURE_EXPECTED[name]['new'])
    return dict(INTEGRATED_EXPECTED.get(name, EXPECTED[name])['new'])

def _integrated_version(version):
    if type(version) is not int or version not in (2, 3):
        raise ValueError('unknown integrated caller history version')
    if version == 3:
        return (INTEGRATED_FIXTURE, INTEGRATED_FIXTURE_PIN,
                INTEGRATED_EXPECTED, INTEGRATED_METADATA)
    return (LEGACY_INTEGRATED_FIXTURE, LEGACY_INTEGRATED_FIXTURE_PIN,
            LEGACY_INTEGRATED_EXPECTED, LEGACY_INTEGRATED_METADATA)

def _integrated_proof(name, version=3):
    fixture, fixture_pin, versions, _ = _integrated_version(version)
    expected = versions[name]
    return {
        'schema': 'hepta.hia.integrated-caller-source-admission-review.v' + str(version),
        'path': name,
        'old': dict(expected['old']), 'new': dict(expected['new']),
        'fixture': {'path': fixture, **fixture_pin},
        'inverse_helper': {'path': INVERSE_HELPER, **INVERSE_HELPER_PIN},
        'original_caller_count': INTEGRATED_CALLERS[name],
        'complete_predecessor_restored': True, 'complete_successor_replayed': True,
        'terminal_reread_identical': True, 'whole_native_delivery_qualified': False,
    }

def _integrated_predecessor(name, raw, root, take):
    actual = pin(raw)
    version = next((number for number in (3, 2)
                    if name in _integrated_version(number)[2]
                    and actual == _integrated_version(number)[2][name]['new']), None)
    if version is None:
        return raw, None, {}
    fixture_name, fixture_pin, versions, metadata = _integrated_version(version)
    expected = versions[name]
    saved = {}
    def capture(selected):
        value = take(root / selected)
        if selected in saved and value != saved[selected]:
            raise ValueError('integrated caller history source changed during capture')
        saved[selected] = value
        return value
    if capture(name) != raw:
        raise ValueError('integrated caller history differs from selected-root source')
    frozen, helper = capture(fixture_name), capture(INVERSE_HELPER)
    if pin(frozen) != fixture_pin or pin(helper) != INVERSE_HELPER_PIN:
        raise ValueError('integrated caller history fixed fixture or inverse helper differs')
    value = json.loads(frozen, object_pairs_hook=_pairs)
    if (type(value) is not dict or set(value) != set(metadata) | {'files'}
            or {key: value[key] for key in metadata} != metadata
            or value['original_callers'] != INTEGRATED_CALLERS
            or value['whole_native_delivery_qualified'] is not False
            or type(value['files']) is not dict
            or set(value['files']) != set(versions)):
        raise ValueError('integrated caller history scope differs')
    record = value['files'][name]
    if (type(record) is not dict or set(record) != {'old', 'new', 'hunks'}
            or record['old'] != expected['old'] or record['new'] != expected['new']
            or expected['old'] != EXPECTED[name]['new']):
        raise ValueError('integrated caller history fixed source chain differs')
    from tools import hia_frozen_component_sources as inverse
    if Path(inverse.__file__).read_bytes() != helper:
        raise ValueError('integrated caller history imported another inverse helper')
    selected = inverse.history_inverse(raw, {
        'old_bytes': record['old']['bytes'], 'old_sha256': record['old']['sha256'],
        'new_bytes': record['new']['bytes'], 'new_sha256': record['new']['sha256'],
        'hunks': record['hunks'],
    }, expected['old'])
    return selected, _integrated_proof(name, version), saved

def reviewed(name, raw, *, root=None, take=Path.read_bytes):
    """Restore exact current admissions before the immutable v1 selection."""
    pin(raw)
    root = ROOT if root is None else Path(root)
    selected, evaluation, evaluation_saved = _evaluation_capture_predecessor(name, raw, root, take)
    selected, integrated, saved = _integrated_predecessor(name, selected, root, take)
    original, proof = _review_selection(name, selected, root=root, take=take)
    if integrated is None and evaluation is None:
        return original, proof
    if proof is None or pin(original) != EXPECTED[name]['old']:
        raise ValueError('integrated caller history lost the original full-file authority')
    if integrated is not None and evaluation is not None:
        raise ValueError('distinct current caller history domains overlap')
    for path, captured in {**saved, **evaluation_saved}.items():
        if take(root / path) != captured:
            raise ValueError('integrated caller history terminal source capture differs')
    current = evaluation if evaluation is not None else integrated
    return original, {
        **proof, 'new': dict(current['new']),
        **({'integrated_source_admission': integrated} if integrated is not None else {}),
        **({'evaluation_caller_capture': evaluation} if evaluation is not None else {}),
    }

def predecessor(name, raw, *, root=None, take=Path.read_bytes):
    return reviewed(name, raw, root=root, take=take)[0]

def bind_adjustment(entry, raw, proof):
    """Bind the actual complete source through both fixed history layers."""
    if proof is None:
        return entry
    if type(proof) is not dict or proof.get('path') not in EXPECTED:
        raise ValueError('caller selection source adjustment has no fixed path')
    name = proof['path']
    expected = EXPECTED[name]
    actual = pin(raw)
    integrated = proof.get('integrated_source_admission')
    evaluation = proof.get('evaluation_caller_capture')
    if evaluation is not None:
        version = next((number for number in (2, 1)
                        if type(evaluation) is dict
                        and evaluation == _evaluation_capture_proof(number)
                        and json.dumps(evaluation, sort_keys=True) ==
                            json.dumps(_evaluation_capture_proof(number), sort_keys=True)), None)
        if (name != EVALUATION_CAPTURE_PATH or integrated is not None
                or version is None
                or evaluation.get('complete_predecessor_restored') is not True
                or evaluation.get('complete_successor_replayed') is not True
                or evaluation.get('physical_capture_rewritten') is not False
                or evaluation.get('terminal_reread_identical') is not True
                or evaluation.get('whole_native_delivery_qualified') is not False
                or type(evaluation.get('original_complete_callers')) is not int):
            raise ValueError('caller selection evaluation capture proof differs')
        current = _evaluation_capture_versions(version)[name]['new']
    elif integrated is None:
        current = expected['new']
    else:
        version = next((number for number in (3, 2)
                        if name in _integrated_version(number)[2]
                        and integrated == _integrated_proof(name, number)), None)
        if (version is None or type(integrated) is not dict
                or integrated.get('complete_predecessor_restored') is not True
                or integrated.get('complete_successor_replayed') is not True
                or integrated.get('terminal_reread_identical') is not True
                or integrated.get('whole_native_delivery_qualified') is not False):
            raise ValueError('caller selection integrated source proof differs')
        current = _integrated_version(version)[2][name]['new']
    prior = {'bytes': entry.get('current_bytes'), 'sha256': entry.get('current_sha256')}
    if (entry.get('path') != name
            or actual != current or proof.get('old') != expected['old']
            or proof.get('new') != current
            or prior not in (expected['old'], expected['new'], current)):
        raise ValueError('caller selection source adjustment lost its admitted predecessor')
    return {**entry, 'current_bytes': len(raw), 'current_sha256': sha256(raw).hexdigest(),
            'native_cold_selection_source': proof}
