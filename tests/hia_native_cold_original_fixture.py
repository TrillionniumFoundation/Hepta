"""Isolated preparation of the unchanged original 131-source test domain.

The current repository is read and checked again after the fixture is used.
Historical bytes are written only beneath a fresh test-owned directory. This
fixture executes source controls and grants no current product qualification.
"""
from contextlib import contextmanager, ExitStack
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import tempfile
from unittest.mock import patch

SELF = 'tests/hia_native_cold_original_fixture.py'
_EXECUTED_SOURCE = Path(__file__).read_bytes()
FIXTURE = 'tests/fixtures/hia_native_cold_original_test_view_v1.json'
FIXTURE_PIN = {"bytes":134652,"sha256":"e95838fab3eaefa788e3166dd3c5a6f7aa200930574d581172c0a1c2608c85f5"}
VERSIONS = {
    "hepta/hia_agent_service.py": {
        "current": {
            "bytes": 268730,
            "sha256": "353bd2673cc4f269c9c2d6cbf226d8956703d434ca960214864f56689d8f82c1"
        },
        "original": {
            "bytes": 268278,
            "sha256": "afc92b555bd0dfa23f25c4f9c2661af30853474342f4e32a036d37c1ce663a57"
        }
    },
    "tests/hia_slot_operations_component_fixture.py": {
        "current": {
            "bytes": 8760,
            "sha256": "44be6a9bf2798b8798e834737e34dacf869ebced7f32b6ed1b5f573e1ba3f24a"
        },
        "original": {
            "bytes": 8904,
            "sha256": "257c95b3d48ce31f261c075f9ef9b9b704311e20451d476150edece4c748b34d"
        }
    },
    "tests/test_hia_artifact_publication_route.py": {
        "current": {
            "bytes": 14742,
            "sha256": "32026b1a35fd73feb127c5940025bde37312948894b68615d5452317203c7d49"
        },
        "original": {
            "bytes": 14826,
            "sha256": "ed4b466b20e6c7b96c671d56263b0501b1a3d20ff314cf47e5c75e52158af740"
        }
    },
    "tests/test_hia_evaluation_native.py": {
        "current": {
            "bytes": 50368,
            "sha256": "8e55e6c0adda8629c5c484173262b63f726c727b2eeefbaf4926622e59a6cec0"
        },
        "original": {
            "bytes": 50228,
            "sha256": "091164ad78e1d3fab04e9410176b259b4a80f1e3b4b0c92c0da14743f2a43ab2"
        }
    },
    "tests/test_hia_slot_ledger_native.py": {
        "current": {
            "bytes": 32270,
            "sha256": "1bdfc91035d8a31c72da7c4fb068a204602f06bb058d0e9b5c557b79cdd7319c"
        },
        "original": {
            "bytes": 32390,
            "sha256": "69a2824787de28d9ff642978ea5fbafd52f5877f5201e0065fb96c419c8e1161"
        }
    },
    "tests/test_hia_slot_ledger_native_integration.py": {
        "current": {
            "bytes": 87678,
            "sha256": "f270650c8b70ef1384d0941a85c15c68b788f8198ef88de7f3fa8c96805e853f"
        },
        "original": {
            "bytes": 85231,
            "sha256": "50699c2dacdf503d5d820466ab590a9786dd2023d2d4fa06bedf1c9673d9ff42"
        }
    },
    "tools/qualify_hia_artifact_delivery_callers.py": {
        "current": {
            "bytes": 30746,
            "sha256": "2bfa65c4f6d1f89aba6eb82ddd8f66db9eaae8def635dbc1b336e0ea5beb486b"
        },
        "original": {
            "bytes": 18836,
            "sha256": "d5d9f8e1ee12e09bc709fb7edadd9bcc67b66d97ce25f946659578a42bfea93a"
        }
    },
    "tools/qualify_hia_cost_ledger_callers.py": {
        "current": {
            "bytes": 14304,
            "sha256": "e196780a77f544d4563b60af646383616045eb5ecda4e912c236e4ba1ec46f60"
        },
        "original": {
            "bytes": 10465,
            "sha256": "bd9682ab67948b2632523b55d595becfed7fe1f860b2544bd8449f1c052a20a1"
        }
    },
    "tools/qualify_hia_evaluation_callers.py": {
        "current": {
            "bytes": 16120,
            "sha256": "3360ffaa55764e6b521b954ec9aa6471dd7a08c9f76c896eb439df789711e4ec"
        },
        "original": {
            "bytes": 15063,
            "sha256": "29c40723460571b2d336e6f23adec005b3f4a89aead62c826efb391d9de762d9"
        }
    },
    "tools/qualify_hia_service_bootstrap_callers.py": {
        "current": {
            "bytes": 24447,
            "sha256": "2516bfb54ea1d2117489189e97cc327ef215be082309104fb2d2110823123599"
        },
        "original": {
            "bytes": 20824,
            "sha256": "898ba13203e4fa31d91f00abd020e4d88f08ad89e72dcf9f4da77e4f4af9b351"
        }
    },
    "tools/qualify_hia_service_context_callers.py": {
        "current": {
            "bytes": 15720,
            "sha256": "a91d034b5f556e5918a51d74d7fc71b83d2d681360eea24f895a61dad718f8df"
        },
        "original": {
            "bytes": 11881,
            "sha256": "c4de90f655d57d0036313f5a454863bfd85b40adfbe73a16efb16ce13eff2d6f"
        }
    },
    "tools/qualify_hia_service_discovery_callers.py": {
        "current": {
            "bytes": 16600,
            "sha256": "7bb5fb5b5807f5b5f8df779eb4c556cc5c4f8c74dc4a0a809d1a6edacf6aaa39"
        },
        "original": {
            "bytes": 13807,
            "sha256": "5ce31de74cdf638aa420f54ce832c768b5e495ba4817f2fa3c43957c9d9a0b0e"
        }
    },
    "tools/qualify_hia_service_verification_callers.py": {
        "current": {
            "bytes": 16365,
            "sha256": "440f63103f8783b5a45ed2bc909508b0b5516de8319729ab93d96305cfcc16c1"
        },
        "original": {
            "bytes": 13569,
            "sha256": "43504e98dbdac948e28fd547c6006b180636f54139f7110e70289dfdfd4e93d9"
        }
    },
    "tools/qualify_hia_slot_operations_callers.py": {
        "current": {
            "bytes": 14239,
            "sha256": "9df34e255caa814cef81b6dbc17f195bda560f9bf27c7ec81e50de7f0e2d386a"
        },
        "original": {
            "bytes": 12798,
            "sha256": "59a187498a565882fe3bd99a16588131d624e5ea1b218ccd3d05e85f0aa42867"
        }
    },
    "tools/qualify_hia_store_lifecycle_callers.py": {
        "current": {
            "bytes": 14213,
            "sha256": "39ef0387ce4a6883432f1b3d616a49f638ab800fc624739b4d24414a696761c1"
        },
        "original": {
            "bytes": 10080,
            "sha256": "2d49a7ae102d1ac11015a394a4bdf5cb71a3642b4d6818755097a699e65c3a04"
        }
    },
    "hepta/hia_evaluation_native.py": {
        "current": {
            "bytes": 47978,
            "sha256": "f9b25023b393f7b621b515b9b7f481a992715f15a386bf8c2457e2eb3136a73d"
        },
        "original": {
            "bytes": 46096,
            "sha256": "71f6d3be9bd116f3419b552e075113110596124365074d74ccf8855d15dc18e4"
        }
    },
    "tools/qualify_hia_service_lease_callers.py": {
        "current": {
            "bytes": 13895,
            "sha256": "0dcfdc29275f41959c1400f860d736a2220e6e1ef68bb0c34a31b5dddf3a389a"
        },
        "original": {
            "bytes": 11521,
            "sha256": "768363114e61b4aa315202de59a2f815a5abf5157c95111aebd480404e5a00ca"
        }
    }
}
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_PIN = {'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'}


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('original source fixture requires complete physical bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


@contextmanager
def original_view(root):
    root = Path(root).resolve(strict=True)
    captured, modes = {}, {}
    def capture(name):
        if (type(name) is not str or not name or str(PurePosixPath(name)) != name
                or name.startswith('/') or any(part in ('.', '..', '.git') for part in name.split('/'))):
            raise ValueError('original source fixture escaped its selected root')
        path = root / name
        raw = path.read_bytes()
        mode = path.stat().st_mode & 0o777
        if name in captured and (captured[name] != raw or modes[name] != mode):
            raise ValueError('original source fixture physical input changed: ' + name)
        captured[name], modes[name] = raw, mode
        return raw

    if capture(SELF) != _EXECUTED_SOURCE or Path(__file__).read_bytes() != _EXECUTED_SOURCE:
        raise ValueError('original source fixture executing reader changed')
    frozen = capture(FIXTURE)
    if pin(frozen) != FIXTURE_PIN:
        raise ValueError('original source fixture complete fixed relation changed')
    value = json.loads(frozen)
    if (value.get('schema') != 'hepta.hia.original-native-cold-source-test-view.v1'
            or value.get('historical_source_commit') != '4681a60bba48409749160e49cd7d3a5a6018460d'
            or value.get('native_product_execution_claimed') is not False
            or value.get('original_fixed_authorities_modified') is not False
            or value.get('original_test_assertions_and_budgets_modified') is not False
            or value.get('historical_view_is_current_repository') is not False
            or set(value.get('files', {})) != set(VERSIONS)):
        raise ValueError('original source fixture declared domain differs')
    from tools import hia_frozen_component_sources as engine
    from tools import hia_native_cold_caller_history as cold
    from tools import hia_selfhost_contract as contract
    engine_raw = capture(ENGINE)
    if pin(engine_raw) != ENGINE_PIN or Path(engine.__file__).read_bytes() != engine_raw:
        raise ValueError('original source fixture immutable inverse engine differs')
    contract_raw = capture('tools/hia_selfhost_contract.py')
    cold_raw = capture(cold.HISTORY_SOURCE)
    if (Path(contract.__file__).read_bytes() != contract_raw
            or Path(cold.__file__).read_bytes() != cold_raw):
        raise ValueError('original source fixture imported another source reader')
    names = set(contract.SOURCE_FILES) | set(cold.PATHS) | set(VERSIONS)
    names.update((SELF, FIXTURE, ENGINE, cold.HISTORY_SOURCE, *cold.DEPENDENCIES,
                  'tools/hia_selfhost_contract.py'))
    sources = {name: capture(name) for name in sorted(names)}
    projected = dict(sources)
    for name, expected in VERSIONS.items():
        physical = sources[name]
        row = value['files'][name]
        if pin(physical) != expected['current']:
            raise ValueError('unreviewed current source cannot enter the original fixture: ' + name)
        if ({'bytes': row['old_bytes'], 'sha256': row['old_sha256']} != expected['original']
                or {'bytes': row['new_bytes'], 'sha256': row['new_sha256']} != expected['current']):
            raise ValueError('original fixture whole source identities differ')
        projected[name] = engine.history_inverse(physical, row, expected['original'])
    if {name: pin(projected[name]) for name in cold.PATHS} != cold.KNOWN_CURRENT:
        raise ValueError('original fixture did not reconstruct all 131 complete fixed current sources')
    review = {
        'schema': 'hepta.hia.original-native-cold-source-test-view-review.v1',
        'physical_root': str(root),
        'actual_captured_files': {name: pin(raw) for name, raw in captured.items()},
        'historical_source_files': {name: pin(projected[name]) for name in cold.PATHS},
        'original_fixed_131_source_domain_restored': True,
        'historical_view_is_current_repository': False,
        'native_product_execution_claimed': False,
        'terminal_reread_identical': False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix='hia-original-native-cold-source-view-') as directory:
            stage = Path(directory)
            for name, raw in projected.items():
                path = stage / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(modes[name])
            # Package markers are source fixture scaffolding when the original
            # directory is a namespace package; no product input is substituted.
            for name in ('tools/__init__.py', 'tests/__init__.py'):
                if not (stage / name).exists():
                    source = root / name
                    (stage / name).write_bytes(capture(name) if source.is_file() else b'')
            yield stage, review
    finally:
        for name, raw in captured.items():
            if capture(name) != raw:
                raise ValueError('actual repository source changed while using its historical fixture')
        if Path(__file__).read_bytes() != _EXECUTED_SOURCE:
            raise ValueError('original source fixture executing reader changed at terminal')
        review['terminal_reread_identical'] = True


def install_original_view(test_class, namespace, *, subjects=()):
    """Bind only this source-test class and its explicit reader modules."""
    physical_root = Path(namespace['ROOT']).resolve(strict=True)
    stack = ExitStack()
    stage, review = stack.enter_context(original_view(physical_root))
    try:
        prior_root = namespace['ROOT']
        namespace['ROOT'] = stage
        stack.callback(namespace.__setitem__, 'ROOT', prior_root)
        for module in subjects:
            for key, value in tuple(vars(module).items()):
                if isinstance(value, Path):
                    try:
                        relative = value.relative_to(physical_root)
                    except ValueError:
                        continue
                    stack.enter_context(patch.object(module, key, stage / relative))
        test_class.original_source_view_review = review
        test_class.addClassCleanup(stack.close)
    except BaseException:
        stack.close()
        raise
