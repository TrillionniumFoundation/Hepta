"""Explicit historical source views for unchanged scoped and Evaluation controls.

Current entry-point qualification is separate. This fixture keeps physical
captures, verifies complete source inverses, and writes only a fresh test-owned
view. Its consumers retain every original test method and budget.
"""
from contextlib import contextmanager, ExitStack
from hashlib import sha256
import ast
import json
from pathlib import Path, PurePosixPath
import tempfile

SELF = 'tests/hia_scoped_evaluation_cold_preparation.py'
FIXTURE = 'tests/fixtures/hia_scoped_evaluation_cold_preparation_v1.json'
FIXTURE_SHA256 = '3b16b8a76f356df199da6ec95bb57b688351fd3482e34ef9fda5c59cc1e9b100'
_EXECUTED_PATH = Path(__file__).resolve()
_EXECUTED_SOURCE = _EXECUTED_PATH.read_bytes()
COLD = 'tools/hia_native_cold_caller_history.py'
COLD_PIN = {'bytes': 44659, 'sha256': '0beac4d7b6f9ca0f87aa7b8f6b63cf2ec0a234228e7358d8ff0f33f8e78ee6e1'}
COMPOSITION = 'tools/hia_native_cold_composition_history.py'
COMPOSITION_PIN = {'bytes': 10987, 'sha256': 'c5a53a1adf23dfefb8f24f3a8cc82d7cf64324362746ac5d25be2f2a663d7b28'}
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_PIN = {'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774'}
TESTS = {
    'scoped': 'tests/test_hia_scoped_caller_source_history.py',
    'evaluation': 'tests/test_hia_evaluation_caller_admission.py',
}
QUALIFIERS = (
    'tools/qualify_hia_service_discovery_callers.py',
    'tools/qualify_hia_service_verification_callers.py',
    'tools/qualify_hia_evaluation_callers.py',
)


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('source fixture requires complete immutable bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _name(value):
    if (type(value) is not str or not value or '\\' in value or '\0' in value
            or str(PurePosixPath(value)) != value or PurePosixPath(value).is_absolute()
            or any(part in ('', '.', '..', '.git') for part in value.split('/'))):
        raise ValueError('source fixture path is not canonical')
    return value


def _test_methods(raw):
    tree = ast.parse(raw)
    return {node.name: ast.get_source_segment(raw.decode(), node)
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith('test_')}


@contextmanager
def historical_view(root, domain, *, take=Path.read_bytes):
    if type(domain) is not str or domain not in TESTS:
        raise ValueError('unknown historical source-test domain')
    root = Path(root).resolve(strict=True)
    captured = {}

    def capture(path):
        path = Path(path)
        name = _name(path.relative_to(root).as_posix())
        raw = take(root / name)
        pin(raw)
        if name in captured and captured[name] != raw:
            raise ValueError('source fixture physical input changed: ' + name)
        captured[name] = raw
        return raw

    if (capture(root / SELF) != _EXECUTED_SOURCE
            or _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE):
        raise ValueError('source fixture executing reader differs')
    frozen = capture(root / FIXTURE)
    if sha256(frozen).hexdigest() != FIXTURE_SHA256:
        raise ValueError('source fixture fixed complete relation changed')
    authority = json.loads(frozen)
    if (type(authority) is not dict
            or authority.get('schema') != 'hepta.hia.scoped-evaluation-cold-test-preparation.v1'
            or authority.get('base_commit') != '322d93c44587986248bac21ad37243fa266517fc'
            or authority.get('original_test_methods_modified') is not False
            or authority.get('native_product_execution_claimed') is not False
            or set(authority.get('files', {})) != {*TESTS.values(), *QUALIFIERS}
            or set(authority.get('domains', {})) != set(TESTS)):
        raise ValueError('source fixture fixed domain differs')
    engine_bytes = capture(root / ENGINE)
    if pin(engine_bytes) != ENGINE_PIN:
        raise ValueError('source fixture immutable inverse engine differs')
    from tools import hia_frozen_component_sources as engine
    if Path(engine.__file__).read_bytes() != engine_bytes:
        raise ValueError('source fixture imported another inverse engine')
    for name, row in authority['files'].items():
        physical = capture(root / name)
        current = {'bytes': row['new_bytes'], 'sha256': row['new_sha256']}
        previous = {'bytes': row['old_bytes'], 'sha256': row['old_sha256']}
        if pin(physical) != current:
            raise ValueError('unreviewed source fixture consumer: ' + name)
        restored = engine.history_inverse(physical, row, previous)
        if name in TESTS.values() and _test_methods(restored) != _test_methods(physical):
            raise ValueError('source fixture changed an original test method')
    row = authority['domains'][domain]
    if (set(row) != {'inputs', 'callers', 'reviewed_callers'}
            or type(row['inputs']) is not dict
            or type(row['callers']) is not list or len(set(row['callers'])) != len(row['callers'])
            or not set(row['callers']) <= set(row['inputs'])
            or set(row['reviewed_callers']) != set(row['callers'])):
        raise ValueError('source fixture caller inventory differs')
    values = {name: capture(root / _name(name)) for name in row['inputs']}
    if {name: pin(data) for name, data in values.items()} != row['inputs']:
        raise ValueError('source fixture complete support input changed')
    from tools import hia_native_cold_caller_history as cold
    from tools import hia_native_cold_composition_history as composition
    cold_bytes, composition_bytes = capture(root / COLD), capture(root / COMPOSITION)
    if (pin(cold_bytes) != COLD_PIN or pin(composition_bytes) != COMPOSITION_PIN
            or Path(cold.__file__).read_bytes() != cold_bytes
            or Path(composition.__file__).read_bytes() != composition_bytes):
        raise ValueError('source fixture imported another physical history reader')
    projected = dict(values)
    cold_histories, composition_histories = [], []
    for name in row['callers']:
        selected, selected_take = values[name], capture
        if pin(selected) == composition.CURRENT.get(name):
            previous, history = composition.prepare(root, {name: selected}, take=selected_take)
            if history is None:
                raise ValueError('source fixture current composition lost its review')
            selected, selected_take = previous[name], history['prior_take']
            composition_histories.append(history)
        if pin(selected) == cold.KNOWN_CURRENT.get(name):
            previous, history = cold.prepare(root, {name: selected}, take=selected_take)
            selected, selected_take = previous[name], history['prior_take']
            cold_histories.append(history)
        if pin(selected) != row['reviewed_callers'][name]:
            raise ValueError('source fixture did not restore the complete reviewed caller: ' + name)
        projected[name] = selected
    # Every lazily consumed authority remains an actual capture; only callers
    # with a verified full-file relation are replaced in the historical view.
    view = {**captured, **projected}
    review = {
        'schema': 'hepta.hia.scoped-evaluation-cold-test-preparation-review.v1',
        'domain': domain, 'physical_root': str(root),
        'actual_captured_files': {n: pin(b) for n, b in captured.items()},
        'historical_view_files': {n: pin(b) for n, b in view.items()},
        'reviewed_callers': dict(row['reviewed_callers']),
        'native_cold_reviews': [h['review'] for h in cold_histories],
        'composition_reviews': [h['review'] for h in composition_histories],
        'physical_capture_rewritten': False,
        'historical_view_is_current_repository': False,
        'native_product_execution_claimed': False,
        'original_test_methods_modified': False,
        'terminal_reread_identical': False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix='hia-scoped-evaluation-source-view-') as directory:
            stage = Path(directory)
            for name, raw in view.items():
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            for name in ('tools/__init__.py', 'tests/__init__.py'):
                if not (stage / name).exists():
                    (stage / name).write_bytes(b'')
            yield stage, review
            for name, raw in view.items():
                if (stage / name).read_bytes() != raw:
                    raise ValueError('declared historical source view changed: ' + name)
    finally:
        for history in cold_histories:
            cold.verify_unchanged(history)
        for history in composition_histories:
            composition.verify_unchanged(history)
        for name, raw in tuple(captured.items()):
            if capture(root / name) != raw:
                raise ValueError('source fixture changed at terminal: ' + name)
        if _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE:
            raise ValueError('source fixture executing reader changed at terminal')
        review['terminal_reread_identical'] = True


def install_view(test_class, namespace, *, domain):
    physical_root = Path(namespace['ROOT']).resolve(strict=True)
    stack = ExitStack()
    try:
        stage, review = stack.enter_context(historical_view(physical_root, domain))
        namespace['ROOT'] = stage
        stack.callback(namespace.__setitem__, 'ROOT', physical_root)
        test_class.historical_source_view_review = review
        test_class.addClassCleanup(stack.close)
    except BaseException:
        stack.close()
        raise
