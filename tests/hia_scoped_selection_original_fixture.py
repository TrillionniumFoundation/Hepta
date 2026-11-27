"""A declared old source domain for unchanged selection and pair controls.

Only the fixed complete Evaluation qualifier is projected in a fresh test
directory. Current production admission is qualified separately. Every actual
input and every staged byte is rechecked when the historical view closes.
"""
from contextlib import contextmanager, ExitStack
from hashlib import sha256
import ast
import json
from pathlib import Path, PurePosixPath
import tempfile
from unittest.mock import patch

SELF = 'tests/hia_scoped_selection_original_fixture.py'
_EXECUTED_PATH = Path(__file__).resolve()
_EXECUTED_SOURCE = _EXECUTED_PATH.read_bytes()
FIXTURE = 'tests/fixtures/hia_scoped_selection_original_test_view_v1.json'
FIXTURE_PIN = {'bytes': 5778, 'sha256': '9d5c8302fe53e24a7a0131773a90c80c76e8ab63f00d0a0937ddd4f7b7ac40dd'}
HISTORY = 'tools/hia_scoped_caller_admission_history.py'
HISTORY_PIN = {'bytes': 8874, 'sha256': '457367f7b37cf304e59c11bceb97b23983932321c51cf40ce98f5a25f8eb00f3'}
EVALUATION = 'tools/qualify_hia_evaluation_callers.py'
TESTS = (
    'tests/test_hia_cold_caller_selection_history.py',
    'tests/test_hia_evaluation_caller_capture_history.py',
    'tests/test_hia_installed_evaluation_source_history.py',
)


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('selection fixture requires complete source bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _methods(raw):
    return {node.name: ast.dump(node, include_attributes=False)
            for node in ast.walk(ast.parse(raw))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith('test_')}


@contextmanager
def original_view(root, *, take=Path.read_bytes):
    root = Path(root).resolve(strict=True)
    captured = {}
    def capture(path):
        path = Path(path)
        try:
            name = path.relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError('selection fixture read escaped the selected root') from error
        if (not name or name == '.' or str(PurePosixPath(name)) != name
                or any(part in ('.', '..', '.git') for part in name.split('/'))):
            raise ValueError('selection fixture path is not canonical')
        raw = take(path)
        pin(raw)
        if name in captured and captured[name] != raw:
            raise ValueError('selection fixture physical input changed: ' + name)
        captured[name] = raw
        return raw

    if capture(root / SELF) != _EXECUTED_SOURCE or _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE:
        raise ValueError('selection fixture executing source differs')
    frozen = capture(root / FIXTURE)
    if pin(frozen) != FIXTURE_PIN:
        raise ValueError('selection fixture fixed whole test relation changed')
    value = json.loads(frozen)
    if (type(value) is not dict or set(value) != {
            'schema', 'base_commit', 'test_files', 'support',
            'original_test_methods_modified', 'historical_view_is_current_repository',
            'native_product_execution_claimed'}
            or value['schema'] != 'hepta.hia.scoped-selection-original-test-view.v1'
            or value['base_commit'] != '0ab357a5a9583dbc03b00382a9e69576320e6549'
            or value['original_test_methods_modified'] is not False
            or value['historical_view_is_current_repository'] is not False
            or value['native_product_execution_claimed'] is not False
            or type(value['test_files']) is not dict or set(value['test_files']) != set(TESTS)
            or type(value['support']) is not dict):
        raise ValueError('selection fixture declared original scope differs')
    helper = capture(root / HISTORY)
    if pin(helper) != HISTORY_PIN:
        raise ValueError('selection fixture current admission reader differs')
    from tools import hia_scoped_caller_admission_history as history
    if Path(history.__file__).resolve().read_bytes() != helper:
        raise ValueError('selection fixture imported another admission reader')
    sources = {}
    for name, expected in value['support'].items():
        raw = capture(root / name)
        if pin(raw) != expected:
            raise ValueError('selection fixture unknown support source: ' + name)
        sources[name] = raw
    from tools import hia_frozen_component_sources as engine
    engine_bytes = capture(root / history.ENGINE)
    if pin(engine_bytes) != history.ENGINE_PIN or Path(engine.__file__).read_bytes() != engine_bytes:
        raise ValueError('selection fixture immutable inverse engine differs')
    for name, row in value['test_files'].items():
        raw = capture(root / name)
        old = engine.history_inverse(raw, row, {'bytes': row['old_bytes'], 'sha256': row['old_sha256']})
        if _methods(raw) != _methods(old):
            raise ValueError('selection fixture changed an original test method')
        sources[name] = old
    projected, prior = history.prepare(root, {EVALUATION: capture(root / EVALUATION)}, take=capture)
    if prior is None or history.pin(projected[EVALUATION]) != history.PRIOR[EVALUATION]:
        raise ValueError('selection fixture lost its complete Evaluation predecessor')
    sources.update(projected)
    view = {**captured, **sources}
    review = {
        'schema': 'hepta.hia.scoped-selection-original-test-view-review.v1',
        'physical_root': str(root),
        'actual_captured_files': {name: pin(raw) for name, raw in captured.items()},
        'historical_view_files': {name: pin(raw) for name, raw in view.items()},
        'current_admission_history': prior['review'],
        'original_test_methods_modified': False,
        'physical_capture_rewritten': False,
        'historical_view_is_current_repository': False,
        'native_product_execution_claimed': False,
        'terminal_reread_identical': False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix='hia-selection-original-view-') as directory:
            stage = Path(directory)
            for name, raw in view.items():
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            for name in ('tools/__init__.py', 'tests/__init__.py'):
                path = stage / name
                if not path.exists():
                    path.write_bytes(b'')
            yield stage, review
            for name, raw in view.items():
                if (stage / name).read_bytes() != raw:
                    raise ValueError('selection fixture staged source changed: ' + name)
    finally:
        history.verify_unchanged(prior)
        for name, raw in tuple(captured.items()):
            if capture(root / name) != raw:
                raise ValueError('selection fixture physical source changed at terminal')
        if _EXECUTED_PATH.read_bytes() != _EXECUTED_SOURCE:
            raise ValueError('selection fixture executing source changed at terminal')
        review['terminal_reread_identical'] = True


def _install(owner, namespace, subjects, cleanup):
    physical_root = Path(namespace['ROOT']).resolve(strict=True)
    stack = ExitStack()
    try:
        stage, review = stack.enter_context(original_view(physical_root))
        previous_root = namespace['ROOT']
        namespace['ROOT'] = stage
        stack.callback(namespace.__setitem__, 'ROOT', previous_root)
        for module in subjects:
            stack.enter_context(patch.object(module, 'ROOT', stage))
        owner.original_selection_view_review = review
        cleanup(stack.close)
    except BaseException:
        stack.close()
        raise


def install_class_view(owner, namespace, *, subjects=()):
    _install(owner, namespace, subjects, owner.addClassCleanup)


def install_test_view(owner, namespace, *, subjects=()):
    _install(owner, namespace, subjects, owner.addCleanup)
