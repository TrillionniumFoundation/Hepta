from pathlib import Path
import ast
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
import os
import sys
import traceback
import unittest

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'source'
BASE = HERE.parent / 'source-original'
OUT = HERE / 'controls-r3'
OUT.mkdir()
sys.dont_write_bytecode = True
sys.path.insert(0, str(SOURCE))
from tools import hia_selfhost_contract as candidate
spec = importlib.util.spec_from_file_location('_original_source_guard', BASE / 'tools/hia_selfhost_contract.py')
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': sha(raw), 'mode': oct(path.stat().st_mode & 0o777)}


def snapshot():
    return {p.relative_to(SOURCE).as_posix(): identity(p) for p in sorted(SOURCE.rglob('*')) if p.is_file()}


@contextmanager
def attribute(obj, name, value, absent=False):
    namespace = vars(obj)
    existed = name in namespace
    old = namespace.get(name)
    if absent:
        delattr(obj, name)
    else:
        setattr(obj, name, value)
    try:
        yield
    finally:
        if existed:
            setattr(obj, name, old)
        else:
            delattr(obj, name)


rows = []


def pair(name, mutation, expected):
    seen = []
    for module in (reference, candidate):
        events = []
        with mutation(module, events):
            try:
                result = module._source_protocol_current(module.ROOT)
                assert type(result) is bool
                observed = {'kind': 'return', 'value': result}
            except BaseException as error:
                observed = {'kind': 'raise', 'type': type(error).__name__, 'args': error.args,
                            'name': getattr(error, 'name', None)}
        assert events == [], (name, events)
        seen.append(observed)
    assert seen[0] == seen[1], (name, seen)
    if expected is not None:
        assert seen == [{'kind': 'return', 'value': expected}] * 2, (name, seen, expected)
    rows.append({'name': name, 'original': seen[0], 'candidate': seen[1], 'foreign_callbacks': []})


@contextmanager
def no_change(module, events):
    yield


class Foreign:
    def __init__(self, events): self.events = events
    def __eq__(self, other): self.events.append('eq'); raise AssertionError('foreign equality')
    def __bool__(self): self.events.append('bool'); raise AssertionError('foreign truth')
    def __get__(self, instance, owner): self.events.append('descriptor'); raise AssertionError('foreign descriptor')


before = snapshot()
(OUT / 'SOURCE-BEFORE.json').write_text(json.dumps(before, sort_keys=True, indent=2) + '\n')
result = None
error = None
try:
    pair('unchanged-standard-provider', no_change, True)
    names = ('read_bytes', 'open', '__truediv__', 'as_posix', 'relative_to',
             '__fspath__', '__str__', 'joinpath', 'with_segments')
    classes = tuple(cls for cls in Path().__class__.__mro__ if cls is not object)
    for cls in classes:
        for name in names:
            original_present = name in vars(cls)
            @contextmanager
            def mutate(module, events, cls=cls, name=name, original_present=original_present):
                if original_present:
                    with attribute(cls, name, Foreign(events)):
                        yield
                else:
                    with attribute(cls, '__slots__', None, absent=True):
                        with attribute(cls, name, Foreign(events)):
                            yield
            pair('same-length-foreign-member:' + cls.__name__ + ':' + name, mutate, False)
            if not original_present:
                @contextmanager
                def mutate_missing(module, events, cls=cls, name=name):
                    with attribute(cls, '__slots__', None, absent=True):
                        with attribute(cls, name, module._SOURCE_PATH_MISSING):
                            yield
                pair('same-length-explicit-missing-sentinel:' + cls.__name__ + ':' + name, mutate_missing, None)
        @contextmanager
        def added(module, events, cls=cls):
            with attribute(cls, '_diagnostic_unrelated_added', object()):
                yield
        pair('class-length-change:' + cls.__name__, added, False)
    @contextmanager
    def changed_missing(module, events):
        with attribute(module, '_SOURCE_PATH_MISSING', object()): yield
    pair('private-missing-sentinel-rebound', changed_missing, False)
    @contextmanager
    def changed_alias(module, events):
        with attribute(module, 'Path', lambda value: value): yield
    pair('public-Path-alias-rebound', changed_alias, False)
    @contextmanager
    def changed_open(module, events):
        with attribute(io, 'open', lambda *args, **kwargs: None): yield
    pair('io-open-rebound', changed_open, False)
    @contextmanager
    def changed_sha(module, events):
        with attribute(module, 'sha256', lambda value: value): yield
    pair('sha256-rebound', changed_sha, False)
    for name in names:
        function = reference._source_static_member(Path().__class__, name)
        @contextmanager
        def defaults(module, events, function=function):
            old = function.__defaults__
            function.__defaults__ = (Foreign(events),)
            try: yield
            finally: function.__defaults__ = old
        pair('function-defaults-identity:' + name, defaults, False)
        @contextmanager
        def keyword_defaults(module, events, function=function):
            old = function.__kwdefaults__
            function.__kwdefaults__ = {'walk_up': Foreign(events)}
            try: yield
            finally: function.__kwdefaults__ = old
        pair('function-kwdefaults-identity:' + name, keyword_defaults, False)
    function = Path.relative_to
    @contextmanager
    def keyword_item(module, events):
        old = function.__kwdefaults__['walk_up']
        function.__kwdefaults__['walk_up'] = Foreign(events)
        try: yield
        finally: function.__kwdefaults__['walk_up'] = old
    pair('function-kwdefault-item-no-foreign-equality', keyword_item, False)

    from tests.test_hia_selfhost_contract import SelfhostContractTests
    fixed_methods = (
        'test_fresh_path_allocation_preserves_complete_original_map_and_order',
        'test_fresh_path_allocation_preserves_lexical_roots_and_foreign_path_lifetime',
        'test_fresh_path_allocation_keeps_all_eleven_ordered_freshness_controls',
        'test_fresh_lexical_standard_provider_uses_exact_runtime_buffer_mode',
        'test_fresh_lexical_preimport_provider_replacements_use_original_protocol',
        'test_fresh_lexical_foreign_kwdefault_is_not_compared_during_admission',
        'test_fresh_lexical_real_file_errors_keep_original_identity_fields_and_context',
        'test_fresh_lexical_fast_route_observes_same_size_same_mtime_and_inventory_changes',
        'test_fresh_lexical_mid_open_provider_changes_keep_complete_original_sequence',
    )
    original_test = BASE / 'tests/test_hia_selfhost_contract.py'
    assert (SOURCE / 'tests/test_hia_selfhost_contract.py').read_bytes() == original_test.read_bytes()
    suite = unittest.TestSuite(SelfhostContractTests(name) for name in fixed_methods)
    with (OUT / 'ORIGINAL-TESTS.log').open('w') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    passed = result.testsRun == 9 and result.wasSuccessful() and not any((
        result.errors, result.failures, result.skipped, result.expectedFailures, result.unexpectedSuccesses))
    assert passed, 'original source/freshness controls did not pass'
except BaseException:
    error = traceback.format_exc()
    (OUT / 'FAILURE.txt').write_text(error)
finally:
    after = snapshot()
    (OUT / 'SOURCE-AFTER.json').write_text(json.dumps(after, sort_keys=True, indent=2) + '\n')
    report = {
        'schema': 'hepta.source-guard-successor-controls.v1', 'python': sys.version,
        'status': 'PASS' if error is None and before == after else 'FAIL',
        'mechanism_cases': rows, 'mechanism_count': len(rows),
        'original_source_tests_run': result.testsRun if result is not None else 0,
        'original_source_test_errors': [(case.id(), detail) for case, detail in result.errors] if result is not None else None,
        'original_source_test_failures': [(case.id(), detail) for case, detail in result.failures] if result is not None else None,
        'source_unchanged': before == after,
        'whole_native': False, 'qualification': False, 'new_native_execution': False,
    }
    (OUT / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'mechanism_cases'}, sort_keys=True))
if error is not None:
    print(error, file=sys.stderr)
    raise SystemExit(1)
