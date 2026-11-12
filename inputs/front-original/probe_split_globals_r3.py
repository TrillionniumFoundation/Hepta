"""Two real module namespaces: fixed anchors, deletion and replacement timing."""
from pathlib import Path
from hashlib import sha256
from contextlib import nullcontext
import json
import os
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
OUT = ROOT / 'global-controls-r3'
OUT.mkdir(exist_ok=False)
for key in tuple(os.environ):
    if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'):
        del os.environ[key]
sys.path.insert(0, str(SOURCE))
from hepta import hia_program as program, hia_agent_assembly as assembly
from hepta.hia_core_verification_native import NativeCoreVerification
from hepta.hia_assembly_front_native import NativeAssemblyFront

BUILD = json.loads((ROOT / 'native-build-r1/RESULT.json').read_bytes())
OBSERVATIONS = []
def snapshot():
    return {p.relative_to(SOURCE).as_posix(): {
        'sha256': sha256(p.read_bytes()).hexdigest(), 'mode': p.stat().st_mode & 0o777}
        for p in SOURCE.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
BEFORE = snapshot()

def make_owner(stem):
    row = BUILD['images'][stem]
    image = (Path(row['manifest_path']).parent / row['manifest']['image_path']).read_bytes()
    assert sha256(image).hexdigest() == row['manifest']['image_sha256']
    cls = NativeCoreVerification if stem == 'core_verification' else NativeAssemblyFront
    return cls(image, sha256(image).hexdigest())

def error_value(error):
    return {'type': type(error).__name__, 'message': str(error),
        'name': getattr(error, 'name', None), 'code': getattr(error, 'code', None),
        'context': None if error.__context__ is None else type(error.__context__).__name__,
        'cause': None if error.__cause__ is None else type(error.__cause__).__name__,
        'suppress_context': error.__suppress_context__}

def observe(stem, route, timing, action, outer):
    module = program if stem == 'core_verification' else assembly
    entry = 'verify_program' if stem == 'core_verification' else '_parameters'
    name = '_decode' if stem == 'core_verification' else '_items'
    if action in ('helper-replaced', 'helper-deleted', 'helper-none'):
        name = '_reject' if stem == 'core_verification' else '_items'
    arguments = ({'schema': 'hepta.hia.program.v2', 'types': []},) if stem == 'core_verification' else ('a:i8', 7)
    events = []
    failure = LookupError('replacement effect')
    class Replacement:
        def __getattribute__(self, attr):
            if attr in ('__module__', '__name__', '__qualname__'):
                events.append('unexpected-metadata:' + attr)
                raise AssertionError('replacement metadata must not be captured')
            return object.__getattribute__(self, attr)
        def __call__(self, *args, **keywords):
            events.append('replacement-call')
            raise failure
    saved = dict(vars(module))
    owner = None
    def mutate():
        if action.endswith('deleted'):
            del vars(module)[name]
        elif action.endswith('none'):
            vars(module)[name] = None
        else:
            vars(module)[name] = Replacement()
    try:
        # The decoded dummy only reaches the original historical-v2 rejection;
        # helper replacement remains a separately observable real GLOBAL read.
        if stem == 'core_verification' and name == '_reject':
            vars(module)['_decode'] = lambda value: (value, b'{}')
        if timing == 'before':
            mutate()
        if route == 'native':
            owner = make_owner(stem)
        if timing == 'after':
            mutate()
        reference = saved['_' + stem + '_reference' + entry]
        call = (lambda: owner.run(entry, *arguments)) if owner else (lambda: reference(*arguments))
        result = None
        if outer:
            try:
                raise OSError('ambient outer')
            except OSError:
                try:
                    result = {'returned': call()}
                except BaseException as error:
                    result = {'error': error_value(error), 'same_replacement': error is failure}
        else:
            try:
                result = {'returned': call()}
            except BaseException as error:
                result = {'error': error_value(error), 'same_replacement': error is failure}
        return {'outcome': result, 'events': events}, None if owner is None else owner.entries
    finally:
        vars(module).clear()
        vars(module).update(saved)

class Controls(unittest.TestCase):
    def matrix(self, stem, actions):
        for timing in ('before', 'after'):
            for action in actions:
                for outer in (False, True):
                    with self.subTest(stem=stem, timing=timing, action=action, outer=outer):
                        expected, _ = observe(stem, 'reference', timing, action, outer)
                        actual, entries = observe(stem, 'native', timing, action, outer)
                        OBSERVATIONS.append({'stem': stem, 'timing': timing,
                            'action': action, 'outer': outer, 'reference': expected,
                            'actual': actual, 'actual_native_entries': entries})
                        self.assertGreater(entries, 0)
                        self.assertEqual(actual, expected)
    def test_core_foreign_global_before_after_admission(self):
        self.matrix('core_verification', ('foreign-replaced', 'foreign-deleted'))
    def test_core_helper_anchor_before_after_admission(self):
        self.matrix('core_verification', ('helper-replaced', 'helper-deleted', 'helper-none'))
    def test_assembly_helper_anchor_before_after_admission(self):
        self.matrix('assembly_front', ('helper-replaced', 'helper-deleted', 'helper-none'))

suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
with (OUT / 'tests.log').open('w') as log:
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
unchanged = snapshot() == BEFORE
passed = unchanged and result.testsRun == 3 and not any((result.failures, result.errors,
    result.skipped, result.expectedFailures, result.unexpectedSuccesses))
report = {'schema': 'hia.front.two-namespace.original-differential.v81.r3',
    'status': 'PASS' if passed else 'FAIL', 'python': sys.version,
    'tests_run': result.testsRun, 'observations': OBSERVATIONS,
    'failures': [(str(t), error) for t, error in result.failures],
    'errors': [(str(t), error) for t, error in result.errors],
    'source_unchanged': unchanged, 'current_cold': False, 'whole_normalization': False}
(OUT / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({'status': report['status'], 'tests_run': result.testsRun,
    'observations': len(OBSERVATIONS), 'source_unchanged': unchanged}))
raise SystemExit(0 if passed else 1)
