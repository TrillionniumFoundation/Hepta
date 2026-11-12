"""Real two-image capture, first-use ordering and fresh-file admission controls."""
from __future__ import annotations
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
OUT = ROOT / 'capture-controls-r2'
OUT.mkdir(exist_ok=False)
for key in tuple(os.environ):
    if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'):
        del os.environ[key]
sys.path.insert(0, str(SOURCE))
from hepta import hia_program as program, hia_agent_assembly as assembly
from hepta import hia_core_verification_native as core_native
from hepta import hia_core_verification_selection as core_selection
from hepta import hia_assembly_front_native as assembly_native
from hepta import hia_assembly_front_selection as assembly_selection
from hepta import hia_front_selection as shared_selection
from hepta.hia_checker_identity import checker_native_selection
from tests.test_hia_agent_assembly import SOURCE as ASM

BUILD = json.loads((ROOT / 'native-build-r1/RESULT.json').read_bytes())
OBSERVATIONS = []

def snapshot(root):
    return {p.relative_to(root).as_posix(): {
        'sha256': sha256(p.read_bytes()).hexdigest(), 'mode': p.stat().st_mode & 0o777}
        for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}

BEFORE = snapshot(SOURCE)
ORIGINAL_R1 = ROOT.with_name('v81-core-assembly-front-development-r1') / 'source'
ORIGINAL_GUARD = json.loads((ROOT / 'ORIGINAL-R1-SOURCE-GUARD.json').read_bytes())
assert snapshot(ORIGINAL_R1) == ORIGINAL_GUARD
DOCUMENT = assembly._parse_assembly_document(ASM)

def error_record(error):
    return {'type': type(error).__name__, 'message': str(error),
            'name': getattr(error, 'name', None), 'code': getattr(error, 'code', None),
            'phase': getattr(error, 'phase', None),
            'cause': None if error.__cause__ is None else type(error.__cause__).__name__,
            'context': None if error.__context__ is None else type(error.__context__).__name__}

class Controls(unittest.TestCase):
    def setUp(self):
        self.out = OUT / self._testMethodName
        self.out.mkdir()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {}, clear=False))
        self.records = {}
        self.owners = {}
        self.sources = {}
        for stem, native, selection in (
                ('core_verification', core_native, core_selection),
                ('assembly_front', assembly_native, assembly_selection)):
            os.environ.pop(native.SELECTOR, None)
            source = native.SOURCE.read_bytes()
            source_path = self.out / (stem + '.hiaasm')
            source_path.write_bytes(source)
            self.sources[stem] = (source_path, source)
            self.stack.enter_context(patch.object(native, 'SOURCE', source_path))
            self.stack.enter_context(patch.object(selection, 'SOURCE', source_path))
            original = BUILD['images'][stem]
            manifest_path = Path(original['manifest_path'])
            image = (manifest_path.parent / original['manifest']['image_path']).read_bytes()
            entries = {}
            for label, data in (('A', image), ('B', image + b'\0')):
                binary = self.out / (stem + '-' + label + '.bin')
                binary.write_bytes(data)
                record = {**original['manifest'], 'image_path': binary.name,
                          'image_sha256': sha256(data).hexdigest()}
                manifest = self.out / (stem + '-' + label + '.json')
                raw = (json.dumps(record, sort_keys=True) + '\n').encode()
                manifest.write_bytes(raw)
                entries[label] = {'path': manifest, 'raw': raw, 'image': binary,
                                  'record': record, 'manifest_sha256': sha256(raw).hexdigest()}
            self.records[stem] = entries
            loader = (selection.installed_core_verification if stem == 'core_verification'
                      else selection.installed_assembly_front)
            self.owners[stem] = loader(entries['A']['path'])
        self.assertEqual(core_selection.captured_checker_owner(), (False, None))
        self.assertEqual(assembly_selection.captured_checker_owner(), (False, None))

    def enable(self, *, core=None, assembly_owner=None):
        for stem, selector, label in (
                ('core_verification', core_native.SELECTOR, core),
                ('assembly_front', assembly_native.SELECTOR, assembly_owner)):
            if label is None:
                os.environ.pop(selector, None)
            else:
                os.environ[selector] = str(self.records[stem][label]['path'])

    def record(self, case, **fields):
        OBSERVATIONS.append({'test': self.id(), 'case': case, **fields})

    def assert_identity(self, value, stem, label):
        record = self.records[stem][label]
        self.assertEqual(value['manifest_sha256'], record['manifest_sha256'])
        self.assertEqual(value['images']['image']['image_sha256'], record['record']['image_sha256'])
        self.assertEqual(value['sources']['image'], sha256(self.sources[stem][1]).hexdigest())

    def test_syntax_error_precedes_first_core_admission(self):
        for text in ('not-an-assembly-header', ASM.replace('int.add.wrap(a64,b64)', 'int.add.wrap(a64,b64) {'),
                     ASM.replace('\nend\n', '\n'), ASM.replace('fn total(', 'invalid total(')):
            self.enable()
            try:
                assembly.assemble_program(text)
            except program.HIAProgramRejected as error:
                expected = error_record(error)
            else:
                self.fail('reference invalid syntax unexpectedly succeeded')
            for selected in (None, 'A'):
                with self.subTest(assembly=selected, text=text[:40]):
                    self.enable(assembly_owner=selected)
                    os.environ[core_native.SELECTOR] = str(self.out / 'absent-core-manifest')
                    calls = []
                    fresh = core_selection._fresh
                    def observed():
                        calls.append(True)
                        return fresh()
                    with patch.object(core_selection, '_fresh', observed):
                        with self.assertRaises(program.HIAProgramRejected) as caught:
                            assembly.assemble_program(text)
                    self.assertEqual(error_record(caught.exception), expected)
                    self.assertEqual(calls, [])
                    self.assertEqual(core_selection.captured_checker_owner(), (False, None))
                    self.record('syntax-first', assembly=selected, error=expected, core_admissions=len(calls))

    def test_first_core_selection_observes_callback_manifest_change(self):
        expected = program.verify_program(DOCUMENT).canonical_bytes
        for selected in (None, 'A'):
            self.enable(assembly_owner=selected)
            calls = []
            fresh = core_selection._fresh
            control = assembly._SOURCE_CONTROL
            class ChooseBeforeCore:
                def search(inner, text):
                    self.assertEqual(calls, [])
                    os.environ[core_native.SELECTOR] = str(self.records['core_verification']['B']['path'])
                    return control.search(text)
            def observed():
                calls.append(os.environ.get(core_native.SELECTOR))
                return fresh()
            with patch.object(assembly, '_SOURCE_CONTROL', ChooseBeforeCore()), patch.object(core_selection, '_fresh', observed):
                self.assertEqual(assembly.assemble_program(ASM).canonical_bytes, expected)
            self.assertEqual(calls, [str(self.records['core_verification']['B']['path'])])
            self.record('first-use-selection', assembly=selected, manifests=calls)

    def test_first_core_use_rechecks_drifted_manifest_and_source(self):
        record = self.records['core_verification']['A']
        path, source = self.sources['core_verification']
        for selected in (None, 'A'):
            for field in ('manifest', 'source'):
                with self.subTest(assembly=selected, field=field):
                    self.enable(core='A', assembly_owner=selected)
                    prior = self.owners['core_verification'].entries
                    calls = []
                    fresh = core_selection._fresh
                    control = assembly._SOURCE_CONTROL
                    class DriftBeforeCore:
                        def search(inner, text):
                            self.assertEqual(calls, [])
                            if field == 'source':
                                path.write_bytes(source + b'\n')
                            else:
                                value = {**record['record'], 'source_sha256': '0' * 64}
                                record['path'].write_text(json.dumps(value))
                            return control.search(text)
                    def observed():
                        calls.append(True)
                        return fresh()
                    try:
                        with patch.object(assembly, '_SOURCE_CONTROL', DriftBeforeCore()), patch.object(core_selection, '_fresh', observed):
                            with self.assertRaises(ValueError) as caught:
                                assembly.assemble_program(ASM)
                        self.assertEqual(len(calls), 1)
                        self.assertEqual(self.owners['core_verification'].entries, prior)
                        self.record('first-use-drift-refused', assembly=selected, field=field,
                                    error=error_record(caught.exception), native_business_delta=0)
                    finally:
                        path.write_bytes(source)
                        record['path'].write_bytes(record['raw'])

    def test_captured_none_survives_second_core_call_and_next_call_is_fresh(self):
        for selected in (None, 'A'):
            self.enable(assembly_owner=selected)
            original_render = assembly._render_assembly_document
            core_owner = self.owners['core_verification']
            before = core_owner.entries
            calls = []
            fresh = core_selection._fresh
            def observed():
                calls.append(os.environ.get(core_native.SELECTOR))
                return fresh()
            def between_core_calls(data):
                self.assertEqual(calls, [None])
                os.environ[core_native.SELECTOR] = str(self.records['core_verification']['A']['path'])
                self.assertEqual(core_selection.captured_checker_owner(), (True, None))
                self.assertIsNone(checker_native_selection()[core_native.SELECTOR])
                return original_render(data)
            with patch.object(core_selection, '_fresh', observed), patch.object(assembly, '_render_assembly_document', between_core_calls):
                self.assertEqual(assembly.render_assembly(DOCUMENT), ASM)
            self.assertEqual(calls, [None])
            self.assertEqual(core_owner.entries, before)
            self.assertEqual(core_selection.captured_checker_owner(), (False, None))
            program.verify_program(DOCUMENT)
            self.assertGreater(core_owner.entries, before)
            self.record('captured-none', assembly=selected, first_use=calls,
                        native_after_independent_call=core_owner.entries-before)

    def test_held_core_identity_survives_environment_and_source_drift(self):
        path, source = self.sources['core_verification']
        for selected in (None, 'A'):
            self.enable(core='A', assembly_owner=selected)
            original_render = assembly._render_assembly_document
            owner = self.owners['core_verification']
            before = owner.entries
            calls = []
            fresh = core_selection._fresh
            def observed():
                calls.append(True)
                return fresh()
            def between_core_calls(data):
                self.assertEqual(len(calls), 1)
                os.environ[core_native.SELECTOR] = str(self.records['core_verification']['B']['path'])
                path.write_bytes(source + b'\n')
                self.assertIs(core_selection.active_core_verification(), owner)
                identity = checker_native_selection()[core_native.SELECTOR]
                self.assert_identity(identity, 'core_verification', 'A')
                self.record('held-core', assembly=selected, identity=identity)
                return original_render(data)
            try:
                with patch.object(core_selection, '_fresh', observed), patch.object(assembly, '_render_assembly_document', between_core_calls):
                    self.assertEqual(assembly.render_assembly(DOCUMENT), ASM)
                self.assertEqual(len(calls), 1)
                self.assertGreater(owner.entries, before)
                self.assertEqual(core_selection.captured_checker_owner(), (False, None))
                entries = owner.entries
                with self.assertRaises(ValueError):
                    program.verify_program(DOCUMENT)
                self.assertEqual(owner.entries, entries)
            finally:
                path.write_bytes(source)

    def test_assembly_absence_is_captured_and_next_independent_call_selects(self):
        self.enable(core='A')
        owner = self.owners['assembly_front']
        before = owner.entries
        control = assembly._SOURCE_CONTROL
        class FromNone:
            def search(inner, text):
                os.environ[assembly_native.SELECTOR] = str(self.records['assembly_front']['A']['path'])
                self.assertEqual(assembly_selection.captured_checker_owner(), (True, None))
                self.assertIsNone(checker_native_selection()[assembly_native.SELECTOR])
                self.assertEqual(assembly._items('x,y', 1), ['x', 'y'])
                return control.search(text)
        with patch.object(assembly, '_SOURCE_CONTROL', FromNone()):
            self.assertEqual(assembly.assemble_program(ASM).as_dict(), DOCUMENT)
        self.assertEqual(owner.entries, before)
        self.assertEqual(assembly_selection.captured_checker_owner(), (False, None))
        self.assertEqual(assembly._items('x,y', 1), ['x', 'y'])
        self.assertGreater(owner.entries, before)
        self.record('assembly-captured-none', native_after_independent_call=owner.entries-before)

    def test_reentry_error_restores_both_scopes_and_keeps_actual_exception(self):
        self.enable(core='A', assembly_owner='A')
        failure = LookupError('actual provider failure after reentry')
        original_decode = program._decode
        nested = []
        def decode(value):
            self.assertIs(core_selection.active_core_verification(), self.owners['core_verification'])
            self.assertIs(assembly_selection.active_assembly_front(), self.owners['assembly_front'])
            if nested:
                return original_decode(value)
            nested.append(True)
            os.environ[core_native.SELECTOR] = str(self.records['core_verification']['B']['path'])
            os.environ[assembly_native.SELECTOR] = str(self.records['assembly_front']['B']['path'])
            self.assertEqual(program.verify_program(DOCUMENT).as_dict(), DOCUMENT)
            self.assertEqual(assembly._items('a,b', 1), ['a', 'b'])
            identity = checker_native_selection()
            self.assert_identity(identity[core_native.SELECTOR], 'core_verification', 'A')
            self.assert_identity(identity[assembly_native.SELECTOR], 'assembly_front', 'A')
            raise failure
        with patch.object(program, '_decode', decode):
            with self.assertRaises(LookupError) as caught:
                assembly.assemble_program(ASM)
        self.assertIs(caught.exception, failure)
        self.assertEqual(core_selection.captured_checker_owner(), (False, None))
        self.assertEqual(assembly_selection.captured_checker_owner(), (False, None))
        identity = checker_native_selection()
        self.assert_identity(identity[core_native.SELECTOR], 'core_verification', 'B')
        self.assert_identity(identity[assembly_native.SELECTOR], 'assembly_front', 'B')
        self.record('reentry-error-restored', error=error_record(failure), after_identity=identity)
        failure.__traceback__ = None

    def test_each_owner_rejects_other_image_and_wrong_exact_metadata(self):
        core = self.owners['core_verification']
        app = self.owners['assembly_front']
        self.assertIsNot(core, app)
        self.assertEqual(core.function_count, 2)
        self.assertEqual(app.function_count, 16)
        self.assertNotEqual(core.image_sha256, app.image_sha256)
        for native, other in ((core_native, 'assembly_front'), (assembly_native, 'core_verification')):
            raw = self.records[other]['A']['image'].read_bytes()
            constructor = native.NativeCoreVerification if native is core_native else native.NativeAssemblyFront
            with self.assertRaises(RuntimeError):
                constructor(raw, sha256(raw).hexdigest())
        raw = self.records['core_verification']['A']['image'].read_bytes()
        with patch.object(self.owners['core_verification'].ports, 'FUNCTION_COUNT', 1):
            with self.assertRaises(RuntimeError):
                core_native.NativeCoreVerification(raw, sha256(raw).hexdigest())
        self.record('independent-table-image-bindings', core_count=2, assembly_count=16)

    def test_final_readback_detects_actual_post_map_manifest_drift(self):
        for stem, native, selection in (
                ('core_verification', core_native, core_selection),
                ('assembly_front', assembly_native, assembly_selection)):
            record = self.records[stem]['A']
            original = shared_selection._mapped
            calls = []
            def change_after_mapping(*arguments):
                owner = original(*arguments)
                calls.append(True)
                record['path'].write_bytes(record['raw'] + b' ')
                return owner
            loader = selection.installed_core_verification if stem == 'core_verification' else selection.installed_assembly_front
            try:
                with patch.object(shared_selection, '_mapped', change_after_mapping):
                    with self.assertRaises(ValueError) as caught:
                        loader(record['path'])
                self.assertEqual(calls, [True])
                self.record('post-map-readback', owner=stem, error=error_record(caught.exception))
            finally:
                record['path'].write_bytes(record['raw'])

def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item.id()

EXECUTED = []
class Result(unittest.TextTestResult):
    def startTest(self, test):
        EXECUTED.append(test.id())
        super().startTest(test)

suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
loaded = list(flatten(suite))
started = time.monotonic()
with (OUT / 'tests.log').open('w') as stream:
    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
after = snapshot(SOURCE)
unchanged = BEFORE == after and snapshot(ORIGINAL_R1) == ORIGINAL_GUARD
passed = (loaded == EXECUTED and result.testsRun == len(loaded) and unchanged
          and not any((result.failures, result.errors, result.skipped, result.expectedFailures, result.unexpectedSuccesses)))
report = {'schema': 'hia.front.two-image-capture.v81.r2', 'status': 'PASS' if passed else 'FAIL',
          'scope': 'DEVELOPMENT_ONLY', 'python': sys.version, 'source_before': BEFORE, 'source_after': after,
          'original_r1_unchanged': unchanged, 'loaded': loaded, 'executed': EXECUTED,
          'tests_run': result.testsRun, 'seconds': time.monotonic()-started, 'observations': OBSERVATIONS,
          'failures': [(str(t), v) for t, v in result.failures], 'errors': [(str(t), v) for t, v in result.errors],
          'skipped': result.skipped, 'expected_failures': [(str(t), v) for t, v in result.expectedFailures],
          'unexpected_successes': list(map(str, result.unexpectedSuccesses)),
          'old_thirteen_root_results_inherited': False, 'cold': False, 'whole_normalization': False}
(OUT / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
print(json.dumps({k: report[k] for k in ('status', 'tests_run', 'seconds', 'original_r1_unchanged')}))
raise SystemExit(0 if passed else 1)
