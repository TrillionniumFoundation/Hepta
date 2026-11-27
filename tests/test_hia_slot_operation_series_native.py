"""Actual image/SQLite controls for Slot operation-series delivery.

This is a new focused four-method module. It does not replace or filter the
original Slot15, TX61, ordinary112/128, Store130, or component152 gates.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'HEPTA_HIA_SLOT_OPERATIONS_'
CHILD_SECONDS = 60
CLEANUP_SECONDS = 3


def _json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2,
                               allow_nan=False) + '\n')


def _members(group):
    values = []
    for p in Path('/proc').iterdir():
        if not p.name.isdecimal():
            continue
        try:
            raw = (p / 'stat').read_text()
            fields = raw[raw.rfind(')') + 2:].split()
            if int(fields[2]) == group and int(fields[3]) == group:
                values.append({'pid': int(p.name), 'state': fields[0],
                               'pgid': int(fields[2]), 'sid': int(fields[3]),
                               'start_ticks': int(fields[19])})
        except (FileNotFoundError, ProcessLookupError):
            pass
    return sorted(values, key=lambda value: value['pid'])


def _stop(process):
    started = time.monotonic()
    before = _members(process.pid)
    signals = []
    if before:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            signals.append('SIGTERM')
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=max(.001, CLEANUP_SECONDS / 2 - (time.monotonic() - started)))
    except subprocess.TimeoutExpired:
        pass
    middle = _members(process.pid)
    if middle:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            signals.append('SIGKILL')
        except ProcessLookupError:
            pass
    reaped = True
    try:
        process.wait(timeout=max(.001, CLEANUP_SECONDS - (time.monotonic() - started)))
    except subprocess.TimeoutExpired:
        reaped = False
    return {'before': before, 'middle': middle, 'after': _members(process.pid),
            'signals': signals, 'reaped': reaped,
            'cleanup_elapsed_seconds': time.monotonic() - started}


class SlotOperationsResourceNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_slot_operations import INPUTS, build
        from tools.build_hia_slot_ledger import build as decision_build
        from tools.build_hia_json_preflight import admit_cold_build
        from tools.build_hia_source_build import _check_pack_output
        from tools.qualify_hia_selfhost import compile_stage
        cold = os.environ.get(PREFIX + 'COLD_REPORT')
        development = os.environ.get(PREFIX + 'DEVELOPMENT_COMPILER')
        if bool(cold) == bool(development):
            raise ValueError('choose one exact current cold report or explicit development compiler')
        cls.temporary = None
        evidence = os.environ.get(PREFIX + 'EVIDENCE')
        if evidence:
            cls.folder = Path(evidence) / cls.__name__
            cls.folder.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-slot-operation-resources-')
            cls.folder = Path(cls.temporary.name)
        cls.cold_path = Path(cold).resolve(strict=True) if cold else None
        cls.cold_bytes = cls.nested_bytes = cls.nested_path = cls.admitted = None
        if cls.cold_path is not None:
            from tools.hia_cold_compiler import read_cold_build_inputs
            cls.cold_inputs = read_cold_build_inputs(cls.cold_path)
            cls.cold_bytes = cls.cold_inputs.report_bytes
            cls.nested_path = cls.cold_inputs.location_path
            cls.nested_bytes = cls.cold_inputs.location_bytes
            cls.compiler = cls.cold_inputs.compiler
            cls.compiler_bytes = cls.cold_inputs.compiler_bytes
            cls.admitted = admit_cold_build(cls.compiler_bytes, cls.cold_bytes)
        else:
            cls.compiler = Path(development).resolve(strict=True)
            cls.compiler_bytes = cls.compiler.read_bytes()
        cls.inputs = tuple(dict.fromkeys((*INPUTS,
            'examples/hia_bootstrap/slot_ledger.hepta', 'tools/generate_hia_slot_ledger.py',
            'tests/hia_slot_operations_resource_controls.py',
            'tests/test_hia_slot_operation_series_native.py')))
        cls.before = {name: (ROOT / name).read_bytes() for name in cls.inputs}
        cls.controller = build(cls.folder / 'controller', cls.compiler, cls.cold_path,
                               development=cls.cold_path is None)
        if cls.cold_path is not None:
            cls.decision = decision_build(cls.folder / 'decision', cls.compiler, cls.cold_path)
        else:
            target = cls.folder / 'decision'
            target.mkdir(mode=0o700)
            source = cls.before['examples/hia_bootstrap/slot_ledger.hepta']
            image, receipt = compile_stage(target, 'slot_decision', cls.compiler, source)
            image_bytes = image.read_bytes()
            packed = _check_pack_output(receipt, (target / 'slot_decision.output.bin').read_bytes(),
                                        artifact=cls.compiler_bytes, source=source)
            if packed != image_bytes:
                raise AssertionError('actual decision pack and image differ')
            value = {'schema': 'hepta.hia.slot-ledger-native.v1',
                     'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                     'image_sha256': sha256(image_bytes).hexdigest(),
                     'compiler_sha256': sha256(cls.compiler_bytes).hexdigest()}
            cls.decision = target / 'manifest.json'
            _json(cls.decision, value)
            _json(target / 'build.json', {
                'scope': 'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_COLD_QUALIFIED',
                'manifest': value, 'native_compile_receipt': receipt})
        cls.manifest_bytes = {str(path): path.read_bytes() for path in (cls.controller, cls.decision)}
        cls.image_bytes = {}
        for path in (cls.controller, cls.decision):
            value = json.loads(cls.manifest_bytes[str(path)])
            image = path.parent / value['image_path']
            cls.image_bytes[str(image)] = image.read_bytes()
            if sha256(cls.image_bytes[str(image)]).hexdigest() != value['image_sha256']:
                raise AssertionError('built declared image hash differs')
        cls.check_sources()
        _json(cls.folder / 'fixture.json', {
            'scope': 'MATCHING_SOURCE_COLD_COMPONENT' if cls.cold_path else 'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_COLD_QUALIFIED',
            'cold_report': None if cls.cold_path is None else str(cls.cold_path),
            'compiler_path': str(cls.compiler), 'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(),
            'sources': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()} for name, raw in cls.before.items()},
            'manifests': {path: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()} for path, raw in cls.manifest_bytes.items()},
            'images': {path: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()} for path, raw in cls.image_bytes.items()},
            'new_resource_cases': 9, 'native_test_methods': 4,
            'original_248_and_derived_7574_replaced': False,
            'existing_complete_gates_and_deadlines_changed': False,
            'SQL_implemented_by_native': False})

    @classmethod
    def check_sources(cls):
        if cls.compiler.read_bytes() != cls.compiler_bytes:
            raise AssertionError('Slot controller compiler changed')
        if any((ROOT / name).read_bytes() != raw for name, raw in cls.before.items()):
            raise AssertionError('Slot controller/component input changed')
        if cls.cold_path is not None and (
                cls.cold_path.read_bytes() != cls.cold_bytes
                or cls.nested_path.read_bytes() != cls.nested_bytes):
            raise AssertionError('Slot controller matching cold report changed')
        if cls.cold_path is not None:
            cls.cold_inputs.unchanged()
            from tools.build_hia_json_preflight import admit_cold_build, current_sources
            if (admit_cold_build(cls.compiler_bytes, cls.cold_bytes) != cls.admitted
                    or current_sources() != cls.admitted):
                raise AssertionError('Slot control is not bound to this complete current source')
        if hasattr(cls, 'manifest_bytes') and any(Path(path).read_bytes() != raw for path, raw in cls.manifest_bytes.items()):
            raise AssertionError('Slot controller or decision manifest changed')
        if hasattr(cls, 'image_bytes') and any(Path(path).read_bytes() != raw for path, raw in cls.image_bytes.items()):
            raise AssertionError('Slot controller or decision image changed')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.check_sources()
        finally:
            if cls.temporary is not None:
                cls.temporary.cleanup()

    def _case(self, name):
        self.check_sources()
        folder = self.folder / name
        folder.mkdir(mode=0o700, exist_ok=False)
        child_evidence = folder / 'observation'
        script = "import runpy,sys;sys.path.insert(0," + repr(str(ROOT)) + ");runpy.run_module('tests.hia_slot_operations_resource_controls',run_name='__main__')"
        command = [sys.executable, '-I', '-B', '-c', script,
                   '--case', name, '--controller-manifest', str(self.controller),
                   '--decision-manifest', str(self.decision), '--evidence', str(child_evidence)]
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('HEPTA_HIA_', 'PYTHON'))}
        before = time.monotonic()
        process = None
        timed_out = False
        cleanup = None
        with (folder / 'stdout.log').open('wb') as stdout, (folder / 'stderr.log').open('wb') as stderr:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            _json(folder / 'command.json', {
                'command': command, 'cwd': str(ROOT), 'pid': process.pid, 'pgid': process.pid,
                'timeout_seconds': CHILD_SECONDS, 'cleanup_seconds': CLEANUP_SECONDS,
                'parent_pid': os.getpid(), 'parent_argv': sys.argv,
                'environment_removed_prefixes': ['HEPTA_HIA_', 'PYTHON'],
                'LD_LIBRARY_PATH': env.get('LD_LIBRARY_PATH'),
                'scope': 'ONE_NEW_FOCUSED_RESOURCE_CONTROL_NOT_AN_ORIGINAL_SUITE'})
            try:
                process.wait(timeout=CHILD_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                cleanup = _stop(process)
            except BaseException:
                cleanup = _stop(process)
                _json(folder / 'interrupted-cleanup.json', cleanup)
                raise
            survivors = _members(process.pid)
            if survivors and cleanup is None:
                cleanup = _stop(process)
        outcome = {
            'case': name, 'returncode': process.returncode, 'timed_out': timed_out,
            'elapsed_seconds': time.monotonic() - before,
            'pid': process.pid, 'pgid': process.pid, 'reaped': process.poll() is not None,
            'survivors_after_natural_exit': survivors, 'survivors_after_cleanup': _members(process.pid),
            'cleanup': cleanup,
        }
        _json(folder / 'result.json', outcome)
        self.check_sources()
        self.assertFalse(timed_out, outcome)
        self.assertEqual(process.returncode, 0, outcome)
        self.assertFalse(survivors, outcome)
        self.assertFalse(outcome['survivors_after_cleanup'], outcome)
        self.assertIsNone(cleanup, outcome)
        report = json.loads((child_evidence / 'report.json').read_bytes())
        self.assertEqual((report['status'], report['id']), ('PASS', name), report)
        self.assertTrue(report['actual_controller_entries'], report)
        self.assertEqual(report['retained_original_calls'], [], report)
        self.assertEqual(report['unraisable'], [], report)
        self.assertIsNone(report['error'], report)

    def test_SQL_prefix_remains_pending_until_the_final_operation_receipt(self):
        for name in ('prefix-before-next-sql', 'prefix-after-third-sql', 'prefix-finalize', 'ordinary-rejection'):
            with self.subTest(case=name):
                self._case(name)

    def test_same_generation_prior_loss_is_rejected_before_first_SQL(self):
        for name in ('prior-loss-context', 'prior-loss-thread'):
            with self.subTest(case=name):
                self._case(name)

    def test_last_SQL_argument_checks_a_new_independent_context_loss(self):
        for name in ('loss-between-borrow-and-call-context', 'loss-between-borrow-and-call-thread'):
            with self.subTest(case=name):
                self._case(name)

    def test_same_Frame_reentry_cannot_clean_up_its_still_active_parent(self):
        self._case('same-frame-reentry')


if __name__ == '__main__':
    unittest.main(verbosity=2)
