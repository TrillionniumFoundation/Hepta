"""Bounded FIFO observations and fresh Core-only execution in new processes."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--child', choices=('fifo', 'core-only'))
parser.add_argument('--case', type=Path)
args = parser.parse_args()
for key in tuple(os.environ):
    if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'):
        del os.environ[key]
sys.path.insert(0, str(SOURCE))

if args.child:
    case = json.loads(args.case.read_bytes())
    started = time.monotonic()
    if args.child == 'core-only':
        os.environ['HEPTA_HIA_CORE_VERIFICATION_MANIFEST'] = case['manifest']
        from hepta import hia_program as program
        from hepta.hia_core_verification_selection import installed_core_verification
        owner = installed_core_verification(case['manifest'])
        before = owner.entries
        verified = program.verify_program(case['document'])
        assert verified.as_dict() == case['document']
        assert owner.entries > before
        try:
            program._reject('actual independent Core error', 'E_CONTROL')
        except program.HIAProgramRejected as error:
            assert error.code == 'E_CONTROL'
        else:
            raise AssertionError('selected Core rejection returned')
        forbidden = ('hepta.hia_agent_assembly', 'hepta.hia_program_tools',
                     'hepta.hia_program_native', 'hepta.hia_machine_plan_control_native')
        assert not any(name in sys.modules for name in forbidden)
        print(json.dumps({'status': 'PASS', 'actual_entries': owner.entries-before,
                          'forbidden_modules_loaded': [name for name in forbidden if name in sys.modules],
                          'loaded_hepta_modules': sorted(name for name in sys.modules if name.startswith('hepta.')),
                          'canonical_sha256': verified.sha256, 'seconds': time.monotonic()-started}))
        raise SystemExit(0)
    if case['owner'] == 'core_verification':
        from hepta import hia_core_verification_native as native
        from hepta import hia_core_verification_selection as selection
        loader = selection.installed_core_verification
    else:
        from hepta import hia_assembly_front_native as native
        from hepta import hia_assembly_front_selection as selection
        loader = selection.installed_assembly_front
    with patch.object(native, 'SOURCE', Path(case['source'])), patch.object(selection, 'SOURCE', Path(case['source'])):
        try:
            loader(case['manifest'])
        except ValueError as error:
            print(json.dumps({'status': 'REFUSED_ORDINARY_FILE', 'type': type(error).__name__,
                              'message': str(error), 'seconds': time.monotonic()-started}))
        else:
            raise AssertionError('FIFO was admitted')
    raise SystemExit(0)

OUT = ROOT / 'admission-controls-r2'
OUT.mkdir(exist_ok=False)
BUILD = json.loads((ROOT / 'native-build-r1/RESULT.json').read_bytes())
OBSERVATIONS = []
def snapshot(root):
    return {p.relative_to(root).as_posix(): {'sha256': sha256(p.read_bytes()).hexdigest(),
            'mode': p.stat().st_mode & 0o777} for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
BEFORE = snapshot(SOURCE)
ORIGINAL = ROOT.with_name('v81-core-assembly-front-development-r1') / 'source'
ORIGINAL_GUARD = json.loads((ROOT / 'ORIGINAL-R1-SOURCE-GUARD.json').read_bytes())
assert snapshot(ORIGINAL) == ORIGINAL_GUARD

class Controls(unittest.TestCase):
    def fifo(self, role):
        for owner in ('core_verification', 'assembly_front'):
            with self.subTest(owner=owner, role=role):
                directory = OUT / (owner + '-' + role)
                directory.mkdir()
                item = BUILD['images'][owner]
                original = Path(item['manifest_path'])
                record = dict(item['manifest'])
                image_path = directory / record['image_path']
                source = directory / (owner + '.hiaasm')
                manifest = directory / 'manifest.json'
                image_path.write_bytes((original.parent / record['image_path']).read_bytes())
                source.write_bytes((SOURCE / 'examples/hia_bootstrap' / (owner + '.hiaasm')).read_bytes())
                manifest.write_text(json.dumps(record))
                selected = {'manifest': manifest, 'source': source, 'image': image_path}[role]
                selected.unlink()
                os.mkfifo(selected)
                case = directory / 'case.json'
                case.write_text(json.dumps({'owner': owner, 'manifest': str(manifest), 'source': str(source)}))
                command = [sys.executable, '-B', str(Path(__file__).resolve()), '--child', 'fifo', '--case', str(case)]
                started = time.monotonic()
                try:
                    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, timeout=1.0)
                except subprocess.TimeoutExpired as error:
                    (directory / 'stdout.bin').write_bytes(error.stdout or b'')
                    (directory / 'stderr.bin').write_bytes(error.stderr or b'')
                    (directory / 'PROCESS.json').write_text(json.dumps({'status': 'TIMEOUT', 'seconds': time.monotonic()-started,
                                                                       'original_observation_limit': 1.0, 'command': command}))
                    raise
                (directory / 'stdout.bin').write_bytes(result.stdout)
                (directory / 'stderr.bin').write_bytes(result.stderr)
                process = {'returncode': result.returncode, 'seconds': time.monotonic()-started,
                           'original_observation_limit': 1.0, 'command': command}
                (directory / 'PROCESS.json').write_text(json.dumps(process, sort_keys=True, indent=2)+'\n')
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                observed = json.loads(result.stdout)
                self.assertEqual(observed['status'], 'REFUSED_ORDINARY_FILE')
                self.assertEqual(observed['message'], 'front admission requires a bounded ordinary file')
                OBSERVATIONS.append({'case': 'actual-fifo-refusal', 'owner': owner, 'role': role,
                                     'process': process, 'observation': observed})

    def test_fifo_manifest_rejects_before_read(self):
        self.fifo('manifest')

    def test_fifo_source_rejects_before_read(self):
        self.fifo('source')

    def test_fifo_image_rejects_before_read(self):
        self.fifo('image')

    def test_actual_selected_core_has_no_assembly_import(self):
        document = {'schema': 'hepta.hia.program.v6', 'module': 'm', 'functions': [
            {'name': 'identity', 'params': [{'name': 'x', 'type': 'u8'}], 'returns': ['u8'],
             'effects': [], 'entry': 'entry', 'blocks': [{'id': 'entry',
                'params': [{'name': 'x', 'type': 'u8'}], 'ops': [],
                'term': {'op': 'ret', 'values': ['x']}}]}]}
        case = OUT / 'core-only-case.json'
        case.write_text(json.dumps({'manifest': BUILD['images']['core_verification']['manifest_path'],
                                   'document': document}))
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--child', 'core-only', '--case', str(case)]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=20)
        (OUT / 'core-only.stdout.log').write_bytes(result.stdout)
        (OUT / 'core-only.stderr.log').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        observed = json.loads(result.stdout)
        self.assertGreater(observed['actual_entries'], 0)
        self.assertEqual(observed['forbidden_modules_loaded'], [])
        OBSERVATIONS.append({'case': 'core-independent-process', 'observation': observed})

EXECUTED = []
class Result(unittest.TextTestResult):
    def startTest(self, test):
        EXECUTED.append(test.id())
        super().startTest(test)
suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
loaded = [test.id() for test in suite]
started = time.monotonic()
with (OUT / 'tests.log').open('w') as stream:
    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
after = snapshot(SOURCE)
unchanged = BEFORE == after and snapshot(ORIGINAL) == ORIGINAL_GUARD
passed = (unchanged and loaded == EXECUTED and result.testsRun == len(loaded)
          and not any((result.failures, result.errors, result.skipped, result.expectedFailures, result.unexpectedSuccesses)))
report = {'schema': 'hia.front.admission-original-fifo-regression.v81.r2', 'status': 'PASS' if passed else 'FAIL',
          'scope': 'DEVELOPMENT_ONLY', 'python': sys.version, 'source_before': BEFORE, 'source_after': after,
          'original_r1_unchanged': unchanged, 'tests_run': result.testsRun, 'loaded': loaded, 'executed': EXECUTED,
          'failures': [(str(t), v) for t, v in result.failures], 'errors': [(str(t), v) for t, v in result.errors],
          'skipped': result.skipped, 'expected_failures': [(str(t), v) for t, v in result.expectedFailures],
          'unexpected_successes': list(map(str, result.unexpectedSuccesses)),
          'observations': OBSERVATIONS, 'seconds': time.monotonic()-started,
          'original_fifo_failure_retained_in_blob': '8167fc2a02a71832d450e89b153524fe50893643',
          'cold': False, 'whole_normalization': False}
(OUT / 'REPORT.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
print(json.dumps({k: report[k] for k in ('status', 'tests_run', 'seconds', 'original_r1_unchanged')}))
raise SystemExit(0 if passed else 1)
